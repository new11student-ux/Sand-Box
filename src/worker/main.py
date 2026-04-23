"""
Advanced Cybersecurity Sandbox Platform
Background Worker - Processes submission queue and orchestrates analysis

Integrates:
- CAPEv2 sandbox for malware detonation
- MISP for pre/post-analysis threat intelligence
- Sigma engine for behavioral rule matching
"""

import asyncio
import logging
import os
import json
from datetime import datetime, timezone
from typing import Optional
import asyncpg
import httpx
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sandbox:sandbox@localhost:5432/sandbox_db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
CAPEV2_URL = os.getenv("CAPEV2_URL", "http://localhost:8080")
MISP_URL = os.getenv("MISP_URL", "http://localhost:8081")
POLL_INTERVAL_SECONDS = int(os.getenv("WORKER_POLL_INTERVAL", "5"))

db_pool: Optional[asyncpg.Pool] = None
http_client: Optional[httpx.AsyncClient] = None

# ---- Lazy-loaded integration modules ----
_misp_client = None
_sigma_engine = None


def get_misp_client():
    """Lazily initialize the MISP client."""
    global _misp_client
    if _misp_client is None:
        from src.ti.misp_client import MISPClient
        _misp_client = MISPClient()
    return _misp_client


def get_sigma_engine():
    """Lazily initialize the Sigma rule engine."""
    global _sigma_engine
    if _sigma_engine is None:
        from src.sigma.engine import SigmaEngine
        _sigma_engine = SigmaEngine()
        count = _sigma_engine.load_rules()
        logger.info("Sigma engine loaded %d rules", count)
    return _sigma_engine


async def init_pool():
    """Initialize database connection pool."""
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    logger.info("Database connection pool initialized")


async def init_http():
    """Initialize HTTP client."""
    global http_client
    http_client = httpx.AsyncClient(timeout=30.0)
    logger.info("HTTP client initialized")


async def claim_task() -> Optional[dict]:
    """Claim the highest priority pending task from queue."""
    async with db_pool.acquire() as conn:
        # Find pending task
        task = await conn.fetchrow("""
            SELECT sq.*, s.sha256_hash, s.storage_path, s.file_type
            FROM submission_queue sq
            JOIN samples s ON sq.sample_id = s.id
            WHERE sq.status = 'pending'
            ORDER BY sq.priority DESC, sq.queued_at ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        """)

        if not task:
            return None

        # Claim task
        await conn.execute("""
            UPDATE submission_queue
            SET status = 'assigned', assigned_at = NOW()
            WHERE id = $1
        """, task["id"])

        # Update sample status
        await conn.execute("""
            UPDATE samples
            SET status = 'queued', analysis_started_at = NOW()
            WHERE id = $1
        """, task["sample_id"])

        logger.info(f"Claimed task {task['id']} for sample {task['sample_id']}")
        return dict(task)


# ============================================================================
# Pre-analysis: MISP enrichment
# ============================================================================

async def pre_analysis_enrichment(task: dict) -> dict:
    """
    Query MISP for existing intelligence before detonation.
    May adjust priority based on known threat associations.
    """
    enrichment = {"misp_found": False, "priority_boost": 0, "tags": []}

    try:
        misp = get_misp_client()
        correlation = await misp.correlate_sample(task["sha256_hash"])

        if correlation["direct_match"]:
            enrichment["misp_found"] = True
            enrichment["priority_boost"] = correlation["priority_boost"]
            enrichment["campaigns"] = correlation.get("campaigns", [])
            enrichment["threat_actors"] = correlation.get("threat_actors", [])

            logger.info(
                "Pre-analysis: sample %s found in MISP (%d related events, priority +%d)",
                task["sha256_hash"][:16],
                len(correlation["related_events"]),
                correlation["priority_boost"],
            )

            # Boost priority in DB if TI says it's important
            if correlation["priority_boost"] > 0:
                async with db_pool.acquire() as conn:
                    current_priority = task.get("priority", 5)
                    new_priority = min(10, current_priority + correlation["priority_boost"])
                    await conn.execute("""
                        UPDATE submission_queue SET priority = $1 WHERE id = $2
                    """, new_priority, task["id"])
    except Exception as e:
        logger.warning("Pre-analysis enrichment failed: %s", e)

    return enrichment


# ============================================================================
# CAPEv2 integration
# ============================================================================

async def submit_to_capev2(task: dict) -> Optional[str]:
    """Submit sample to CAPEv2 sandbox for analysis."""
    try:
        storage_path = task["storage_path"]
        if not os.path.exists(storage_path):
            logger.error(f"Sample file not found: {storage_path}")
            return None

        with open(storage_path, "rb") as f:
            file_content = f.read()

        files = {"file": (os.path.basename(storage_path), file_content)}
        data = {
            "options": json.dumps({
                "timeout": 300,
                "enforce_timeout": False,
            })
        }

        response = await http_client.post(
            f"{CAPEV2_URL}/apiv2/tasks/create/file",
            files=files,
            data=data
        )

        if response.status_code == 200:
            result = response.json()
            task_id = result.get("data", {}).get("task_ids", [None])[0]
            logger.info(f"Submitted to CAPEv2, task_id: {task_id}")
            return str(task_id) if task_id else None
        else:
            logger.error(f"CAPEv2 submission failed: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        logger.error(f"Error submitting to CAPEv2: {e}")
        return None


async def poll_capev2_status(capev2_task_id: str) -> str:
    """Poll CAPEv2 for task status."""
    response = await http_client.get(
        f"{CAPEV2_URL}/apiv2/tasks/view/{capev2_task_id}"
    )

    if response.status_code == 200:
        result = response.json()
        return result.get("task", {}).get("status", "unknown")
    return "unknown"


async def fetch_capev2_report(capev2_task_id: str) -> Optional[dict]:
    """Fetch full analysis report from CAPEv2."""
    response = await http_client.get(
        f"{CAPEV2_URL}/apiv2/tasks/report/{capev2_task_id}/json"
    )

    if response.status_code == 200:
        return response.json()
    return None


# ============================================================================
# Post-analysis: Sigma matching
# ============================================================================

def run_sigma_matching(report: dict) -> list:
    """
    Run Sigma rules against CAPEv2 behavioral report.
    Transforms CAPEv2 output into a format the Sigma engine understands.
    """
    # Transform CAPEv2 report into Sigma-compatible behavior data
    behavior_data = _transform_capev2_to_behavior(report)

    engine = get_sigma_engine()
    matches = engine.match(behavior_data)

    logger.info("Sigma matching: %d rules triggered", len(matches))
    return matches


def _transform_capev2_to_behavior(report: dict) -> dict:
    """Transform CAPEv2 JSON report into flat behavior data for Sigma matching."""
    behavior = report.get("behavior", {})
    network = report.get("network", {})

    # Extract API calls from all processes
    api_calls = []
    for process in behavior.get("processes", []):
        for call in process.get("calls", []):
            api_calls.append(call.get("api", ""))

    # Extract registry operations
    registry_ops = []
    for regkey in behavior.get("regkey_written", []):
        registry_ops.append({"path": regkey, "type": "write"})
    for regkey in behavior.get("regkey_opened", []):
        registry_ops.append({"path": regkey, "type": "read"})

    # Extract file operations
    file_ops = []
    for fp in behavior.get("file_written", []):
        file_ops.append({"path": fp, "type": "write"})
    for fp in behavior.get("file_read", []):
        file_ops.append({"path": fp, "type": "read"})

    # Network
    connections = []
    for conn in network.get("tcp", []) + network.get("udp", []):
        connections.append({
            "host": conn.get("dst", ""),
            "port": conn.get("dport", 0),
            "timestamp": conn.get("time", 0),
        })

    dns_queries = []
    for d in network.get("dns", []):
        dns_queries.append({"query": d.get("request", "")})

    return {
        "api_calls": api_calls,
        "registry_operations": registry_ops,
        "file_operations": file_ops,
        "network": {
            "connections": connections,
            "dns": dns_queries,
        },
        "process_tree": behavior.get("processtree", {}),
    }


# ============================================================================
# Process results & store
# ============================================================================

async def process_analysis_result(task: dict, report: dict):
    """Process CAPEv2 report, run Sigma matching, and store in database."""
    async with db_pool.acquire() as conn:
        sample_id = task["sample_id"]

        # --- Sigma rule matching ---
        sigma_matches = run_sigma_matching(report)
        sigma_engine = get_sigma_engine()
        sigma_behaviors = sigma_engine.matches_to_behaviors(sigma_matches, str(sample_id))

        # --- Determine verdict ---
        verdict = "unknown"
        confidence = 0.5

        signatures = report.get("signatures", [])
        high_sigma = sum(1 for m in sigma_matches if m.level in ("high", "critical"))

        if signatures or high_sigma >= 2:
            verdict = "malicious"
            confidence = min(1.0, 0.5 + len(signatures) * 0.1 + high_sigma * 0.15)
        elif report.get("info", {}).get("score", 0) > 0 or sigma_matches:
            verdict = "suspicious"
            confidence = 0.6
        elif not signatures and not sigma_matches:
            # No hits at all — likely benign
            verdict = "benign"
            confidence = 0.7

        # Update sample with verdict
        await conn.execute("""
            UPDATE samples
            SET status = 'completed',
                verdict = $1,
                confidence_score = $2,
                analysis_completed_at = NOW()
            WHERE id = $3
        """, verdict, confidence, sample_id)

        # Store analysis report
        await conn.execute("""
            INSERT INTO analysis_reports (
                sample_id, report_format, report_data, summary, processing_status
            ) VALUES ($1, 'capev2', $2, $3, 'completed')
        """, sample_id, json.dumps(report), f"Analysis completed with verdict: {verdict}")

        # --- Store Sigma-matched behaviors ---
        for sb in sigma_behaviors:
            await conn.execute("""
                INSERT INTO behaviors (
                    sample_id, behavior_type, severity, description,
                    sigma_rule_id, sigma_rule_name,
                    mitre_attack_id, mitre_attack_tactic, mitre_attack_technique,
                    raw_data, timestamp
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
            """,
                sample_id, sb["behavior_type"], sb["severity"], sb["description"],
                sb["sigma_rule_id"], sb["sigma_rule_name"],
                sb.get("mitre_attack_id"), sb.get("mitre_attack_tactic"),
                sb.get("mitre_attack_technique"),
                json.dumps(sb.get("raw_data", {})),
            )

        # --- Store CAPEv2 process-level behaviors ---
        behavior_list = report.get("behavior", {}).get("processes", [])
        for process in behavior_list:
            for call in process.get("calls", [])[:100]:
                await conn.execute("""
                    INSERT INTO behaviors (
                        sample_id, behavior_type, severity, description,
                        raw_data, timestamp
                    ) VALUES ($1, 'process', 'info', $2, $3, NOW())
                """, sample_id, call.get("api", ""), json.dumps(call))

        # --- Extract and store IOCs ---
        iocs_data = report.get("network", {})
        for domain in iocs_data.get("domains", []):
            await conn.execute("""
                INSERT INTO iocs (sample_id, ioc_type, value, confidence)
                VALUES ($1, 'domain', $2, 'medium')
                ON CONFLICT (ioc_type, value) DO NOTHING
            """, sample_id, domain.get("domain", ""))

        for ip in iocs_data.get("hosts", []):
            await conn.execute("""
                INSERT INTO iocs (sample_id, ioc_type, value, confidence)
                VALUES ($1, 'ip', $2, 'medium')
                ON CONFLICT (ioc_type, value) DO NOTHING
            """, sample_id, ip)

        # Update queue status
        await conn.execute("""
            UPDATE submission_queue
            SET status = 'completed', completed_at = NOW()
            WHERE id = $1
        """, task["id"])

        logger.info(
            "Processed sample %s: verdict=%s, confidence=%.2f, sigma_matches=%d",
            sample_id, verdict, confidence, len(sigma_matches),
        )


# ============================================================================
# Post-analysis: MISP sync
# ============================================================================

async def post_analysis_misp_sync(task: dict, verdict: str, confidence: float):
    """Sync analysis results back to MISP."""
    try:
        misp = get_misp_client()

        async with db_pool.acquire() as conn:
            # Fetch IOCs for this sample
            iocs = await conn.fetch(
                "SELECT ioc_type, value, confidence FROM iocs WHERE sample_id = $1",
                task["sample_id"]
            )
            ioc_list = [dict(i) for i in iocs]

            # Fetch Sigma-matched behaviors for MITRE tagging
            behaviors = await conn.fetch(
                "SELECT mitre_attack_id FROM behaviors WHERE sample_id = $1 AND mitre_attack_id IS NOT NULL",
                task["sample_id"]
            )
            mitre_ids = list(set(b["mitre_attack_id"] for b in behaviors if b["mitre_attack_id"]))

        # Create MISP event
        event_uuid = await misp.create_event_from_analysis(
            sample_sha256=task["sha256_hash"],
            sample_name=os.path.basename(task.get("storage_path", "unknown")),
            verdict=verdict,
            confidence=confidence,
            iocs=ioc_list,
            behaviors=[],
            mitre_tactics=mitre_ids,
        )

        if event_uuid:
            logger.info("MISP event created: %s", event_uuid)

    except Exception as e:
        logger.error("MISP sync failed: %s", e)


# ============================================================================
# Main task processor
# ============================================================================

async def process_task(task: dict):
    """Process a single analysis task end-to-end."""
    try:
        # Update task status to processing
        async with db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE submission_queue
                SET status = 'processing', started_at = NOW()
                WHERE id = $1
            """, task["id"])

        # --- Step 1: Pre-analysis MISP enrichment ---
        enrichment = await pre_analysis_enrichment(task)

        # --- Step 2: Submit to CAPEv2 ---
        capev2_task_id = await submit_to_capev2(task)
        if not capev2_task_id:
            raise Exception("Failed to submit to CAPEv2")

        # --- Step 3: Poll for completion ---
        max_wait = 600  # 10 minutes max
        waited = 0
        while waited < max_wait:
            await asyncio.sleep(10)
            waited += 10

            status = await poll_capev2_status(capev2_task_id)
            logger.info(f"CAPEv2 task {capev2_task_id} status: {status}")

            if status == "completed":
                break
            elif status in ["failed", "cancelled"]:
                raise Exception(f"CAPEv2 task failed: {status}")

        # --- Step 4: Fetch report, run Sigma, store results ---
        report = await fetch_capev2_report(capev2_task_id)
        if report:
            await process_analysis_result(task, report)

            # --- Step 5: Post-analysis MISP sync ---
            async with db_pool.acquire() as conn:
                sample = await conn.fetchrow(
                    "SELECT verdict, confidence_score FROM samples WHERE id = $1",
                    task["sample_id"]
                )
            if sample:
                await post_analysis_misp_sync(
                    task, sample["verdict"], float(sample["confidence_score"] or 0)
                )
        else:
            raise Exception("Failed to fetch report from CAPEv2")

    except Exception as e:
        logger.error(f"Error processing task {task['id']}: {e}")
        async with db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE submission_queue
                SET status = 'failed', error_message = $1
                WHERE id = $2
            """, str(e), task["id"])

            await conn.execute("""
                UPDATE samples
                SET status = 'failed'
                WHERE id = $1
            """, task["sample_id"])


async def worker_loop():
    """Main worker loop."""
    logger.info("Worker started")

    while True:
        try:
            task = await claim_task()
            if task:
                await process_task(task)
            else:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
        except Exception as e:
            logger.error(f"Worker error: {e}")
            await asyncio.sleep(5)


async def main():
    """Main entry point."""
    await init_pool()
    await init_http()

    try:
        await worker_loop()
    except KeyboardInterrupt:
        logger.info("Worker shutting down...")
    finally:
        misp = get_misp_client()
        await misp.close()
        if http_client:
            await http_client.aclose()
        if db_pool:
            await db_pool.close()


if __name__ == "__main__":
    asyncio.run(main())
