"""
Advanced Cybersecurity Sandbox Platform
Sample Submission API - REST endpoints for malware sample submission and status tracking
"""

import os
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from uuid import UUID

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Header, Query, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import asyncpg
from dotenv import load_dotenv

# AI Sandbox imports
from src.ai_sandbox.schemas import SandboxExecutionRequest, SandboxExecutionResult
from src.ai_sandbox.e2b_manager import get_e2b_manager
from src.ai_sandbox.network_policies import generate_egress_policy

# Isolation imports
from src.isolation.schemas import RBISessionRequest, RBISessionResponse, SanitizationRequest, SanitizationResponse
from src.isolation.kasm_client import get_kasm_client
from src.isolation.dangerzone import get_dangerzone_manager

# Advanced imports
from src.advanced.schemas import CowrieEvent
from src.advanced.drakvuf_client import get_drakvuf_client
from src.advanced.cowrie_parser import CowrieParser
from src.advanced.mitre_tagger import MitreTagger

try:
    from prometheus_fastapi_instrumentator import Instrumentator
    from prometheus_client import Counter, Histogram
except ImportError:
    Instrumentator = None
    Counter = None
    Histogram = None

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Custom Business Metrics (Only if prometheus_client is installed)
if Counter and Histogram:
    malware_detected = Counter(
        'sandbox_malware_detected_total',
        'Total malware detections',
        ['severity', 'technique']
    )

    analysis_duration = Histogram(
        'sandbox_analysis_duration_seconds',
        'Time spent analyzing samples',
        ['sample_type', 'worker_type']
    )
else:
    malware_detected = None
    analysis_duration = None

def record_malware_detection(severity: str, technique: str):
    if malware_detected:
        malware_detected.labels(severity=severity, technique=technique).inc()

# ============================================================================
# Configuration
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sandbox:sandbox@localhost:5432/sandbox_db")
STORAGE_PATH = Path(os.getenv("STORAGE_PATH", "./storage/samples"))
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")  # 32-byte key for AES-256

# Ensure storage directory exists
STORAGE_PATH.mkdir(parents=True, exist_ok=True)

# Security
security = HTTPBearer()

# FastAPI app
app = FastAPI(
    title="Sandbox Platform API",
    description="REST API for submitting and tracking malware analysis samples",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Instrument FastAPI with Prometheus
if Instrumentator:
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")


# ============================================================================
# Database Connection Pool
# ============================================================================

db_pool: Optional[asyncpg.Pool] = None


async def get_db_pool() -> asyncpg.Pool:
    """Get or create database connection pool."""
    global db_pool
    if db_pool is None:
        db_pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=5,
            max_size=20,
            command_timeout=60
        )
    return db_pool


async def get_db_connection():
    """Dependency for getting database connection."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        yield conn


# ============================================================================
# Authentication
# ============================================================================

async def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Verify API key from Authorization header."""
    pool = await get_db_pool()
    api_key = credentials.credentials

    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            """
            SELECT id, username, role, permissions, api_rate_limit
            FROM users
            WHERE api_key_hash = crypt($1, api_key_hash)
            AND active = TRUE
            AND (api_key_expires_at IS NULL OR api_key_expires_at > NOW())
            """,
            api_key
        )

        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired API key"
            )

        return dict(user)


# ============================================================================
# Pydantic Models
# ============================================================================

class SampleSubmissionResponse(BaseModel):
    """Response model for sample submission."""
    sample_id: str
    sha256: str
    status: str
    message: str
    queued_at: datetime


class SampleStatusResponse(BaseModel):
    """Response model for sample status."""
    sample_id: str
    sha256: str
    file_name: str
    status: str
    verdict: Optional[str]
    confidence_score: Optional[float]
    submitted_at: datetime
    analysis_started_at: Optional[datetime]
    analysis_completed_at: Optional[datetime]
    behavior_count: int = 0
    ioc_count: int = 0


class AnalysisResult(BaseModel):
    """Analysis result model."""
    sample_id: str
    verdict: str
    confidence_score: float
    summary: str
    behaviors: List[dict]
    iocs: List[dict]
    mitre_attack: List[dict]
    sigma_matches: List[dict]


class QueueStatusResponse(BaseModel):
    """Queue status response."""
    pending_count: int
    processing_count: int
    estimated_wait_seconds: int
    position: Optional[int] = None


# ============================================================================
# Helper Functions
# ============================================================================

def calculate_hashes(file_content: bytes) -> dict:
    """Calculate SHA256, SHA1, and MD5 hashes of file content."""
    return {
        "sha256": hashlib.sha256(file_content).hexdigest(),
        "sha1": hashlib.sha1(file_content).hexdigest(),
        "md5": hashlib.md5(file_content).hexdigest()
    }


def get_storage_path(sha256_hash: str) -> Path:
    """Get storage path for sample using directory sharding."""
    # Use first 2 chars as subdirectory for better FS performance
    shard = sha256_hash[:2]
    sample_dir = STORAGE_PATH / shard
    sample_dir.mkdir(parents=True, exist_ok=True)
    return sample_dir / sha256_hash


async def store_sample(file_content: bytes, sha256_hash: str) -> str:
    """Store sample file and return storage path."""
    storage_path = get_storage_path(sha256_hash)

    # In production, encrypt before writing
    if ENCRYPTION_KEY:
        from cryptography.fernet import Fernet
        f = Fernet(ENCRYPTION_KEY)
        encrypted_content = f.encrypt(file_content)
        storage_path.write_bytes(encrypted_content)
    else:
        storage_path.write_bytes(file_content)

    return str(storage_path)


async def check_duplicate_sample(sha256_hash: str) -> Optional[dict]:
    """Check if sample already exists in database."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, sha256_hash, status, verdict
            FROM samples
            WHERE sha256_hash = $1
            """,
            sha256_hash
        )
        return dict(row) if row else None


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0"
    }


@app.post("/samples", response_model=SampleSubmissionResponse)
async def submit_sample(
    file: UploadFile = File(..., description="Sample file to analyze"),
    priority: int = Query(5, ge=1, le=10, description="Analysis priority (1-10)"),
    sandbox_type: Optional[str] = Query(None, description="Requested sandbox type"),
    user: dict = Depends(verify_api_key)
):
    """
    Submit a sample for malware analysis.

    - **file**: The sample file to analyze
    - **priority**: Analysis priority (1=lowest, 10=highest)
    - **sandbox_type**: Optional specific sandbox type request
    """
    # Read file content
    file_content = await file.read()
    file_size = len(file_content)

    # Validate file size (max 100MB)
    if file_size > 100 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 100MB limit")

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Calculate hashes
    hashes = calculate_hashes(file_content)

    # Check for duplicate
    existing = await check_duplicate_sample(hashes["sha256"])
    if existing:
        return SampleSubmissionResponse(
            sample_id=str(existing["id"]),
            sha256=hashes["sha256"],
            status=existing["status"],
            message="Sample already exists in system",
            queued_at=datetime.now(timezone.utc)
        )

    # Store sample file
    storage_path = await store_sample(file_content, hashes["sha256"])

    # Determine file type
    import magic
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(file_content[:2048])
    except ImportError:
        file_type = "application/octet-stream"

    # Insert into database
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Create sample record
            sample_id = await conn.fetchval(
                """
                INSERT INTO samples (
                    sha256_hash, sha1_hash, md5_hash,
                    file_name, file_size, file_type, mime_type,
                    submitted_by, source_type, priority,
                    storage_path, encrypted
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                RETURNING id
                """,
                hashes["sha256"], hashes["sha1"], hashes["md5"],
                file.filename, file_size, file_type, file_type,
                user["id"], "api", priority,
                storage_path, bool(ENCRYPTION_KEY)
            )

            # Add to submission queue
            await conn.execute(
                """
                INSERT INTO submission_queue (
                    sample_id, priority, requested_sandbox_type, status
                ) VALUES ($1, $2, $3, 'pending')
                """,
                sample_id, priority, sandbox_type
            )

            # Log audit event
            await conn.execute(
                """
                INSERT INTO audit_log (
                    user_id, action, resource_type, resource_id,
                    details, status
                ) VALUES ($1, 'sample_submitted', 'sample', $2, $3, 'success')
                """,
                user["id"], sample_id,
                {"file_name": file.filename, "file_size": file_size, "priority": priority}
            )

    logger.info(f"Sample submitted: {sample_id}, SHA256: {hashes['sha256']}")

    return SampleSubmissionResponse(
        sample_id=str(sample_id),
        sha256=hashes["sha256"],
        status="queued",
        message="Sample submitted successfully for analysis",
        queued_at=datetime.now(timezone.utc)
    )


@app.get("/samples/{sample_id}", response_model=SampleStatusResponse)
async def get_sample_status(
    sample_id: UUID,
    user: dict = Depends(verify_api_key)
):
    """Get status and summary of a submitted sample."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                s.id, s.sha256_hash, s.file_name, s.status, s.verdict,
                s.confidence_score, s.submitted_at, s.analysis_started_at,
                s.analysis_completed_at,
                COUNT(DISTINCT b.id) as behavior_count,
                COUNT(DISTINCT i.id) as ioc_count
            FROM samples s
            LEFT JOIN behaviors b ON s.id = b.sample_id
            LEFT JOIN iocs i ON s.id = i.sample_id
            WHERE s.id = $1
            GROUP BY s.id
            """,
            sample_id
        )

        if not row:
            raise HTTPException(status_code=404, detail="Sample not found")

        return SampleStatusResponse(
            sample_id=str(row["id"]),
            sha256=row["sha256_hash"],
            file_name=row["file_name"],
            status=row["status"],
            verdict=row["verdict"],
            confidence_score=float(row["confidence_score"]) if row["confidence_score"] else None,
            submitted_at=row["submitted_at"],
            analysis_started_at=row["analysis_started_at"],
            analysis_completed_at=row["analysis_completed_at"],
            behavior_count=row["behavior_count"] or 0,
            ioc_count=row["ioc_count"] or 0
        )


@app.get("/samples/{sample_id}/report", response_model=AnalysisResult)
async def get_analysis_report(
    sample_id: UUID,
    user: dict = Depends(verify_api_key)
):
    """Get full analysis report for a completed sample."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        # Get sample and report
        row = await conn.fetchrow(
            """
            SELECT s.id, s.verdict, s.confidence_score, ar.summary, ar.report_data
            FROM samples s
            LEFT JOIN analysis_reports ar ON s.id = ar.sample_id
            WHERE s.id = $1
            """,
            sample_id
        )

        if not row:
            raise HTTPException(status_code=404, detail="Sample not found")

        if row["verdict"] is None:
            raise HTTPException(
                status_code=400,
                detail="Analysis not yet completed"
            )

        # Get behaviors
        behaviors = await conn.fetch(
            """
            SELECT
                behavior_type, severity, description, timestamp,
                mitre_attack_id, mitre_attack_tactic, mitre_attack_technique,
                sigma_rule_name, raw_data
            FROM behaviors
            WHERE sample_id = $1
            ORDER BY timestamp
            """,
            sample_id
        )

        # Get IOCs
        iocs = await conn.fetch(
            """
            SELECT ioc_type, value, confidence, tlp, description
            FROM iocs
            WHERE sample_id = $1
            """,
            sample_id
        )

        # Get MITRE ATT&CK mapping from report
        mitre_attack = row["report_data"].get("mitre_attack", []) if row["report_data"] else []

        # Get Sigma matches
        sigma_matches = await conn.fetch(
            """
            SELECT DISTINCT sigma_rule_name, sigma_rule_id
            FROM behaviors
            WHERE sample_id = $1 AND sigma_rule_id IS NOT NULL
            """,
            sample_id
        )

        return AnalysisResult(
            sample_id=str(sample_id),
            verdict=row["verdict"],
            confidence_score=float(row["confidence_score"]) if row["confidence_score"] else 0,
            summary=row["summary"] or "",
            behaviors=[dict(b) for b in behaviors],
            iocs=[dict(i) for i in iocs],
            mitre_attack=mitre_attack,
            sigma_matches=[dict(s) for s in sigma_matches]
        )


@app.get("/queue/status", response_model=QueueStatusResponse)
async def get_queue_status(user: dict = Depends(verify_api_key)):
    """Get current submission queue status."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        # Get queue counts
        counts = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'processing') as processing
            FROM submission_queue
            """
        )

        # Calculate estimated wait time (assume 5 min per analysis avg)
        pending = counts["pending"] or 0
        estimated_wait = pending * 300  # 5 minutes in seconds

        return QueueStatusResponse(
            pending_count=pending,
            processing_count=counts["processing"] or 0,
            estimated_wait_seconds=estimated_wait
        )


@app.get("/iocs", response_model=List[dict])
async def search_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    value: Optional[str] = Query(None, description="Search IOC value"),
    tlp: Optional[str] = Query(None, description="Filter by TLP marking"),
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(verify_api_key)
):
    """Search for Indicators of Compromise."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        query = """
            SELECT ioc_type, value, confidence, tlp, ti_tags,
                   first_seen, last_seen, sample_count
            FROM v_active_iocs
            WHERE 1=1
        """
        params = []
        param_count = 0

        if ioc_type:
            param_count += 1
            query += f" AND ioc_type = ${param_count}"
            params.append(ioc_type)

        if value:
            param_count += 1
            query += f" AND value ILIKE ${param_count}"
            params.append(f"%{value}%")

        if tlp:
            param_count += 1
            query += f" AND tlp = ${param_count}"
            params.append(tlp)

        query += f" LIMIT ${param_count + 1}"
        params.append(limit)

        rows = await conn.fetch(query, *params)
        return [dict(row) for row in rows]


@app.get("/mitre-attack")
async def get_mitre_attack_coverage(user: dict = Depends(verify_api_key)):
    """Get MITRE ATT&CK technique coverage from analyzed samples."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM v_mitre_attack_coverage")
        return [dict(row) for row in rows]


@app.delete("/samples/{sample_id}")
async def delete_sample(
    sample_id: UUID,
    user: dict = Depends(verify_api_key)
):
    """
    Delete a sample and all associated data.
    Requires admin or senior_analyst role.
    """
    if user["role"] not in ("admin", "senior_analyst"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions to delete samples"
        )

    pool = await get_db_pool()
    async with pool.acquire() as conn:
        # Check if sample exists
        sample = await conn.fetchrow(
            "SELECT id, storage_path FROM samples WHERE id = $1",
            sample_id
        )

        if not sample:
            raise HTTPException(status_code=404, detail="Sample not found")

        # Delete sample (cascade will handle related records)
        await conn.execute("DELETE FROM samples WHERE id = $1", sample_id)

        # Delete physical file
        storage_path = Path(sample["storage_path"])
        if storage_path.exists():
            storage_path.unlink()

        # Log audit event
        await conn.execute(
            """
            INSERT INTO audit_log (
                user_id, action, resource_type, resource_id,
                details, status
            ) VALUES ($1, 'sample_deleted', 'sample', $2, $3, 'success')
            """,
            user["id"], sample_id, {"file_path": str(storage_path)}
        )

    logger.info(f"Sample deleted: {sample_id}")
    return {"message": "Sample deleted successfully", "sample_id": str(sample_id)}


@app.post("/samples/batch")
async def batch_submit_samples(
    files: List[UploadFile] = File(..., description="Sample files to analyze"),
    priority: int = Query(5, ge=1, le=10, description="Analysis priority"),
    sandbox_type: Optional[str] = Query(None, description="Requested sandbox type"),
    user: dict = Depends(verify_api_key)
):
    """
    Submit multiple samples for analysis in a single request.
    Maximum 100 files per batch.
    """
    if len(files) > 100:
        raise HTTPException(
            status_code=400,
            detail="Maximum 100 files per batch submission"
        )

    results = []
    pool = await get_db_pool()

    for file in files:
        file_content = await file.read()
        file_size = len(file_content)

        if file_size == 0:
            results.append({
                "file_name": file.filename,
                "status": "error",
                "message": "Empty file"
            })
            continue

        if file_size > 100 * 1024 * 1024:
            results.append({
                "file_name": file.filename,
                "status": "error",
                "message": "File exceeds 100MB limit"
            })
            continue

        hashes = calculate_hashes(file_content)

        # Check for duplicate
        existing = await check_duplicate_sample(hashes["sha256"])
        if existing:
            results.append({
                "file_name": file.filename,
                "sample_id": str(existing["id"]),
                "sha256": hashes["sha256"],
                "status": "duplicate",
                "existing_status": existing["status"]
            })
            continue

        # Store sample
        storage_path = await store_sample(file_content, hashes["sha256"])

        # Get file type
        import magic
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_buffer(file_content[:2048])
        except ImportError:
            file_type = "application/octet-stream"

        # Insert into database
        async with pool.acquire() as conn:
            async with conn.transaction():
                sample_id = await conn.fetchval(
                    """
                    INSERT INTO samples (
                        sha256_hash, sha1_hash, md5_hash,
                        file_name, file_size, file_type, mime_type,
                        submitted_by, source_type, priority,
                        storage_path, encrypted
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    RETURNING id
                    """,
                    hashes["sha256"], hashes["sha1"], hashes["md5"],
                    file.filename, file_size, file_type, file_type,
                    user["id"], "api", priority,
                    storage_path, bool(ENCRYPTION_KEY)
                )

                # Add to submission queue
                await conn.execute(
                    """
                    INSERT INTO submission_queue (
                        sample_id, priority, requested_sandbox_type, status
                    ) VALUES ($1, $2, $3, 'pending')
                    """,
                    sample_id, priority, sandbox_type
                )

        results.append({
            "file_name": file.filename,
            "sample_id": str(sample_id),
            "sha256": hashes["sha256"],
            "status": "queued",
            "message": "Sample submitted successfully"
        })

    logger.info(f"Batch submission: {len(files)} files, {sum(1 for r in results if r['status'] == 'queued')} queued")

    return {
        "total": len(files),
        "queued": sum(1 for r in results if r["status"] == "queued"),
        "duplicates": sum(1 for r in results if r["status"] == "duplicate"),
        "errors": sum(1 for r in results if r["status"] == "error"),
        "results": results
    }


@app.delete("/queue/{queue_id}")
async def cancel_queue_item(
    queue_id: UUID,
    user: dict = Depends(verify_api_key)
):
    """
    Cancel a pending or queued analysis task.
    Only works for tasks that haven't started processing yet.
    """
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        # Check queue item status
        queue_item = await conn.fetchrow(
            "SELECT id, sample_id, status FROM submission_queue WHERE id = $1",
            queue_id
        )

        if not queue_item:
            raise HTTPException(status_code=404, detail="Queue item not found")

        if queue_item["status"] not in ("pending", "assigned"):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel task with status: {queue_item['status']}"
            )

        # Update queue status
        await conn.execute(
            """
            UPDATE submission_queue
            SET status = 'cancelled', completed_at = NOW()
            WHERE id = $1
            """,
            queue_id
        )

        # Update sample status
        await conn.execute(
            "UPDATE samples SET status = 'cancelled' WHERE id = $1",
            queue_item["sample_id"]
        )

        # Log audit event
        await conn.execute(
            """
            INSERT INTO audit_log (
                user_id, action, resource_type, resource_id,
                details, status
            ) VALUES ($1, 'analysis_cancelled', 'queue', $2, $3, 'success')
            """,
            user["id"], queue_id, {"sample_id": str(queue_item["sample_id"])}
        )

    logger.info(f"Queue item cancelled: {queue_id}")
    return {
        "message": "Analysis cancelled successfully",
        "queue_id": str(queue_id)
    }


@app.get("/samples")
async def list_samples(
    request: Request,
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    verdict_filter: Optional[str] = Query(None, description="Filter by verdict"),
    priority_filter: Optional[int] = Query(None, description="Filter by priority"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    user: dict = Depends(verify_api_key)
):
    """
    List samples with filtering and pagination.
    """
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        query = """
            SELECT id, sha256_hash, file_name, file_size, file_type,
                   status, verdict, confidence_score, priority,
                   submitted_at, analysis_completed_at
            FROM samples
            WHERE 1=1
        """
        params = []
        param_count = 0

        if status_filter:
            param_count += 1
            query += f" AND status = ${param_count}"
            params.append(status_filter)

        if verdict_filter:
            param_count += 1
            query += f" AND verdict = ${param_count}"
            params.append(verdict_filter)

        if priority_filter:
            param_count += 1
            query += f" AND priority = ${param_count}"
            params.append(priority_filter)

        param_count += 1
        query += f" ORDER BY submitted_at DESC LIMIT ${param_count}"
        params.append(limit)

        param_count += 1
        query += f" OFFSET ${param_count}"
        params.append(offset)

        rows = await conn.fetch(query, *params)

        # Get total count for pagination
        count_query = "SELECT COUNT(*) FROM samples WHERE 1=1"
        count_params = []
        if status_filter:
            count_query += " AND status = $1"
            count_params.append(status_filter)
        if verdict_filter:
            count_query += f" AND verdict = ${len(count_params) + 1}"
            count_params.append(verdict_filter)

        total = await conn.fetchval(count_query, *count_params)

        return {
            "samples": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(rows) < total
        }


# ============================================================================
# PHASE 3: AI AGENT SANDBOX ENDPOINTS
# ============================================================================

@app.post("/ai-sandbox/execute", response_model=SandboxExecutionResult)
async def execute_agent_code(
    request: SandboxExecutionRequest,
    user: dict = Depends(verify_api_key)
):
    """
    Execute AI agent code in an ephemeral sandbox.
    Phase 3: E2B / gVisor Integration
    """
    # Initialize the sandbox manager
    mode = os.getenv("E2B_MODE", "simulated")
    manager = get_e2b_manager(mode=mode)
    
    # Generate and log the egress policy that WOULD be applied
    egress_policy = generate_egress_policy(request.network_access, request.allowed_domains)
    # (In a production environment with gVisor/Docker, we'd apply this policy here)
    
    # Execute the code
    result = await manager.execute(request)
    
    # Log the execution in the database for auditing
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO audit_log (user_id, action, resource_type, details, status)
            VALUES ($1, $2, $3, $4, $5)
            """,
            user.get("id"),
            "ai_sandbox_execution",
            "execution",
            json.dumps({
                "language": request.language,
                "execution_id": result.execution_id,
                "execution_time_ms": result.execution_time_ms,
                "status": result.status
            }),
            result.status
        )

    return result

# ============================================================================
# PHASE 4: REMOTE BROWSER ISOLATION ENDPOINTS
# ============================================================================

@app.post("/isolation/browser", response_model=RBISessionResponse)
async def create_browser_session(
    request: RBISessionRequest,
    user: dict = Depends(verify_api_key)
):
    """
    Create a new containerized Remote Browser Isolation session via Kasm.
    Phase 4: Kasm Workspaces Integration
    """
    mode = os.getenv("KASM_MODE", "simulated")
    client = get_kasm_client(mode=mode)
    result = await client.create_session(request)
    
    # Log session creation
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO audit_log (user_id, action, resource_type, details, status)
            VALUES ($1, $2, $3, $4, $5)
            """,
            user.get("id"),
            "rbi_session_created",
            "kasm_session",
            json.dumps({"url": request.url, "session_id": result.session_id}),
            result.status
        )
        
    return result

@app.post("/isolation/sanitize", response_model=SanitizationResponse)
async def sanitize_document(
    file: UploadFile = File(..., description="Document to sanitize"),
    user: dict = Depends(verify_api_key)
):
    """
    Sanitize a document by converting it to safe pixels and back to PDF.
    Phase 4: Dangerzone Integration
    """
    file_content = await file.read()
    file_size = len(file_content)
    
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large for sanitization (max 50MB)")
        
    mode = os.getenv("DANGERZONE_MODE", "simulated")
    manager = get_dangerzone_manager(mode=mode)
    req = SanitizationRequest(file_name=file.filename, file_size=file_size)
    result = await manager.sanitize_document(file_content, req)
    
    # Log document sanitization
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO audit_log (user_id, action, resource_type, details, status)
            VALUES ($1, $2, $3, $4, $5)
            """,
            user.get("id"),
            "document_sanitized",
            "dangerzone_task",
            json.dumps({"file_name": file.filename, "task_id": result.task_id}),
            result.status
        )
        
    return result

# ============================================================================
# PHASE 5: ADVANCED FEATURES ENDPOINTS
# ============================================================================

@app.post("/advanced/drakvuf/submit")
async def submit_to_drakvuf(
    sample_id: str = Query(..., description="Sample Hash/ID to submit"),
    user: dict = Depends(verify_api_key)
):
    """Submit a sample for DRAKVUF hypervisor introspection."""
    mode = os.getenv("DRAKVUF_MODE", "simulated")
    client = get_drakvuf_client(mode=mode)
    job = await client.submit_sample(sample_id)
    return job

@app.get("/advanced/drakvuf/{job_id}")
async def get_drakvuf_status(job_id: str, user: dict = Depends(verify_api_key)):
    """Poll status of a DRAKVUF job."""
    mode = os.getenv("DRAKVUF_MODE", "simulated")
    client = get_drakvuf_client(mode=mode)
    report = await client.get_results(job_id)
    return report

@app.post("/advanced/cowrie/webhook", status_code=status.HTTP_202_ACCEPTED)
async def cowrie_webhook(
    event: CowrieEvent,
    x_cowrie_token: str = Header(None)
):
    """Ingest events from Cowrie honeypot."""
    expected_token = os.getenv("COWRIE_WEBHOOK_TOKEN", "dev_token_123")
    if x_cowrie_token != expected_token:
        raise HTTPException(status_code=401, detail="Invalid webhook token")
        
    parser = CowrieParser()
    parsed = parser.parse_event(event)
    
    # In a real system, we'd enqueue this to Celery and save to DB
    return {"status": "accepted", "event_type": parsed.event_type}

@app.post("/advanced/mitre/tag")
async def trigger_mitre_tagging(
    sample_id: str = Query(..., description="Sample ID to tag"),
    user: dict = Depends(verify_api_key)
):
    """Manually trigger MITRE ATT&CK tagging for a sample's behaviors."""
    tagger = MitreTagger()
    # Mock behaviors for testing
    mock_behaviors = [
        {"syscall": "CreateProcess", "process": "powershell.exe", "parent_process": "cmd.exe"},
        {"syscall": "open", "path": "payload.exe"}
    ]
    tags = tagger.analyze(mock_behaviors)
    return {"sample_id": sample_id, "tags": [t.model_dump() for t in tags]}

# ============================================================================
# Startup/Shutdown Events
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize database connection pool on startup."""
    await get_db_pool()
    logger.info("Database connection pool initialized")


@app.on_event("shutdown")
async def shutdown_event():
    """Close database connection pool on shutdown."""
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info("Database connection pool closed")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
