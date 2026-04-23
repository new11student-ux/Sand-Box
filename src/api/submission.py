"""
Advanced Cybersecurity Sandbox Platform
Sample Submission API - REST endpoints for malware sample submission and status tracking
"""

import os
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List
from uuid import UUID

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Header, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import asyncpg
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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


@app.post("/api/v1/samples", response_model=SampleSubmissionResponse)
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


@app.get("/api/v1/samples/{sample_id}", response_model=SampleStatusResponse)
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


@app.get("/api/v1/samples/{sample_id}/report", response_model=AnalysisResult)
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


@app.get("/api/v1/queue/status", response_model=QueueStatusResponse)
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


@app.get("/api/v1/iocs", response_model=List[dict])
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


@app.get("/api/v1/mitre-attack")
async def get_mitre_attack_coverage(user: dict = Depends(verify_api_key)):
    """Get MITRE ATT&CK technique coverage from analyzed samples."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM v_mitre_attack_coverage")
        return [dict(row) for row in rows]


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
