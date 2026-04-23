"""
Advanced Cybersecurity Sandbox Platform
Analyst Dashboard - FastAPI-based Web Interface
"""

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncpg
import os
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sandbox:sandbox@localhost:5432/sandbox_db")

app = FastAPI(
    title="Sandbox Platform Dashboard",
    description="Analyst dashboard for malware analysis",
    version="1.0.0"
)

templates = Jinja2Templates(directory="src/frontend/templates")
security = HTTPBearer()

db_pool: Optional[asyncpg.Pool] = None


async def get_db_pool():
    global db_pool
    if db_pool is None:
        db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    return db_pool


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user."""
    pool = await get_db_pool()
    api_key = credentials.credentials

    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            """
            SELECT id, username, role, permissions
            FROM users
            WHERE api_key_hash = crypt($1, api_key_hash)
            AND active = TRUE
            """,
            api_key
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )

        return dict(user)


@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Dashboard home page."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        # Get statistics
        stats = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as pending_samples,
                COUNT(*) FILTER (WHERE status = 'analyzing') as analyzing_samples,
                COUNT(*) FILTER (WHERE status = 'completed') as completed_samples,
                COUNT(*) FILTER (WHERE verdict = 'malicious') as malicious_samples,
                COUNT(*) FILTER (WHERE verdict = 'benign') as benign_samples
            FROM samples
        """)

        # Recent samples
        recent_samples = await conn.fetch("""
            SELECT id, sha256_hash, file_name, status, verdict, submitted_at
            FROM samples
            ORDER BY submitted_at DESC
            LIMIT 10
        """)

        # Recent IOCs
        recent_iocs = await conn.fetch("""
            SELECT ioc_type, value, confidence, first_seen
            FROM iocs
            ORDER BY first_seen DESC
            LIMIT 10
        """)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": dict(stats),
        "recent_samples": [dict(s) for s in recent_samples],
        "recent_iocs": [dict(i) for i in recent_iocs]
    })


@app.get("/api/stats")
async def get_dashboard_stats():
    """Get dashboard statistics."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        stats = await conn.fetchrow("""
            SELECT
                COUNT(*) as total_samples,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'analyzing') as analyzing,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE verdict = 'malicious') as malicious,
                COUNT(*) FILTER (WHERE verdict = 'benign') as benign,
                COUNT(*) FILTER (WHERE verdict = 'suspicious') as suspicious,
                AVG(confidence_score) FILTER (WHERE verdict IS NOT NULL) as avg_confidence
            FROM samples
        """)

        # Queue status
        queue_stats = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as queue_pending,
                COUNT(*) FILTER (WHERE status = 'processing') as queue_processing
            FROM submission_queue
        """)

        # Sandbox status
        sandbox_stats = await conn.fetch("""
            SELECT sandbox_type, status, COUNT(*) as count
            FROM sandboxes
            GROUP BY sandbox_type, status
        """)

        return {
            "samples": dict(stats),
            "queue": dict(queue_stats),
            "sandboxes": [dict(s) for s in sandbox_stats],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@app.get("/samples")
async def samples_list(
    request: Request,
    status_filter: Optional[str] = None,
    verdict_filter: Optional[str] = None,
    page: int = 1,
    limit: int = 20
):
    """Samples list page."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        query = """
            SELECT id, sha256_hash, file_name, status, verdict,
                   confidence_score, submitted_at, analysis_completed_at
            FROM samples
            WHERE 1=1
        """
        params = []

        if status_filter:
            query += " AND status = $" + str(len(params) + 1)
            params.append(status_filter)

        if verdict_filter:
            query += " AND verdict = $" + str(len(params) + 1)
            params.append(verdict_filter)

        query += " ORDER BY submitted_at DESC LIMIT $" + str(len(params) + 1)
        params.append(limit)

        samples = await conn.fetch(query, *params)

    return templates.TemplateResponse("samples.html", {
        "request": request,
        "samples": [dict(s) for s in samples],
        "status_filter": status_filter,
        "verdict_filter": verdict_filter
    })


@app.get("/sample/{sample_id}")
async def sample_detail(request: Request, sample_id: str):
    """Sample detail page."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        sample = await conn.fetchrow("""
            SELECT * FROM samples WHERE id = $1
        """, sample_id)

        if not sample:
            raise HTTPException(status_code=404, detail="Sample not found")

        behaviors = await conn.fetch("""
            SELECT * FROM behaviors
            WHERE sample_id = $1
            ORDER BY timestamp
        """, sample_id)

        iocs = await conn.fetch("""
            SELECT * FROM iocs
            WHERE sample_id = $1
        """, sample_id)

    return templates.TemplateResponse("sample_detail.html", {
        "request": request,
        "sample": dict(sample),
        "behaviors": [dict(b) for b in behaviors],
        "iocs": [dict(i) for i in iocs]
    })


@app.get("/iocs")
async def iocs_list(request: Request, ioc_type: Optional[str] = None):
    """IOCs list page."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        query = """
            SELECT ioc_type, value, confidence, tlp, ti_tags,
                   first_seen, last_seen, sample_count
            FROM v_active_iocs
        """
        if ioc_type:
            query += " WHERE ioc_type = $1"
            iocs = await conn.fetch(query, ioc_type)
        else:
            iocs = await conn.fetch(query)

    return templates.TemplateResponse("iocs.html", {
        "request": request,
        "iocs": [dict(i) for i in iocs],
        "ioc_type_filter": ioc_type
    })


@app.get("/mitre-attack")
async def mitre_attack_view(request: Request):
    """MITRE ATT&CK coverage view."""
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        coverage = await conn.fetch("SELECT * FROM v_mitre_attack_coverage")

    return templates.TemplateResponse("mitre_attack.html", {
        "request": request,
        "coverage": [dict(c) for c in coverage]
    })


@app.on_event("startup")
async def startup():
    await get_db_pool()


@app.on_event("shutdown")
async def shutdown():
    global db_pool
    if db_pool:
        await db_pool.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
