"""
Advanced Cybersecurity Sandbox Platform — Integrated Launcher
Runs the Dashboard (HTML UI) + REST API on a single server.
Connects to PostgreSQL. If the database is unavailable, exits with a clear error.
"""

import asyncio
import logging
import sys
import os
import json

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Add project root to path
sys.path.append(".")

# Load .env
load_dotenv()

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


async def main():
    logger.info("Starting Advanced Cybersecurity Sandbox Platform")

    # 1. Import sub-applications
    try:
        from src.frontend.dashboard import app as dashboard_app
        from src.api.submission import app as submission_app
    except Exception as e:
        logger.error(f"Failed to import application modules: {e}")
        logger.error("Ensure all dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)

    # 2. CORS — allow the dashboard to talk to the API on the same origin
    dashboard_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 3. Mount the REST API under /api/v1 so the dashboard can call it
    dashboard_app.mount("/api/v1", submission_app)

    # 4. Start server
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    config = uvicorn.Config(
        app=dashboard_app,
        host=host,
        port=port,
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips="*"
    )
    server = uvicorn.Server(config)

    logger.info(f"Server starting on http://{host}:{port}")
    logger.info("Dashboard:  http://localhost:%d/", port)
    logger.info("API Docs:   http://localhost:%d/api/v1/docs", port)
    logger.info("Health:     http://localhost:%d/api/v1/health", port)
    await server.serve()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down cleanly.")
