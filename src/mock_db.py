"""
Mock Database for Graduation Demo
Simulates asyncpg Pool and Connection to allow the dashboard to run without PostgreSQL.
"""

import asyncio
import logging
from typing import Any, List, Optional
from datetime import datetime, timezone
import uuid

logger = logging.getLogger(__name__)

class MockRecord(dict):
    """Simple dictionary-based record to simulate asyncpg.Record."""
    def __getattr__(self, name):
        return self.get(name)

class MockConnection:
    """Simulates asyncpg.Connection."""
    async def fetchrow(self, query: str, *args):
        logger.debug(f"Mock DB FetchRow: {query}")
        
        if "FROM users" in query:
            return MockRecord({
                "id": uuid.uuid4(),
                "username": "admin",
                "role": "admin",
                "permissions": '["*"]',
                "api_rate_limit": 1000
            })
            
        if "FROM samples" in query and "COUNT" in query:
            return MockRecord({
                "pending_samples": 2,
                "analyzing_samples": 1,
                "completed_samples": 45,
                "malicious_samples": 28,
                "benign_samples": 17
            })
            
        if "FROM samples" in query and "sha256_hash" in query:
            return MockRecord({
                "id": uuid.uuid4(),
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_name": "malware_sample.exe",
                "status": "completed",
                "verdict": "malicious",
                "confidence_score": 0.98,
                "submitted_at": datetime.now(timezone.utc)
            })

        return None

    async def fetch(self, query: str, *args):
        logger.debug(f"Mock DB Fetch: {query}")
        
        if "FROM samples" in query:
            return [
                MockRecord({
                    "id": uuid.uuid4(),
                    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "file_name": "wannacry.exe",
                    "status": "completed",
                    "verdict": "malicious",
                    "submitted_at": datetime.now(timezone.utc)
                }),
                MockRecord({
                    "id": uuid.uuid4(),
                    "sha256_hash": "5d41402abc4b2a76b9719d911017c592",
                    "file_name": "clean_report.pdf",
                    "status": "completed",
                    "verdict": "benign",
                    "submitted_at": datetime.now(timezone.utc)
                })
            ]
            
        if "FROM iocs" in query:
            return [
                MockRecord({"ioc_type": "ip", "value": "185.122.1.5", "confidence": "high", "first_seen": datetime.now(timezone.utc)}),
                MockRecord({"ioc_type": "domain", "value": "malicious-c2.com", "confidence": "high", "first_seen": datetime.now(timezone.utc)})
            ]
            
        return []

    async def fetchval(self, query: str, *args):
        logger.debug(f"Mock DB FetchVal: {query}")
        if "INSERT INTO samples" in query:
            return uuid.uuid4()
        return 1

    async def execute(self, query: str, *args):
        logger.debug(f"Mock DB Execute: {query}")
        return "OK"

    async def transaction(self):
        class MockTransaction:
            async def __aenter__(self): return self
            async def __aexit__(self, exc_type, exc, tb): pass
        return MockTransaction()

    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc, tb): pass

class MockDBPool:
    """Simulates asyncpg.Pool."""
    def acquire(self):
        return MockConnection()

    async def release(self, connection):
        pass

    async def close(self):
        pass

async def create_mock_pool(*args, **kwargs):
    logger.info("🎨 Initializing Mock Database Pool for Demo Mode")
    return MockDBPool()
