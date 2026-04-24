"""
Data Retention Policy Enforcer
Soft and hard deletes data exceeding configured TTLs.
"""

from datetime import datetime, timedelta, timezone
import asyncpg
import logging
import json
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RetentionPolicy:
    def __init__(self, db_pool, config: dict):
        self.db = db_pool
        # Default rules if not provided
        self.ttl_rules = config.get("ttl_rules", {
            "samples": 30,
            "behaviors": 60,
            "iocs": 90,
            "audit_log": 365
        })
        self.grace_period_days = config.get("grace_period_days", 7)
    
    async def enforce_retention(self):
        """Delete data exceeding TTL, with audit logging."""
        logger.info("Starting retention policy enforcement.")
        
        for entity, days in self.ttl_rules.items():
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            logger.info(f"Enforcing TTL for {entity} older than {cutoff}")
            
            async with self.db.acquire() as conn:
                async with conn.transaction():
                    if entity == "samples":
                        # Soft delete first (mark as deferred or similar)
                        await conn.execute(
                            f"UPDATE samples SET status='deferred' WHERE created_at < $1 AND status != 'deferred'",
                            cutoff
                        )
                        
                        # Hard delete after grace period
                        hard_cutoff = cutoff - timedelta(days=self.grace_period_days)
                        deleted = await conn.fetchval(
                            f"WITH deleted AS (DELETE FROM samples WHERE status='deferred' AND created_at < $1 RETURNING *) SELECT count(*) FROM deleted",
                            hard_cutoff
                        )
                        if deleted > 0:
                            await self._log_deletion(conn, entity, deleted, hard_cutoff)
                    else:
                        # Direct hard delete for other tables based on created_at
                        deleted = await conn.fetchval(
                            f"WITH deleted AS (DELETE FROM {entity} WHERE created_at < $1 RETURNING *) SELECT count(*) FROM deleted",
                            cutoff
                        )
                        if deleted > 0:
                            await self._log_deletion(conn, entity, deleted, cutoff)

    async def _log_deletion(self, conn, entity: str, count: int, cutoff: datetime):
        logger.info(f"Deleted {count} records from {entity} older than {cutoff}")
        await conn.execute(
            """
            INSERT INTO audit_log (action, resource_type, details, status)
            VALUES ($1, $2, $3, $4)
            """,
            "data_retention_purge",
            entity,
            json.dumps({"records_deleted": count, "cutoff_date": cutoff.isoformat()}),
            "success"
        )

# Entry point for cron job
if __name__ == "__main__":
    import asyncio
    
    async def main():
        db_url = os.getenv("DATABASE_URL", "postgresql://sandbox:sandbox@localhost:5432/sandbox_db")
        pool = await asyncpg.create_pool(db_url)
        policy = RetentionPolicy(pool, {})
        await policy.enforce_retention()
        await pool.close()
        
    asyncio.run(main())
