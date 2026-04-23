#!/usr/bin/env python3
"""
Advanced Cybersecurity Sandbox Platform
Database Migration Script
"""

import asyncio
import asyncpg
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sandbox:sandbox@localhost:5432/sandbox_db")
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


async def run_migration():
    """Run database migrations."""
    print(f"Connecting to database: {DATABASE_URL}")

    # Read schema file
    if not SCHEMA_PATH.exists():
        print(f"Error: Schema file not found at {SCHEMA_PATH}")
        return False

    schema_sql = SCHEMA_PATH.read_text()

    try:
        # Connect and execute
        conn = await asyncpg.connect(DATABASE_URL)
        print("Connected successfully")

        # Execute schema
        print("Executing schema SQL...")
        await conn.execute(schema_sql)
        print("Schema applied successfully")

        # Verify tables
        tables = await conn.fetch(
            """
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name
            """
        )
        print(f"\nCreated {len(tables)} tables:")
        for table in tables:
            print(f"  - {table['table_name']}")

        await conn.close()
        print("\nMigration completed successfully!")
        return True

    except asyncpg.exceptions.DuplicateTableError:
        print("Warning: Some tables already exist. Use --fresh flag to recreate.")
        return False
    except Exception as e:
        print(f"Error during migration: {e}")
        return False


async def drop_all_tables():
    """Drop all tables (for fresh start)."""
    print("Dropping all tables...")

    conn = await asyncpg.connect(DATABASE_URL)

    # Get all tables
    tables = await conn.fetch(
        """
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public'
        """
    )

    # Drop with cascade
    for table in tables:
        await conn.execute(f'DROP TABLE IF EXISTS "{table["tablename"]}" CASCADE')
        print(f"  Dropped: {table['tablename']}")

    await conn.close()
    print("All tables dropped")


async def main():
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--fresh":
        await drop_all_tables()

    success = await run_migration()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
