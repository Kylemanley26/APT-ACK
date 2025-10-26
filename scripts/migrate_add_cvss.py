#!/usr/bin/env python3
"""
Database migration to add CVSS fields to IOC table.
Run this ONCE after updating models.py.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.database import db
from sqlalchemy import inspect, text

def migrate_add_cvss():
    """Add CVSS columns to IOC table"""

    print("Checking IOC table structure...")

    engine = db.engine
    inspector = inspect(engine)

    # Get current columns
    columns = [col['name'] for col in inspector.get_columns('iocs')]

    # Check if migration needed
    if 'cvss_v3_score' in columns:
        print("✓ CVSS columns already exist - no migration needed")
        return

    print("Adding CVSS columns to IOC table...")

    # SQLite doesn't support multiple ADD COLUMN, so run separately
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE iocs ADD COLUMN cvss_v3_score REAL"))
            print("  ✓ Added cvss_v3_score")
        except Exception as e:
            print(f"  Note: cvss_v3_score - {e}")

        try:
            conn.execute(text("ALTER TABLE iocs ADD COLUMN cvss_v3_severity VARCHAR(20)"))
            print("  ✓ Added cvss_v3_severity")
        except Exception as e:
            print(f"  Note: cvss_v3_severity - {e}")

        try:
            conn.execute(text("ALTER TABLE iocs ADD COLUMN cvss_v3_vector VARCHAR(100)"))
            print("  ✓ Added cvss_v3_vector")
        except Exception as e:
            print(f"  Note: cvss_v3_vector - {e}")

        try:
            conn.execute(text("ALTER TABLE iocs ADD COLUMN cvss_v2_score REAL"))
            print("  ✓ Added cvss_v2_score")
        except Exception as e:
            print(f"  Note: cvss_v2_score - {e}")

        try:
            conn.execute(text("ALTER TABLE iocs ADD COLUMN cvss_v2_severity VARCHAR(20)"))
            print("  ✓ Added cvss_v2_severity")
        except Exception as e:
            print(f"  Note: cvss_v2_severity - {e}")

        conn.commit()

    print("\n✓ Migration complete!")
    print("\nNext steps:")
    print("1. Run: python scripts/test_nvd.py")
    print("   (Re-enriches CVEs with CVSS scores)")
    print("2. Run: python scripts/test_tagger.py")
    print("   (Re-calculates relevance scores using CVSS)")

if __name__ == "__main__":
    db.init_db()
    migrate_add_cvss()
