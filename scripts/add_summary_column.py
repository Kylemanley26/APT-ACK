#!/usr/bin/env python3
"""
Migration: Add summary column to feed_items table
Run this once after deploying the code update.
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import text
from storage.database import db

def migrate():
    """Add summary column to feed_items table"""
    session = db.get_session()
    
    try:
        # Check if column exists
        result = session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'feed_items' AND column_name = 'summary'
        """))
        
        if result.fetchone():
            print("Column 'summary' already exists. No migration needed.")
            return
        
        # Add the column
        session.execute(text("""
            ALTER TABLE feed_items 
            ADD COLUMN summary TEXT
        """))
        session.commit()
        print("Successfully added 'summary' column to feed_items table.")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    db.init_db()
    migrate()
