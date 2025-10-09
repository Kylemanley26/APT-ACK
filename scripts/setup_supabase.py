import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import text
from storage.database import db

def setup_supabase_features():
    """Enable Supabase realtime and RLS"""
    
    if not db.is_postgres:
        print("Not using PostgreSQL. Skipping Supabase setup.")
        return
    
    print("Setting up Supabase features...")
    
    session = db.get_session()
    
    try:
        # Enable realtime for tables
        print("\nEnabling realtime replication...")
        
        tables = ['feed_items', 'iocs', 'tags', 'alerts']
        
        for table in tables:
            try:
                session.execute(text(f"""
                    ALTER PUBLICATION supabase_realtime ADD TABLE {table};
                """))
                print(f"  ✓ Enabled realtime for {table}")
            except Exception as e:
                print(f"  - Realtime already enabled for {table} or error: {e}")
        
        session.commit()
        
        # Row Level Security (RLS) - disabled for now since this is single-user
        print("\nRow Level Security:")
        print("  - RLS disabled (single-user application)")
        print("  - To enable RLS, go to Supabase Dashboard → Authentication")
        
        print("\n✓ Supabase features configured")
        print("\nNext: Enable realtime in Supabase Dashboard:")
        print("1. Go to Database → Replication")
        print("2. Enable replication for tables")
        
    except Exception as e:
        print(f"Error: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    setup_supabase_features()