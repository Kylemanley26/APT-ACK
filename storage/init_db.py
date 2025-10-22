from sqlalchemy import text
from storage.database import db
from storage.models import Base

def init_db_safe():
    """Initialize database with idempotent ENUM creation for PostgreSQL"""
    engine = db.engine
    
    # Only create ENUMs for PostgreSQL
    if db.is_postgres:
        with engine.connect() as conn:
            # Create SeverityLevel ENUM if it doesn't exist
            conn.execute(text("""
                DO $$ BEGIN
                    CREATE TYPE severitylevel AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            
            # Create IOCType ENUM if it doesn't exist
            conn.execute(text("""
                DO $$ BEGIN
                    CREATE TYPE ioctype AS ENUM ('IP', 'DOMAIN', 'URL', 'CVE', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'EMAIL', 'FILE_PATH');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            
            conn.commit()
    
    # Create all tables
    Base.metadata.create_all(engine)
    
    db_type = "PostgreSQL" if db.is_postgres else "SQLite"
    env = "Production" if db.is_production else "Development"
    print(f"✓ Database initialized: {db_type} ({env})")