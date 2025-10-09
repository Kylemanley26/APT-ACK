from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from storage.models import Base
import os

class Database:
    def __init__(self, db_url=None):
        """
        Initialize database connection
        - Production (Railway): Requires DATABASE_URL (PostgreSQL)
        - Development: Falls back to SQLite if DATABASE_URL not set
        """
        # Get database URL
        if db_url is None:
            db_url = os.environ.get('DATABASE_URL')
        
        # Check if in production environment
        is_production = os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('RENDER') or os.environ.get('FLY_APP_NAME')
        
        if db_url is None:
            if is_production:
                raise ValueError(
                    "DATABASE_URL environment variable must be set in production. "
                    "Add your PostgreSQL connection string to Railway variables."
                )
            else:
                # Development: use SQLite
                db_path = 'apt_ack.db'
                if not os.path.isabs(db_path):
                    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
                    db_path = os.path.join(project_root, db_path)
                db_url = f'sqlite:///{db_path}'
                print(f"⚠️  Using SQLite for local development: {db_path}")
        
        self.db_url = db_url
        self.is_postgres = db_url.startswith('postgresql')
        self.is_production = is_production
        
        # Create engine
        if self.is_postgres:
            self.engine = create_engine(
                db_url,
                echo=False,
                pool_pre_ping=True,
                pool_size=5,
                max_overflow=10
            )
        else:
            self.engine = create_engine(db_url, echo=False)
        
        self.Session = scoped_session(sessionmaker(bind=self.engine))
    
    def init_db(self):
        """Create all tables"""
        Base.metadata.create_all(self.engine)
        
        db_type = "PostgreSQL" if self.is_postgres else "SQLite"
        env = "Production" if self.is_production else "Development"
        print(f"✓ Database initialized: {db_type} ({env})")
    
    def get_session(self):
        """Get a new session"""
        return self.Session()
    
    def close(self):
        """Close the session"""
        self.Session.remove()
    
    def health_check(self):
        """Check database connectivity"""
        try:
            session = self.get_session()
            session.execute("SELECT 1")
            session.close()
            return True
        except Exception as e:
            print(f"✗ Database health check failed: {e}")
            return False

# Singleton instance
db = Database()