from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from storage.models import Base
import os

class Database:
    def __init__(self, db_url=None):
        """
        Initialize database connection
        db_url: Database URL (PostgreSQL or SQLite)
                If None, uses DATABASE_URL env var or defaults to SQLite
        """
        if db_url is None:
            db_url = os.environ.get('DATABASE_URL')
        
        if db_url is None:
            # Default to SQLite
            db_path = 'apt_ack.db'
            if not os.path.isabs(db_path):
                project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
                db_path = os.path.join(project_root, db_path)
            db_url = f'sqlite:///{db_path}'
        
        self.db_url = db_url
        self.is_postgres = db_url.startswith('postgresql')
        
        # Create engine with appropriate settings
        if self.is_postgres:
            self.engine = create_engine(db_url, echo=False, pool_pre_ping=True)
        else:
            self.engine = create_engine(db_url, echo=False)
        
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        
    def init_db(self):
        """Create all tables"""
        Base.metadata.create_all(self.engine)
        db_type = "PostgreSQL" if self.is_postgres else "SQLite"
        print(f"Database initialized ({db_type})")
    
    def get_session(self):
        """Get a new session"""
        return self.Session()
    
    def close(self):
        """Close the session"""
        self.Session.remove()

# Singleton instance
db = Database()