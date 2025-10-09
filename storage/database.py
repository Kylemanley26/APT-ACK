from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from storage.models import Base
import os

class Database:
    def __init__(self, db_path='apt_ack.db'):
        # Always use absolute path relative to project root
        if not os.path.isabs(db_path):
            # Get project root (parent of storage directory)
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            db_path = os.path.join(project_root, db_path)
        
        self.db_path = db_path
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False)
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        
    def init_db(self):
        """Create all tables"""
        Base.metadata.create_all(self.engine)
        print(f"Database initialized at {self.db_path}")
    
    def get_session(self):
        """Get a new session"""
        return self.Session()
    
    def close(self):
        """Close the session"""
        self.Session.remove()

# Singleton instance
db = Database()