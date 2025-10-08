import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.database import db
from storage.models import FeedItem, IOC, Tag, SeverityLevel, IOCType
from datetime import datetime, UTC

def test_database():
    """Test database initialization and basic CRUD"""
    
    # Delete existing database for clean test
    if os.path.exists('apt_ack.db'):
        os.remove('apt_ack.db')
    
    # Initialize database
    db.init_db()
    
    # Create test data
    session = db.get_session()
    
    try:
        # Create a feed item
        feed = FeedItem(
            source_name="Krebs on Security",
            title="New ransomware campaign targeting healthcare",
            content="Sample content...",
            link="https://example.com/article",
            published_date=datetime.now(UTC),
            severity=SeverityLevel.HIGH,
            relevance_score=0.85
        )
        
        # Add IOC
        ioc = IOC(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            context="Command and control server",
            confidence=0.9
        )
        feed.iocs.append(ioc)
        
        # Add tags
        tag = Tag(name="ransomware", category="malware")
        feed.tags.append(tag)
        
        session.add(feed)
        session.commit()
        
        print(f"Created feed item: {feed}")
        print(f"With IOC: {ioc}")
        print(f"Tagged with: {tag}")
        
        # Query test
        items = session.query(FeedItem).filter_by(severity=SeverityLevel.HIGH).all()
        print(f"\nFound {len(items)} high severity items")
        
    except Exception as e:
        print(f"Error: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    test_database()