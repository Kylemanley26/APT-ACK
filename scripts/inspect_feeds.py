import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.database import db
from storage.models import FeedItem

def inspect_feeds():
    """Inspect collected feed content"""
    
    session = db.get_session()
    
    try:
        items = session.query(FeedItem).limit(3).all()
        
        for item in items:
            print(f"\n{'='*80}")
            print(f"Title: {item.title}")
            print(f"Source: {item.source_name}")
            print(f"Link: {item.link}")
            print(f"\nContent preview:")
            print(item.content[:500])
            print(f"\n{'='*80}")
    
    finally:
        session.close()

if __name__ == "__main__":
    inspect_feeds()