import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from enrichment.tagging_engine import ThreatTagger
from storage.database import db
from storage.models import FeedItem, SeverityLevel

def test_tagger():
    """Test tagging engine"""
    
    db.init_db()
    
    tagger = ThreatTagger()
    
    print("Tagging feed items...\n")
    count = tagger.tag_all_untagged()
    
    print(f"\nTagged {count} items")
    
    # Show summary by severity
    session = db.get_session()
    try:
        print("\nSeverity Breakdown:")
        for severity in SeverityLevel:
            count = session.query(FeedItem).filter_by(severity=severity).count()
            if count > 0:
                print(f"  {severity.value.upper()}: {count}")
        
        # Show high priority items
        print("\nHigh Priority Items:")
        high_priority = session.query(FeedItem).filter(
            FeedItem.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        ).order_by(FeedItem.relevance_score.desc()).limit(5).all()
        
        for item in high_priority:
            tags_str = ', '.join([t.name for t in item.tags[:5]])
            print(f"\n  [{item.severity.value.upper()}] {item.title}")
            print(f"  Score: {item.relevance_score:.2f} | Tags: {tags_str}")
            print(f"  Link: {item.link}")
    
    finally:
        session.close()

if __name__ == "__main__":
    test_tagger()