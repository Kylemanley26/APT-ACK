import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from enrichment.ioc_extractor import IOCExtractor
from storage.database import db
from storage.models import FeedItem, IOC

def test_extractor():
    """Test IOC extraction"""
    
    db.init_db()
    
    extractor = IOCExtractor()
    
    print("Processing unprocessed feed items...")
    total = extractor.process_all_unprocessed()
    
    print(f"\nTotal IOCs extracted: {total}")
    
    # Show summary
    session = db.get_session()
    try:
        iocs = session.query(IOC).all()
        
        print("\nIOC Summary:")
        for ioc_type in set(ioc.ioc_type for ioc in iocs):
            count = len([i for i in iocs if i.ioc_type == ioc_type])
            print(f"  {ioc_type.value}: {count}")
        
        print("\nSample IOCs:")
        for ioc in iocs[:10]:
            print(f"  [{ioc.ioc_type.value}] {ioc.value} (confidence: {ioc.confidence:.2f})")
    
    finally:
        session.close()

if __name__ == "__main__":
    test_extractor()