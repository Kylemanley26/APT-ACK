import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.cisa_kev import CISAKEVCollector
from storage.database import db
from storage.models import FeedItem, IOC, IOCType

def test_cisa_kev():
    """Test CISA KEV collection"""
    
    db.init_db()
    
    collector = CISAKEVCollector()
    
    # Show catalog stats
    print("Fetching CISA KEV catalog stats...\n")
    stats = collector.get_stats()
    
    if stats:
        print(f"Catalog: {stats['title']}")
        print(f"Version: {stats['catalog_version']}")
        print(f"Released: {stats['date_released']}")
        print(f"Total Vulnerabilities: {stats['total_vulnerabilities']}")
        print(f"Ransomware-Related: {stats['ransomware_related']}")
    
    # Collect recent entries (last 30 days)
    print(f"\nCollecting KEV entries from last 30 days...")
    count = collector.collect(days_lookback=30)
    print(f"Collected {count} new KEV entries")
    
    # Show samples
    session = db.get_session()
    try:
        kev_items = session.query(FeedItem).filter_by(source_name="CISA KEV").limit(5).all()
        
        if kev_items:
            print("\nSample KEV Entries:")
            print("-" * 80)
            for item in kev_items:
                print(f"\n{item.title}")
                print(f"Severity: {item.severity.value.upper()}")
                print(f"Score: {item.relevance_score:.2f}")
                print(f"Published: {item.published_date}")
                
                # Show CVE IOCs
                cves = [ioc for ioc in item.iocs if ioc.ioc_type.value == 'cve']
                if cves:
                    print(f"CVE: {cves[0].value}")
        
        # IOC summary
        total_cves = session.query(IOC).filter_by(ioc_type=IOCType.CVE).count()
        print(f"\n\nTotal CVEs in database: {total_cves}")
        
    finally:
        session.close()

if __name__ == "__main__":
    test_cisa_kev()