import sys
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.nvd_api import NVDCollector
from storage.database import db
from storage.models import IOC, IOCType

def test_nvd():
    """Test NVD enrichment"""
    
    db.init_db()
    
    # Check for API key in environment
    api_key = os.environ.get('NVD_API_KEY')
    
    if api_key:
        print(f"Using NVD API key (faster rate limits)")
    else:
        print("No NVD API key found. Using public rate limits (slower).")
        print("To speed up, set NVD_API_KEY environment variable.")
        print("Get a key at: https://nvd.nist.gov/developers/request-an-api-key\n")
    
    collector = NVDCollector(api_key=api_key)
    
    # Show CVE count
    session = db.get_session()
    try:
        total_cves = session.query(IOC).filter_by(ioc_type=IOCType.CVE).count()
        unenriched = session.query(IOC).filter(
            IOC.ioc_type == IOCType.CVE,
            IOC.mitre_techniques.is_(None)
        ).count()
        
        print(f"Total CVEs: {total_cves}")
        print(f"Unenriched CVEs: {unenriched}\n")
    finally:
        session.close()
    
    # Enrich CVEs (limit to 10 for testing to avoid rate limits)
    print("Enriching CVEs from NVD (limiting to 10 for test)...\n")
    count = collector.enrich_all_cves(limit=10)
    
    # Show enriched samples
    session = db.get_session()
    try:
        enriched_cves = session.query(IOC).filter(
            IOC.ioc_type == IOCType.CVE,
            IOC.mitre_techniques.isnot(None)
        ).limit(5).all()
        
        if enriched_cves:
            print("\n" + "="*80)
            print("Sample Enriched CVEs:")
            print("="*80)
            
            for ioc in enriched_cves:
                print(f"\n{ioc.value}")
                print(f"  Confidence: {ioc.confidence:.2f}")
                if ioc.mitre_techniques:
                    print(f"  CWE: {ioc.mitre_techniques}")
                if ioc.context:
                    print(f"  Description: {ioc.context[:200]}...")
                
                # Get associated feed item
                if ioc.feed_item:
                    print(f"  Source: {ioc.feed_item.source_name}")
                    print(f"  Link: {ioc.feed_item.link}")
    
    finally:
        session.close()

if __name__ == "__main__":
    test_nvd()