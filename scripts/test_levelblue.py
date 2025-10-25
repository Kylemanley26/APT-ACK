# scripts/test_levelblue.py
import sys
import os
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.levelblue_otx import LevelBlueCollector
from storage.database import db

def test_levelblue():
    """Test LevelBlue OTX integration"""
    
    api_key = os.environ.get('LEVELBLUE_API_KEY')
    if not api_key:
        print("ERROR: LEVELBLUE_API_KEY not set in .env")
        print("Get your key at: https://otx.alienvault.com/")
        return
    
    db.init_db()
    
    collector = LevelBlueCollector(api_key=api_key)
    
    # Test 1: Enrich recent IOCs
    print("="*80)
    print("ENRICHING RECENT IOCs")
    print("="*80)
    enriched = collector.enrich_recent_iocs(days=30, limit=20)
    print(f"\nEnriched {enriched} IOCs")
    
    # Test 2: Collect threat pulses
    print("\n" + "="*80)
    print("COLLECTING THREAT PULSES")
    print("="*80)
    pulses = collector.collect_pulses(days_back=7)
    print(f"\nCollected {pulses} pulses")

if __name__ == "__main__":
    test_levelblue()