import sys
import os
from datetime import datetime, UTC

from dotenv import load_dotenv

# Load .env file
load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import yaml

from storage.database import db
from collectors.rss_feeds import RSSCollector
from collectors.cisa_kev import CISAKEVCollector
from collectors.nvd_api import NVDCollector
from enrichment.ioc_extractor import IOCExtractor
from enrichment.tagging_engine import ThreatTagger

class ThreatIntelOrchestrator:
    def __init__(self):
        self.start_time = datetime.now(UTC)
        self.stats = {
            'rss_items': 0,
            'kev_items': 0,
            'iocs_extracted': 0,
            'items_tagged': 0,
            'cves_enriched': 0
        }
    def run_levelblue_enrichment(self, days=7, limit=100):
        self.log("Starting LevelBlue OTX enrichment...")
        
        try:
            api_key = os.environ.get('LEVELBLUE_API_KEY')
            if not api_key:
                self.log("No LEVELBLUE_API_KEY found, skipping")
                return False
            
            from collectors.levelblue_otx import LevelBlueCollector
            collector = LevelBlueCollector(api_key=api_key)
            
            # Enrich IOCs
            enriched = collector.enrich_recent_iocs(days=days, limit=limit)
            self.stats['iocs_enriched'] = enriched
            
            # Collect pulses
            pulses = collector.collect_pulses(days_back=days)
            self.stats['otx_pulses'] = pulses
            
            self.log(f"LevelBlue enrichment complete: {enriched} IOCs, {pulses} pulses")
            return True
            
        except Exception as e:
            self.log(f"ERROR in LevelBlue enrichment: {e}")
            return False
    
    def log(self, message):
        """Simple logging with timestamp"""
        timestamp = datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}")
    
    def run_rss_collection(self):
        """Collect from RSS feeds"""
        self.log("Starting RSS collection...")
        
        try:
            with open('config/sources.yaml', 'r') as f:
                config = yaml.safe_load(f)
            
            collector = RSSCollector()
            total = collector.collect_all(config['rss_feeds'])
            
            self.stats['rss_items'] = total
            self.log(f"RSS collection complete: {total} new items")
            return True
            
        except Exception as e:
            self.log(f"ERROR in RSS collection: {e}")
            return False
    
    def run_cisa_kev_collection(self, days_lookback=7):
        """Collect from CISA KEV catalog"""
        self.log("Starting CISA KEV collection...")
        
        try:
            collector = CISAKEVCollector()
            total = collector.collect(days_lookback=days_lookback)
            
            self.stats['kev_items'] = total
            self.log(f"CISA KEV collection complete: {total} new items")
            return True
            
        except Exception as e:
            self.log(f"ERROR in CISA KEV collection: {e}")
            return False
    
    def run_ioc_extraction(self):
        """Extract IOCs from unprocessed items"""
        self.log("Starting IOC extraction...")
        
        try:
            extractor = IOCExtractor()
            total = extractor.process_all_unprocessed()
            
            self.stats['iocs_extracted'] = total
            self.log(f"IOC extraction complete: {total} IOCs extracted")
            return True
            
        except Exception as e:
            self.log(f"ERROR in IOC extraction: {e}")
            return False
    
    def run_tagging(self):
        """Tag and score untagged items"""
        self.log("Starting threat tagging...")
        
        try:
            tagger = ThreatTagger()
            total = tagger.tag_all_untagged()
            
            self.stats['items_tagged'] = total
            self.log(f"Tagging complete: {total} items tagged")
            return True
            
        except Exception as e:
            self.log(f"ERROR in tagging: {e}")
            return False
    
    def run_nvd_enrichment(self, limit=None):
        """Enrich CVEs with NVD data"""
        self.log("Starting NVD enrichment...")
        
        try:
            api_key = os.environ.get('NVD_API_KEY')
            collector = NVDCollector(api_key=api_key)
            total = collector.enrich_all_cves(limit=limit)
            
            self.stats['cves_enriched'] = total
            self.log(f"NVD enrichment complete: {total} CVEs enriched")
            return True
            
        except Exception as e:
            self.log(f"ERROR in NVD enrichment: {e}")
            return False
    
    def print_summary(self):
        """Print execution summary"""
        duration = (datetime.now(UTC) - self.start_time).total_seconds()
        
        print("\n" + "="*80)
        print("COLLECTION RUN SUMMARY".center(80))
        print("="*80)
        print(f"\nExecution Time: {duration:.1f} seconds")
        print("\nResults:")
        print(f"  RSS Items Collected: {self.stats['rss_items']}")
        print(f"  CISA KEV Items: {self.stats['kev_items']}")
        print(f"  IOCs Extracted: {self.stats['iocs_extracted']}")
        print(f"  Items Tagged: {self.stats['items_tagged']}")
        print(f"  CVEs Enriched: {self.stats['cves_enriched']}")
        print("\n" + "="*80 + "\n")
    
    def run_full_pipeline(self, skip_nvd=False, nvd_limit=None, use_levelblue=True):
        """Run complete collection and enrichment pipeline"""
        self.log("="*80)
        self.log("APT-ACK THREAT INTELLIGENCE COLLECTION STARTED")
        self.log("="*80)
        
        # Initialize database
        db.init_db()
        
        # Run collection
        self.run_rss_collection()
        self.run_cisa_kev_collection(days_lookback=7)
        
        # Run enrichment
        self.run_ioc_extraction()
        self.run_tagging()
        
        # NVD enrichment (optional, can be slow)
        if not skip_nvd:
            self.run_nvd_enrichment(limit=nvd_limit)
        else:
            self.log("Skipping NVD enrichment (use --enrich-nvd to enable)")
        
        if use_levelblue:
            self.run_levelblue_enrichment(days=7, limit=100)
        
        # Summary
        self.print_summary()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='APT-ACK Threat Intelligence Orchestrator')
    parser.add_argument('--skip-nvd', action='store_true', 
                       help='Skip NVD enrichment (faster)')
    parser.add_argument('--nvd-limit', type=int, default=None,
                       help='Limit number of CVEs to enrich (for testing)')
    
    args = parser.parse_args()
    
    orchestrator = ThreatIntelOrchestrator()
    orchestrator.run_full_pipeline(
        skip_nvd=args.skip_nvd,
        nvd_limit=args.nvd_limit
    )

if __name__ == "__main__":
    main()