#!/usr/bin/env python3
"""
APT-ACK Collection Pipeline with MITRE ATT&CK Mapping
"""
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
from enrichment.mitre_attack_mapper import MitreAttackMapper

class ThreatIntelOrchestrator:
    def __init__(self):
        self.start_time = datetime.now(UTC)
        self.stats = {
            'rss_items': 0,
            'kev_items': 0,
            'iocs_extracted': 0,
            'items_tagged': 0,
            'cves_enriched': 0,
            'mitre_mapped': 0
        }
    
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
    
    def run_mitre_mapping(self):
        """Map threat intel to MITRE ATT&CK techniques"""
        self.log("Starting MITRE ATT&CK mapping...")
        
        try:
            mapper = MitreAttackMapper()
            total = mapper.enrich_all_items()
            
            self.stats['mitre_mapped'] = total
            self.log(f"MITRE mapping complete: {total} items enriched")
            return True
            
        except Exception as e:
            self.log(f"ERROR in MITRE mapping: {e}")
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
        print(f"  MITRE Techniques Mapped: {self.stats['mitre_mapped']}")
        print(f"  CVEs Enriched: {self.stats['cves_enriched']}")
        print("\n" + "="*80 + "\n")
    
    def run_full_pipeline(self, skip_nvd=False, skip_mitre=False, nvd_limit=None):
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
        
        # MITRE ATT&CK mapping (NEW)
        if not skip_mitre:
            self.run_mitre_mapping()
        else:
            self.log("Skipping MITRE ATT&CK mapping")
        
        # NVD enrichment (optional, can be slow)
        if not skip_nvd:
            self.run_nvd_enrichment(limit=nvd_limit)
        else:
            self.log("Skipping NVD enrichment (use --enrich-nvd to enable)")
        
        # Summary
        self.print_summary()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='APT-ACK Threat Intelligence Orchestrator')
    parser.add_argument('--skip-nvd', action='store_true', 
                       help='Skip NVD enrichment (faster)')
    parser.add_argument('--skip-mitre', action='store_true',
                       help='Skip MITRE ATT&CK mapping')
    parser.add_argument('--nvd-limit', type=int, default=None,
                       help='Limit number of CVEs to enrich (for testing)')
    
    args = parser.parse_args()
    
    orchestrator = ThreatIntelOrchestrator()
    orchestrator.run_full_pipeline(
        skip_nvd=args.skip_nvd,
        skip_mitre=args.skip_mitre,
        nvd_limit=args.nvd_limit
    )

if __name__ == "__main__":
    main()
