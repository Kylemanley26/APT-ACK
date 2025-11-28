#!/usr/bin/env python3
"""
Diagnose MITRE technique tagging issues
"""

import sys
sys.path.insert(0, '.')

from storage.database import db
from storage.models import FeedItem, Tag
from enrichment.mitre_attack_mapper import MitreAttackMapper

def main():
    print("=" * 60)
    print("MITRE Technique Diagnostics")
    print("=" * 60)
    
    session = db.get_session()
    
    try:
        # Count total feed items
        total_items = session.query(FeedItem).count()
        print(f"\nTotal feed items: {total_items}")
        
        # Count all tags by category
        print("\n--- Tag Categories ---")
        from sqlalchemy import func
        tag_cats = session.query(
            Tag.category,
            func.count(Tag.id)
        ).group_by(Tag.category).all()
        
        for cat, count in tag_cats:
            print(f"  {cat}: {count} tags")
        
        # Count MITRE technique tags specifically
        mitre_tags = session.query(Tag).filter_by(category='mitre_technique').all()
        print(f"\n--- MITRE Technique Tags: {len(mitre_tags)} ---")
        
        if mitre_tags:
            # Show top 10 by usage
            for tag in mitre_tags[:10]:
                item_count = len(tag.feed_items)
                print(f"  {tag.name}: {item_count} items")
        else:
            print("  NO MITRE TECHNIQUE TAGS FOUND!")
            print("\n  This means feed items haven't been enriched with MITRE techniques.")
            print("  Run: python -c \"from enrichment.mitre_attack_mapper import MitreAttackMapper; m = MitreAttackMapper(); m.enrich_all_items()\"")
        
        # Check if STIX data is loaded
        print("\n--- STIX Loader Status ---")
        mapper = MitreAttackMapper()
        if mapper.stix_loader and mapper.stix_loader.techniques:
            print(f"  STIX loaded: {len(mapper.stix_loader.techniques)} techniques available")
        else:
            print("  STIX NOT LOADED - using hardcoded patterns")
        
        # Sample a few items to see if they have content that should match
        print("\n--- Sample Feed Items (checking for technique keywords) ---")
        sample_items = session.query(FeedItem).limit(5).all()
        
        for item in sample_items:
            text = f"{item.title} {item.content[:200] if item.content else ''}"
            detected = mapper.detect_techniques(text)
            existing_mitre = [t.name for t in item.tags if t.category == 'mitre_technique']
            
            print(f"\n  [{item.id}] {item.title[:60]}...")
            print(f"      Existing MITRE tags: {existing_mitre}")
            print(f"      Would detect: {detected[:5]}")
        
    finally:
        session.close()
    
    print("\n" + "=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
