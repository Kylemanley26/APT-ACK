#!/usr/bin/env python3
"""
Debug the /api/techniques endpoint output
"""
import sys
sys.path.insert(0, '.')

from enrichment.mitre_attack_mapper import MitreAttackMapper
from enrichment.mitre_stix_loader import get_mitre_loader
from storage.database import db
from storage.models import Tag, FeedItem
from sqlalchemy import func

def main():
    print("=" * 60)
    print("API Techniques Debug")
    print("=" * 60)
    
    # Check STIX loader
    loader = get_mitre_loader()
    print(f"\nSTIX techniques loaded: {len(loader.techniques)}")
    
    # Sample some sub-techniques
    sample_subs = ['T1037.005', 'T1547.009', 'T1055.012']
    print("\n--- Sub-technique lookups ---")
    for tid in sample_subs:
        tech = loader.get_technique(tid)
        if tech:
            print(f"  {tid}: {tech['name']} -> {tech['tactic']}")
        else:
            print(f"  {tid}: NOT FOUND IN STIX")
            # Try parent
            parent = loader.get_technique(tid.split('.')[0])
            if parent:
                print(f"    Parent {tid.split('.')[0]}: {parent['name']} -> {parent['tactic']}")
    
    # Check what's in the database
    session = db.get_session()
    try:
        print("\n--- Database MITRE tags (sample) ---")
        mitre_tags = session.query(
            Tag.name,
            func.count(FeedItem.id).label('count')
        ).join(FeedItem.tags).filter(
            Tag.category == 'mitre_technique'
        ).group_by(Tag.name).order_by(func.count(FeedItem.id).desc()).limit(20).all()
        
        if not mitre_tags:
            print("  NO MITRE TAGS FOUND!")
            return
        
        print(f"  Found {len(mitre_tags)} technique tags")
        
        # Check tactic resolution for each
        mapper = MitreAttackMapper()
        
        tactic_counts = {}
        print("\n--- Tag -> Tactic Resolution ---")
        for tag_name, count in mitre_tags[:15]:
            tech_id = tag_name.replace('mitre-', '').upper()
            info = mapper.get_technique_info(tech_id)
            tactic = info['tactic']
            
            print(f"  {tag_name} ({count}) -> {tech_id} -> {tactic}")
            
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        print("\n--- Tactic Distribution ---")
        for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
            print(f"  {tactic}: {count}")
        
    finally:
        session.close()

if __name__ == "__main__":
    main()
