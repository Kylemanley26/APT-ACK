#!/usr/bin/env python3
"""
Cleanup Invalid MITRE Technique Tags

Removes technique tags that don't exist in STIX data.
Run this once after updating mitre_attack_mapper.py to remove legacy invalid tags.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.database import db
from storage.models import Tag, FeedItem
from enrichment.mitre_stix_loader import get_mitre_loader

def cleanup_invalid_techniques(dry_run=True):
    """Remove MITRE technique tags that don't exist in STIX data"""
    
    # Load STIX data
    loader = get_mitre_loader()
    if not loader or not loader.techniques:
        print("ERROR: Could not load STIX data")
        return
    
    valid_techniques = set(loader.techniques.keys())
    print(f"Loaded {len(valid_techniques)} valid techniques from STIX")
    
    session = db.get_session()
    
    try:
        # Find all MITRE technique tags
        mitre_tags = session.query(Tag).filter(Tag.category == 'mitre_technique').all()
        print(f"Found {len(mitre_tags)} MITRE technique tags in database")
        
        invalid_tags = []
        for tag in mitre_tags:
            # Extract technique ID from tag name (mitre-t1234 -> T1234)
            tech_id = tag.name.replace('mitre-', '').upper()
            
            if tech_id not in valid_techniques:
                invalid_tags.append((tag, tech_id, len(tag.feed_items)))
        
        print(f"\nFound {len(invalid_tags)} invalid technique tags:")
        
        # Sort by feed_item count (most referenced first)
        invalid_tags.sort(key=lambda x: x[2], reverse=True)
        
        for tag, tech_id, count in invalid_tags[:20]:  # Show top 20
            print(f"  {tech_id}: {count} items")
        
        if len(invalid_tags) > 20:
            print(f"  ... and {len(invalid_tags) - 20} more")
        
        if dry_run:
            print(f"\nDRY RUN - No changes made. Run with --execute to delete.")
            return
        
        # Delete invalid tags
        print(f"\nDeleting {len(invalid_tags)} invalid tags...")
        
        for tag, tech_id, count in invalid_tags:
            # Remove associations first
            tag.feed_items = []
            tag.iocs = []
            session.delete(tag)
        
        session.commit()
        print("Done! Invalid technique tags removed.")
        
    except Exception as e:
        print(f"Error: {e}")
        session.rollback()
    finally:
        session.close()


if __name__ == "__main__":
    dry_run = "--execute" not in sys.argv
    
    if dry_run:
        print("=== DRY RUN MODE ===")
        print("Use --execute flag to actually delete tags\n")
    else:
        print("=== EXECUTE MODE ===")
        confirm = input("This will delete invalid technique tags. Continue? [y/N] ")
        if confirm.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
    
    cleanup_invalid_techniques(dry_run=dry_run)
