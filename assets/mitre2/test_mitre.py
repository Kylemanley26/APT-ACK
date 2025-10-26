import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from enrichment.mitre_attack_mapper import MitreAttackMapper
from storage.database import db
from storage.models import FeedItem, Tag

def test_mitre_mapping():
    """Test MITRE ATT&CK technique mapping"""
    
    db.init_db()
    
    mapper = MitreAttackMapper()
    
    print("="*80)
    print("MITRE ATT&CK TECHNIQUE MAPPING")
    print("="*80)
    
    # Enrich all items
    print("\nEnriching feed items with MITRE ATT&CK techniques...")
    count = mapper.enrich_all_items()
    
    # Show technique matrix
    print("\n" + "="*80)
    print("TECHNIQUE COVERAGE MATRIX")
    print("="*80)
    
    matrix = mapper.export_technique_matrix()
    
    # Group by tactic
    by_tactic = {}
    for tech_id, info in matrix.items():
        tactic = info['tactic']
        if tactic not in by_tactic:
            by_tactic[tactic] = []
        by_tactic[tactic].append((tech_id, info['name'], info['count']))
    
    for tactic in sorted(by_tactic.keys()):
        print(f"\n{tactic}:")
        techniques = sorted(by_tactic[tactic], key=lambda x: x[2], reverse=True)
        for tech_id, name, count in techniques:
            print(f"  {tech_id}: {name} ({count} items)")
    
    # Show sample enriched items
    print("\n" + "="*80)
    print("SAMPLE ENRICHED ITEMS")
    print("="*80)
    
    session = db.get_session()
    try:
        items = session.query(FeedItem).join(FeedItem.tags).filter(
            Tag.category == 'mitre_technique'
        ).limit(5).all()
        
        for item in items:
            mitre_tags = [t for t in item.tags if t.category == 'mitre_technique']
            techniques = [t.name.replace('mitre-', '').upper() for t in mitre_tags]
            
            print(f"\n{item.title}")
            print(f"Severity: {item.severity.value.upper()} | Score: {item.relevance_score:.2f}")
            print(f"Techniques: {', '.join(techniques[:10])}")
            
            # Show technique details
            for tech_id in techniques[:3]:
                info = mapper.get_technique_info(tech_id)
                print(f"  - {tech_id}: {info['name']} ({info['tactic']})")
    
    finally:
        session.close()
    
    print("\n" + "="*80)
    print(f"✓ MITRE mapping complete - {count} items enriched")
    print("="*80)

if __name__ == "__main__":
    test_mitre_mapping()
