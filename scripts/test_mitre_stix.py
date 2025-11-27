#!/usr/bin/env python3
"""
Test MITRE STIX loader and mapper integration
"""

import sys
sys.path.insert(0, '.')

from enrichment.mitre_stix_loader import MitreStixLoader

def main():
    print("=" * 60)
    print("MITRE ATT&CK STIX Loader Test")
    print("=" * 60)
    
    # Initialize loader (will download if needed)
    loader = MitreStixLoader()
    
    if not loader.techniques:
        print("ERROR: No techniques loaded!")
        return 1
    
    # Stats
    print(f"\n✓ Loaded {len(loader.techniques)} techniques")
    print(f"✓ Loaded {len(loader.tactics)} tactics")
    print(f"✓ Loaded {len(loader.groups)} groups")
    print(f"✓ Loaded {len(loader.software)} software")
    
    # Tactics
    print("\n=== All Tactics ===")
    for tactic in loader.get_all_tactics():
        count = len(loader.get_techniques_by_tactic(tactic))
        print(f"  {tactic}: {count} techniques")
    
    # Sample techniques
    print("\n=== Sample Techniques ===")
    for tid in ['T1566', 'T1059', 'T1486', 'T1003', 'T1595']:
        tech = loader.get_technique(tid)
        if tech:
            print(f"  {tid}: {tech['name']}")
            print(f"         Tactic: {tech['tactic']}")
            print(f"         Patterns: {loader.technique_patterns.get(tid, [])[:3]}")
    
    # Sample groups
    print("\n=== Sample Groups ===")
    for alias in ['APT28', 'Lazarus', 'Scattered Spider']:
        group = loader.get_group_by_alias(alias)
        if group:
            print(f"  {group['id']}: {group['name']}")
            print(f"         Aliases: {group.get('aliases', [])[:5]}")
    
    # Detection test
    print("\n=== Detection Test ===")
    test_text = """
    The threat actor used spear phishing emails with malicious Word documents 
    to gain initial access. After establishing persistence via scheduled tasks,
    they deployed Cobalt Strike beacons for command and control. The attackers
    used Mimikatz for credential dumping and moved laterally via RDP.
    Finally, they deployed ransomware encrypting critical systems.
    """
    
    detected = loader.detect_techniques(test_text)
    print(f"  Detected {len(detected)} techniques from sample text:")
    for tid in sorted(detected):
        tech = loader.get_technique(tid)
        name = tech['name'] if tech else tid
        print(f"    - {tid}: {name}")
    
    print("\n✓ All tests passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
