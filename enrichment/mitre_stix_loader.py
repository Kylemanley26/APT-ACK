"""
MITRE ATT&CK STIX Data Loader

Dynamically loads techniques, tactics, groups, and software from the official
MITRE ATT&CK STIX 2.1 data feed. Replaces hardcoded technique dictionaries.

Data source: https://github.com/mitre-attack/attack-stix-data
"""

import json
import os
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# Cache settings
CACHE_DIR = Path(__file__).parent.parent / "data" / "mitre"
CACHE_FILE = CACHE_DIR / "enterprise-attack.json"
CACHE_MAX_AGE_DAYS = 7  # Re-download weekly

# MITRE ATT&CK STIX URLs
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"


class MitreStixLoader:
    """Load and parse MITRE ATT&CK data from STIX 2.1 format"""
    
    def __init__(self, auto_update: bool = True):
        self.stix_data = None
        self.techniques = {}  # T1234 -> {name, tactic, description, ...}
        self.tactics = {}     # TA0001 -> {name, description}
        self.groups = {}      # G0001 -> {name, aliases, description}
        self.software = {}    # S0001 -> {name, type, description}
        self.technique_to_tactic = {}  # T1234 -> tactic_name
        
        # Keyword patterns for detection (built from technique descriptions)
        self.technique_patterns = {}
        
        if auto_update:
            self.load_data()
    
    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist"""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    def _cache_is_valid(self) -> bool:
        """Check if cached data exists and is fresh"""
        if not CACHE_FILE.exists():
            return False
        
        file_age = datetime.now() - datetime.fromtimestamp(CACHE_FILE.stat().st_mtime)
        return file_age < timedelta(days=CACHE_MAX_AGE_DAYS)
    
    def download_stix_data(self, force: bool = False) -> bool:
        """Download latest STIX data from MITRE GitHub"""
        self._ensure_cache_dir()
        
        if not force and self._cache_is_valid():
            print(f"Using cached MITRE ATT&CK data (less than {CACHE_MAX_AGE_DAYS} days old)")
            return True
        
        print("Downloading latest MITRE ATT&CK STIX data...")
        try:
            response = requests.get(STIX_URL, timeout=60)
            response.raise_for_status()
            
            with open(CACHE_FILE, 'w') as f:
                f.write(response.text)
            
            print(f"Downloaded and cached MITRE ATT&CK data to {CACHE_FILE}")
            return True
            
        except requests.RequestException as e:
            print(f"Failed to download MITRE ATT&CK data: {e}")
            return False
    
    def load_data(self) -> bool:
        """Load STIX data from cache or download"""
        # Try to download/update
        self.download_stix_data()
        
        if not CACHE_FILE.exists():
            print("No MITRE ATT&CK data available")
            return False
        
        try:
            with open(CACHE_FILE, 'r') as f:
                self.stix_data = json.load(f)
            
            self._parse_stix_objects()
            return True
            
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading MITRE ATT&CK data: {e}")
            return False
    
    def _parse_stix_objects(self):
        """Parse STIX bundle into usable dictionaries"""
        if not self.stix_data:
            return
        
        objects = self.stix_data.get('objects', [])
        
        # First pass: extract tactics (x-mitre-tactic)
        for obj in objects:
            if obj.get('type') == 'x-mitre-tactic':
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                    
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', '')
                self.tactics[tactic_id] = {
                    'id': tactic_id,
                    'stix_id': obj.get('id'),
                    'name': obj.get('name', ''),
                    'shortname': obj.get('x_mitre_shortname', ''),
                    'description': obj.get('description', '')
                }
        
        # Build shortname to name mapping for tactic lookup
        shortname_to_name = {t['shortname']: t['name'] for t in self.tactics.values()}
        
        # Second pass: extract techniques (attack-pattern)
        for obj in objects:
            if obj.get('type') == 'attack-pattern':
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                
                # Get technique ID (T1234 or T1234.001)
                external_refs = obj.get('external_references', [])
                technique_id = None
                mitre_url = None
                
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        mitre_url = ref.get('url')
                        break
                
                if not technique_id:
                    continue
                
                # Get tactic(s) from kill chain phases
                kill_chain = obj.get('kill_chain_phases', [])
                tactics = []
                for phase in kill_chain:
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        phase_name = phase.get('phase_name', '')
                        tactic_name = shortname_to_name.get(phase_name, phase_name.replace('-', ' ').title())
                        tactics.append(tactic_name)
                
                # Primary tactic (first one)
                primary_tactic = tactics[0] if tactics else 'Unknown'
                
                # Get platforms
                platforms = obj.get('x_mitre_platforms', [])
                
                # Get detection info
                detection = obj.get('x_mitre_detection', '')
                
                # Store technique
                self.techniques[technique_id] = {
                    'id': technique_id,
                    'stix_id': obj.get('id'),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'tactic': primary_tactic,
                    'tactics': tactics,  # All tactics (for multi-tactic techniques)
                    'platforms': platforms,
                    'detection': detection,
                    'url': mitre_url,
                    'is_subtechnique': '.' in technique_id
                }
                
                # Build pattern keywords from name and description
                self._extract_keywords(technique_id, obj)
        
        # Third pass: extract groups (intrusion-set)
        for obj in objects:
            if obj.get('type') == 'intrusion-set':
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                
                external_refs = obj.get('external_references', [])
                group_id = None
                
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        group_id = ref.get('external_id')
                        break
                
                if not group_id:
                    continue
                
                self.groups[group_id] = {
                    'id': group_id,
                    'stix_id': obj.get('id'),
                    'name': obj.get('name', ''),
                    'aliases': obj.get('aliases', []),
                    'description': obj.get('description', '')
                }
        
        # Fourth pass: extract software (malware and tool)
        for obj in objects:
            if obj.get('type') in ('malware', 'tool'):
                if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                
                external_refs = obj.get('external_references', [])
                software_id = None
                
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        software_id = ref.get('external_id')
                        break
                
                if not software_id:
                    continue
                
                self.software[software_id] = {
                    'id': software_id,
                    'stix_id': obj.get('id'),
                    'name': obj.get('name', ''),
                    'type': obj.get('type'),
                    'aliases': obj.get('x_mitre_aliases', []),
                    'platforms': obj.get('x_mitre_platforms', []),
                    'description': obj.get('description', '')
                }
        
        print(f"Loaded {len(self.techniques)} techniques, {len(self.tactics)} tactics, "
              f"{len(self.groups)} groups, {len(self.software)} software")
    
    def _extract_keywords(self, technique_id: str, obj: dict):
        """Extract detection keywords from technique name and description"""
        name = obj.get('name', '').lower()
        description = obj.get('description', '').lower()
        
        # Start with technique name words
        keywords = set()
        
        # Add name as keyword (excluding common words)
        name_words = name.split()
        stop_words = {'the', 'a', 'an', 'and', 'or', 'for', 'to', 'of', 'in', 'on', 'with'}
        for word in name_words:
            if word not in stop_words and len(word) > 2:
                keywords.add(word)
        
        # Add full name as phrase
        if len(name) > 3:
            keywords.add(name)
        
        # Extract key technical terms from description (first 500 chars)
        desc_snippet = description[:500]
        
        # Technical indicators to look for
        tech_patterns = [
            'powershell', 'cmd', 'bash', 'wmi', 'registry', 'scheduled task',
            'credential', 'password', 'hash', 'token', 'kerberos', 'ntlm',
            'injection', 'hooking', 'dll', 'process', 'memory', 'api',
            'persistence', 'autostart', 'service', 'driver', 'rootkit',
            'exfiltration', 'c2', 'command and control', 'beacon',
            'phishing', 'spearphishing', 'attachment', 'link',
            'exploit', 'vulnerability', 'overflow', 'rce',
            'lateral movement', 'remote', 'smb', 'ssh', 'rdp', 'winrm',
            'discovery', 'enumeration', 'reconnaissance', 'scanning'
        ]
        
        for pattern in tech_patterns:
            if pattern in desc_snippet:
                keywords.add(pattern)
        
        if keywords:
            self.technique_patterns[technique_id] = list(keywords)
    
    def get_technique(self, technique_id: str) -> Optional[dict]:
        """Get technique info by ID (T1234 or T1234.001)"""
        return self.techniques.get(technique_id.upper())
    
    def get_techniques_by_tactic(self, tactic_name: str) -> list:
        """Get all techniques for a given tactic"""
        return [t for t in self.techniques.values() if tactic_name in t.get('tactics', [])]
    
    def get_group(self, group_id: str) -> Optional[dict]:
        """Get group info by ID (G0001)"""
        return self.groups.get(group_id.upper())
    
    def get_group_by_alias(self, alias: str) -> Optional[dict]:
        """Find group by alias name"""
        alias_lower = alias.lower()
        for group in self.groups.values():
            if alias_lower == group['name'].lower():
                return group
            if alias_lower in [a.lower() for a in group.get('aliases', [])]:
                return group
        return None
    
    def get_all_tactics(self) -> list:
        """Get ordered list of all tactics"""
        # MITRE ATT&CK kill chain order
        order = [
            'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
            'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
            'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
            'Exfiltration', 'Impact'
        ]
        
        return [name for name in order if any(t['name'] == name for t in self.tactics.values())]
    
    def detect_techniques(self, text: str) -> list:
        """Detect techniques from text using keyword patterns"""
        text_lower = text.lower()
        detected = set()
        
        for technique_id, keywords in self.technique_patterns.items():
            for keyword in keywords:
                if keyword in text_lower:
                    detected.add(technique_id)
                    break
        
        return list(detected)
    
    def get_technique_metadata(self) -> dict:
        """Get technique metadata in format compatible with existing mapper"""
        return {
            tid: {
                'name': t['name'],
                'tactic': t['tactic'],
                'tactics': t['tactics'],
                'url': t.get('url', '')
            }
            for tid, t in self.techniques.items()
        }
    
    def get_technique_patterns(self) -> dict:
        """Get technique patterns in format compatible with existing mapper"""
        return self.technique_patterns.copy()
    
    def export_for_api(self) -> dict:
        """Export data structure for API endpoint"""
        # Group techniques by tactic
        by_tactic = {}
        for tactic_name in self.get_all_tactics():
            by_tactic[tactic_name] = []
        
        for technique in self.techniques.values():
            if technique['is_subtechnique']:
                continue  # Skip sub-techniques for main view
            
            for tactic in technique['tactics']:
                if tactic in by_tactic:
                    by_tactic[tactic].append({
                        'id': technique['id'],
                        'name': technique['name'],
                        'tactic': tactic,
                        'url': technique.get('url', '')
                    })
        
        # Sort techniques within each tactic
        for tactic in by_tactic:
            by_tactic[tactic].sort(key=lambda x: x['id'])
        
        return by_tactic


# Singleton instance
_loader_instance = None

def get_mitre_loader() -> MitreStixLoader:
    """Get or create singleton MitreStixLoader instance"""
    global _loader_instance
    if _loader_instance is None:
        _loader_instance = MitreStixLoader()
    return _loader_instance


if __name__ == "__main__":
    # Test the loader
    loader = MitreStixLoader()
    
    print("\n=== Tactics ===")
    for tactic in loader.get_all_tactics():
        print(f"  {tactic}")
    
    print("\n=== Sample Techniques ===")
    for tid in ['T1566', 'T1059', 'T1078', 'T1486']:
        tech = loader.get_technique(tid)
        if tech:
            print(f"  {tid}: {tech['name']} ({tech['tactic']})")
    
    print("\n=== Sample Groups ===")
    for gid in ['G0016', 'G0032', 'G0034']:
        group = loader.get_group(gid)
        if group:
            print(f"  {gid}: {group['name']} - aliases: {group.get('aliases', [])[:3]}")
    
    print("\n=== Detection Test ===")
    test_text = "The attacker used phishing emails with malicious attachments to gain initial access, then deployed PowerShell scripts for execution."
    detected = loader.detect_techniques(test_text)
    print(f"  Detected: {detected}")
