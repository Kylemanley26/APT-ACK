"""
MITRE ATT&CK Mapper for APT-ACK

Maps feed items to MITRE ATT&CK techniques using:
1. Dynamic STIX data from official MITRE feed (primary)
2. Fallback hardcoded patterns (if STIX unavailable)
3. Malware family to technique associations
"""

import re
from typing import TYPE_CHECKING, Any, Optional
from storage.database import db
from storage.models import FeedItem, IOC, Tag

# Try to import STIX loader, fall back gracefully
STIX_AVAILABLE = False
get_mitre_loader = None

try:
    from enrichment.mitre_stix_loader import get_mitre_loader as _get_mitre_loader, MitreStixLoader
    STIX_AVAILABLE = True
    get_mitre_loader = _get_mitre_loader
except ImportError:
    print("Warning: MITRE STIX loader not available, using hardcoded patterns")

if TYPE_CHECKING:
    from enrichment.mitre_stix_loader import MitreStixLoader


class MitreAttackMapper:
    def __init__(self):
        self.stix_loader: Optional["MitreStixLoader"] = None

        # Try to load STIX data
        if STIX_AVAILABLE and get_mitre_loader is not None:
            try:
                self.stix_loader = get_mitre_loader()
                if self.stix_loader and self.stix_loader.techniques:
                    print(f"MITRE ATT&CK: Loaded {len(self.stix_loader.techniques)} techniques from STIX")
                    self._init_from_stix()
                    return
            except Exception as e:
                print(f"Warning: Failed to load STIX data: {e}")
        
        # Fallback to hardcoded patterns
        print("MITRE ATT&CK: Using hardcoded technique patterns")
        self._init_hardcoded()
    
    def _init_from_stix(self):
        """Initialize from STIX data"""
        if self.stix_loader is None:
            self._init_hardcoded()
            return
        self.technique_patterns = self.stix_loader.get_technique_patterns()
        self.technique_metadata = self.stix_loader.get_technique_metadata()
        
        # Add custom patterns that STIX descriptions might miss
        self._add_custom_patterns()
        
        # Malware mappings (not in STIX, maintain separately)
        self._init_malware_techniques()
    
    def _init_hardcoded(self):
        """Fallback hardcoded patterns if STIX unavailable"""
        self.technique_patterns = {
            # Reconnaissance
            'T1595': ['active scanning', 'vulnerability scanning', 'scanning target'],
            'T1592': ['gather victim host', 'host reconnaissance', 'fingerprinting'],
            'T1589': ['gather victim identity', 'employee names', 'email harvesting'],
            'T1590': ['gather victim network', 'network topology', 'ip ranges'],
            'T1591': ['gather victim org', 'business relationships', 'org structure'],
            'T1598': ['phishing for information', 'spearphishing for recon'],
            'T1597': ['search closed sources', 'dark web', 'underground forums'],
            'T1596': ['search open technical', 'shodan', 'censys'],
            'T1593': ['search open websites', 'linkedin recon', 'social media recon'],
            'T1594': ['search victim-owned', 'career pages', 'partner pages'],
            
            # Resource Development
            'T1583': ['acquire infrastructure', 'buy domain', 'rent server', 'purchase vps'],
            'T1586': ['compromise accounts', 'hijacked accounts', 'stolen social media'],
            'T1584': ['compromise infrastructure', 'compromised server', 'hacked server'],
            'T1587': ['develop capabilities', 'custom malware', 'develop exploit'],
            'T1585': ['establish accounts', 'fake accounts', 'persona creation'],
            'T1588': ['obtain capabilities', 'purchase malware', 'acquire tools'],
            'T1608': ['stage capabilities', 'upload malware', 'host payload'],
            
            # Initial Access
            'T1566': ['phishing', 'spear phishing', 'malicious attachment', 'email attachment'],
            'T1190': ['exploit public-facing', 'web server exploit', 'exposed service'],
            'T1133': ['vpn', 'remote desktop', 'rdp', 'external remote service'],
            'T1078': ['valid accounts', 'stolen credentials', 'compromised credentials'],
            'T1195': ['supply chain', 'software supply chain', 'third-party'],
            
            # Execution
            'T1059': ['command-line', 'powershell', 'cmd.exe', 'bash', 'script execution'],
            'T1203': ['exploit', 'exploitation for client execution', 'browser exploit'],
            'T1204': ['user execution', 'malicious file', 'user clicked'],
            'T1047': ['wmi', 'windows management instrumentation'],
            'T1053': ['scheduled task', 'cron', 'at command'],
            
            # Persistence
            'T1547': ['boot', 'logon', 'registry run keys', 'startup folder'],
            'T1543': ['service', 'systemd', 'windows service'],
            'T1136': ['create account', 'new user account'],
            'T1098': ['account manipulation', 'modify account'],
            'T1505': ['web shell', 'server software component'],
            
            # Privilege Escalation
            'T1068': ['privilege escalation', 'elevation of privilege', 'local privilege'],
            'T1548': ['abuse elevation control', 'sudo', 'uac bypass'],
            
            # Defense Evasion
            'T1070': ['indicator removal', 'clear logs', 'delete artifacts'],
            'T1027': ['obfuscation', 'obfuscated', 'encoded', 'packed'],
            'T1562': ['impair defenses', 'disable security', 'disable antivirus', 'kill av'],
            'T1055': ['process injection', 'dll injection', 'code injection'],
            'T1112': ['modify registry'],
            'T1036': ['masquerading', 'rename', 'disguise'],
            'T1218': ['signed binary proxy', 'rundll32', 'regsvr32', 'mshta'],
            
            # Credential Access
            'T1110': ['brute force', 'password spray', 'credential stuffing'],
            'T1003': ['credential dumping', 'lsass', 'sam', 'mimikatz', 'hashdump'],
            'T1056': ['input capture', 'keylogger', 'keylogging'],
            'T1555': ['credentials from password stores', 'browser credentials'],
            'T1212': ['exploitation for credential access'],
            
            # Discovery
            'T1083': ['file and directory discovery', 'enumerate files'],
            'T1087': ['account discovery', 'enumerate users'],
            'T1018': ['remote system discovery', 'network scan'],
            'T1046': ['network service scanning', 'port scan'],
            'T1057': ['process discovery', 'tasklist', 'ps'],
            'T1082': ['system information discovery', 'systeminfo'],
            
            # Lateral Movement
            'T1021': ['remote services', 'smb', 'ssh', 'remote desktop'],
            'T1080': ['taint shared content'],
            'T1570': ['lateral tool transfer'],
            
            # Collection
            'T1005': ['data from local system'],
            'T1039': ['data from network shared drive'],
            'T1114': ['email collection'],
            'T1113': ['screen capture', 'screenshot'],
            'T1115': ['clipboard data'],
            
            # Command and Control
            'T1071': ['application layer protocol', 'http', 'https', 'dns tunneling'],
            'T1568': ['dynamic resolution', 'dga', 'domain generation'],
            'T1573': ['encrypted channel', 'encryption', 'tls'],
            'T1090': ['proxy', 'internal proxy'],
            'T1095': ['non-application layer protocol', 'custom protocol'],
            'T1219': ['remote access software', 'teamviewer', 'anydesk'],
            
            # Exfiltration
            'T1020': ['automated exfiltration'],
            'T1030': ['data transfer size limits'],
            'T1048': ['exfiltration over alternative protocol', 'exfil'],
            'T1041': ['exfiltration over c2', 'command and control channel'],
            'T1567': ['exfiltration over web service', 'cloud storage'],
            
            # Impact
            'T1485': ['data destruction', 'wiper', 'delete data'],
            'T1486': ['data encrypted for impact', 'ransomware', 'encryption'],
            'T1490': ['inhibit system recovery', 'delete backups', 'vssadmin'],
            'T1491': ['defacement', 'website defacement'],
            'T1498': ['network denial of service', 'ddos'],
            'T1499': ['endpoint denial of service'],
            'T1657': ['financial theft']
        }
        
        self.technique_metadata = {
            # Reconnaissance
            'T1595': {'name': 'Active Scanning', 'tactic': 'Reconnaissance'},
            'T1592': {'name': 'Gather Victim Host Information', 'tactic': 'Reconnaissance'},
            'T1589': {'name': 'Gather Victim Identity Information', 'tactic': 'Reconnaissance'},
            'T1590': {'name': 'Gather Victim Network Information', 'tactic': 'Reconnaissance'},
            'T1591': {'name': 'Gather Victim Org Information', 'tactic': 'Reconnaissance'},
            'T1598': {'name': 'Phishing for Information', 'tactic': 'Reconnaissance'},
            'T1597': {'name': 'Search Closed Sources', 'tactic': 'Reconnaissance'},
            'T1596': {'name': 'Search Open Technical Databases', 'tactic': 'Reconnaissance'},
            'T1593': {'name': 'Search Open Websites/Domains', 'tactic': 'Reconnaissance'},
            'T1594': {'name': 'Search Victim-Owned Websites', 'tactic': 'Reconnaissance'},
            
            # Resource Development
            'T1583': {'name': 'Acquire Infrastructure', 'tactic': 'Resource Development'},
            'T1586': {'name': 'Compromise Accounts', 'tactic': 'Resource Development'},
            'T1584': {'name': 'Compromise Infrastructure', 'tactic': 'Resource Development'},
            'T1587': {'name': 'Develop Capabilities', 'tactic': 'Resource Development'},
            'T1585': {'name': 'Establish Accounts', 'tactic': 'Resource Development'},
            'T1588': {'name': 'Obtain Capabilities', 'tactic': 'Resource Development'},
            'T1608': {'name': 'Stage Capabilities', 'tactic': 'Resource Development'},
            
            # Initial Access
            'T1566': {'name': 'Phishing', 'tactic': 'Initial Access'},
            'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
            'T1133': {'name': 'External Remote Services', 'tactic': 'Initial Access'},
            'T1078': {'name': 'Valid Accounts', 'tactic': 'Initial Access'},
            'T1195': {'name': 'Supply Chain Compromise', 'tactic': 'Initial Access'},
            
            # Execution
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
            'T1203': {'name': 'Exploitation for Client Execution', 'tactic': 'Execution'},
            'T1204': {'name': 'User Execution', 'tactic': 'Execution'},
            'T1047': {'name': 'Windows Management Instrumentation', 'tactic': 'Execution'},
            'T1053': {'name': 'Scheduled Task/Job', 'tactic': 'Execution'},
            
            # Persistence
            'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence'},
            'T1543': {'name': 'Create or Modify System Process', 'tactic': 'Persistence'},
            'T1136': {'name': 'Create Account', 'tactic': 'Persistence'},
            'T1098': {'name': 'Account Manipulation', 'tactic': 'Persistence'},
            'T1505': {'name': 'Server Software Component', 'tactic': 'Persistence'},
            
            # Privilege Escalation
            'T1068': {'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'},
            'T1548': {'name': 'Abuse Elevation Control Mechanism', 'tactic': 'Privilege Escalation'},
            
            # Defense Evasion
            'T1070': {'name': 'Indicator Removal', 'tactic': 'Defense Evasion'},
            'T1027': {'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
            'T1562': {'name': 'Impair Defenses', 'tactic': 'Defense Evasion'},
            'T1055': {'name': 'Process Injection', 'tactic': 'Defense Evasion'},
            'T1112': {'name': 'Modify Registry', 'tactic': 'Defense Evasion'},
            'T1036': {'name': 'Masquerading', 'tactic': 'Defense Evasion'},
            'T1218': {'name': 'System Binary Proxy Execution', 'tactic': 'Defense Evasion'},
            
            # Credential Access
            'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access'},
            'T1003': {'name': 'OS Credential Dumping', 'tactic': 'Credential Access'},
            'T1056': {'name': 'Input Capture', 'tactic': 'Credential Access'},
            'T1555': {'name': 'Credentials from Password Stores', 'tactic': 'Credential Access'},
            'T1212': {'name': 'Exploitation for Credential Access', 'tactic': 'Credential Access'},
            
            # Discovery
            'T1083': {'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
            'T1087': {'name': 'Account Discovery', 'tactic': 'Discovery'},
            'T1018': {'name': 'Remote System Discovery', 'tactic': 'Discovery'},
            'T1046': {'name': 'Network Service Discovery', 'tactic': 'Discovery'},
            'T1057': {'name': 'Process Discovery', 'tactic': 'Discovery'},
            'T1082': {'name': 'System Information Discovery', 'tactic': 'Discovery'},
            
            # Lateral Movement
            'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement'},
            'T1080': {'name': 'Taint Shared Content', 'tactic': 'Lateral Movement'},
            'T1570': {'name': 'Lateral Tool Transfer', 'tactic': 'Lateral Movement'},
            
            # Collection
            'T1005': {'name': 'Data from Local System', 'tactic': 'Collection'},
            'T1039': {'name': 'Data from Network Shared Drive', 'tactic': 'Collection'},
            'T1114': {'name': 'Email Collection', 'tactic': 'Collection'},
            'T1113': {'name': 'Screen Capture', 'tactic': 'Collection'},
            'T1115': {'name': 'Clipboard Data', 'tactic': 'Collection'},
            
            # Command and Control
            'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
            'T1568': {'name': 'Dynamic Resolution', 'tactic': 'Command and Control'},
            'T1573': {'name': 'Encrypted Channel', 'tactic': 'Command and Control'},
            'T1090': {'name': 'Proxy', 'tactic': 'Command and Control'},
            'T1095': {'name': 'Non-Application Layer Protocol', 'tactic': 'Command and Control'},
            'T1219': {'name': 'Remote Access Software', 'tactic': 'Command and Control'},
            
            # Exfiltration
            'T1020': {'name': 'Automated Exfiltration', 'tactic': 'Exfiltration'},
            'T1030': {'name': 'Data Transfer Size Limits', 'tactic': 'Exfiltration'},
            'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'Exfiltration'},
            'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic': 'Exfiltration'},
            'T1567': {'name': 'Exfiltration Over Web Service', 'tactic': 'Exfiltration'},
            
            # Impact
            'T1485': {'name': 'Data Destruction', 'tactic': 'Impact'},
            'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
            'T1490': {'name': 'Inhibit System Recovery', 'tactic': 'Impact'},
            'T1491': {'name': 'Defacement', 'tactic': 'Impact'},
            'T1498': {'name': 'Network Denial of Service', 'tactic': 'Impact'},
            'T1499': {'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
            'T1657': {'name': 'Financial Theft', 'tactic': 'Impact'}
        }
        
        self._init_malware_techniques()
    
    def _add_custom_patterns(self):
        """Add custom detection patterns that STIX might miss"""
        custom_patterns = {
            # Common security terms that map to techniques
            'T1566': ['phishing email', 'malspam', 'spearphish'],
            'T1059': ['powershell', 'cmd.exe', 'bash', 'python script', 'vbscript'],
            'T1486': ['ransomware', 'encrypt files', 'ransom note', 'data encrypted'],
            'T1003': ['mimikatz', 'credential dump', 'lsass', 'password hash'],
            'T1055': ['process injection', 'dll injection', 'code injection', 'hollowing'],
            'T1071': ['c2', 'c&c', 'command and control', 'beacon'],
            'T1078': ['stolen credentials', 'valid accounts', 'compromised account'],
            'T1190': ['exploit', 'cve-', 'vulnerability', 'rce'],
        }
        
        for tech_id, patterns in custom_patterns.items():
            if tech_id in self.technique_patterns:
                self.technique_patterns[tech_id].extend(patterns)
            else:
                self.technique_patterns[tech_id] = patterns
    
    def _init_malware_techniques(self):
        """Initialize malware to technique mappings"""
        self.malware_techniques = {
            'ransomware': ['T1486', 'T1490', 'T1082', 'T1047'],
            'qakbot': ['T1566', 'T1059', 'T1055', 'T1003'],
            'emotet': ['T1566', 'T1204', 'T1059', 'T1547'],
            'cobalt strike': ['T1055', 'T1021', 'T1071', 'T1003'],
            'mimikatz': ['T1003', 'T1558', 'T1550'],
            'backdoor': ['T1071', 'T1573', 'T1547'],
            'stealer': ['T1555', 'T1056', 'T1113', 'T1005'],
            'wiper': ['T1485', 'T1490'],
            'keylogger': ['T1056'],
            'rat': ['T1219', 'T1071', 'T1113'],
            'loader': ['T1204', 'T1059', 'T1547'],
            'botnet': ['T1071', 'T1568', 'T1059'],
            'rootkit': ['T1014', 'T1547', 'T1562'],
            'infostealer': ['T1555', 'T1005', 'T1056', 'T1113']
        }
    
    def detect_techniques(self, text):
        """Detect MITRE ATT&CK techniques from text"""
        text_lower = text.lower()
        detected = set()
        
        # Pattern matching
        for technique_id, keywords in self.technique_patterns.items():
            for keyword in keywords:
                if keyword in text_lower:
                    detected.add(technique_id)
                    break
        
        return list(detected)
    
    def map_malware_to_techniques(self, malware_tags):
        """Map malware families to common techniques"""
        techniques = set()
        
        for tag in malware_tags:
            tag_lower = tag.lower()
            for malware, techs in self.malware_techniques.items():
                if malware in tag_lower:
                    techniques.update(techs)
        
        return list(techniques)
    
    def enrich_feed_item(self, feed_item_id):
        """Add MITRE ATT&CK techniques to a feed item"""
        session = db.get_session()
        
        try:
            feed_item = session.query(FeedItem).filter_by(id=feed_item_id).first()
            if not feed_item:
                return False
            
            text = f"{feed_item.title} {feed_item.content}"
            
            # Detect from content
            content_techniques = self.detect_techniques(text)
            
            # Detect from malware tags
            malware_tags = [t.name for t in feed_item.tags if t.category == 'malware']
            malware_techniques = self.map_malware_to_techniques(malware_tags)
            
            # Combine and deduplicate
            all_techniques = list(set(content_techniques + malware_techniques))
            
            # Validate techniques against STIX data - only create tags for valid techniques
            valid_techniques = []
            for tech_id in all_techniques:
                tech_id_upper = tech_id.upper()
                # Check if technique exists in STIX data
                if self.stix_loader and tech_id_upper in self.stix_loader.techniques:
                    valid_techniques.append(tech_id)
                elif not self.stix_loader and tech_id_upper in self.technique_metadata:
                    # Fallback to hardcoded if no STIX
                    valid_techniques.append(tech_id)
            
            # Create technique tags only for validated techniques
            for technique_id in valid_techniques:
                metadata = self.get_technique_info(technique_id)
                tag_name = f"mitre-{technique_id.lower()}"
                
                tag = session.query(Tag).filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(
                        name=tag_name,
                        category='mitre_technique',
                        auto_generated=True
                    )
                    session.add(tag)
                
                if tag not in feed_item.tags:
                    feed_item.tags.append(tag)
            
            # Store technique IDs in IOCs if applicable
            for ioc in feed_item.iocs:
                if not ioc.mitre_techniques or 'CWE' not in ioc.mitre_techniques:
                    technique_str = ', '.join(valid_techniques[:5])  # Limit to 5
                    if technique_str and not ioc.mitre_techniques:
                        ioc.mitre_techniques = technique_str
            
            session.commit()
            return len(valid_techniques)
            
        except Exception as e:
            print(f"Error enriching feed item {feed_item_id} with MITRE: {e}")
            session.rollback()
            return 0
        finally:
            session.close()
    
    def enrich_all_items(self):
        """Enrich all feed items without MITRE technique tags"""
        session = db.get_session()
        
        try:
            # Find items without MITRE tags
            all_items = session.query(FeedItem).all()
            items_to_process = []
            
            for item in all_items:
                has_mitre = any(t.category == 'mitre_technique' for t in item.tags)
                if not has_mitre:
                    items_to_process.append((item.id, item.title[:60]))
            
        finally:
            session.close()
        
        enriched_count = 0
        total = len(items_to_process)
        
        print(f"Found {total} items to enrich with MITRE ATT&CK techniques")
        
        for feed_id, title in items_to_process:
            tech_count = self.enrich_feed_item(feed_id)
            if tech_count > 0:
                enriched_count += 1
                print(f"Enriched '{title}...' with {tech_count} techniques")
        
        print(f"\nTotal enriched: {enriched_count}/{total} items")
        return enriched_count
    
    def get_technique_info(self, technique_id):
        """Get metadata for a technique"""
        technique_id = technique_id.upper()
        
        # Try STIX loader first (exact match)
        if self.stix_loader and technique_id in self.stix_loader.techniques:
            t = self.stix_loader.techniques[technique_id]
            return {
                'name': t['name'],
                'tactic': t['tactic'],
                'url': t.get('url', f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/')
            }
        
        # For sub-techniques (T1234.001), try parent technique for tactic
        if '.' in technique_id and self.stix_loader:
            parent_id = technique_id.split('.')[0]
            if parent_id in self.stix_loader.techniques:
                parent = self.stix_loader.techniques[parent_id]
                # Return sub-technique with parent's tactic
                return {
                    'name': technique_id,  # We don't have the sub-technique name
                    'tactic': parent['tactic'],
                    'url': f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/'
                }
        
        # Fallback to hardcoded
        return self.technique_metadata.get(technique_id, {
            'name': technique_id,
            'tactic': 'Unknown'
        })
    
    def export_technique_matrix(self):
        """Export technique coverage matrix"""
        session = db.get_session()
        
        try:
            # Get all MITRE technique tags
            mitre_tags = session.query(Tag).filter_by(category='mitre_technique').all()
            
            technique_counts = {}
            for tag in mitre_tags:
                technique_id = tag.name.replace('mitre-', '').upper()
                count = len(tag.feed_items)
                
                metadata = self.get_technique_info(technique_id)
                technique_counts[technique_id] = {
                    'name': metadata['name'],
                    'tactic': metadata['tactic'],
                    'count': count
                }
            
            return technique_counts
            
        finally:
            session.close()
    
    def get_all_tactics(self):
        """Get ordered list of all tactics"""
        if self.stix_loader:
            return self.stix_loader.get_all_tactics()
        
        return [
            'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
            'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
            'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
            'Exfiltration', 'Impact'
        ]
    
    def get_techniques_for_api(self):
        """Get techniques grouped by tactic for API endpoint"""
        if self.stix_loader:
            return self.stix_loader.export_for_api()
        
        # Fallback: group hardcoded techniques by tactic
        by_tactic = {tactic: [] for tactic in self.get_all_tactics()}
        
        for tech_id, metadata in self.technique_metadata.items():
            tactic = metadata.get('tactic', 'Unknown')
            if tactic in by_tactic:
                by_tactic[tactic].append({
                    'id': tech_id,
                    'name': metadata['name'],
                    'tactic': tactic
                })
        
        return by_tactic
