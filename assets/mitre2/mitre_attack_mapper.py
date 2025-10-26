import re
import json
from pathlib import Path
from storage.database import db
from storage.models import FeedItem, IOC, Tag

class MitreAttackMapper:
    def __init__(self):
        # Technique mappings - keyword/pattern to MITRE technique
        self.technique_patterns = {
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
            'T1078': ['valid accounts', 'privileged account'],
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
        
        # Technique metadata (name and tactic)
        self.technique_metadata = {
            'T1566': {'name': 'Phishing', 'tactic': 'Initial Access'},
            'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
            'T1133': {'name': 'External Remote Services', 'tactic': 'Initial Access'},
            'T1078': {'name': 'Valid Accounts', 'tactic': 'Multiple'},
            'T1195': {'name': 'Supply Chain Compromise', 'tactic': 'Initial Access'},
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
            'T1203': {'name': 'Exploitation for Client Execution', 'tactic': 'Execution'},
            'T1204': {'name': 'User Execution', 'tactic': 'Execution'},
            'T1047': {'name': 'Windows Management Instrumentation', 'tactic': 'Execution'},
            'T1053': {'name': 'Scheduled Task/Job', 'tactic': 'Execution'},
            'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence'},
            'T1543': {'name': 'Create or Modify System Process', 'tactic': 'Persistence'},
            'T1136': {'name': 'Create Account', 'tactic': 'Persistence'},
            'T1098': {'name': 'Account Manipulation', 'tactic': 'Persistence'},
            'T1505': {'name': 'Server Software Component', 'tactic': 'Persistence'},
            'T1068': {'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'},
            'T1548': {'name': 'Abuse Elevation Control Mechanism', 'tactic': 'Privilege Escalation'},
            'T1070': {'name': 'Indicator Removal', 'tactic': 'Defense Evasion'},
            'T1027': {'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
            'T1562': {'name': 'Impair Defenses', 'tactic': 'Defense Evasion'},
            'T1055': {'name': 'Process Injection', 'tactic': 'Defense Evasion'},
            'T1112': {'name': 'Modify Registry', 'tactic': 'Defense Evasion'},
            'T1036': {'name': 'Masquerading', 'tactic': 'Defense Evasion'},
            'T1218': {'name': 'System Binary Proxy Execution', 'tactic': 'Defense Evasion'},
            'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access'},
            'T1003': {'name': 'OS Credential Dumping', 'tactic': 'Credential Access'},
            'T1056': {'name': 'Input Capture', 'tactic': 'Credential Access'},
            'T1555': {'name': 'Credentials from Password Stores', 'tactic': 'Credential Access'},
            'T1212': {'name': 'Exploitation for Credential Access', 'tactic': 'Credential Access'},
            'T1083': {'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
            'T1087': {'name': 'Account Discovery', 'tactic': 'Discovery'},
            'T1018': {'name': 'Remote System Discovery', 'tactic': 'Discovery'},
            'T1046': {'name': 'Network Service Discovery', 'tactic': 'Discovery'},
            'T1057': {'name': 'Process Discovery', 'tactic': 'Discovery'},
            'T1082': {'name': 'System Information Discovery', 'tactic': 'Discovery'},
            'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement'},
            'T1080': {'name': 'Taint Shared Content', 'tactic': 'Lateral Movement'},
            'T1570': {'name': 'Lateral Tool Transfer', 'tactic': 'Lateral Movement'},
            'T1005': {'name': 'Data from Local System', 'tactic': 'Collection'},
            'T1039': {'name': 'Data from Network Shared Drive', 'tactic': 'Collection'},
            'T1114': {'name': 'Email Collection', 'tactic': 'Collection'},
            'T1113': {'name': 'Screen Capture', 'tactic': 'Collection'},
            'T1115': {'name': 'Clipboard Data', 'tactic': 'Collection'},
            'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
            'T1568': {'name': 'Dynamic Resolution', 'tactic': 'Command and Control'},
            'T1573': {'name': 'Encrypted Channel', 'tactic': 'Command and Control'},
            'T1090': {'name': 'Proxy', 'tactic': 'Command and Control'},
            'T1095': {'name': 'Non-Application Layer Protocol', 'tactic': 'Command and Control'},
            'T1219': {'name': 'Remote Access Software', 'tactic': 'Command and Control'},
            'T1020': {'name': 'Automated Exfiltration', 'tactic': 'Exfiltration'},
            'T1030': {'name': 'Data Transfer Size Limits', 'tactic': 'Exfiltration'},
            'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'Exfiltration'},
            'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic': 'Exfiltration'},
            'T1567': {'name': 'Exfiltration Over Web Service', 'tactic': 'Exfiltration'},
            'T1485': {'name': 'Data Destruction', 'tactic': 'Impact'},
            'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
            'T1490': {'name': 'Inhibit System Recovery', 'tactic': 'Impact'},
            'T1491': {'name': 'Defacement', 'tactic': 'Impact'},
            'T1498': {'name': 'Network Denial of Service', 'tactic': 'Impact'},
            'T1499': {'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
            'T1657': {'name': 'Financial Theft', 'tactic': 'Impact'}
        }
        
        # Malware to technique mappings (common TTPs)
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
            'rat': ['T1219', 'T1071', 'T1113']
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
            
            # Create technique tags
            for technique_id in all_techniques:
                if technique_id in self.technique_metadata:
                    metadata = self.technique_metadata[technique_id]
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
                    technique_str = ', '.join(all_techniques[:5])  # Limit to 5
                    if technique_str and not ioc.mitre_techniques:
                        ioc.mitre_techniques = technique_str
            
            session.commit()
            return len(all_techniques)
            
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
