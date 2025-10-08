import re
from storage.database import db
from storage.models import FeedItem, Tag, SeverityLevel

class ThreatTagger:
    def __init__(self):
        # Threat actor groups (APTs, ransomware gangs)
        self.threat_actors = {
            'apt28', 'apt29', 'apt41', 'lazarus', 'kimsuky', 'turla',
            'scattered spider', 'alphv', 'lockbit', 'blackcat', 'royal',
            'cl0p', 'conti', 'revil', 'ryuk', 'darkside', 'blackmatter',
            'wizard spider', 'fin7', 'fin8', 'carbanak', 'ta505',
            'shinyhunters', 'lapsus', 'karakurt', 'play', 'akira',
            'sandworm', 'equation group', 'cozy bear', 'fancy bear'
        }
        
        # Malware families
        self.malware_families = {
            'qakbot', 'emotet', 'trickbot', 'dridex', 'icedid', 'bumblebee',
            'cobalt strike', 'mimikatz', 'metasploit', 'bloodhound',
            'ransomware', 'backdoor', 'trojan', 'wiper', 'rootkit',
            'stealer', 'loader', 'rat', 'keylogger', 'spyware',
            'lockbit', 'blackcat', 'royal', 'akira', 'play',
            'redline', 'vidar', 'raccoon', 'lumma', 'worldwind'
        }
        
        # Attack types
        self.attack_types = {
            'ransomware', 'phishing', 'spear phishing', 'business email compromise',
            'ddos', 'supply chain', 'watering hole', 'sql injection',
            'xss', 'rce', 'privilege escalation', 'lateral movement',
            'data breach', 'credential theft', 'cryptojacking', 'botnet',
            'zero-day', 'exploit', 'vulnerability', 'patch', 'cve'
        }
        
        # Affected sectors
        self.sectors = {
            'healthcare', 'financial', 'energy', 'government', 'education',
            'retail', 'manufacturing', 'transportation', 'telecom',
            'critical infrastructure', 'defense', 'aerospace'
        }
        
        # Vendors/technologies
        self.vendors = {
            'microsoft', 'windows', 'exchange', 'active directory', 'sharepoint',
            'cisco', 'fortinet', 'palo alto', 'juniper', 'vmware',
            'citrix', 'apache', 'nginx', 'oracle', 'sap', 'adobe',
            'chrome', 'firefox', 'safari', 'wordpress', 'drupal',
            'aws', 'azure', 'google cloud', 'kubernetes', 'docker'
        }
        
        # Severity indicators
        self.severity_keywords = {
            'critical': ['zero-day', 'actively exploited', 'in the wild', 'mass exploitation',
                        'critical vulnerability', 'remote code execution', 'unauthenticated rce',
                        'wormable', 'ransomware', 'data breach'],
            'high': ['high severity', 'privilege escalation', 'authentication bypass',
                    'sql injection', 'credential theft', 'lateral movement',
                    'backdoor', 'supply chain', 'apt'],
            'medium': ['vulnerability', 'security update', 'patch available',
                      'denial of service', 'information disclosure', 'xss'],
            'low': ['security advisory', 'best practices', 'hardening',
                   'configuration', 'awareness']
        }
    
    def extract_tags(self, text):
        """Extract all applicable tags from text"""
        text_lower = text.lower()
        tags = {}
        
        # Threat actors
        for actor in self.threat_actors:
            if actor in text_lower:
                tags[actor] = 'threat_actor'
        
        # Malware families
        for malware in self.malware_families:
            if malware in text_lower:
                tags[malware] = 'malware'
        
        # Attack types
        for attack in self.attack_types:
            if attack in text_lower:
                tags[attack] = 'attack_type'
        
        # Sectors
        for sector in self.sectors:
            if sector in text_lower:
                tags[sector] = 'sector'
        
        # Vendors
        for vendor in self.vendors:
            if vendor in text_lower:
                tags[vendor] = 'vendor'
        
        return tags
    
    def calculate_severity(self, text):
        """Calculate severity level based on keywords"""
        text_lower = text.lower()
        
        # Check for critical indicators
        for keyword in self.severity_keywords['critical']:
            if keyword in text_lower:
                return SeverityLevel.CRITICAL
        
        # Check for high severity
        for keyword in self.severity_keywords['high']:
            if keyword in text_lower:
                return SeverityLevel.HIGH
        
        # Check for medium severity
        for keyword in self.severity_keywords['medium']:
            if keyword in text_lower:
                return SeverityLevel.MEDIUM
        
        # Check for low severity
        for keyword in self.severity_keywords['low']:
            if keyword in text_lower:
                return SeverityLevel.LOW
        
        return SeverityLevel.INFO
    
    def calculate_relevance_score(self, text, tags):
        """Calculate relevance score 0.0 to 1.0"""
        score = 0.0
        text_lower = text.lower()
        
        # Base score on number of tags
        score += min(len(tags) * 0.1, 0.3)
        
        # Boost for threat actors
        if any(cat == 'threat_actor' for cat in tags.values()):
            score += 0.2
        
        # Boost for malware
        if any(cat == 'malware' for cat in tags.values()):
            score += 0.15
        
        # Boost for CVEs
        if re.search(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE):
            score += 0.25
        
        # Boost for zero-day
        if 'zero-day' in text_lower or 'zero day' in text_lower:
            score += 0.3
        
        # Boost for active exploitation
        if 'actively exploited' in text_lower or 'in the wild' in text_lower:
            score += 0.25
        
        return min(score, 1.0)
    
    def tag_feed_item(self, feed_item_id):
        """Tag and score a single feed item"""
        session = db.get_session()
        
        try:
            feed_item = session.query(FeedItem).filter_by(id=feed_item_id).first()
            if not feed_item:
                return False
            
            text = f"{feed_item.title} {feed_item.content}"
            
            # Extract tags
            tag_dict = self.extract_tags(text)
            
            # Special handling for CISA KEV items
            if feed_item.source_name == "CISA KEV":
                # Check for ransomware in content
                if 'Known Ransomware Use: Known' in text:
                    tag_dict['ransomware-campaign'] = 'attack_type'
            
            # Get or create tags
            for tag_name, category in tag_dict.items():
                tag = session.query(Tag).filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name, category=category, auto_generated=True)
                    session.add(tag)
                
                if tag not in feed_item.tags:
                    feed_item.tags.append(tag)
            
            # Calculate severity (only if not already set for KEV)
            if feed_item.source_name != "CISA KEV":
                severity = self.calculate_severity(text)
                feed_item.severity = severity
            
            # Calculate relevance score
            relevance = self.calculate_relevance_score(text, tag_dict)
            
            # Ensure KEV items maintain high relevance
            if feed_item.source_name == "CISA KEV":
                relevance = max(relevance, 0.95)
            
            feed_item.relevance_score = relevance
            
            session.commit()
            return True
            
        except Exception as e:
            print(f"Error tagging feed item {feed_item_id}: {e}")
            session.rollback()
            return False
        finally:
            session.close()
    
    def tag_all_untagged(self):
        session = db.get_session()
        
        try:
            # Find items with default relevance score and extract IDs and titles
            untagged = session.query(FeedItem).filter(FeedItem.relevance_score == 0.0).all()
            
            # Extract data before processing
            items_to_process = [(item.id, item.title[:60]) for item in untagged]
            
        finally:
            session.close()
        
        # Now process with fresh sessions
        tagged_count = 0
        for feed_id, title in items_to_process:
            if self.tag_feed_item(feed_id):
                tagged_count += 1
                
                # Re-query to get updated values
                session_check = db.get_session()
                try:
                    updated_item = session_check.query(FeedItem).filter_by(id=feed_id).first()
                    if updated_item:
                        severity = updated_item.severity.value
                        score = updated_item.relevance_score
                        tags = len(updated_item.tags)
                        print(f"Tagged '{title}...' - {severity.upper()} (score: {score:.2f}, tags: {tags})")
                finally:
                    session_check.close()
        
        return tagged_count