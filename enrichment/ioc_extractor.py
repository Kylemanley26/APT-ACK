import re
from storage.database import db
from storage.models import FeedItem, IOC, IOCType
from datetime import datetime, UTC

class IOCExtractor:
    def __init__(self):
        # Regex patterns for IOC extraction
        self.patterns = {
            IOCType.IP: re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            IOCType.DOMAIN: re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
            IOCType.CVE: re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
            IOCType.HASH_MD5: re.compile(r'\b[a-fA-F0-9]{32}\b'),
            IOCType.HASH_SHA1: re.compile(r'\b[a-fA-F0-9]{40}\b'),
            IOCType.HASH_SHA256: re.compile(r'\b[a-fA-F0-9]{64}\b'),
            IOCType.EMAIL: re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            IOCType.URL: re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        }
        
        # Domains to exclude (legitimate services)
        self.domain_whitelist = {
            'github.com', 'twitter.com', 'linkedin.com', 'facebook.com',
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'youtube.com', 'reddit.com', 'wikipedia.org', 'bit.ly',
            't.co', 'ow.ly', 'tinyurl.com', 'pastebin.com'
        }
        
        # IP ranges to exclude (RFC 1918, loopback, etc)
        self.ip_whitelist_patterns = [
            re.compile(r'^10\.'),
            re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
            re.compile(r'^192\.168\.'),
            re.compile(r'^127\.'),
            re.compile(r'^0\.'),
            re.compile(r'^169\.254\.'),
        ]
    
    def is_valid_ip(self, ip):
        """Check if IP should be included"""
        for pattern in self.ip_whitelist_patterns:
            if pattern.match(ip):
                return False
        return True
    
    def is_valid_domain(self, domain):
        """Check if domain should be included"""
        domain_lower = domain.lower()
        
        # Check exact whitelist
        if domain_lower in self.domain_whitelist:
            return False
        
        # Check if subdomain of whitelisted
        for whitelisted in self.domain_whitelist:
            if domain_lower.endswith('.' + whitelisted):
                return False
        
        # Exclude very common TLDs used in examples
        if domain_lower.endswith(('.example', '.test', '.local', '.localhost')):
            return False
        
        return True
    
    def extract_context(self, text, match, context_chars=100):
        """Extract surrounding text for context"""
        start = max(0, match.start() - context_chars)
        end = min(len(text), match.end() + context_chars)
        return text[start:end].strip()
    
    def extract_iocs(self, feed_item):
        """Extract all IOCs from a feed item"""
        text = f"{feed_item.title} {feed_item.content}"
        extracted = []
        
        for ioc_type, pattern in self.patterns.items():
            matches = pattern.finditer(text)
            
            for match in matches:
                value = match.group(0)
                
                # Apply filters
                if ioc_type == IOCType.IP and not self.is_valid_ip(value):
                    continue
                if ioc_type == IOCType.DOMAIN and not self.is_valid_domain(value):
                    continue
                
                # Calculate confidence based on type
                confidence = self.calculate_confidence(ioc_type, value, text)
                
                ioc = IOC(
                    feed_item_id=feed_item.id,
                    ioc_type=ioc_type,
                    value=value,
                    context=self.extract_context(text, match),
                    confidence=confidence
                )
                extracted.append(ioc)
        
        return extracted
    
    def calculate_confidence(self, ioc_type, value, text):
        """Calculate confidence score for IOC"""
        confidence = 0.5
        
        # CVEs are high confidence
        if ioc_type == IOCType.CVE:
            confidence = 0.95
        
        # Hashes mentioned with "malicious" or "sample"
        if ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
            if re.search(r'\b(malicious|malware|sample|hash)\b', text, re.IGNORECASE):
                confidence = 0.85
        
        # IPs/domains with threat indicators
        if ioc_type in [IOCType.IP, IOCType.DOMAIN]:
            threat_keywords = ['malicious', 'c2', 'command and control', 'botnet', 
                             'ransomware', 'phishing', 'exploit', 'attacker']
            for keyword in threat_keywords:
                if keyword in text.lower():
                    confidence = min(confidence + 0.15, 0.95)
        
        return confidence
    
    def process_all_unprocessed(self):
        """Process all unprocessed feed items"""
        session = db.get_session()
        
        try:
            unprocessed = session.query(FeedItem).filter_by(processed=False).all()
            total_iocs = 0
            
            for feed_item in unprocessed:
                # Extract title before processing (avoid detached instance)
                title = feed_item.title
                
                # Extract IOCs
                iocs = self.extract_iocs(feed_item)
                
                # Deduplicate by value and type
                unique_iocs = {}
                for ioc in iocs:
                    key = (ioc.ioc_type, ioc.value)
                    if key not in unique_iocs or ioc.confidence > unique_iocs[key].confidence:
                        unique_iocs[key] = ioc
                
                # Add to database
                for ioc in unique_iocs.values():
                    session.add(ioc)
                
                # Mark as processed
                feed_item.processed = True
                
                count = len(unique_iocs)
                total_iocs += count
                print(f"Processed '{title[:60]}...' - extracted {count} IOCs")
            
            session.commit()
            return total_iocs
            
        except Exception as e:
            print(f"Error processing feed items: {e}")
            session.rollback()
            return 0
        finally:
            session.close()