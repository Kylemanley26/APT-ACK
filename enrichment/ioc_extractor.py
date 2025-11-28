import re
from storage.database import db
from storage.models import FeedItem, IOC, IOCType
from datetime import datetime, UTC

class IOCExtractor:
    def __init__(self):
        # Valid TLDs (most common - expand as needed)
        self.valid_tlds = {
            # Generic
            'com', 'net', 'org', 'info', 'biz', 'edu', 'gov', 'mil', 'int',
            'co', 'io', 'ai', 'app', 'dev', 'xyz', 'online', 'site', 'tech',
            'cloud', 'pro', 'me', 'tv', 'cc', 'ws', 'to', 'fm', 'am', 'ly',
            'gg', 'sh', 'so', 'la', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq',
            # Country codes (common ones)
            'us', 'uk', 'ca', 'au', 'de', 'fr', 'nl', 'ru', 'cn', 'jp', 'kr',
            'in', 'br', 'it', 'es', 'pl', 'ua', 'ir', 'kp', 'za', 'mx', 'ar',
            'ch', 'at', 'be', 'se', 'no', 'dk', 'fi', 'cz', 'ro', 'hu', 'tr',
            'il', 'ae', 'sg', 'hk', 'tw', 'th', 'vn', 'id', 'my', 'ph', 'nz',
            # Double TLDs
            'co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'co.jp', 'co.kr',
            'org.uk', 'net.au', 'gov.uk', 'ac.uk', 'edu.au'
        }
        
        # File extensions to reject (not domains)
        self.file_extensions = {
            # Executables
            'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'msi',
            'scr', 'pif', 'com', 'hta', 'cpl', 'jar', 'wsf', 'vbe', 'jse',
            # Documents
            'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'rtf', 'odt',
            'txt', 'csv', 'log', 'xml', 'json', 'yaml', 'yml', 'ini', 'cfg',
            'conf', 'config', 'md', 'rst',
            # Archives
            'zip', 'rar', 'tar', 'gz', 'bz2', '7z', 'iso', 'img', 'dmg',
            # Images
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'svg', 'webp', 'tif', 'tiff',
            # Media
            'mp3', 'mp4', 'wav', 'avi', 'mov', 'mkv', 'flv', 'wmv',
            # Code
            'py', 'pyc', 'pyo', 'rb', 'php', 'asp', 'aspx', 'jsp', 'c', 'cpp',
            'h', 'cs', 'java', 'class', 'go', 'rs', 'swift', 'kt', 'sh', 'pl',
            # Web
            'html', 'htm', 'css', 'scss', 'less', 'ts', 'tsx', 'jsx',
            # Data
            'sql', 'db', 'sqlite', 'mdb', 'accdb', 'bak', 'tmp', 'dat', 'bin',
            # Other
            'lnk', 'url', 'reg', 'inf', 'cer', 'crt', 'pem', 'key', 'pfx'
        }
        
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
            # Social/general
            'github.com', 'twitter.com', 'linkedin.com', 'facebook.com',
            'google.com', 'googleblog.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'youtube.com', 'reddit.com', 'wikipedia.org', 'medium.com',
            # URL shorteners
            'bit.ly', 't.co', 'ow.ly', 'tinyurl.com', 'goo.gl', 'is.gd',
            # Dev/hosting
            'pastebin.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
            'amazonaws.com', 'cloudflare.com', 'azure.com', 'googleapis.com',
            # Security vendors (legitimate sources)
            'virustotal.com', 'malwarebytes.com', 'kaspersky.com', 'symantec.com',
            'mcafee.com', 'trendmicro.com', 'sophos.com', 'crowdstrike.com',
            'fireeye.com', 'mandiant.com', 'paloaltonetworks.com',
            # News/research
            'bleepingcomputer.com', 'thehackernews.com', 'securityweek.com',
            'darkreading.com', 'threatpost.com', 'krebsonsecurity.com',
            'schneier.com', 'sans.org', 'nist.gov', 'cisa.gov', 'mitre.org',
            'cve.org', 'nvd.nist.gov', 'attack.mitre.org',
            # CDNs/infrastructure
            'cloudfront.net', 'akamaized.net', 'fastly.net', 'cdnjs.cloudflare.com',
            # Example domains (RFC 2606)
            'example.com', 'example.org', 'example.net'
        }
        
        # IP ranges to exclude (RFC 1918, loopback, etc)
        self.ip_whitelist_patterns = [
            re.compile(r'^10\.'),
            re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
            re.compile(r'^192\.168\.'),
            re.compile(r'^127\.'),
            re.compile(r'^0\.'),
            re.compile(r'^169\.254\.'),
            re.compile(r'^224\.'),        # Multicast
            re.compile(r'^255\.'),        # Broadcast
        ]
        
        # Patterns that indicate a filename, not a domain
        self.filename_patterns = [
            re.compile(r'^\w+\.\w{2,4}$'),  # Simple filename pattern
            re.compile(r'^[A-Z][a-z]+[A-Z]'),  # CamelCase (likely code/filename)
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
        
        # Must have at least one dot
        if '.' not in domain_lower:
            return False
        
        # Extract TLD (last part after final dot)
        parts = domain_lower.rsplit('.', 1)
        if len(parts) != 2:
            return False
        
        tld = parts[1]
        name_part = parts[0]
        
        # Reject if it looks like a filename (single word + file extension)
        # But allow multi-part domains like evil-domain.com
        if tld in self.file_extensions and '.' not in name_part and '-' not in name_part:
            # Single word + file extension = likely a file, not domain
            return False
        
        # Reject if TLD is not in our valid TLDs list
        # Also check double TLDs like co.uk
        if tld not in self.valid_tlds:
            # Check for double TLD
            if '.' in parts[0]:
                double_parts = domain_lower.rsplit('.', 2)
                if len(double_parts) >= 2:
                    double_tld = f"{double_parts[-2]}.{double_parts[-1]}"
                    if double_tld not in self.valid_tlds:
                        return False
                else:
                    return False
            else:
                return False
        
        # Check exact whitelist
        if domain_lower in self.domain_whitelist:
            return False
        
        # Check if subdomain of whitelisted
        for whitelisted in self.domain_whitelist:
            if domain_lower.endswith('.' + whitelisted):
                return False
        
        # Exclude reserved/example TLDs
        if domain_lower.endswith(('.example', '.test', '.local', '.localhost', '.invalid', '.onion')):
            return False
        
        # Reject if it looks like a Windows path component
        if domain_lower.endswith(('.dll', '.exe', '.sys', '.bat', '.cmd', '.msi')):
            return False
        
        # Reject single-label "domains" that got a fake TLD
        if len(name_part) < 2:
            return False
        
        # Reject ALL CAPS (likely acronym/code, not domain)
        if domain.isupper() and len(domain) < 20:
            return False
        
        return True
    
    def is_valid_url(self, url):
        """Check if URL should be included"""
        url_lower = url.lower()
        
        # Check if URL domain is whitelisted
        try:
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check whitelist
            if domain in self.domain_whitelist:
                return False
            
            for whitelisted in self.domain_whitelist:
                if domain.endswith('.' + whitelisted):
                    return False
                    
        except Exception:
            pass
        
        # Reject common non-threat URLs
        safe_patterns = [
            r'https?://schemas\.',
            r'https?://www\.w3\.org',
            r'https?://xmlns\.',
            r'https?://docs\.',
            r'https?://support\.',
            r'https?://help\.',
        ]
        
        for pattern in safe_patterns:
            if re.match(pattern, url_lower):
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
                if ioc_type == IOCType.URL and not self.is_valid_url(value):
                    continue
                
                # Skip hashes that are too short or look like version numbers
                if ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
                    # Skip if all same character (placeholder)
                    if len(set(value.lower())) < 4:
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
            if re.search(r'\b(malicious|malware|sample|hash|indicator|ioc)\b', text, re.IGNORECASE):
                confidence = 0.85
            else:
                confidence = 0.6  # Hashes without context are less certain
        
        # IPs/domains with threat indicators
        if ioc_type in [IOCType.IP, IOCType.DOMAIN, IOCType.URL]:
            threat_keywords = ['malicious', 'c2', 'c&c', 'command and control', 'botnet', 
                             'ransomware', 'phishing', 'exploit', 'attacker', 'threat',
                             'ioc', 'indicator', 'compromise', 'malware', 'apt', 'campaign']
            for keyword in threat_keywords:
                if keyword in text.lower():
                    confidence = min(confidence + 0.1, 0.95)
        
        return round(confidence, 2)
    
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
                if count > 0:
                    print(f"Processed '{title[:60]}...' - extracted {count} IOCs")
            
            session.commit()
            return total_iocs
            
        except Exception as e:
            print(f"Error processing feed items: {e}")
            session.rollback()
            return 0
        finally:
            session.close()
