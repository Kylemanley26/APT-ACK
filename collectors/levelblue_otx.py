# collectors/levelblue_otx.py
"""
LevelBlue OTX (Open Threat Exchange) Collector
Enriches IOCs and collects threat intelligence pulses
"""
import requests
import time
from datetime import datetime, UTC, timedelta
from storage.database import db
from storage.models import FeedItem, IOC, Tag, SeverityLevel, IOCType

class LevelBlueCollector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": api_key}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Rate limiting (10,000 requests/hour = ~3 requests/second)
        self.rate_limit_delay = 0.35  # Conservative 350ms between requests
    
    def _rate_limit(self):
        """Simple rate limiting"""
        time.sleep(self.rate_limit_delay)
    
    def get_ioc_general(self, ioc_type, value):
        """Get general IOC information"""
        endpoint_map = {
            'ip': f"/indicators/IPv4/{value}/general",
            'domain': f"/indicators/domain/{value}/general",
            'hash_md5': f"/indicators/file/{value}/general",
            'hash_sha1': f"/indicators/file/{value}/general",
            'hash_sha256': f"/indicators/file/{value}/general",
            'url': f"/indicators/url/{value}/general"
        }
        
        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return None
        
        try:
            self._rate_limit()
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None  # IOC not found in OTX
            else:
                print(f"  OTX API error {response.status_code} for {value}")
                return None
                
        except Exception as e:
            print(f"  Error fetching OTX data for {value}: {e}")
            return None
    
    def get_ioc_malware(self, ioc_type, value):
        """Get malware associations for IOC"""
        endpoint_map = {
            'ip': f"/indicators/IPv4/{value}/malware",
            'domain': f"/indicators/domain/{value}/malware",
            'hash_md5': f"/indicators/file/{value}/analysis",
            'hash_sha1': f"/indicators/file/{value}/analysis",
            'hash_sha256': f"/indicators/file/{value}/analysis"
        }
        
        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return None
        
        try:
            self._rate_limit()
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            return None
                
        except Exception as e:
            print(f"  Error fetching malware data: {e}")
            return None
    
    def enrich_ioc(self, ioc_id):
        """Enrich a single IOC with OTX data"""
        session = db.get_session()
        
        try:
            ioc = session.query(IOC).filter_by(id=ioc_id).first()
            if not ioc:
                return False
            
            # Skip CVEs (use NVD instead)
            if ioc.ioc_type == IOCType.CVE:
                return False
            
            # Skip if already enriched recently (check if threat_actor is set)
            # You might want to add a last_enriched timestamp field
            
            value = ioc.value
            ioc_type = ioc.ioc_type.value
            
            print(f"Enriching {ioc_type}: {value}")
            
            # Get general info
            general_data = self.get_ioc_general(ioc_type, value)
            if not general_data:
                return False
            
            # Extract pulse count and reputation
            pulse_count = general_data.get('pulse_info', {}).get('count', 0)
            
            if pulse_count == 0:
                print(f"  No OTX pulses found for {value}")
                return False
            
            print(f"  Found in {pulse_count} OTX pulses")
            
            # Get malware associations
            malware_data = self.get_ioc_malware(ioc_type, value)
            
            # Extract malware families
            if malware_data:
                if ioc_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
                    # File hash analysis
                    analysis = malware_data.get('analysis', {})
                    malware_families = analysis.get('malware', {}).get('data', [])
                    if malware_families and ioc.malware_family is None:
                        detections = malware_families[0].get('detections', {})
                        if isinstance(detections, dict):
                            family = detections.get('avast', '') or detections.get('kaspersky', '') or ''
                            if family:
                                ioc.malware_family = str(family)[:255]
                                print(f"  Malware family: {family}")
                else:
                    # IP/Domain malware associations
                    malware_list = malware_data.get('data', [])
                    if malware_list and ioc.malware_family is None:
                        detections = malware_list[0].get('detections', '')
                        if detections:
                            ioc.malware_family = str(detections)[:255]
                            print(f"  Malware family: {detections}")
            
            # Extract threat actors from pulses
            pulses = general_data.get('pulse_info', {}).get('pulses', [])
            threat_actors = set()
            mitre_techniques = set()
            
            for pulse in pulses[:5]:  # Check first 5 pulses
                # Look for APT/threat actor tags
                tags = pulse.get('tags', [])
                for tag in tags:
                    tag_lower = tag.lower()
                    if any(apt in tag_lower for apt in ['apt', 'lazarus', 'sandworm', 'turla']):
                        threat_actors.add(tag)
                
                # Extract MITRE ATT&CK references
                attack_ids = pulse.get('attack_ids', [])
                for attack in attack_ids:
                    technique_id = attack.get('id', '')
                    if technique_id:
                        mitre_techniques.add(technique_id)
            
            # Update threat actor if found
            if threat_actors and ioc.threat_actor is None:
                ioc.threat_actor = ', '.join(list(threat_actors)[:3])[:255]
                print(f"  Threat actors: {ioc.threat_actor}")
            
            # Update MITRE techniques
            if mitre_techniques:
                existing_techniques = str(ioc.mitre_techniques or '')
                all_techniques = set(existing_techniques.split(', ')) if existing_techniques else set()
                all_techniques.update(mitre_techniques)
                ioc.mitre_techniques = ', '.join(sorted(all_techniques))[:500]
                print(f"  MITRE techniques: {ioc.mitre_techniques}")

            # Increase confidence based on pulse count
            if pulse_count > 0:
                # Boost confidence (max 0.95)
                confidence_boost = min(pulse_count * 0.05, 0.3)
                current_confidence = float(ioc.confidence or 0.5)
                ioc.confidence = min(current_confidence + confidence_boost, 0.95)
                print(f"  Updated confidence: {ioc.confidence:.2f}")
            
            # Mark as verified if found in multiple pulses
            if pulse_count >= 3:
                ioc.verified = True
            
            # Add OTX tag
            otx_tag = session.query(Tag).filter_by(name='otx-validated').first()
            if not otx_tag:
                otx_tag = Tag(name='otx-validated', category='validation', auto_generated=True)
                session.add(otx_tag)
            
            if otx_tag not in ioc.tags:
                ioc.tags.append(otx_tag)
            
            # Update last_seen
            ioc.last_seen = datetime.now(UTC)
            
            session.commit()
            return True
            
        except Exception as e:
            print(f"Error enriching IOC {ioc_id}: {e}")
            session.rollback()
            return False
        finally:
            session.close()
    
    def enrich_recent_iocs(self, days=7, limit=100):
        """Enrich IOCs from the last N days"""
        session = db.get_session()
        
        try:
            # Find recent IOCs that aren't CVEs
            cutoff_date = datetime.now(UTC) - timedelta(days=days)
            
            iocs = session.query(IOC).filter(
                IOC.ioc_type != IOCType.CVE,
                IOC.first_seen >= cutoff_date
            ).limit(limit).all()
            
            ioc_ids = [ioc.id for ioc in iocs]
            
        finally:
            session.close()
        
        enriched_count = 0
        total = len(ioc_ids)
        
        if total == 0:
            print("No IOCs to enrich")
            return 0
        
        print(f"\nEnriching {total} IOCs with LevelBlue OTX...")
        
        for idx, ioc_id in enumerate(ioc_ids, 1):
            print(f"\n[{idx}/{total}]", end=" ")
            if self.enrich_ioc(ioc_id):
                enriched_count += 1
        
        print(f"\n\nEnriched {enriched_count}/{total} IOCs")
        return enriched_count
    
    def collect_pulses(self, days_back=7):
        """Collect recent threat pulses as feed items"""
        session = db.get_session()
        
        try:
            # Get subscribed pulses
            self._rate_limit()
            response = self.session.get(
                f"{self.base_url}/pulses/subscribed",
                params={'limit': 50, 'page': 1},
                timeout=30
            )
            
            if response.status_code != 200:
                print(f"Error fetching pulses: {response.status_code}")
                return 0
            
            pulses = response.json().get('results', [])
            
            new_items = 0
            cutoff_date = datetime.now(UTC) - timedelta(days=days_back)
            
            for pulse in pulses:
                # Parse dates
                created = pulse.get('created')
                if not created:
                    continue
                
                try:
                    # Normalize datetime format
                    if created.endswith('Z'):
                        created = created.replace('Z', '+00:00')
                    
                    published_date = datetime.fromisoformat(created)
                    
                    # Ensure timezone-aware
                    if published_date.tzinfo is None:
                        published_date = published_date.replace(tzinfo=UTC)
                except Exception as e:
                    print(f"  Error parsing date '{created}': {e}")
                    continue
                
                # Skip old pulses
                if published_date < cutoff_date:
                    continue
                
                # Check if already exists
                pulse_id = pulse.get('id')
                link = f"https://otx.alienvault.com/pulse/{pulse_id}"
                
                existing = session.query(FeedItem).filter_by(link=link).first()
                if existing:
                    continue
                
                # Extract data
                title = pulse.get('name', 'Untitled Pulse')
                description = pulse.get('description', '')
                tags = pulse.get('tags', [])
                
                # Determine severity based on tags
                severity = SeverityLevel.INFO
                if any(tag.lower() in ['critical', 'zero-day', 'ransomware'] for tag in tags):
                    severity = SeverityLevel.CRITICAL
                elif any(tag.lower() in ['apt', 'exploit', 'malware'] for tag in tags):
                    severity = SeverityLevel.HIGH
                elif any(tag.lower() in ['phishing', 'vulnerability'] for tag in tags):
                    severity = SeverityLevel.MEDIUM
                
                # Build content
                content = description
                if tags:
                    content += f"\n\nTags: {', '.join(tags[:10])}"
                
                indicator_count = len(pulse.get('indicators', []))
                content += f"\n\nIndicators: {indicator_count}"
                
                # Create feed item
                feed_item = FeedItem(
                    source_name="LevelBlue OTX",
                    source_url="https://otx.alienvault.com",
                    title=title,
                    content=content,
                    link=link,
                    published_date=published_date,
                    severity=severity,
                    relevance_score=0.75,  # OTX is high quality
                    processed=False
                )
                
                session.add(feed_item)
                session.flush()
                
                # Add tags
                for tag_name in tags[:10]:  # Limit to 10 tags
                    tag = session.query(Tag).filter_by(name=tag_name.lower()).first()
                    if not tag:
                        tag = Tag(name=tag_name.lower(), category='otx', auto_generated=True)
                        session.add(tag)
                    
                    if tag not in feed_item.tags:
                        feed_item.tags.append(tag)
                
                # Extract IOCs from pulse
                indicators = pulse.get('indicators', [])
                for indicator in indicators[:50]:  # Limit IOCs per pulse
                    ioc_type_map = {
                        'IPv4': IOCType.IP,
                        'IPv6': IOCType.IP,
                        'domain': IOCType.DOMAIN,
                        'hostname': IOCType.DOMAIN,
                        'URL': IOCType.URL,
                        'FileHash-MD5': IOCType.HASH_MD5,
                        'FileHash-SHA1': IOCType.HASH_SHA1,
                        'FileHash-SHA256': IOCType.HASH_SHA256,
                        'email': IOCType.EMAIL,
                        'CVE': IOCType.CVE
                    }
                    
                    otx_type = indicator.get('type')
                    ioc_type = ioc_type_map.get(otx_type)
                    
                    if not ioc_type:
                        continue
                    
                    value = indicator.get('indicator', '')
                    if not value:
                        continue
                    
                    # Check if IOC already exists
                    existing_ioc = session.query(IOC).filter_by(
                        value=value,
                        ioc_type=ioc_type
                    ).first()
                    
                    if existing_ioc:
                        # Update last_seen
                        existing_ioc.last_seen = datetime.now(UTC)
                        continue
                    
                    # Create new IOC
                    ioc = IOC(
                        feed_item_id=feed_item.id,
                        ioc_type=ioc_type,
                        value=value,
                        context=indicator.get('description', ''),
                        confidence=0.8,  # OTX is high confidence
                        verified=True
                    )
                    
                    session.add(ioc)
                
                new_items += 1
                print(f"  Collected pulse: {title[:60]}... ({indicator_count} indicators)")
            
            session.commit()
            print(f"\nCollected {new_items} new pulses from LevelBlue OTX")
            return new_items
            
        except Exception as e:
            print(f"Error collecting pulses: {e}")
            session.rollback()
            return 0
        finally:
            session.close()