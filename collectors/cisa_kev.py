import requests
from datetime import datetime, UTC
from storage.database import db
from storage.models import FeedItem, IOC, IOCType, SeverityLevel

class CISAKEVCollector:
    def __init__(self):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.source_name = "CISA KEV"
    
    def fetch_kev_catalog(self):
        """Fetch CISA Known Exploited Vulnerabilities catalog"""
        try:
            response = requests.get(self.kev_url, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching CISA KEV catalog: {e}")
            return None
    
    def collect(self, days_lookback=30):
        """Collect KEV entries, optionally filtering recent additions"""
        kev_data = self.fetch_kev_catalog()
        if not kev_data:
            return 0
        
        vulnerabilities = kev_data.get('vulnerabilities', [])
        
        session = db.get_session()
        new_items = 0
        
        try:
            for vuln in vulnerabilities:
                cve_id = vuln.get('cveID')
                if not cve_id:
                    continue
                
                # Generate unique link
                link = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}"
                
                # Check if already exists
                existing = session.query(FeedItem).filter_by(link=link).first()
                if existing:
                    continue
                
                # Parse dates
                date_added = vuln.get('dateAdded')
                published_date = None
                if date_added:
                    try:
                        published_date = datetime.strptime(date_added, '%Y-%m-%d').replace(tzinfo=UTC)
                    except:
                        pass
                
                # Skip if too old (optional filter)
                if days_lookback and published_date:
                    days_diff = (datetime.now(UTC) - published_date).days
                    if days_diff > days_lookback:
                        continue
                
                # Build content
                vendor_project = vuln.get('vendorProject', 'Unknown')
                product = vuln.get('product', 'Unknown')
                vuln_name = vuln.get('vulnerabilityName', '')
                description = vuln.get('shortDescription', '')
                required_action = vuln.get('requiredAction', '')
                due_date = vuln.get('dueDate', '')
                ransomware_use = vuln.get('knownRansomwareCampaignUse', 'Unknown')
                
                title = f"{cve_id}: {vendor_project} {product} - {vuln_name}"
                
                content = f"{description}\n\n"
                content += f"Vendor: {vendor_project}\n"
                content += f"Product: {product}\n"
                content += f"Required Action: {required_action}\n"
                content += f"Due Date: {due_date}\n"
                content += f"Known Ransomware Use: {ransomware_use}"
                
                # Create feed item - KEV items are always CRITICAL
                feed_item = FeedItem(
                    source_name=self.source_name,
                    source_url=self.kev_url,
                    title=title,
                    content=content,
                    link=link,
                    published_date=published_date,
                    severity=SeverityLevel.CRITICAL,
                    relevance_score=0.95,  # KEV items are high relevance by default
                    processed=True
                )
                
                session.add(feed_item)
                session.flush()  # Get feed_item.id
                
                # Add CVE as IOC
                cve_ioc = IOC(
                    feed_item_id=feed_item.id,
                    ioc_type=IOCType.CVE,
                    value=cve_id,
                    context=vuln_name,
                    confidence=1.0,  # CISA KEV is authoritative
                    verified=True
                )
                session.add(cve_ioc)
                
                new_items += 1
            
            session.commit()
            print(f"Collected {new_items} new KEV entries from CISA")
            return new_items
            
        except Exception as e:
            print(f"Error saving KEV entries: {e}")
            session.rollback()
            return 0
        finally:
            session.close()
    
    def get_stats(self):
        """Get statistics about KEV catalog"""
        kev_data = self.fetch_kev_catalog()
        if not kev_data:
            return None
        
        stats = {
            'title': kev_data.get('title'),
            'catalog_version': kev_data.get('catalogVersion'),
            'date_released': kev_data.get('dateReleased'),
            'total_vulnerabilities': kev_data.get('count', len(kev_data.get('vulnerabilities', [])))
        }
        
        # Count ransomware-related
        ransomware_count = sum(
            1 for v in kev_data.get('vulnerabilities', [])
            if v.get('knownRansomwareCampaignUse', '').lower() == 'known'
        )
        stats['ransomware_related'] = ransomware_count
        
        return stats