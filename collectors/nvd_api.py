import requests
import time
from storage.database import db
from storage.models import IOC, IOCType

class NVDCollector:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.rate_limit_delay = 6  # 5 requests per 30 seconds = 6 seconds between requests
        
        if api_key:
            self.rate_limit_delay = 0.6  # 50 requests per 30 seconds with API key
    
    def fetch_cve(self, cve_id):
        """Fetch detailed information for a specific CVE"""
        params = {'cveId': cve_id}
        headers = {}
        
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            response = requests.get(self.base_url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if data.get('resultsPerPage', 0) > 0:
                return data['vulnerabilities'][0]['cve']
            return None
            
        except Exception as e:
            print(f"Error fetching {cve_id} from NVD: {e}")
            return None
    
    def extract_cvss_scores(self, cve_data):
        """Extract CVSS scores from CVE data"""
        scores = {
            'cvss_v3_score': None,
            'cvss_v3_severity': None,
            'cvss_v3_vector': None,
            'cvss_v2_score': None,
            'cvss_v2_severity': None
        }
        
        # CVSS v3.x (prioritize v3.1, then v3.0)
        metrics = cve_data.get('metrics', {})
        
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            v3_data = metrics['cvssMetricV31'][0]['cvssData']
            scores['cvss_v3_score'] = v3_data.get('baseScore')
            scores['cvss_v3_severity'] = v3_data.get('baseSeverity')
            scores['cvss_v3_vector'] = v3_data.get('vectorString')
        
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            v3_data = metrics['cvssMetricV30'][0]['cvssData']
            scores['cvss_v3_score'] = v3_data.get('baseScore')
            scores['cvss_v3_severity'] = v3_data.get('baseSeverity')
            scores['cvss_v3_vector'] = v3_data.get('vectorString')
        
        # CVSS v2
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            v2_data = metrics['cvssMetricV2'][0]['cvssData']
            scores['cvss_v2_score'] = v2_data.get('baseScore')
            scores['cvss_v2_severity'] = v2_data.get('baseSeverity', 'UNKNOWN')
        
        return scores
    
    def extract_cwe_ids(self, cve_data):
        """Extract CWE IDs from CVE data"""
        cwes = []
        
        weaknesses = cve_data.get('weaknesses', [])
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe_id = desc.get('value', '')
                    if cwe_id.startswith('CWE-'):
                        cwes.append(cwe_id)
        
        return ', '.join(cwes) if cwes else None
    
    def extract_references(self, cve_data):
        """Extract reference URLs"""
        refs = []
        
        references = cve_data.get('references', [])
        for ref in references[:5]:  # Limit to 5 references
            url = ref.get('url')
            if url:
                refs.append(url)
        
        return ', '.join(refs) if refs else None
    
    def extract_description(self, cve_data):
        """Extract English description"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return None
    
    def enrich_cve_ioc(self, ioc_id):
        """Enrich a single CVE IOC with NVD data"""
        session = db.get_session()
        
        try:
            ioc = session.query(IOC).filter_by(id=ioc_id, ioc_type=IOCType.CVE).first()
            if not ioc:
                return False
            
            # Skip if already enriched
            if ioc.mitre_techniques:  # Using this field to track if enriched
                return False
            
            cve_id = ioc.value
            print(f"Enriching {cve_id}...")
            
            # Fetch from NVD
            cve_data = self.fetch_cve(cve_id)
            if not cve_data:
                print(f"  No data found for {cve_id}")
                return False
            
            # Extract CVSS scores
            scores = self.extract_cvss_scores(cve_data)
            
            # Extract CWE IDs
            cwe_ids = self.extract_cwe_ids(cve_data)
            
            # Extract description (store in context if empty)
            description = self.extract_description(cve_data)
            if description and not ioc.context:
                ioc.context = description[:500]  # Limit length
            
            # Store CWE in mitre_techniques field for now
            if cwe_ids:
                ioc.mitre_techniques = cwe_ids
            
            # Log enrichment
            cvss_str = f"CVSS v3: {scores['cvss_v3_score']} ({scores['cvss_v3_severity']})" if scores['cvss_v3_score'] else "No CVSS"
            cwe_str = f"CWE: {cwe_ids}" if cwe_ids else "No CWE"
            print(f"  {cvss_str} | {cwe_str}")
            
            session.commit()
            
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            return True
            
        except Exception as e:
            print(f"Error enriching IOC {ioc_id}: {e}")
            session.rollback()
            return False
        finally:
            session.close()
    
    def enrich_all_cves(self, limit=None):
        """Enrich all CVE IOCs that haven't been enriched yet"""
        session = db.get_session()
        
        try:
            # Find CVEs without enrichment data
            query = session.query(IOC).filter(
                IOC.ioc_type == IOCType.CVE,
                IOC.mitre_techniques.is_(None)
            )
            
            if limit:
                query = query.limit(limit)
            
            cves = query.all()
            cve_ids = [cve.id for cve in cves]
            
        finally:
            session.close()
        
        enriched_count = 0
        total = len(cve_ids)
        
        print(f"Found {total} CVEs to enrich")
        
        for idx, cve_id in enumerate(cve_ids, 1):
            print(f"\n[{idx}/{total}]", end=" ")
            if self.enrich_cve_ioc(cve_id):
                enriched_count += 1
        
        print(f"\n\nEnriched {enriched_count} CVEs")
        return enriched_count