# CVSS-Based Relevance Scoring Implementation Guide

## Objective
Replace keyword-guessing relevance scoring with objective CVSS-based scoring for CVE threats while maintaining universal threat indicators for non-CVE intelligence. This creates an environment-agnostic public threat feed that prioritizes based on industry-standard metrics.

## Problem Statement

### Current System (Keyword Guessing)
```python
if 'zero-day' in text:
    score += 0.3  # Subjective, gamed by headlines

if 'critical' in text:
    score += some_arbitrary_number
```

**Issues:**
- Sensational headlines score artificially high
- No objective measurement
- Ignores CVSS data we're already fetching from NVD

### New System (CVSS + Universal Threat Indicators)
```python
# For CVE threats: Use objective CVSS scores
if ioc.cvss_v3_score >= 9.0:
    score += 0.6  # Based on NIST standard

# For non-CVE threats: Use universal indicators
if threat_actor_present:
    score += 0.2  # APT activity is universally relevant

if actively_exploited:
    score += 0.2  # Active exploitation is universally relevant
```

## Implementation Steps

### Step 1: Update Database Schema

**File:** `storage/models.py`

**Action:** ADD new CVSS fields to IOC model

**Find this section** (around line 40-70):
```python
class IOC(Base):
    __tablename__ = 'iocs'
    
    id = Column(Integer, primary_key=True)
    feed_item_id = Column(Integer, ForeignKey('feed_items.id'))
    ioc_type = Column(Enum(IOCType), nullable=False, index=True)
    value = Column(String(512), nullable=False, index=True)
    confidence = Column(Float, default=0.5)
    context = Column(Text)
    first_seen = Column(DateTime, default=lambda: datetime.now(UTC))
    verified = Column(Boolean, default=False)
    threat_actor = Column(String(255))
    malware_family = Column(String(255))
    mitre_techniques = Column(String(512))
```

**Add AFTER mitre_techniques:**
```python
    # CVSS Scoring (from NVD enrichment)
    cvss_v3_score = Column(Float, index=True)              # 0.0-10.0 base score
    cvss_v3_severity = Column(String(20))                  # CRITICAL/HIGH/MEDIUM/LOW
    cvss_v3_vector = Column(String(100))                   # Full CVSS v3 vector string
    cvss_v2_score = Column(Float)                          # Legacy CVSS v2 (fallback)
    cvss_v2_severity = Column(String(20))                  # Legacy severity
```

### Step 2: Persist CVSS Scores in Database

**File:** `collectors/nvd_api.py`

**Action:** MODIFY enrich_cve_ioc() to store CVSS scores

**Find this section** (around line 85-110):
```python
def enrich_cve_ioc(self, ioc_id):
    """Enrich a single CVE IOC with NVD data"""
    session = db.get_session()
    
    try:
        # ... existing code ...
        
        # Extract CVSS scores
        scores = self.extract_cvss_scores(cve_data)
        
        # Extract CWE IDs
        cwe_ids = self.extract_cwe_ids(cve_data)
        
        # Extract description
        description = self.extract_description(cve_data)
        if description and not ioc.context:
            ioc.context = description[:500]
        
        # Store CWE in mitre_techniques field for now
        if cwe_ids:
            ioc.mitre_techniques = cwe_ids
        
        # Log enrichment
        cvss_str = f"CVSS v3: {scores['cvss_v3_score']} ({scores['cvss_v3_severity']})" if scores['cvss_v3_score'] else "No CVSS"
```

**Replace the section starting from "# Store CWE..." with:**
```python
        # Store CWE in mitre_techniques field
        if cwe_ids:
            ioc.mitre_techniques = cwe_ids
        
        # NEW: Store CVSS scores
        if scores['cvss_v3_score']:
            ioc.cvss_v3_score = scores['cvss_v3_score']
            ioc.cvss_v3_severity = scores['cvss_v3_severity']
            ioc.cvss_v3_vector = scores['cvss_v3_vector']
        
        if scores['cvss_v2_score']:
            ioc.cvss_v2_score = scores['cvss_v2_score']
            ioc.cvss_v2_severity = scores['cvss_v2_severity']
        
        # Log enrichment (existing)
        cvss_str = f"CVSS v3: {scores['cvss_v3_score']} ({scores['cvss_v3_severity']})" if scores['cvss_v3_score'] else "No CVSS"
```

### Step 3: Update Relevance Scoring Algorithm

**File:** `enrichment/tagging_engine.py`

**Action:** REPLACE calculate_relevance_score() method

**Find this method** (around line 100-135):
```python
def calculate_relevance_score(self, text, tags):
    """Calculate relevance score 0.0 to 1.0"""
    score = 0.0
    text_lower = text.lower()
    
    # Base score on number of tags
    score += min(len(tags) * 0.1, 0.3)
    
    # Boost for threat actors
    if any(cat == 'threat_actor' for cat in tags.values()):
        score += 0.2
    
    # ... rest of keyword-based scoring ...
    
    return min(score, 1.0)
```

**Replace entire method with:**
```python
def calculate_relevance_score(self, feed_item, tags):
    """
    Calculate relevance score 0.0 to 1.0 based on objective metrics.
    
    Scoring Philosophy:
    - CVE threats: Use CVSS scores (objective, standardized)
    - Non-CVE threats: Use universal threat indicators
    - Environment agnostic: No org-specific tuning
    
    Score Breakdown:
    - 0.0-0.3: Informational/Low priority
    - 0.3-0.6: Medium priority (monitor)
    - 0.6-0.8: High priority (investigate)
    - 0.8-1.0: Critical priority (immediate action)
    """
    score = 0.0
    text = f"{feed_item.title} {feed_item.content}".lower()
    
    # ========================================
    # PRIMARY: CVSS-Based Scoring for CVEs
    # ========================================
    max_cvss = 0.0
    has_cve = False
    
    for ioc in feed_item.iocs:
        if ioc.ioc_type == IOCType.CVE:
            has_cve = True
            
            # Use CVSS v3 score (preferred), fallback to v2
            cvss_score = ioc.cvss_v3_score or ioc.cvss_v2_score
            
            if cvss_score:
                max_cvss = max(max_cvss, cvss_score)
    
    if max_cvss > 0:
        # Map CVSS 0-10 to relevance 0-0.7
        # CVSS 10.0 = 0.7 relevance (leaves room for other factors)
        # CVSS 9.0 = 0.63
        # CVSS 7.0 = 0.49
        # CVSS 5.0 = 0.35
        score += (max_cvss / 10.0) * 0.7
    
    # ========================================
    # UNIVERSAL THREAT INDICATORS
    # ========================================
    
    # Threat Actor Activity (+0.2)
    # APT/threat actor campaigns are universally relevant
    if any(cat == 'threat_actor' for cat in tags.values()):
        score += 0.2
    
    # Active Exploitation (+0.25)
    # "In the wild" exploitation is universally critical
    if 'actively exploited' in text or 'in the wild' in text or 'exploit available' in text:
        score += 0.25
    
    # Widespread Malware Campaigns (+0.15)
    # Known malware families indicate active threats
    if any(cat == 'malware' for cat in tags.values()):
        score += 0.15
    
    # Zero-Day Vulnerabilities (+0.2)
    # Unpatched vulnerabilities are universally high priority
    if 'zero-day' in text or 'zero day' in text or '0-day' in text:
        score += 0.2
    
    # Ransomware Activity (+0.2)
    # Ransomware is a universal critical threat
    if 'ransomware' in text:
        score += 0.2
    
    # Data Breach Incidents (+0.15)
    # Major breaches indicate successful attacks
    if 'data breach' in text or 'data leak' in text:
        score += 0.15
    
    # ========================================
    # SOURCE CREDIBILITY BOOSTS
    # ========================================
    
    # CISA KEV (Known Exploited Vulnerabilities)
    # Government-confirmed exploitation = always high priority
    if feed_item.source_name == "CISA KEV":
        score = max(score, 0.95)
    
    # ========================================
    # PENALTY: Reduce Over-Scoring
    # ========================================
    
    # If CVE has low CVSS but keywords boost it, cap score
    # Prevents "critical vulnerability" in title boosting CVSS 3.0 vuln
    if has_cve and max_cvss < 7.0:
        score = min(score, 0.6)  # Cap medium CVSS at medium relevance
    
    return min(score, 1.0)
```

**Note:** This method signature changed from `(text, tags)` to `(feed_item, tags)` to access IOCs.

### Step 4: Update Method Call in tag_feed_item()

**File:** `enrichment/tagging_engine.py`

**Action:** UPDATE the call to calculate_relevance_score()

**Find this section** (around line 170):
```python
def tag_feed_item(self, feed_item_id):
    """Tag and score a single feed item"""
    session = db.get_session()
    
    try:
        feed_item = session.query(FeedItem).filter_by(id=feed_item_id).first()
        # ... tagging code ...
        
        # Calculate relevance score
        relevance = self.calculate_relevance_score(text, tag_dict)
```

**Replace the relevance calculation line with:**
```python
        # Calculate relevance score (UPDATED: now uses feed_item instead of text)
        relevance = self.calculate_relevance_score(feed_item, tag_dict)
```

### Step 5: Database Migration Script

**File:** `scripts/migrate_add_cvss.py` (CREATE NEW)

**Action:** CREATE new migration script

```python
#!/usr/bin/env python3
"""
Database migration to add CVSS fields to IOC table.
Run this ONCE after updating models.py.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.database import db
from sqlalchemy import inspect

def migrate_add_cvss():
    """Add CVSS columns to IOC table"""
    
    print("Checking IOC table structure...")
    
    engine = db.engine
    inspector = inspect(engine)
    
    # Get current columns
    columns = [col['name'] for col in inspector.get_columns('iocs')]
    
    # Check if migration needed
    if 'cvss_v3_score' in columns:
        print("✓ CVSS columns already exist - no migration needed")
        return
    
    print("Adding CVSS columns to IOC table...")
    
    # SQLite doesn't support multiple ADD COLUMN, so run separately
    with engine.connect() as conn:
        try:
            conn.execute("ALTER TABLE iocs ADD COLUMN cvss_v3_score REAL")
            print("  ✓ Added cvss_v3_score")
        except Exception as e:
            print(f"  Note: cvss_v3_score - {e}")
        
        try:
            conn.execute("ALTER TABLE iocs ADD COLUMN cvss_v3_severity VARCHAR(20)")
            print("  ✓ Added cvss_v3_severity")
        except Exception as e:
            print(f"  Note: cvss_v3_severity - {e}")
        
        try:
            conn.execute("ALTER TABLE iocs ADD COLUMN cvss_v3_vector VARCHAR(100)")
            print("  ✓ Added cvss_v3_vector")
        except Exception as e:
            print(f"  Note: cvss_v3_vector - {e}")
        
        try:
            conn.execute("ALTER TABLE iocs ADD COLUMN cvss_v2_score REAL")
            print("  ✓ Added cvss_v2_score")
        except Exception as e:
            print(f"  Note: cvss_v2_score - {e}")
        
        try:
            conn.execute("ALTER TABLE iocs ADD COLUMN cvss_v2_severity VARCHAR(20)")
            print("  ✓ Added cvss_v2_severity")
        except Exception as e:
            print(f"  Note: cvss_v2_severity - {e}")
        
        conn.commit()
    
    print("\n✓ Migration complete!")
    print("\nNext steps:")
    print("1. Run: python scripts/test_nvd.py")
    print("   (Re-enriches CVEs with CVSS scores)")
    print("2. Run: python scripts/test_tagger.py")
    print("   (Re-calculates relevance scores using CVSS)")

if __name__ == "__main__":
    db.init_db()
    migrate_add_cvss()
```

### Step 6: Update Web API to Display CVSS

**File:** `web/app.py`

**Action:** ADD CVSS data to IOC serialization

**Find the IOC serialization** (around line 150-170 in get_feed_detail route):
```python
'iocs': [
    {
        'id': ioc.id,
        'type': ioc.ioc_type.value,
        'value': ioc.value,
        'confidence': ioc.confidence,
        'context': ioc.context,
        'verified': ioc.verified,
        'threat_actor': ioc.threat_actor,
        'malware_family': ioc.malware_family,
        'mitre_techniques': ioc.mitre_techniques
    } for ioc in item.iocs
]
```

**Replace with:**
```python
'iocs': [
    {
        'id': ioc.id,
        'type': ioc.ioc_type.value,
        'value': ioc.value,
        'confidence': ioc.confidence,
        'context': ioc.context,
        'verified': ioc.verified,
        'threat_actor': ioc.threat_actor,
        'malware_family': ioc.malware_family,
        'mitre_techniques': ioc.mitre_techniques,
        # NEW: CVSS data
        'cvss_v3_score': ioc.cvss_v3_score,
        'cvss_v3_severity': ioc.cvss_v3_severity,
        'cvss_v3_vector': ioc.cvss_v3_vector,
        'cvss_v2_score': ioc.cvss_v2_score
    } for ioc in item.iocs
]
```

## Testing Instructions

### 1. Run Database Migration
```bash
cd /home/baals/Desktop/bigdev/APT-ACK
source venv/bin/activate

# Add CVSS columns to database
python scripts/migrate_add_cvss.py
```

Expected output:
```
Checking IOC table structure...
Adding CVSS columns to IOC table...
  ✓ Added cvss_v3_score
  ✓ Added cvss_v3_severity
  ✓ Added cvss_v3_vector
  ✓ Added cvss_v2_score
  ✓ Added cvss_v2_severity

✓ Migration complete!
```

### 2. Re-Enrich CVEs with CVSS
```bash
# Fetch CVSS scores for all CVEs
python scripts/test_nvd.py
```

Expected output:
```
Total CVEs: 47
Unenriched CVEs: 47

Enriching CVEs from NVD...

[1/47] Enriching CVE-2024-1234...
  CVSS v3: 9.8 (CRITICAL) | CWE: CWE-787

[2/47] Enriching CVE-2024-5678...
  CVSS v3: 7.5 (HIGH) | CWE: CWE-79
```

### 3. Re-Calculate Relevance Scores
```bash
# Re-tag all items with new CVSS-based scoring
python scripts/test_tagger.py
```

Expected output:
```
Tagging feed items...

Tagged 'Critical RCE in...' - CRITICAL (score: 0.85, tags: 5)
Tagged 'New malware campaign...' - HIGH (score: 0.67, tags: 3)
Tagged 'Security advisory...' - MEDIUM (score: 0.42, tags: 2)

Severity Breakdown:
  CRITICAL: 12
  HIGH: 28
  MEDIUM: 45
  LOW: 18
  INFO: 53
```

### 4. Verify CVSS in Database
```bash
# Check that CVSS scores are stored
sqlite3 apt_ack.db "SELECT value, cvss_v3_score, cvss_v3_severity FROM iocs WHERE ioc_type='cve' LIMIT 5;"
```

Expected output:
```
CVE-2024-1234|9.8|CRITICAL
CVE-2024-5678|7.5|HIGH
CVE-2023-9999|5.3|MEDIUM
```

### 5. Test Web API
```bash
# Start web app
python web/app.py

# Test feed detail endpoint
curl http://localhost:5000/api/feed/1 | jq '.iocs[] | select(.type=="cve") | {value, cvss_v3_score, cvss_v3_severity}'
```

Expected output:
```json
{
  "value": "CVE-2024-1234",
  "cvss_v3_score": 9.8,
  "cvss_v3_severity": "CRITICAL"
}
```

## Verification Checklist

After implementation, verify:

- [ ] Database migration added CVSS columns
- [ ] NVD enrichment populates CVSS scores
- [ ] Relevance scores use CVSS data for CVEs
- [ ] High CVSS scores (9.0+) produce high relevance (0.8+)
- [ ] Low CVSS scores (4.0-) produce medium relevance (0.4-)
- [ ] Non-CVE threats still score based on threat indicators
- [ ] CISA KEV items maintain 0.95+ relevance
- [ ] Web API returns CVSS data in responses
- [ ] Terminal view shows improved prioritization

## Expected Behavior Changes

### Before (Keyword-Based)
```
"CRITICAL VULNERABILITY in obscure tool"
- Keyword: "CRITICAL" = +0.3
- No real severity assessment
- Relevance: 0.45 (medium-high)
- Result: False positive in high-priority queue
```

### After (CVSS-Based)
```
"CRITICAL VULNERABILITY in obscure tool"
- CVE present: CVE-2024-9999
- CVSS v3: 4.3 (MEDIUM)
- Relevance: 0.30 (medium)
- Result: Correctly prioritized as medium
```

### Example: Log4Shell
```
"Apache Log4j RCE Vulnerability (CVE-2021-44228)"
- CVE: CVE-2021-44228
- CVSS v3: 10.0 (CRITICAL)
- Actively exploited: +0.25
- Relevance: 0.95 (critical)
- Result: Correctly flagged as maximum priority
```

## Scoring Philosophy

### Environment Agnostic Design
The new scoring is based on **universal threat indicators** that are relevant to any security team:

1. **CVSS Scores** - Industry standard, vendor-neutral severity
2. **Active Exploitation** - "In the wild" attacks affect everyone
3. **Threat Actor Activity** - APT campaigns are universally concerning
4. **Ransomware** - Critical threat to all organizations
5. **Zero-Days** - Unpatched vulnerabilities are universal risk
6. **CISA KEV** - Government-confirmed active exploitation

### NOT Environment-Specific
The scoring does NOT consider:
- Your specific software stack
- Your industry/sector
- Your geographic region
- Your risk tolerance
- Your asset inventory

This makes APT-ACK useful as a public feed that any organization can consume and apply their own contextual filtering on top of.

## Future Enhancements

### Phase 1 (This Implementation)
- Store CVSS scores
- Use CVSS in relevance calculation
- Universal threat indicators

### Phase 2 (Future)
- CVSS Temporal Score (considers exploit availability)
- CVSS Environmental Score (organization-specific)
- EPSS (Exploit Prediction Scoring System)
- User-configurable scoring weights

### Phase 3 (Advanced)
- Machine learning on user behavior
- Integration with asset inventory
- Sector-specific threat models
- Custom priority rules engine

## Troubleshooting

**CVSS scores not appearing:**
- Run migration script first
- Check NVD enrichment completed
- Verify API key is set (faster rate limits)

**Relevance scores unchanged:**
- Re-run tagging: `python scripts/test_tagger.py`
- Check that calculate_relevance_score() signature updated
- Verify IOCs have cvss_v3_score populated

**All scores still low:**
- Check that NVD enrichment ran successfully
- Verify CVEs exist in feed items
- Check that IOC extraction found CVEs

**Migration fails:**
- Check database file exists
- Verify no other processes using database
- Try closing any open SQLite connections

## Success Metrics

After implementation, you should see:

1. **Better Prioritization**
   - High CVSS (9.0+) items at top of feed
   - Low CVSS (3.0-) items deprioritized
   - Non-CVE threats still properly ranked

2. **Objective Scoring**
   - CVSS 10.0 → ~0.9-1.0 relevance
   - CVSS 7.0 → ~0.6-0.7 relevance
   - CVSS 4.0 → ~0.3-0.4 relevance

3. **Reduced False Positives**
   - Sensational headlines don't artificially boost scores
   - "CRITICAL" keyword doesn't override objective data

4. **Universal Applicability**
   - Scoring works for any security team
   - No organization-specific tuning needed
   - Standards-based approach

## Files Modified Summary

**New Files:**
- `scripts/migrate_add_cvss.py`

**Modified Files:**
- `storage/models.py` (added CVSS fields)
- `collectors/nvd_api.py` (store CVSS scores)
- `enrichment/tagging_engine.py` (CVSS-based relevance)
- `web/app.py` (expose CVSS in API)

**No Changes Needed:**
- Collection pipeline (already enriches CVEs)
- RSS collectors
- IOC extraction
- Web templates (CVSS display is optional UI enhancement)
