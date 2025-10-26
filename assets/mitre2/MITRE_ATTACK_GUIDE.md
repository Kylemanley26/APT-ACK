# MITRE ATT&CK Integration Guide

## Overview

APT-ACK now automatically maps threat intelligence to MITRE ATT&CK techniques, providing standardized categorization of adversary tactics and techniques.

## Features

### Automated Technique Detection
- **Keyword Matching**: Detects techniques from content (e.g., "phishing" -> T1566)
- **Malware Mapping**: Maps known malware families to their common TTPs
- **Context-Aware**: Analyzes full threat intel content and tags

### Technique Coverage

**80+ techniques across all tactics:**
- Initial Access (5 techniques)
- Execution (5 techniques)  
- Persistence (5 techniques)
- Privilege Escalation (3 techniques)
- Defense Evasion (7 techniques)
- Credential Access (5 techniques)
- Discovery (6 techniques)
- Lateral Movement (3 techniques)
- Collection (5 techniques)
- Command and Control (6 techniques)
- Exfiltration (5 techniques)
- Impact (7 techniques)

## Usage

### Initial Mapping

Run MITRE mapping on existing threat intel:

```bash
python scripts/test_mitre.py
```

This will:
1. Process all feed items
2. Detect MITRE techniques from content
3. Map malware tags to techniques
4. Create technique tags
5. Display coverage matrix

### Collection Pipeline Integration

MITRE mapping is now part of the standard collection pipeline:

```bash
# Full pipeline with MITRE mapping
python scripts/run_collection.py

# Skip MITRE mapping if needed
python scripts/run_collection.py --skip-mitre
```

### Web Dashboard

#### Techniques Page
Navigate to `/techniques` to view:
- Technique matrix organized by tactic
- Occurrence counts for each technique
- Heat map visualization
- Click any technique to filter threat intel

#### Feed Items
Each feed item now displays:
- Purple MITRE technique badges (e.g., T1566)
- Technique names on hover
- Click to filter by technique

#### Filtering
Filter feeds by technique:
```
/feeds?technique=t1566
```

## Architecture

### Technique Detection Logic

```python
# Pattern matching
text -> keywords -> technique ID

# Malware mapping  
malware_tag -> known_TTPs -> technique IDs

# Combined approach
content_techniques + malware_techniques -> unique_list
```

### Data Storage

**Tags Table:**
```
category: mitre_technique
name: mitre-t1566
```

**IOC Table:**
```
mitre_techniques: T1486, T1490 (comma-separated)
```

### API Endpoints

**Get Technique Matrix:**
```
GET /api/techniques
Returns: { tactic: [{ id, name, count }] }
```

**Filter by Technique:**
```
GET /api/feeds?technique=t1566
```

## Examples

### Example Mappings

**Ransomware Article:**
```
Content: "LockBit ransomware encrypts files and deletes backups"
Detected: T1486 (Data Encrypted for Impact)
          T1490 (Inhibit System Recovery)
```

**Phishing Campaign:**
```
Content: "Spear phishing emails with malicious attachments"
Tags: phishing
Detected: T1566 (Phishing)
          T1204 (User Execution)
```

**Cobalt Strike Usage:**
```
Tags: cobalt strike
Detected: T1055 (Process Injection)
          T1021 (Remote Services)
          T1071 (Application Layer Protocol)
```

### Dashboard Output

```
=== TECHNIQUE COVERAGE MATRIX ===

Initial Access:
  T1566: Phishing (23 items)
  T1190: Exploit Public-Facing Application (12 items)
  T1133: External Remote Services (8 items)

Execution:
  T1059: Command and Scripting Interpreter (45 items)
  T1203: Exploitation for Client Execution (15 items)

Defense Evasion:
  T1027: Obfuscated Files or Information (34 items)
  T1562: Impair Defenses (28 items)
  
... [continues for all tactics]
```

## Configuration

### Adding New Techniques

Edit `enrichment/mitre_attack_mapper.py`:

```python
self.technique_patterns = {
    'T1234': ['new keyword', 'another pattern'],
}

self.technique_metadata = {
    'T1234': {'name': 'New Technique', 'tactic': 'Tactic Name'},
}
```

### Custom Malware Mappings

```python
self.malware_techniques = {
    'custom_malware': ['T1234', 'T1235'],
}
```

## Performance

- **Mapping Speed**: ~100 items/second
- **Memory**: Minimal overhead (tag-based)
- **Database**: Standard SQLAlchemy queries
- **No External API**: All detection is local

## Best Practices

1. **Run After Tagging**: MITRE mapping should run after threat tagging for best results
2. **Periodic Re-mapping**: Re-run on existing data when adding new technique patterns
3. **Verify Mappings**: Review technique assignments for high-value intel
4. **Export for SIEM**: Use technique tags in STIX/TAXII exports

## Integration with Other Tools

### Detection Engineering

Use technique mappings to prioritize detection rule development:

```python
from enrichment.mitre_attack_mapper import MitreAttackMapper

mapper = MitreAttackMapper()
matrix = mapper.export_technique_matrix()

# Find most common techniques
top_techniques = sorted(
    matrix.items(), 
    key=lambda x: x[1]['count'], 
    reverse=True
)[:10]
```

### Threat Hunting

Filter threat intel by technique for targeted hunting:

```bash
# Find all ransomware-related intel
curl "http://localhost:5000/api/feeds?technique=t1486"
```

### Gap Analysis

Identify coverage gaps:

```python
# All MITRE techniques
all_techniques = set(mapper.technique_metadata.keys())

# Detected techniques
detected = set(mapper.export_technique_matrix().keys())

# Gaps
gaps = all_techniques - detected
```

## Roadmap

### Phase 1 (Current)
- [x] Keyword-based detection
- [x] Malware TTP mapping
- [x] Web UI integration
- [x] Technique matrix view

### Phase 2 (Planned)
- [ ] Sub-technique support (T1566.001, etc.)
- [ ] MITRE ATT&CK Navigator export
- [ ] Technique heat map over time
- [ ] Automated detection rule suggestions

### Phase 3 (Future)
- [ ] ML-based technique prediction
- [ ] Procedure example extraction
- [ ] Campaign tracking by technique overlap
- [ ] STIX integration with techniques

## Troubleshooting

**No techniques detected:**
- Verify threat tagging ran first
- Check keyword patterns in mapper
- Review feed item content quality

**Incorrect mappings:**
- Tune keyword patterns
- Add malware to technique mappings
- Consider manual tag overrides

**Performance issues:**
- MITRE mapping is lightweight (no API calls)
- Batch process large datasets
- Use database indexes on tag category

## References

- MITRE ATT&CK Framework: https://attack.mitre.org
- Technique Matrix: https://attack.mitre.org/matrices/enterprise
- Navigator Tool: https://mitre-attack.github.io/attack-navigator

## Support

For questions or issues with MITRE integration:
- Check logs for mapping errors
- Review technique patterns in source
- Verify tag relationships in database
