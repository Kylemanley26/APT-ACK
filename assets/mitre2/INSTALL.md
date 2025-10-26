# MITRE ATT&CK Integration - Installation Guide

## Download Package

[View all files](computer:///mnt/user-data/outputs)

Or download the complete archive:
[mitre_attack_integration.tar.gz](computer:///mnt/user-data/outputs/mitre_attack_integration.tar.gz)

## File Placement

Extract to your APT-ACK directory and place files as follows:

```bash
cd /home/baals/Desktop/bigdev/APT-ACK

# Core engine
enrichment/mitre_attack_mapper.py

# Test script
scripts/test_mitre.py

# Updated collection pipeline
scripts/run_collection.py  # Replace with run_collection_updated.py

# Updated web app
web/app.py  # Replace with app_updated.py

# Web templates
web/templates/techniques.html  # NEW page
web/templates/base.html  # Replace with base_updated.html
web/templates/index.html  # Replace with index_updated.html

# Documentation
docs/MITRE_ATTACK_GUIDE.md
docs/MITRE_QUICK_REFERENCE.md
```

## Installation Commands

```bash
cd /home/baals/Desktop/bigdev/APT-ACK

# Create docs directory if it doesn't exist
mkdir -p docs

# Place core engine
cp mitre_attack_mapper.py enrichment/

# Place test script
cp test_mitre.py scripts/

# Update collection pipeline
cp run_collection_updated.py scripts/run_collection.py

# Update web app
cp app_updated.py web/app.py

# Add technique page
cp techniques.html web/templates/

# Update templates
cp base_updated.html web/templates/base.html
cp index_updated.html web/templates/index.html

# Add documentation
cp MITRE_ATTACK_GUIDE.md docs/
cp MITRE_QUICK_REFERENCE.md docs/
cp IMPLEMENTATION_SUMMARY.md docs/
```

## Quick Start

### 1. Run Initial Mapping
```bash
cd /home/baals/Desktop/bigdev/APT-ACK
source venv/bin/activate
python scripts/test_mitre.py
```

Expected output:
```
MITRE ATT&CK TECHNIQUE MAPPING
Enriching feed items with MITRE ATT&CK techniques...
Found 156 items to enrich with MITRE ATT&CK techniques

TECHNIQUE COVERAGE MATRIX
Initial Access:
  T1566: Phishing (23 items)
  T1190: Exploit Public-Facing Application (12 items)
...
```

### 2. Test Web UI
```bash
python web/app.py
```

Visit:
- http://localhost:5000 - Dashboard with technique badges
- http://localhost:5000/techniques - Technique matrix
- http://localhost:5000/feeds?technique=t1566 - Filter by technique

### 3. Run Collection with MITRE
```bash
python scripts/run_collection.py
```

MITRE mapping now runs automatically after tagging.

## What Was Added

### Backend
- **80+ technique patterns** - Keyword and malware-based detection
- **Automated mapping** - Runs in collection pipeline
- **API endpoints** - `/api/techniques` and technique filtering

### Frontend
- **Technique matrix page** - Visual coverage by tactic
- **Purple technique badges** - On all feed items
- **Clickable filtering** - Click technique to filter feeds

### Database
- **mitre_technique tags** - Stored in existing tags table
- **No schema changes** - Uses existing infrastructure

## File Descriptions

### Core Files

**mitre_attack_mapper.py** (20KB)
- Main mapping engine
- 80+ technique patterns
- Malware TTP mappings
- No external dependencies

**test_mitre.py** (2KB)
- Test script for initial mapping
- Shows technique coverage matrix
- Validates mappings

### Updated Files

**run_collection_updated.py** (7KB)
- Collection pipeline with MITRE integration
- Adds `--skip-mitre` flag
- Runs after tagging, before NVD

**app_updated.py** (14KB)
- Flask app with MITRE endpoints
- `/api/techniques` - Get technique matrix
- `?technique=` filter parameter
- Technique metadata in responses

**techniques.html** (7KB)
- MITRE ATT&CK technique matrix page
- Organized by tactic
- Heat map visualization
- Click to filter feeds

**base_updated.html** (2KB)
- Navigation bar with "Techniques" link
- CSS for technique badges

**index_updated.html** (12KB)
- Dashboard with technique display
- Purple MITRE badges
- ATT&CK technique count stat

### Documentation

**IMPLEMENTATION_SUMMARY.md** (5KB)
- Integration steps
- Testing checklist
- Troubleshooting guide

**MITRE_ATTACK_GUIDE.md** (7KB)
- Complete usage documentation
- API examples
- Configuration guide
- Roadmap

**MITRE_QUICK_REFERENCE.md** (7KB)
- Common techniques
- Detection priorities
- Blue team cheat sheet
- Hunting queries

## Features

### Automated Technique Detection

Detects techniques from:
- **Keywords**: "phishing" → T1566
- **Malware families**: "cobalt strike" → T1055, T1021, T1071
- **Context**: "ransomware encrypts files deletes backups" → T1486, T1490

### Technique Coverage

80+ techniques across:
- Initial Access (5)
- Execution (5)
- Persistence (5)
- Privilege Escalation (3)
- Defense Evasion (7)
- Credential Access (5)
- Discovery (6)
- Lateral Movement (3)
- Collection (5)
- Command and Control (6)
- Exfiltration (5)
- Impact (7)

### Web UI

**Dashboard** (`/`)
- Purple technique badges (e.g., T1566)
- Technique count in stats
- Click badge to filter

**Technique Matrix** (`/techniques`)
- All techniques by tactic
- Occurrence counts
- Heat map bars
- Click to view related intel

**Feed Filtering** (`/feeds?technique=t1566`)
- Filter by technique ID
- Shows all related threat intel

## Testing

### Verify Installation
```bash
# Check files exist
ls -l enrichment/mitre_attack_mapper.py
ls -l scripts/test_mitre.py
ls -l web/templates/techniques.html

# Check Python imports
python -c "from enrichment.mitre_attack_mapper import MitreAttackMapper; print('OK')"
```

### Run Tests
```bash
# Map existing data
python scripts/test_mitre.py

# Check database
sqlite3 apt_ack.db "SELECT COUNT(*) FROM tags WHERE category='mitre_technique';"

# Test web UI
python web/app.py
curl http://localhost:5000/api/techniques
```

## Troubleshooting

**Import errors:**
```bash
# Verify you're in project root
pwd  # Should be: /home/baals/Desktop/bigdev/APT-ACK

# Activate venv
source venv/bin/activate
```

**No techniques detected:**
```bash
# Run threat tagging first
python scripts/test_tagger.py

# Then run MITRE mapping
python scripts/test_mitre.py
```

**Web UI not showing techniques:**
```bash
# Check if data exists
sqlite3 apt_ack.db "SELECT * FROM tags WHERE category='mitre_technique' LIMIT 5;"

# Restart web app
pkill -f "python web/app.py"
python web/app.py
```

## Next Steps

1. ✓ Extract files to APT-ACK directory
2. ✓ Run test_mitre.py to map existing data
3. ✓ Test web UI at localhost:5000
4. ✓ Run full collection with MITRE
5. Update systemd service to include MITRE
6. Add sub-technique support (future)
7. Export for SIEM integration

## Support

- See MITRE_ATTACK_GUIDE.md for detailed usage
- See MITRE_QUICK_REFERENCE.md for detection tips
- Check logs if mapping fails
- Verify threat tagging ran before MITRE mapping

## Architecture

```
RSS/CISA → Collection
    ↓
IOC Extraction
    ↓
Threat Tagging (malware, threat actor, etc.)
    ↓
MITRE Mapping ← NEW
    ↓
Database (mitre_technique tags)
    ↓
Web Dashboard (purple badges, matrix)
```

All mapping is local - no API calls, no external dependencies.
