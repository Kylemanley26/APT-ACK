# APT-ACK

Automated threat intelligence aggregator with IOC enrichment, auto-tagging, and digest generation.

## Features

- RSS feed collection from security blogs and advisories
- Automatic threat actor, malware, and vulnerability tagging
- Severity scoring and relevance ranking
- IOC extraction (IPs, domains, CVEs, hashes)
- Terminal dashboard with filtering
- Export to JSON/CSV formats

## Quick Start
```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize database
python scripts/test_db.py

# Collect feeds
python scripts/test_collector.py

# Extract IOCs
python scripts/test_extractor.py

# Tag and score
python scripts/test_tagger.py

# View dashboard
python scripts/dashboard.py

# Overview
python scripts/dashboard.py

# Critical/High priority items
python scripts/dashboard.py critical

# Filter by severity
python scripts/dashboard.py severity critical

# Filter by tag
python scripts/dashboard.py tag ransomware
python scripts/dashboard.py tag microsoft

# Recent items (last 24h)
python scripts/dashboard.py recent

# Export data
python scripts/dashboard.py export json
python scripts/dashboard.py export csv
python scripts/dashboard.py export iocs

APT-ACK/
├── collectors/      # RSS and API collectors
├── enrichment/      # IOC extraction, tagging, scoring
├── storage/         # Database models and connections
├── outputs/         # Dashboard and export tools
├── config/          # Feed sources configuration
└── scripts/         # Test and utility scripts

Phase 1 Complete Summary:

- 11 feed items collected and tagged
- 1 IOC extracted (test data)
- CRITICAL severity detection working (Microsoft Patch Tuesday)
- Threat actor tagging (Scattered Spider, ShinyHunters)
- Export functionality operational

Next Phase Options:

Phase 2A - Enhanced Intel (recommended):
- CISA KEV API for guaranteed CVE data
- NVD integration for CVSS scores
- Full article fetching for CRITICAL items

Phase 2B - Automation:
- Scheduled collection (cron/systemd)
- Daily digest email generation
- Slack webhook integration

Phase 2C - Web UI:
- Flask dashboard
- Real-time feed view
- Tag filtering interface

Data Sources
Currently configured RSS feeds:

Krebs on Security
BleepingComputer
The Hacker News
Schneier on Security
Dark Reading


DEV Roadmap

Phase 1 Status: COMPLETE

RSS collection
IOC extraction framework
Threat tagging engine
Severity scoring
Terminal dashboard
Data export

Next Steps (Phase 2)

CISA KEV API integration
NVD CVE enrichment
Full article fetching for high-value items
MITRE ATT&CK technique mapping
Email/Slack digest generation
Simple Flask web UI
