**README.md**


# APT-ACK

Automated threat intelligence aggregator with IOC enrichment, auto-tagging, and digest generation for security operations teams.

## Features

### Data Collection
- RSS feed aggregation from security blogs and advisories
- CISA Known Exploited Vulnerabilities (KEV) catalog integration
- NVD CVE enrichment with CVSS scores and CWE mappings
- Automated collection every 6 hours via systemd

### Intelligence Processing
- Automatic IOC extraction (IPs, domains, CVEs, hashes, URLs, emails)
- Threat actor and malware family tagging
- Attack type classification
- Vendor and sector identification
- Severity scoring (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Relevance ranking (0.0 to 1.0)

### Outputs
- Terminal dashboard with filtering and search
- JSON and CSV export
- IOC list generation
- Severity-based views
- Tag-based filtering
- Recent items timeline

## Architecture

```
APT-ACK/
├── collectors/          # Data source integrations
│   ├── rss_feeds.py    # Security blogs, vendor advisories
│   ├── cisa_kev.py     # CISA Known Exploited Vulnerabilities
│   └── nvd_api.py      # National Vulnerability Database
├── enrichment/          # Analysis and classification
│   ├── ioc_extractor.py    # IOC pattern matching and extraction
│   └── tagging_engine.py   # Threat categorization and scoring
├── storage/             # Database layer
│   ├── database.py     # SQLite connection management
│   └── models.py       # Data models (FeedItem, IOC, Tag, Alert)
├── outputs/             # Visualization and export
│   ├── terminal_view.py    # CLI dashboard
│   └── export.py           # JSON/CSV export
├── scripts/             # Utilities and orchestration
│   ├── run_collection.py   # Main orchestration pipeline
│   └── test_*.py           # Component tests
└── config/
    └── sources.yaml    # Feed configuration
```

## Installation

### Prerequisites
- Python 3.13+
- Fedora Linux (or any systemd-based distro)

### Setup

```bash
# Clone repository
cd /home/baals/Desktop/bigdev/APT-ACK

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python scripts/test_db.py
```

### Configuration

Create `.env` file for API keys:

```bash
cat > .env << 'EOF'
NVD_API_KEY=your-nvd-api-key-here
EOF
```

Get free NVD API key: https://nvd.nist.gov/developers/request-an-api-key

### Automated Collection

Install systemd timer for automatic collection every 6 hours:

```bash
./scripts/setup_systemd.sh
```

## Usage

### Manual Collection

```bash
# Full pipeline (RSS + CISA KEV + IOC extraction + tagging + NVD enrichment)
python scripts/run_collection.py

# Skip NVD enrichment (faster)
python scripts/run_collection.py --skip-nvd

# Limit NVD enrichment for testing
python scripts/run_collection.py --nvd-limit 20
```

### Dashboard

```bash
# Default view (summary + critical alerts)
python scripts/dashboard.py

# Show summary statistics
python scripts/dashboard.py summary

# Critical and high severity items
python scripts/dashboard.py critical

# Filter by severity
python scripts/dashboard.py severity critical
python scripts/dashboard.py severity high

# Filter by tag
python scripts/dashboard.py tag ransomware
python scripts/dashboard.py tag microsoft
python scripts/dashboard.py tag apt29

# Recent items (last 24 hours)
python scripts/dashboard.py recent

# Recent items (custom timeframe)
python scripts/dashboard.py recent 48
```

### Export

```bash
# Export to JSON
python scripts/dashboard.py export json

# Export to CSV
python scripts/dashboard.py export csv

# Export IOCs only
python scripts/dashboard.py export iocs
```

Exports are saved to `exports/` directory.

### Systemd Management

```bash
# Check timer status
systemctl --user status apt-ack.timer

# List scheduled runs
systemctl --user list-timers

# Run collection manually
systemctl --user start apt-ack.service

# View collection logs
tail -f logs/collection.log

# Stop automatic collection
systemctl --user stop apt-ack.timer

# Change schedule (edit apt-ack.timer, then):
systemctl --user daemon-reload
systemctl --user restart apt-ack.timer
```

## Data Sources

### RSS Feeds
- Krebs on Security
- BleepingComputer
- The Hacker News
- Schneier on Security
- Dark Reading

### APIs
- **CISA KEV**: Known Exploited Vulnerabilities catalog (authoritative CVE list)
- **NVD**: National Vulnerability Database (CVSS scores, CWE mappings, descriptions)

## Intelligence Categories

### Threat Actors
APT28, APT29, APT41, Lazarus, Scattered Spider, ALPHV/BlackCat, LockBit, ShinyHunters, Lapsus$, and 20+ more

### Malware Families
Qakbot, Emotet, TrickBot, Cobalt Strike, Mimikatz, RedLine Stealer, Vidar, ransomware variants, and 25+ more

### Attack Types
Ransomware, phishing, supply chain attacks, zero-days, RCE, privilege escalation, SQL injection, and 15+ more

### Sectors
Healthcare, financial, energy, government, education, critical infrastructure, and 10+ more

### Vendors
Microsoft, Cisco, Fortinet, VMware, Apache, Citrix, Oracle, Adobe, and 20+ more

## Database Schema

- **FeedItem**: Source articles with severity, relevance score, tags
- **IOC**: Extracted indicators (IP, domain, CVE, hash, URL, email)
- **Tag**: Auto-generated categorization (threat actor, malware, attack type, sector, vendor)
- **Alert**: High-priority items for digest generation
- **DigestLog**: Tracking for sent notifications

## Performance

- RSS collection: ~15 seconds for 5 feeds
- CISA KEV: ~5 seconds for full catalog
- NVD enrichment: 
  - Without API key: 5 CVEs per 30 seconds
  - With API key: 50 CVEs per 30 seconds
- IOC extraction: ~100 items per second
- Tagging: ~50 items per second

## Current Statistics

- **Feed Items**: 156+
- **IOCs**: 37+ CVEs, various IPs/domains/hashes
- **Tags**: 50+ auto-generated categories
- **Sources**: 5 RSS feeds + CISA KEV + NVD
- **Update Frequency**: Every 6 hours

## Roadmap

### Phase 1: MVP (COMPLETE)
- RSS collection
- IOC extraction
- Threat tagging
- Terminal dashboard
- Export functionality

### Phase 2: Enhanced Intelligence (COMPLETE)
- CISA KEV integration
- NVD enrichment
- Orchestration pipeline
- Systemd automation

### Phase 3: Deployment (IN PROGRESS)
- [ ] Supabase migration (PostgreSQL)
- [ ] REST API
- [ ] Web UI (Flask/React)
- [ ] Real-time updates

### Phase 4: Advanced Features
- [ ] Email digest generation
- [ ] Slack webhook integration
- [ ] MITRE ATT&CK technique mapping
- [ ] Threat actor campaign tracking
- [ ] YARA rule generation from IOCs
- [ ] STIX/TAXII export
- [ ] SIEM integration (Splunk, Sentinel)

## Contributing

This is a personal threat intelligence project. Issues and pull requests welcome.

## License

MIT License

## Acknowledgments

- CISA for the Known Exploited Vulnerabilities catalog
- NVD for comprehensive CVE data
- Security researchers and bloggers sharing threat intelligence