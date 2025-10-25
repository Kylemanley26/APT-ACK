# APT-ACK Agent - Claude Code Instructions

## Project Context

**APT-ACK** is a production-deployed threat intelligence aggregator providing automated IOC extraction, threat tagging, and real-time dashboards for security operations. Currently running on Railway with Supabase PostgreSQL backend.

**Tech Stack:** Python 3.13, Flask, SQLAlchemy, PostgreSQL (Supabase), Alpine.js, Tailwind CSS

## Current Architecture

```
APT-ACK/
├── web/
│   ├── app.py                    # Flask routes + API endpoints
│   └── templates/
│       ├── base.html             # Base layout
│       ├── index.html            # Dashboard
│       ├── feeds.html            # Feed listing
│       ├── timeline.html         # Timeline visualization
│       └── cve_detail.html       # CVE detail page (reference)
├── storage/
│   ├── models.py                 # SQLAlchemy models
│   └── database.py               # DB connection manager
├── collectors/                   # RSS, CISA KEV, NVD
├── enrichment/                   # IOC extraction, tagging
└── outputs/                      # Export, terminal views
```

## Immediate Task: IOC Details Page

**Goal:** Create `/ioc/<ioc_type>/<value>` endpoint and template for non-CVE IOCs.

**Requirements:**
1. **Backend route** in `web/app.py`:
   - GET `/api/ioc/<int:ioc_id>` - Return full IOC details with related feed items
   - GET `/ioc/<ioc_type>/<value>` - Render template

2. **Frontend template** `web/templates/ioc_detail.html`:
   - Follow `cve_detail.html` pattern
   - Display: IOC type, value, confidence, first/last seen, threat attribution
   - Show all feed items mentioning this IOC (with links)
   - List tags, related IOCs from same feed items
   - External enrichment links (VirusTotal for hashes/IPs, URLScan for domains)

3. **Design constraints:**
   - Match existing UI (gray-800 cards, red/orange/yellow severity badges)
   - Use Alpine.js for reactivity
   - Keep DB queries efficient (use joins, avoid N+1)

**Reference models:**
```python
# storage/models.py
class IOC:
    ioc_type: IOCType  # IP, DOMAIN, URL, HASH_*, EMAIL
    value: str
    confidence: float
    verified: bool
    first_seen: datetime
    last_seen: datetime
    threat_actor: str
    malware_family: str
    feed_item: FeedItem  # parent
    tags: List[Tag]
```

## Phase 2 Goals (Future Work)

**Priority order:**
1. **Additional collectors** - Vendor blogs RSS, CERT advisories
2. **MITRE ATT&CK mapping** - Tag IOCs with techniques
3. **Export enhancements** - STIX 2.1, YARA rule generation
4. **Notification system** - Email/Slack digests with severity filters
5. **Advanced sources** - Discord monitoring (requires scraping), Reddit Security
6. **UX improvements** - Date range filters, advanced search, IOC pivot views

## Development Guidelines

**Code patterns to follow:**
- Use `db.get_session()` context manager for all DB operations
- Pagination: 20 items default, support `page` and `per_page` params
- Error handling: Return 404 JSON for missing resources
- Date handling: Always use `datetime.now(UTC)` 
- SQL queries: Use SQLAlchemy ORM, leverage relationships

**Web route pattern:**
```python
@app.route('/api/endpoint')
def api_function():
    session = db.get_session()
    try:
        # Query logic
        return jsonify(data)
    finally:
        session.close()
```

**Template pattern:**
- Extend `base.html`
- Use Alpine.js `x-data`, `x-init`, `x-text` for dynamic content
- Tailwind utility classes (no custom CSS)
- Loading states: `<template x-if="loading">`

## Database Notes

- **Production:** PostgreSQL on Supabase (via `DATABASE_URL` env var)
- **Dev fallback:** SQLite (`apt_ack.db`)
- **Migrations:** Manual via `scripts/migrate_to_postgres.py`
- **Health check:** `db.health_check()` verifies connectivity

## Testing Workflow

1. Local dev: `python web/app.py` (uses SQLite)
2. Test with existing data: Run `scripts/run_collection.py` first
3. Check route: `curl http://localhost:5000/api/ioc/1`
4. Deploy: Push to Railway (auto-deploys from main branch)

## Key Constraints

- **No new dependencies** unless critical
- **Maintain existing patterns** - follow `cve_detail.html` structure
- **PostgreSQL compatibility** - test ENUM handling, avoid SQLite-specific syntax
- **Security:** No exposed API keys, validate all user inputs
- **Performance:** Index queries on `ioc_type`, `value`, `feed_item_id`

## Phase 2 Implementation Notes

**MITRE ATT&CK:**
- Use `mitreattack-python` library
- Map CVE CWEs to techniques via CAPEC
- Store in `IOC.mitre_techniques` (currently used for CWE IDs)

**STIX export:**
- Use `stix2` library
- Map models: `FeedItem` → Indicator, `IOC` → Observable
- Generate bundles with relationships

**Discord monitoring:**
- Requires `discord.py` with bot token
- Monitor specific channels for threat intel
- Extract IOCs from messages, link to Discord message URL

**Slack digests:**
- Use webhook URLs (store in env vars)
- Daily summary: Critical/High items from last 24h
- Format as Slack blocks for rich presentation

---

**Current focus:** Build IOC details page. Reference `cve_detail.html` for structure, ensure consistent UI/UX, test with multiple IOC types (IP, domain, hash).