# IOC Detail Page - Quick Reference

## URLs

### Page Routes
```
/ioc/ip/192.168.1.1
/ioc/domain/evil.com
/ioc/url/http://malicious.site/payload
/ioc/hash-md5/5d41402abc4b2a76b9719d911017c592
/ioc/hash-sha1/aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
/ioc/hash-sha256/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
/ioc/email/attacker@evil.com
/ioc/file-path/C:/Windows/System32/malware.exe
```

### API Endpoints
```
GET /api/ioc/<ioc_type>/<value>
```

## IOC Type Mappings

| Database Enum | URL Format | Example |
|---------------|------------|---------|
| `IOCType.IP` | `ip` | `/ioc/ip/1.2.3.4` |
| `IOCType.DOMAIN` | `domain` | `/ioc/domain/evil.com` |
| `IOCType.URL` | `url` | `/ioc/url/http://site.com` |
| `IOCType.HASH_MD5` | `hash-md5` | `/ioc/hash-md5/abc123...` |
| `IOCType.HASH_SHA1` | `hash-sha1` | `/ioc/hash-sha1/def456...` |
| `IOCType.HASH_SHA256` | `hash-sha256` | `/ioc/hash-sha256/789ghi...` |
| `IOCType.EMAIL` | `email` | `/ioc/email/user@domain.com` |
| `IOCType.FILE_PATH` | `file-path` | `/ioc/file-path/C:/path/to/file` |

## API Response Format

```json
{
  "ioc_type": "ip",
  "value": "192.168.1.1",
  "confidence": 0.85,
  "context": "Malicious IP observed in APT campaign",
  "verified": true,
  "first_seen": "2024-10-01T10:30:00Z",
  "last_seen": "2024-10-24T15:45:00Z",
  "threat_actor": "APT28",
  "malware_family": "Emotet",
  "mitre_techniques": "T1566, T1071",
  "occurrence_count": 5,
  "feed_items": [
    {
      "id": 123,
      "title": "New APT Campaign Detected",
      "source": "ThreatPost",
      "link": "https://threatpost.com/article",
      "severity": "high",
      "published_date": "2024-10-24T12:00:00Z",
      "relevance_score": 0.92
    }
  ],
  "related_iocs": [
    {
      "type": "domain",
      "value": "evil.com",
      "confidence": 0.78
    }
  ],
  "tags": [
    {
      "name": "apt",
      "category": "threat_type"
    }
  ]
}
```

## External Enrichment Links

### IP Addresses
- VirusTotal: `https://www.virustotal.com/gui/ip-address/{value}`
- AbuseIPDB: `https://www.abuseipdb.com/check/{value}`

### Domains
- VirusTotal: `https://www.virustotal.com/gui/domain/{value}`
- URLScan: `https://urlscan.io/search/#{value}`

### File Hashes
- VirusTotal: `https://www.virustotal.com/gui/file/{value}`

### URLs
- URLScan: `https://urlscan.io/search/#{encoded_value}`

## Code Snippets

### Linking to IOC Detail Page from Python
```python
from storage.models import IOC

def get_ioc_url_type(ioc_type_value):
    type_map = {
        'ip': 'ip', 'domain': 'domain', 'url': 'url',
        'hash_md5': 'hash-md5', 'hash_sha1': 'hash-sha1',
        'hash_sha256': 'hash-sha256', 'email': 'email',
        'file_path': 'file-path'
    }
    return type_map.get(ioc_type_value, ioc_type_value)

# Generate URL
ioc = session.query(IOC).first()
ioc_url = f"/ioc/{get_ioc_url_type(ioc.ioc_type.value)}/{ioc.value}"
```

### Linking from JavaScript/Alpine.js
```javascript
function getUrlType(iocType) {
    const typeMap = {
        'ip': 'ip',
        'domain': 'domain',
        'url': 'url',
        'hash_md5': 'hash-md5',
        'hash_sha1': 'hash-sha1',
        'hash_sha256': 'hash-sha256',
        'email': 'email',
        'file_path': 'file-path'
    };
    return typeMap[iocType] || iocType;
}

// In Alpine.js template
const iocUrl = `/ioc/${getUrlType(ioc.type)}/${encodeURIComponent(ioc.value)}`;
```

### Querying IOC with Related Data
```python
from storage.database import db
from storage.models import IOC, IOCType
from sqlalchemy.orm import selectinload

session = db.get_session()
try:
    # Query with eager loading
    ioc = session.query(IOC)\
        .options(
            selectinload(IOC.feed_item),
            selectinload(IOC.tags)
        )\
        .filter_by(ioc_type=IOCType.IP, value='192.168.1.1')\
        .first()

    if ioc:
        print(f"IOC: {ioc.value}")
        print(f"Feed Item: {ioc.feed_item.title}")
        print(f"Tags: {[t.name for t in ioc.tags]}")
finally:
    session.close()
```

## Tailwind CSS Classes Reference

### Card Containers
```html
<div class="bg-gray-800 p-6 rounded-lg border border-gray-700 mb-6">
```

### Severity Badges
```html
<!-- Critical -->
<span class="px-2 py-1 text-xs bg-red-900 text-red-200 rounded">CRITICAL</span>

<!-- High -->
<span class="px-2 py-1 text-xs bg-orange-900 text-orange-200 rounded">HIGH</span>

<!-- Medium -->
<span class="px-2 py-1 text-xs bg-yellow-900 text-yellow-200 rounded">MEDIUM</span>

<!-- Low -->
<span class="px-2 py-1 text-xs bg-blue-900 text-blue-200 rounded">LOW</span>

<!-- Info -->
<span class="px-2 py-1 text-xs bg-gray-700 text-gray-300 rounded">INFO</span>
```

### Type Badges
```html
<span class="px-3 py-1 text-xs font-semibold rounded bg-purple-900 text-purple-200">
    IP
</span>
```

### Action Buttons
```html
<!-- Primary -->
<a class="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-white">
    Primary Action
</a>

<!-- Secondary -->
<a class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded">
    Secondary Action
</a>
```

## Alpine.js Component Structure

```javascript
function iocDetail() {
    return {
        // State
        ioc: null,
        loading: true,
        error: null,
        copied: false,

        // Methods
        async loadIOC() {
            const pathParts = window.location.pathname.split('/');
            const iocType = pathParts[2];
            const iocValue = decodeURIComponent(pathParts.slice(3).join('/'));

            try {
                const response = await fetch(`/api/ioc/${iocType}/${encodeURIComponent(iocValue)}`);
                if (!response.ok) throw new Error('IOC not found');
                this.ioc = await response.json();
            } catch (err) {
                this.error = err.message;
            } finally {
                this.loading = false;
            }
        },

        formatDate(dateStr) {
            if (!dateStr) return 'Unknown';
            return new Date(dateStr).toLocaleDateString();
        },

        async copyToClipboard(text) {
            try {
                await navigator.clipboard.writeText(text);
                this.copied = true;
                setTimeout(() => this.copied = false, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        },

        getUrlType(iocType) {
            // Convert database types to URL format
            const typeMap = {
                'ip': 'ip', 'domain': 'domain', 'url': 'url',
                'hash_md5': 'hash-md5', 'hash_sha1': 'hash-sha1',
                'hash_sha256': 'hash-sha256', 'email': 'email',
                'file_path': 'file-path'
            };
            return typeMap[iocType] || iocType;
        }
    }
}
```

## Testing Commands

```bash
# Start application
python web/app.py

# Test API endpoint
curl http://localhost:5000/api/ioc/ip/192.168.1.1

# Test with invalid type (should return 400)
curl -i http://localhost:5000/api/ioc/invalid/test

# Test with non-existent IOC (should return 404)
curl -i http://localhost:5000/api/ioc/ip/0.0.0.0

# Check database for IOCs
python -c "from storage.database import db; from storage.models import IOC, IOCType; \
session = db.get_session(); \
print('Total IOCs:', session.query(IOC).count()); \
print('IPs:', session.query(IOC).filter_by(ioc_type=IOCType.IP).count()); \
session.close()"
```

## Common Issues and Solutions

### Issue: IOC not found (404)
**Solution:** Verify the IOC exists in the database with the exact value
```python
from storage.database import db
from storage.models import IOC, IOCType

session = db.get_session()
ioc = session.query(IOC).filter_by(
    ioc_type=IOCType.IP,
    value='192.168.1.1'
).first()
print(f"Found: {ioc is not None}")
session.close()
```

### Issue: Invalid IOC type (400)
**Solution:** Use URL-friendly type names (hash-md5, not hash_md5)

### Issue: Related IOCs not showing
**Solution:** Check that IOCs share feed items
```python
ioc = session.query(IOC).filter_by(value='example').first()
if ioc.feed_item:
    print(f"Related IOCs: {len(ioc.feed_item.iocs)}")
```

### Issue: External links not working
**Solution:** Check IOC type mapping in template (x-if conditions)

## File Locations

- **Backend Routes:** `/home/baals/Desktop/bigdev/APT-ACK/web/app.py`
- **Template:** `/home/baals/Desktop/bigdev/APT-ACK/web/templates/ioc_detail.html`
- **Base Template:** `/home/baals/Desktop/bigdev/APT-ACK/web/templates/base.html`
- **Models:** `/home/baals/Desktop/bigdev/APT-ACK/storage/models.py`
- **Database:** `/home/baals/Desktop/bigdev/APT-ACK/storage/database.py`
