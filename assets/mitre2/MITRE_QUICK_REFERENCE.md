# MITRE ATT&CK Quick Reference

## Most Common Techniques in Threat Intel

### Initial Access

**T1566 - Phishing**
- Keywords: phishing, spear phishing, malicious attachment, email attachment
- Common in: Email campaigns, social engineering reports
- Blue team action: Email security controls, user training

**T1190 - Exploit Public-Facing Application**
- Keywords: exploit public-facing, web server exploit, exposed service
- Common in: Web app vulnerabilities, zero-days
- Blue team action: Patch management, WAF rules

**T1078 - Valid Accounts**
- Keywords: valid accounts, stolen credentials, compromised credentials
- Common in: Credential theft, account takeover
- Blue team action: MFA, account monitoring

### Execution

**T1059 - Command and Scripting Interpreter**
- Keywords: powershell, cmd.exe, bash, script execution
- Common in: Almost all malware campaigns
- Blue team action: Script blocking, logging, EDR

**T1204 - User Execution**
- Keywords: user execution, malicious file, user clicked
- Common in: Social engineering attacks
- Blue team action: Application whitelisting, sandboxing

### Persistence

**T1547 - Boot or Logon Autostart**
- Keywords: registry run keys, startup folder, autostart
- Common in: Malware persistence mechanisms
- Blue team action: Autoruns monitoring, registry auditing

**T1543 - Create or Modify System Process**
- Keywords: service, systemd, windows service
- Common in: Advanced malware, rootkits
- Blue team action: Service creation monitoring

### Defense Evasion

**T1027 - Obfuscated Files or Information**
- Keywords: obfuscation, obfuscated, encoded, packed
- Common in: 80%+ of malware samples
- Blue team action: Behavioral detection, deobfuscation tools

**T1562 - Impair Defenses**
- Keywords: disable security, disable antivirus, kill av
- Common in: Ransomware, advanced malware
- Blue team action: Tamper protection, security tool hardening

**T1055 - Process Injection**
- Keywords: process injection, dll injection, code injection
- Common in: Cobalt Strike, advanced malware
- Blue team action: Memory protection, behavior monitoring

### Credential Access

**T1003 - OS Credential Dumping**
- Keywords: lsass, sam, mimikatz, hashdump, credential dumping
- Common in: Post-exploitation, lateral movement prep
- Blue team action: Credential Guard, LSA protection, LSASS monitoring

**T1110 - Brute Force**
- Keywords: brute force, password spray, credential stuffing
- Common in: External attacks, account compromise
- Blue team action: Account lockout, rate limiting, MFA

### Impact

**T1486 - Data Encrypted for Impact**
- Keywords: ransomware, encryption, data encrypted
- Common in: All ransomware incidents
- Blue team action: Backups, EDR, segmentation

**T1490 - Inhibit System Recovery**
- Keywords: delete backups, vssadmin, shadow copies
- Common in: Ransomware pre-encryption
- Blue team action: Backup monitoring, command blocking

## Technique Combinations

### Ransomware Kill Chain
```
T1566 (Phishing)
  -> T1204 (User Execution)
  -> T1059 (Script Execution)
  -> T1547 (Persistence)
  -> T1562 (Disable AV)
  -> T1490 (Delete Backups)
  -> T1486 (Encrypt Files)
```

### APT Intrusion
```
T1190 (Exploit Web App)
  -> T1059 (Command Execution)
  -> T1003 (Credential Dumping)
  -> T1078 (Valid Accounts)
  -> T1021 (Remote Services)
  -> T1041 (Exfiltration over C2)
```

### Phishing Campaign
```
T1566 (Phishing)
  -> T1204 (User Execution)
  -> T1059 (Macro/Script)
  -> T1547 (Persistence)
  -> T1071 (C2 Communication)
  -> T1005 (Data Collection)
```

## Detection Priority Matrix

### Critical (Immediate Response)
- T1486 - Ransomware encryption
- T1003 - Credential dumping (Mimikatz)
- T1068 - Privilege escalation exploit
- T1190 - Web app exploitation

### High (Investigation Required)
- T1055 - Process injection
- T1562 - Defense evasion attempts
- T1021 - Lateral movement
- T1567 - Exfiltration attempts

### Medium (Monitor Closely)
- T1059 - Script execution
- T1027 - Obfuscation
- T1071 - C2 communication
- T1083 - File discovery

### Low (Baseline Awareness)
- T1082 - System info discovery
- T1057 - Process discovery
- T1518 - Software discovery

## Malware Family Mappings

### Cobalt Strike
```
T1055 - Process Injection
T1021 - Remote Services (SMB, RDP)
T1071 - HTTP/HTTPS C2
T1003 - Credential Dumping
```

### Qakbot
```
T1566 - Phishing (delivery)
T1059 - PowerShell/Script execution
T1055 - Process injection
T1003 - Credential theft
```

### LockBit Ransomware
```
T1486 - File encryption
T1490 - Backup deletion
T1082 - System discovery
T1047 - WMI execution
```

### Emotet
```
T1566 - Phishing (delivery)
T1204 - Macro execution
T1059 - PowerShell download
T1547 - Registry persistence
```

## Blue Team Detection Cheat Sheet

### Log Sources by Technique
```
T1003 (Credential Dump)
  -> Security Event 4624 (logon)
  -> Sysmon Event 10 (process access)
  -> EDR process memory access

T1059 (PowerShell)
  -> PowerShell logs 4103/4104
  -> Sysmon Event 1 (process creation)
  -> Script block logging

T1486 (Ransomware)
  -> Volume Shadow Copy deletion logs
  -> Mass file modifications
  -> Unusual file extensions
  -> High CPU usage
```

### Sigma Rules by Technique
```
T1003 - LSASS_Access_Mimikatz.yml
T1059 - PowerShell_Suspicious_Script.yml
T1055 - Process_Injection_CreateRemoteThread.yml
T1562 - Defender_Disabled.yml
T1486 - Ransomware_File_Extensions.yml
```

## Hunting Queries

### Hunt for T1003 (Credential Dumping)
```sql
-- Sysmon Event 10: LSASS access
SELECT * FROM sysmon_logs
WHERE EventID = 10
AND TargetImage LIKE '%lsass.exe'
AND GrantedAccess IN ('0x1010', '0x1410', '0x1438')
```

### Hunt for T1055 (Process Injection)
```sql
-- Sysmon Event 8: CreateRemoteThread
SELECT * FROM sysmon_logs
WHERE EventID = 8
AND TargetImage NOT LIKE 'C:\Program Files%'
```

### Hunt for T1486 (Ransomware)
```sql
-- Mass file modifications
SELECT * FROM file_events
WHERE action = 'modified'
GROUP BY process_name
HAVING COUNT(*) > 100
AND time_window < 60
```

## Integration Tips

### Prioritize Detections
1. Map your existing detections to MITRE
2. Identify coverage gaps using technique matrix
3. Focus on techniques appearing in your threat intel
4. Build detections for top 10 techniques first

### Threat Hunting
1. Filter threat intel by technique
2. Extract IOCs for that technique
3. Hunt for technique-specific behaviors
4. Correlate with your telemetry

### Metrics
```
Coverage = Detected Techniques / Total Relevant Techniques
Quality = True Positives / (True Positives + False Positives)
Priority = Technique Frequency in Threat Intel
```

## Quick Commands

### Find most common techniques
```bash
curl http://localhost:5000/api/techniques | jq 'to_entries | map({tactic: .key, count: (.value | length)}) | sort_by(.count) | reverse'
```

### Get all ransomware-related intel
```bash
curl "http://localhost:5000/api/feeds?technique=t1486" | jq '.items[] | {title, severity}'
```

### Export technique IOCs
```python
from enrichment.mitre_attack_mapper import MitreAttackMapper
from storage.database import db
from storage.models import FeedItem, Tag

mapper = MitreAttackMapper()
session = db.get_session()

# Get all items with T1486
items = session.query(FeedItem).join(FeedItem.tags).filter(
    Tag.name == 'mitre-t1486'
).all()

# Extract IOCs
for item in items:
    for ioc in item.iocs:
        print(f"{ioc.ioc_type.value}: {ioc.value}")
```
