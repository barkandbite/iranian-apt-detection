# Suricata Rules for Iranian APT Network Detection

## Overview
This directory contains Suricata IDS signatures for detecting Iranian APT network activities, including C2 communication, exploitation attempts, and data exfiltration.

## Current Ruleset

### Main File: iranian_apt_v2.rules
- **Version**: 2.1
- **Last Updated**: 2025-06-27
- **SID Range**: 2000001-2000130
- **Total Rules**: 130 signatures

### Rule Categories

| Category | SID Range | Count | Description |
|----------|-----------|-------|-------------|
| CVE Exploitation | 2000001-2000014 | 14 | Network exploitation attempts |
| C2 Infrastructure | 2000015-2000025 | 11 | Command & control detection |
| Post-Exploitation | 2000026-2000029 | 4 | Lateral movement patterns |
| Data Exfiltration | 2000030-2000032 | 3 | Large transfers, DNS tunneling |
| Web Shells | 2000033-2000035 | 3 | Web shell activity |
| Reconnaissance | 2000036-2000037 | 2 | Scanning patterns |
| Destructive | 2000038-2000039 | 2 | Wiper deployment |
| ICS/SCADA | 2000040-2000041 | 2 | Water sector targeting |
| AI-Enhanced | 2000042 | 1 | AI phishing infrastructure |
| Cloud Targeting | 2000090-2000114 | 25 | Cloud and container attacks |
| Tool-Specific | 2000115-2000124 | 10 | Iranian APT tools |
| June 2025 Updates | 2000125-2000130 | 6 | Latest threat signatures |

## Deployment

### 1. Copy Rules File
```bash
sudo cp iranian_apt_v2.rules /etc/suricata/rules/
```

### 2. Update suricata.yaml
Add to the `rule-files` section:
```yaml
rule-files:
  - iranian_apt_v2.rules
```

### 3. Test Configuration
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### 4. Reload Rules
```bash
sudo kill -USR2 $(pidof suricata)
# or
sudo systemctl reload suricata
```

## Performance Tuning

### High-Volume Networks
Consider disabling these resource-intensive rules:
- SID 2000031: DNS tunneling detection (high CPU)
- SID 2000036: Internal reconnaissance (noisy)
- SID 2000112: Fast flux detection (memory intensive)

### Threshold Adjustments
Many rules use thresholds to reduce false positives:
```
threshold:type both, track by_src, count X, seconds Y
```

Adjust based on your network baseline.

## Integration with Wazuh

To forward Suricata alerts to Wazuh:

1. Configure Suricata EVE JSON output:
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
```

2. Configure Wazuh agent to read EVE log:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

## Custom Variables

Define in suricata.yaml:
```yaml
vars:
  HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
  EXTERNAL_NET: "!$HOME_NET"
```

## Testing Rules

### Generate Safe Test Traffic
```bash
# Test DNS tunneling detection
dig TXT $(echo "test" | base64).malicious.com

# Test web shell detection
curl -X POST http://testserver/shell.aspx?cmd=whoami

# Test C2 pattern
curl -H "User-Agent: Mozilla/5.0" http://testserver/a
```

### Monitor Alerts
```bash
tail -f /var/log/suricata/fast.log
tail -f /var/log/suricata/eve.json | jq '.alert'
```

## False Positive Tuning

Common false positives and fixes:

| Rule | False Positive | Fix |
|------|----------------|-----|
| 2000018 | Legitimate ngrok usage | Whitelist specific IPs |
| 2000026 | PowerShell automation | Tune User-Agent string |
| 2000031 | Large DNS responses | Increase threshold |
| 2000094 | Cloud storage backup | Whitelist backup servers |

## Archived Rules

Historical rules are preserved in the archive directory:
- `iranian-apt.rules` - Original v1.0 ruleset
- `iranian-apt-cloud-ai.rules` - Cloud-specific rules (merged into v2)

## Updates

Check repository regularly for new signatures as Iranian APT tactics evolve.

## Support

Report false positives or rule issues via GitHub Issues.
