# Suricata Rules for Iranian APT Network Detection

## Overview
This directory contains Suricata IDS signatures for detecting Iranian APT network activities, including C2 communication, exploitation attempts, and data exfiltration.

## Current Ruleset

### Main File: iranian_apt_v3.1.rules
- **Version**: 3.1
- **Last Updated**: 2026-03-12
- **SID Range**: 1000039-2000322
- **Total Rules**: 199 signatures

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
| March 2026 v3.0 | 2000131-2000193 | 63 | MuddyWater malware, CyberAv3ngers OT |
| **March 2026 v3.1** | **2000231-2000322** | **92** | **Emergency update (see below)** |

### v3.1 Emergency Update Coverage (March 12, 2026)

| Section | SID Range | Count | Description |
|---------|-----------|-------|-------------|
| Cisco SD-WAN | 2000231-2000234 | 4 | CVE-2026-20122/20128 exploitation |
| MDM Wiper (Stryker) | 2000235-2000238 | 4 | Intune/Workspace ONE bulk wipe |
| Sicarii Ransomware | 2000239-2000242 | 4 | .sicarii extension, file.io exfil |
| Operation Olalampo | 2000243-2000247 | 5 | GhostFetch, HTTP_VIP patterns |
| MuddyWater C2 Domains | 2000248-2000252 | 5 | New C2 infrastructure |
| RedAlert APK | 2000253-2000256 | 4 | Phishing campaign IOCs |
| RMM Tool Abuse | 2000257-2000263 | 7 | SimpleHelp, Syncro, NetBird, etc. |
| Backdoor Patterns | 2000264-2000266 | 3 | BugSleep, TameCat, PowerLess |
| Privilege Escalation | 2000267 | 1 | CVE-2024-30088 |
| Deno Runtime | 2000268-2000269 | 2 | BYOR evasion detection |
| Cobalt Strike | 2000270-2000272 | 3 | HTTP/DNS beacon, named pipes |
| Wiper Detection | 2000273-2000274 | 2 | Mass distribution, disk overwrite |
| DDoS/Hacktivist | 2000275-2000277 | 3 | UDP/HTTP/SYN flood |
| SOCKS5 Proxy | 2000278-2000279 | 2 | MuddyWater tunneling |
| Credential Theft | 2000280-2000282 | 3 | Kerberoasting, LSASS, browser |
| DCHSpy Mobile | 2000283 | 1 | SFTP exfiltration |
| Infrastructure | 2000284-2000287 | 4 | .online TLD, polyglot, double ext |
| Cloud Abuse | 2000288-2000292 | 5 | OneDrive, Drive, Discord, Firebase |
| Correlation Chains | 2000293-2000297 | 5 | Multi-stage attack detection |
| Encryption Evasion | 2000298-2000300 | 3 | Self-signed cert, SSH/443, DoH |
| Enhanced OT/ICS | 2000301-2000305 | 5 | Modbus, DNP3, BACnet, EtherNet/IP |
| NTP Manipulation | 2000306 | 1 | Time source attacks |
| Stagecomp/Darkcomp | 2000307-2000308 | 2 | MuddyWater tools |
| Sosano/GhostForm | 2000309-2000310 | 2 | Go/WebSocket backdoors |
| React2Shell | 2000311 | 1 | CVE-2025-55182 |
| FortiOS fgfmd | 2000312 | 1 | CVE-2024-23113 |
| AMSI/ETW Bypass | 2000313-2000314 | 2 | Evasion detection |
| Mobile Targeting | 2000315 | 1 | Shortened URL APK delivery |
| Known C2 IPs | 2000316-2000317 | 2 | MuddyWater infrastructure |
| DGA Detection | 2000318-2000319 | 2 | OilRig high-entropy DNS |
| Wiper Pre-cursors | 2000320-2000322 | 3 | Backup deletion, boot tamper |

## Deployment

### 1. Copy Rules File
```bash
sudo cp iranian_apt_v3.1.rules /etc/suricata/rules/
```

### 2. Update suricata.yaml
Add to the `rule-files` section:
```yaml
rule-files:
  - iranian_apt_v3.1.rules
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
