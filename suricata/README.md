# Suricata Rules for Iranian APT Network Detection

## Overview
This directory contains Suricata IDS signatures for detecting Iranian APT network activities, including C2 communication, exploitation attempts, and data exfiltration.

## Current Ruleset

### Canonical File: `iranian-apt-detection.rules`
- **Version**: 4.0.10 (consolidated from v3.1, v3.2, v3.3 + ongoing updates)
- **Last Updated**: 2026-04-19
- **SID Range**: 1000039–2000501
- **Total Rules**: 378 signatures
- **Zero duplicate SIDs**
- **Requires**: Suricata 7.0+

### SID Allocation

| Range | Count | Description |
|-------|-------|-------------|
| 1000039–2000014 | 14 | CVE exploitation detection (Check Point, PAN-OS, Fortinet, Cisco, Ivanti) |
| 2000015–2000030 | 16 | C2 infrastructure, post-exploitation, data exfiltration |
| 2000031–2000050 | 20 | Reconnaissance, web shells, destructive, ICS/SCADA, correlation |
| 2000090–2000130 | 41 | Cloud targeting, tool-specific, June 2025 updates |
| 2000131–2000193 | 63 | March 2026 v3.0: MuddyWater malware, CyberAv3ngers OT |
| 2000194–2000230 | 37 | MuddyViper, WezRat, UNC1549, Handala, Sicarii, IOCONTROL (from v3.3) |
| 2000231–2000359 | 129 | March 2026 expansion: Cisco SD-WAN, MDM wiper, Olalampo, healthcare, correlation |
| 2000360–2000456 | 97 | ICS/PCOM, TAMECAT, Infy blockchain DGA, FortiOS/Ivanti chains (renumbered from v3.3) |
| 2000457–2000461 | 5 | CRESCENTHARVEST RAT (APT35/Charming Kitten, Feb 2026) |
| 2000462–2000477 | 16 | Boggy Serpens/BlackBeard, Nuso, Infy Tonnerre, Dust Specter TwinTalk/SPLITDROP |
| 2000478–2000501 | 24 | CyberAv3ngers ICS/PLC (AA26-097A), Infy IOC update, MuddyWater ChainShell/CastleRAT/Fooder C2 |

### Threat Group Coverage

| Group | Malware/Tools | SIDs |
|-------|---------------|------|
| MuddyWater | Dindoor, RustyWater, MuddyViper/Fooder, TWINTASK, PowGoop, CHAR, ChainShell/CastleRAT | ~45 |
| CyberAv3ngers | IOCONTROL, PCOM PLC, RabbitMQ, DoH, Rockwell CIP/EtherNet-IP, Modbus, S7comm | ~33 |
| APT34 (OilRig) | Spearal DNS, Veaty, STEALHOOK, Dark Scepter | ~10 |
| APT35 (Charming Kitten) | BellaCPP, PowerLess v3, CRESCENTHARVEST RAT | ~12 |
| APT42 (RedKitten) | TAMECAT, WezRat, SloppyMIO, GitHub dead-drop | ~10 |
| Handala/Void Manticore | Stryker MDM wiper, Telegram C2, Intune mass wipe | ~15 |
| UNC1549 (Nimbus Manticore) | LIGHTRAIL, POLLBLEND, TWOSTROKE, DEEPROOT, MINIBIKE | ~10 |
| Pioneer Kitten | CVE-2024-24919, CVE-2024-3400, Backblaze exfil | ~8 |
| Dust Specter | TwinTalk, SPLITDROP C2, domain IOCs | ~10 |
| Boggy Serpens/BlackBeard | Nuso backdoor | ~5 |
| Infy (Prince of Persia) | Tornado, Tonnerre, blockchain DGA, Telegram bot, IOC update | ~11 |
| CottonSandstorm | WezRat, credential theft | ~5 |
| Sicarii RaaS | Connectivity burst, file.io exfil | ~4 |
| Crafty Camel (Sosano) | PDF+HTA polyglot, C2 domains | ~4 |
| WINTAPIX/UNC1860 | IIS passive C2, heartbeat | ~3 |

### Key Detection Features
- **xbits cross-flow correlation**: FortiOS→Wasabi, Ivanti→Telegram, Havoc+Telegram multi-stage chains
- **ICS/OT protocols**: PCOM (Unitronics), Modbus, BACnet, S7comm
- **Healthcare emergency**: CVE-2025-59287 WSUS, Pay2Key v3, Intune MDM mass wipe
- **Blockchain C2**: Ethereum DGA resolution (eth_getStorageAt)

## Migration from v3.x

If you were loading multiple v3.x files, replace them with the single consolidated file:

```yaml
# Old (REMOVE):
rule-files:
  - iranian_apt_v3.1.rules       # archived
  - iranian_apt_v3_2.rules       # archived
  - iranian_apt_v3_3_expansion.rules  # archived

# New:
rule-files:
  - iranian-apt-detection.rules
```

The v3.x files are preserved in `archive/suricata-v3-legacy/` for reference.

## Deployment

### 1. Copy Rules File
```bash
sudo cp iranian-apt-detection.rules /etc/suricata/rules/
```

### 2. Update suricata.yaml
```yaml
rule-files:
  - iranian-apt-detection.rules
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

## False Positive Tuning

Common false positives and fixes:

| Rule | False Positive | Fix |
|------|----------------|-----|
| 2000018 | Legitimate ngrok usage | Whitelist specific IPs |
| 2000026 | PowerShell automation | Tune User-Agent string |
| 2000030 | International data transfers | Increase threshold dramatically |
| 2000031 | Large DNS responses | Increase threshold |
| 2000172/2000188 | Legitimate non-22 SSH | Whitelist known SSH ports |
| 2000182-2000183 | Authorized AnyDesk/MeshCentral | Suppress for approved RMM |
| 2000284 | .online TLD legitimate traffic | Consider disabling |
| 2000315 | bit.ly legitimate usage | Increase threshold |

## Updates

Check repository regularly for new signatures as Iranian APT tactics evolve.

## Support

Report false positives or rule issues via GitHub Issues.
