# Iranian APT Detection Rules

[![Version](https://img.shields.io/badge/version-0.6.2-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v13-orange.svg)](documentation/MITRE-ATT&CK-Mapping.md)

## Overview

Enterprise-grade detection rules for Iranian Advanced Persistent Threat (APT) groups targeting critical infrastructure, defense, and technology sectors. This repository provides comprehensive Wazuh SIEM rules and Suricata IDS signatures to detect and respond to Iranian cyber operations.

## HEALTHCARE EMERGENCY (March 25, 2026)

Three concurrent Iranian campaigns targeting U.S. healthcare disclosed March 24:

- **Handala/Void Manticore** wiped 200K+ Stryker devices via **Microsoft Intune MDM** abuse — no malware needed. Maryland EKG transmission went dark statewide. DOJ attributed; $10M reward.
- **Pay2Key v3** (IRGC) hit unnamed U.S. healthcare org with **ChaCha20 + Curve25519** ransomware. Fake Avast AV bypass. **I2P C2** (not Tor). Purely destructive — no ransom demand.
- **MuddyWater** exploiting **CVE-2025-59287** (WSUS CVSS 9.8) to pre-position on healthcare networks.

## Recent Threats (v0.6.2)

- **CRITICAL**: Operation Epic Fury (Feb 28, 2026) response signatures
- **NEW**: 28+ Iranian APT threat families with dedicated detection rules
- **NEW**: MuddyWater toolset — **UDPGangster**, **Dindoor**, **Fakeset**, **MuddyViper**, **CHAR**, **Phoenix**, **PowGoop**, **TWINTASK**
- **NEW**: CyberAv3ngers **IOCONTROL** OT malware — full MQTT topic structure, PCOM protocol exploitation, DoH evasion
- **NEW**: **Pay2Key v3** ransomware — ChaCha20, fake Avast bypass, I2P C2, full kill chain detection
- **NEW**: UNC1549 full toolset — **LIGHTRAIL**, **TWOSTROKE**, **DEEPROOT**, **POLLBLEND**, **MINIBIKE**, **CRASHPAD**, **SIGHTGRAB**
- **NEW**: **Handala/Void Manticore** wiper — Intune MDM abuse, NetBird tunneling, known infrastructure
- **NEW**: **WezRat** infostealer, **TAMECAT** backdoor, **STEALHOOK**, **Sosano**, **SloppyMIO**, **Sicarii RaaS**, **WhiteLock**, **WINTAPIX**
- **NEW**: Industrial protocol rules — BACnet, Modbus FC6/FC16, S7comm, Unitronics PCOM
- **NEW**: 40+ CVEs covered including CVE-2025-59287, CVE-2026-1281, CVE-2025-59718, CVE-2024-55591, CVE-2024-38434

## Quick Start

### 1. Deploy Wazuh Rules

#### Option A: Deploy Individual Rule Files (Recommended)
```bash
sudo cp wazuh-rules/09*.xml /var/ossec/etc/rules/
sudo chown ossec:ossec /var/ossec/etc/rules/09*.xml
sudo chmod 660 /var/ossec/etc/rules/09*.xml
sudo systemctl restart wazuh-manager
```

#### Option B: Deploy Consolidated Master File
```bash
sudo cp archive/0900-iranian-apt-detection-master.xml /var/ossec/etc/rules/
sudo chown ossec:ossec /var/ossec/etc/rules/0900-iranian-apt-detection-master.xml
sudo chmod 660 /var/ossec/etc/rules/0900-iranian-apt-detection-master.xml
sudo systemctl restart wazuh-manager
```

### 2. Deploy Suricata Rules
```bash
# Deploy base rules + expansion
sudo cp suricata/iranian_apt_v3_2.rules /etc/suricata/rules/
sudo cp suricata/iranian_apt_v3_3_expansion.rules /etc/suricata/rules/

# Add both to suricata.yaml rule-files section:
#   - iranian_apt_v3_2.rules
#   - iranian_apt_v3_3_expansion.rules

# Validate and reload (no restart needed)
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo kill -USR2 $(pidof suricata)
```

### 3. Enable Active Response
```bash
sudo cp tools/iranian-apt-active-response.sh /var/ossec/active-response/bin/
sudo chmod +x /var/ossec/active-response/bin/iranian-apt-active-response.sh
# Add configuration from configurations/iranian-apt-active-response.xml to ossec.conf
```

## Iranian APT Groups Covered (28+)

| Group | Also Known As | Primary Targets | Key Detections |
|-------|---------------|-----------------|----------------|
| **MuddyWater** | Seedworm, MERCURY | Healthcare, Gov, Telecom, Defense | MuddyViper, UDPGangster, Dindoor, Fakeset, CHAR, Phoenix, PowGoop, TWINTASK |
| **CyberAv3ngers** | IRGC-CEC, BAUXITE | Water, Energy, OT/ICS, Healthcare | IOCONTROL (MQTT C2), PLC_Controller, PCOM exploitation, camera BDA |
| **Handala** | Void Manticore, Storm-0842 | Healthcare, Defense, Tech | Intune MDM wipe, NetBird, wiper, GPO deployment |
| **Pioneer Kitten** | Fox Kitten, Pay2Key | Healthcare, VPN vendors | Pay2Key v3 (ChaCha20, I2P), CVE exploitation |
| **Cotton Sandstorm** | Emennet Pasargad | Healthcare, Media | WezRat, WhiteLock ransomware |
| **UNC1549** | Nimbus Manticore | Aerospace, Defense, Telecom | TWOSTROKE, DEEPROOT, LIGHTRAIL, POLLBLEND, MINIBIKE, CRASHPAD |
| **APT42** | Charming Kitten | Gov officials, Activists | TAMECAT (Discord/Cloudflare/Firebase C2) |
| **APT34** | OilRig, Helix Kitten | Gov, Finance, Telecom | STEALHOOK, Veaty, Spearal, DNS tunneling |
| **APT33** | Peach Sandstorm | Aerospace, Energy | Tickler, VHD delivery, SHAPESHIFT wiper |
| **Infy** | Prince of Persia | Activists, Dissidents | Foudre v34, Tonnerre v50, Tornado v51 (blockchain DGA) |
| **RedKitten** | IRGC-aligned | Human rights NGOs | SloppyMIO (steganography, GitHub dead-drop) |
| **Crafty Camel** | UNK_CraftyCamel | Aviation, Transport (UAE) | Sosano (Golang), polyglot files |
| **UNC1860** | MOIS | Government, Telecom | WINTAPIX, TOFUDRV, passive IIS backdoors |
| **Sicarii** | Handala-linked RaaS | Multiple | AES-GCM, file.io exfil, fake WinDefender |
| **Dark Scepter** | APT34 subcluster | Multiple | Cloudflare fronting, known infrastructure |
| **BQT.Lock** | Hezbollah cyber | Israel, U.S., Saudi | Baqiyat RaaS platform |

## Detection Coverage

### By Kill Chain Phase
- **Initial Access**: 25 techniques (+6)
- **Execution**: 18 techniques (+7)
- **Persistence**: 19 techniques (+5)
- **Privilege Escalation**: 10 techniques (+3)
- **Defense Evasion**: 24 techniques (+6)
- **Credential Access**: 15 techniques (+3)
- **Discovery**: 11 techniques (+3)
- **Lateral Movement**: 12 techniques (+3)
- **Collection**: 9 techniques (+3)
- **Command & Control**: 32 techniques (+11)
- **Exfiltration**: 12 techniques (+5)
- **Impact**: 14 techniques (+5)

### Rule Statistics
- **Wazuh Rules**: 319 detection rules across 10 files
- **Suricata Signatures**: 318 network signatures across 2 rule files
- **CVEs Covered**: 40+ including 2025/2026 zero-days
- **Known C2 IPs**: 35+
- **Known C2 Domains**: 25+
- **Unique Behavioral Patterns**: 100+
- **Threat Families**: 28+

## Key Features

### Targeted CVE Detection
- **CVE-2025-59287** (Windows WSUS Deserialization RCE, CVSS 9.8) **HEALTHCARE**
- **CVE-2026-1281** (Ivanti EPMM RCE via bash arithmetic)
- **CVE-2025-59718** (FortiOS SAML Bypass)
- **CVE-2024-55591** (FortiOS WebSocket Auth Bypass — MuddyWater modified PoC)
- **CVE-2025-64446** (FortiWeb Path Traversal)
- **CVE-2025-23006** (SonicWall SMA Deserialization)
- **CVE-2025-9316** (N-able N-central SOAP RCE)
- **CVE-2024-38434** (Unitronics PCOM Password Reset)
- **CVE-2025-31701** (Dahua Camera RCE)
- CVE-2024-24919, CVE-2024-3400, CVE-2021-36260, CVE-2021-33044, and 25+ more

### Unique Iranian Signatures
- **Microsoft Intune MDM** weaponized as wiper (Handala/Stryker)
- **Pay2Key v3** kill chain — BitLocker suspend, fake Avast, I2P C2
- **Cloud Storage Exfiltration** (Wasabi, Backblaze via Rclone)
- **Telegram Bot API** C2 (CHAR, Tonnerre, SloppyMIO, Handala)
- **MQTT-TLS** Industrial Control System C2 (IOCONTROL)
- **Ethereum blockchain** C2 resolution (EtherHiding — smart contract getString())
- **Discord/Cloudflare Workers/Firebase** C2 (APT42 TAMECAT)
- **PCOM protocol** exploitation (Unitronics PLCs, magic bytes + opcodes)
- **BACnet/Modbus/S7comm** industrial protocol abuse
- **GitHub Gist dead-drop** resolver (SloppyMIO steganography chain)
- **DLL sideloading** via VMware VGAuth and Windows Defender components
- **WINTAPIX** passive IIS backdoor heartbeat detection
- MuddyViper distinctive WinHTTP User-Agent fingerprint
- LIGHTRAIL obsolete Chrome/42 + Edge/12 User-Agent combo
- Tehran business hours activity (UTC+3:30), Farsi language artifacts
- Passive implants (no outbound C2), DNS hijacking

### 🛡️ Active Response
- Automated IP blocking
- Process termination
- Host isolation
- Emergency shutdown for ransomware
- Integration with SOAR platforms

## Repository Structure

```
iranian-apt-detection/
├── wazuh-rules/               # SIEM detection rules
│   ├── 0910-iranian-apt-cve-detection-rules.xml
│   ├── 0911-iranian-apt-behavior-rules.xml
│   ├── 0912-iranian-apt-network-rules.xml
│   ├── 0913-iranian-apt-fim-rules.xml
│   ├── 0914-iranian-apt-windows-rules.xml
│   ├── 0915-iranian-apt-unique-behaviors.xml
│   ├── 0916-iranian-apt-cloud-container.xml
│   ├── 0917-iranian-apt-june2025-updates.xml
│   ├── 0918-iranian-apt-march2026-updates.xml
│   ├── 0919-iranian-apt-march2026-expansion.xml
│   └── README.md
├── suricata/                  # Network IDS signatures
│   ├── iranian_apt_v3_2.rules
│   ├── iranian_apt_v3_3_expansion.rules
│   └── README.md
├── configurations/            # Agent and system configs
│   ├── sysmon-config-iranian-apt.xml
│   ├── ossec-agent-iranian-apt.conf
│   ├── iranian-apt-active-response.xml
│   └── README.md
├── documentation/             # Threat intelligence and guides
│   ├── SOC-Quick-Reference-Iranian-APT.md
│   ├── MITRE-ATT&CK-Mapping.md
│   ├── Sector-Vulnerability-Analysis.md
│   └── README.md
├── tools/                     # Deployment and testing scripts
│   ├── deploy-iranian-apt-rules.sh
│   ├── iranian-apt-active-response.sh
│   ├── deploy-active-response.sh
│   ├── test.sh
│   └── README.md
├── archive/                   # Historical versions
│   └── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
└── UPDATE_TEMPLATE.md
```

## Installation Guide

### Prerequisites
- Wazuh 4.3+ (Manager and Agents)
- Suricata 6.0+
- Sysmon 13+ (Windows endpoints)
- Python 3.8+ (for tools)

### Full Deployment
```bash
# Clone repository
git clone https://github.com/BarkandBite/iranian-apt-detection.git
cd iranian-apt-detection

# Run automated deployment
sudo ./tools/deploy-iranian-apt-rules.sh --full

# Test deployment
sudo ./tools/test.sh --complete
```

### Manual Deployment

See individual README files in each directory for detailed instructions.

## SOC Integration

### Dashboard Queries

**Wazuh/Elasticsearch**:
```
rule.groups: "iranian_apt" AND rule.level: [14 TO 16]
```

**Splunk**:
```
index=wazuh rule.groups="iranian_apt" rule.level>=14
```

### Alert Priorities

| Level | Response Time | Action |
|-------|---------------|---------|
| 16 | Immediate | Isolate, investigate, executive brief |
| 15 | 15 minutes | Block, investigate, incident response |
| 14 | 1 hour | Investigate, correlate, monitor |
| 13 | 4 hours | Review, validate, track |

## Performance Impact

| Component | CPU | Memory | Network | Storage |
|-----------|-----|---------|---------|----------|
| Wazuh Rules | +2-3% | +50MB | Minimal | +100MB/day |
| Suricata | +5-10% | +200MB | None | +500MB/day |
| Active Response | Spike | Minimal | Varies | Minimal |

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Needed Contributions
- macOS/Linux specific endpoint rules
- Cloud provider detections (AWS GuardDuty, GCP SCC integration)
- Additional ICS/SCADA protocol signatures (DNP3, OPC DA)
- False positive tuning and threshold optimization
- Splunk/Elastic SIEM rule translations
- YARA rules for file-level detection

## Support

- **Issues**: Use GitHub Issues for bugs and feature requests
- **Updates**: Watch this repo for threat intelligence updates
- **Contact**: security@barkandbite.com

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- CISA for threat intelligence
- MITRE ATT&CK framework
- Wazuh and Suricata communities
- Security researchers tracking Iranian threats

## Disclaimer

These rules are provided as-is for defensive purposes. Users are responsible for testing and tuning in their environment. Monitor for false positives before enabling active response.

---

**Last Updated**: March 25, 2026 | **Version**: 0.6.2 | **Maintainer**: Bark&Bite Security Intelligence
