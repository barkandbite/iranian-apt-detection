# Iranian APT Detection Rules

[![Version](https://img.shields.io/badge/version-5.0.0-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v13-orange.svg)](documentation/MITRE-ATT&CK-Mapping.md)

## Overview

Open-source detection rules for defending critical infrastructure against Iranian Advanced Persistent Threat (APT) groups in the context of the ongoing US-Iranian cyber conflict. This repository provides production-ready Suricata IDS signatures and Wazuh SIEM rules designed to give organizations of all sizes access to nation-state-level threat detection.

**This is a purely defensive toolkit.** It contains no offensive capabilities, exploit code, or attack tools.

### Why This Exists

Nation-state cyber operations increasingly target critical infrastructure -- energy grids, water treatment facilities, hospitals, financial systems, telecommunications networks, transportation, and government agencies. Large enterprises and federal agencies have dedicated threat intelligence teams and commercial detection platforms. Smaller organizations, municipal utilities, rural hospitals, and regional infrastructure operators often do not.

This project aims to close that gap by providing free, continuously updated detection rules that any organization running Suricata or Wazuh can deploy to defend against documented Iranian cyber operations.

### Sectors Covered

- **Energy** -- power grid, oil and gas, renewable energy systems
- **Water and Wastewater** -- treatment plants, SCADA systems, Unitronics PLCs
- **Healthcare** -- hospitals, medical device networks, health IT systems
- **Telecommunications** -- ISPs, mobile carriers, network infrastructure
- **Finance** -- banks, payment processors, financial exchanges
- **Transportation** -- aviation, maritime, logistics
- **Defense and Aerospace** -- defense industrial base, aerospace contractors
- **Government** -- federal, state, and local government networks

## What Is New in v5.0.0

- **354 Suricata signatures** with comprehensive automated test coverage
- **265+ Wazuh detection rules** across 10 rule files
- **28+ Iranian APT threat families** with dedicated detection logic
- **40+ CVEs** covered including 2025/2026 zero-days actively exploited by Iranian groups
- **Automated test suite** -- every Suricata rule has synthetic packet generation tests to validate detection accuracy
- **Standardized rule descriptions** across all signatures for consistent SOC workflows
- Full toolset coverage for MuddyWater, CyberAv3ngers, UNC1549, APT42, APT34, APT33, and more
- Industrial protocol detection for BACnet, Modbus, S7comm, and Unitronics PCOM

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
# Deploy consolidated rules (354 signatures)
sudo cp suricata/iranian-apt-detection.rules /etc/suricata/rules/

# Add to suricata.yaml rule-files section:
#   - iranian-apt-detection.rules

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
| **MuddyWater** | Seedworm, MERCURY | Gov, Telecom, Defense, Healthcare | MuddyViper, UDPGangster, Dindoor, Fakeset, CHAR, Phoenix, PowGoop, TWINTASK |
| **CyberAv3ngers** | IRGC-CEC, BAUXITE | Water, Energy, OT/ICS | IOCONTROL (MQTT C2), PLC_Controller, PCOM exploitation, camera BDA |
| **Handala** | Void Manticore, Storm-0842 | Defense, Tech, Healthcare | Intune MDM wipe, NetBird, wiper, GPO deployment |
| **Pioneer Kitten** | Fox Kitten, Pay2Key | VPN vendors, Healthcare | Pay2Key v3 (ChaCha20, I2P), CVE exploitation |
| **Cotton Sandstorm** | Emennet Pasargad | Media, Healthcare | WezRat, WhiteLock ransomware |
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
- **Initial Access**: 25 techniques
- **Execution**: 18 techniques
- **Persistence**: 19 techniques
- **Privilege Escalation**: 10 techniques
- **Defense Evasion**: 24 techniques
- **Credential Access**: 15 techniques
- **Discovery**: 11 techniques
- **Lateral Movement**: 12 techniques
- **Collection**: 9 techniques
- **Command and Control**: 32 techniques
- **Exfiltration**: 12 techniques
- **Impact**: 14 techniques

### Rule Statistics
- **Suricata Signatures**: 354 network detection signatures
- **Wazuh Rules**: 265+ detection rules across 10 files
- **CVEs Covered**: 40+ including 2025/2026 zero-days
- **Known C2 IPs**: 35+
- **Known C2 Domains**: 25+
- **Unique Behavioral Patterns**: 100+
- **Threat Families**: 28+

## Targeted CVE Detection

- **CVE-2025-59287** (Windows WSUS Deserialization RCE, CVSS 9.8)
- **CVE-2026-1281** (Ivanti EPMM RCE via bash arithmetic)
- **CVE-2025-59718** (FortiOS SAML Bypass)
- **CVE-2024-55591** (FortiOS WebSocket Auth Bypass)
- **CVE-2025-64446** (FortiWeb Path Traversal)
- **CVE-2025-23006** (SonicWall SMA Deserialization)
- **CVE-2025-9316** (N-able N-central SOAP RCE)
- **CVE-2024-38434** (Unitronics PCOM Password Reset)
- **CVE-2025-31701** (Dahua Camera RCE)
- CVE-2024-24919, CVE-2024-3400, CVE-2021-36260, CVE-2021-33044, and 25+ more

## Detection Signatures

- **Microsoft Intune MDM** weaponized as wiper (Handala)
- **Pay2Key v3** kill chain -- BitLocker suspend, fake Avast, I2P C2
- **Cloud Storage Exfiltration** (Wasabi, Backblaze via Rclone)
- **Telegram Bot API** C2 (CHAR, Tonnerre, SloppyMIO, Handala)
- **MQTT-TLS** Industrial Control System C2 (IOCONTROL)
- **Ethereum blockchain** C2 resolution (EtherHiding)
- **Discord/Cloudflare Workers/Firebase** C2 (APT42 TAMECAT)
- **PCOM protocol** exploitation (Unitronics PLCs)
- **BACnet/Modbus/S7comm** industrial protocol abuse
- **GitHub Gist dead-drop** resolver (SloppyMIO steganography chain)
- **DLL sideloading** via VMware VGAuth and Windows Defender components
- **WINTAPIX** passive IIS backdoor heartbeat detection
- Tehran business hours activity correlation (UTC+3:30)
- Passive implants (no outbound C2), DNS hijacking

## Test Suite

Every Suricata rule in this repository is backed by automated tests. The test framework generates synthetic packets that match each rule's detection logic, then runs them against Suricata to verify correct alerting. This ensures that rule updates do not introduce regressions and that all signatures fire as intended.

Run the test suite:
```bash
sudo ./tools/test_suricata.sh
```

## Active Response

- Automated IP blocking for confirmed threat indicators
- Process termination for known malicious tooling
- Host isolation for compromised endpoints
- Emergency shutdown capability for ransomware scenarios
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
│   ├── iranian-apt-detection.rules  # Consolidated (354 rules)
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
│   ├── test_suricata.sh
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

We welcome contributions. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

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

- CISA for threat advisories and infrastructure defense guidance
- MITRE ATT&CK framework
- Wazuh and Suricata open-source communities
- Security researchers tracking Iranian threat operations

## Disclaimer

These rules are provided as-is for defensive purposes only. No offensive capabilities are included. Users are responsible for testing and tuning in their environment. Monitor for false positives before enabling active response.

---

**Last Updated**: April 7, 2026 | **Version**: 5.0.0 | **Maintainer**: Bark&Bite Security Intelligence
