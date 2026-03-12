# Iranian APT Detection Rules

[![Version](https://img.shields.io/badge/version-0.6.0--pre-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v13-orange.svg)](documentation/MITRE-ATT&CK-Mapping.md)

## Overview

Enterprise-grade detection rules for Iranian Advanced Persistent Threat (APT) groups targeting critical infrastructure, defense, and technology sectors. This repository provides comprehensive Wazuh SIEM rules and Suricata IDS signatures to detect and respond to Iranian cyber operations.

## 🚨 Recent Threats (March 2026 Update)

- **CRITICAL**: Operation Epic Fury (Feb 28, 2026) response signatures
- **NEW**: MuddyWater's **UDPGangster**, **Dindoor**, and **Fakeset** malware families
- **NEW**: CyberAv3ngers **IOCONTROL** OT/ICS malware targeting 400+ device types
- **NEW**: Exploitation of **CVE-2026-1281** (Ivanti EPMM) and **CVE-2025-59718** (FortiOS)
- **NEW**: C2 via Telegram Bot API, Wasabi/Backblaze cloud storage, and MQTT-TLS

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
sudo cp suricata/iranian_apt_v3.1.rules /etc/suricata/rules/
sudo suricata-update
sudo systemctl restart suricata
```

### 3. Enable Active Response
```bash
sudo cp tools/iranian-apt-active-response.sh /var/ossec/active-response/bin/
sudo chmod +x /var/ossec/active-response/bin/iranian-apt-active-response.sh
# Add configuration from configurations/iranian-apt-active-response.xml to ossec.conf
```

## Iranian APT Groups Covered

| Group | Also Known As | Primary Targets | Key Techniques |
|-------|---------------|-----------------|----------------|
| **MuddyWater** | Mercury, Static Kitten | Government, Telecom, Finance | **UDPGangster**, **Dindoor**, **Fakeset**, PowerShell |
| **CyberAv3ngers** | IRGC-CEC | Water, Energy, OT/ICS | **IOCONTROL**, PLC disruption, MQTT C2 |
| **Pioneer Kitten** | Fox Kitten, UNC757, Parisite | VPN/Firewall vendors | CVE exploitation, Ransomware, I2P RaaS |
| **UNC1549** | Nimbus Manticore | Defense, Aerospace | **TWOSTROKE**, **DEEPROOT**, Azure C2 |
| **Infy** | Prince of Persia | Activists, Government | **Foudre**, **Tonnerre**, DGA, Telegram C2 |
| **Lemon Sandstorm** | RUBIDIUM | Cloud services | Exchange exploitation |

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
- **Wazuh Rules**: 177 detection rules across 9 files
- **Suricata Signatures**: 193 network signatures
- **CVEs Covered**: 25+ including 2025/2026 zero-days
- **Unique Behavioral Patterns**: 60+

## Key Features

### 🎯 Targeted CVE Detection
- **CVE-2026-1281** (Ivanti EPMM RCE) **NEW**
- **CVE-2025-59718** (FortiOS SAML Bypass) **NEW**
- **CVE-2025-55182** (React Server Components RCE) **NEW**
- **CVE-2024-55591** (FortiOS Auth Bypass) **NEW**
- CVE-2024-24919 (Check Point Security Gateway)
- CVE-2024-3400 (Palo Alto PAN-OS)

### 🔍 Unique Iranian Signatures
- **Cloud Storage Exfiltration** (Wasabi, Backblaze)
- **Telegram Bot API** Command & Control
- **MQTT-TLS** Industrial Control System communication
- **Deno Runtime** evasion artifacts (Dindoor)
- Tehran business hours activity (UTC+3:30)
- Farsi language artifacts
- DNS hijacking with Let's Encrypt
- Cryptocurrency mining for funding
- Passive implants (no outbound C2)

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
│   └── README.md
├── suricata/                  # Network IDS signatures
│   ├── iranian_apt_v3.1.rules
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
- macOS/Linux specific rules
- Cloud provider detections (AWS, GCP)
- ICS/SCADA protocol signatures
- False positive tuning
- Translations

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

**Last Updated**: March 9, 2026 | **Version**: 0.6.0-pre | **Maintainer**: Bark&Bite Security Intelligence
