# Iranian APT Detection Rules

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v13-orange.svg)](documentation/MITRE-ATT&CK-Mapping.md)

## Overview

Enterprise-grade detection rules for Iranian Advanced Persistent Threat (APT) groups targeting critical infrastructure, defense, and technology sectors. This repository provides comprehensive Wazuh SIEM rules and Suricata IDS signatures to detect and respond to Iranian cyber operations.

## 🚨 Recent Threats (June 2025)

- **NEW**: AI-powered phishing campaigns using React frameworks
- **NEW**: IOCONTROL malware targeting industrial control systems
- **NEW**: TEMPLEDROP/TEMPLELOCK kernel-level evasion techniques
- **NEW**: Passive backdoors with no outbound C2
- **NEW**: Azure cloud infrastructure abuse

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
sudo cp suricata/iranian_apt_v2.rules /etc/suricata/rules/
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
| **Pioneer Kitten** | Fox Kitten, UNC757, Parisite | VPN/Firewall vendors | CVE exploitation, Ransomware |
| **Lemon Sandstorm** | RUBIDIUM | Cloud services | Exchange exploitation |
| **MuddyWater** | Mercury, Static Kitten | Government, Telecom | PowerShell, Living-off-the-land |
| **APT34** | OilRig, Helix Kitten | Energy, Finance | DNS tunneling, Custom tools |
| **APT35** | Charming Kitten, Phosphorus | Academia, Activists | Social engineering, Phishing |
| **IRGC CyberAv3ngers** | - | Water facilities | ICS/SCADA attacks |

## Detection Coverage

### By Kill Chain Phase
- **Initial Access**: 19 techniques
- **Execution**: 11 techniques  
- **Persistence**: 14 techniques
- **Privilege Escalation**: 7 techniques
- **Defense Evasion**: 18 techniques
- **Credential Access**: 12 techniques
- **Discovery**: 8 techniques
- **Lateral Movement**: 9 techniques
- **Collection**: 6 techniques
- **Command & Control**: 21 techniques
- **Exfiltration**: 7 techniques
- **Impact**: 9 techniques

### Rule Statistics
- **Wazuh Rules**: 166 detection rules across 8 files
- **Suricata Signatures**: 130 network signatures
- **CVEs Covered**: 15+ including zero-days
- **Unique Behavioral Patterns**: 40+

## Key Features

### 🎯 Targeted CVE Detection
- CVE-2024-24919 (Check Point Security Gateway)
- CVE-2024-3400 (Palo Alto PAN-OS)
- CVE-2023-23397 (Outlook NTLM Relay)
- CVE-2021-26855 (Exchange ProxyLogon)
- CVE-2025-24201 (WebKit Zero-Day) **NEW**

### 🔍 Unique Iranian Signatures
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
│   ├── iranian_apt_v2.rules
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

**Last Updated**: June 29, 2025 | **Version**: 2.0.0 | **Maintainer**: Bark&Bite Security
