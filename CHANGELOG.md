# Changelog

All notable changes to the Iranian APT Detection Rules project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-06-25

### Added
- Initial release of Iranian APT detection rules
- Wazuh rules for CVE exploitation detection (100900-100919)
- Behavioral detection rules (100920-100939)
- Network-based detection rules (100940-100959)
- File integrity monitoring rules (100960-100979)
- Windows-specific detection rules (100980-100999)
- Suricata IDS signatures (SID 1000001-1000036)
- Sysmon configuration for enhanced logging
- Wazuh agent configuration template
- Support for detecting the following CVEs:
  - CVE-2024-24919 (Check Point Security Gateway)
  - CVE-2024-3400 (Palo Alto Networks PAN-OS)
  - CVE-2023-3519 & CVE-2019-19781 (Citrix NetScaler)
  - CVE-2022-1388 (F5 BIG-IP)
  - CVE-2024-21887 (Ivanti Connect Secure)
  - CVE-2021-26855 (Exchange Server ProxyLogon)
  - CVE-2023-23397 (Outlook Elevation of Privilege)
  - CVE-2020-1472 (Zerologon)
  - CVE-2023-38950/38951/38952 (ZKTeco BioTime)

### Security
- Detection for Iranian APT groups including Pioneer Kitten, Lemon Sandstorm, Peach Sandstorm
- IRGC-affiliated threat actor detection
- Ransomware collaboration indicators

## [Unreleased]

### Planned
- Detection for additional Iranian APT groups
- Cloud service exploitation patterns
- Container and Kubernetes attack detection
- MacOS and Linux specific rules
- Integration with additional SIEM platforms
- Machine learning-based anomaly detection
- Automated response playbooks