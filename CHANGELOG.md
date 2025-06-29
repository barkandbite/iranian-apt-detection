# Changelog

All notable changes to the Iranian APT Detection Rules project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-06-29

### Fixed
- Corrected invalid Wazuh alert levels (changed level 17 to 16)
- Consolidated duplicate rule IDs across files
- Fixed XML syntax errors in master rule file
- Corrected rule ID allocation to prevent conflicts

### Added
- Comprehensive active response script for automated threat mitigation
- Active response configuration for Iranian APT rules
- Update template for standardized change documentation
- README for archive directory
- New detections for June 2025 threats:
  - TEMPLEDROP kernel driver abuse
  - TEMPLELOCK event log manipulation
  - IOCONTROL industrial malware
  - AI-powered phishing campaigns
  - Passive backdoor detection
  - Azure cloud C2 infrastructure

### Changed
- Reorganized rule IDs for better categorization:
  - 100900-100929: CVE exploitation
  - 100930-100959: Behavioral detection
  - 100960-100989: Network detection
  - 100990-100999: File integrity
  - 101000-101029: Windows-specific
  - 101030-101059: Unique behaviors
  - 101060-101089: Cloud/container
  - 101090-101099: Correlation
- Improved documentation structure
- Enhanced Suricata rule metadata

### Security
- Added detection for CVE-2025-24201 (WebKit zero-day)
- Added detection for CVE-2024-30088 (Windows kernel)
- Enhanced cryptocurrency exchange targeting detection
- Improved critical infrastructure protection rules

## [1.0.0] - 2025-06-25

### Added
- Initial release of Iranian APT detection rules
- Wazuh rules for CVE exploitation detection
- Behavioral detection rules
- Network-based detection rules
- File integrity monitoring rules
- Windows-specific detection rules
- Suricata IDS signatures (SID 1000001-1000036)
- Sysmon configuration for enhanced logging
- Wazuh agent configuration template
- Support for detecting CVEs:
  - CVE-2024-24919 (Check Point)
  - CVE-2024-3400 (Palo Alto)
  - CVE-2023-3519 (Citrix)
  - CVE-2022-1388 (F5 BIG-IP)
  - CVE-2024-21887 (Ivanti)
  - CVE-2021-26855 (Exchange ProxyLogon)
  - CVE-2023-23397 (Outlook)
  - CVE-2020-1472 (Zerologon)

### Security
- Detection for Iranian APT groups:
  - Pioneer Kitten
  - Lemon Sandstorm
  - Peach Sandstorm
  - MuddyWater
  - APT34/OilRig
  - APT35/Charming Kitten
  - IRGC-affiliated groups
