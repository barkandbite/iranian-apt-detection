# Changelog

All notable changes to the Iranian APT Detection Rules project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-03-09

### Added
- **Major Update (Pre-release)**: Integration of detections from Operation Epic Fury (Feb 2026).
- New Wazuh Rules file: `0918-iranian-apt-march2026-updates.xml` (SID 101200-101240).
- 63 new Suricata signatures (SID 2000131-2000193) covering 2025-2026 activity.
- Comprehensive threat intelligence report: `documentation/THREAT_INTEL_MARCH_2026.md`.
- Deployment guide: `documentation/MARCH-2026-DEPLOYMENT.md`.
- New detections for MuddyWater malware families:
  - **UDPGangster**: UDP:1269 C2 and `SystemProc.exe` persistence.
  - **Dindoor**: Deno-based backdoor with Wasabi cloud exfiltration.
  - **Fakeset**: Python backdoor with Backblaze B2 storage integration.
  - **CHAR/Olalampo**: Telegram Bot API-controlled Rust backdoor.
- New detections for CyberAv3ngers OT/ICS malware:
  - **IOCONTROL**: Custom cyberweapon targeting PLCs/HMIs via MQTT-TLS.
- Expanded CVE coverage:
  - CVE-2026-1281 (Ivanti EPMM RCE)
  - CVE-2025-59718 (FortiOS SAML Auth Bypass)
  - CVE-2024-55591 (FortiOS Auth Bypass / "FortiSetup" admin creation)
  - CVE-2025-55182 (React Server Components "React2Shell")
  - CVE-2025-23006 (SonicWall SMA 1000)

### Changed
- Updated main README with vibrant new layout and current statistics.
- Refreshed group attribution table with latest 2026 intelligence.
- Improved detection coverage statistics across all kill chain phases.

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
