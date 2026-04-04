# Changelog

All notable changes to the Iranian APT Detection Rules project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.3] - 2026-04-04

### Added
- **5 MuddyWater RustyWater Suricata rules** (SIDs 2000468-2000472): New Rust-based RAT targeting Israeli government and Middle East critical infrastructure. Covers nomercys C2 domain, Rust reqwest HTTP C2 beacon with Base64-XOR obfuscation, CertificationKit.ini payload delivery, and Telegram Bot API C2 polling/exfiltration. Source: CloudSEK TRIAD, The Hacker News (January-March 2026).
- **5 Wazuh rules** (IDs 101511-101515): Host-side detection for RustyWater CertificationKit.ini registry persistence, payload artifact on disk, nomercys C2 domain resolution, AV/EDR product enumeration, and Telegram Bot API access from non-browser processes.
- **Total: 349 Suricata rules** (344 from v4.0.2 + 5 new), **265 Wazuh rules** (260 + 5 new)

### Intelligence Context
- MuddyWater escalated operations post-February 28, 2026 Iran airstrikes, targeting US critical infrastructure (bank, airport, nonprofit) and Israeli entities
- RustyWater represents a significant tooling evolution from PowerShell/VBS to compiled Rust binaries with 3-layer obfuscation
- Telegram Bot C2 channel identified via Group-IB Operation Olalampo monitoring
- MITRE: T1071.001, T1059, T1547.001, T1036.005, T1518.001, T1102.002

## [4.0.2] - 2026-04-03

### Added
- **1 Infy/Prince of Persia replacement C2 rule** (SID 2000467): New C2 IP 45.80.148.249 identified via SafeBreach research. Actor migrated from 45.80.148.195 in late Dec 2025.
- **Total: 344 rules** (343 from v4.0.1 + 1 new)

### Changed
- **SID 2000169** (Infy Tonnerre C2 IP-1): Annotated as abandoned, lowered to priority:3. IP 45.80.148.195 decommissioned by actor in early Jan 2026. (rev 1 -> 2)
- **SID 2000327** (Infy Tonnerre C2 IP-1 duplicate): Same annotation and priority change. (rev 1 -> 2)

### IOC Currency Audit
Verified 4 Iranian APT-associated IPs:
- **194.11.246.101** (MuddyWater/Handala): ACTIVE — HosterDaddy AS215117, confirmed Mar 2026
- **157.20.182.75** (MuddyWater UDPGangster C2): ACTIVE — same hosting block
- **157.20.182.49** (MuddyWater Sliver C2): ACTIVE — open directory, Feb/Mar 2026
- **45.80.148.195** (Infy/Prince of Persia): ABANDONED — migrated to .249 in Jan 2026

## [4.0.1] - 2026-03-30

### Added
- **5 Boggy Serpens (MuddyWater) BlackBeard rules** (SIDs 2000462-2000466): Backported from barkbite-suricata-by-country. Covers BlackBeard Rust C2 beacon, header-based exfiltration, Nuso HTTP backdoor novaservice fingerprint, Phoenix VBA macro delivery, and diplomatic "Sustainable Peace" phishing lure. Source: Unit 42 Boggy Serpens Threat Assessment (March 2026). Campaign: 4-wave attack against UAE marine/energy company, Aug 2025 – Feb 2026.
- **Total: 343 rules** (338 from v4.0 + 5 new)

## [4.0.0] - 2026-03-30

### Changed — BREAKING
- **Consolidated three Suricata rule files into one canonical file**: `suricata/iranian-apt-detection.rules` (338 rules, zero duplicate SIDs). Replaces `iranian_apt_v3.1.rules` (199 rules), `iranian_apt_v3_2.rules` (241 rules), and `iranian_apt_v3_3_expansion.rules` (97 rules).
- The old v3.x files had **199 duplicate SIDs** (v3.1 was a complete subset of v3.2) and **60 SID collisions** (v3.2 and v3.3 assigned the same SIDs 2000231-2000290 to completely different rules). Loading multiple files caused silent rule overrides.
- Colliding v3.3 rules renumbered to SIDs 2000360-2000456 to match the barkandbite/barkbite-suricata-by-country distribution.
- Old files archived to `archive/suricata-v3-legacy/`.
- Updated all deployment scripts, documentation, and STRUCTURE.md to reference the new filename.

### Fixed
- **SID 2000359** (RMM + Telegram Correlation Chain): Converted from `flowbits:isset` to `xbits:isset` for cross-flow correlation. The rule previously required both `iranian.havoc` and `iranian.telegram` bits set on the same TCP connection, which is impossible (Havoc C2 and Telegram are separate connections). Now uses `xbits:isset,iranian.havoc,track ip_src` and `xbits:isset,iranian.telegram,track ip_src` for proper cross-connection detection. (rev 1 -> 2)
- **SID 2000022** (Havoc C2 Beacon): Added `xbits:set,iranian.havoc,track ip_src,expire 3600` alongside existing flowbits, enabling cross-flow correlation with SID 2000359. (rev 11 -> 12)
- **SID 2000346** (Telegram Bot API sendDocument Exfil): Added `xbits:set,iranian.telegram,track ip_src,expire 3600` to provide the missing setter for the correlation chain. Previously, the `iranian.telegram` xbit/flowbit was never set by any rule. (rev 1 -> 2)

### Migration
Users loading v3.x files should update `suricata.yaml`:
```yaml
# Remove:
#   - iranian_apt_v3.1.rules
#   - iranian_apt_v3_2.rules
#   - iranian_apt_v3_3_expansion.rules
# Add:
  - iranian-apt-detection.rules
```

## [0.6.3] - 2026-03-29

### Added
- **CRESCENTHARVEST espionage campaign** (APT35/Charming Kitten overlap): 5 new Suricata rules (SID 2000457-2000461) detecting the structured C2 protocol used by this campaign targeting Farsi-speaking activists and diaspora communities.
  - RAT registration (`/register_agent`), command polling (`/info`), output exfiltration (`/Out`), file upload (`/upload`)
  - Correlation rule linking registration with subsequent exfiltration
  - DLL sideloading via signed Google binary (software_reporter_tool.exe)
- Source: Acronis TRU, Recorded Future, The Hacker News (Feb-Mar 2026)
- MITRE ATT&CK: T1566.001, T1204.002, T1574.002, T1041, T1056.001

### Notes
- The CRESCENTHARVEST campaign exploits Iran protest narratives to deliver RAT/infostealer malware via malicious RAR archives containing LNK files with double extensions. The implant supports command execution, keylogging, credential theft, and Telegram data extraction.
- Validated: 241 rules in v3.2 pass `suricata -T` (Suricata 7.0.3), 0 errors.

## [0.6.1] - 2026-03-12

### Fixed
- **SID 2000022** (Havoc C2 Beacon): Fixed mixed buffer syntax — changed sticky buffer `http.user_agent` to legacy modifier `http_user_agent` for compatibility with the `http_header` modifier in the same rule. Suricata 7.x rejects mixing sticky buffers and legacy modifiers without a `pkt_data` reset. (rev 9 -> 10)
- **SID 2000026** (PowerShell Download Cradle): Fixed "no matches for previous buffer" error caused by `pkt_data` reset between `http.user_agent` sticky buffer and `http_uri` legacy modifier. Simplified to use consistent legacy modifier syntax throughout. (rev 8 -> 9)

### Notes
- Both bugs caused Suricata to refuse to load the entire rules file (`Loading signatures failed`), making all 199 rules non-functional until fixed.
- Validated all 199 rules pass `suricata -T` with Suricata 7.0.3.

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
