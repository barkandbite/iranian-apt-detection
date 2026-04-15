# Changelog

All notable changes to the Iranian APT Detection Rules project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.7] - 2026-04-15

### Added
- **2 MuddyWater Fooder/MuddyViper C2 IOC rules** (SIDs 2000494-2000495): New C2 infrastructure from Trellix "The Iranian Cyber Capability 2026" report.
  - SID 2000494: C2 IP 206.71.149.51 (Fooder/MuddyViper HTTPS C2)
  - SID 2000495: C2 IP 104.238.191.185 (SSH tunneled over port 443)
- **Total: 372 Suricata rules** (370 from v4.0.6 + 2 new), **~271 Wazuh rules**

### Changed
- **README.md**: Fixed version badge (0.6.2 -> 4.0.6), updated rule counts (318/338 -> 372), updated Recent Threats section with v4.0.1-v4.0.6 additions, fixed footer date and version, updated MITRE ATT&CK badge (v13 -> v15)
- **STRUCTURE.md**: Added missing SID blocks for v4.0.5 (SIDs 2000478-2000490, Wazuh IDs 101516-101521) and v4.0.6 (SIDs 2000491-2000493). Updated header ranges.

### MITRE ATT&CK
- T1071.001 (Web Protocols), T1573.002 (Asymmetric Cryptography), T1090 (Proxy), T1219 (Remote Access Software)

### IOC Currency Audit
- **206.71.149.51** (MuddyWater): NEW — Trellix April 2026. Fooder loader payload server.
- **104.238.191.185** (MuddyWater): NEW — Trellix April 2026. SSH-over-443 interactive access.
- **194.11.246.101** (MuddyWater): ACTIVE — Verified by Trellix, OTX (15 pulses). HosterDaddy AS215117.
- **157.20.182.{49,75}** (MuddyWater): ACTIVE — per v4.0.6 notes, no change.
- **45.80.148.195** (Infy): ABANDONED — confirmed migrated (v4.0.2). No change.

### Notes
- MuddyWater continues operating in US airport, bank, and Israel-linked software firm networks per Trellix.
- Source intelligence is public (Trellix blog) — safe for public repo.
- All rules synced with barkandbite/barkbite-suricata-by-country.

## [4.0.6] - 2026-04-11

### Added
- **3 MuddyWater ChainShell/CastleRAT rules** (SIDs 2000491-2000493): New coverage for MuddyWater's adoption of TAG-150's Russian MaaS platform. ChainShell is a Node.js-based C2 agent that resolves its control server address from an Ethereum smart contract, making traditional IP blocking largely ineffective.
  - SID 2000491: ChainShell C2 DNS — serialmenot.com domain (shared across deployments)
  - SID 2000492: CastleRAT "Smokest" campaign JWT beacon with userID bb47c0615477a877
  - SID 2000493: ChainShell Node.js HTTP POST to serialmenot.com
- **Total: 370 Suricata rules** (367 from v4.0.5 + 3 new), **~271 Wazuh rules**

### MITRE ATT&CK
- T1059.007 (JavaScript), T1102.002 (Bidirectional Communication), T1573.002 (Asymmetric Cryptography), T1071.001 (Web Protocols)

### IOC Currency Audit
- **157.20.182.49** (MuddyWater): ACTIVE — ChainShell/CastleRAT infrastructure confirmed by JUMPSEC, Ctrl-Alt-Intel (March 2026). Farsi-language code comments + Israeli IP range lists found on exposed server. Same IP as existing UDPGangster/FMAPP rules.
- **serialmenot.com** (ChainShell C2): NEW IOC — shared domain across TAG-150 MaaS deployments. Per-operation JWT credentials separate tracking.

### Notes
- MuddyWater's adoption of Russian criminal MaaS (TAG-150/CastleRAT) represents a significant operational shift — MOIS is outsourcing tooling to Russian-speaking cybercriminal groups. The existing `eth_call` rule (SID 2000181) covers ChainShell's Ethereum smart contract C2 resolution; these new rules add domain and campaign-specific detection.
- Source intelligence is public (JUMPSEC, CybersecurityNews) — safe for public repo.
- All 3 rules synced with barkandbite/barkbite-suricata-by-country.

## [4.0.5] - 2026-04-09

### Added
- **8 CyberAv3ngers Rockwell Automation PLC rules** (SIDs 2000478-2000485): New coverage per CISA Advisory AA26-097A (April 7, 2026). CyberAv3ngers (IRGC/Shahid Kaveh/Storm-0784/UNC5691) targeting Rockwell CompactLogix/Micro850 PLCs across US Water, Energy, and Government sectors since March 2026.
  - SID 2000478: CIP RegisterSession from external (CVE-2021-22681 auth bypass)
  - SID 2000479: CIP ListIdentity device enumeration recon
  - SID 2000480: CIP ForwardOpen connection establishment (PLC project access)
  - SID 2000481: CIP SendRRData encapsulated commands to PLC
  - SID 2000482: Dropbear SSH on OT ports (PLC persistence indicator)
  - SID 2000483: Rockwell ACD project file exfiltration
  - SID 2000484: EtherNet/IP UDP ListIdentity broadcast scan
  - SID 2000485: SSH to OT port from external source
- **6 Wazuh rules** (IDs 101516-101521): Host-side detection for CyberAv3ngers PLC targeting — Dropbear SSH process detection, Studio 5000 connections to port 44818, ACD project file access, suspicious process connecting to EtherNet/IP, SSH to OT ports, Dropbear in syslog.
- **5 Infy/Prince of Persia IOC update rules** (SIDs 2000486-2000490): New C2 infrastructure discovered post-Iran internet blackout (Jan 2026). Source: SafeBreach, The Hacker News.
  - SID 2000486: New C2 IP 45.80.149.3 (Tonnerre v12-16, Foudre v34)
  - SID 2000487: Foudre C2 DNS f13.ddnsking.com
  - SID 2000488: Tonnerre C2 DNS t13.ddnsking.com
  - SID 2000489: Infy C2 DNS conningstone.net domain
  - SID 2000490: Infy C2 DNS hbmc.net domain
- **Total: 367 Suricata rules** (354 from v4.0.4 + 8 CyberAv3ngers + 5 Infy IOC), **~271 Wazuh rules**

### MITRE ATT&CK
- T0883 (Internet Accessible Device), T0885/T1219 (Command and Control), T1565 (Stored Data Manipulation)

### IOC Currency Audit
- **194.11.246.101** (MuddyWater): ACTIVE — Hosterdaddy AS215117, confirmed active MuddyWater infra (15 OTX pulses, 64 IPs in /26 all running dnsmasq 2.85)
- **157.20.182.75** (MuddyWater UDPGangster): Status unchanged from v4.0.2 audit
- **157.20.182.49** (MuddyWater Sliver): Status unchanged from v4.0.2 audit
- **45.80.148.195** (Infy): ABANDONED — confirmed migrated to .249 (Dec 2025), then to 45.80.149.3 (Jan 2026). New IOC rules added (SIDs 2000486-2000490)
- **45.80.148.249** (Infy): ACTIVE — still serving Foudre/Tonnerre payloads alongside 45.80.149.3
- **159.100.6.69** (CyberAv3ngers IOCONTROL): ACTIVE — Frankfurt DE, MQTT 1883/8883 + RabbitMQ 15672

### Notes
- All 8 ICS/OT rules marked priority:1 with deployment guidance: enable ONLY on OT-adjacent segments.
- These rules complement existing CyberAv3ngers coverage (Unitronics PCOM, S7comm, Modbus, DNP3, BACnet, IOCONTROL MQTT) with Rockwell-specific EtherNet/IP CIP protocol detection.
- Source intelligence is public (CISA advisory) — safe for public repo.
- Infy actor has established parallel C2 infrastructure: 45.80.148.249 + 45.80.149.3 both active. Domain pattern shifted from subdomain-based (conningstone/hbmc) to DDNS-based (ddnsking.com).

## [4.0.4] - 2026-04-07

### Changed
- **SID 2000030** (Data Exfiltration to Non-US Host): FP reduction — dsize threshold 5KB -> 50KB, alert threshold 1/hour -> 100/hour, type limit -> type both. (rev 3 -> 4)
- **SID 2000284** (.online TLD Resolution): FP reduction — threshold 5/hour -> 50/hour. Added tuning note: .online is a legitimate gTLD; recommend disabling unless correlated with other Iranian APT indicators. (rev 1 -> 2)
- **Total: 354 rules** (unchanged)

### Notes
- IOC currency spot-check: all 4 IPs from v4.0.2 audit (194.11.246.101, 157.20.182.75, 157.20.182.49, 45.80.148.195) verified <5 days ago; no re-check needed this session.
- Dragos PYROXENE (IRGC-CEC aligned) tracked but no public IOCs available for rules yet.

## [4.0.3] - 2026-04-05

### Added
- **10 Dust Specter (Iran-nexus) rules** (SIDs 2000468-2000477): New coverage for Dust Specter APT campaign targeting Iraqi government officials. Source: Zscaler ThreatLabz March 2026, Trellix "Iranian Cyber Capability 2026".
  - SID 2000468: TwinTalk C2 beacon — behavioral detection of JWT Bearer auth with randomized hex URI paths (checksum seed 0xABCDEF)
  - SIDs 2000469-2000475: DNS IOC rules for 7 known C2 domains (lecturegenieltd.pro, meetingapp.site, afterworld.store, girlsbags.shop, onlinepettools.shop, web14.info, web27.info)
  - SID 2000476: SPLITDROP ZIP payload delivery (mofaSurvey archive from compromised ca.iq)
  - SID 2000477: Fake Webex lure download from meetingapp.site
- **5 Wazuh rules** (IDs 101511-101515): Host-side detection for Dust Specter artifacts — TwinTask file-based C2 polling (ProgramData\PolGuid), SPLITDROP DLL sideloading (libvlc.dll/hostfxr.dll), registry persistence via VLC/WingetUI Run keys, extended C2 domain DNS resolution.
- **Total: 354 Suricata rules** (344 from v4.0.2 + 10 new), **~265 Wazuh rules**

### MITRE ATT&CK
- T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1574.002 (DLL Side-Loading), T1001.003 (Protocol Impersonation), T1547.001 (Registry Run Keys)

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
