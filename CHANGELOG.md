# Changelog

All notable changes to the Iranian APT Detection Rules project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.13] - 2026-04-30

### Fixed
- **4 Suricata rules fixed for Suricata 7.0.3 sticky buffer validation** — SIDs 2000462, 2000463, 2000465, 2000468 had reversed `content:"..."; http.method;` / `http.content_type;` syntax that caused parse errors. Fixed to proper sticky buffer ordering: `http.method; content:"...";`. All 4 rules bumped to rev 2.

## [4.0.12] - 2026-04-29

### Added
- **12 new APT34/OilRig "Dark Scepter" C2 domain DNS detection rules** (SID 2000502-2000513) — Cloudflare-fronted domains mapped by Hunt.io April 2026 infrastructure tracking: anythingshere.shop, cside.site, footballfans.asia, menclub.lt, musiclivetrack.website, stone110.store, web14.info, justweb.click, girlsbags.shop, lecturegenieltd.pro, ntcx.pro, retseptik.info
- **1 new APT34/OilRig Dark Scepter C2 IP rule** (SID 2000514): 38.180.239.161 (M247 hosting)
- **1 new MuddyWater C2 IP rule** (SID 2000515): 157.20.182.49 (AS136557 Hosterdaddy, confirmed active by Oasis Security targeting US/Israeli infrastructure)
- **Total: 392 Suricata rules** (was 378), SID range: 1000039-2000515

## [4.0.11] - 2026-04-28

### Fixed
- **Archived deprecated `cyberav3ngers-ioc-aa26-097a.rules`** — Moved to `archive/` to prevent SID collision with SIDs 2000496-2000497 already merged into main file in v4.0.10
- **Updated suricata/README.md** — Version 4.0→4.0.10, rules 338→378, SID range extended to 2000501
- **Updated STRUCTURE.md** — Removed deprecated file from suricata/ tree, added to archive/ tree

## [4.0.10] - 2026-04-19

### Fixed
- **Merged CyberAv3ngers IOC rules (SIDs 2000496-2000497) into main file** — Previously these rules existed only in the supplemental `cyberav3ngers-ioc-aa26-097a.rules` file, which the by-country repo's daily sync workflow does not pull. This caused the sync bot to overwrite the by-country Iran file without these 2 rules, silently dropping them from the production distribution. Merging into the main file ensures the sync workflow picks them up.
- **Deprecated `cyberav3ngers-ioc-aa26-097a.rules`** — File retained for backward compatibility but marked as merged. Loading both files simultaneously will cause duplicate SID errors.
- **Total: 378 Suricata rules** (same count — rules moved, not added), **~271 Wazuh rules**

### Technical Detail
- SID 2000496 (CyberAv3ngers engineering workstation 185.82.73.x) and SID 2000497 (staging server 135.136.1.133) inserted between MuddyWater C2 section and CyberAv3ngers behavioral section
- Behavioral section comment updated to reference SIDs 2000496-2000497 instead of supplemental file

## [4.0.9] - 2026-04-18

### Added
- **4 CyberAv3ngers ICS/OT behavioral detection rules** (SIDs 2000498-2000501): Protocol-level signatures that survive infrastructure rotation, complementing IOC rules SIDs 2000496-2000497 and behavioral CIP detection SIDs 2000478-2000485.
  - SID 2000498: External EtherNet/IP to internal PLCs on port 44818
  - SID 2000499: Dropbear SSH on alt port 2222 to ICS segments
  - SID 2000500: External Modbus TCP to OT on port 502
  - SID 2000501: External S7comm/ISO-TSAP to OT on port 102
- **Total: 378 Suricata rules** (374 from v4.0.8 + 4 new), **~271 Wazuh rules**

### MITRE ATT&CK
- T0883 (Internet Accessible Device), T0885 (Commonly Used Port), T1219 (Remote Access Tools), T0855 (Unauthorized Command Message)

### Deployment Notes
- All 4 rules are Priority:1 ICS/OT rules. Enable ONLY on OT-adjacent segments.
- $HOME_NET should be tuned to ICS/SCADA subnets; deploying on IT segments will cause false positives from legitimate engineering workstation traffic.
- Backported from barkandbite/barkbite-suricata-by-country to maintain sync parity.

## [4.0.8] - 2026-04-17

### Added
- **2 CyberAv3ngers IOC infrastructure rules** (SIDs 2000496-2000497): IOC IP rules from CISA Advisory AA26-097A (April 7, 2026). Complements existing behavioral detection (SIDs 2000478-2000485) with high-confidence infrastructure attribution.
  - SID 2000496: CyberAv3ngers engineering workstation — 7 IPs on 185.82.73.0/24 (single multi-homed Windows box running Rockwell Studio 5000, active Jan 2025 – Mar 2026)
  - SID 2000497: CyberAv3ngers staging server 135.136.1.133 (provisioned Feb 2026, active 4 days in mid-Mar 2026, then abandoned; priority:2 due to possible reassignment)
- **Total: 374 Suricata rules** (372 from v4.0.7 + 2 new), **~271 Wazuh rules**

### MITRE ATT&CK
- T0883 (Internet Accessible Device), T0885 (Commonly Used Port), T1219 (Remote Access Tools), T1565.001 (Stored Data Manipulation)

### IOC Currency Notes
- **185.82.73.{162,164,165,167,168,170,171}** (CyberAv3ngers): ACTIVE — CISA confirms 14+ months persistent activity. These 7 IPs are a single multi-homed workstation running Rockwell toolchain.
- **135.136.1.133** (CyberAv3ngers staging): ABANDONED — 4-day activity window mid-March 2026. May be reassigned. Rule set to priority:2.
- **Existing IOCs**: No changes from v4.0.7 audit. MuddyWater C2 IPs (206.71.149.51, 104.238.191.185) remain active per Trellix.

### Notes
- Source intelligence is public (CISA AA26-097A joint advisory) — safe for public repo.
- Both rules use `threshold:type limit, track by_src, count 1, seconds 300` to prevent alert flooding while ensuring detection.
- These IOC rules complement the EtherNet/IP CIP behavioral detection in SIDs 2000478-2000485. Together they provide both high-confidence attribution (IOC match) and infrastructure-independent detection (protocol patterns).
- Pending sync with barkandbite/barkbite-suricata-by-country via daily workflow.

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
- **3 MuddyWater ChainShell/CastleRAT rules** (SIDs 2000491-2000493): New coverage for MuddyWater's adoption of TAG-150's Russian MaaS platform.
  - SID 2000491: ChainShell C2 DNS — serialmenot.com domain
  - SID 2000492: CastleRAT "Smokest" campaign JWT beacon
  - SID 2000493: ChainShell Node.js HTTP POST to serialmenot.com
- **Total: 370 Suricata rules**, **~271 Wazuh rules**

### MITRE ATT&CK
- T1059.007, T1102.002, T1573.002, T1071.001

## [4.0.5] - 2026-04-09

### Added
- **8 CyberAv3ngers Rockwell PLC rules** (SIDs 2000478-2000485): Per CISA AA26-097A.
- **6 Wazuh rules** (IDs 101516-101521): Host-side CyberAv3ngers detection.
- **5 Infy/Prince of Persia IOC rules** (SIDs 2000486-2000490)
- **Total: 367 Suricata rules**, **~271 Wazuh rules**

## [4.0.4] - 2026-04-07

### Changed
- SID 2000030: FP reduction (dsize 5KB->50KB, threshold 1->100/hr)
- SID 2000284: FP reduction (threshold 5->50/hr)

## [4.0.3] - 2026-04-05

### Added
- **10 Dust Specter rules** (SIDs 2000468-2000477)
- **5 Wazuh rules** (IDs 101511-101515)

## [4.0.2] - 2026-04-03

### Added
- SID 2000467: Infy replacement C2 IP 45.80.148.249

## [4.0.1] - 2026-03-30

### Added
- **5 Boggy Serpens/BlackBeard rules** (SIDs 2000462-2000466)

## [4.0.0] - 2026-03-30

### Changed — BREAKING
- Consolidated three Suricata files into one: `iranian-apt-detection.rules` (338 rules)
- Resolved 199 duplicate SIDs and 60 SID collisions
- Old files archived to `archive/suricata-v3-legacy/`

## [0.6.3] - 2026-03-29

### Added
- CRESCENTHARVEST campaign (SIDs 2000457-2000461)

## [0.6.1] - 2026-03-12

### Fixed
- SID 2000022, 2000026: Mixed buffer syntax errors

## [0.6.0] - 2026-03-09

### Added
- Major update: 63 new signatures, Wazuh rules, threat intel report

## [2.0.0] - 2025-06-29

### Fixed
- Invalid Wazuh alert levels, duplicate rule IDs, XML syntax

### Added
- Active response, June 2025 detections

## [1.0.0] - 2025-06-25

### Added
- Initial release