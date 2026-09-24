# Changelog

All notable changes to the Iranian APT Detection Rules project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.27] - 2026-09-24

### Added — MOIS CHOSEN BRICK / HEAVYGRAM observables (SID 2000584–2000585)

UK NCSC + FBI + Netherlands AIVD joint advisory (2026-09-15) on MOIS
Windows surveillance spyware targeting Iranian dissidents, activists and
journalists (delivered via WhatsApp/Telegram rapport-building as fake
Pictory/RunwayML/Norton/KeePass installers). Its C2 rides per-victim
Telegram Bot IDs — the existing Telegram Bot API behavioral rules
(getUpdates polling / file exfil) already fire on that fabric — so the new
network rules cover the advisory's remaining observables:

- **SID 2000584** — DNS resolution of the residential-proxy providers the
  recent variants route Telegram traffic through (`iproyal.com`,
  `lightningproxies.net`). Tuning: suppress for hosts authorized to use
  these services.
- **SID 2000585** — DNS resolution of the cloud object-storage exfil
  endpoints (`vultrobjects.com`, `storjshare.io`). Backblaze B2 exfil was
  already covered by the MuddyWater cloud rules.

### Added — Wazuh host-side parity (101561–101564)

New file `wazuh-rules/0928-iranian-apt-september2026-chosenbrick.xml`:

- **101561** — `SMQDService` / `winappx` Run-key persistence created.
- **101562** — file written under the masquerading `C:\Windows \SysWOW64`
  directory (deliberate trailing space).
- **101563** — Microsoft Defender exclusion added for that path.
- **101564** — process executed from the trailing-space directory.

### Notes

- The advisory's full hash/IOC appendix (ic3.gov 260915.pdf) is
  image-scanned and could not be machine-extracted; chase manually for the
  complete set.
- Header counts reconciled: 462 rules, SID 1000039–2000585.
- Rule IDs 101550–101556 remain reserved for PR #54's CDB/IOC-list work.

## [4.0.26] - 2026-09-23

### Changed — 2026-09-23 consolidation refinements

- Wazuh parity files renamed to keep the `0925-` prefix clear for PR #54's
  planned `0925-ioc-list-matching.xml` (rule IDs 101550–101556):
  `0925-…noderabbit.xml` → `0926-…noderabbit.xml`,
  `0926-…unc1549.xml` → `0927-…unc1549.xml`. Rule IDs unchanged (they were
  already allocated around #54's block).
- Fixed the stale ruleset header (claimed 452 rules / SID max 2000575;
  actual 460 / 2000583). Same fix applied to the private repo's synced
  `bb-iran-suricata.rules`, whose header had also drifted (4.0.24 / broken
  count line).

### Added — UNC1549 / Mirage Kitten / Nimbus Manticore September 2026 campaigns (SID 2000576–2000583)

Consolidates draft PRs #52 and #53, which had both allocated SIDs from
2000576 against an unchanged main. All eight rules are retained; the
UNC1549 SSH-tunnel pair from PR #52 is renumbered 2000582–2000583.

**NodeRabbit / PollCat (Kaspersky Securelist, 2026-09-01) — Mirage Kitten /
UNC1549 fake-job npm supply-chain campaign:**
- **SID 2000576** — NodeRabbit staging bucket `oracle-challenge.s3` TLS SNI
- **SID 2000577** — NodeRabbit staging bucket path over plain HTTP
- **SID 2000578** — Fake-job "technical challenge" lure archive download
  (`Front-Technical-Challenge*.zip`, `FrontEnd-Task*.zip`, `RankChallenge-react*.zip`)
- **SID 2000580** — PollCat Azure App Service host flow marker (noalert correlator)
- **SID 2000581** — PollCat repeated-HTTP-400 check-in pattern against
  `*.azurewebsites.net` (PollCat treats 400 as successful registration)

**Nimbus Manticore SSH tunneler (Check Point / Group-IB, Aug 2026):**
- **SID 2000579** — SSH banner on TCP/443 to confirmed C2 172.86.98.113
- **SID 2000582** — any-protocol outbound contact with 172.86.98.113
- **SID 2000583** — inbound contact from 172.86.98.113

### Added — Wazuh host-side parity (101545–101549, 101557–101560)

- `wazuh-rules/0926-iranian-apt-september2026-noderabbit.xml` (101545–101549):
  NodeRabbit implant under `node_modules/.cache/.<hex8>/`, Node.js launch from
  hidden cache, malicious Git hooks, npm postinstall execution chain,
  RankChallenge-react lure artifact.
- `wazuh-rules/0927-iranian-apt-september2026-unc1549.xml` (101557–101560):
  `wtsapi32.dll` masquerade written outside System32, reverse-SSH tunneler
  invocation, C2 IP on process command line, service ImagePath persistence.
  Renumbered from the draft's 101545–101548; 101550–101556 left unallocated
  for the CDB list-matching rules proposed in PR #54.

### Notes

- Backported to the private by-country repo in the same session — Iran SID
  parity verified (both repos at 460 rules, SIDs 1000039–2000583).
- This entry supersedes draft PRs #51 (docs drift, merged here), #52, and #53.
- PR #54 (Wazuh manager load fixes, CI, CDB tiering, severity re-grade) is
  reviewed and recommended to merge; these new Wazuh rules avoid the defect
  classes it fixes and its claimed rule-ID range.

## [Unreleased]

### Fixed — documentation reconciliation (2026-09-15)

Version/count drift left behind by the v4.0.25 release (which updated
CHANGELOG.md and the top of README.md but not the other docs): the canonical
rules-file header, `suricata/README.md`, `STRUCTURE.md`, and the README
deployment/statistics sections still said **449 rules / v4.0.24 / SID max
2000572**. All now state **452 rules / v4.0.25 / SID 1000039-2000575**, and
the header's SID-allocation map gains the 2000573-2000575 RustyWater row.
No rule content changed — `suricata -T` verified, 452 signatures, parity
with the private repo's `bb-iran-suricata.rules` intact.

## [4.0.25] - 2026-08-20

### Added — MuddyWater RustyWater behavioral rules (SID 2000573–2000575)

Rescana (Aug 2026) profiled MuddyWater's Rust-based `reqwest`-driven RAT
targeting Israeli government and infrastructure. v4.0.21 already ships four
IOC-anchored RustyWater rules against `nomercys.it.com` / `159.198.66.153`
(SID 2000534–2000537). These new rules complement that with **behavioral
fingerprints** that survive C2 infrastructure rotation:

- **SID 2000573** — `POST /rw/beacon` with `User-Agent: reqwest/…` and a
  Base64-shaped body ≥200 bytes. Threshold 2/600s to suppress single-hit
  scanner probes.
- **SID 2000574** — `GET /rw/task` with the campaign-unique `X-Rw-Id`
  16-byte-hex agent-identifier header.
- **SID 2000575** — `POST /rw/upload` with `Content-Encoding: gzip` and a
  `reqwest/` UA. High-priority exfil signal.

### Added — Wazuh host-side parity rules (101540–101544)

New file `wazuh-rules/0924-iranian-apt-august2026-rustywater.xml`:

- **101540** — RustyWater agent binary drop under a known naming pattern
  (`rustyw.exe`, `rw_agent.exe`, `winrust.exe`, `reqwsvc.exe`) in
  LocalAppData / Roaming / ProgramData.
- **101541** — Same binaries invoked with `--beacon` / `--task` / `--upload`
  or `/rw/(beacon|task|upload)` command-line arguments.
- **101542** — Windows service literally named `RustyWater` installed.
- **101543** — Windows service whose ImagePath resolves to a known
  RustyWater binary path.
- **101544** — RustyWater state file (`rw_id.bin` / `rw_cfg.bin` /
  `rw_state.bin`) dropped under `AppData\Roaming\Microsoft\Windows\Templates`.

### Backport direction

Originated in the private `barkbite-suricata-by-country` repo in the same
2026-08-20 maintenance session; backported here per the standing rule that
both repos must stay in sync on Iran content. SID/rule-ID allocation matches
the private repo — Iran SID parity verified (both repos at 452 rules,
SIDs 1000039–2000575).

### Validation

- `suricata -T` on `suricata/iranian-apt-detection.rules`: OK, 452 rules load
- `xmllint --noout wazuh-rules/*.xml`: all 15 XML files pass
- Wazuh rule ID `100900–101544`: 289 rules, zero duplicates
- Suricata SID parity vs `bb-iran-suricata.rules`: **identical**
## [4.0.24] - 2026-08-14

### Added — August 2026 backlog consolidation

Nine draft PRs (#40–#48) had accumulated unmerged since 2026-07-08, each
opened against an unchanged `main` and each allocating from the same "next
available" SID/rule-ID. The result was four different rule sets all claiming
Wazuh IDs from 101530 and three different Suricata rule sets all claiming
SID 2000562. This release merges every unique rule from that backlog into a
single collision-free allocation. No detection content was dropped.

**11 Suricata rules (SID 2000562–2000572):**

- **2000562–2000563** — Cavern HollowGraph (from PRs #41/#42). M365 Graph-API
  C2 over `cloudlanecdn.com`, plus the DNS-tunnel credential-refresh channel.
- **2000564–2000566** — CyberAv3ngers ICS expansion (from PRs #43/#45), per
  CISA AA26-097A (updated 2026-07-22): Schneider UMAS external control,
  Siemens S7comm external CPU STOP, and S7comm program download. These are
  OT rules — enable **only** on OT-adjacent segments.
- **2000567–2000572** — MuddyWater Operation Olalampo (from PR #46):
  GhostBackDoor French-language API C2 (`/api/accueil/actualiser`,
  `/api/graphique/obtenir-donnees`, `/api/authentification/renouveler_token`),
  HTTP_VIP victim registration and chunked download, PatchAgent PTCH v2
  container retrieval.

**10 Wazuh rules (101530–101539):**

- **101530–101531** (`0920`) — MuddyWater Chaos false-flag host indicators:
  `ms_upd.exe` stager, `Game.exe` RAT C2 egress (from PR #40).
- **101532–101533** (`0921`) — Cavern HollowGraph: `logAzure.txt` Graph
  credential store dropped to disk, host DNS query to `cloudlanecdn.com`
  (from PRs #41/#42).
- **101534–101535** (new `0922-iranian-apt-august2026-ics-indicators.xml`) —
  CyberAv3ngers ICS: Schneider PLC project-file access by engineering
  software, Siemens S7 programming binary from a non-standard path
  (from PR #45).
- **101536–101539** (new `0923-iranian-apt-august2026-host-indicators.xml`) —
  Olalampo host footprint: CHAR `novaservice.exe`, GhostFetch
  `burnutill\burn.exe`, `MicrosoftVersionUpdater` service masquerade,
  `FMAPP.dll` reverse-SOCKS5 sideload (from PR #46).

### Added — contributor guidance

`CONTRIBUTING.md` now documents the Suricata 7.x syntax pitfalls that have
each caused a real defect in this project, split into hard errors (the file
will not load) and silent failures (the rule loads but never fires). Salvaged
from PR #47.

### Fixed — documentation drift

`STRUCTURE.md`, `suricata/README.md` and the rule-file header all understated
the shipping ruleset. The rules file header still claimed 376 rules with a
ceiling of SID 2000501 and a 2026-04-19 date while the file actually shipped
438 rules up to SID 2000561. All three are now reconciled against the
ruleset, and the header's SID-allocation map covers 2000502-2000572.
Partly salvaged from PR #48.

### Cross-repo

`bb-iran-suricata.rules` in `barkbite-suricata-by-country` and
`suricata/iranian-apt-detection.rules` here are byte-identical at 449 rules
(verified). SIDs were assigned once and applied to both repos in the same
cycle.

## [4.0.23] - 2026-07-07

### Added — Cavern Manticore modular C2 framework (Check Point Research, July 2026)

Cavern Manticore is an Iran MOIS-linked actor (OilRig/Lyceum nexus) targeting
Israeli government and IT-sector organizations with the Cavern (ex-Cav3rn)
modular .NET C2 framework. Deploys via DLL sideloading (legitimate
WinDirStat.exe loading trojanized uxtheme.dll from `C:\ProgramData\WinDir\`);
HTTP C2 polls `GET /profile` and submits via `POST /gallery` with the agent ID
in an `X-User-token` header; SQL browser module passes database credentials in
`x-db-user`/`x-db-password` pseudo-headers; WebSocket alternative channel on
`/socket`; operator-deployed `cac.aspx` webshell on IIS.

**9 Suricata rules (SID 2000553–2000561):**
- 2000553: DNS `hospitalinstallation.com` (parent — also catches `auth.` and
  the `google.com.hospitalinstallation.com` visual-obfuscation subdomain)
- 2000554: TLS SNI `hospitalinstallation.com`
- 2000555: DNS `adserviceupdate.com` (older Cav3rn HTTP module)
- 2000556: DNS `hygienehistory.com` (older Cav3rn HTTP module)
- 2000557: Behavioral — C2 beacon poll `GET /profile` + `X-User-token` header
- 2000558: Behavioral — result submit `POST /gallery` + `X-User-token` +
  `text/plain`
- 2000559: High-confidence — `x-db-user` + `x-db-password` credential
  pseudo-headers in one request (unique to the Cavern SQL module), priority 1
- 2000560: `cac.aspx` IIS webshell access (inbound), priority 1
- 2000561: WebSocket upgrade to exact `/socket` path (exact-match URI to
  exclude socket.io's `/socket.io/`)

**2 Wazuh rules (101528–101529, new file
`wazuh-rules/0921-iranian-apt-july2026-host-indicators.xml`):**
- 101528: Sysmon Event 7 — `WinDirStat.exe` loading `uxtheme.dll` from a
  non-System32/SysWOW64 path (the Cavern sideload chain)
- 101529: Sysmon Event 1 — any process executing from
  `C:\ProgramData\WinDir\` (masquerade directory, absent on clean systems)

### Notes
- **Total: 438 Suricata rules** (SID 1000039–2000561); **279 Wazuh rules**
  (max ID 101529)
- Same rules added to `bb-iran-suricata.rules` in the by-country repo in the
  same maintenance window — daily sync stays a no-op.
- Same-day survey also confirmed the Unit 42 "Tracking Screening Serpens"
  publication is the May 27 2026 disclosure already integrated in v4.0.21
  (SID 2000538–2000549) — no new IOCs.

### MITRE ATT&CK
- T1574.002 (DLL Side-Loading), T1071.001 (Web Protocols/WebSocket),
  T1021.003, T1087.002 (LDAP enumeration), T1090 (SOCKS5 tunnel),
  T1036.005 (Masquerading), T1505.003 (Web Shell)

## [4.0.22] - 2026-07-07

### Fixed (P0 — 26-day production outage; behavior preserved, revs bumped)

Since v4.0.21 shipped 2026-06-11, `suricata -T -S suricata/iranian-apt-detection.rules`
has been rejected under Suricata 7.0.3 with `Loading signatures failed`. Every
community deployer of the public ruleset has had **zero Iranian APT network
coverage for 26 days**. Two rules introduced in the v4.0.21 backlog merge
contained syntax Suricata 7 hard-errors on, aborting load of the entire file
(not just the offending rules).

Seven prior draft PRs (#30, #32, #33, #34, #35, #36, #37, #38) identified this
same root cause across seven separate sessions and stalled unmerged. This
release lands the fix.

- **SID 2000030 rev 5→6** — `dsize:>500000` was outside Suricata's uint16
  packet-size range (max 65535). The v4.0.21 FP-tightening pass treated `dsize`
  as a session-wide byte counter, but it is per-packet u16. Rewritten to
  `dsize:>1400` (near-MTU full data packet — the actual behavioral marker for
  bulk transfer). The existing `count 500, seconds 3600` threshold was already
  doing the volumetric work and is unchanged, so behavioral intent (sustained
  bulk outbound to non-RFC1918) is preserved.
- **SID 2000535 rev 1→2** — Removed redundant `nocase` after the sticky
  `http.host` buffer. Suricata 7 normalizes the host buffer to lowercase and
  rejects the `http.host + content + nocase + fast_pattern` combination as a
  hard parse error (was a warning in earlier 7.0.x). Match string is already
  lowercase so detection semantics are identical.

### Validation

```
$ suricata -T -S suricata/iranian-apt-detection.rules -l /tmp/suri
i: suricata: This is Suricata version 7.0.3 RELEASE running in SYSTEM mode
i: suricata: Configuration provided was successfully loaded. Exiting.
```

All 429 rules arm. `xmllint --noout wazuh-rules/*.xml` exits 0. Rule count,
SID range, and Wazuh inventory unchanged from v4.0.21:

- **429 Suricata rules** (SID 1000039–2000552)
- **277 Wazuh rules** (max ID 101527)

### Cross-repo sync

Identical fixes applied to `bb-iran-suricata.rules` in the private
`barkbite-suricata-by-country` repo (v3.1.5). That repo's
`bb-crosscountry-suricata.rules` had **seven additional** broken rules with
the same syntax-error root cause (unescaped `;` in PCRE bracketed alternations,
one flow-direction / http.uri conflict, one `http.host + nocase`); all fixed
there too. The daily `sync-iran-rules.yml` workflow stays a no-op after both
land.

### Root cause of the 26-day miss

Prior maintenance sessions could not run `suricata -T` — the environment had
no Suricata binary — so static-check-only validation missed both defects and
none of the seven follow-up sessions merged their fix PRs. Suricata 7.0.3 is
now installed via `apt-get install suricata` at session start (~30s cost).
Standing follow-up for the next maintenance cycle: add a GitHub Actions
workflow that runs `suricata -T` on every PR touching `suricata/**`, plus
`xmllint` on `wazuh-rules/**`, so this class of regression cannot ship silently
again.

## [4.0.21] - 2026-06-11

### Added (consolidated backlog merge — PRs #16, #18, #22, #24 with SID renumbering)
- **4 MuddyWater RustyWater Rust RAT rules** (SID 2000534-2000537, renumbered from PR #16's 2000528-2000531 to resolve collision with v4.0.20 Rockwell rules):
  - SID 2000534: DNS query `nomercys.it.com`
  - SID 2000535: HTTP Host header `nomercys.it.com`
  - SID 2000536: TLS SNI `nomercys.it.com`
  - SID 2000537: C2 IP `159.198.66.153` (Hostinger AS47583)
- **12 Screening Serpens (UNC1549) MiniUpdate + MiniJunk V2 rules** (SID 2000538-2000549, renumbered from PR #22's 2000528-2000539) — Unit 42 May 27 2026 disclosure. Azure-hosted C2 domain clusters (`buisness-centeral*`/`premier*healthadvisory*`/`ramiltons*finance*` + Manager-suffix and abstract-noun clusters), `/agent/poll` and `/api/app/*` beacon behavioral, filemail.com + OnlyOffice staging
- **3 CVE-2025-34291 Langflow rules** (SID 2000550-2000552, renumbered from PR #18's 2000534-2000536) — CORS bypass POST `/api/v1/refresh`, RCE-by-design `/api/v1/validate/code` endpoint, Python exec/eval body match. CISA KEV 2026-05-21, MuddyWater attribution
- **6 Wazuh host-side rules**:
  - 101522 (from PR #18): Langflow python/uvicorn parent spawning shell or curl/wget
  - 101523-101527 (renumbered from PR #24's 101511-101515, which collided with existing 0919 IDs): Dindoor Deno runtime exec (Windows/Linux), Rclone-to-Wasabi/Backblaze exfil, quickassist.exe spawned by mail/browser, Amy Cherne / Donald Gay signed binaries — new file `wazuh-rules/0920-iranian-apt-june2026-host-indicators.xml`

### Changed (FP tightening from PR #16)
- SID 2000030 (rev 5): dsize 50KB→500KB, threshold 100→500/hr; renamed "Bulk Outbound Transfer Sustained Volume"
- SID 2000172 (rev 2): port exclusion [22,443,2222], threshold 1→5/hr
- SID 2000188 (rev 2): threshold 1→5/hr
- SID 2000284 (rev 3): threshold 50→500/hr (.online TLD)
- SID 2000315 (rev 3): Android UA constraint (Dalvik|okhttp|com.android.) via pcre /V, threshold 10→50/hr

### Notes
- **Total: 429 Suricata rules** (was 410), SID range: 1000039-2000552; 277 Wazuh rules, max ID 101527
- Consolidates four PRs that each claimed overlapping SID ranges against a stale main. Renumbering follows merge order: Rockwell (v4.0.20) kept its SIDs as first claimer.

### MITRE ATT&CK
- T1566.001, T1059.005, T1547.001, T1055, T1071.001 (RustyWater)
- T1574.002, T1574.014, T1102.002, T1583.006, T1027 (Screening Serpens)
- T1190, T1059.006, T1199 (Langflow)
- T1059.007, T1567.002, T1219, T1553.002, T1036.001/005 (Wazuh host indicators)

## [4.0.20] - 2026-05-18

### Added
- **6 new CyberAv3ngers Rockwell/Allen-Bradley PLC targeting rules** (SID 2000528-2000533) — CISA AA26-097A (April 7, 2026). IRGC-CEC actors exploiting internet-exposed CompactLogix and Micro850 PLCs using legitimate Studio 5000 Logix Designer:
  - SID 2000528: Known operator IPs `185.82.73.160/.161/.163/.166` (AS214036 multi-homed workstation)
  - SID 2000529: Staging host `135.136.1.133`
  - SID 2000530: Suspect range `185.82.73.160/28` to EtherNet/IP port 44818
  - SID 2000531: Behavioral — external EtherNet/IP RegisterSession (encap cmd 0x0065)
  - SID 2000532: Behavioral — external CIP Unconnected Send (service 0x52 via SendRRData) for PLC program manipulation
  - SID 2000533: External VNC to OT HMI workstations (771 exposed instances per Censys)
- **Total: 410 Suricata rules** (was 404), SID range: 1000039-2000533

### MITRE ATT&CK (ICS)
- T0831 (Manipulation of Control), T0843 (Program Download), T0842 (Project File Infection), T0855 (Unauthorized Command Message)

## [4.0.19] - 2026-05-13

### Added
- **4 new MuddyWater Microsoft Teams false flag C2 rules** (SID 2000524-2000527) — Rapid7 TR-Muddying-Tracks (May 2026). IT-support pretexting over Teams leading to Quick Assist session and Chaos ransomware false-flag deployment:
  - SID 2000524: DNS query `moonzonet.com`
  - SID 2000525: DNS query `uploadfiler.com` (encrypted config C2)
  - SID 2000526: DNS query `adm-pulse.com` (Quick Assist phishing lure)
  - SID 2000527: Post-compromise C2 IP `116.203.208.186` (Hetzner)
- **Total: 404 Suricata rules** (was 400), SID range: 1000039-2000527

### MITRE ATT&CK
- T1566.004 (Spearphishing Voice/Chat), T1598 (Phishing for Information), T1219 (Remote Access Software), T1036.005 (Masquerading)

## [4.0.18] - 2026-05-11

### Fixed
- **SID 2000022** (Havoc C2 Beacon) and **SID 2000026** (PowerShell Download Cradle): mixed legacy `http_header` modifier alongside sticky buffers (`http.user_agent`, `http.uri`, `http.cookie`) — Suricata 7.0+ rejects this combination at load. Converted to consistent sticky-buffer syntax. Same failure class as the v0.6.1 production outage and the v4.0.13/v4.0.17 fixes. Both bumped to rev 2.

## [4.0.17] - 2026-05-08

### Fixed
- **SID 2000523** (MuddyWater Stagecomp dropper behavioral): Reversed sticky buffer ordering caused Suricata 7.0.3 parse error. `content:"GET"; http.method;` → `http.method; content:"GET";`. Same class of issue fixed in v4.0.13 (SID 2000462-2000468). Bumped to rev 2.

## [4.0.16] - 2026-05-07

### Added
- **3 new MuddyWater Stagecomp/Darkcomp staging infrastructure rules** (SID 2000521-2000523) — IOCs from Rapid7 false flag ransomware campaign report (THN May 6, 2026):
  - SID 2000521: `172.86.126.208` — Stagecomp (ms_upd.exe) download server (RouterHosting VPS, UAE)
  - SID 2000522: `172.86.76.127` — Open directory toolkit hosting server (RouterHosting VPS, UAE)
  - SID 2000523: Behavioral — HTTP download of `ms_upd.exe` dropper filename (survives IP rotation)
- **Total: 400 Suricata rules** (was 397), SID range: 1000039-2000523

### MITRE ATT&CK
- T1105 (Ingress Tool Transfer), T1204.002 (Malicious File), T1036.005 (Match Legitimate Name or Location), T1598 (Phishing for Information)

## [4.0.15] - 2026-05-06

### Added
- **2 new Prince of Persia (Infy) Foudre replacement C2 IP rules** (SID 2000519-2000520) — SafeBreach confirmed 45.80.148.195 abandoned Dec 2025, replaced by 45.80.148.249 and 45.80.149.3 on same HOSTGW SRL (AS204641) network
- **Total: 397 Suricata rules** (was 395), SID range: 1000039-2000520

### IOC Currency Audit
- 45.80.148.195 (Prince of Persia Foudre): **ABANDONED** — SafeBreach Feb 2026 confirmed non-active, replaced by 45.80.148.249 and 45.80.149.3. Rule retained but flagged for review.
- 194.11.246.101 (MuddyWater Hosterdaddy): **STILL ACTIVE** — confirmed anchor node, multiple vendor confirmations through Mar 2026
- 157.20.182.75 (MuddyWater UDPGangster): **STILL ACTIVE** — Group-IB, Dark Reading confirmations
- 157.20.182.49 (MuddyWater AS136557): **STILL ACTIVE** — open directory discovered Mar 2026, Sliver C2 on port 31337

### MITRE ATT&CK
- T1071.001 (Web Protocols), T1568.002 (Domain Generation Algorithms)

## [4.0.14] - 2026-05-04

### Added
- **3 new Iranian APT cloud C2 domain DNS detection rules** (SID 2000516-2000518) — C2 domains from the Trellix "Iranian Cyber Capability 2026" report abusing free-tier cloud hosting platforms:
  - SID 2000516: `datadrift.somee.com` (MuddyWater C2 on free ASP.NET hosting)
  - SID 2000517: `prism-west-candy.glitch.me` (Iranian APT C2 on Glitch containers)
  - SID 2000518: `line.completely.workers.dev` (Iranian APT C2 on Cloudflare Workers)
- **Total: 395 Suricata rules** (was 392), SID range: 1000039-2000518

### MITRE ATT&CK
- T1071.001 (Web Protocols), T1102.002 (Bidirectional Communication), T1583.006 (Web Services)

### IOC Currency Audit
- 194.11.246.101 (Hosterdaddy/MuddyWater): **STILL ACTIVE** — confirmed anchor node for 64 Hosterdaddy IPs in 194.11.246.64/26 block, linked to Ethereum smart contract 0x2B77671c for on-chain C2 IP storage
- 157.20.182.75, 157.20.182.49 (AS136557/Hosterdaddy): No deattribution found, retaining
- 45.80.148.195: No specific recent intelligence, flagged for deeper verification next session

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