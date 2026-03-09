# Iranian APT threat intelligence for network detection: July 2025–March 2026

**Iranian state-sponsored cyber operations have escalated to their highest intensity in history**, driven by two kinetic conflicts — the June 2025 twelve-day Iran-Israel war and Operation Epic Fury on February 28, 2026. MuddyWater is the most operationally active group, deploying at least **six new malware families** and actively compromising U.S. banks, airports, and defense suppliers as of early March 2026. CyberAv3ngers remains the most dangerous ICS-focused threat, with custom OT malware (IOCONTROL) deployed across **400+ devices globally**. At least **16 new CVEs** are being actively exploited, edge devices remain the primary entry vector, and Iranian actors have adopted novel C2 channels including Telegram Bot API, MQTT over TLS, Ethereum blockchain resolution, and cloud storage exfiltration via Wasabi and Backblaze. Below is the complete technical intelligence organized for Suricata IDS signature development.

---

## Actively exploited CVEs demand immediate patching and detection

Iranian APT groups are exploiting a mix of newly disclosed and older unpatched vulnerabilities across edge devices, enterprise software, and IoT/OT systems. The following CVEs have confirmed active exploitation by Iranian actors during this period:

**New CVEs (2025–2026) actively exploited by Iranian groups:**

| CVE | Product | CVSS | Exploiting Group | Notes |
|-----|---------|------|------------------|-------|
| CVE-2026-1281 | Ivanti EPMM | 9.8 | MuddyWater | Unauthenticated RCE via bash arithmetic expansion; CISA KEV Jan 29, 2026; scanned with Nuclei |
| CVE-2026-1731 | BeyondTrust | Critical | MuddyWater | RCE; active exploitation confirmed |
| CVE-2025-9316 | SolarWinds N-central RMM | High | MuddyWater | Mass exploitation campaign |
| CVE-2025-59718 | FortiOS/FortiProxy SAML | Critical | Multiple groups | Auth bypass via FortiCloud SSO; CISA KEV Dec 16, 2025; initial patch failed |
| CVE-2025-64446 | FortiWeb Manager | 9.1 | Multiple groups | Path traversal to admin access; zero-day exploit sold Nov 2025; exploited since Oct 2025 |
| CVE-2025-55182 | React Server Components | Critical | MuddyWater, Mint Sandstorm | RCE ("React2Shell") |
| CVE-2025-23006 | SonicWall SMA 1000 | Critical | Multiple groups | Pre-auth deserialization; chained with CVE-2025-40602 |
| CVE-2025-34067 | Hikvision cameras | High | CyberAv3ngers | Camera exploitation for surveillance and BDA |
| CVE-2024-55591 | FortiOS | Critical | MuddyWater | Auth bypass; modified watchTowr PoC with hardcoded FortiOS CLI payloads |
| CVE-2024-3400 | Palo Alto PAN-OS | 10.0 | Pioneer Kitten | Command injection; continued scanning |
| CVE-2024-24919 | Check Point Security Gateways | High | Pioneer Kitten | Zero-day info disclosure; scanning via Shodan |

**Legacy CVEs still under active Iranian exploitation:** CVE-2018-13379 (Fortinet VPN), CVE-2019-11510 (Pulse Secure), CVE-2019-1579 (PAN-OS GlobalProtect), CVE-2019-19781 (Citrix Netscaler), CVE-2022-42475 (FortiOS heap overflow), CVE-2023-3519 (Citrix Netscaler), CVE-2021-36260 (Hikvision command injection), CVE-2021-33044 (Dahua auth bypass), CVE-2023-28130 (Check Point GAIA RCE), CVE-2017-7921 (Hikvision auth bypass).

MuddyWater's Fortinet exploitation deserves special attention. The group **modified the watchTowr CVE-2024-55591 proof-of-concept** to replace test commands with hardcoded FortiOS CLI payloads (labeled test1 through test13) focused on creating administrator accounts ("FortiSetup" with **super_admin** profile), modifying VPN groups, and deploying webshells. The confirmed C2 IP for this activity is **194.11.246[.]101**.

---

## Sixteen new malware families and their network signatures

MuddyWater alone deployed six new tools, while UNC1549, Infy, and other groups introduced additional families. Each entry below includes the network-level indicators most useful for Suricata rules.

### MuddyWater (MOIS) — most active group

**Dindoor** (March 2026): A backdoor built on the **Deno JavaScript/TypeScript runtime** — a "bring your own runtime" evasion technique. Signed with a certificate issued to "**Amy Cherne**." Exfiltrates data via Rclone to Wasabi cloud storage. Detection: monitor for HTTPS traffic to `*.wasabisys.com` from unexpected hosts, and TLS certificates with subject "Amy Cherne." MITRE: T1059.007, T1567.002.

**Fakeset** (March 2026): Python-based backdoor downloaded from Backblaze B2 storage at `gitempire.s3.us-east-005.backblazeb2.com` and `elvenforest.s3.us-east-005.backblazeb2.com`. Signed by both "Amy Cherne" and "**Donald Gay**" — the latter previously linked to Stagecomp/Darkcomp malware. Detection: HTTP/HTTPS to `*.s3.us-east-005.backblazeb2.com` subdomains. MITRE: T1059.006, T1105.

**UDPGangster** (December 2025): Uses **UDP port 1269** for C2 with IP **157.20.182[.]75**. Commands use specific byte codes: **0x04** (heartbeat), **0x0A** (cmd.exe execution), **0x14** (file exfil), **0x1E** (payload deployment), **0x63** (C2 update). Data is ROR-encoded before transmission. Persists at `%AppData%\RoamingLow\SystemProc.exe`. PDB paths reference usernames "gangster" and "SURGE." MITRE: T1095, T1059.003.

**CHAR** (January 2026, Operation Olalampo): Rust-based backdoor controlled entirely via **Telegram Bot API**. Bot name "Olalampo," username "**stager_51_bot**." Shows signs of **AI-assisted development** (emoji debug strings). Associated tools include GhostFetch (downloader), GhostBackDoor (interactive shell), and HTTP_VIP (connects to `codefusiontech[.]org` for auth, deploys AnyDesk). MITRE: T1102, T1573.

**PersianC2 and ArenaC2** (exposed February 2026): Two custom C2 frameworks discovered on a Netherlands-based VPS. PersianC2 uses **JSON API polling over HTTP** with Persian/Farsi strings. ArenaC2 uses **HTTP POST via FastAPI/uvicorn with AES-256-CBC encryption**, fronted by a decoy "ArenaReport" news website. A third framework, **Key C2**, operates over **custom UDP**. MITRE: T1071.001, T1573.001.

**Phoenix v4** (August–October 2025): C2 domain `screenai[.]online` registered via NameCheap with CloudFlare DNS. Exposed an open directory via `SimpleHTTP/0.6 Python/3.10.12` server header on ports 443 and 8080. MITRE: T1566.001, T1219.

### CyberAv3ngers (IRGC-CEC) — ICS threat

**IOCONTROL**: Custom OT/IoT cyberweapon targeting PLCs, HMIs, routers, IP cameras, and fuel management systems from D-Link, Hikvision, Baicells, Red Lion, Orpak, Phoenix Contact, Teltonika, and Unitronics. Uses **MQTT over TLS on port 8883** (also port 1883) for C2, with **DNS-over-HTTPS via Cloudflare** for domain resolution. Configuration encrypted with **AES-256-CBC**. Binary located at `/usr/bin/iocontrol`. Commands: "hello" (sysinfo), "check exec," "execute command," "self-delete," "port scan." Initially achieved **0/66 VirusTotal detections**.

**PLC_Controller.exe** (July 2025): A compiled Python tool that sends **S7comm and COTP requests** to force Siemens S7-300/S7-400 PLCs into STOP mode. This represents a direct ICS disruption capability.

### UNC1549/Nimbus Manticore (IRGC-linked)

**TWOSTROKE** (November 2025): C++ backdoor signed with legitimate compromised code-signing certificates. Supports DLL loading, file manipulation, persistence. **DEEPROOT**: Cross-platform Go-based backdoor (Linux/Windows) with shell commands and file transfers. Both use **Azure tenant accounts for C2** and **SSH reverse tunnels**. Additional tools: CRASHPAD (credential harvesting), DCSYNCER.SLICK (DCSync attacks), SIGHTGRAB (screenshots), TRUSTTRAP (fake login prompts), GHOSTLINE and POLLBLEND (tunnelers). MITRE: T1574.001, T1572, T1003.006.

### Infy/Prince of Persia

**Foudre v34** and **Tonnerre v50** (September 2025): Foudre uses a two-step **DGA** generating 10-12 character domains on `.site` and `.ix.tc` TLDs, with RSA signature verification at `/key/<domain><yy><day_of_year>.sig`. C2 beacon path: `/1/?c=<GUID>`. Tonnerre v50 generates **13-character domains on `.privatedns.org`** and uses **Telegram bot `@ttestro1bot`** for C2. C2 servers: **45.80.148.195** and **45.80.148.124**. MITRE: T1568.002, T1102.002.

### RedKitten (Iranian state-aligned)

**SloppyMIO** (January 2026): Targets human rights NGOs. Uses a **three-stage C2 chain**: GitHub dead-drop resolver → steganographic config images on Google Drive → Telegram Bot API for commands and exfiltration. Beacons every 2 hours via scheduled task. Shows signs of **AI-generated VBA macro code**. MITRE: T1102.001, T1027.003.

### Other notable new malware

- **Pay2Key.I2P** (February 2025, evolved): Ransomware-as-a-service hosted entirely on the **I2P anonymous network** — the first full RaaS on I2P. Linked to Fox Kitten. Uses Mimic ransomware variant with Themida protection. Offers **80% profit share** for attacks against "enemies of Iran."
- **Sicarii RaaS** (December 2025): Deliberately **discards encryption keys** after encrypting, making recovery permanently impossible. Destructive by design.
- **WhiteLock** (2025): Cotton Sandstorm ransomware deployed against Israeli targets with potential for expansion.
- **SilkySand** (July 2025): Deployed by Pulsar Kitten via ONLYOFFICE against German transportation sector with aviation-themed lures.
- **MuddyViper** and **Fooder** (mid-2025): MuddyViper is a C/C++ backdoor; Fooder is its loader disguised as a Snake video game. Uses CNG API encryption and SSH reverse tunnels.
- **WezRat** (ongoing): Cotton Sandstorm modular infostealer with command execution, screenshots, keylogging, clipboard and cookie theft.

---

## Suricata detection signatures for Iranian C2 protocols

The following conceptual Suricata rules target the most distinctive network behaviors observed across Iranian malware families. Each rule targets a specific, observable protocol artifact.

**UDPGangster C2 (MuddyWater):**
```
alert udp $HOME_NET any -> $EXTERNAL_NET 1269 (msg:"ET MALWARE MuddyWater UDPGangster C2 Beacon"; dsize:>50; sid:2900001; rev:1;)
alert udp $HOME_NET any -> 157.20.182.75 1269 (msg:"ET MALWARE UDPGangster Known C2 IP"; sid:2900002; rev:1;)
```

**IOCONTROL MQTT C2 (CyberAv3ngers):**
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 8883 (msg:"ET MALWARE IOCONTROL MQTT-TLS C2"; flow:established,to_server; content:"|10|"; offset:0; depth:1; sid:2900003; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 1883 (msg:"ET MALWARE IOCONTROL MQTT Cleartext C2"; flow:established,to_server; content:"MQTT"; depth:8; sid:2900004; rev:1;)
```

**IOCONTROL DNS-over-HTTPS evasion:**
```
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"ET MALWARE IOCONTROL DoH via Cloudflare from OT Segment"; tls.sni; content:"cloudflare-dns.com"; sid:2900005; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE DoH Query Pattern"; content:"dns-query"; http_uri; content:"application/dns-message"; http_content_type; sid:2900006; rev:1;)
```

**Foudre v34 DGA beacon and RSA validation (Infy APT):**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Foudre C2 GUID Beacon"; flow:established,to_server; content:"GET"; http_method; content:"/1/?c="; http_uri; pcre:"/\/1\/\?c=[0-9a-f\-]{36}/Ui"; sid:2900007; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Foudre RSA Sig Verification"; flow:established,to_server; content:"/key/"; http_uri; content:".sig"; http_uri; sid:2900008; rev:1;)
```

**Tonnerre v50 DGA domain pattern:**
```
alert dns $HOME_NET any -> any any (msg:"ET MALWARE Tonnerre DGA Domain"; dns.query; content:".privatedns.org"; endswith; pcre:"/^[a-z0-9]{13}\.privatedns\.org$/"; sid:2900009; rev:1;)
```

**BellaCiao/BellaCpp DNS beaconing (Charming Kitten):**
```
alert dns $HOME_NET any -> any any (msg:"ET MALWARE BellaCiao DNS C2 Beacon"; dns.query; content:".systemupdate.info"; endswith; pcre:"/^[a-z]{5}[a-z0-9]+\.[a-z]{2}\.systemupdate\.info$/"; sid:2900010; rev:1;)
```

**Telegram Bot API C2 (multiple Iranian families):**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Telegram Bot API C2 Communication"; flow:established,to_server; content:"api.telegram.org"; http_host; content:"/bot"; http_uri; sid:2900011; rev:1;)
```

**MuddyWater Phoenix SimpleHTTP server fingerprint:**
```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE MuddyWater SimpleHTTP C2 Server"; flow:established,from_server; content:"SimpleHTTP/0.6 Python/3.10"; http_server_body; sid:2900012; rev:1;)
```

**Backblaze B2 staging (MuddyWater Fakeset):**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE MuddyWater Backblaze B2 Staging"; flow:established,to_server; content:".s3.us-east-005.backblazeb2.com"; http_host; sid:2900013; rev:1;)
```

**Wasabi cloud exfiltration (MuddyWater Dindoor):**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Rclone Wasabi Cloud Exfil"; flow:established,to_server; content:".wasabisys.com"; http_host; sid:2900014; rev:1;)
```

**Sliver C2 framework (MuddyWater infrastructure):**
```
alert tcp $HOME_NET any -> 157.20.182.49 31337 (msg:"ET MALWARE MuddyWater Sliver C2 Known Port"; flow:established; sid:2900015; rev:1;)
```

**S7comm PLC STOP command (CyberAv3ngers PLC_Controller):**
```
alert tcp $HOME_NET any -> $HOME_NET 102 (msg:"ET ICS Suspicious S7comm CPU STOP Request"; flow:established,to_server; content:"|03 00|"; depth:2; content:"|29|"; offset:17; depth:1; sid:2900016; rev:1;)
```

---

## MITRE ATT&CK techniques newly observed in Iranian operations

The following techniques represent new or notably expanded adoption by Iranian APTs during this period, beyond their traditional playbook:

**Novel technique adoption:**

| MITRE ID | Technique | Actor | Context |
|----------|-----------|-------|---------|
| T1102.001 | Dead Drop Resolver | RedKitten (SloppyMIO) | GitHub → Google Drive → Telegram three-stage C2 chain |
| T1102.002 | Bidirectional Communication via Web Service | Infy, MuddyWater | Telegram Bot API as full interactive C2 |
| T1027.003 | Steganography | RedKitten | Config embedded in images on Google Drive |
| T1568.002 | Domain Generation Algorithms | Infy (Foudre v34/Tonnerre v50) | Two distinct DGA families with RSA validation |
| T1574.001 | DLL Search Order Hijacking | UNC1549 (DCSYNCER.SLICK) | DCSync via DLL hijack |
| T1621 | MFA Request Generation | Multiple Iranian groups | MFA push bombing for initial access |
| T1567.002 | Exfiltration to Cloud Storage | MuddyWater | Rclone to Wasabi and Backblaze |
| T1095 | Non-Application Layer Protocol | MuddyWater (UDPGangster) | Custom UDP C2 on port 1269 |
| T1573.001 | Symmetric Cryptography | MuddyWater (ArenaC2) | AES-256-CBC encrypted HTTP C2 |
| T1071.005 | MQTT Protocol | CyberAv3ngers (IOCONTROL) | IoT/OT C2 via MQTT on 8883 |
| T1583.006 | Web Services | Cotton Sandstorm | Fictitious hosting resellers for infrastructure |
| T1588.003 | Code Signing Certificates | MuddyWater, UNC1549 | "Amy Cherne" and "Donald Gay" certs; compromised legitimate certs |

**Highest-frequency techniques across all groups (March 2026 telemetry per Nozomi Networks):** T1110 (Default Credential Abuse), T1078 (Valid Accounts), T1110.001/003 (Brute Force/Password Spraying), T1595 (Active Scanning), T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell), T1059 (Command and Scripting Interpreter).

---

## Government advisories and the escalation timeline

The **primary new advisory** during this period is the June 30, 2025 Joint Fact Sheet — "Iranian Cyber Actors May Target Vulnerable US Networks and Entities of Interest" — co-authored by CISA, FBI, DC3, and NSA. It was updated on December 3, 2025, and again on **January 14, 2026**. This document serves as the umbrella warning, citing elevated risk to Defense Industrial Base companies with Israeli relationships, OT/ICS systems, and all internet-exposed infrastructure using default credentials.

On **March 3, 2026**, the FBI issued an urgent reminder to critical infrastructure organizations to implement mitigations from the June 2025 fact sheet, following Operation Epic Fury. The advisory specifically warned about Iranian targeting of hospital HVAC, water systems, life-safety, and building automation systems.

Key earlier advisories remain highly relevant and were updated during this period: **AA23-335A** (CyberAv3ngers/Unitronics PLC exploitation, updated December 18, 2024 with IOCONTROL malware details), **AA24-241A** (Pioneer Kitten ransomware affiliations), and **AA24-290A** (Five Eyes joint advisory on Iranian brute force and credential access). CISA added **CVE-2025-59718** (Fortinet SAML bypass) and **CVE-2026-1281** (Ivanti EPMM) to the Known Exploited Vulnerabilities catalog with urgent remediation deadlines.

A critical caveat: CISA was reportedly operating at approximately **38% staffing** due to a DHS funding standoff as of March 2026, potentially affecting advisory production.

---

## Critical infrastructure under active threat from pre-positioned access

Three Dragos-tracked OT threat groups present the most urgent ICS risk. **BAUXITE** (CyberAv3ngers) achieved **Stage 2 ICS Kill Chain** capability — meaning demonstrated ability to directly compromise and manipulate industrial control systems. In June 2025, BAUXITE deployed **two custom wiper malware variants** against Israeli industrial targets, marking their first confirmed destructive operations. In July 2025, Dragos identified **PLC_Controller.exe**, capable of sending S7comm/COTP requests to force Siemens S7-300/S7-400 PLCs into STOP mode.

**PYROXENE** is a newly identified Dragos threat group (2025) with IRGC-CEC alignment. It deployed wiper malware against Israeli targets in June 2025, conducts multi-year supply chain campaigns via fake LinkedIn recruiter profiles targeting OT personnel, and uses **Azure tenant C2** infrastructure. PYROXENE receives initial access from PARISITE (Pioneer Kitten) before attempting IT-to-OT lateral movement.

MuddyWater's confirmed U.S. victims as of March 2026 include a **U.S. bank**, a **U.S. airport**, and a **Canadian non-profit**, using the Dindoor and Fakeset backdoors. The group was pre-positioned on these networks since early February 2026 — weeks before the February 28 strikes — suggesting intelligence-driven prepositioning for potential destructive operations.

For ICS/OT network monitoring, the most critical detection points are:

- **TCP port 20256**: Default Unitronics PLC communication exploited by CyberAv3ngers
- **MQTT ports 8883/1883**: IOCONTROL malware C2 from OT segments
- **S7comm/COTP on TCP 102**: PLC_Controller.exe targeting Siemens PLCs
- **DNS-over-HTTPS from embedded devices**: IOCONTROL evasion technique
- **Unauthorized RMM tools** (AnyDesk, MeshCentral, SimpleHelp) on OT-adjacent workstations

---

## Iranian ransomware operations have evolved dramatically

Pioneer Kitten/Fox Kitten continues as an **initial access broker** for ransomware gangs, collaborating with ALPHV/BlackCat, NoEscape, and RansomHouse. The group provides full domain control privileges without disclosing their Iranian origin to partners — FBI assesses this ransomware activity is likely conducted for personal profit rather than state direction.

The most significant new development is **Pay2Key.I2P**, which reemerged in February 2025 after a four-year hiatus. Linked to Fox Kitten and incorporating Mimic ransomware (ELENOR-Corp variant), it is the **first full ransomware-as-a-service platform hosted entirely on the I2P anonymous network** rather than Tor. The attack chain uses 7-Zip SFX archives → dual-format CMD/PowerShell loaders → XOR-encrypted payloads → Themida-protected Mimic ransomware. By June 2025, the operation claimed **$4M+ in ransom from 51+ attacks** and released a Linux-compatible build. It offers **80% profit share** for attacks against "enemies of Iran" and operates through a full affiliate dashboard with ransomware builders and victim communication tools. Detection: monitor for I2P network traffic patterns (UDP port 9000+) and PowerShell creating `.exe` file-type exclusions in Microsoft Defender.

---

## Cloud services and legitimate platforms weaponized for C2

Iranian actors have dramatically expanded their abuse of legitimate cloud services for command and control, creating significant challenges for network-based detection:

- **Telegram Bot API**: Used by at least four malware families — CHAR (Operation Olalampo), Tonnerre v50, SloppyMIO, and Handala Hack operations. Traffic pattern: HTTPS to `api.telegram.org/bot<TOKEN>/` endpoints including `sendMessage` and `getUpdates`. Detection requires identifying Telegram API traffic from non-browser processes.
- **Wasabi and Backblaze cloud storage**: MuddyWater uses Rclone for exfiltration to Wasabi (`*.wasabisys.com`) and stages malware on Backblaze B2 (`*.backblazeb2.com`). Both are less commonly monitored than AWS/Azure.
- **Azure tenant accounts**: UNC1549 routes C2 through compromised Azure tenants to blend with legitimate cloud traffic. MINIBIKE/MINIBUS backdoors specifically use Azure infrastructure.
- **GitHub and Google Drive**: SloppyMIO uses GitHub as a dead-drop resolver to retrieve Google Drive URLs, which host steganographically encoded configuration data.
- **Cloudflare fronting**: Dark Scepter (APT34-linked), Nimbus Manticore, and MuddyWater's Phoenix v4 all use Cloudflare to proxy C2 and obscure origin infrastructure. Nimbus Manticore specifically blends Cloudflare with Azure App Service for resilience.
- **Ethereum blockchain**: MuddyWater has adopted **EtherHiding** — embedding C2 addresses in smart contracts, making them resistant to takedown since blockchain data is immutable. Detection: monitor for Ethereum RPC calls from enterprise endpoints.
- **OneDrive/Dropbox**: APT42/Charming Kitten exfiltrates to OneDrive accounts masquerading as victim organizations. Crafty Camel uses both OneDrive and Dropbox for payload relay.

---

## TLS certificate and infrastructure patterns enable tracking

Iranian operations exhibit consistent infrastructure preferences that enable proactive hunting. **NameCheap** is the preferred domain registrar across multiple groups. MuddyWater infrastructure consistently uses **Cloudflare DNS** and favors hosting on **AS136557 (Hosterdaddy Private Limited)**. Operational activity concentrates in **Tehran business hours (UTC+3:30)**.

Two code-signing certificate identities provide high-confidence attribution pivots: "**Amy Cherne**" (used to sign both Dindoor and Fakeset) and "**Donald Gay**" (Fakeset, Stagecomp, Darkcomp). UNC1549 obtains and abuses **legitimate code-signing certificates** from software vendors, then deploys them across TWOSTROKE, GHOSTLINE, and POLLBLEND variants before they can be revoked.

For IP camera exploitation supporting battlefield intelligence, Iranian actors use commercial VPN exit nodes — specifically **Mullvad, ProtonVPN, Surfshark, and NordVPN** — to scan for vulnerable Hikvision and Dahua cameras.

---

## Conclusion

This is the most dangerous period for Iranian cyber threats since the inception of their offensive program. Three developments stand out as novel and strategically significant. First, **MuddyWater's pre-positioning on U.S. critical infrastructure networks** weeks before kinetic operations suggests deliberate advance preparation for potential destructive retaliation — a threshold Iranian actors have not previously crossed against U.S. targets. Second, the adoption of **MQTT-based C2 for OT malware** (IOCONTROL) and **S7comm-capable PLC attack tools** represents a concrete advancement in ICS disruption capability that most traditional IDS deployments are not configured to detect. Third, the shift toward **Telegram, Ethereum blockchain, and obscure cloud storage services** (Wasabi, Backblaze) for C2 channels indicates a deliberate strategy to evade organizations monitoring only traditional HTTP/HTTPS C2 patterns.

For Suricata deployment priorities, the highest-value signatures target: UDP port 1269 (UDPGangster), MQTT on ports 8883/1883 from non-IoT segments (IOCONTROL), Telegram Bot API from non-browser processes, DNS patterns matching `.systemupdate.info` (BellaCiao) and `.privatedns.org` (Tonnerre DGA), S7comm anomalies on TCP 102 (PLC_Controller), and cloud storage exfiltration to Wasabi/Backblaze endpoints. The existing community resource at `barkandbite/iranian-apt-detection` on GitHub contains **130+ Suricata signatures** covering 15+ CVEs and 40+ behavioral patterns and should be incorporated as a baseline. Iran's internet connectivity remains at 1–4% following the February 28 strikes, potentially degrading central coordination — but pre-positioned access, external proxy groups, and the newly formed **Electronic Operations Room** (coordinating 60+ hacktivist groups) ensure the threat remains acute and likely to intensify.