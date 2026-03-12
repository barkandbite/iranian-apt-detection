# Iranian APT Threat Intelligence Briefing - Reverse Enumeration Prompt
# Date: March 12, 2026
# Classification: DEFENSIVE USE ONLY
# Purpose: Provide to another Claude instance for building detection rules in a different repo

---

## PROMPT START

You are a cybersecurity threat intelligence analyst specializing in Iranian Advanced Persistent Threat (APT) groups. You have been provided with a comprehensive reverse enumeration of Iranian cyber capabilities derived from analyzing what US, Israeli, and private-sector defenders are actively monitoring and detecting as of March 12, 2026.

**Your task**: Use this intelligence to build detection rules, SIEM correlations, YARA signatures, or other defensive tooling for whichever platform the user specifies. Everything below represents confirmed, actively-exploited capabilities.

---

## PART 1: THREAT ACTOR INVENTORY AND ORGANIZATIONAL STRUCTURE

### State-Sponsored Groups (MOIS - Ministry of Intelligence and Security)

**MuddyWater / Seedworm / Mango Sandstorm / Static Kitten**
- Most active Iranian APT as of March 2026
- MOIS-affiliated; confirmed on networks of US bank, US airport, Canadian non-profit
- Operates 7+ custom C2 frameworks simultaneously
- Known for "living off the land" + rapid tool rotation
- Source: Ctrl-Alt-Intel "MuddyWater Exposed" (Mar 2026), Broadcom/Symantec Seedworm report (Mar 6, 2026)

**CyberAv3ngers / BAUXITE (Dragos designation)**
- IRGC-CEC (Cyber-Electronic Command) affiliated
- ICS/OT specialist - confirmed Stage 2 ICS Kill Chain capability
- 400+ compromised devices globally (PLCs, HMIs, routers, cameras)
- Focus: water/wastewater, energy, grain storage, building automation
- Source: CISA AA23-335A (updated Dec 2024), Dragos 2026 OT Year in Review

**Handala / Void Manticore**
- MOIS-operated, using hacktivist persona as cover
- Destructive operations specialist (wipers, data destruction)
- Executed the Stryker Corporation MDM wiper attack (March 11, 2026)
- Wiped 200,000+ devices across 79 countries via Microsoft Intune abuse
- Source: Check Point Research, Krebs on Security (Mar 12, 2026), BleepingComputer

**APT42 / Charming Kitten / RedKitten / Mint Sandstorm**
- IRGC-IO (Intelligence Organization) affiliated
- Credential theft specialist; targets journalists, activists, NGOs
- Known for AI-generated phishing infrastructure
- Multi-stage C2: GitHub dead-drop -> Google Drive steganography -> Telegram Bot API
- Source: Mandiant, Unit 42 (Mar 1, 2026)

**OilRig / APT34 / Helix Kitten**
- MOIS-affiliated
- DNS specialist - uses high-entropy DGA for C2
- Known for structured subdomain DNS queries
- Source: SOCRadar 2026

**Infy / Prince of Persia**
- Resurfaced September 2025 after years of silence
- Runs Foudre v34 and Tonnerre v50 with custom DGAs
- Known C2 IPs: 45.80.148.195, 45.80.148.124
- Source: Check Point Research (Sep 2025)

**UNC1549 / Nimbus Manticore**
- Aerospace and defense targeting via third-party access
- Uses TWOSTROKE (C++), DEEPROOT (Go cross-platform), DCSYNCER.SLICK
- Azure tenant accounts for C2; SSH reverse tunnels
- Source: Mandiant (Nov 2025)

**Pioneer Kitten / Fox Kitten / Lemon Sandstorm / Rubidium**
- Ransomware access broker
- Operates Pay2Key.I2P (first full RaaS on I2P network)
- 80% profit share for attacks on "enemies of Iran"; $4M+ from 51+ attacks
- Source: CISA AA24-241A

**Cotton Sandstorm**
- Operates WezRat modular infostealer
- Source: Microsoft Threat Intelligence

**Crafty Camel**
- Targets GCC aviation/critical infrastructure
- Compromises third-party email accounts for spearphishing
- Uses polyglot files (PDF/HTA) via OneDrive/Dropbox
- Source: Trellix 2026

### State-Sponsored Groups (IRGC)

**GreenCharlie / APT35**
- IRGC-affiliated
- Pioneered GitHub dead-drop resolver technique
- AI-generated phishing domains targeting US elections
- Source: Unit 42, Google TAG

### Hacktivist Coalition (Post-Operation Epic Fury, Feb 28, 2026)

60+ groups coordinated under "Electronic Operations Room":
- DieNet, Dark Storm Team, SylhetGang, FAD Team
- Cyber Islamic Resistance, Holy League
- Focus: DDoS (UDP flood, HTTP flood, SYN flood), defacement, data leaks
- Source: SOCRadar, CloudSEK (Mar 1, 2026)

---

## PART 2: MALWARE FAMILIES AND CAPABILITIES

### Custom Backdoors

| Malware | Language | C2 Channel | Key Behaviors | Attribution |
|---------|----------|------------|---------------|-------------|
| UDPGangster | Custom | UDP port 1269, ROR-encoded | Heartbeat (0x04), cmd.exe (0x0A), file exfil (0x14), payload deploy (0x1E), C2 update (0x63) | MuddyWater |
| Dindoor | Deno/JS | HTTP + Rclone to Wasabi | "Bring Your Own Runtime" evasion; signed by "Amy Cherne" cert | MuddyWater |
| Fakeset | Python | HTTP via Backblaze B2 | Staged from gitempire.s3.us-east-005.backblazeb2.com, elvenforest.s3.us-east-005.backblazeb2.com; signed "Amy Cherne" and "Donald Gay" | MuddyWater |
| CHAR | Rust | Telegram Bot API | Bot name "Olalampo", username "stager_51_bot"; AI-assisted development (emoji debug strings) | MuddyWater |
| GhostFetch | Unknown | HTTP to codefusiontech[.]org | Drops to C:\Users\Public\Documents\MicrosoftExcelUser.exe; anti-VM mouse movement check | MuddyWater |
| GhostBackDoor | Unknown | HTTP | Part of Operation Olalampo toolkit | MuddyWater |
| HTTP_VIP | Unknown | HTTP | URI patterns: /postifo (registration), /connect (C2 retrieval); connects to codefusiontech[.]org | MuddyWater |
| BugSleep / StealthCache | Unknown | HTTP POST | Base64-encoded system info; structured sleep intervals; x-www-form-urlencoded | MuddyWater |
| TameCat | PowerShell | HTTP | Memory-resident; -EncodedCommand in URI; unusual execution paths | MuddyWater |
| PowerLess | PowerShell | HTTP POST JSON | Versions 3.3.0-3.3.4; PowerShell user-agent; application/json | APT35 |
| Stagecomp | Unknown | HTTP | Downloads Darkcomp backdoor; linked via certificate reuse | MuddyWater |
| Darkcomp | Unknown | HTTP | Follow-on backdoor deployed by Stagecomp | MuddyWater |
| Sosano | Go | HTTP POST | Go-http-client default user-agent; periodic beacon | Iranian APT |
| GhostForm | .NET | WebSocket | Invisible Windows forms; WebSocket-driven dynamic flow control | Iranian APT |
| BladedFeline | Unknown | Email (compromised Exchange) | 8+ year persistence; SMTP-based C2 with Base64 payloads | BladedFeline |
| UNC1860 Passive Implant | Unknown | Inbound TLS | NO outbound C2 - waits for inbound connections; passive backdoor | UNC1860 |
| TWOSTROKE | C++ | Azure tenants | Compromised code-signing certificates | UNC1549 |
| DEEPROOT | Go | Azure tenants + SSH | Cross-platform (Linux/Windows) | UNC1549 |
| DCSYNCER.SLICK | Unknown | DRSUAPI | DCSync credential theft tool | UNC1549 |
| SloppyMIO | Unknown | GitHub -> Google Drive -> Telegram | Three-stage: dead-drop -> steganographic config -> Bot API; AI-generated VBA macros; 2-hour beacon interval | RedKitten |
| Foudre v34 | Unknown | HTTP with DGA | Two-step DGA: 10-12 char domains on .site and .ix.tc; RSA sig at /key/<domain><yy><day>.sig; beacon: /1/?c=<GUID> | Infy |
| Tonnerre v50 | Unknown | HTTP DGA + Telegram | 13-char domains on .privatedns.org; bot @ttestro1bot | Infy |
| WezRat | Unknown | HTTPS JSON | Modular: commands, screenshots, keylogging, clipboard, cookie theft | Cotton Sandstorm |
| PersianC2 | Unknown | JSON API | Farsi/Persian strings in protocol | MuddyWater |
| ArenaC2 | Python | HTTP POST via FastAPI/uvicorn | AES-256-CBC encryption; "ArenaReport" decoy; uvicorn server header | MuddyWater |
| Phoenix v4 | Unknown | HTTP | C2: screenai[.]online; SimpleHTTP/0.6 Python/3.10.12 server on 443/8080 | MuddyWater |

### ICS/OT Malware

| Malware | Protocol | Targets | Capabilities |
|---------|----------|---------|-------------|
| IOCONTROL | MQTT over TLS (8883), cleartext (1883) | D-Link, Hikvision, Baicells, Red Lion, Orpak, Phoenix Contact, Teltonika, Unitronics | Commands: "hello" (sysinfo), "check exec", "execute command", "self-delete", "port scan"; AES-256-CBC config; DNS-over-HTTPS via Cloudflare; binary: /usr/bin/iocontrol; initially 0/66 VT detections |
| PLC_Controller.exe | S7comm/COTP (TCP 102) | Siemens S7-300/S7-400 | Forces PLCs into STOP mode; compiled Python; S7comm function code 0x29 |

### Ransomware

| Family | Encryption | Extension | Exfil | Characteristics |
|--------|-----------|-----------|-------|----------------|
| Sicarii | AES-GCM | .sicarii | file.io (POST multipart) | destruct.bat wiper component; creates "WinDefender" service + "SysAdmin" user (Password123!); 120x google.com/generate_204 connectivity checks before encryption; shadow copy deletion; CVE-2025-64446 embedded |
| Pay2Key.I2P | Unknown (Themida-protected Mimic/ELENOR-Corp) | Various | I2P network | First full RaaS on I2P; attack chain: 7-Zip SFX -> dual CMD/PS loaders -> XOR payloads -> Themida-protected binary; creates Defender .exe exclusion |

### Wipers

| Family | Method | Target Selection |
|--------|--------|-----------------|
| Handala MDM Wiper | Microsoft Intune Graph API bulk wipe/retire commands; Workspace ONE MDM API | 200,000+ devices via MDM abuse |
| Anon-g Fox / BibiWiper | Direct disk overwrite (\\.\PhysicalDrive0, MBR) | Geofenced: Israel Standard Time + Hebrew locale |
| MultiLayer | SMB distribution | Mass .exe deployment to multiple hosts |

### Mobile Malware

| Family | Platform | Delivery | Capabilities |
|--------|----------|----------|-------------|
| RedAlert APK | Android | SMS phishing; shirideitch[.]com distribution | Trojanized rocket alert app; C2: api.ra-backup.com/analytics/submit.php |
| DCHSpy | Android | Telegram channels; disguised as VPN apps (Earth VPN, Comodo VPN, Starlink VPN) | SFTP exfiltration; full device surveillance |

---

## PART 3: ACTIVELY EXPLOITED VULNERABILITIES (CVEs)

### Critical (Active Exploitation Confirmed March 2026)

| CVE | Product | CVSS | Exploiting Groups | Technical Detail |
|-----|---------|------|-------------------|------------------|
| CVE-2026-20122 | Cisco SD-WAN Manager (vManage) | High | UAT-8616 | PUT/POST to /dataservice/ with ../ path traversal; arbitrary file overwrite; web shell deployment; software downgrade to re-exploit CVE-2022-20775 |
| CVE-2026-20128 | Cisco SD-WAN DCA | High | UAT-8616 | GET /dataservice/*/dca/*/credential; credential exposure enabling lateral movement |
| CVE-2026-1281 | Ivanti EPMM | 9.8 | MuddyWater | POST /mifs/rs/api/v2/ with bash arithmetic expansion $((; CISA KEV Jan 29, 2026; scanned with Nuclei templates |
| CVE-2025-59718 | FortiOS/FortiProxy | High | Multiple Iranian | POST /api/v2/authentication with SAMLResponse; FortiCloud SSO SAML assertion manipulation |
| CVE-2024-55591 | FortiOS | High | MuddyWater | POST /api/v2/cmdb/system/admin with super_admin; modified watchTowr PoC; creates admin "FortiSetup"; known C2 IP: 194.11.246.101 |
| CVE-2024-23113 | FortiOS fgfmd | High | Multiple | Format string vulnerability in fgfmd daemon on TCP 541; %s/%x format strings |
| CVE-2024-30088 | Windows Kernel | High | Multiple Iranian | Local privilege escalation via NtQueryInformationToken; post-compromise SYSTEM-level lateral movement via SMB/RDP |
| CVE-2025-55182 | React (Next.js SSR) | High | Iranian APT | React2Shell RCE via __NEXT_DATA__ + constructor in POST body |
| CVE-2025-64446 | FortiWeb Manager | 9.1 | Iranian APT | GET /api/v2.0/ with ../ path traversal to admin access; zero-day sold Nov 2025, exploited since Oct 2025 |
| CVE-2025-23006 | SonicWall SMA 1000 | Critical | Multiple Iranian | POST /cgi-bin/ with java.lang.Runtime; pre-auth deserialization; chained with CVE-2025-40602 |

### Ongoing Exploitation (Older CVEs Still Active)

| CVE | Product | Exploiting Groups |
|-----|---------|-------------------|
| CVE-2024-24919 | Check Point Security Gateway | Pioneer Kitten, Lemon Sandstorm |
| CVE-2024-3400 | Palo Alto PAN-OS | Pioneer Kitten |
| CVE-2024-21887 | Ivanti Connect Secure | Multiple Iranian |
| CVE-2023-46805 | Ivanti Connect Secure (chain) | Multiple Iranian |
| CVE-2023-3519 | Citrix NetScaler | Lemon Sandstorm, UNC1860 |
| CVE-2023-36664 | GhostScript (PDF) | Peach Sandstorm |
| CVE-2023-23397 | Outlook NTLM Relay | APT35 |
| CVE-2022-1388 | F5 BIG-IP | Pioneer Kitten |
| CVE-2021-36260 | Hikvision | CyberAv3ngers |
| CVE-2021-33044 | Dahua | CyberAv3ngers |
| CVE-2021-26855 | Exchange ProxyLogon | Lemon Sandstorm, APT35 |
| CVE-2020-1472 | Zerologon | Multiple |

---

## PART 4: NETWORK INDICATORS AND INFRASTRUCTURE

### Known C2 IP Addresses (Active March 2026)

| IP | Attribution | Usage |
|----|-------------|-------|
| 194.11.246.101 | MuddyWater | FortiOS exploitation C2 |
| 157.20.182.75 | MuddyWater | UDPGangster C2 (UDP port 1269) |
| 157.20.182.49 | MuddyWater | Sliver C2 framework (TCP port 31337) |
| 45.80.148.195 | Infy/Prince of Persia | Tonnerre v50 C2 |
| 45.80.148.124 | Infy/Prince of Persia | Tonnerre v50 C2 |

### Known C2 Domains (Active March 2026)

| Domain | Attribution | Usage |
|--------|-------------|-------|
| codefusiontech[.]org | MuddyWater | HTTP_VIP / GhostFetch C2 |
| uppdatefile[.]com | MuddyWater | C2 domain |
| serialmenot[.]com | MuddyWater | C2 domain |
| moonzonet[.]com | MuddyWater | C2 domain |
| screenai[.]online | MuddyWater | Phoenix v4 C2 |
| whatsapp-meeting.duckdns[.]org | RedKitten | Phishing infrastructure |
| ra-backup[.]com | Arid Viper/APT-C-23 | RedAlert APK C2 |
| shirideitch[.]com | Arid Viper/APT-C-23 | RedAlert APK distribution |
| .systemupdate[.]info | Charming Kitten | BellaCiao/BellaCpp DNS beacon |
| gitempire.s3.us-east-005.backblazeb2[.]com | MuddyWater | Fakeset staging |
| elvenforest.s3.us-east-005.backblazeb2[.]com | MuddyWater | Fakeset staging |

### Telegram Bot C2 Channels

| Bot Username | Attribution | Malware |
|-------------|-------------|---------|
| stager_51_bot | MuddyWater | CHAR backdoor |
| ttestro1bot | Infy | Tonnerre v50 |

### DGA Patterns

| Pattern | TLD | Length | Attribution |
|---------|-----|--------|-------------|
| Alphanumeric | .site | 10-14 chars | Infy/Foudre v34 |
| Alphanumeric | .ix.tc | 10-12 chars | Infy/Foudre v34 |
| Alphanumeric | .privatedns.org | 13 chars | Infy/Tonnerre v50 |
| Hex characters (20+ chars) | Various | 20+ chars | OilRig high-entropy DNS |

### DNS Patterns

- **DNS tunneling**: Hex-encoded subdomain queries (32+ hex chars) with high query rate (20+ per 5 min)
- **Base64 DNS exfil**: Base64-encoded subdomain queries (40+ chars) (APT35 TTP)
- **DGA on .site TLD**: 10-14 random alphanumeric character domains
- **DGA on .ix.tc**: Uncommon TLD, high signal
- **High-entropy subdomains**: 20+ alphanumeric chars, consistent with OilRig
- **Dynamic DNS abuse**: Heavy use of .duckdns.org
- **DNS-over-HTTPS**: Via Cloudflare (cloudflare-dns.com) and Google (dns.google) to evade DNS inspection

### Infrastructure Patterns

- **TLD abuse**: .online, .site, .ix.tc, .tk, .ml, .ga, .cf consistently used
- **European VPS**: Hosting preference for European providers
- **Self-signed certificates**: Consistently used on C2 infrastructure (no DigiCert, Let's Encrypt, Sectigo, GeoTrust)
- **SimpleHTTP Python server**: Server header "SimpleHTTP/0.6 Python/3.10.12" exposed on multiple C2s
- **FastAPI/uvicorn**: ArenaC2 uses uvicorn server header (uncommon in enterprise)
- **Polyglot files**: PDF/HTA and PDF/ZIP combinations
- **Double extensions**: .doc.exe, .pdf.exe, .xlsx.scr, .pdf.hta

---

## PART 5: ATTACK TECHNIQUES AND PROCEDURES (MITRE ATT&CK MAPPED)

### Initial Access (TA0001)

| Technique | Detail | Groups |
|-----------|--------|--------|
| T1190 | Exploit public-facing apps (Fortinet, Ivanti, Cisco, Citrix, PAN-OS, SonicWall, F5, Exchange) | All groups |
| T1566.001 | Spearphishing with macro-laced Office docs; AI-generated VBA | MuddyWater, APT42 |
| T1566.002 | SMS phishing with APK links; shortened URLs (bit.ly) | Arid Viper |
| T1078 | Default credentials ("1111" on Unitronics PLCs) | CyberAv3ngers |
| T1078.001 | Default accounts on IoT/OT devices | CyberAv3ngers |
| T1133 | VPN credential compromise + FortiOS VPN group manipulation | MuddyWater |

### Execution (TA0002)

| Technique | Detail |
|-----------|--------|
| T1059.001 | PowerShell download cradles; -EncodedCommand; memory-resident backdoors |
| T1059.003 | CMD: destruct.bat (Sicarii), net stop surge (pre-wiper) |
| T1059.005 | VBA macros in Office documents (Operation Olalampo) |
| T1059.006 | Python-based backdoors (Fakeset, PLC_Controller.exe) |
| T1059.007 | JavaScript/Deno runtime ("Bring Your Own Runtime" evasion) |
| T1218 | Signed binary proxy execution via Deno (legitimate developer tool) |

### Persistence (TA0003)

| Technique | Detail |
|-----------|--------|
| T1505.003 | Web shells on Exchange (TWOFACE, GLASSTOKEN), Fortinet, Cisco SD-WAN, PAN-OS |
| T1219 | RMM tools: AnyDesk, MeshCentral, SimpleHelp, Syncro, NetBird, Atera, ScreenConnect, PDQ Deploy, ZeroTier |
| T1136.001 | Local account creation: "FortiSetup" (super_admin), "SysAdmin" (Password123!) |

### Privilege Escalation (TA0004)

| Technique | Detail |
|-----------|--------|
| T1068 | CVE-2024-30088 Windows kernel privilege escalation |
| T1078 | Compromised VPN credentials with MFA push bombing |

### Defense Evasion (TA0005)

| Technique | Detail |
|-----------|--------|
| T1562.001 | AMSI bypass (AmsiScanBuffer patching), ETW bypass (EtwEventWrite patching) |
| T1027.002 | Themida packing (Pay2Key ransomware), UPX modifications |
| T1027.003 | Steganography in Google Drive images (SloppyMIO) |
| T1027.009 | Embedded payloads in polyglot files |
| T1573.001 | AES-256-CBC encryption (ArenaC2, IOCONTROL config) |
| T1573.002 | TLS encrypted C2; self-signed certificates |
| T1001.003 | Protocol impersonation: SSH over port 443 |

### Credential Access (TA0006)

| Technique | Detail |
|-----------|--------|
| T1558.003 | Kerberoasting: TGS-REQ with RC4 (etype 23) - 10+ requests in 60 seconds |
| T1003.001 | LSASS memory dump (Mimikatz) - lsass.dmp transfer via SMB |
| T1003.006 | DCSync via DRSUAPI (DCSYNCER.SLICK tool); detectable via RPC UUID e3514235-4b06-11d1-ab04-00c04fc2dcd2 |
| T1110.003 | Password spraying: 30+ LDAP bind failures in 60 seconds |
| T1621 | MFA push bombing |
| Browser theft | HackBrowserData, LaZagne; Chrome cookie database exfiltration |

### Lateral Movement (TA0008)

| Technique | Detail |
|-----------|--------|
| T1021 | SMB lateral movement: 10+ connections in 2-hour window (characteristic timing) |
| T1021 | RDP surge: 5+ RDP connections in 2-hour window |
| Cobalt Strike | Named pipe names: postex_, msagent_, status_, msse-, MSSE- |
| SYSTEM creds | Post-CVE-2024-30088 SYSTEM token in NTLMSSP for lateral SMB/RDP |

### Command and Control (TA0011)

| Technique | Detail |
|-----------|--------|
| T1071.001 | HTTP/HTTPS C2 with structured URI patterns (/postifo, /connect, /1/?c=<GUID>) |
| T1071.004 | DNS C2: tunneling, DGA, high-entropy subdomains |
| T1071.005 | MQTT over TLS (port 8883) / cleartext (port 1883) - IOCONTROL |
| T1090 | SOCKS5 proxy on non-standard ports; FMAPP.dll reverse SOCKS5 |
| T1090.004 | SSH reverse tunnels on high ports (2222-65535); SSH over 443 |
| T1095 | UDP C2 on port 1269 (UDPGangster) |
| T1102 | Telegram Bot API (getUpdates polling for commands, sendDocument for exfil) |
| T1102.001 | GitHub dead-drop resolver (api.github.com/repos/*/contents, raw.githubusercontent.com) |
| T1102.002 | Bidirectional Telegram communication; Ethereum blockchain C2 (eth_call JSON-RPC) |
| T1568.002 | Domain Generation Algorithms (Foudre, Tonnerre, OilRig) |
| T1572 | Ngrok tunneling (<hex>.ngrok.io); ZeroTier; Chisel (TCP 8888, "CHISEL/1.0") |
| Cobalt Strike | HTTP beacon: 4-char alphanumeric URI (checksum8=92/93); DNS beacon: 8-16 hex char subdomains |
| Sliver | TCP port 31337 |

### Exfiltration (TA0010)

| Technique | Detail |
|-----------|--------|
| T1567.002 | Cloud storage: Rclone to Wasabi (.wasabisys.com), Backblaze B2; file.io public sharing |
| T1048 | DNS tunneling with hex-encoded data; SFTP from mobile (DCHSpy) |
| Cloud relay | OneDrive, Google Drive, Discord webhooks (/api/webhooks/), Firebase (.firebaseapp.com), Cloudflare Workers (.workers.dev) |
| Telegram | sendDocument API for file upload exfiltration |

### Impact (TA0040)

| Technique | Detail |
|-----------|--------|
| T1485 | Data destruction via wipers (Handala, Anon-g Fox, BibiWiper, MultiLayer) |
| T1486 | Ransomware encryption (Sicarii AES-GCM, Pay2Key Themida-Mimic) |
| T1489 | Service stopping surge: 10+ "net stop" commands in 2 minutes (pre-wiper) |
| T1490 | Shadow copy deletion (vssadmin Delete Shadows /all); backup catalog deletion (wbadmin delete catalog); boot config tamper (bcdedit recoveryenabled no) |
| T1498/T1499 | DDoS: UDP flood (>1000 byte packets, 500+/10sec), HTTP flood (200+ GET/10sec), SYN flood (500+/10sec) |
| T1561.002 | Disk structure wipe (\\.\PhysicalDrive0, MBR overwrite) |
| T1072 | MDM abuse: Microsoft Intune Graph API (/deviceManagement/managedDevices/*/wipe, /retire); Workspace ONE API (/API/mdm/devices/*/commands DeviceWipe) |

### ICS/OT Specific (MITRE ICS ATT&CK)

| Technique | Protocol | Port | Detail |
|-----------|----------|------|--------|
| T0831 | Modbus | TCP 502 | Function code 0x10 (write multiple registers); function code 0x06 (write single register) |
| T0831 | S7comm/COTP | TCP 102 | COTP header 03 00; S7comm job 32 01 00 00; function code 0x29 (PLC Stop) |
| T0855 | PCOM | TCP 20256 | Unitronics Vision PLCs; default credential "1111" |
| T0855 | DNP3 | TCP 20000 | Header 05 64; unauthorized control commands |
| T0855 | BACnet | UDP 47808 | BACnet header 0x81; write property function 0x0F |
| T0855 | EtherNet/IP CIP | TCP 44818 | RegisterSession header 65 00 |
| T0855 | IEC 60870-5-104 | TCP 2404 | APDU header 0x68; power grid targeting |
| T1557 | NTP | UDP 123 | Time source manipulation; client mode byte 0x1B at high rate (20+/60sec) |
| Camera | RTSP | TCP 554 | Hikvision/Dahua brute-force: DESCRIBE rtsp:// at 20+/60sec |
| Camera | ISAPI | HTTP | PUT /ISAPI/System/configurationFile post-exploitation |

---

## PART 6: ATTACK CHAIN PATTERNS (MULTI-STAGE CORRELATIONS)

These are confirmed attack chains where Stage 1 -> Stage 2 correlation provides high-confidence detection:

1. **FortiOS exploitation -> Wasabi/Backblaze exfiltration**: SAML bypass -> Rclone to cloud storage
2. **FortiOS exploitation -> SOCKS5 tunneling**: Admin creation -> Reverse SOCKS5 proxy
3. **Ivanti EPMM exploit -> Telegram C2**: RCE via $((  -> CHAR backdoor polling
4. **FortiOS admin creation -> IOCONTROL deployment**: FortiSetup account -> MQTT C2 on 8883
5. **SD-WAN exploitation -> credential theft**: API file overwrite -> LSASS dump
6. **SD-WAN exploitation -> RMM deployment**: vManage compromise -> AnyDesk installation
7. **CVE exploitation -> Rclone exfiltration**: Initial access -> Rclone user-agent data theft
8. **MuddyWater C2 contact -> file.io exfiltration**: Domain resolution -> file.io POST
9. **Check Point exploit -> Havoc C2**: Gateway compromise -> Havoc beacon
10. **Macro delivery -> GhostFetch -> HTTP_VIP C2**: Office doc -> MicrosoftExcelUser.exe -> codefusiontech.org

---

## PART 7: DETECTION SIGNATURES AND BEHAVIORAL INDICATORS

### Network-Level Detection Priorities

**CRITICAL (Alert Immediately)**:
- Any traffic to known C2 IPs (194.11.246.101, 157.20.182.75, 157.20.182.49, 45.80.148.195/124)
- MDM bulk wipe/retire API calls (50+ deviceManagement calls/minute)
- MQTT from non-OT segments to external hosts on 8883
- S7comm CPU STOP commands (function code 0x29)
- Modbus write commands from external sources
- LSASS dump file transfers via SMB
- Shadow copy deletion + bcdedit tampering + service stop surge (wiper triad)

**HIGH (Investigate Within 1 Hour)**:
- Telegram Bot API programmatic usage (getUpdates polling, sendDocument)
- Rclone user-agent strings to Wasabi/Backblaze
- SSH on port 443
- Self-signed cert inbound connections
- Cobalt Strike beacon patterns
- Kerberoasting (RC4 TGS-REQ surge)
- DNS-over-HTTPS from OT/ICS networks

**MEDIUM (Review Daily)**:
- RMM tool connections (SimpleHelp, Syncro, NetBird, Atera, ScreenConnect, PDQ, ZeroTier)
- Ngrok tunnel DNS resolution
- Dynamic DNS (.duckdns.org) resolution
- .online TLD resolution patterns
- Double file extension downloads
- Go-http-client user-agent with POST requests
- GitHub API content fetches from non-browser user-agents

### Behavioral Baselines to Monitor

- Normal MDM API call rate vs. anomalous surge
- Normal DNS query entropy vs. DGA patterns
- Normal Modbus/DNP3 traffic sources vs. unauthorized external
- Normal RMM tool usage vs. unauthorized installations
- Normal SSH destinations vs. SSH to high ports or port 443
- Normal cloud storage usage vs. Rclone to Wasabi/Backblaze

---

## PART 8: INTELLIGENCE SOURCES

### US Government

| Source | Reference | Date |
|--------|-----------|------|
| CISA | Joint Fact Sheet: Iranian Cyber Actors May Target Vulnerable US Networks | Jun 30, 2025 (updated Jan 14, 2026) |
| CISA | AA23-335A: IRGC-Affiliated CyberAv3ngers | Updated Dec 18, 2024 |
| CISA | AA24-241A: Iran-based Ransomware Access Brokers | 2024 |
| CISA | AA24-290A: Iranian Brute Force and Credential Access | 2024 |
| CISA KEV | Cisco SD-WAN CVE-2026-20122/20128 | Feb 25, 2026 |
| CISA KEV | Ivanti EPMM CVE-2026-1281 | Jan 29, 2026 |
| FBI | Urgent Reminder: Iranian Cyber Actors | Mar 3, 2026 |
| Cisco Talos | CVE-2026-20122/20128 Exploitation Analysis | Mar 5, 2026 |
| Microsoft | Mango/Peach/Mint/Cotton Sandstorm tracking | Ongoing |
| Mandiant | UNC1549 TWOSTROKE/DEEPROOT | Nov 2025 |
| Dragos | 2026 OT Cybersecurity Year in Review (BAUXITE) | 2026 |
| CrowdStrike | NEMESIS KITTEN, PIONEER KITTEN tracking | Ongoing |

### Israeli / Middle East

| Source | Reference | Date |
|--------|-----------|------|
| Check Point Research | Void Manticore / Handala analysis; Sicarii ransomware | Jan 14, 2026 |
| SOCRadar | Iran-Israel Cyber War Dashboard | Mar 12, 2026 |
| CloudSEK | Middle East Escalation: GPS Spoofing, Prayer App Compromise | Mar 1, 2026 |

### Private Sector

| Source | Reference | Date |
|--------|-----------|------|
| Palo Alto Unit 42 | Threat Brief: March 2026 Escalation; RedAlert APK | Mar 1-2, 2026 |
| Broadcom/Symantec | Seedworm Dindoor/Fakeset/Stagecomp/Darkcomp | Mar 6, 2026 |
| Group-IB | Operation Olalampo (GhostFetch, HTTP_VIP, CHAR) | Feb 23, 2026 |
| Trellix | Iranian Cyber Capability 2026 (comprehensive) | 2026 |
| Ctrl-Alt-Intel | MuddyWater Exposed | Mar 2026 |
| Krebs on Security | Handala Wiper Attack on Stryker Corporation | Mar 12, 2026 |
| BleepingComputer | Stryker MDM Wiper incident report | Mar 12, 2026 |
| Anvilogic | FortiGuard CVE-2024-23113 continued exploitation | 2026 |

---

## PART 9: KEY TAKEAWAYS FOR DETECTION ENGINEERING

1. **MDM is the new attack surface**: Microsoft Intune and Workspace ONE APIs can be weaponized for mass device wipes. Monitor Graph API call rates to /deviceManagement/ endpoints.

2. **"Bring Your Own Runtime"**: MuddyWater deploys Deno runtime to bypass EDR that only monitors Node.js/PowerShell. Monitor for Deno binary downloads and unusual JS runtime execution.

3. **Telegram is a C2 platform**: Multiple malware families use Telegram Bot API. Monitor for programmatic api.telegram.org access (getUpdates polling, sendDocument).

4. **Cloud storage as exfiltration**: Rclone to Wasabi, Backblaze B2, file.io, and legitimate cloud services. Monitor for Rclone user-agent strings and bulk uploads to uncommon storage providers.

5. **ICS/OT protocols are being directly attacked**: Modbus, DNP3, BACnet, EtherNet/IP, IEC 104, S7comm, PCOM. Any external source communicating on these protocols is critical.

6. **The wiper triad**: Shadow copy deletion + backup catalog deletion + boot config tampering = imminent wiper deployment. Detect these three together for highest urgency.

7. **Certificate-based attribution**: MuddyWater reuses certificates across tools. "Amy Cherne" and "Donald Gay" certificates link Dindoor and Fakeset.

8. **DGA diversity**: Each Iranian group uses different DGA patterns. Foudre uses .site/.ix.tc, Tonnerre uses .privatedns.org, OilRig uses high-entropy subdomains.

9. **RMM tool abuse is ubiquitous**: 7+ legitimate RMM tools are routinely deployed. Baseline authorized RMM tools and alert on any others.

10. **Multi-stage correlation is essential**: Single indicators have high false positive rates. Correlating initial access (CVE exploitation) with post-exploitation (C2, exfiltration) provides high-confidence detection.

---

## PART 10: EXPANDED INTELLIGENCE FROM ISRAELI AND US SOURCES

### Stryker Corporation Attack - Deep Technical Detail (March 11, 2026)

**Attack Chain Specifics:**
1. Initial access via compromised administrator credentials - likely credential theft or brute-force against VPN using commercial VPN nodes with hostnames in `DESKTOP-XXXXXX` / `WIN-XXXXXX` format (hundreds of logon attempts observed)
2. Escalated to Intune Global Administrator
3. Issued Microsoft Intune remote wipe commands to ALL enrolled devices simultaneously
4. No traditional malware deployed for the MDM wipe phase - pure living-off-the-land
5. Lifenet EKG transmission systems went non-functional across Maryland
6. Ireland operations (5,500 employees) sent home

**Handala's Traditional Wiper Technical Details (from prior Israeli campaigns):**
- **handala.exe**: Delphi-coded second-stage loader / AutoIt injector
- **Hatef.exe**: Windows wiper, overwrites files in 4096-byte chunks with random data via `OverwriteFileBlockSize4096` function, then deletes; targets MBR/MFT
- **Hamsa**: Linux wiper variant
- **Singleton check**: Checks if machine name equals `Gaza hackers Team Handala Machine` (dev machine exclusion)
- **C2**: Telegram channel for status updates (pre-wipe/post-wipe per drive category)
- **Distribution**: Group Policy logon scripts via `handala.bat`; executable launched remotely from Domain Controller, not written to disk
- **PowerShell wiper**: Enumerates user directories, deletes files, places `handala.gif` propaganda image on all logical drives; likely AI-assisted development
- **Additional tool**: NetBird for tunneling traffic into target networks
- **Pairing**: Rhadamanthys commercial infostealer paired with wipers in campaigns impersonating F5 updates

**Known Handala IOCs:**
- SHA256 (second loader): `ca9bf13897af109cb354f2629c10803966eb757ee4b2e468abc04e7681d0d74a`
- MSI installer: `6eb7dbf27a25639c7f11c05fd88ea2a301e0ca93d3c3bdee1eb5917fc60a56ff` (hosted on Mega)
- Starlink IP ranges used for C2 to bypass Iran's internet blackout

**Leadership Context:** Seyed Yahya Hosseini Panjaki (MOIS Counter-Terrorism Division, supervised Handala/Karma/Homeland Justice personas) was reportedly killed March 2, 2026. The Stryker attack occurred 9 days later - indicating pre-positioned access or autonomous cell operation.

### RedAlert APK - Deep Technical Chain

**Multi-Stage Infection:**
1. **Stage 1**: Outer APK uses Package Manager Hooking via Java reflection to intercept system calls, returning hardcoded certificate impersonating official Home Front Command app's 2014 credential. Forces system to report installation source as Google Play Store.
2. **Stage 2**: Extracts hidden file `umgdn` (no extension) from APK assets directory, loads as Dalvik Executable in memory - evades static scanners.
3. **Stage 3**: Deploys `DebugProbesKt.dex` - primary spyware/banking trojan with overlay phishing capabilities.

**Capabilities:** Real-time GPS tracking (weaponizable for shelter mapping, population movement, IDF reservist location), SMS/contacts/accounts exfiltration, phishing overlay injection (OTP/credential interception), full rocket alert functionality maintained as cover.

**RedAlert IOCs:**
| Indicator | Value |
|-----------|-------|
| Package name | `com.red.alertx` |
| Dropper | `RedAlert.apk` |
| Hidden payload | `umgdn` (assets directory) |
| Final stage | `DebugProbesKt.dex` |
| C2 protection | Cloudflare + AWS routing |

### DCHSpy - New Samples (Post-Feb 28)

- Lookout acquired **four new DCHSpy samples** approximately one week after February 28 strikes
- One sample distributed using **Starlink lures** exploiting reports of Starlink services during Iranian internet outages
- Shares infrastructure with **SandStrike** (Kaspersky 2022) targeting Baha'i Faith practitioners
- Part of broader ecosystem: Lookout has identified **17 mobile malware families** across **10 Iranian APTs**

### Hacktivist Coalition Scale

**First 72 Hours (Feb 28 - Mar 2):**
- **149 DDoS attacks** targeting **110 organizations** across **16 countries**
- Geographic concentration: Kuwait (28%), Israel (27.1%), Jordan (21.5%)
- Sector targeting: Government (48%), Finance (12%), Telecommunications (7%)
- ~70% of DDoS activity attributed to Keymous+ and DieNet

**Pro-Russian Convergence (March 3):**
- Russian Legion and NoName057(16) formally joined pro-Iran coalition
- Shifted from Ukraine-focused to anti-Israel/anti-Western operations

**ICS Claims:**
- Z-Pentest Alliance: Claimed real-time control of Israeli water pump HMI (valves/alarms)
- APT Iran: Claimed month-long intrusion into Jordan grain storage systems

### Iran's Complete Wiper Arsenal (15+ Families)

ZeroCleare, Meteor, Dustman, DEADWOOD, Apostle, Fantasy Wiper, BFG Agonizer, MultiLayer, PartialWasher, BibiWiper, Hatef/Handala Wiper, Hamsa (Linux), SHAPESHIFT/STONEDRILL, No-Justice, Cl Wiper, ROADSWEEP, Sicarii (destructive ransomware - discards keys)

### PowerLess Backdoor Evolution (APT35)

Per Trellix "The Iranian Cyber Capability 2026":
- AMSI bypass: patches `AmsiScanBuffer` at runtime
- ETW bypass: patches `NtTraceControl` to prevent telemetry
- AES-encrypted payloads delivered via malicious LNK files
- **BellaCPP**: C++ reimplementation of BellaCiao .NET implant - webshell-tunneling hybrid ported to harder-to-detect language

### Infrastructure Attribution Patterns

| Pattern | Detail |
|---------|--------|
| Registrar | NameCheap (preferred across multiple groups) |
| DNS provider | Cloudflare (consistently used) |
| Hosting | AS136557 (Hosterdaddy Private Limited) |
| Activity hours | Tehran business hours (UTC+3:30) |
| VPN exit nodes | Mullvad, ProtonVPN, Surfshark, NordVPN (for reconnaissance) |
| Login patterns | Commercial VPN nodes with DESKTOP-XXXXXX / WIN-XXXXXX hostnames |

### INCD / Government Warnings

**Israel National Cyber Directorate (March 9, 2026):**
- Detecting wave of cyberattacks aimed at destroying data and systems across multiple Israeli economic sectors
- Attacks exploit stolen credentials and remote-access vulnerabilities
- Shift from espionage to attempted data destruction
- INCD issued 2,480 alerts in past year - 2.5x increase year-over-year
- Cyber Dome (AI-driven centralized threat detection) reportedly thwarted dozens of attacks

**FBI (March 3, 2026):**
- Specifically warned about Iranian targeting of hospital HVAC, water systems, life-safety, and building automation systems

**CISA:**
- Investigating Stryker attack; operating at approximately 38% staffing due to DHS funding standoff

### Operational Pause Analysis

- Feb 28: Iran connectivity dropped to 1-4% following kinetic strikes
- Operational pause observed Jan 8-27, 2026 (earlier internet blackout) provides circumstantial evidence of direct state coordination
- APT34/OilRig has been operationally silent since Feb 28 - assessed as "covert pre-positioning" rather than disruption
- Pre-positioned access on US/Israeli networks provides capability for destructive pivot regardless of connectivity

---

## PART 11: GRANULAR IOCs FROM UNIT 42 / PALO ALTO RESEARCH

### IOCONTROL Malware - Deep Technical IOCs (Claroty Team82)

| Indicator | Value |
|-----------|-------|
| Binary path | `/usr/bin/iocontrol` |
| Version | 1.0.5, ARM-32 bit Big Endian |
| Persistence | `/etc/rc3.d/S93InitSystemd.sh` (watchdog restarts every 5 sec) |
| PID file | `/var/run/iocontrol.pid` |
| Temp dir | `/tmp/iocontrol/` |
| Packing | Modified UPX (magic "UPX!" changed to "ABC!" to break unpackers) |
| AES key | `22e70a3056aa209e90dc5a354edda2c1c3b88f1e4720dc6a090c4617a919447e` |
| AES IV | `1c3b88f1e4720dc6a090c4617a919447` |
| MQTT broker IP | `159.100.6.69` (Frankfurt) |
| MQTT management | RabbitMQ on port 15672 |
| C2 domain | `uuokhhfsdlk.tylarion867mino.com` |
| Legacy C2 | `ocferda.com` (registered Nov 23, 2023) |
| MQTT topics | `{GUID}/hello`, `{GUID}/push`, `{GUID}/output` |
| MQTT creds | Derived from victim GUID (e.g., GUID `855958ce-6483-4953-8c18-3f9625d88c27` -> user `5958ce`, pass `3-4953-8c18-3f9625`) |
| Command opcodes | 0=device info, 1=check exec, 2=OS commands, 3=self-delete, 8=port scan |
| Sample hash | `1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f33b84498` |

### Operation Olalampo - Full IOC List

**Domains:**
- `codefusiontech[.]org`
- `miniquest[.]org`
- `promoverse[.]org`
- `jerusalemsolutions[.]com`

**IPs:**
- `162.0.230.185`
- `209.74.87.100`
- `143.198.5.41`
- `209.74.87.67`

**File Hashes (SHA-1):**
- `f4e0f4449dc50e33e912403082e093dd8e4bc55d` (AnyDesk)
- `3441306816018d08dd03a97ac306fac0200e9152` (chrome_inject.exe)
- `9ca11fcbd75420bd7a578e8bf6ef855e7bd0fb8e` (ex-server)
- `06f3b55f0d66913cd53d2f0e76a5e2d67ff8ed04` (client.exe)
- `2f5166086da5a57d7e59a767a54ed6fe9a6db444` (lpu.exe)

**SOCKS5 DLL:** `FMAPP.dll` (SHA-1: `62ED16701A14CE26314F2436D9532FE606C15407`)
**Persistence:** Windows service "MicrosoftVersionUpdater"
**Doc metadata usernames:** "DontAsk", "Jacob"

### Stagecomp/Darkcomp Hashes

**Stagecomp:**
- `24857fe82f454719cd18bcbe19b0cfa5387bee1022008b7f5f3a8be9f05e4d14`
- `A92d28f1d32e3a9ab7c3691f8bfca8f7586bb0666adbba47eab3e1a8faf7ecc0`

**Darkcomp:**
- `3df9dcc45d2a3b1f639e40d47eceeafb229f6d9e7f0adcd8f1731af1563ffb90`
- `1319d474d19eb386841732c728acf0c5fe64aa135101c6ceee1bd0369ecf97b6`

### Sosano Backdoor (Go-based, UNK_CraftyCamel/IRGC-linked)

- 12MB Go binary (bloated with unused libraries)
- Delivered via polyglot files (PDF+HTA, PDF+ZIP)
- XOR keys: `1234567890abcdef`, `abcdef1234567890`, `0fedcba987654321`
- Commands: `sosano` (directory ops), `yangom` (dir listing), `monday` (download next stage)
- C2: `bokhoreshonline[.]com` -> `104.238.57[.]61` (CrownCloud hosting)

### APT42 SpearSpecter Campaign IOCs

**C2 domains:**
- `datadrift.somee.com`
- `prism-west-candy.glitch.me`
- `line.completely.workers.dev`
- `meetingapp.site`

**TameCat persistence:**
- Path: `%APPDATA%\Local\Microsoft\InputPersonalization\TrainedDataStore.ps1`
- Registry: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`

### APT42 Credential Harvesting Infrastructure

- 130+ phishing domains registered via NameCheap (2025)
- Custom phishing kits built in React with live keyloggers
- Mimics Gmail, Outlook, Yahoo login pages
- GCollection and DWP kits capable of real-time MFA token capture
- Only FIDO2/passkeys are immune; defeats TOTP/SMS-based MFA

### MuddyWater Malware Evolution Timeline

BugSleep -> StealthCache -> Phoenix -> Fooder -> MuddyViper -> RustyWater -> CHAR -> UDPGangster -> Dindoor -> Fakeset

**C2 framework evolution:** POWERSTATS -> MuddyC3 -> PhonyC2 -> MuddyC2Go -> DarkBeatC2 -> PersianC2 -> ArenaC2 -> Key C2

### Pioneer Kitten / Fox Kitten Additional Details

- Sells domain admin credentials on cybercrime marketplaces using handles "Br0k3r" and "xplfinder"
- Does NOT disclose Iranian origin to ransomware partners
- FBI assesses activity is personal profit, not state-directed
- Operates under cover company **Danesh Novin Sahand**
- During 2023-2025 FortiGuard IR campaign: deployed Havoc, HanifNet, HXLibrary, NeoExpressRAT, MeshCentral, SystemBC
- Activity patterns match Iranian workweek (Sunday-Wednesday) and +03:30 timezone

### Deno BYOR Technical Details

- `deno.exe` delivered via PowerShell if not present
- Executes hidden Base64-encoded commands using `-A` (Allow All) flag
- Payloads fetched in **8KB chunks**, reassembled as Base64 Data URI, executed directly in memory (zero disk artifacts)
- Deno supports HTTP/S imports natively - thin loader pulls real functionality from C2 at runtime
- Cross-platform (Windows/macOS/Linux)
- Deno is rarely in endpoint watchlists, evading signature-based and process-lineage detection

### Dust Specter / GhostForm RAT Technical Details

- .NET RAT using invisible Windows forms with timers for delayed execution
- In-memory PowerShell execution
- Some binaries embed hardcoded Google Forms URLs (Arabic-language Iraqi MoFA impersonation)
- AI-assisted development markers (emojis, 0xABCDEF seed placeholder)
- **TwinTalk C2 protocol:** Randomized 10-hex URI paths with 6-char checksum verification, JWT (weak HS256) in Authorization headers, hardcoded Chrome User-Agent verification, geofencing

### Cobalt Strike Infrastructure Scale (January 2026)

- Hunt.io observed **1,921 unique IPs** hosting Cobalt Strike infrastructure (vs. ~739/month average in 2025)
- Beacon configurations: XOR encoding (0x69 for v3, 0x2e for v4), TLV format
- Iranian actors use Malleable C2 profiles to mimic legitimate traffic
- **CrossC2** framework (2025) extends beacon deployment to Linux/macOS
- AI-driven malleable C2 profile generation is emerging trend

---

## PART 12: ADDITIONAL SOURCED REFERENCES

### Israeli Sources
- [Check Point Research: "Handala Hack" - Unveiling Group's Modus Operandi](https://research.checkpoint.com/2026/handala-hack-unveiling-groups-modus-operandi/)
- [Splunk: Handala's Wiper Threat Analysis and Detections](https://www.splunk.com/en_us/blog/security/handalas-wiper-threat-analysis-and-detections.html)
- [Check Point Research: Iranian MOIS Actors & the Cyber Crime Connection](https://research.checkpoint.com/2026/iranian-mois-actors-the-cyber-crime-connection/)
- [Intezer: Operation HamsaUpdate](https://intezer.com/blog/stealth-wiper-israeli-infrastructure/)
- [Haaretz: How Iranian Hackers Plan to Retaliate (INCD)](https://www.haaretz.com/israel-news/security-aviation/2026-03-09/)
- [Jerusalem Post: Israel releases video countering Iranian cyber warfare](http://www.jpost.com/israel-news/defense-news/article-889462)
- [Lookout: MuddyWater Leveraging DCHSpy](https://www.lookout.com/threat-intelligence/article/lookout-discovers-iranian-dchsy-surveillanceware)

### US Sources
- [Krebs on Security: Iran-Backed Hackers Claim Wiper Attack on Stryker](https://krebsonsecurity.com/2026/03/iran-backed-hackers-claim-wiper-attack-on-medtech-firm-stryker/)
- [BleepingComputer: Medtech giant Stryker offline after Iran-linked wiper malware attack](https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-offline-after-iran-linked-wiper-malware-attack/)
- [The Hacker News: MuddyWater Hackers Target U.S. Networks With Dindoor Backdoor](https://thehackernews.com/2026/03/iran-linked-muddywater-hackers-target.html)
- [The Register: Iran intelligence backdoored US bank, airport networks](https://www.theregister.com/2026/03/05/mudywater_backdoor_us_networks/)
- [SecurityWeek: Iranian APT Targets Android Users With DCHSpy](https://www.securityweek.com/new-variants-of-dchspy-spyware-used-by-iranian-apt-to-target-android-users/)
- [Unit 42: Threat Brief — March 2026 Escalation](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- [SentinelOne: Intelligence Brief — Iranian Cyber Activity Outlook](https://www.sentinelone.com/blog/sentinelone-intelligence-brief-iranian-cyber-activity-outlook/)

### Coalition / International
- [SOCRadar: Iran vs. Israel & US Cyber War 2026](https://socradar.io/blog/cyber-reflections-us-israel-iran-war/)
- [Flashpoint: Escalation in the Middle East — Tracking Operation Epic Fury](https://flashpoint.io/blog/escalation-in-the-middle-east-operation-epic-fury/)
- [Tenable: Cyber Retaliation Analyzing Iranian Cyber Activity](https://www.tenable.com/blog/cyber-retaliation-analyzing-iranian-cyber-activity-following-operation-epic-fury/)
- [CloudSEK: RedAlert Trojan Campaign](https://www.cloudsek.com/blog/redalert-trojan-campaign-fake-emergency-alert-app-spread-via-sms-spoofing-israeli-home-front-command)
- [CloudSEK: ICS/OT Targeting Assessment](https://www.cloudsek.com/blog/a-threat-actor-landscape-assessment-of-ics-ot-targeting-in-the-2026-iran-us-conflict-and-the-scale-of-the-risk)
- [Canadian Centre for Cyber Security: Cyber Threat Bulletin](https://www.cyber.gc.ca/en/guidance/cyber-threat-bulletin-iranian-cyber-threat-response-usisrael-strikes-february-2026)
- [Picus Security: Iranian Threat Actors — What Defenders Need to Know](https://www.picussecurity.com/resource/iranian-threat-actors-what-defenders-need-to-know)
- [Trellix: The Iranian Cyber Capability 2026](https://www.trellix.com/blogs/research/the-iranian-cyber-capability-2026/)
- [Rescana: 149 Hacktivist DDoS Attacks](https://www.rescana.com/post/global-surge-149-hacktivist-ddos-attacks-target-scada-and-critical-infrastructure-across-16-countri)

### Technical Analysis / IOC Sources
- [Claroty Team82: IOCONTROL Analysis](https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol)
- [Group-IB: Operation Olalampo](https://www.group-ib.com/blog/muddywater-operation-olalampo/)
- [SecPro: Operation Olalampo IOCs](https://secpro.substack.com/p/operation-olalampo-indicators-of)
- [Symantec/Security.com: Seedworm US Targets](https://www.security.com/threat-intelligence/iran-cyber-threat-activity-us)
- [Proofpoint: Sosano/CraftyCamel](https://www.proofpoint.com/us/blog/threat-insight/call-it-what-you-want-threat-actor-delivers-highly-targeted-multistage-polyglot)
- [Zscaler ThreatLabz: Dust Specter](https://www.zscaler.com/blogs/security-research/dust-specter-apt-targets-government-officials-iraq)
- [Google Cloud: Untangling APT42](https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations)
- [CISA Advisory AA24-241A: Pioneer Kitten](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a)
- [FortiGuard: Fox Kitten](https://fortiguard.fortinet.com/threat-actor/5570/fox-kitten)
- [HarfangLab: MuddyWater RMM Campaign](https://harfanglab.io/insidethelab/muddywater-rmm-campaign/)
- [Ctrl-Alt-Intel: MuddyWater Exposed](https://ctrlaltintel.com/threat%20research/MuddyWater/)
- [CyberWarrior76: MuddyWater BYOR Analysis](https://cyberwarrior76.substack.com/p/irans-muddywater-just-dropped-two)
- [Rescana: Dindoor Analysis](https://www.rescana.com/post/muddywater-s-dindoor-backdoor-iranian-apt-targets-u-s-organizations-via-deno-runtime-and-cloud-sto)
- [Hunt.io: Cobalt Strike Hunting Guide](https://hunt.io/blog/guide-hunting-cobalt-strike-part-4-c2-feeds-api)
- [Halcyon: Iranian Cybercriminal Tactics 2026](https://www.halcyon.ai/ransomware-alerts/iranian-use-of-cybercriminal-tactics-in-destructive-cyber-attacks-2026-updates)
- [Help Net Security: Cisco SD-WAN Exploitation](https://www.helpnetsecurity.com/2026/03/05/cisco-cve-2026-20128-cve-2026-20122-exploited/)
- [Australian ACSC: SD-WAN Alert](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/exploitation-of-cisco-sd-wan-appliances)

---

## END OF PROMPT

Use this intelligence to build detections appropriate for the target platform. When building rules, prioritize the CRITICAL indicators first, then HIGH, then MEDIUM. Always include MITRE ATT&CK mappings and source references in metadata.
