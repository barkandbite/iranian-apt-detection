# SOC Quick Reference - Iranian APT Detection

## Critical Indicators - Investigate Immediately

### CVE Exploitation Attempts
| Rule ID | CVE | Target | Indicator |
|---------|-----|---------|-----------|
| 100900-100901 | CVE-2024-24919 | Check Point | `/clients/MyCRL` requests |
| 100902-100903 | CVE-2024-3400 | Palo Alto | `/ssl-vpn/hipreport.esp` |
| 100904-100905 | CVE-2019-19781/2023-3519 | Citrix | Path traversal `/../vpns/` |
| 100906-100907 | CVE-2022-1388 | F5 BIG-IP | `X-F5-Auth-Token` headers |
| 100908-100909 | CVE-2024-21887 | Ivanti | `/api/v1/license/key-status/` |
| 100910-100911 | CVE-2020-1472 | Windows | Zerologon null computer account |
| 100915-100917 | CVE-2021-26855 | Exchange | ProxyLogon `/owa/auth/` SSRF |
| 100918-100919 | CVE-2023-23397 | Outlook | NTLM relay via reminder sound |

### Known Malicious Tools
- **Remote Access**: AnyDesk, Ngrok, Ligolo, MeshCentral, plink
- **Backdoors**: Havoc, HanifNet, HXLibrary, NeoExpressRAT, SystemBC, Tickler
- **C2 Frameworks**: Cobalt Strike beacons, Metasploit

### Suspicious Domains/IPs
```
apps.gist.githubapp[.]net
gupdate[.]net
*.ngrok.io
*.localhost.run
microsoft-update[.]net
windows-update[.]org

# Dust Specter C2 domains (April 2026)
lecturegenieltd[.]pro
meetingapp[.]site
afterworld[.]store
girlsbags[.]shop
onlinepettools[.]shop
web14[.]info
web27[.]info

# MuddyWater DinDoor Teams-vishing C2 (October 2026, Daylight.ai)
d1mjrkjsk5qy13[.]cloudfront[.]net   # wss C2 /api/connect (exact FQDN only)
51.120.77[.]97                       # staging IP
# UNC1549 / Nimbus Manticore SSH-tunnel C2 (Group-IB, Aug 2026)
172.86.98[.]113   # reverse SSH tunnel over TCP/443
```

### MuddyWater DinDoor Teams-Vishing (October 2026) — Key Indicators
- **Delivery**: fake M365 "IT support" tenant vishes the user over Microsoft Teams into running a "patch"
- **C2**: WebSocket (`wss://`) to `d1mjrkjsk5qy13.cloudfront.net/api/connect` — detect by TLS SNI / DNS on the exact FQDN, never the shared `cloudfront.net` parent
- **Staging dir**: `%AppData%\Roaming\DenoJSEnv\` (Deno runtime unpacked here)
- **Payload archive**: `patch08078.b`
- **Runtime**: `deno.exe` executed from the DenoJSEnv staging directory
- **Loopback listeners (host)**: 127.0.0.1:10020/10021/10022
- **Distinct from**: the older `serialmenot.com` HTTP:80 `/health` DinDoor beacon


### Mirage Kitten NodeRabbit/PollCat + Nimbus Manticore (September 2026) — Key Indicators
- **Staging**: `oracle-challenge.s3.amazonaws[.]com` bucket; lure archives
  `Front-Technical-Challenge.zip`, `FrontEnd-Task.zip`, `RankChallenge-react` project
- **Delivery**: trojanized npm packages `colorized_terminal`, `pretty-log@2.1.0`
  (postinstall lifecycle script launches implant); job/recruitment lures (Dream Job variant)
- **Host artifact**: implant at `node_modules/.cache/.<8-hex>/index.js` run as background node process
- **Persistence (variant 3)**: VS Code extension dir writes, malicious Git hooks (post-checkout/post-merge);
  Windows service whose ImagePath points to a masqueraded `wtsapi32.dll`
- **C2**: AES-256-GCM to `*.azurewebsites.net` (subdomains embed target org names), Cloudflare-fronted
  domains via NameCheap; PollCat treats HTTP 400 as successful registration — repeated 400s from an
  Azure App Service host at ~2-min cadence is the network tell
- **SSH tunneler**: reverse SSH to `172.86.98[.]113:443`, masquerades as `wtsapi32.dll`
  (Windows Terminal Server SDK DLL) loaded from a non-System32 path
- **Suricata**: SID 2000576-2000583 | **Wazuh**: 101545-101549, 101557-101560

### Dust Specter (April 2026) — Key Indicators
- **TwinTalk C2**: HTTPS GET with `Authorization: Bearer eyJ...` to randomized hex URI paths
- **File artifacts**: `C:\ProgramData\PolGuid\in.txt` and `out.txt` (TwinTask polling)
- **DLL sideloading**: Unsigned `libvlc.dll` (TwinTask) and `hostfxr.dll` (TwinTalk)
- **Registry**: Run keys for `VLC` or `WingetUI` pointing to non-standard paths
- **Lure**: Fake Webex installer from `meetingapp[.]site/webexdownload`

## Investigation Checklist

### When Alert Triggers:
1. **Identify affected system**
   - Hostname, IP address, user account
   - Is it internet-facing?
   - What services are running?

2. **Check for persistence**
   - Registry Run keys
   - Scheduled tasks
   - New services
   - Startup folder items
   - Exchange OAB virtual directories

3. **Look for lateral movement**
   - RDP/SSH connections from the host
   - SMB/WMI activity
   - New local accounts
   - Privilege escalations
   - Outlook process making network connections

4. **Data exfiltration signs**
   - Large outbound transfers (>5MB)
   - Connections to cloud storage
   - DNS tunneling patterns
   - Archive file creation
   - Email archive exports (PST/OST files)

## Common Attack Flow

```
1. Initial Access (CVE Exploitation)
   |
   v
2. Web Shell Deployment
   |
   v
3. Tool Download (Ngrok/AnyDesk)
   |
   v
4. Persistence Establishment
   |
   v
5. Credential Harvesting
   |
   v
6. Lateral Movement
   |
   v
7. Data Collection/Exfiltration
   |
   v
8. Ransomware Deployment (sometimes)
```

## Immediate Response Actions

### Level 16 Alerts (Multiple Indicators):
1. **ISOLATE** the affected system immediately
2. **DISABLE** compromised accounts
3. **BLOCK** C2 domains/IPs at firewall
4. **CAPTURE** memory dump if possible
5. **NOTIFY** incident response team

### Level 15 Alerts (Critical Single Indicator):
1. **INVESTIGATE** within 15 minutes
2. **CHECK** for additional compromise indicators
3. **REVIEW** authentication logs plus/minus 4 hours
4. **SCAN** for web shells in web directories
5. **VERIFY** security tool status

### Level 14 Alerts (High Priority):
1. **REVIEW** within 1 hour
2. **CORRELATE** with other events
3. **CHECK** user legitimacy
4. **MONITOR** for escalation

## Key Log Sources to Check

### Windows:
- Sysmon Event IDs: 1, 3, 7, 8, 10, 11, 13, 22
- Security Event IDs: 4624, 4625, 4720, 4732, 4688
- PowerShell logs
- IIS/Apache access logs
- Exchange Management Shell logs
- MSExchange Management event logs

### Network:
- Firewall logs (especially ports 443, 3389, 22, 445, 139)
- DNS query logs
- Proxy logs
- VPN connection logs
- Suricata alerts in /var/log/suricata/

## Useful Queries

### Elasticsearch/Wazuh Dashboard:

Find all Iranian APT alerts:
```
rule.groups: "iranian_apt"
```

Check for multiple stages:
```
rule.id:[100900 TO 100999] AND agent.name:"HOSTNAME"
```

Web shell detection:
```
rule.id:(100922 OR 100923 OR 100960 OR 100961)
```

C2 communication:
```
rule.id:(100944 OR 100945 OR 100949 OR 100952)
```

Exchange compromise:
```
rule.id:(100915 OR 100916 OR 100917 OR 100936 OR 100937)
```

### Suricata Fast Pattern Matches:

Check Suricata alerts:
```bash
grep "Iranian APT" /var/log/suricata/fast.log | tail -20
```

Count alerts by signature:
```bash
grep "Iranian APT" /var/log/suricata/fast.log | cut -d'"' -f2 | sort | uniq -c
```

## Quick Wins

1. **Patch these NOW**: Check Point, Palo Alto, Citrix, F5, Ivanti devices, Exchange servers
2. **Enable**: PowerShell script block logging
3. **Monitor**: External RDP/SSH access
4. **Block**: ngrok.io, localhost.run at perimeter
5. **Alert on**: New service creation, shadow copy deletion
6. **Review**: Exchange OWA/ECP logs daily
7. **Check**: Outlook rules for suspicious forwarding

## Escalation

**Escalate to IR team when:**
- Multiple related alerts from same host
- Confirmed web shell presence
- Ransomware indicators
- Data exfiltration confirmed
- Domain admin compromise suspected
- Exchange server compromise
- Mass credential theft suspected

## Additional Resources

- CISA Advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a
- Exchange Mitigation: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a
- MITRE ATT&CK: https://attack.mitre.org/groups/
- Wazuh Rules: https://documentation.wazuh.com/current/user-manual/ruleset/
- Suricata Rules: https://suricata.readthedocs.io/en/latest/rules/
## CHOSEN BRICK / HEAVYGRAM (MOIS, Sept 2026 joint advisory)

**Who gets hit:** Iranian dissidents, activists, journalists (UK/US/NL and
global); rapport-building via WhatsApp/Telegram, fake installers (Pictory,
RunwayML, Norton, KeePass) or "MRI scan results."

**Network signals (SID 2000584–2000585 DNS, 2000587–2000589 TLS SNI + Telegram correlation, + existing Telegram Bot rules):**
- Workstation DNS for `iproyal.com` / `lightningproxies.net` (proxy fabric)
- Workstation DNS for `vultrobjects.com` / `storjshare.io` (exfil)
- `api.telegram.org` Bot API traffic from non-Telegram hosts — per-victim
  bot IDs; the existing getUpdates/file-exfil rules fire here

**Host signals (Wazuh 101561–101568):** `SMQDService`/`winappx` Run keys;
anything under `C:\Windows \SysWOW64` (note trailing space); Defender
exclusions for that path; implant drops under
`ProgramData\SMQDServicePackages` / `MicrosoftDistribution\sysmain`;
`MsCache.exe`/`chromedriver.exe` from user-writable paths.
Mutexes: `ytyjyujyu`, `noi672pp434awkc12f` (101567). Multi-stage
correlation fires 101568 at level 14.

### MuddyWater Darkcomp/Stagecomp (September 2026) — Host Artifacts
| Artifact | Detail |
|----------|--------|
| `ms_upd.exe` | Stagecomp downloader (fetches the Darkcomp triad) |
| `Game.exe` | Darkcomp RAT, masquerades as Microsoft `WebView2APISample` |
| `WebView2Loader.dll` | genuine Microsoft DLL dropped for side-load staging |
| `visualwincomp.txt` | encrypted C2 config |
| Delivery | Microsoft Teams social engineering + screen-share MFA bypass; fake Quick Assist portal `adm-pulse[.]com` |
| Suricata SIDs | 2000586 (TLS SNI); existing 2000523-2000526 (dropper URI + DNS) |
| Wazuh IDs | 101569–101573 (file `0929`); existing 101530–101531 |

**Escalation:** treat as targeted surveillance of an individual, not
commodity malware — involve the victim sensitively; full IOC annex in
ic3.gov 260915.pdf.

## Nimbus Manticore MiniFast (October 2026 gap-closure; Check Point 2026-05-22)

### Network Indicators (Suricata 2000590-2000594)
| Indicator | Meaning |
|-----------|---------|
| POST `/rg` with `{"clientId":"<host>:<domain>\<user>","type":"poll"}` | MiniFast initial handshake (server answers HTTP 400 + socketId JSON) |
| POST `/agent/init` (token/pcName/isElevated JSON) | victim registration |
| GET `/agent/poll?token=` every ~120s | task-poll beacon |
| `PUT /upload/`, `GET /files/` | exfil / tool delivery legs (covered by beacon correlation) |
| DNS/SNI: business-startup.org, buisness-centeral-transportation.com, ramiltonsfinance.com, premierhealthadvisory.com, getsqldeveloper.com | dedicated C2 + SEO-poisoning delivery |
| SNI: typo'd azurewebsites.net labels (buisness-centeral*, licencemanagers, peerdistsvcmanagers, nanomatrix, global-it-*) | Azure App Service C2 masquerade |

### Host Artifacts (Wazuh 101574-101578)
| Artifact | Meaning |
|----------|---------|
| `%LOCALAPPDATA%\Zoom\bin\update\` execution | second-stage staging (trojanized Zoom installer) |
| Scheduled tasks `WindowsSecurityUpdate`, `ZoomUpdateTaskUser-<SID>` | persistence (opcode 0xB1 / hijacked updater task) |
| `uevmonitor.dll` / `InitInstall.dll` / `UpdateChecker.dll` in user-writable path | AppDomain-manager implant DLL (export `CheckForUpdates`) |
| `<name>.exe.config` dropped beside an exe in user-writable path | .NET AppDomain hijacking staging |
| `cmd.exe` child of a process in the staging dirs | command-execution opcode 0x04 |

Escalation: treat any `/rg` + `/agent/init` pair as active compromise (priority-1 rules); the beacon alone may be residual. Chrome/146 UA from non-browser processes corroborates.
