# Bark & Bite Iranian APT Detection - March 2026 Update
## Deployment Guide & Changelog

### Version 3.0 | 2026-03-09

---

## Quick Deploy

```bash
# Deploy the consolidated v3.1 ruleset
sudo cp iranian-apt-detection.rules /etc/suricata/rules/

# Update suricata.yaml:
#   rule-files:
#     - iranian-apt-detection.rules

# Validate syntax
sudo suricata -T -c /etc/suricata/suricata.yaml

# Reload rules (no restart needed)
sudo kill -USR2 $(pidof suricata)
```

---

## What's New: 63 Rules (SID 2000131-2000193)

### New CVE Exploitation Detection (10 rules)
| SID | CVE | Product | Group |
|-----|-----|---------|-------|
| 2000131 | CVE-2026-1281 | Ivanti EPMM RCE | MuddyWater |
| 2000132 | CVE-2025-59718 | FortiOS SAML Bypass | Multiple |
| 2000133-134 | CVE-2024-55591 | FortiOS Auth Bypass + "FortiSetup" | MuddyWater |
| 2000135 | CVE-2025-23006 | SonicWall SMA 1000 | Multiple |
| 2000136 | CVE-2021-36260 | Hikvision Cmd Injection | CyberAv3ngers |
| 2000137 | CVE-2021-33044 | Dahua Auth Bypass | CyberAv3ngers |
| 2000138 | CVE-2025-64446 | FortiWeb Path Traversal | Multiple |
| 2000139-140 | — | MuddyWater C2 IP 194.11.246.101 | MuddyWater |

### MuddyWater New Malware (16 rules)
| SID Range | Malware | C2 Channel | Detection Method |
|-----------|---------|------------|------------------|
| 2000141-143 | UDPGangster | UDP:1269 | Port + known IP + heartbeat byte |
| 2000144-145 | Dindoor | Wasabi cloud | Rclone UA + wasabisys.com |
| 2000146-148 | Fakeset | Backblaze B2 | Known bucket domains + .exe download |
| 2000149-150 | CHAR/Olalampo | Telegram Bot API | Bot name + codefusiontech.org |
| 2000151-152 | Generic Telegram C2 | Telegram API | getUpdates polling + sendDocument |
| 2000153 | ArenaC2 | FastAPI/uvicorn | Server header fingerprint |
| 2000154-155 | Phoenix v4 | HTTP | C2 domain + SimpleHTTP fingerprint |
| 2000156 | Sliver C2 | TCP:31337 | Known IP:port |

### CyberAv3ngers ICS/OT (8 rules)
| SID Range | Threat | Target | Priority |
|-----------|--------|--------|----------|
| 2000157-158 | IOCONTROL MQTT C2 | IoT/OT devices | P1 - Critical |
| 2000159-160 | IOCONTROL DoH evasion | Cloudflare DNS | P1 - Critical |
| 2000161 | PLC_Controller S7comm STOP | Siemens PLCs | P1 - Critical |
| 2000162 | Unitronics PCOM exploit | Water sector PLCs | P1 - Critical |
| 2000163-164 | Camera exploitation | Hikvision/Dahua | P2 - High |

### Infy/Prince of Persia (7 rules)
| SID Range | Malware | Technique |
|-----------|---------|-----------|
| 2000165-167 | Foudre v34 | DGA beacon + RSA verification + .ix.tc domains |
| 2000168-171 | Tonnerre v50 | DGA .privatedns.org + known C2 IPs + Telegram bot |

### Other APT Groups (5 rules)
| SID | Group | Detection |
|-----|-------|-----------|
| 2000172-173 | UNC1549/Nimbus Manticore | SSH tunnels + DCSync |
| 2000174 | RedKitten | GitHub dead-drop resolver |
| 2000175 | Charming Kitten | BellaCiao DNS beacon |
| 2000176 | Crafty Camel | Polyglot HTA download |

### Ransomware (3 rules)
| SID | Threat | Detection |
|-----|--------|-----------|
| 2000177 | Pay2Key.I2P | Defender .exe exclusion |
| 2000178 | Pay2Key.I2P | I2P network bootstrap |
| 2000179 | Pay2Key.I2P | 7-Zip SFX payload delivery |

### Cloud Abuse & Evasion (4 rules)
| SID | Technique | Detection |
|-----|-----------|-----------|
| 2000180 | Rclone exfil | User-agent string |
| 2000181 | EtherHiding | Ethereum JSON-RPC calls |
| 2000182 | AnyDesk abuse | RMM relay traffic |
| 2000183 | MeshCentral abuse | Agent check-in |

### Behavioral Patterns (6 rules)
| SID | Behavior | Context |
|-----|----------|---------|
| 2000184 | FortiOS webshell | Post-exploitation |
| 2000185 | VPN group manipulation | Persistence |
| 2000186 | LDAP credential spray | Initial access |
| 2000187 | Unitronics default creds | ICS targeting |
| 2000188 | SSH tunnel high port | Lateral movement |
| 2000189 | WezRat cookie theft | Exfiltration |

### Correlation / Multi-Stage (4 rules)
| SID | Chain | Confidence |
|-----|-------|------------|
| 2000190 | FortiOS exploit → Wasabi exfil | Very High |
| 2000191 | FortiOS exploit → Backblaze staging | Very High |
| 2000192 | Ivanti exploit → Telegram C2 | Very High |
| 2000193 | ICS exploit → MQTT C2 | Very High |

---

## MITRE ATT&CK Coverage Summary

| Tactic | New Techniques Covered |
|--------|----------------------|
| Initial Access | T1190, T1133, T1078.001 |
| Execution | T1059.003, T1059.006, T1059.007 |
| Persistence | T1505.003, T1219 |
| Credential Access | T1003.006, T1110.003, T1621 |
| Command & Control | T1071.001, T1071.005, T1095, T1102, T1102.001, T1102.002, T1568.002, T1572, T1573.001 |
| Exfiltration | T1567.002 |
| Impact | T0831, T0855, T1486 |

---

## Performance Notes

**Resource-intensive rules** (consider disabling on bandwidth-constrained deployments):
- SID 2000163: RTSP camera brute-force (high threshold, but noisy on camera-heavy networks)
- SID 2000186: LDAP bind flood (may trigger on legitimate AD auth traffic)

**ICS/OT-specific rules** (enable ONLY on OT-adjacent network segments):
- SID 2000157-162: IOCONTROL and PLC-targeting rules
- SID 2000187: Unitronics default credential detection

**Rules requiring tuning** per environment:
- SID 2000172/2000188: SSH on non-standard ports (whitelist legitimate SSH services)
- SID 2000182-183: RMM tool detection (whitelist if AnyDesk/MeshCentral is authorized)
