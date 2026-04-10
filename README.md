# Iranian APT Detection Rules

[![Version](https://img.shields.io/badge/version-5.0.0-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v13-orange.svg)](documentation/MITRE-ATT&CK-Mapping.md)

## What This Is

This is a free, open-source collection of **detection rules** that help identify Iranian government-backed cyberattacks on your network. These rules are designed for two widely used security tools:

- **Suricata** -- a network intrusion detection system (IDS) that monitors your network traffic
- **Wazuh** -- a security information and event management system (SIEM) that monitors your endpoints and logs

**This is not standalone software.** You must already have Suricata, Wazuh, or both installed and running. These are rule files that you drop into your existing setup. If you only run Suricata, you only need the Suricata files. If you only run Wazuh, you only need the Wazuh files. You do not need both.

This is a purely defensive toolkit. It contains no offensive capabilities, exploit code, or attack tools.

---

## Install in 5 Minutes

### Step 1: Download the repository

```bash
git clone https://github.com/BarkandBite/iranian-apt-detection.git
cd iranian-apt-detection
```

### Step 2: Pick what applies to you

You only need the section that matches the software you already run. Skip the rest.

---

### I use Suricata (network IDS)

You need **one file**: `suricata/iranian-apt-detection.rules`

This single file contains all 354 network detection signatures.

```bash
# Copy the rules file into your Suricata rules directory
sudo cp suricata/iranian-apt-detection.rules /etc/suricata/rules/

# Tell Suricata to load the new rules.
# Open /etc/suricata/suricata.yaml and add this line under "rule-files:":
#   - iranian-apt-detection.rules

# Test that the rules load without errors
sudo suricata -T -c /etc/suricata/suricata.yaml

# Reload Suricata (no restart needed, no downtime)
sudo kill -USR2 $(pidof suricata)
```

That is it. Suricata will now alert on Iranian APT traffic patterns.

---

### I use Wazuh (SIEM)

You need the XML files from the `wazuh-rules/` folder. There are 10 rule files, organized by category so you can deploy all of them or only the ones relevant to your environment:

| File | What It Detects |
|------|----------------|
| `0910-iranian-apt-cve-detection-rules.xml` | Exploitation of known vulnerabilities (CVEs) |
| `0911-iranian-apt-behavior-rules.xml` | Suspicious behaviors: remote tools, credential theft, persistence |
| `0912-iranian-apt-network-rules.xml` | C2 communication, DNS tunneling, data exfiltration |
| `0913-iranian-apt-fim-rules.xml` | Unauthorized file changes: web shells, credential drops |
| `0914-iranian-apt-windows-rules.xml` | Windows-specific: event log clearing, registry persistence |
| `0915-iranian-apt-unique-behaviors.xml` | Iranian-specific: Tehran business hours, Farsi artifacts |
| `0916-iranian-apt-cloud-container.xml` | Cloud and container attacks: Azure, Kubernetes |
| `0917-iranian-apt-june2025-updates.xml` | June 2025 campaign coverage |
| `0918-iranian-apt-march2026-updates.xml` | March 2026 campaign coverage |
| `0919-iranian-apt-march2026-expansion.xml` | Latest threat families and attack chains |

```bash
# Copy all rule files (recommended)
sudo cp wazuh-rules/09*.xml /var/ossec/etc/rules/
sudo chown ossec:ossec /var/ossec/etc/rules/09*.xml
sudo chmod 660 /var/ossec/etc/rules/09*.xml

# Restart Wazuh to load the new rules
sudo systemctl restart wazuh-manager
```

Or, if you only want specific categories, copy just those files.

---

### I use both Suricata and Wazuh

Follow both sections above. You can also optionally enable active response, which lets Wazuh automatically block threats that Suricata detects:

```bash
sudo cp tools/iranian-apt-active-response.sh /var/ossec/active-response/bin/
sudo chmod +x /var/ossec/active-response/bin/iranian-apt-active-response.sh
# Then add the configuration from configurations/iranian-apt-active-response.xml
# into your Wazuh ossec.conf file.
```

---

### I want endpoint monitoring too (Windows)

If you run Sysmon on Windows endpoints, deploy the enhanced Sysmon configuration:

```
configurations/sysmon-config-iranian-apt.xml
```

If you use Wazuh agents, the agent configuration template is at:

```
configurations/ossec-agent-iranian-apt.conf
```

---

## What This Repo Contains

```
iranian-apt-detection/
|
|-- suricata/                       <-- SURICATA USERS: start here
|   |-- iranian-apt-detection.rules     One file, 354 network signatures
|   `-- README.md                       Suricata-specific docs
|
|-- wazuh-rules/                    <-- WAZUH USERS: start here
|   |-- 0910 through 0919 .xml files   265+ SIEM detection rules
|   `-- README.md                       Wazuh-specific docs
|
|-- configurations/                 <-- OPTIONAL: endpoint configs
|   |-- sysmon-config-iranian-apt.xml   Windows Sysmon config
|   |-- ossec-agent-iranian-apt.conf    Wazuh agent config
|   `-- iranian-apt-active-response.xml Active response config
|
|-- tests/                          <-- FOR DEVELOPERS: test suite
|   |-- test_suricata_rules.py          Automated tests for all 354 rules
|   |-- conftest.py                     Test infrastructure
|   `-- requirements.txt                Test dependencies
|
|-- tools/                          <-- Deployment and testing scripts
|-- documentation/                  <-- Threat intelligence and guides
|-- archive/                        <-- Historical rule versions
`-- CHANGELOG.md, LICENSE, etc.
```

---

## What Gets Detected

### 28+ Iranian Threat Groups

| Group | Also Known As | Primary Targets | Key Detections |
|-------|---------------|-----------------|----------------|
| **MuddyWater** | Seedworm, MERCURY | Gov, Telecom, Defense, Healthcare | MuddyViper, UDPGangster, Dindoor, Fakeset, CHAR, Phoenix |
| **CyberAv3ngers** | IRGC-CEC, BAUXITE | Water, Energy, OT/ICS | IOCONTROL (MQTT C2), PLC exploitation, PCOM protocol |
| **Handala** | Void Manticore, Storm-0842 | Defense, Tech, Healthcare | Intune MDM wipe, NetBird, wiper deployment |
| **Pioneer Kitten** | Fox Kitten, Pay2Key | VPN vendors, Healthcare | Pay2Key v3 (ChaCha20, I2P), CVE exploitation |
| **Cotton Sandstorm** | Emennet Pasargad | Media, Healthcare | WezRat, WhiteLock ransomware |
| **UNC1549** | Nimbus Manticore | Aerospace, Defense, Telecom | TWOSTROKE, DEEPROOT, LIGHTRAIL, MINIBIKE |
| **APT42** | Charming Kitten | Gov officials, Activists | TAMECAT (Discord/Cloudflare/Firebase C2) |
| **APT34** | OilRig, Helix Kitten | Gov, Finance, Telecom | STEALHOOK, Veaty, Spearal, DNS tunneling |
| **APT33** | Peach Sandstorm | Aerospace, Energy | Tickler, SHAPESHIFT wiper |
| **Infy** | Prince of Persia | Activists, Dissidents | Foudre v34, Tonnerre v50, blockchain DGA |
| **RedKitten** | IRGC-aligned | Human rights NGOs | SloppyMIO (steganography, GitHub dead-drop) |
| **Crafty Camel** | UNK_CraftyCamel | Aviation, Transport | Sosano (Golang), polyglot files |
| **UNC1860** | MOIS | Government, Telecom | WINTAPIX, TOFUDRV, passive IIS backdoors |
| **Sicarii** | Handala-linked RaaS | Multiple | AES-GCM, file.io exfiltration |
| **Dust Specter** | Iran-nexus | Government (Iraq) | TwinTalk JWT C2, SPLITDROP wiper |
| **Boggy Serpens** | MuddyWater sub | Energy, Marine | BlackBeard Rust C2, Nuso backdoor |

### 40+ Vulnerabilities (CVEs)

These rules detect active exploitation of known vulnerabilities that Iranian groups target:

- **CVE-2025-59287** -- Windows WSUS (critical, CVSS 9.8)
- **CVE-2026-1281** -- Ivanti EPMM
- **CVE-2025-59718** -- FortiOS SAML bypass
- **CVE-2024-55591** -- FortiOS WebSocket auth bypass
- **CVE-2025-64446** -- FortiWeb path traversal
- **CVE-2025-23006** -- SonicWall SMA
- **CVE-2024-24919** -- Check Point Security Gateway
- **CVE-2024-3400** -- Palo Alto PAN-OS
- **CVE-2024-38434** -- Unitronics PCOM
- **CVE-2025-31701** -- Dahua Camera
- And 30+ more

### Sectors Protected

- **Energy** -- power grid, oil and gas, renewable energy systems
- **Water and Wastewater** -- treatment plants, SCADA systems, Unitronics PLCs
- **Healthcare** -- hospitals, medical device networks, health IT
- **Telecommunications** -- ISPs, carriers, network infrastructure
- **Finance** -- banks, payment processors, exchanges
- **Transportation** -- aviation, maritime, logistics
- **Defense and Aerospace** -- defense industrial base, contractors
- **Government** -- federal, state, and local networks

### Detection Techniques

- Exploitation of VPN and edge devices (FortiOS, Ivanti, PAN-OS, Check Point, SonicWall, Citrix, F5)
- Command-and-control communication (Telegram, Discord, Cloudflare Workers, MQTT, blockchain)
- Lateral movement (SMB, RDP, SSH tunneling, RMM tool abuse)
- Data exfiltration (DNS tunneling, cloud storage, Rclone)
- Wiper and ransomware deployment (Intune MDM abuse, mass file deletion)
- Industrial control system attacks (Modbus, BACnet, S7comm, PCOM)
- Credential theft (Kerberoasting, LSASS dumping, LDAP spray)

---

## Verifying the Rules Work

### Quick validation

```bash
# Suricata: check that rules load without errors
sudo suricata -T -c /etc/suricata/suricata.yaml

# Wazuh: check for rule compilation errors
sudo /var/ossec/bin/wazuh-logtest -V
```

### Full test suite (for developers and contributors)

The test suite generates synthetic network traffic for every rule and confirms Suricata alerts on it:

```bash
pip3 install scapy pytest
sudo python3 -m pytest tests/test_suricata_rules.py -v
```

---

## SOC Integration

### Dashboard Queries

**Wazuh/Elasticsearch**:
```
rule.groups: "iranian_apt" AND rule.level: [14 TO 16]
```

**Splunk**:
```
index=wazuh rule.groups="iranian_apt" rule.level>=14
```

**Suricata alert filtering** (all rules use the `IRANIAN-APT` keyword):
```
alert.signature:"*IRANIAN-APT*"
alert.signature:"*IRANIAN-APT MuddyWater*"
```

### Alert Priorities

| Level | Response Time | Action |
|-------|---------------|---------|
| 16 | Immediate | Isolate host, investigate, brief leadership |
| 15 | 15 minutes | Block indicator, investigate, start incident response |
| 14 | 1 hour | Investigate, correlate with other alerts, monitor |
| 13 | 4 hours | Review, validate, track for patterns |

---

## Performance Impact

| Component | CPU | Memory | Network | Storage |
|-----------|-----|---------|---------|----------|
| Wazuh Rules | +2-3% | +50MB | Minimal | +100MB/day |
| Suricata | +5-10% | +200MB | None | +500MB/day |
| Active Response | Spike | Minimal | Varies | Minimal |

---

## Why This Exists

Nation-state cyber operations increasingly target critical infrastructure -- energy grids, water treatment facilities, hospitals, financial systems, telecommunications networks, transportation, and government agencies. Large enterprises and federal agencies have dedicated threat intelligence teams and commercial detection platforms. Smaller organizations, municipal utilities, rural hospitals, and regional infrastructure operators often do not.

This project closes that gap by providing free, continuously updated detection rules that any organization running Suricata or Wazuh can deploy to defend against documented Iranian cyber operations.

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where help is needed:
- macOS/Linux specific endpoint rules
- Cloud provider detections (AWS GuardDuty, GCP SCC integration)
- Additional ICS/SCADA protocol signatures (DNP3, OPC DA)
- False positive tuning and threshold optimization
- Splunk/Elastic SIEM rule translations
- YARA rules for file-level detection

## Support

- **Issues**: Use GitHub Issues for bugs and feature requests
- **Updates**: Watch this repo for threat intelligence updates
- **Contact**: security@barkandbite.com

## License

MIT License -- see [LICENSE](LICENSE).

## Acknowledgments

- CISA for threat advisories and infrastructure defense guidance
- MITRE ATT&CK framework
- Wazuh and Suricata open-source communities
- Security researchers tracking Iranian threat operations

## Disclaimer

These rules are provided as-is for defensive purposes only. No offensive capabilities are included. Users are responsible for testing and tuning in their environment. Monitor for false positives before enabling active response.

---

**Last Updated**: April 10, 2026 | **Version**: 5.0.0 | **Maintainer**: Bark&Bite Security Intelligence
