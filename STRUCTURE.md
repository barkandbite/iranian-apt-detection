# Repository Structure

```
iranian-apt-detection/
│
├── wazuh-rules/
│   ├── 0910-iranian-apt-cve-detection-rules.xml     # CVE exploitation detection
│   ├── 0911-iranian-apt-behavior-rules.xml          # Behavioral patterns
│   ├── 0912-iranian-apt-network-rules.xml           # Network-based detection
│   ├── 0913-iranian-apt-fim-rules.xml               # File integrity monitoring
│   ├── 0914-iranian-apt-windows-rules.xml           # Windows-specific rules
│   ├── 0915-iranian-apt-unique-behaviors.xml        # Unique Iranian signatures
│   ├── 0916-iranian-apt-cloud-container.xml         # Cloud and container security
│   ├── 0917-iranian-apt-june2025-updates.xml        # June 2025 threat updates
│   ├── 0918-iranian-apt-march2026-updates.xml       # March 2026 threat updates
│   ├── 0919-iranian-apt-march2026-expansion.xml     # March 2026 expansion
│   └── README.md                                     # Wazuh rules documentation
│
├── configurations/
│   ├── sysmon-config-iranian-apt.xml                # Sysmon configuration
│   ├── ossec-agent-iranian-apt.conf                 # Wazuh agent config
│   ├── iranian-apt-active-response.xml              # Active response config
│   └── README.md                                     # Configuration guide
│
├── suricata/
│   ├── iranian-apt-detection.rules                  # Consolidated Suricata IDS signatures (v4.0)
│   └── README.md                                     # Suricata deployment guide
│
├── documentation/
│   ├── README.md                                     # Documentation overview
│   ├── MARCH-2026-DEPLOYMENT.md                     # March 2026 deployment guide
│   ├── THREAT_INTEL_MARCH_2026.md                   # March 2026 threat intelligence
│   ├── SOC-Quick-Reference-Iranian-APT.md           # SOC quick reference
│   ├── MITRE-ATT&CK-Mapping.md                      # MITRE framework mapping
│   └── Sector-Vulnerability-Analysis.md             # Sector-specific analysis
│
├── tools/
│   ├── test.sh                                      # Rule validation script
│   ├── deploy-iranian-apt-rules.sh                  # Main deployment script
│   ├── iranian-apt-active-response.sh               # Active response script
│   ├── deploy-active-response.sh                    # Active response deployment
│   └── README.md                                     # Tools documentation
│
├── archive/
│   ├── suricata-v3-legacy/                          # Archived v3.x Suricata files
│   │   ├── iranian_apt_v3.1.rules                   # v3.1 (199 rules, superseded)
│   │   ├── iranian_apt_v3_2.rules                   # v3.2 (241 rules, superseded)
│   │   ├── iranian_apt_v3_3_expansion.rules         # v3.3 expansion (97 rules, superseded)
│   │   └── README.md                                # Migration notes
│   ├── 0900-iranian-apt-detection-master.xml        # Consolidated Wazuh rules (optional)
│   ├── iranian-apt.rules                            # Original Suricata rules v1.0
│   ├── iranian-apt-cloud-ai.rules                   # Cloud rules (merged)
│   ├── iranian-apt-2025-06-29                       # June updates archive
│   └── README.md                                     # Archive documentation
│
├── CHANGELOG.md                                      # Version history
├── CONTRIBUTING.md                                   # Contribution guidelines
├── LICENSE                                           # MIT License
├── README.md                                         # Main documentation
├── STRUCTURE.md                                      # This file
└── UPDATE_TEMPLATE.md                                # Update documentation template
```

## Quick Start

1. **Wazuh Rules**: Deploy all files from `wazuh-rules/09*.xml`
2. **Sysmon**: Deploy `configurations/sysmon-config-iranian-apt.xml` to Windows endpoints
3. **Agent Config**: Add content from `configurations/ossec-agent-iranian-apt.conf` to agents
4. **Suricata**: Copy `suricata/iranian-apt-detection.rules` to your rules directory
5. **Active Response**: Run `tools/deploy-active-response.sh` for automated response

## Rule ID Allocation

### Wazuh Rules (100900-101521)
- **100900-100924**: CVE exploitation detection (0910)
- **100925-100959**: Behavioral detection (0911)
- **100940-100959**: Network detection (0912)
- **100960-100979**: File integrity monitoring (0913)
- **100980-100999**: Windows-specific detection (0914)
- **101000-101023**: Unique Iranian behaviors (0915)
- **101100-101121**: Cloud and container security (0916)
- **101122-101199**: June 2025 updates (0917)
- **101200-101299**: March 2026 updates (0918)
- **101300-101477**: March 2026 expansion (0919)
- **101480-101510**: Healthcare emergency (0919)
- **101511-101515**: Dust Specter TwinTalk/SPLITDROP host indicators (0919)
- **101516-101521**: CyberAv3ngers Rockwell PLC host-side detection (0919)

### Suricata SID Ranges (1000039-2000493)
- **1000039-2000014**: CVE exploitation signatures
- **2000015-2000030**: C2 infrastructure, post-exploitation, exfiltration
- **2000031-2000050**: Reconnaissance, web shells, ICS/SCADA, correlation
- **2000090-2000130**: Cloud targeting, tool-specific, June 2025 updates
- **2000131-2000193**: March 2026 v3.0 (MuddyWater, CyberAv3ngers OT)
- **2000194-2000230**: MuddyViper, WezRat, UNC1549, Handala, Sicarii, IOCONTROL
- **2000231-2000359**: March 2026 expansion (healthcare, correlation, IOCs)
- **2000360-2000456**: ICS/PCOM, TAMECAT, Infy blockchain, FortiOS/Ivanti chains
- **2000457-2000461**: CRESCENTHARVEST RAT (APT35/Charming Kitten)
- **2000462-2000466**: Boggy Serpens/BlackBeard + Nuso backdoor
- **2000467**: Infy Tonnerre replacement C2
- **2000468-2000477**: Dust Specter TwinTalk/SPLITDROP C2 + domain IOCs
- **2000478-2000485**: CyberAv3ngers Rockwell CompactLogix/Micro850 PLC targeting (CISA AA26-097A)
- **2000486-2000490**: Infy/Prince of Persia IOC update (45.80.149.3, ddnsking.com, conningstone.net, hbmc.net)
- **2000491-2000493**: MuddyWater ChainShell/CastleRAT Russian MaaS (TAG-150)

## File Naming Conventions

### Wazuh Rules
- Format: `09XX-iranian-apt-[category].xml`
- Start with 09 to ensure loading after default rules
- Category describes the detection focus

### Documentation
- Use descriptive names with hyphens
- Markdown format for all documentation
- Include table of contents for long documents

### Scripts
- Executable bash scripts for Linux/Unix
- Descriptive names indicating function
- Include version and date in header comments
