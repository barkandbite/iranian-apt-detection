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
│   └── README.md                                     # Wazuh rules documentation
│
├── configurations/
│   ├── sysmon-config-iranian-apt.xml                # Sysmon configuration
│   ├── ossec-agent-iranian-apt.conf                 # Wazuh agent config
│   ├── iranian-apt-active-response.xml              # Active response config
│   └── README.md                                     # Configuration guide
│
├── suricata/
│   ├── iranian_apt_v2.rules                         # Current Suricata IDS signatures
│   └── README.md                                     # Suricata deployment guide
│
├── documentation/
│   ├── README.md                                     # Documentation overview
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
│   ├── 0900-iranian-apt-detection-master.xml        # Consolidated rules (optional)
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

1. **Wazuh Rules**: Deploy all files from `wazuh-rules/09*.xml` or use master from archive
2. **Sysmon**: Deploy `configurations/sysmon-config-iranian-apt.xml` to Windows endpoints
3. **Agent Config**: Add content from `configurations/ossec-agent-iranian-apt.conf` to agents
4. **Suricata**: Copy `suricata/iranian_apt_v2.rules` to your rules directory
5. **Active Response**: Run `tools/deploy-active-response.sh` for automated response

## Rule ID Allocation

### Wazuh Rules (100900-101199)
- **100900-100924**: CVE exploitation detection (0910)
- **100925-100959**: Behavioral detection (0911)
- **100940-100959**: Network detection (0912) - overlaps with behavioral
- **100960-100979**: File integrity monitoring (0913)
- **100980-100999**: Windows-specific detection (0914)
- **101000-101023**: Unique Iranian behaviors (0915)
- **101100-101121**: Cloud and container security (0916)
- **101122-101199**: June 2025 updates (0917)

### Suricata SID Ranges (2000001-2000130)
- **2000001-2000014**: CVE exploitation signatures
- **2000015-2000025**: C2 infrastructure detection
- **2000026-2000089**: Various detection categories
- **2000090-2000114**: Cloud and AI attacks
- **2000115-2000124**: Tool-specific signatures
- **2000125-2000130**: June 2025 updates

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
