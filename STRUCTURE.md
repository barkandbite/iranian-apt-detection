# Repository Structure

```
iranian-apt-detection/
│
├── wazuh-rules/
│   ├── 0910-iranian-cve-detection-rules.xml     # CVE exploitation detection
│   ├── 0911-iranian-apt-behavior-rules.xml      # Behavioral patterns
│   ├── 0912-iranian-apt-network-rules.xml       # Network-based detection
│   ├── 0913-iranian-apt-fim-rules.xml           # File integrity monitoring
│   └── 0914-iranian-apt-windows-rules.xml       # Windows-specific rules
│
├── configurations/
│   ├── sysmon-config-iranian-apt.xml            # Sysmon configuration
│   └── ossec-agent-iranian-apt.conf             # Wazuh agent config
│
├── suricata/
│   └── iranian-apt.rules                        # Suricata IDS signatures
│
├── documentation/
│   ├── README.md                                # Main documentation
│   ├── SOC-Quick-Reference-Iranian-APT.md       # SOC quick reference
│   ├── MITRE-ATT&CK-Mapping.md                  # MITRE framework mapping
│   └── Sector-Vulnerability-Analysis.md         # Sector-specific analysis
│
├── tools/
│   └── test-rules.sh                            # Rule validation script
│
├── CHANGELOG.md                                 # Version history
├── CONTRIBUTING.md                              # Contribution guidelines
├── LICENSE                                      # MIT License
└── STRUCTURE.md                                 # This file
```

## Quick Start

1. **Wazuh Rules**: Copy XML files from `wazuh-rules/` to your Wazuh manager
2. **Sysmon**: Deploy `sysmon-config-iranian-apt.xml` to Windows endpoints
3. **Agent Config**: Add content from `ossec-agent-iranian-apt.conf` to agent configuration
4. **Suricata**: Copy `iranian-apt.rules` to your Suricata rules directory
5. **Documentation**: Review README.md for detailed installation steps

## Rule ID Ranges

- **100900-100919**: CVE exploitation detection
- **100920-100939**: Behavioral detection
- **100940-100959**: Network detection
- **100960-100979**: File integrity monitoring
- **100980-100999**: Windows-specific detection

## Suricata SID Ranges

- **1000001-1000036**: Iranian APT detection signatures