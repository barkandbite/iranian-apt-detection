# Documentation for Iranian APT Detection Suite

## Overview
This directory contains threat intelligence, analysis, and operational guides for defending against Iranian APT groups.

## Documents

### Operational Guides

#### [SOC-Quick-Reference-Iranian-APT.md](SOC-Quick-Reference-Iranian-APT.md)
**For**: SOC Analysts, Incident Responders  
**Contents**: 
- Critical indicators with rule mappings
- Investigation checklists
- Common attack flows
- Response priorities

#### [MITRE-ATT&CK-Mapping.md](MITRE-ATT&CK-Mapping.md)
**For**: Threat Hunters, Detection Engineers  
**Contents**:
- Complete technique mapping (89 techniques)
- Kill chain coverage analysis
- Detection gaps identification
- Hunt queries by tactic

### Strategic Analysis

#### [Sector-Vulnerability-Analysis.md](Sector-Vulnerability-Analysis.md)
**For**: Risk Managers, CISOs  
**Contents**:
- Energy sector vulnerabilities
- Defense industrial base risks
- Veteran services targeting
- Predicted attack vectors

#### [Iranian-APT-Unique-Signatures.md](README.md)
**For**: Threat Intelligence Teams  
**Contents**:
- Behavioral signatures unique to Iranian actors
- Cultural and temporal artifacts
- Advanced evasion techniques
- Attribution indicators

## Quick Reference Matrix

| Document | Audience | Update Frequency | Last Updated |
|----------|----------|------------------|--------------|
| SOC Quick Reference | Analysts | Monthly | 2025-06-25 |
| MITRE Mapping | Hunters | Quarterly | 2025-06-25 |
| Sector Analysis | Leadership | Quarterly | 2025-06-25 |
| Unique Signatures | Intel Teams | As needed | 2025-06-27 |

## Key Insights

### Top Iranian APT Characteristics
1. **Working Hours**: 05:30-13:30 UTC (Tehran business hours)
2. **Languages**: Farsi language artifacts in tools
3. **Infrastructure**: Preference for .ir, .tk, .ml domains
4. **Techniques**: DNS hijacking, passive implants
5. **Sectors**: Energy, water, defense, veterans

### Critical Vulnerabilities Exploited
| CVE | Product | Exploitation Rate |
|-----|---------|-------------------|
| CVE-2024-24919 | Check Point | ████████░░ 85% |
| CVE-2024-3400 | Palo Alto | ████████░░ 80% |
| CVE-2023-23397 | Outlook | █████████░ 95% |
| CVE-2021-26855 | Exchange | ████████░░ 85% |

### Emerging Threats (2025)
1. **AI-Enhanced Operations**: GPT-powered phishing
2. **Cloud Infrastructure**: Azure subdomain abuse
3. **Supply Chain**: Package repository poisoning
4. **ICS Targeting**: MQTT-based C2 for SCADA
5. **Cryptocurrency**: Exchange API exploitation

## Usage Guidelines

### For Incident Response
1. Start with SOC Quick Reference
2. Check MITRE mapping for technique
3. Review sector analysis for context
4. Apply unique signatures for attribution

### For Threat Hunting
1. Review unique signatures monthly
2. Focus on behavioral patterns
3. Hunt for temporal anomalies
4. Correlate with sector analysis

### For Leadership Briefings
1. Use sector analysis for risk assessment
2. Reference SOC metrics for program effectiveness
3. Show MITRE coverage for capability gaps
4. Highlight unique signatures for attribution

## Integration with Rules

Each document references specific rule IDs:
- **Wazuh Rules**: 100900-101155
- **Suricata SIDs**: 2000001-2000130

Cross-reference format:
```
[Rule Type] [Rule ID]: [Description]
Example: Wazuh 101002: Tehran business hours detection
```

## Contributing

When updating documentation:
1. Use the update template format
2. Maintain cross-references to rules
3. Update the matrix table
4. Tag with relevant MITRE techniques

## Recent Updates

### 2025-06-27
- Added unique behavioral signatures document
- Expanded AI-powered attack analysis
- Updated sector vulnerabilities

### 2025-06-25
- Initial documentation release
- Complete MITRE mapping
- SOC operational guide
