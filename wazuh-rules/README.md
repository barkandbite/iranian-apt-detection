# Wazuh Rules for Iranian APT Detection

## Overview
This directory contains modular Wazuh SIEM rules for detecting Iranian APT activities. Rules are organized by detection category for easier management.

## Rule Files and ID Ranges

| File | ID Range | Description | Rule Count |
|------|----------|-------------|------------|
| 0910-iranian-apt-cve-detection-rules.xml | 100900-100924 | CVE exploitation detection | 25 rules |
| 0911-iranian-apt-behavior-rules.xml | 100925-100959 | Behavioral patterns and tools | 35 rules |
| 0912-iranian-apt-network-rules.xml | 100940-100959 | Network-based detection | 20 rules |
| 0913-iranian-apt-fim-rules.xml | 100960-100979 | File integrity monitoring | 20 rules |
| 0914-iranian-apt-windows-rules.xml | 100980-100999 | Windows-specific detection | 20 rules |
| 0915-iranian-apt-unique-behaviors.xml | 101000-101023 | Unique Iranian signatures | 24 rules |
| 0916-iranian-apt-cloud-container.xml | 101100-101121 | Cloud and container security | 22 rules |
| 0917-iranian-apt-june2025-updates.xml | 101122-101199 | June 2025 threat updates | 78 rules |
| 0918-iranian-apt-march2026-updates.xml | 101200-101299 | March 2026 threat updates | 11 rules |
| 0919-iranian-apt-march2026-expansion.xml | 101300-101450 | March 2026 expansion (deep research) | 45 rules |

## PREREQUISITE: Sysmon is load-bearing

Most rules in this directory depend on Sysmon event groups
(`sysmon_event_1/3/6/7/8/10/11/13/20/22`). Without Sysmon deployed on your
Windows endpoints **and** the Wazuh Sysmon decoders present, the majority of
this ruleset cannot fire at all.

Sysmon-dominant files, effectively inert without it: `0911`, `0914`, `0915`,
`0917`, `0918`, `0919`, `0920`, `0921`, `0923`, `0924`.

Deploy `configurations/sysmon-config-iranian-apt.xml` to endpoints first, then
verify decoding:

```bash
/var/ossec/bin/wazuh-logtest -v
# paste a Sysmon EventChannel event; Phase 2 must show
#   win.system.providerName: 'Microsoft-Windows-Sysmon'
```

## PREREQUISITE: CDB lists

Rules 100947, 101004, 101013, 101148, 101149 and all of `0925` reference CDB
lists and will not match until those are installed and declared. See
[../cdb-lists/README.md](../cdb-lists/README.md).

## Severity rubric

Before this release nearly every rule here was level 14 or 15, which made
level meaningless: level 12+ is conventionally "attack in progress, act now"
and is a common paging and active-response trigger, so grading routine
activity at 14 meant normal sysadmin work could drive automated response.

| Level | Meaning | Example |
|-------|---------|---------|
| 3-6 | Ambient / enrichment. Correlation input only. | Farsi language preference in a web request (101004, level 3) |
| 7-9 | Suspicious, needs correlation. | Executable dropped in a temp directory (100963) |
| 10-11 | Strong single indicator. | Registry hive export, LSASS dump, shadow copy deletion |
| 12-13 | High-confidence attack behaviour. | ProxyLogon exploitation, C2 beacon, ICS/OT write commands |
| 14-15 | Confirmed IOC or named-actor infrastructure; multi-stage correlation. | Hardcoded C2 domain/IP hits, attack-chain rules |
| 16 | Destructive action in progress. | Wiper execution, ransomware encryption, mass deletion |

### Re-grading method and remaining backlog

184 rules were re-graded by category: destructive action, confirmed IOC,
correlation/multi-stage, exploitation/C2, ICS/OT, strong single indicator,
needs-correlation.

**78 rules were deliberately left at their original level.** They could not be
confidently classified from their description, and demoting an unclassified
rule into a generic middle band buries a working detection just as badly as
over-grading inflates a noisy one. A first-pass classifier was demoting
"Multiple attack stages detected" from 16 to 10 and "Credential theft
artifact" from 15 to 10; it was made conservative rather than allowed to
finish. These 78 are a manual-review backlog, not a finished grading.

### False-positive profiles

13 rules that match routine activity carry an explicit `FP PROFILE` comment
naming exactly what benign behaviour triggers them. Read it before enabling
active response on any of them:

```bash
grep -A4 'FP PROFILE' wazuh-rules/*.xml
```

## Validation

XML well-formedness is necessary but **not sufficient**. Wazuh's `OS_XML`
parser is stricter than standard XML (no CDATA) and `analysisd` rejects
constructs no XML parser sees. Always test against a real manager:

```bash
xmllint --noout wazuh-rules/*.xml          # necessary
python3 tools/lint-rules.py                # known defect classes
sudo /var/ossec/bin/wazuh-analysisd -t     # authoritative
```

A single invalid rule aborts loading of its entire file, and an invalid
`level` aborts manager startup entirely, taking every rule offline.

## Deployment Options

### Option 1: Deploy Individual Files (Recommended)
```bash
# Copy all rule files
sudo cp /path/to/iranian-apt-detection/wazuh-rules/09*.xml /var/ossec/etc/rules/

# Set permissions
sudo chown ossec:ossec /var/ossec/etc/rules/09*.xml
sudo chmod 660 /var/ossec/etc/rules/09*.xml

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

### Option 2: Deploy Consolidated Master File
If you prefer a single file, use the master file from the archive:
```bash
sudo cp /path/to/iranian-apt-detection/archive/0900-iranian-apt-detection-master.xml /var/ossec/etc/rules/
sudo chown ossec:ossec /var/ossec/etc/rules/0900-iranian-apt-detection-master.xml
sudo chmod 660 /var/ossec/etc/rules/0900-iranian-apt-detection-master.xml
sudo systemctl restart wazuh-manager
```

## Testing Rules

### Validate Syntax
```bash
sudo /var/ossec/bin/wazuh-logtest -V
```

### Test Specific Rule
```bash
echo "Test log entry" | sudo /var/ossec/bin/wazuh-logtest -v
```

### Check for Conflicts
```bash
grep -h "rule id=" /var/ossec/etc/rules/09*.xml | sort | uniq -d
```

## Rule Categories

### CVE Detection (0910)
- Check Point (CVE-2024-24919)
- Palo Alto (CVE-2024-3400)
- Citrix (CVE-2023-3519)
- F5 BIG-IP (CVE-2022-1388)
- Ivanti (CVE-2024-21887)
- Exchange ProxyLogon (CVE-2021-26855)
- Outlook (CVE-2023-23397)
- Zerologon (CVE-2020-1472)

### Behavioral Detection (0911)
- Remote access tools (AnyDesk, ngrok, MeshCentral)
- Web shells
- Known backdoors (Havoc, SystemBC)
- PowerShell abuse
- Credential theft
- Lateral movement

### Network Detection (0912)
- C2 communication patterns
- Data exfiltration
- Port scanning
- DNS tunneling
- Known malicious domains

### File Integrity (0913)
- Web shell file creation
- Credential file drops
- Ransomware indicators
- Persistence mechanisms

### Windows-Specific (0914)
- Event log clearing
- Service manipulation
- Shadow copy deletion
- Registry persistence
- Process injection

### Unique Behaviors (0915)
- Tehran business hours activity
- Farsi language artifacts
- DNS hijacking patterns
- Cryptocurrency mining
- Passive backdoors

### Cloud & Container (0916)
- AWS/Azure/GCP attacks
- Kubernetes exploitation
- Container escapes
- AI API abuse

### March 2026 Updates (0918)
- Ivanti EPMM (CVE-2026-1281)
- FortiOS SAML (CVE-2025-59718)
- MuddyWater Malware: UDPGangster, Dindoor, Fakeset, CHAR
- CyberAv3ngers OT/ICS: IOCONTROL
- Cloud Exfiltration: Wasabi, Backblaze B2
- Telegram Bot API C2

### March 2026 Expansion (0919)
- MuddyViper/Fooder backdoor (MuddyWater/ESET)
- WezRat infostealer (Cotton Sandstorm/Check Point)
- Handala/Void Manticore wiper + Stryker attack (Check Point)
- Sicarii RaaS (Check Point)
- WhiteLock ransomware (Cotton Sandstorm)
- Crafty Camel/Sosano backdoor (Proofpoint)
- SloppyMIO/RedKitten steganography (HarfangLab)
- UNC1549 full toolset: LIGHTRAIL, CRASHPAD, DCSYNCER, SIGHTGRAB, MINIBIKE (Mandiant)
- APT42 TAMECAT fileless backdoor (Mandiant)
- IOCONTROL expanded IOCs (Claroty)
- BQT.Lock/Baqiyat Hezbollah RaaS
- Cross-actor correlation rules

## Integration with Active Response

Enable active response by adding configuration from `configurations/iranian-apt-active-response.xml.example` to your `ossec.conf`.

## Performance Considerations

- Rules with frequency/timeframe may impact performance on busy systems
- Consider adjusting thresholds based on your environment
- Monitor CPU usage after deployment

## Customization

Edit rule levels based on your environment:
- Level 13: Low priority
- Level 14: Medium priority  
- Level 15: High priority
- Level 16: Critical (maximum)

## Troubleshooting

If rules don't trigger:
1. Check agent logs: `/var/ossec/logs/ossec.log`
2. Verify log collection is configured
3. Ensure proper log parsing with `wazuh-logtest`
4. Check rule syntax for errors

## Updates

Check the repository regularly for rule updates as new Iranian APT techniques emerge.
