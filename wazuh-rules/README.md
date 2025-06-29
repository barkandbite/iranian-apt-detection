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

## Integration with Active Response

Enable active response by adding configuration from `configurations/iranian-apt-active-response.xml` to your `ossec.conf`.

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
