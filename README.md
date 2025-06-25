# Wazuh Rules for Iranian APT Detection

## Overview

This repository contains a comprehensive set of Wazuh rules, Suricata signatures, and configurations for identifying and responding to Iranian Advanced Persistent Threat (APT) activities. The rules are based on publicly reported tactics, techniques, and procedures (TTPs) used by Iranian threat actors including:

- **Pioneer Kitten** (Fox Kitten, UNC757, Parisite)
- **Lemon Sandstorm** (formerly Rubidium)
- **Peach Sandstorm** (APT33, Elfin, Refined Kitten)
- **IRGC-affiliated groups** (CyberAv3ngers)

## Threat Intelligence Summary

### Common CVEs Exploited
- **CVE-2024-24919**: Check Point Security Gateway Information Disclosure
- **CVE-2024-3400**: Palo Alto Networks PAN-OS Command Injection
- **CVE-2023-3519 & CVE-2019-19781**: Citrix NetScaler vulnerabilities
- **CVE-2022-1388**: F5 BIG-IP Authentication Bypass
- **CVE-2024-21887**: Ivanti Connect Secure Command Injection
- **CVE-2021-26855**: Exchange Server ProxyLogon SSRF
- **CVE-2023-23397**: Outlook Elevation of Privilege/NTLM Relay
- **CVE-2020-1472**: Zerologon - Windows Netlogon Elevation of Privilege
- **CVE-2023-38950, CVE-2023-38951, CVE-2023-38952**: ZKTeco BioTime vulnerabilities

### Key TTPs
- Initial access via VPN/firewall exploitation
- Web shell deployment (GLASSTOKEN, RecShell, DropShell)
- Use of remote access tools (AnyDesk, Ngrok, Ligolo, MeshCentral)
- Credential harvesting and lateral movement
- Collaboration with ransomware affiliates (BlackCat/ALPHV, NoEscape)
- Use of Cobalt Strike and custom backdoors (Havoc, HanifNet, SystemBC)
- Exchange Server compromise for email collection
- Outlook exploitation for NTLM credential theft

## Files Included

### Wazuh Rules
1. **0910-iranian-cve-detection-rules.xml** - CVE-specific detection rules
2. **0911-iranian-apt-behavior-rules.xml** - Behavioral detection rules
3. **0912-iranian-apt-network-rules.xml** - Network-based detection rules
4. **0913-iranian-apt-fim-rules.xml** - File Integrity Monitoring rules
5. **0914-iranian-apt-windows-rules.xml** - Windows-specific detection rules

### Configuration Files
6. **sysmon-config-iranian-apt.xml** - Sysmon configuration for enhanced logging
7. **ossec-agent-iranian-apt.conf** - Wazuh agent configuration snippet
8. **iranian-apt.rules** - Suricata IDS signatures

### Documentation
9. **README.md** - Installation and configuration guide
10. **SOC-Quick-Reference-Iranian-APT.md** - Quick reference for SOC analysts
11. **MITRE-ATT&CK-Mapping.md** - Complete MITRE framework mapping
12. **Sector-Vulnerability-Analysis.md** - Energy, defense, and veteran sector analysis
13. **PROJECT-SUMMARY.md** - Executive summary of the project
14. **STRUCTURE.md** - Repository organization guide
15. **CONTRIBUTING.md** - Contribution guidelines
16. **CHANGELOG.md** - Version history

### Tools
17. **test-rules.sh** - Automated rule validation script

## Installation Instructions

### Prerequisites
- Wazuh Manager 4.7.0 or higher
- Wazuh Dashboard access with administrative privileges
- For Windows monitoring: Sysmon installed on Windows agents
- For network monitoring: Suricata 6.0 or higher

### Part 1: Wazuh Configuration

#### Step 1: Access Wazuh Dashboard
1. Log into your Wazuh Dashboard with administrative credentials
2. Navigate to **Management** > **Rules**

#### Step 2: Upload Custom Rules via Dashboard

##### Method A: Using the Rules Management Interface
1. In the Wazuh Dashboard, go to **Management** > **Rules** > **Manage rule files**
2. Click **Add new rule file**
3. For each `.xml` rule file:
   - Enter the filename (e.g., `0910-iranian-cve-detection-rules.xml`)
   - Copy and paste the content from the file
   - Click **Save**
4. Repeat for all rule files

##### Method B: Using the API Console
1. Navigate to **Dev Tools** > **API Console**
2. Use the following API call for each rule file:

```json
PUT /rules/files/{filename}
{
  "content": "<!-- paste rule content here -->"
}
```

#### Step 3: Configure Agents

##### For Windows Agents with Sysmon:
1. Install Sysmon on the Windows agent:
   ```powershell
   .\Sysmon64.exe -accepteula -i sysmon-config-iranian-apt.xml
   ```

2. Update the agent configuration:
   - Navigate to **Management** > **Configuration** > **Edit agent configuration**
   - Select the agent or agent group
   - Add the contents from `ossec-agent-iranian-apt.conf`
   - Save the configuration

##### For Linux Agents:
1. Navigate to **Management** > **Configuration** > **Edit agent configuration**
2. Add relevant log file monitoring based on your services (Apache, Nginx, etc.)

#### Step 4: Create Custom Decoders (if needed)

Some rules may require custom decoders. Navigate to **Management** > **Decoders** and ensure all necessary decoders are present.

#### Step 5: Restart Services

1. From the Dashboard, navigate to **Management** > **Configuration**
2. Click **Restart manager** to apply the new rules
3. Agents will automatically receive the updated configuration

#### Step 6: Verify Installation

1. Navigate to **Management** > **Rules**
2. Search for rule IDs starting with 1009xx to confirm rules are loaded
3. Check **Events** tab for any syntax errors

### Part 2: Suricata Configuration

#### Step 1: Install Suricata

##### On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
```

##### On CentOS/RHEL:
```bash
sudo yum install epel-release
sudo yum install suricata
```

#### Step 2: Configure Suricata

1. Edit the main configuration file:
   ```bash
   sudo nano /etc/suricata/suricata.yaml
   ```

2. Configure the network interface:
   ```yaml
   af-packet:
     - interface: eth0  # Change to your interface
       cluster-id: 99
       cluster-type: cluster_flow
   ```

3. Set the HOME_NET variable to your internal network:
   ```yaml
   vars:
     address-groups:
       HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
       EXTERNAL_NET: "!$HOME_NET"
   ```

#### Step 3: Install Iranian APT Rules

1. Copy the rules file:
   ```bash
   sudo cp iranian-apt.rules /etc/suricata/rules/
   ```

2. Edit the suricata.yaml to include the rules:
   ```yaml
   rule-files:
     - iranian-apt.rules
   ```

3. Test the configuration:
   ```bash
   sudo suricata -T -c /etc/suricata/suricata.yaml
   ```

4. Start Suricata:
   ```bash
   sudo systemctl start suricata
   sudo systemctl enable suricata
   ```

#### Step 4: Configure Wazuh to Read Suricata Alerts

Add to the Wazuh agent configuration:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

### Testing and Validation

#### Run Automated Tests
1. Make the test script executable:
   ```bash
   chmod +x tools/test-rules.sh
   ```

2. Run the validation script:
   ```bash
   sudo ./tools/test-rules.sh
   ```

#### Test Alert Generation
1. Create a test file to trigger FIM rules:
   ```bash
   # On Windows
   echo "test" > C:\inetpub\wwwroot\test.aspx
   
   # On Linux
   echo "test" > /var/www/html/test.jsp
   ```

2. Monitor the **Alerts** dashboard for rule triggers

#### Verify MITRE ATT&CK Mapping
1. Navigate to **Security Operations** > **MITRE ATT&CK**
2. Confirm that new techniques are being mapped

#### Test Suricata Rules
1. Make the test script executable:
   ```bash
   chmod +x test-rules.sh
   ```

2. Generate test traffic:
   ```bash
   curl -H "X-F5-Auth-Token: test" -H "X-Forwarded-Host: localhost" http://target/mgmt/tm/util/bash
   ```

2. Check Suricata logs:
   ```bash
   tail -f /var/log/suricata/fast.log
   ```

## Alert Response Recommendations

### Critical Alerts (Level 15-16)
- **Immediate Investigation Required**
- CVE exploitation attempts
- Known Iranian APT tool execution
- Multiple attack stages detected
- Exchange/Outlook compromise indicators

### High Priority Alerts (Level 14)
- **Investigation within 1 hour**
- Suspicious PowerShell execution
- Remote access tool installation
- Off-hours administrative activity
- Web shell creation

### Medium Priority Alerts (Level 13)
- **Investigation within 4 hours**
- Network reconnaissance
- Unusual file creation patterns
- Failed authentication spikes

## Integration with SOAR/SIEM

These rules can be integrated with your existing security stack:

1. **Splunk Integration**: Forward alerts using the Wazuh Splunk app
2. **Elasticsearch**: Alerts are already indexed and can be queried
3. **TheHive**: Use Wazuh4TheHive for automated case creation
4. **PagerDuty/Slack**: Configure integrations for critical alerts

## Threat Landscape: Additional Vulnerabilities

### Energy Sector Vulnerabilities
Iranian actors have shown particular interest in:
- **SCADA/ICS Systems**: Vulnerabilities in Schneider Electric, Siemens, and ABB controllers
- **CVE-2022-29303**: SolarView Compact Command Injection
- **CVE-2021-22205**: GitLab CE/EE RCE (used against energy companies)
- **DNP3 Protocol Weaknesses**: Industrial protocol manipulation
- **Modbus Vulnerabilities**: Unencrypted industrial communications

### Defense Sector Targets
- **CVE-2023-2868**: Barracuda ESG Zero-Day (defense contractors targeted)
- **Supply Chain Software**: Vulnerabilities in procurement and logistics systems
- **CAD/Engineering Software**: AutoCAD, CATIA, and similar design tools
- **Classified Network Gateways**: Cross-domain solution vulnerabilities

### Veteran-Adjacent Services ("Soft Targets")
Iranian actors may target veterans through:

1. **Healthcare Systems**
   - VA hospital networks and patient portals
   - CVE-2023-34362**: MOVEit Transfer SQL Injection
   - Medical device vulnerabilities (insulin pumps, pacemakers)
   - Telehealth platforms

2. **Benefits and Financial Services**
   - USAA, Navy Federal Credit Union systems
   - VA benefits portals
   - Military pension systems
   - TSP (Thrift Savings Plan) platforms

3. **Employment Services**
   - ClearanceJobs, Corporate Gray, RecruitMilitary
   - LinkedIn profiles with military experience
   - Defense contractor job boards
   - Security clearance verification systems

4. **Retail and Services**
   - Exchange/Commissary systems
   - Veterans discount verification services (ID.me, SheerID)
   - Military-focused retailers
   - Base housing management systems

### Predicted Future Targets
Based on Iranian TTPs and geopolitical objectives:
- **Municipal Water Systems**: Smaller utilities with limited security budgets
- **Agricultural Technology**: GPS-guided equipment, irrigation systems
- **Transportation Infrastructure**: Port management systems, rail control
- **Educational Institutions**: Universities with defense research programs
- **Cryptocurrency Exchanges**: For sanctions evasion and fundraising

## Maintenance and Updates

### Regular Updates
- Review Iranian APT threat intelligence weekly
- Update rules when new CVEs are disclosed
- Test rules in a staging environment first

### Performance Monitoring
- Monitor Wazuh Manager CPU/Memory usage
- Adjust rule frequency if performance issues occur
- Use alert grouping for high-volume rules
- Monitor Suricata packet drops

## References and Attribution

This ruleset is based on public threat intelligence from:
- CISA Cybersecurity Advisories (AA24-241A, AA23-335A)
- Microsoft Threat Intelligence
- Mandiant/Google Cloud Threat Intelligence
- CrowdStrike Intelligence Reports
- Recorded Future Iranian Threat Analysis
- Various security researchers and incident response teams

## License

This project is released under the MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome. Please:
1. Fork the repository
2. Create a feature branch
3. Test your rules thoroughly
4. Submit a pull request with details

## Additional Documentation

- **MITRE ATT&CK Mapping**: See `MITRE-ATT&CK-Mapping.md` for complete technique coverage
- **Sector Analysis**: See `Sector-Vulnerability-Analysis.md` for industry-specific threats
- **Quick Reference**: See `SOC-Quick-Reference-Iranian-APT.md` for operational guidance
- **Contributing**: See `CONTRIBUTING.md` for how to submit improvements
- **Testing**: Run `./test-rules.sh` to validate your installation

## Support

For issues or questions:
- Check Wazuh documentation: https://documentation.wazuh.com
- Review rule syntax guide: https://documentation.wazuh.com/current/user-manual/ruleset/
- Suricata documentation: https://suricata.readthedocs.io
- Submit issues via GitHub

## Disclaimer

These rules are provided as-is for defensive purposes. Ensure you have proper authorization before implementing monitoring in your environment. False positives may occur and rules should be tuned for your specific environment.