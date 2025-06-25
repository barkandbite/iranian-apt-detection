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
```

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