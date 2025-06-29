# Configuration Files for Iranian APT Detection

## Overview
This directory contains agent configurations and logging profiles optimized for Iranian APT detection.

## Files

### sysmon-config-iranian-apt.xml
Enhanced Sysmon configuration for Windows endpoints with Iranian APT-specific filters.

**Key Features**:
- Process creation monitoring for Iranian tools
- Network connection tracking to known C2 ports
- Registry persistence detection
- PowerShell script block logging
- DNS query logging

**Deployment**:
```powershell
# Install Sysmon with configuration
sysmon64 -accepteula -i sysmon-config-iranian-apt.xml

# Update existing installation
sysmon64 -c sysmon-config-iranian-apt.xml
```

### ossec-agent-iranian-apt.conf
Wazuh agent configuration snippet for comprehensive Windows monitoring.

**Includes**:
- Sysmon integration
- PowerShell operational logs
- Exchange/IIS log monitoring
- Enhanced FIM for web directories
- Critical registry monitoring

**Deployment**:
1. Append to agent's `ossec.conf`
2. Restart agent: `net stop wazuh; net start wazuh`

### iranian-apt-active-response.xml
Wazuh manager configuration for automated response to Iranian APT detections.

**Features**:
- Rule-based response actions
- Granular severity handling
- Integration configurations
- Alert routing

**Deployment**:
1. Insert into manager's `ossec.conf` before `</ossec_config>`
2. Copy active response script to `/var/ossec/active-response/bin/`
3. Restart manager: `systemctl restart wazuh-manager`

## Prerequisites

### Windows Endpoints
1. **Sysmon 13.0+** - For enhanced logging
2. **PowerShell 5.0+** - For script block logging
3. **Wazuh Agent 4.3+** - For rule compatibility
4. **.NET Framework 4.5+** - For some Sysmon features

### Linux Endpoints
1. **Auditd** - For system call monitoring
2. **Wazuh Agent 4.3+** - For rule compatibility

### Network Devices
1. **Syslog capability** - For log forwarding
2. **Time synchronization** - For accurate correlation

## Configuration Best Practices

### Sysmon Configuration

**High-Security Environments**:
- Enable all event types
- Reduce filtering exclusions
- Add custom Iranian APT indicators

**Performance-Conscious Environments**:
- Exclude noisy legitimate processes
- Limit network monitoring to specific ports
- Reduce image load monitoring

**Customization Example**:
```xml
<!-- Add custom Iranian APT process names -->
<ProcessCreate onmatch="include">
  <Image condition="contains any">your-custom-tool;specific-malware</Image>
</ProcessCreate>
```

### Wazuh Agent Configuration

**Log Collection Priorities**:
1. **Critical**: Sysmon, Security, PowerShell logs
2. **High**: Exchange, IIS, DNS Client logs
3. **Medium**: Application, System logs
4. **Low**: Performance, diagnostic logs

**FIM Tuning**:
```xml
<!-- Adjust frequency for busy servers -->
<frequency>600</frequency>  <!-- 10 minutes instead of 5 -->

<!-- Add exclusions for temporary files -->
<ignore>C:\Windows\Temp\*.tmp</ignore>
<ignore>C:\inetpub\logs\LogFiles</ignore>
```

### Active Response Configuration

**Response Levels**:
```xml
<!-- Immediate response for critical -->
<active-response>
  <rules_id>100900-100910</rules_id>  <!-- CVE exploits -->
  <timeout>0</timeout>  <!-- Permanent block -->
</active-response>

<!-- Delayed response for medium -->
<active-response>
  <rules_group>iranian_apt</rules_group>
  <level>14</level>
  <timeout>3600</timeout>  <!-- 1 hour block -->
</active-response>
```

## Integration Points

### SIEM Integration
Configure log forwarding to central SIEM:
```xml
<client>
  <server>
    <address>siem.company.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

### Threat Intelligence Feeds
Add CDB lists for Iranian IOCs:
```xml
<ossec_config>
  <lists>
    <list>etc/lists/iranian-c2-ips</list>
    <list>etc/lists/iranian-domains</list>
    <list>etc/lists/iranian-hashes</list>
  </lists>
</ossec_config>
```

## Performance Impact

### Sysmon Performance

| Setting | CPU Impact | Disk I/O | Network |
|---------|------------|----------|---------|
| Full config | 3-5% | High | Moderate |
| Reduced network | 2-3% | Moderate | Low |
| Process only | 1-2% | Low | None |

### Wazuh Agent Performance

| Component | CPU | Memory | Disk |
|-----------|-----|---------|------|
| Log reading | 1-2% | 50MB | Low |
| FIM scanning | 2-5% | 100MB | High |
| Active response | Spike | Minimal | Low |

## Troubleshooting

### Sysmon Issues
```powershell
# Check Sysmon status
sysmon64 -s

# View configuration
sysmon64 -c

# Check event log
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 10
```

### Wazuh Agent Issues
```bash
# Check agent status
/var/ossec/bin/agent_control -i 001

# Test configuration
/var/ossec/bin/wazuh-logtest

# View agent log
tail -f /var/ossec/logs/ossec.log
```

### Common Problems

| Issue | Solution |
|-------|----------|
| High CPU usage | Reduce Sysmon network monitoring |
| Disk space | Limit file change reporting in FIM |
| Missing events | Check Windows Event Log service |
| No alerts | Verify log collection configuration |

## Maintenance

### Weekly Tasks
- Review Sysmon filter effectiveness
- Check agent connectivity
- Validate active response actions

### Monthly Tasks
- Update Sysmon configuration
- Review FIM exclusions
- Test active response
- Update threat intelligence lists

### Quarterly Tasks
- Performance baseline review
- Configuration optimization
- Rule effectiveness analysis

## Security Considerations

1. **Protect Configuration Files**: Limit access to prevent tampering
2. **Encrypt Communications**: Use authd for agent registration
3. **Monitor Changes**: Alert on configuration modifications
4. **Regular Updates**: Keep Sysmon and Wazuh updated
5. **Test Changes**: Validate in lab before production
