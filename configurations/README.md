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

## Best Practices

### Windows Endpoints
1. Deploy Sysmon before Wazuh agent
2. Enable PowerShell script block logging via GPO
3. Configure audit policies for process creation
4. Enable command line auditing

### Linux Endpoints
1. Enable auditd with provided rules
2. Monitor SSH logs
3. Configure FIM for web directories
4. Enable SELinux/AppArmor logging

### Network Devices
1. Enable syslog forwarding
2. Configure verbose logging
3. Monitor authentication attempts
4. Log configuration changes

## Integration Testing

Test log collection:
```bash
# Windows
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 10

# Linux  
ausearch -m execve -ts recent

# Wazuh
tail -f /var/ossec/logs/alerts/alerts.json | grep iranian_apt
```

## Performance Impact

| Component | CPU Impact | Memory | Disk I/O |
|-----------|------------|---------|----------|
| Sysmon | 2-5% | 50MB | Moderate |
| Wazuh Agent | 1-3% | 100MB | Low |
| PowerShell Logging | 1-2% | Minimal | High |

## Recent Updates

### 2025-06-29
- Added HTTP.sys monitoring for TOFUDRV detection
- Enhanced process injection detection
- Added Azure PowerShell module monitoring

### 2025-06-25
- Initial release with core monitoring capabilities
