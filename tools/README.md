# Tools for Iranian APT Detection Deployment

## Overview
This directory contains automation scripts for deploying and testing the Iranian APT detection rules.

## Scripts

### test.sh
Basic validation script for Wazuh rules and Suricata signatures.

**Features**:
- XML syntax validation
- Rule ID conflict detection
- Basic functionality testing
- Safe traffic generation

**Usage**:
```bash
sudo ./test.sh
```

### deploy-iranian-apt-rules.sh
Advanced deployment script with safety checks and rollback capability.

**Features**:
- Service detection
- Backup creation
- Syntax validation
- Dashboard creation
- Alert configuration

**Usage**:
```bash
sudo ./deploy-iranian-apt-rules.sh
```

### iranian-apt-active-response.sh
Wazuh active response script for automated threat mitigation.

**Features**:
- IP blocking with time limits
- Process termination
- Host isolation
- Emergency shutdown for ransomware
- Slack/email notifications
- Passive backdoor monitoring

**Installation**:
```bash
sudo cp iranian-apt-active-response.sh /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/iranian-apt-active-response.sh
sudo chown root:wazuh /var/ossec/active-response/bin/iranian-apt-active-response.sh
```

### deploy-active-response.sh
Automated deployment script for active response components.

**Features**:
- Automatic configuration insertion
- Directory creation
- Permission setting
- Configuration backup
- Post-deployment testing

**Usage**:
```bash
sudo ./deploy-active-response.sh
```

## Configuration Requirements

### Email Notifications
Edit the active response script to set your email:
```bash
ALERT_EMAIL="security-team@company.com"
```

### Slack Integration
Set your webhook URL:
```bash
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/HERE"
```

### SOAR Integration
Configure in Wazuh ossec.conf:
```xml
<integration>
  <name>iranian-apt-soar</name>
  <api_key>YOUR_API_KEY</api_key>
  <hook_url>https://soar.company.com/api/v1/incidents</hook_url>
</integration>
```

## Response Actions by Rule Category

| Rule Range | Action | Duration | Severity |
|------------|---------|----------|----------|
| 100900-100929 (CVE) | Block IP | 24 hours | Critical |
| 100930-100939 (Tools) | Kill process | N/A | High |
| 100931,100990 (Webshell) | Isolate host | Permanent | Critical |
| 100934,100991,101002 (Creds) | Isolate + Reset | Permanent | Critical |
| 100960,100964 (ICS) | Full lockdown | Permanent | Critical |
| 101001 (Ransomware) | Emergency shutdown | N/A | Critical |
| 101034 (Passive) | Monitor only | N/A | High |
| 101090-101099 (Campaign) | Full IR | Permanent | Critical |

## Testing Active Response

### Test IP Blocking
```bash
/var/ossec/bin/wazuh-control --test-active-response iranian-apt-response 192.168.1.100
```

### Check Logs
```bash
tail -f /var/ossec/logs/active-responses/iranian-apt-response.log
```

### Verify Firewall Rules
```bash
iptables -L -n | grep DROP
```

## Safety Features

### Internal IP Protection
The script will not block RFC1918 addresses:
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16

### Wazuh Connection Preservation
When isolating hosts, TCP/1514 remains open for Wazuh communication.

### Automatic Unblocking
Temporary blocks are automatically removed using `at` scheduler.

## Troubleshooting

### Script Not Executing
1. Check permissions: `ls -la /var/ossec/active-response/bin/`
2. Verify in ossec.conf: `<command>` and `<active-response>` sections
3. Check logs: `/var/ossec/logs/ossec.log`

### No Blocking Occurring
1. Verify iptables is installed
2. Check script logs for errors
3. Ensure running as root
4. Test manually: `iptables -I INPUT -s 1.2.3.4 -j DROP`

### Email/Slack Not Working
1. Test sendmail: `echo "test" | sendmail user@domain.com`
2. Test Slack webhook with curl
3. Check network connectivity
4. Verify webhook URL format

## Emergency Procedures

### Disable All Active Response
```bash
# Edit ossec.conf and set:
<active-response>
  <disabled>yes</disabled>
</active-response>

# Restart Wazuh
systemctl restart wazuh-manager
```

### Remove All Blocks
```bash
# Flush iptables rules (careful!)
iptables -F INPUT
iptables -F FORWARD

# Clear blocklist
> /var/ossec/etc/lists/iranian-apt-blocklist
```

### Rollback Deployment
```bash
# Restore configuration backup
cp /var/ossec/etc/ossec.conf.bak.* /var/ossec/etc/ossec.conf
systemctl restart wazuh-manager
```

## Best Practices

1. **Test in Lab First**: Always test active response in non-production
2. **Start Conservative**: Begin with monitoring, add blocking gradually
3. **Document Changes**: Log all configuration modifications
4. **Regular Reviews**: Check blocked IPs weekly
5. **Incident Tracking**: Correlate blocks with tickets
6. **Performance Monitoring**: Watch CPU/memory during responses

## Integration Examples

### Splunk Integration
```bash
# Forward response logs to Splunk
echo "iranian_apt_response,src_ip=$IP,rule=$RULEID,action=blocked" >> /var/log/splunk/iranian_apt.log
```

### ServiceNow Integration
```bash
# Create incident via API
curl -X POST https://instance.service-now.com/api/now/table/incident \
  -H "Authorization: Basic $SNOW_AUTH" \
  -d "{\"short_description\":\"Iranian APT Alert - Rule $RULEID\",\"urgency\":\"1\"}"
```

## Updates and Maintenance

- Review and update response actions monthly
- Test active response after Wazuh updates
- Monitor for false positive patterns
- Adjust thresholds based on environment
