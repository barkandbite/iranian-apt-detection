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

### deploy-new-rules.sh
Streamlined script for deploying only the newest rule updates.

**Usage**:
```bash
sudo ./deploy-new-rules.sh --rules-only
sudo ./deploy-new-rules.sh --full
```

## Safety Features

All scripts include:
- Pre-flight checks
- Backup mechanisms  
- Rollback capability
- Non-destructive testing
- Service state validation

## Testing Procedures

### Rule Validation
```bash
# Check syntax only
./test.sh --syntax-only

# Full validation
./test.sh --complete
```

### Performance Testing
```bash
# Measure rule impact
./test.sh --performance
```

### Generate Test Events
```bash
# Safe test patterns (non-functional)
./test.sh --generate-events
```

## Integration

### CI/CD Pipeline
```yaml
# .gitlab-ci.yml example
test:
  script:
    - ./tools/test.sh --syntax-only
    - ./tools/test.sh --performance
```

### Automated Deployment
```bash
# Ansible playbook example
- name: Deploy Iranian APT Rules
  script: deploy-iranian-apt-rules.sh
  become: yes
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Permission denied | Run with sudo |
| Service not found | Install Wazuh/Suricata first |
| Rule conflicts | Check rule ID allocation |
| Performance impact | Reduce rule scope |

### Rollback Procedure
```bash
# Automatic rollback
./deploy-iranian-apt-rules.sh --rollback

# Manual rollback
cp /var/ossec/etc/rules/*.bak /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

## Recent Updates

### 2025-06-27
- Added cloud deployment support
- Enhanced error handling
- Added performance metrics

### 2025-06-25
- Initial tool release
- Basic deployment automation
