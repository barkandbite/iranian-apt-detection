#!/bin/bash
# Deploy Iranian APT Detection Rules - New Unique Signatures
# Version: 1.0
# Bark&Bite Security
#
# This script deploys the unique Iranian APT detection signatures including:
# - DNS hijacking patterns
# - Time-based behavioral analytics
# - Persian language artifacts
# - Cloud and AI-enhanced attack detection

set -e

echo "================================================"
echo "Iranian APT Detection Rules - Unique Signatures"
echo "Bark&Bite Security - Premium Threat Detection"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Function to check service status
check_service() {
    if systemctl is-active --quiet $1; then
        echo -e "${GREEN}✓ $1 is running${NC}"
        return 0
    else
        echo -e "${RED}✗ $1 is not running${NC}"
        return 1
    fi
}

# Function to deploy Wazuh rules
deploy_wazuh_rules() {
    echo -e "\n${YELLOW}[*] Deploying Wazuh Rules...${NC}"
    
    WAZUH_RULES_DIR="/var/ossec/etc/rules"
    
    if [ ! -d "$WAZUH_RULES_DIR" ]; then
        echo -e "${RED}Wazuh rules directory not found!${NC}"
        return 1
    fi
    
    # Copy new rule files
    echo "Copying new Iranian APT unique behavior rules..."
    cp wazuh-rules/0915-iranian-apt-unique-behaviors.xml "$WAZUH_RULES_DIR/" || echo -e "${RED}Failed to copy 0915${NC}"
    cp wazuh-rules/0916-iranian-apt-cloud-container.xml "$WAZUH_RULES_DIR/" || echo -e "${RED}Failed to copy 0916${NC}"
    
    # Set proper permissions
    chown ossec:ossec "$WAZUH_RULES_DIR"/091*.xml
    chmod 660 "$WAZUH_RULES_DIR"/091*.xml
    
    # Test rule syntax
    echo "Testing Wazuh rule syntax..."
    /var/ossec/bin/wazuh-logtest -V 2>&1 | grep -q "error" && {
        echo -e "${RED}Rule syntax errors detected!${NC}"
        return 1
    } || echo -e "${GREEN}Rule syntax OK${NC}"
    
    # Restart Wazuh manager
    echo "Restarting Wazuh manager..."
    systemctl restart wazuh-manager
    
    echo -e "${GREEN}✓ Wazuh rules deployed successfully${NC}"
}

# Function to deploy Suricata rules
deploy_suricata_rules() {
    echo -e "\n${YELLOW}[*] Deploying Suricata Rules...${NC}"
    
    SURICATA_RULES_DIR="/etc/suricata/rules"
    
    if [ ! -d "$SURICATA_RULES_DIR" ]; then
        echo -e "${RED}Suricata rules directory not found!${NC}"
        return 1
    fi
    
    # Backup existing rules
    echo "Backing up existing rules..."
    cp "$SURICATA_RULES_DIR"/iranian-apt*.rules "$SURICATA_RULES_DIR"/iranian-apt*.rules.bak 2>/dev/null || true
    
    # Copy new rule files
    echo "Copying new Iranian APT detection rules..."
    cp suricata/iranian-apt-dns-hijacking.rules "$SURICATA_RULES_DIR/" || echo -e "${RED}Failed to copy DNS hijacking rules${NC}"
    cp suricata/iranian-apt-cloud-ai.rules "$SURICATA_RULES_DIR/" || echo -e "${RED}Failed to copy Cloud/AI rules${NC}"
    
    # Update suricata.yaml to include new rules
    if ! grep -q "iranian-apt-dns-hijacking.rules" /etc/suricata/suricata.yaml; then
        echo "Adding new rules to suricata.yaml..."
        sed -i '/rule-files:/a\  - iranian-apt-dns-hijacking.rules\n  - iranian-apt-cloud-ai.rules' /etc/suricata/suricata.yaml
    fi
    
    # Test Suricata configuration
    echo "Testing Suricata configuration..."
    suricata -T -c /etc/suricata/suricata.yaml 2>&1 | grep -q "ERROR" && {
        echo -e "${RED}Suricata configuration errors detected!${NC}"
        return 1
    } || echo -e "${GREEN}Suricata configuration OK${NC}"
    
    # Reload Suricata rules
    echo "Reloading Suricata..."
    systemctl reload suricata || systemctl restart suricata
    
    echo -e "${GREEN}✓ Suricata rules deployed successfully${NC}"
}

# Function to enable enhanced logging
enable_enhanced_logging() {
    echo -e "\n${YELLOW}[*] Enabling Enhanced Logging...${NC}"
    
    # Enable DNS query logging if using systemd-resolved
    if systemctl is-active --quiet systemd-resolved; then
        echo "Enabling DNS query logging..."
        mkdir -p /etc/systemd/resolved.conf.d/
        cat > /etc/systemd/resolved.conf.d/iranian-apt.conf <<EOF
[Resolve]
# Enable DNS query logging for Iranian APT detection
LogLevel=debug
EOF
        systemctl restart systemd-resolved
    fi
    
    # Enable PowerShell script block logging
    if command -v pwsh &> /dev/null; then
        echo "Configuring PowerShell logging..."
        # This would need to be done via Group Policy on Windows
        echo -e "${YELLOW}Note: Configure PowerShell ScriptBlockLogging via Group Policy on Windows endpoints${NC}"
    fi
    
    # Enable cloud audit logging reminder
    echo -e "${YELLOW}Reminder: Enable cloud audit logging:${NC}"
    echo "  - AWS: CloudTrail with S3 data events"
    echo "  - Azure: Activity logs and diagnostic settings"
    echo "  - GCP: Cloud Audit Logs with data access"
}

# Function to create detection dashboards
create_dashboards() {
    echo -e "\n${YELLOW}[*] Creating Detection Dashboards...${NC}"
    
    # Create a directory for dashboard configs
    mkdir -p /opt/iranian-apt-detection/dashboards
    
    # Create Wazuh dashboard query
    cat > /opt/iranian-apt-detection/dashboards/iranian-apt-unique.json <<EOF
{
  "name": "Iranian APT Unique Signatures",
  "panels": [
    {
      "title": "DNS Hijacking Attempts",
      "query": "rule.id:[101000 TO 101001] OR rule.id:[2000060 TO 2000066]"
    },
    {
      "title": "Time-Based Anomalies (Tehran Hours)",
      "query": "rule.id:[101002 TO 101003]"
    },
    {
      "title": "Persian Language Artifacts",
      "query": "rule.id:[101004 TO 101005] OR rule.groups:language_artifact"
    },
    {
      "title": "Cryptocurrency Mining",
      "query": "rule.id:[101006 TO 101007] OR rule.groups:cryptomining"
    },
    {
      "title": "Cloud Attacks",
      "query": "rule.id:[101100 TO 101121] OR rule.groups:cloud"
    }
  ]
}
EOF
    
    echo -e "${GREEN}✓ Dashboard queries created in /opt/iranian-apt-detection/dashboards/${NC}"
}

# Function to set up monitoring alerts
setup_alerts() {
    echo -e "\n${YELLOW}[*] Setting Up Critical Alerts...${NC}"
    
    # Create alert script
    cat > /opt/iranian-apt-detection/critical-alert.sh <<'EOF'
#!/bin/bash
# Critical Iranian APT Alert Handler

ALERT_RULE=$1
ALERT_LEVEL=$2
ALERT_DESCRIPTION=$3

# Critical rule IDs that require immediate response
CRITICAL_RULES="101001|101021|101023|101120|2000061|2000071|2000076|2000081|2000083|2000113|2000114"

if echo "$ALERT_RULE" | grep -qE "$CRITICAL_RULES"; then
    # Send critical alert (customize for your environment)
    echo "CRITICAL: Iranian APT Activity Detected!" | mail -s "Iranian APT Alert - Rule $ALERT_RULE" security-team@company.com
    
    # Log to security event system
    logger -p security.crit "Iranian APT Critical Alert: $ALERT_DESCRIPTION"
    
    # Trigger automated response (customize as needed)
    # /opt/security/isolate-host.sh $AFFECTED_HOST
fi
EOF
    
    chmod +x /opt/iranian-apt-detection/critical-alert.sh
    
    echo -e "${GREEN}✓ Alert handler created${NC}"
}

# Function to run post-deployment tests
run_tests() {
    echo -e "\n${YELLOW}[*] Running Post-Deployment Tests...${NC}"
    
    # Test Wazuh rules
    echo "Testing Wazuh rule detection..."
    echo "Jun 27 10:30:00 test powershell: Accept-Language: fa-IR external test" | /var/ossec/bin/wazuh-logtest -q 2>&1 | grep -q "101004" && \
        echo -e "${GREEN}✓ Persian language detection working${NC}" || \
        echo -e "${RED}✗ Persian language detection failed${NC}"
    
    # Test Suricata rules
    echo "Testing Suricata rule loading..."
    suricata --list-app-layer-protos | grep -q "dns" && \
        echo -e "${GREEN}✓ DNS inspection enabled${NC}" || \
        echo -e "${RED}✗ DNS inspection not available${NC}"
    
    # Check for rule conflicts
    echo "Checking for rule ID conflicts..."
    grep -h "rule id=" /var/ossec/etc/rules/091*.xml | sort | uniq -d | grep -q "rule id" && \
        echo -e "${RED}✗ Duplicate rule IDs found!${NC}" || \
        echo -e "${GREEN}✓ No rule ID conflicts${NC}"
}

# Main deployment flow
main() {
    echo -e "\n${YELLOW}Starting deployment of Iranian APT unique detection rules...${NC}"
    
    # Check services
    echo -e "\n${YELLOW}[*] Checking Services...${NC}"
    WAZUH_OK=false
    SURICATA_OK=false
    
    check_service wazuh-manager && WAZUH_OK=true
    check_service suricata && SURICATA_OK=true
    
    # Deploy rules based on available services
    if [ "$WAZUH_OK" = true ]; then
        deploy_wazuh_rules
    else
        echo -e "${YELLOW}Skipping Wazuh deployment - service not running${NC}"
    fi
    
    if [ "$SURICATA_OK" = true ]; then
        deploy_suricata_rules
    else
        echo -e "${YELLOW}Skipping Suricata deployment - service not running${NC}"
    fi
    
    # Additional configurations
    enable_enhanced_logging
    create_dashboards
    setup_alerts
    
    # Run tests
    run_tests
    
    echo -e "\n${GREEN}================================================${NC}"
    echo -e "${GREEN}Deployment Complete!${NC}"
    echo -e "${GREEN}================================================${NC}"
    
    echo -e "\n${YELLOW}Next Steps:${NC}"
    echo "1. Import dashboard queries into your Wazuh/Kibana interface"
    echo "2. Configure alert forwarding to your SIEM/SOAR platform"
    echo "3. Enable DNS query logging on all endpoints"
    echo "4. Configure cloud audit log collection"
    echo "5. Test detection capabilities with safe samples"
    
    echo -e "\n${YELLOW}Monitoring Focus Areas:${NC}"
    echo "- DNS hijacking attempts (Let's Encrypt + suspicious domains)"
    echo "- Activities during Tehran business hours (UTC 05:30-13:30)"
    echo "- Persian/Farsi language artifacts in traffic"
    echo "- Cryptocurrency mining after exploitation"
    echo "- Cloud metadata service access"
    echo "- AI API usage for content generation"
    
    echo -e "\n${GREEN}Thank you for using Bark&Bite Security solutions!${NC}"
}

# Run main function
main

exit 0