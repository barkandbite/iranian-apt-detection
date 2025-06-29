#!/bin/bash
# Deploy Iranian APT Active Response Components
# Version: 2.0
# Last Updated: 2025-06-29

set -e

echo "================================================"
echo "Iranian APT Active Response Deployment"
echo "Bark&Bite Security"
echo "================================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Wazuh directories
WAZUH_DIR="/var/ossec"
AR_BIN_DIR="$WAZUH_DIR/active-response/bin"
WAZUH_CONF="$WAZUH_DIR/etc/ossec.conf"
WAZUH_LISTS="$WAZUH_DIR/etc/lists"

# Check Wazuh installation
if [ ! -d "$WAZUH_DIR" ]; then
    echo -e "${RED}Wazuh directory not found at $WAZUH_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Wazuh installation found${NC}"

# Create directories if needed
echo "Creating required directories..."
mkdir -p $AR_BIN_DIR
mkdir -p $WAZUH_LISTS
mkdir -p $WAZUH_DIR/logs/active-responses
mkdir -p $WAZUH_DIR/var/lock

# Deploy active response script
echo "Deploying active response script..."
if [ -f "iranian-apt-active-response.sh" ]; then
    cp iranian-apt-active-response.sh $AR_BIN_DIR/
    chmod 750 $AR_BIN_DIR/iranian-apt-active-response.sh
    chown root:wazuh $AR_BIN_DIR/iranian-apt-active-response.sh
    echo -e "${GREEN}✓ Active response script deployed${NC}"
else
    echo -e "${RED}Active response script not found in current directory${NC}"
    exit 1
fi

# Create blocklist file
touch $WAZUH_LISTS/iranian-apt-blocklist
chown wazuh:wazuh $WAZUH_LISTS/iranian-apt-blocklist
chmod 640 $WAZUH_LISTS/iranian-apt-blocklist

# Backup current configuration
echo "Backing up current configuration..."
cp $WAZUH_CONF $WAZUH_CONF.bak.$(date +%Y%m%d_%H%M%S)

# Check if active response is already configured
if grep -q "iranian-apt-response" $WAZUH_CONF; then
    echo -e "${YELLOW}Active response already configured - skipping${NC}"
else
    echo "Adding active response configuration..."
    
    # Create temporary config snippet
    cat > /tmp/iranian-apt-ar-config.xml << 'EOF'

<!-- Iranian APT Active Response Configuration -->
<command>
  <n>iranian-apt-response</n>
  <executable>iranian-apt-active-response.sh</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Critical CVE Exploitation Response -->
<active-response>
  <command>iranian-apt-response</command>
  <location>local</location>
  <rules_id>100900,100901,100902,100903,100904,100905,100906,100907,100908,100909,100910</rules_id>
  <timeout>86400</timeout>
</active-response>

<!-- Web Shell Response -->
<active-response>
  <command>iranian-apt-response</command>
  <location>local</location>
  <rules_id>100931,100990</rules_id>
</active-response>

<!-- Credential Theft Response -->
<active-response>
  <command>iranian-apt-response</command>
  <location>local</location>
  <rules_id>100934,100991,101002</rules_id>
</active-response>

<!-- Critical Infrastructure Response -->
<active-response>
  <command>iranian-apt-response</command>
  <location>all</location>
  <rules_id>100960,100964</rules_id>
</active-response>

<!-- Ransomware Response -->
<active-response>
  <command>iranian-apt-response</command>
  <location>local</location>
  <rules_id>101001</rules_id>
</active-response>

<!-- High Severity Response -->
<active-response>
  <command>iranian-apt-response</command>
  <location>local</location>
  <rules_group>iranian_apt</rules_group>
  <level>15,16</level>
</active-response>

EOF

    # Insert before closing </ossec_config> tag
    sed -i '/<\/ossec_config>/i IRANIAN_APT_MARKER' $WAZUH_CONF
    sed -i '/IRANIAN_APT_MARKER/r /tmp/iranian-apt-ar-config.xml' $WAZUH_CONF
    sed -i '/IRANIAN_APT_MARKER/d' $WAZUH_CONF
    
    rm -f /tmp/iranian-apt-ar-config.xml
    echo -e "${GREEN}✓ Configuration added to ossec.conf${NC}"
fi

# Create emergency response scripts directory
echo "Creating emergency response scripts..."
mkdir -p /opt/emergency
cat > /opt/emergency/isolate-ics.sh << 'EOF'
#!/bin/bash
# Emergency ICS isolation script
AGENT=$1
echo "$(date): Emergency ICS isolation triggered for $AGENT" >> /var/log/ics-isolation.log
# Add your ICS isolation commands here
EOF
chmod 750 /opt/emergency/isolate-ics.sh

# Create incident response directory
mkdir -p /opt/ir
cat > /opt/ir/initiate-response.sh << 'EOF'
#!/bin/bash
# Incident response initiation script
echo "$(date): IR initiated with args: $@" >> /var/log/ir-initiation.log
# Add your IR platform integration here
EOF
chmod 750 /opt/ir/initiate-response.sh

# Test configuration
echo "Testing configuration..."
$WAZUH_DIR/bin/wazuh-control --test-config
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Configuration test passed${NC}"
else
    echo -e "${RED}Configuration test failed - restoring backup${NC}"
    cp $WAZUH_CONF.bak.$(date +%Y%m%d_%H%M%S) $WAZUH_CONF
    exit 1
fi

# Create test alert function
test_active_response() {
    echo -e "\n${YELLOW}Testing active response...${NC}"
    
    # Create test alert
    $WAZUH_DIR/bin/wazuh-control --test-active-response iranian-apt-response 192.168.1.100
    
    # Check log
    if [ -f "$WAZUH_DIR/logs/active-responses/iranian-apt-response.log" ]; then
        echo -e "${GREEN}✓ Active response log created${NC}"
        tail -5 $WAZUH_DIR/logs/active-responses/iranian-apt-response.log
    else
        echo -e "${YELLOW}No log file created yet${NC}"
    fi
}

# Restart Wazuh
echo -e "\n${YELLOW}Restarting Wazuh Manager...${NC}"
systemctl restart wazuh-manager

sleep 5

# Check status
if systemctl is-active --quiet wazuh-manager; then
    echo -e "${GREEN}✓ Wazuh Manager restarted successfully${NC}"
else
    echo -e "${RED}Wazuh Manager failed to start${NC}"
    exit 1
fi

# Summary
echo -e "\n${GREEN}================================================${NC}"
echo -e "${GREEN}Active Response Deployment Complete!${NC}"
echo -e "${GREEN}================================================${NC}"

echo -e "\n${YELLOW}Configuration Summary:${NC}"
echo "- Active response script: $AR_BIN_DIR/iranian-apt-active-response.sh"
echo "- Blocklist location: $WAZUH_LISTS/iranian-apt-blocklist"
echo "- Log location: $WAZUH_DIR/logs/active-responses/iranian-apt-response.log"
echo "- Emergency scripts: /opt/emergency/"

echo -e "\n${YELLOW}Next Steps:${NC}"
echo "1. Configure email alerts: Edit <email_to> in ossec.conf"
echo "2. Set Slack webhook: Edit SLACK_WEBHOOK in active response script"
echo "3. Test with: $WAZUH_DIR/bin/wazuh-control --test-active-response iranian-apt-response <IP>"
echo "4. Monitor logs: tail -f $WAZUH_DIR/logs/active-responses/iranian-apt-response.log"

echo -e "\n${YELLOW}Important:${NC}"
echo "- Test thoroughly before production deployment"
echo "- Ensure firewall rules allow Wazuh agent connections (TCP 1514)"
echo "- Configure SOAR integration if available"
echo "- Review and customize emergency scripts for your environment"

# Optional test
read -p "Run active response test? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    test_active_response
fi

exit 0
