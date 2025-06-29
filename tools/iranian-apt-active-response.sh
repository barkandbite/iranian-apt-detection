#!/bin/bash
# Iranian APT Active Response Script for Wazuh
# Version: 2.0
# Last Updated: 2025-06-29
#
# This script provides automated response actions for Iranian APT detections
# Supports both blocking and alerting modes with granular control

# Active response parameters from Wazuh
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT=$6

# Configuration
LOGFILE="/var/ossec/logs/active-responses/iranian-apt-response.log"
LOCKDIR="/var/ossec/var/lock"
BLOCKLIST="/var/ossec/etc/lists/iranian-apt-blocklist"
ALERT_EMAIL="security-team@company.com"
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/HERE"

# Ensure log directory exists
mkdir -p $(dirname $LOGFILE)
mkdir -p $LOCKDIR

# Logging function
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

# Send critical alert
send_alert() {
    local severity=$1
    local message=$2
    local details=$3
    
    # Email alert for critical
    if [ "$severity" == "CRITICAL" ]; then
        echo -e "Subject: [CRITICAL] Iranian APT Detection - Rule $RULEID\n\n$message\n\nDetails:\n$details" | \
            sendmail $ALERT_EMAIL
    fi
    
    # Slack notification
    if [ ! -z "$SLACK_WEBHOOK" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 Iranian APT Alert\",\"blocks\":[{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*Severity:* $severity\n*Rule:* $RULEID\n*Agent:* $AGENT\n*IP:* $IP\n*Message:* $message\"}}]}" \
            $SLACK_WEBHOOK 2>/dev/null
    fi
}

# Check if IP is internal
is_internal_ip() {
    local ip=$1
    if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        return 0
    fi
    return 1
}

# Block IP function
block_ip() {
    local ip=$1
    local duration=$2
    
    # Don't block internal IPs
    if is_internal_ip $ip; then
        log_action "SKIP: Internal IP $ip not blocked"
        return
    fi
    
    # Add to Wazuh blocklist
    echo "$ip:$RULEID:$(date +%s):$duration" >> $BLOCKLIST
    
    # Firewall blocking (iptables)
    iptables -I INPUT -s $ip -j DROP
    iptables -I FORWARD -s $ip -j DROP
    
    # Schedule unblock if duration specified
    if [ ! -z "$duration" ] && [ "$duration" -gt 0 ]; then
        echo "sleep $duration && iptables -D INPUT -s $ip -j DROP && iptables -D FORWARD -s $ip -j DROP" | at now
    fi
    
    log_action "BLOCKED: IP $ip for rule $RULEID (duration: ${duration:-permanent})"
}

# Kill process function
kill_process() {
    local pid=$1
    local process_name=$2
    
    if [ ! -z "$pid" ] && [ "$pid" -gt 0 ]; then
        kill -9 $pid 2>/dev/null
        log_action "KILLED: Process $process_name (PID: $pid)"
    fi
}

# Isolate host function
isolate_host() {
    local agent_ip=$1
    
    # Create isolation rules
    iptables -I INPUT -s $agent_ip -j DROP
    iptables -I OUTPUT -d $agent_ip -j DROP
    iptables -I INPUT -s $agent_ip -p tcp --dport 1514 -j ACCEPT  # Keep Wazuh connection
    
    log_action "ISOLATED: Host $agent_ip (agent: $AGENT)"
    send_alert "CRITICAL" "Host Isolated" "Agent $AGENT at $agent_ip has been network isolated"
}

# Main response logic based on rule groups
case $RULEID in
    # CVE Exploitation (100900-100929) - Immediate blocking
    10090[0-9]|10091[0-9]|10092[0-9])
        log_action "CVE exploitation detected - Rule $RULEID"
        block_ip $IP 86400  # 24 hour block
        send_alert "CRITICAL" "Iranian APT CVE Exploitation" "Blocked $IP for CVE exploitation attempt"
        ;;
    
    # Remote Access Tools (100930-100939) - Kill and alert
    10093[0-9])
        log_action "Remote access tool detected - Rule $RULEID"
        # Extract process info from alert
        PID=$(echo $ALERTID | grep -oP 'pid":\K[0-9]+')
        kill_process $PID "remote_access_tool"
        send_alert "HIGH" "Iranian APT Remote Access Tool" "Terminated suspicious process on $AGENT"
        ;;
    
    # Web Shells (100931, 100990) - Immediate response
    100931|100990)
        log_action "Web shell detected - Rule $RULEID"
        block_ip $IP 0  # Permanent block
        isolate_host $IP
        send_alert "CRITICAL" "Iranian APT Web Shell" "Web shell detected and host isolated"
        ;;
    
    # Credential Theft (100934, 100991, 101002) - Isolate and reset
    100934|100991|101002)
        log_action "Credential theft detected - Rule $RULEID"
        isolate_host $IP
        send_alert "CRITICAL" "Iranian APT Credential Theft" "Credential theft detected - passwords must be reset"
        # Trigger AD password reset workflow
        echo "$AGENT:$USER:$(date +%s)" >> /var/ossec/logs/password-reset-queue
        ;;
    
    # Critical Infrastructure (100960, 100964) - Maximum response
    100960|100964)
        log_action "Critical infrastructure attack - Rule $RULEID"
        block_ip $IP 0
        isolate_host $IP
        send_alert "CRITICAL" "Iranian APT ICS/SCADA Attack" "Critical infrastructure targeted - emergency response required"
        # Trigger SCADA isolation procedures
        /opt/emergency/isolate-ics.sh $AGENT
        ;;
    
    # Ransomware/Wiper (101001) - Emergency shutdown
    101001)
        log_action "Ransomware/wiper activity - Rule $RULEID"
        isolate_host $IP
        # Force shutdown to prevent encryption
        ssh root@$IP "shutdown -h now" 2>/dev/null || \
            wazuh-control --run-command $AGENT "shutdown /s /t 0 /f"
        send_alert "CRITICAL" "Iranian APT Ransomware/Wiper" "Emergency shutdown initiated for $AGENT"
        ;;
    
    # Passive Backdoor (101034) - Monitor mode
    101034)
        log_action "Passive backdoor detected - Rule $RULEID"
        # Don't block - monitor for intelligence
        echo "$IP:$RULEID:$(date +%s)" >> /var/ossec/logs/iranian-apt-monitor.log
        send_alert "HIGH" "Iranian APT Passive Backdoor" "Monitoring passive backdoor on $AGENT"
        ;;
    
    # High severity correlation rules (101090-101099) - Full lockdown
    10109[0-9])
        log_action "Multi-stage attack detected - Rule $RULEID"
        block_ip $IP 0
        isolate_host $IP
        send_alert "CRITICAL" "Iranian APT Campaign Detected" "Multi-stage nation-state attack - full incident response required"
        # Trigger full IR playbook
        /opt/ir/initiate-response.sh --severity critical --agent $AGENT --campaign iranian_apt
        ;;
    
    # Default action for other Iranian APT rules
    *)
        if [[ $RULEID =~ ^10[0-1][0-9]{3}$ ]]; then
            log_action "Iranian APT activity detected - Rule $RULEID"
            block_ip $IP 3600  # 1 hour block
            send_alert "MEDIUM" "Iranian APT Activity" "Suspicious activity blocked from $IP"
        fi
        ;;
esac

# Cleanup old blocks
if [ "$ACTION" == "delete" ]; then
    iptables -D INPUT -s $IP -j DROP 2>/dev/null
    iptables -D FORWARD -s $IP -j DROP 2>/dev/null
    sed -i "/$IP/d" $BLOCKLIST
    log_action "UNBLOCKED: IP $IP"
fi

exit 0
