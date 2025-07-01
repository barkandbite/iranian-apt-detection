#!/bin/bash
# Test script for Iranian APT detection rules
# Version: 1.0
# This script validates Wazuh rules and Suricata signatures

set -e

echo "Iranian APT Detection Rules - Validation Script"
echo "=============================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script should be run as root for full functionality"
   echo "Some tests may fail without proper permissions"
fi

# Function to test Wazuh rules
test_wazuh_rules() {
    echo -e "\n[*] Testing Wazuh Rules..."
    
    if ! command -v /var/ossec/bin/wazuh-logtest &> /dev/null; then
        echo "[-] wazuh-logtest not found. Is Wazuh installed?"
        return 1
    fi
    
    # Test each rule file
    for rulefile in wazuh-rules/*.xml; do
        echo "[*] Validating $rulefile"
        
        # Check XML syntax
        if command -v xmllint &> /dev/null; then
            xmllint --noout "$rulefile" 2>/dev/null && echo "[+] XML syntax valid" || echo "[-] XML syntax error in $rulefile"
        fi
        
        # Copy to test location
        sudo cp "$rulefile" /var/ossec/etc/rules/ 2>/dev/null || echo "[-] Could not copy $rulefile"
    done
    
    # Test rule loading
    echo "[*] Testing rule compilation..."
    sudo /var/ossec/bin/wazuh-logtest -V 2>/dev/null | grep -q "error" && echo "[-] Rule compilation errors found" || echo "[+] Rules compiled successfully"
}

# Function to test Suricata rules
test_suricata_rules() {
    echo -e "\n[*] Testing Suricata Rules..."
    
    if ! command -v suricata &> /dev/null; then
        echo "[-] Suricata not found. Is Suricata installed?"
        return 1
    fi
    
    # Test rule syntax
    echo "[*] Validating Suricata rules syntax..."
    suricata -T -S suricata/iranian_apt_v2.rules -l /tmp 2>&1 | grep -E "(error|invalid)" && echo "[-] Suricata rule errors found" || echo "[+] Suricata rules valid"
}

# Function to generate test events
generate_test_events() {
    echo -e "\n[*] Generating test events..."
    
    # Test CVE patterns (safe, non-functional)
    echo "[*] Testing CVE detection patterns..."
    
    # Test Check Point pattern
    curl -s -o /dev/null -H "User-Agent: Test" "http://localhost/clients/MyCRL" 2>/dev/null || true
    
    # Test F5 pattern
    curl -s -o /dev/null -H "X-F5-Auth-Token: test" -H "X-Forwarded-Host: localhost" "http://localhost/mgmt/tm/util/bash" 2>/dev/null || true
    
    # Test Exchange pattern
    curl -s -o /dev/null -H "X-AnonResource-Backend: test" "http://localhost/owa/auth/Current/" 2>/dev/null || true
    
    echo "[+] Test events generated (check your SIEM for alerts)"
}

# Function to check dependencies
check_dependencies() {
    echo -e "\n[*] Checking dependencies..."
    
    deps=("xmllint" "curl" "grep" "sed")
    for dep in "${deps[@]}"; do
        if command -v $dep &> /dev/null; then
            echo "[+] $dep found"
        else
            echo "[-] $dep not found (optional)"
        fi
    done
}

# Function to validate MITRE mappings
validate_mitre() {
    echo -e "\n[*] Validating MITRE ATT&CK mappings..."
    
    # Extract all MITRE IDs from rules
    grep -h "<id>T[0-9]" wazuh-rules/*.xml | sed 's/.*<id>\(T[0-9.]*\)<\/id>.*/\1/' | sort -u > /tmp/mitre_ids.txt
    
    echo "[+] Found $(wc -l < /tmp/mitre_ids.txt) unique MITRE techniques"
    
    # Check for common techniques
    common_techniques=("T1190" "T1059" "T1055" "T1003" "T1021")
    for technique in "${common_techniques[@]}"; do
        grep -q "$technique" /tmp/mitre_ids.txt && echo "[+] $technique mapped" || echo "[-] $technique not found"
    done
    
    rm -f /tmp/mitre_ids.txt
}

# Function to test specific CVE patterns
test_cve_patterns() {
    echo -e "\n[*] Testing CVE pattern detection..."
    
    # Create test log entries
    test_logs=(
        "GET /clients/MyCRL$/../../../etc/passwd HTTP/1.1"
        "POST /owa/auth/Current/themes HTTP/1.1"
        "GET /ssl-vpn/hipreport.esp?SESSID=../../ HTTP/1.1"
        "POST /mgmt/tm/util/bash HTTP/1.1"
    )
    
    for log in "${test_logs[@]}"; do
        echo "[*] Testing: $log"
        echo "$log" | /var/ossec/bin/wazuh-logtest -q 2>/dev/null | grep -q "Alert" && echo "[+] Detection triggered" || echo "[-] No detection"
    done
}

# Main execution
main() {
    check_dependencies
    test_wazuh_rules
    test_suricata_rules
    validate_mitre
    
    read -p "Generate test events? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        generate_test_events
    fi
    
    echo -e "\n[*] Testing complete!"
    echo "[*] Review your SIEM for any triggered alerts"
    echo "[*] Check /var/ossec/logs/alerts/alerts.log for Wazuh alerts"
    echo "[*] Check /var/log/suricata/fast.log for Suricata alerts"
}

# Run main function
main
