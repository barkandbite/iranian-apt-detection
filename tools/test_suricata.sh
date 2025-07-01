#!/bin/bash
# Suricata rules validation script
# Version: 1.0
# Only tests Suricata IDS rules

set -e

RULES_FILE="suricata/iranian_apt_v2.rules"

echo "Suricata Rules Validation"
echo "========================="

if ! command -v suricata >/dev/null; then
    echo "[-] Suricata not installed"
    exit 1
fi

if [ ! -f "$RULES_FILE" ]; then
    echo "[-] Rules file $RULES_FILE not found"
    exit 1
fi

echo "[*] Testing Suricata rules syntax..."
suricata -T -S "$RULES_FILE" -l /tmp 2>&1 | tee /tmp/suricata_rules_test.log
res=${PIPESTATUS[0]}

if [ $res -eq 0 ]; then
    echo "[+] Suricata rules loaded successfully"
else
    echo "[-] Suricata rule errors detected"
fi

exit $res
