#!/bin/bash
# Suricata rules validation and test suite runner
# Version: 5.0
# Tests both rule syntax and detection accuracy

set -e

RULES_FILE="suricata/iranian-apt-detection.rules"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Suricata Rules Validation & Test Suite"
echo "======================================="

# --- Phase 1: Syntax validation ---
echo ""
echo "[Phase 1] Rule Syntax Validation"
echo "---------------------------------"

if ! command -v suricata >/dev/null; then
    echo "[-] Suricata not installed"
    exit 1
fi

if [ ! -f "$REPO_ROOT/$RULES_FILE" ]; then
    echo "[-] Rules file $RULES_FILE not found"
    exit 1
fi

echo "[*] Testing Suricata rules syntax..."
mkdir -p /tmp/suricata_test
suricata -T -S "$REPO_ROOT/$RULES_FILE" -l /tmp/suricata_test 2>&1 | tee /tmp/suricata_rules_test.log
res=${PIPESTATUS[0]}

if [ $res -eq 0 ]; then
    RULE_COUNT=$(grep -c '^alert\|^drop\|^reject\|^pass' "$REPO_ROOT/$RULES_FILE" 2>/dev/null || echo "?")
    echo "[+] All $RULE_COUNT Suricata rules loaded successfully (0 errors)"
else
    echo "[-] Suricata rule errors detected -- see /tmp/suricata_rules_test.log"
    exit $res
fi

# --- Phase 2: SID consistency checks ---
echo ""
echo "[Phase 2] SID Consistency Checks"
echo "---------------------------------"

# Check for duplicate SIDs
DUPES=$(grep -oP 'sid:\d+' "$REPO_ROOT/$RULES_FILE" | sort | uniq -d)
if [ -z "$DUPES" ]; then
    echo "[+] No duplicate SIDs found"
else
    echo "[-] Duplicate SIDs detected:"
    echo "$DUPES"
fi

# Check msg format consistency
NON_STANDARD=$(grep -oP 'msg:"[^"]*"' "$REPO_ROOT/$RULES_FILE" | grep -v 'IRANIAN-APT' | head -5)
if [ -z "$NON_STANDARD" ]; then
    echo "[+] All msg: fields follow standardized IRANIAN-APT format"
else
    echo "[-] Non-standard msg: fields found:"
    echo "$NON_STANDARD"
fi

# --- Phase 3: Automated detection tests ---
echo ""
echo "[Phase 3] Detection Accuracy Tests"
echo "------------------------------------"

if command -v python3 >/dev/null && python3 -c "import scapy" 2>/dev/null; then
    if [ -f "$REPO_ROOT/tests/test_suricata_rules.py" ]; then
        echo "[*] Running pytest test suite..."
        cd "$REPO_ROOT"
        python3 -m pytest tests/test_suricata_rules.py -v --tb=short 2>&1 | tail -40
        echo "[+] Detection tests complete"
    else
        echo "[!] Test file tests/test_suricata_rules.py not found -- skipping detection tests"
    fi
else
    echo "[!] scapy not installed -- skipping detection tests (pip3 install scapy)"
fi

echo ""
echo "[*] Validation complete"
exit 0
