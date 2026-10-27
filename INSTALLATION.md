# Installation Guide

## Prerequisites (read first)

### Sysmon is required for most of this ruleset

142 Wazuh rule conditions depend on Sysmon event groups
(`sysmon_event_1/3/6/7/8/10/11/13/20/22`). Without Sysmon on your Windows
endpoints and the Wazuh Sysmon decoders in place, **the majority of this
ruleset cannot fire at all**. Sysmon-dominant files, effectively inert
without it: `0911`, `0914`, `0915`, `0917`, `0918`, `0919`, `0920`, `0921`,
`0923`, `0924`.

1. Install Sysmon 13+ on Windows endpoints.
2. Apply `configurations/sysmon-config-iranian-apt.xml`.
3. Confirm the agent forwards the Sysmon EventChannel.
4. Verify decoding:

```bash
/var/ossec/bin/wazuh-logtest -v
# paste a Sysmon event; Phase 2 must show
#   win.system.providerName: 'Microsoft-Windows-Sysmon'
# If Phase 2 shows no decoder, the Sysmon rules cannot match.
```

### CDB lists are required by some rules

Rules 100947, 101004, 101013, 101148, 101149 and all of
`0925-ioc-list-matching.xml` reference CDB lists. Install and declare them or
those rules never match. See [cdb-lists/README.md](cdb-lists/README.md).

### Versions

- Wazuh 4.3+ manager and agents (validated against 4.14.7)
- Suricata 7.0+ (validated against 7.0.3)
- Sysmon 13+ on Windows endpoints
- Python 3.8+ for the tooling

### Validate before you trust it

```bash
xmllint --noout wazuh-rules/*.xml       # necessary, NOT sufficient
python3 tools/lint-rules.py             # known defect classes
sudo /var/ossec/bin/wazuh-analysisd -t  # authoritative
sudo suricata -T -S suricata/iranian-apt-detection.rules -l /tmp
```

Wazuh's XML parser is stricter than standard XML and `analysisd` rejects
constructs `xmllint` accepts. An invalid rule aborts its whole file; an
invalid `level` aborts manager startup entirely.


This guide covers deployment of the Wazuh XML rules and Suricata network signatures contained in this repository.

## Prerequisites
- **Wazuh** 4.3 or later
- **Suricata** 6.0 or later
- Root or sudo privileges on the target system

## 1. Clone the Repository
```bash
git clone https://github.com/BarkandBite/iranian-apt-detection.git
cd iranian-apt-detection
```

## 2. Install Wazuh Rules
### Option A – Individual Rule Files
```bash
sudo cp wazuh-rules/09*.xml /var/ossec/etc/rules/
sudo chown ossec:ossec /var/ossec/etc/rules/09*.xml
sudo chmod 660 /var/ossec/etc/rules/09*.xml
```

### Option B – Consolidated File
```bash
sudo cp archive/0900-iranian-apt-detection-master.xml /var/ossec/etc/rules/
sudo chown ossec:ossec /var/ossec/etc/rules/0900-iranian-apt-detection-master.xml
sudo chmod 660 /var/ossec/etc/rules/0900-iranian-apt-detection-master.xml
```

Restart the manager to load the rules:
```bash
sudo systemctl restart wazuh-manager
```

## 3. Install Suricata Rules
```bash
sudo cp suricata/iranian-apt-detection.rules /etc/suricata/rules/
```
Add the file to `suricata.yaml` under `rule-files`:
```yaml
rule-files:
  - iranian-apt-detection.rules
```
Validate the configuration and reload Suricata:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
```

## 4. Optional Active Response
```bash
sudo cp tools/iranian-apt-active-response.sh /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/iranian-apt-active-response.sh
# Insert XML from configurations/iranian-apt-active-response.xml.example into ossec.conf
sudo systemctl restart wazuh-manager
```

## 5. Validation
Use the included script to perform basic checks:
```bash
sudo ./tools/test.sh
```
The script validates rule syntax and can generate sample events. Review `/var/ossec/logs/alerts/alerts.log` and `/var/log/suricata/fast.log` for alerts.

## Troubleshooting Tips
- If `wazuh-logtest` is missing, ensure Wazuh is installed correctly.
- For Suricata rule errors, run `suricata -T` to identify the problem rule.
- Check permissions on the rule files if they fail to load.
