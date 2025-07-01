# Installation Guide

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
sudo cp suricata/iranian_apt_v2.rules /etc/suricata/rules/
```
Add the file to `suricata.yaml` under `rule-files`:
```yaml
rule-files:
  - iranian_apt_v2.rules
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
# Insert XML from configurations/iranian-apt-active-response.xml into ossec.conf
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
