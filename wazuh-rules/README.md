This file includes:

- **CVE Detection Rules** (100900-100919): Check Point, Palo Alto, Citrix, F5, Ivanti, Exchange, Outlook exploits
- **Behavioral Detection** (100920-100939): Remote access tools, web shells, backdoors, persistence
- **Network Detection** (100940-100959): C2 communication, port scanning, known domains
- **Unique Behaviors** (101000-101023): DNS hijacking, Tehran business hours, Farsi language, crypto mining
- **Correlation Rules**: Multi-stage attack detection

The file uses simplified syntax that should work better with the CLI method:

```bash
# SSH into your Wazuh manager
ssh root@192.168.2.196

# Navigate to rules directory
cd /var/ossec/etc/rules/

# Create the file
nano 0900-iranian-apt-detection-all.xml

# Paste the content from the artifact above

# Set permissions
chown ossec:ossec 0900-iranian-apt-detection-all.xml
chmod 660 0900-iranian-apt-detection-all.xml

# Test the configuration
/var/ossec/bin/ossec-logtest -t

# If no errors, restart Wazuh
systemctl restart wazuh-manager

# Check logs for any issues
tail -f /var/ossec/logs/ossec.log
```
