This file includes:

- **CVE Detection Rules** (100900-100919): Check Point, Palo Alto, Citrix, F5, Ivanti, Exchange, Outlook exploits
- **Behavioral Detection** (100920-100939): Remote access tools, web shells, backdoors, persistence
- **Network Detection** (100940-100959): C2 communication, port scanning, known domains
- **Unique Behaviors** (101000-101023): DNS hijacking, Tehran business hours, Farsi language, crypto mining
- **Correlation Rules**: Multi-stage attack detection

**New Advanced Rules (100960-100999):**

- **MuddyWater** PowGoop DLL side-loading
- **APT34/OilRig** QUADAGENT persistence
- **APT35/Charming Kitten** PowerLess backdoor (enhanced)
- **APT35/TA455** SnailResin malware
- **APT33** TurnedUp YARA detection

**Deployment Instructions:**
The file uses simplified syntax that should work better with the CLI method:
'''bash
# SSH into Wazuh manager
ssh root@192.168.2.196

# Navigate to rules directory
cd /var/ossec/etc/rules/

# Create the master rule file
nano 0900-iranian-apt-detection-master.xml

# Paste the content from above

# Set permissions
chown ossec:ossec 0900-iranian-apt-detection-master.xml
chmod 660 0900-iranian-apt-detection-master.xml

# Validate configuration
/var/ossec/bin/ossec-logtest -t

# Restart Wazuh
systemctl restart wazuh-manager

# Monitor logs
tail -f /var/ossec/logs/ossec.log
```
