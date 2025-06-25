# MITRE ATT&CK Mapping for Iranian APT Detection Rules

## Initial Access
- **T1190 - Exploit Public-Facing Application**
  - Rules: 100900-100919 (CVE exploitation)
  - CVEs: 2024-24919, 2024-3400, 2023-3519, 2022-1388, 2024-21887, 2021-26855
- **T1133 - External Remote Services**
  - Rules: 100947 (External access to sensitive services)
- **T1566.001 - Spearphishing Attachment**
  - Rules: 100974 (Outlook-related files)

## Execution
- **T1059 - Command and Scripting Interpreter**
  - Rules: 100902, 100907, 100908, 100922, 100925, 100937
- **T1059.001 - PowerShell**
  - Rules: 100932, 100980, 100981
- **T1059.004 - Unix Shell**
  - Rules: 100907
- **T1047 - Windows Management Instrumentation**
  - Rules: 100930, 100990
- **T1053.005 - Scheduled Task**
  - Rules: 100925, 100998
- **T1569.002 - Service Execution**
  - Rules: 100985

## Persistence
- **T1505.003 - Web Shell**
  - Rules: 100915, 100922, 100923, 100936, 100960, 100961, 100973
- **T1547.001 - Registry Run Keys**
  - Rules: 100926, 100965, 100992
- **T1543.003 - Windows Service**
  - Rules: 100965, 100984, 100985
- **T1098 - Account Manipulation**
  - Rules: 100987
- **T1136.001 - Local Account**
  - Rules: 100986

## Privilege Escalation
- **T1068 - Exploitation for Privilege Escalation**
  - Rules: 100910, 100911 (Zerologon)
- **T1078 - Valid Accounts**
  - Rules: 100911, 100929, 100986, 100988
- **T1078.002 - Domain Accounts**
  - Rules: 100987
- **T1548 - Abuse Elevation Control Mechanism**
  - Rules: 100906

## Defense Evasion
- **T1562.001 - Disable or Modify Tools**
  - Rules: 100931, 100994
- **T1562.002 - Disable Windows Event Logging**
  - Rules: 100983
- **T1562.004 - Disable or Modify System Firewall**
  - Rules: 100964
- **T1070 - Indicator Removal**
  - Rules: 100967, 100982, 100983
- **T1070.001 - Clear Windows Event Logs**
  - Rules: 100967, 100982, 100983
- **T1027 - Obfuscated Files or Information**
  - Rules: 100923, 100932, 100960, 100981
- **T1036.007 - Double File Extension**
  - Rules: 100961
- **T1055 - Process Injection**
  - Rules: 100924, 100972, 100993, 100995
- **T1140 - Deobfuscate/Decode Files or Information**
  - Rules: 100981
- **T1112 - Modify Registry**
  - Rules: 100926, 100992
- **T1222 - File and Directory Permissions Modification**
  - Rules: 100964

## Credential Access
- **T1003 - OS Credential Dumping**
  - Rules: 100927, 100966, 100975, 100991
- **T1003.001 - LSASS Memory**
  - Rules: 100975, 100991
- **T1003.002 - Security Account Manager**
  - Rules: 100928
- **T1187 - Forced Authentication**
  - Rules: 100918, 100919, 100938
- **T1557 - Adversary-in-the-Middle**
  - Rules: 100918, 100956
- **T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay**
  - Rules: 100918, 100938
- **T1552 - Unsecured Credentials**
  - Rules: 100966
- **T1552.002 - Credentials in Registry**
  - Rules: 100928
- **T1555 - Credentials from Password Stores**
  - Rules: 100927, 100991

## Discovery
- **T1046 - Network Service Discovery**
  - Rules: 100933, 100946
- **T1018 - Remote System Discovery**
  - Rules: 100933
- **T1083 - File and Directory Discovery**
  - Rules: 100904
- **T1595 - Active Scanning**
  - Rules: 100900, 100909, 100913, 100941
- **T1595.001 - Scanning IP Blocks**
  - Rules: 100946
- **T1595.002 - Vulnerability Scanning**
  - Rules: 100900, 100913

## Lateral Movement
- **T1021 - Remote Services**
  - Rules: 100929, 100984, 100988
- **T1021.001 - Remote Desktop Protocol**
  - Rules: 100988
- **T1021.006 - Windows Remote Management**
  - Rules: 100930, 100990
- **T1210 - Exploitation of Remote Services**
  - Rules: 100901, 100903, 100905, 100910, 100914

## Collection
- **T1074 - Data Staged**
  - Rules: 100970, 100971
- **T1074.001 - Local Data Staging**
  - Rules: 100970
- **T1005 - Data from Local System**
  - Rules: 100975
- **T1114.001 - Local Email Collection**
  - Rules: 100971
- **T1114.002 - Remote Email Collection**
  - Rules: 100917
- **T1560 - Archive Collected Data**
  - Rules: 100970

## Command and Control
- **T1071.001 - Web Protocols**
  - Rules: 100934, 100941, 100945, 100949
- **T1071.004 - DNS**
  - Rules: 100948
- **T1090 - Proxy**
  - Rules: 100921
- **T1090.001 - Internal Proxy**
  - Rules: 100952
- **T1095 - Non-Application Layer Protocol**
  - Rules: 100940, 100944, 100954
- **T1102 - Web Service**
  - Rules: 100934, 100954
- **T1102.002 - Bidirectional Communication**
  - Rules: 100949
- **T1132 - Data Encoding**
  - Rules: 100945
- **T1219 - Remote Access Software**
  - Rules: 100920
- **T1571 - Non-Standard Port**
  - Rules: 100940, 100950
- **T1572 - Protocol Tunneling**
  - Rules: 100921, 100952
- **T1573 - Encrypted Channel**
  - Rules: 100950
- **T1001 - Data Obfuscation**
  - Rules: 100944
- **T1072 - Software Deployment Tools**
  - Rules: 100920
- **T1106 - Native API**
  - Rules: 100924
- **T1204.002 - Malicious File**
  - Rules: 100974
- **T1608.001 - Upload Malware**
  - Rules: 100962

## Exfiltration
- **T1041 - Exfiltration Over C2 Channel**
  - Rules: 100942, 100943
- **T1048 - Exfiltration Over Alternative Protocol**
  - Rules: 100942, 100948, 100953
- **T1048.003 - Exfiltration Over Unencrypted Protocol**
  - Rules: 100948
- **T1029 - Scheduled Transfer**
  - Rules: 100953
- **T1567 - Exfiltration Over Web Service**
  - Rules: 100943

## Impact
- **T1486 - Data Encrypted for Impact**
  - Rules: 100935, 100951, 100968, 100995
- **T1490 - Inhibit System Recovery**
  - Rules: 100935, 100968, 100969, 100989
- **T1485 - Data Destruction**
  - Rules: 100989
- **T1089 - Disabling Security Tools**
  - Rules: 100931, 100994
- **T1203 - Exploitation for Client Execution**
  - Rules: 100916, 100957
- **T1657 - Financial Theft**
  - Rules: 100951