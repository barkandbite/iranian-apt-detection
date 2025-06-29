## Summary of New Detection Coverage

### **Suricata Rules** (16 new rules, SIDs 2000115-2000130)
- **AI-powered phishing**: React-based kits with WebSocket backends
- **IOCONTROL malware**: MQTT C2 for critical infrastructure targeting  
- **Cryptocurrency targeting**: Exchange theft and fund burning patterns
- **Azure cloud abuse**: C2 subdomains and resource manager exploitation
- **Passive backdoors**: Inbound-only connections with Bearer token auth
- **New CVEs**: 2025 zero-day series detection patterns

## Key Innovations Addressed

1. **TEMPLEDROP**: Detects abuse of legitimate Sheed AV driver for kernel persistence
2. **TEMPLELOCK**: Identifies event log thread termination for forensic evasion
3. **AI Social Engineering**: Behavioral detection of perfect grammar phishing with React frameworks
4. **IOCONTROL**: Critical infrastructure targeting via MQTT protocol on port 8883
5. **Passive Backdoors**: No-outbound-C2 detection through inbound connection patterns
6. **Azure C2 Abuse**: 125+ subdomain patterns and fraudulent subscription detection

The rules include proper **MITRE ATT&CK mapping**, **PCI DSS/GDPR compliance tags**, and **correlation logic** to detect sophisticated multi-stage campaigns while minimizing false positives through careful behavioral analysis rather than simple signature matching.
