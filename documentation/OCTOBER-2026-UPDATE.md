# Update: Iranian APT Detection Rules

## Version: 4.0.26
## Date: 2026-10-29
## Author: Ben Barker / Bark & Bite Security

### Summary
Integrates the Blinder Tunnel campaign (cluster CL-STA-1178, Unit 42
2026-10-06): an Iranian-nexus intrusion set targeting Iraqi critical
infrastructure through a fake "Dubai Airport Careers" portal and a
weaponized Visual Studio `.csproj` project file. Adds network coverage
for the campaign's GitHub-based ShelbyC2 V2 channel, Chisel tunneling
infrastructure, and phishing domain clusters, plus host-side Wazuh parity.

### New Threats Addressed
- **APT Group**: CL-STA-1178 (Iranian-nexus; low-confidence overlap with
  Screening Serpens / Agent Serpens; Elastic: "The Shelby Strategy")
- **Campaign**: Blinder Tunnel (staged Nov 2025, active from Mar 2026,
  published Oct 2026)
- **TTPs**: Weaponized `.csproj` MSBuild `GetFrameworkPaths` override
  execution, `RuntimeBroker.exe`/`vshost32.exe` sideloading, in-memory
  PowerShell (PsProxy), GitHub contents-API C2 with per-machine
  `Lic.txt`/`Inf.txt` files, GitHub issue-search fallback channel,
  Chisel reverse SOCKS via the Blackwood loader, ETW disablement.
- **IOCs**: 6 phishing domains (.cam/.online Google-themed), 4 C2/staging
  IPs, `peakyblinders-tm` GitHub account, 2 lure archive names,
  distinctive host artifacts (RuntimeBrokers directory, MicrosoftRuntime
  Run key, Blackwood config files).

### Rules Added
| Rule Type | Rule IDs | Description | MITRE ATT&CK |
|-----------|----------|-------------|--------------|
| Suricata | 2000576-2000577 | Phishing domain DNS queries (.cam / .online clusters) | T1566.002 |
| Suricata | 2000578 | Chisel/Blackwood C2 infrastructure outbound | T1090 |
| Suricata | 2000579 | GitHub peakyblinders-tm repo path (account IOC) | T1102 |
| Suricata | 2000580 | Behavioral: contents-API /{16-hex}/Lic\|Inf.txt tasking poll | T1102 |
| Suricata | 2000581 | Lure archive download (DubaiAirport / WarUnPublishedDocuments) | T1566.001 |
| Wazuh | 101545-101549 | ShelbyLoader masquerade, Run key, vshost sideload, Blackwood/ETW artifacts, MSBuild spawn (new file 0925) | T1574.001, T1547.001, T1036.005, T1562.006, T1127.001 |

### Rules Modified
| Rule Type | Rule IDs | Change Description | Reason |
|-----------|----------|-------------------|---------|
| (none in this repo) | — | — | — |

### Rules Deprecated
| Rule Type | Rule IDs | Reason | Replacement |
|-----------|----------|---------|-------------|
| (none) | — | — | — |

### Testing Performed
- [x] Syntax validation — `suricata -T` (7.0.3) zero errors on all 458 rules;
  `xmllint --noout` clean on all 16 Wazuh XML files
- [x] False positive testing — benign GitHub contents-API poll and benign
  `.cam`-lookalike DNS confirmed non-alerting in PCAP tests
- [x] Performance impact assessment — all new HTTP rules carry fast_pattern
  anchors and thresholds; DNS rules anchored on TLD content match
- [x] Integration testing — SID parity with barkbite-suricata-by-country
  verified identical (458 SIDs, full rule text)
- [ ] Rollback tested — standard procedure below, not re-executed this cycle

### Deployment Notes
- SID 2000579 (GitHub repo path) only matches plaintext HTTP or
  TLS-inspected traffic; SID 2000580 is the rotation-resistant behavioral
  companion and the higher-value alert (priority 1).
- SID 2000578 is an IP IOC set — expect decay; verify attribution before
  acting on isolated hits (Hetzner-hosted endpoint serves other tenants).

### Known Issues
- ShelbyC2's fallback channel (api.github.com/search/issues with a
  yyyymmdd query, AES blob in issue comments) is not covered: no
  distinguishing UA/header has been published and the URI alone would
  false-positive on legitimate API clients.

### Rollback Procedure
```bash
git checkout v4.0.25 -- suricata/iranian-apt-detection.rules
rm wazuh-rules/0925-iranian-apt-october2026-blindertunnel.xml
sudo systemctl restart suricata wazuh-manager
```

### References
- Unit 42, "Blinder Tunnel (CL-STA-1178) Targets Iraqi Critical
  Infrastructure", 2026-10-06:
  https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
