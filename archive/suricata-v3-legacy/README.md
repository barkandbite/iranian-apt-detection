# Archived Suricata Rule Files (v3.x Legacy)

These files have been superseded by the consolidated `suricata/iranian-apt-detection.rules` (v4.0).

## Files

| File | Rules | Status |
|------|-------|--------|
| `iranian_apt_v3.1.rules` | 199 | Fully contained within v3_2; all SIDs present in consolidated file |
| `iranian_apt_v3_2.rules` | 241 | Base for consolidation; all SIDs present in consolidated file |
| `iranian_apt_v3_3_expansion.rules` | 97 | 60 SIDs collided with v3_2 (different rules, same SID numbers); renumbered to SIDs 2000360-2000456 in consolidated file. 37 unique SIDs (2000194-2000230) preserved as-is. |

## Why Consolidate?

The three versioned files had **199 duplicate SIDs** when loaded together (all of v3.1 overlapped with v3_2) plus **60 SID collisions** between v3_2 and v3_3 (same SID numbers assigned to completely different rules). Loading all three files in Suricata caused silent rule overrides with no warning.

The consolidated file resolves all conflicts:
- v3_2 rules kept their original SIDs
- v3_3 collision rules renumbered to SIDs 2000360-2000456
- v3_3 unique rules (2000194-2000230) kept original SIDs
- Zero duplicate SIDs in the final file

## Archived: 2026-03-30
