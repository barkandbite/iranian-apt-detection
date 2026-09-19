#!/usr/bin/env python3
"""
Static linter for the Wazuh + Suricata rulesets.

Every check corresponds to a defect that actually reached HEAD and was only
caught by loading the rules into a real engine. xmllint and ElementTree pass
on all of them, which is why they survived.

Exit codes:
    0  clean
    1  one or more ERROR-level findings

Usage:
    python3 tools/lint-rules.py [--warn-only]
"""

import argparse
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WAZUH_GLOB = os.path.join(REPO, "wazuh-rules", "*.xml")
SURICATA_GLOB = os.path.join(REPO, "suricata", "*.rules")
AR_GLOB = os.path.join(REPO, "configurations", "*active-response*")

findings = []


def err(check, path, msg):
    findings.append(("ERROR", check, os.path.relpath(path, REPO), msg))


# Verified against wazuh-analysisd 4.14.7 (option table extracted from binary).
VALID_RULE_OPTS = {
    'match', 'regex', 'decoded_as', 'category', 'field', 'srcip', 'dstip',
    'srcport', 'dstport', 'user', 'srcuser', 'dstuser', 'program_name',
    'hostname', 'time', 'weekday', 'id', 'url', 'location', 'action',
    'status', 'extra_data', 'system_name', 'protocol', 'data', 'srcgeoip',
    'dstgeoip', 'if_sid', 'if_group', 'if_level', 'if_matched_sid',
    'if_matched_group', 'if_matched_level',
    'same_source_ip', 'same_srcip', 'same_source_port', 'same_src_port',
    'same_dst_port', 'same_dstport', 'same_srcport', 'same_location',
    'same_srcuser', 'same_user', 'same_agent', 'same_id', 'same_field',
    'same_dstip', 'same_action', 'same_data', 'same_protocol', 'same_status',
    'same_url', 'same_system_name', 'same_extra_data', 'same_srcgeoip',
    'same_dstgeoip',
    'different_source_ip', 'different_srcip', 'different_user',
    'different_srcuser', 'different_id', 'different_field', 'different_url',
    'different_location', 'different_dstip', 'different_dstport',
    'different_srcport', 'different_action', 'different_data',
    'different_protocol', 'different_status', 'different_system_name',
    'different_extra_data', 'different_src_port', 'different_dst_port',
    'different_srcgeoip', 'different_dstgeoip',
    'description', 'info', 'options', 'check_diff', 'list', 'mitre',
    'group', 'compiled_rule', 'noalert', 'fts', 'global_frequency',
}

# analysisd rejects <field name="X"> for these: "Field is static".
STATIC_FIELDS = {
    'srcip', 'dstip', 'url', 'srcport', 'dstport', 'user', 'srcuser',
    'dstuser', 'program_name', 'hostname', 'id', 'status', 'action',
    'protocol', 'data', 'extra_data', 'system_name', 'location',
}

VALID_WEEKDAYS = {
    'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday',
    'sunday', 'weekdays', 'weekends',
}

# Constructs the default OS_Regex engine rejects; require type="pcre2".
PCRE_ONLY = re.compile(
    r'\\\$|\\\(|\\\)|\\\||\\\.|\\\\|\\/|\{\d|\(\?|\[\^|\\d|\\w|\\s|\\x'
    r'|\+\?|\*\?|\([^)]*\|'
)


def lint_wazuh():
    seen_ids = defaultdict(list)

    for path in sorted(glob.glob(WAZUH_GLOB)):
        raw = open(path, encoding='utf-8').read()

        try:
            ET.parse(path)
        except ET.ParseError as e:
            err('xml-parse', path, f'not well-formed: {e}')
            continue

        # Wazuh OS_XML has no CDATA support; it reads "<!" as a comment open.
        if 'CDATA' in raw:
            err('cdata', path,
                'CDATA is unsupported by Wazuh OS_XML -- it parses "<!" as a '
                'comment opener and reports "Element not closed". Use &lt; &gt; &amp;')

        # PCRE2 here is not built in UTF mode.
        for m in re.finditer(r'\\u[0-9A-Fa-f]{4}', raw):
            err('unicode-escape', path,
                f'{m.group(0)} is invalid; PCRE2 is not in UTF mode. Match the '
                'UTF-8 byte sequence instead.')

        # "--" inside an XML comment body makes the file non-well-formed.
        for m in re.finditer(r'<!--(.*?)-->', raw, re.S):
            if '--' in m.group(1):
                err('comment-double-hyphen', path,
                    'XML comment body contains "--", which is not permitted')

        body_nc = re.sub(r'<!--.*?-->', '', raw, flags=re.S)

        for m in re.finditer(r'<rule\s+id="(\d+)"([^>]*)>(.*?)</rule>', body_nc, re.S):
            rid, attrs, body = m.group(1), m.group(2), m.group(3)
            seen_ids[rid].append(path)

            lvl = re.search(r'level="(\d+)"', attrs)
            if lvl and int(lvl.group(1)) > 16:
                err('level-range', path,
                    f'rule {rid} level={lvl.group(1)}; valid range is 0-16. '
                    'analysisd HARD-FAILS to start, taking the whole ruleset offline.')

            for tag in re.findall(r'<([a-zA-Z_][a-zA-Z0-9_]*)[\s/>]', body):
                if tag not in VALID_RULE_OPTS:
                    err('invalid-option', path,
                        f'rule {rid}: <{tag}> is not a valid Wazuh rule option')

            for fm in re.finditer(r'<field\s+name="([^"]+)"', body):
                if fm.group(1) in STATIC_FIELDS:
                    err('static-field', path,
                        f'rule {rid}: <field name="{fm.group(1)}"> rejected -- '
                        f'"Field is static". Use <{fm.group(1)}>.')

            # Sysmon groups: events 1-9 have NO underscore, 10+ DO.
            # sysmon_event_3 does not exist; the rule is silently ignored.
            for sm2 in re.finditer(r'sysmon_event_([1-9])\b', body):
                err('sysmon-group-naming', path,
                    f'rule {rid}: "sysmon_event_{sm2.group(1)}" is not a Wazuh group. '
                    f'Events 1-9 have no underscore: use "sysmon_event{sm2.group(1)}". '
                    'The rule loads but is silently ignored.')

            # if_group reads the whole string as ONE group name; "|" is the OR.
            for gm in re.finditer(r'<if_group>([^<]*)</if_group>', body):
                if ',' in gm.group(1):
                    err('if_group-comma', path,
                        f'rule {rid}: <if_group>{gm.group(1)}</if_group> is read as a '
                        'single literal group name. Use "|" as the separator.')

            # same_agent was removed; analysisd warns and ignores it.
            if re.search(r'<same_agent\s*/>', body):
                err('deprecated-anchor', path,
                    f'rule {rid}: same_agent is deprecated and non-functional in '
                    'Wazuh 4.x. Use same_location for agent correlation.')

            # if_sid takes Wazuh rule IDs, not Windows Event IDs.
            for im2 in re.finditer(r'<if_sid>\s*([\d,\s]*\b4\d{3}\b[\d,\s]*)</if_sid>', body):
                err('if_sid-windows-eventid', path,
                    f'rule {rid}: <if_sid>{im2.group(1)}</if_sid> looks like a Windows '
                    'Event ID, not a Wazuh rule ID. Use <if_group>windows</if_group> '
                    'plus a win.system.eventID field match.')

            if 'frequency=' in attrs:
                if not re.search(r'<if_matched_(sid|group|level)>', body):
                    err('frequency-no-if-matched', path,
                        f'rule {rid}: frequency= without if_matched_* -- analysisd: '
                        '"Invalid use of frequency/context options."')
                if not re.search(r'<(same|different)_\w+(\s*/>|[\s>])', body):
                    err('frequency-no-anchor', path,
                        f'rule {rid}: frequency= with no same_*/different_* anchor; '
                        'counts across all hosts. Use same_agent for host correlation '
                        '(source IP is unreliable behind NAT).')

            for tm in re.finditer(r'<(regex|field)([^>]*?)>(.*?)</\1>', body, re.S):
                tag, tattrs, val = tm.group(1), tm.group(2) or '', tm.group(3)
                if 'pcre2' not in tattrs and PCRE_ONLY.search(val):
                    err('needs-pcre2', path,
                        f'rule {rid}: <{tag}> uses PCRE syntax without type="pcre2"; '
                        f'OS_Regex rejects it: {val[:50]}')

            for im in re.finditer(r'<(srcip|dstip)([^>]*)>(.*?)</\1>', body, re.S):
                tag, val = im.group(1), im.group(3).strip()
                if ',' in val or '|' in val:
                    err('ip-list', path,
                        f'rule {rid}: <{tag}> accepts one address/CIDR only; '
                        f'"{val[:40]}" is rejected. Use a CDB list.')
                elif re.search(r'[\\^$()\[\]]', val):
                    err('ip-regex', path,
                        f'rule {rid}: <{tag}> does not accept regex. Use a CDB list '
                        'with lookup="address_match_key".')

            for wm in re.finditer(r'<weekday>(.*?)</weekday>', body, re.S):
                if '|' in wm.group(1):
                    err('weekday', path,
                        f'rule {rid}: <weekday> separator must be "," not "|"')
                for day in re.split(r'[,\|]', wm.group(1).strip()):
                    if day and day.strip().lower() not in VALID_WEEKDAYS:
                        err('weekday', path,
                            f'rule {rid}: invalid weekday "{day.strip()}"')

    for rid, paths in sorted(seen_ids.items()):
        if len(paths) > 1:
            err('duplicate-id', paths[0],
                f'rule id {rid} defined {len(paths)} times: '
                + ', '.join(os.path.basename(p) for p in paths))


def lint_active_response():
    for path in sorted(glob.glob(AR_GLOB)):
        if path.endswith('README.md'):
            continue
        raw = open(path, encoding='utf-8').read()
        # Docs legitimately quote the broken syntax to explain it.
        raw = re.sub(r'<!--.*?-->', '', raw, flags=re.S)

        for m in re.finditer(r'<rules_id>([^<]*)</rules_id>', raw):
            if '-' in m.group(1):
                err('rules_id-range', path,
                    f'<rules_id>{m.group(1)}</rules_id> -- hyphenated ranges are NOT '
                    'expanded; this matches nothing. Enumerate with commas.')

        for m in re.finditer(r'<level>([^<]*)</level>', raw):
            if ',' in m.group(1):
                err('level-list', path,
                    f'<level>{m.group(1)}</level> -- level is a single integer')

        if '<expect>' in raw:
            err('obsolete-expect', path, '<expect> was removed in Wazuh 4.2')

        for m in re.finditer(r'<integration>(.*?)</integration>', raw, re.S):
            nm = re.search(r'<name>([^<]*)</name>', m.group(1))
            if nm:
                name = nm.group(1).strip()
                allowed = {'slack', 'pagerduty', 'virustotal', 'shuffle', 'maltiverse'}
                if name not in allowed and not name.startswith('custom-'):
                    err('integration-name', path,
                        f'integration "{name}" is neither stock {sorted(allowed)} nor '
                        '"custom-" prefixed; integratord logs "File not found inside '
                        "'integrations'\".")

        for m in re.finditer(r'<active-response>(.*?)</active-response>', raw, re.S):
            block = m.group(1)
            if re.search(r'<location>\s*all\s*</location>', block):
                lvl = re.search(r'<level>(\d+)</level>', block)
                if not lvl or int(lvl.group(1)) < 14:
                    err('blast-radius', path,
                        'location=all without a level floor >=14 runs the response on '
                        'every enrolled agent for a single alert.')

        if not path.endswith('.example'):
            for pat in (r'hooks\.slack\.com/services/YOUR', r'YOUR_[A-Z_]*API_KEY',
                        r'@company\.com'):
                if re.search(pat, raw):
                    err('placeholder', path,
                        'ships placeholder endpoints outside a .example file; a '
                        'copy-paste deploy fails silently')


def lint_suricata():
    for path in sorted(glob.glob(SURICATA_GLOB)):
        sids = defaultdict(int)
        for line in open(path, encoding='utf-8'):
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            sm = re.search(r'\bsid:(\d+)', s)
            if sm:
                sids[sm.group(1)] += 1
            sid = sm.group(1) if sm else '?'

            # dsize is a per-packet uint16; >65535 can never match.
            for dm in re.finditer(r'dsize:\s*>\s*(\d+)', s):
                if int(dm.group(1)) > 65535:
                    err('dsize-overflow', path,
                        f'sid {sid}: dsize:>{dm.group(1)} exceeds the uint16 '
                        'packet-size range (max 65535); can never match.')

            mm = re.search(r'msg:"([^"]*)"', s)
            if mm and not mm.group(1).startswith('Bark&Bite IRANIAN-APT '):
                err('msg-format', path,
                    f'sid {sid}: msg must start with "Bark&Bite IRANIAN-APT " -- '
                    f'got "{mm.group(1)[:45]}"')

        for sid, n in sorted(sids.items()):
            if n > 1:
                err('duplicate-sid', path, f'sid {sid} defined {n} times')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--warn-only', action='store_true')
    args = ap.parse_args()

    lint_wazuh()
    lint_active_response()
    lint_suricata()

    errors = [f for f in findings if f[0] == 'ERROR']
    for sev, check, path, msg in findings:
        print(f'{sev} [{check}] {path}: {msg}')
    print()
    print(f'{len(errors)} error(s)')
    return 1 if errors and not args.warn_only else 0


if __name__ == '__main__':
    sys.exit(main())
