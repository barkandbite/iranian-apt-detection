#!/usr/bin/env python3
"""
Generate Wazuh CDB lists from the Suricata ruleset.

    python3 tools/extract-iocs.py            # write cdb-lists/
    python3 tools/extract-iocs.py --check    # fail if stale (CI)

=============================================================================
TIERING -- read before using any output as a blocklist
=============================================================================

Attackers abuse legitimate infrastructure. A naive extraction of every domain
and IP mentioned in the ruleset produces a "blocklist" that, if enforced,
breaks DNS resolution, software distribution, and your own alerting pipeline,
because the rules reference those services in order to detect abuse OF them.

  T1  malicious-domains-t1     Dedicated actor-controlled domains. BLOCKABLE.

  T2  malicious-fqdn-t2        A malicious FQDN hosted under a shared provider
                               (e.g. line.completely.workers.dev). Block the
                               EXACT FQDN only -- never the parent, which
                               would take out every tenant of that provider,
                               including yours.

  T3  detect-only-providers    Legitimate providers referenced because they
                               are abused (github.com, api.telegram.org,
                               dns.google...). DETECT ONLY. Never block.

  IP  malicious-ip             Actor IPs, public resolvers excluded.

Hard exclusions, asserted on every run:
  * 1.1.1.1 -- appears in a rule header, but that rule detects IOCONTROL
    using Cloudflare DoH for evasion. Cloudflare is not the threat.
  * Everything in LEGIT_PROVIDERS.
"""

import argparse
import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SURICATA_GLOB = os.path.join(REPO, "suricata", "*.rules")
OUT_DIR = os.path.join(REPO, "cdb-lists")

LEGIT_PROVIDERS = {
    "dns.google", "google.com", "drive.google.com", "cloudflare-dns.com",
    "cloudflare.com", "workers.dev", "github.com", "githubusercontent.com",
    "raw.githubusercontent.com", "gist.github.com", "api.github.com",
    "graph.microsoft.com", "microsoft.com", "onedrive.live.com", "live.com",
    "office.com", "sharepoint.com", "azurewebsites.net", "windows.net",
    "firebaseapp.com", "firebaseio.com", "firebase.com", "backblazeb2.com",
    "wasabisys.com", "amazonaws.com", "s3.amazonaws.com", "bit.ly",
    "tinyurl.com", "ngrok.io", "ngrok.com", "screenconnect.com",
    "net.anydesk.com", "anydesk.com", "atera.com", "syncromsp.com", "pdq.com",
    "netbird.io", "zerotier.com", "deno.land", "api.telegram.org",
    "telegram.org", "discord.com", "discordapp.com", "glitch.me", "somee.com",
    "duckdns.org", "ddnsking.com", "file.io", "filemail.com",
    "mesh.meshcentral.com", "meshcentral.com", "simple-help.com",
    "logmein.com", "teamviewer.com", "dropbox.com", "box.com",
    "mediafire.com", "pastebin.com",
    # Caught by reviewing generated T1 output rather than assumed up front.
    # Blocking these would break a legitimate SaaS or a shared provider.
    "onlyoffice.com",    # Screening Serpens staged payloads on OnlyOffice
    "privatedns.org",    # shared dynamic-DNS parent (Infy DGA lives under it)
    "it.com",            # shared registry
}

IP_EXCLUDE = {
    "1.1.1.1", "1.0.0.1",                 # Cloudflare resolver (DoH evasion detection)
    "8.8.8.8", "8.8.4.4",                 # Google resolver
    "9.9.9.9",                            # Quad9
    "208.67.222.222", "208.67.220.220",   # OpenDNS
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
}

# Final labels indicating a filename or header token misparsed as a domain.
# ".zip" is a real gTLD but here only ever appears as a filename.
NON_TLD_LABELS = {
    'php', 'zip', 'exe', 'dll', 'aspx', 'jsp', 'asp', 'html', 'htm', 'js',
    'py', 'ps1', 'bat', 'cmd', 'sh', 'txt', 'xml', 'json', 'pdf', 'doc',
    'docx', 'xls', 'xlsx', 'rar', 'apk', 'hta', 'lnk', 'msi', 'jar', 'bin',
    'dat', 'log', 'ini', 'conf', 'cfg', 'tmp', 'bak', 'sig', 'github',
    'dmg', 'iso', 'vhd', 'img', 'sys', 'scr', 'png', 'jpg', 'gif', 'aspnet',
}

IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
DOMAIN_RE = re.compile(
    r'\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b', re.I)
DOMAIN_BUFFERS = ('http.host', 'http_host', 'tls.sni', 'dns.query', 'dns_query')

HEADER = ("# GENERATED FILE -- do not edit by hand.\n"
          "# Regenerate:  python3 tools/extract-iocs.py\n"
          "# Source:      suricata/*.rules\n")


def suffix_match(domain, provider):
    d = domain.lower().rstrip('.')
    p = provider.lower()
    return d == p or d.endswith('.' + p)


def is_legit(domain):
    return any(suffix_match(domain, p) for p in LEGIT_PROVIDERS)


def parse_rules():
    ips, domains = set(), set()
    for path in sorted(glob.glob(SURICATA_GLOB)):
        for line in open(path, encoding='utf-8'):
            s = line.strip()
            if not s or s.startswith('#'):
                continue

            head = s.split('(', 1)[0]
            for ip in IP_RE.findall(head):
                if all(0 <= int(o) <= 255 for o in ip.split('.')):
                    ips.add(ip)

            opts = s.split('(', 1)[1] if '(' in s else ''
            in_domain_buffer = False
            for opt in opts.split(';'):
                o = opt.strip()
                low = o.lower()
                if any(low.startswith(b) for b in DOMAIN_BUFFERS):
                    in_domain_buffer = True
                    continue
                if low.startswith('content:') and in_domain_buffer:
                    cm = re.search(r'content:\s*!?"([^"]+)"', o)
                    if cm:
                        for d in DOMAIN_RE.findall(cm.group(1).lstrip('.')):
                            d = d.lower()
                            if d.rsplit('.', 1)[-1] not in NON_TLD_LABELS:
                                domains.add(d)
                elif low.startswith(('pcre:', 'flow:', 'msg:', 'metadata:')):
                    in_domain_buffer = False
    return ips, domains


def tier(domains):
    t1, t2, t3 = set(), set(), set()
    for d in sorted(domains):
        if is_legit(d):
            if any(d.lower() == p.lower() for p in LEGIT_PROVIDERS):
                t3.add(d)
            else:
                t2.add(d)
                t3.add(next(p for p in LEGIT_PROVIDERS if suffix_match(d, p)))
        else:
            t1.add(d)
    return t1, t2, t3


def render(entries, value):
    return HEADER + ''.join(f"{e}:{value}\n" for e in sorted(entries))


def build():
    ips, domains = parse_rules()
    ips = {i for i in ips if i not in IP_EXCLUDE}
    t1, t2, t3 = tier(domains)
    return {
        'malicious-ip': render(ips, 'iranian_apt_c2'),
        'malicious-domains-t1': render(t1, 'iranian_apt_c2'),
        'malicious-fqdn-t2': render(t2, 'iranian_apt_c2_shared_host'),
        'detect-only-providers': render(t3, 'abused_legitimate_service'),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    gen = build()

    # A naive extractor gets these wrong; fail loudly rather than ship an
    # output that would cause an outage.
    blockable = gen['malicious-ip'] + gen['malicious-domains-t1']
    for bad in IP_EXCLUDE:
        assert f'\n{bad}:' not in blockable, f'{bad} leaked into a blockable list'
    for prov in LEGIT_PROVIDERS:
        assert f'\n{prov}:' not in gen['malicious-domains-t1'], \
            f'legit provider {prov} leaked into T1 blockable'
    for junk in ('content.zip', 'submit.php', 'vnd.github'):
        assert f'\n{junk}:' not in blockable, f'{junk} is not a domain'

    stale = []
    for name, content in gen.items():
        path = os.path.join(OUT_DIR, name)
        existing = open(path).read() if os.path.exists(path) else None
        if existing != content:
            stale.append(name)
            if not args.check:
                open(path, 'w').write(content)

    for name, content in gen.items():
        n = sum(1 for l in content.splitlines() if l and not l.startswith('#'))
        print(f"  {name}: {n} entries")

    if args.check and stale:
        print(f"\nSTALE (run tools/extract-iocs.py): {', '.join(stale)}")
        return 1
    print("\nin sync" if args.check else f"\nwrote {len(gen)} lists to cdb-lists/")
    return 0


if __name__ == '__main__':
    sys.exit(main())
