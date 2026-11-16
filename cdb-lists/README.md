# CDB Lists

Wazuh CDB lists generated from the Suricata ruleset, plus one hand-maintained
list. Consumed by `wazuh-rules/0925-ioc-list-matching.xml`.

| File | Generated | Safe to block? | Contents |
|------|-----------|----------------|----------|
| `malicious-ip` | yes | Yes | Actor-controlled IPs |
| `malicious-domains-t1` | yes | Yes | Dedicated actor domains |
| `malicious-fqdn-t2` | yes | Exact FQDN only | Actor FQDNs on shared providers |
| `detect-only-providers` | yes | **No** | Legitimate services attackers abuse |
| `rfc1918` | no | n/a | Private ranges, for "source is external" checks |

Regenerate after any Suricata rule change:

```bash
python3 tools/extract-iocs.py
```

## Read this before blocking anything

Iranian actors run most of their tooling on infrastructure you also use. A
blocklist built by scraping every domain out of a detection ruleset will
contain GitHub, Telegram, Cloudflare, Microsoft Graph and your DNS resolver,
because the rules reference those services in order to *detect abuse of them*.
Enforcing that list breaks software distribution, DNS, and your own alerting.

### T1 — `malicious-domains-t1` — blockable

Dedicated actor-registered domains with no legitimate function. Blocking them
affects nobody but the actor. Example: `hospitalinstallation.com`
(Cavern Manticore).

### T2 — `malicious-fqdn-t2` — block the exact FQDN, never the parent

```
line.completely.workers.dev     <- block this
workers.dev                     <- NEVER block this
```

Blocking the parent takes out every tenant of that provider. On `workers.dev`,
`duckdns.org` or `somee.com` that includes a large number of unrelated sites,
and potentially your own services.

### T3 — `detect-only-providers` — never block

Legitimate services referenced precisely because they are abused:
`github.com`, `api.telegram.org`, `dns.google`, `graph.microsoft.com`,
`workers.dev`, `duckdns.org`, `ngrok.io`, the RMM vendors.

Matching these is a weak signal alone. Rule 101555 rates it level 4
(enrichment) and escalates only via 101556 when the same host also hits a
confirmed IOC.

### Specific exclusions

`1.1.1.1` appears in a Suricata rule header, but that rule detects **IOCONTROL
using Cloudflare DoH for evasion**. Cloudflare is not the threat. It is
excluded from every blockable output, as are the other public resolvers.

`onlyoffice.com` and `privatedns.org` were caught while reviewing generated
output: the first is a legitimate SaaS that Screening Serpens used for payload
staging, the second is a shared dynamic-DNS parent. Both are now T3.

The generator asserts these exclusions on every run and fails loudly rather
than emitting a list that would cause an outage.

## Deployment

```bash
sudo cp cdb-lists/malicious-ip \
        cdb-lists/malicious-domains-t1 \
        cdb-lists/malicious-fqdn-t2 \
        cdb-lists/detect-only-providers \
        cdb-lists/rfc1918 \
        /var/ossec/etc/lists/
sudo chown wazuh:wazuh /var/ossec/etc/lists/*
```

Declare in `ossec.conf`:

```xml
<ruleset>
  <list>etc/lists/malicious-ip</list>
  <list>etc/lists/malicious-domains-t1</list>
  <list>etc/lists/malicious-fqdn-t2</list>
  <list>etc/lists/detect-only-providers</list>
  <list>etc/lists/rfc1918</list>
</ruleset>
```

Then restart the manager. Wazuh compiles the lists on start.

The rules will not match until the lists are declared. `rfc1918` in particular
is required by rules 100947, 101004, 101013, 101148 and 101149, which use it to
express "source is external" — `<srcip>` accepts a single CIDR and rejects both
regex and comma lists, so a CDB list is the only way to express it.

## Where reputation actually pays off

On a NAT'd network, inbound source-IP reputation is close to useless: external
source IPs are translated or absent, and a correct active-response whitelist
covers RFC1918 anyway. The value is in the **egress** direction — an internal
host reaching out to actor infrastructure — enforced at your DNS resolver and
firewall. Rules 101550-101553 cover egress and are rated above the inbound
equivalent (101554) for that reason.
