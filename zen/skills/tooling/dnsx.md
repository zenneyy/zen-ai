---
name: dnsx
description: dnsx DNS toolkit syntax, record-type selection, wildcard filtering, and bruteforce controls for resolution/CNAME-chain recon.
---

# dnsx CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/dnsx/usage
- https://docs.projectdiscovery.io/opensource/dnsx/running
- https://github.com/projectdiscovery/dnsx

Canonical syntax:
`dnsx [flags]` (reads targets from `-l <file>`, `-d <domain>`, or stdin)

Install (not preinstalled in the sandbox):
`go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest`
(installed to `$HOME/go/bin/dnsx`; sandbox PATH already includes it.)

## Complete Flag Reference

INPUT:
- `-l, -list <file|csv|stdin>` targets (sub/domains or hosts)
- `-d, -domain <domain>` domain(s) to bruteforce (file / csv / stdin)
- `-w, -wordlist <file|csv|stdin>` wordlist for bruteforce

QUERY (default `-a`):
- `-a` A record
- `-aaaa` AAAA record
- `-cname` CNAME record
- `-ns` NS record
- `-txt` TXT record
- `-srv` SRV record
- `-ptr` PTR record
- `-mx` MX record
- `-soa` SOA record
- `-any` ANY record
- `-axfr` AXFR (zone transfer)
- `-caa` CAA record
- `-all, -recon` query all record types (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa)
- `-e, -exclude-type <types>` exclude specific record types from query

FILTER:
- `-re, -resp` display DNS response data
- `-ro, -resp-only` display DNS response only (no host prefix)
- `-rc, -rcode <codes>` filter by DNS status code (e.g. `noerror,servfail,refused`)
- `-rtf, -response-type-filter <types>` return entries with no records for specified query types

PROBE:
- `-cdn` display CDN name
- `-asn` display host ASN information

RATE-LIMIT:
- `-t, -threads <n>` concurrent threads (default 100)
- `-rl, -rate-limit <n>` DNS requests/second (default -1 = unlimited)

OUTPUT:
- `-o, -output <file>` output file
- `-j, -json` JSONL output
- `-omit-raw, -or` omit raw DNS response from JSONL
- `-ot, -output-template <tpl>` custom output template (e.g. `'{{host}} {{a}}'`)

DEBUG:
- `-hc, -health-check` run diagnostic check
- `-silent` display only results
- `-v, -verbose` verbose output
- `-raw, -debug` display raw DNS response
- `-stats` display running scan stats
- `-version` display version
- `-nc, -no-color` disable color

OPTIMIZATION:
- `-retry <n>` DNS attempts (must be ≥1; default 2)
- `-hf, -hostsfile` use system host file for resolution
- `-trace` perform DNS tracing
- `-trace-max-recursion <n>` max recursion for DNS trace (default 255)
- `-resume` resume existing scan
- `-stream` stream mode (disables wordlist, wildcard, stats, resume)
- `-timeout <dur>` max time to wait for DNS query (default `3s`)

CONFIGURATIONS:
- `-r, -resolver <file|csv>` custom resolvers
- `-wt, -wildcard-threshold <n>` wildcard filter threshold (default 5)
- `-auto-wildcard` automatically detect wildcard domains for filtering
- `-wd, -wildcard-domain <domain>` manual wildcard filter domain (mutually exclusive with `-auto-wildcard`; JSON output recommended)
- `-proxy <url>` SOCKS5 proxy (e.g. `socks5://127.0.0.1:8080`)

## Agent-Safe Baseline

`dnsx -l hosts.txt -recon -resp -t 100 -rl 500 -timeout 3s -retry 2 -auto-wildcard -silent -j -o dnsx.jsonl`

## Common Patterns

Resolve a list of candidates (A records, live-only):
`dnsx -l candidates.txt -silent -o live.txt`

Full record profile per host:
`dnsx -l hosts.txt -recon -resp -silent -j -o dnsx_full.jsonl`

CNAME chain discovery (feeds subdomain takeover):
`dnsx -l subdomains.txt -cname -resp -silent -j -o dnsx_cname.jsonl`

Subdomain bruteforce (seed with a wordlist):
`dnsx -d target.tld -w subs_wordlist.txt -a -resp -auto-wildcard -silent -j -o dnsx_brute.jsonl`

MX/TXT/CAA policy enumeration:
`dnsx -d target.tld -mx -txt -caa -resp -silent -j -o dnsx_policy.jsonl`

Attempt AXFR (zone transfer) across NS servers:
`dnsx -d target.tld -axfr -resp -silent -j -o dnsx_axfr.jsonl`

CDN/ASN enrichment of live hosts:
`dnsx -l hosts.txt -cdn -asn -silent -j -o dnsx_meta.jsonl`

Custom resolvers (quad9/cloudflare, avoid upstream recursion):
`dnsx -l hosts.txt -r resolvers.txt -silent -o live.txt`

Reverse PTR lookup:
`dnsx -l ips.txt -ptr -resp -silent -j -o dnsx_ptr.jsonl`

Response-code filtering (find NXDOMAIN for dangling records):
`dnsx -l subdomains.txt -rc refused,servfail -resp -silent -j -o dnsx_errors.jsonl`

Custom output template:
`dnsx -l hosts.txt -a -aaaa -ot '{{host}} {{a}} {{aaaa}}' -silent -o dnsx_custom.txt`

Stream mode for large pre-resolved lists:
`dnsx -l massive_list.txt -stream -silent -o dnsx_stream.txt`

Resume an interrupted bruteforce:
`dnsx -d target.tld -w large_wordlist.txt -a -auto-wildcard -resume -silent -j -o dnsx_brute.jsonl`

## Critical Correctness Rules

- Wildcard detection is essential for bruteforce — without `-auto-wildcard` or `-wd <domain>`, any `*.target.tld` responder generates false positives for every wordlist entry.
- `-wd` and `-auto-wildcard` are mutually exclusive; `-wd` recommends JSON output because it rewrites result records.
- Default query is A-only (`-a`). Any workflow that cares about CNAME chains, TXT policies, or MX records must pass explicit flags (or `-recon` for everything).
- `-rc <codes>` filters DNS rcodes **after** the query; it does not change what dnsx asks for.
- `-stream` is faster but disables wordlist mode, wildcard filtering, stats, and resume — only use it when resolving a static list.
- `-rl -1` (default) means **unlimited** DNS QPS, which can swamp a resolver or trigger rate-limiting. Pin `-rl 500-1000` for public resolvers.
- `-r <file>` resolvers file: ProjectDiscovery ships trusted lists — avoid open resolvers that cache aggressively or log queries.
- `-cname` output is the input signal for `subdomain_takeover` — the CNAME target plus a dangling-NXDOMAIN check is the primitive.
- `-timeout` accepts Go duration syntax (`3s`, `5s`, `500ms`), not bare integers.
- `-retry` must be at least 1; setting 0 may cause missed resolutions on lossy networks.

## Usage Rules

- Pair with `tooling/subfinder.md` output: `subfinder -d target.tld | dnsx -silent -o live.txt`.
- Use `-recon` for inventory passes; narrow to specific record types when the task has a specific question (CNAME chain, MX, TXT).
- JSONL (`-j -o`) is the format for downstream consumers; default text output drops record detail.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

## Failure Recovery

- All resolutions NXDOMAIN against a known-live domain: resolvers list is unreachable or filtered — switch to `-r resolvers.txt` with public resolvers or verify the sandbox's `/etc/resolv.conf`.
- Bruteforce returns everything (wildcard trap): add `-auto-wildcard` or `-wd target.tld` and re-run.
- AXFR silently empty: zone transfer is almost always refused — don't expect data; use CT logs / `tlsx` for cert SANs instead.
- Throughput saturates the sandbox: lower `-t`/`-rl`, raise `-timeout`, verify `/etc/resolv.conf` points to a reachable resolver.
- `-stream` returns partial results: stream mode disables retries and wildcard filtering — switch back to standard mode for completeness.
- Resume file not found: `-resume` looks for a `resume.cfg` in CWD from a prior interrupted run; if absent, start fresh.

---

## Methodology

DNS reconnaissance with dnsx follows a phased workflow. The specific phase depends on what input is available and what the engagement requires.

### Phase 1 — Resolution Validation

The most common entry point: a list of candidate subdomains from passive sources (subfinder, amass, CT logs) that need resolution to confirm they actually exist.

Minimal resolution pass (A-only, live hosts):
`subfinder -d target.tld -all -silent | dnsx -silent -o live_subs.txt`

Resolution with response data for downstream analysis:
`subfinder -d target.tld -all -silent | dnsx -a -resp -silent -j -o resolved.jsonl`

Dual-stack resolution (IPv4 + IPv6):
`dnsx -l candidates.txt -a -aaaa -resp -silent -j -o resolved_dual.jsonl`

Filter by rcode to separate live from dead:
`dnsx -l candidates.txt -a -rc noerror -resp -silent -j -o live.jsonl`

Find candidates that return NXDOMAIN (potential dangling records):
`dnsx -l candidates.txt -a -rc nxdomain -resp -silent -j -o nxdomain.jsonl`

The resolution pass serves as a gate: only confirmed-live hosts flow into active scanning (httpx, naabu, nuclei). Running active tools against unresolved candidates wastes time and generates noise.

### Phase 2 — Record-Type Enumeration

Each DNS record type answers a different recon question. Select record types based on the engagement objective.

**A / AAAA** — IP address mapping. Identifies hosting infrastructure, cloud providers, CDN presence. Dual-stack (`-a -aaaa`) reveals IPv6 infrastructure that may have different security posture.

**CNAME** — Alias chains. The primary input for subdomain takeover detection. A CNAME pointing to a service that no longer exists (dangling CNAME) is a takeover candidate.
`dnsx -l subs.txt -cname -resp -silent -j -o cname_chains.jsonl`

**NS** — Nameserver delegation. Identifies who controls DNS for each zone. Useful for finding NS-level takeover (nameserver pointed at a domain you can register) and understanding zone delegation structure.
`dnsx -d target.tld -ns -resp -silent -j -o ns_records.jsonl`

**MX** — Mail exchange. Maps email infrastructure. MX records pointing to third-party providers (Google Workspace, Microsoft 365, Mimecast) reveal service dependencies. MX records pointing to non-existent hosts are mail-infrastructure takeover candidates.
`dnsx -d target.tld -mx -resp -silent -j -o mx_records.jsonl`

**TXT** — Text records. Contains SPF, DKIM, DMARC, domain verification tokens, and sometimes internal notes or configuration fragments. SPF records map the authorized sending infrastructure; overly permissive SPF (`+all`, broad `include:` chains) signals phishing surface.
`dnsx -d target.tld -txt -resp -silent -j -o txt_records.jsonl`

**SRV** — Service location. Enumerates services that use SRV-based discovery (SIP, LDAP, XMPP, Kerberos). Reveals internal service architecture and port assignments.
`dnsx -l subs.txt -srv -resp -silent -j -o srv_records.jsonl`

**SOA** — Start of Authority. Contains the primary nameserver, responsible-party email, serial number, and zone timing parameters. The serial number pattern (date-based vs increment-based) hints at the DNS management system.
`dnsx -d target.tld -soa -resp -silent -j -o soa_records.jsonl`

**PTR** — Reverse DNS. Maps IPs back to hostnames. Useful for enumerating hostnames within a known IP range when forward enumeration is exhausted.
`dnsx -l ips.txt -ptr -resp -silent -j -o ptr_records.jsonl`

**CAA** — Certificate Authority Authorization. Specifies which CAs are authorized to issue certificates for the domain. Missing or overly permissive CAA records expand the certificate-issuance attack surface.
`dnsx -d target.tld -caa -resp -silent -j -o caa_records.jsonl`

**ANY** — All available records in a single query. Some resolvers refuse ANY queries (RFC 8482) or return minimal responses; use `-recon` (individual per-type queries) when ANY returns less than expected.
`dnsx -d target.tld -any -resp -silent -j -o any_records.jsonl`

**Full enumeration** — When the goal is a complete DNS inventory:
`dnsx -l subs.txt -recon -resp -silent -j -o full_dns.jsonl`

Exclude specific types when they generate noise or are irrelevant:
`dnsx -l subs.txt -recon -e axfr,any -resp -silent -j -o full_no_axfr.jsonl`

### Phase 3 — Subdomain Bruteforce

When passive sources are exhausted, bruteforce discovers subdomains by testing wordlist entries against the target domain's DNS.

Basic bruteforce:
`dnsx -d target.tld -w wordlist.txt -a -resp -auto-wildcard -silent -j -o brute.jsonl`

Multi-domain bruteforce:
`dnsx -d target.tld,sub.target.tld -w wordlist.txt -a -resp -auto-wildcard -silent -j -o brute_multi.jsonl`

Bruteforce with controlled rate (public resolvers):
`dnsx -d target.tld -w wordlist.txt -a -resp -auto-wildcard -r resolvers.txt -rl 500 -t 50 -retry 3 -silent -j -o brute.jsonl`

Bruteforce with resume (large wordlists, long runs):
`dnsx -d target.tld -w large_wordlist.txt -a -resp -auto-wildcard -resume -silent -j -o brute.jsonl`

Wildcard handling is critical during bruteforce. See the Techniques section for the full wildcard deep-dive.

### Phase 4 — AXFR (Zone Transfer)

Zone transfers retrieve the complete zone file from a nameserver. Almost always refused by properly configured servers, but the check costs one query per NS and occasionally succeeds on misconfigured internal or secondary nameservers.

`dnsx -d target.tld -axfr -resp -silent -j -o axfr.jsonl`

When AXFR fails (expected), the subdomain inventory relies on passive sources + bruteforce + CT logs.

### Phase 5 — DNS Tracing

DNS tracing follows the delegation chain from root servers to the authoritative nameserver, revealing the full resolution path. Useful for diagnosing DNS infrastructure, identifying intermediate resolvers, and detecting DNS hijacking.

`dnsx -l targets.txt -trace -silent -j -o trace.jsonl`

Control recursion depth:
`dnsx -l targets.txt -trace -trace-max-recursion 10 -silent -j -o trace.jsonl`

Tracing reveals:
- Delegation chain: root → TLD → authoritative NS
- Split-horizon DNS (different answers from different vantage points)
- DNS-based load balancing and failover configurations
- Intermediate resolvers that may inject or modify responses

### Phase 6 — CDN/ASN Enrichment

Annotate resolved hosts with CDN and ASN metadata to inform downstream decisions.

`dnsx -l live_hosts.txt -cdn -asn -silent -j -o enriched.jsonl`

CDN detection determines whether a host sits behind a CDN (Cloudflare, Akamai, Fastly, etc.), which affects:
- Port scanning strategy (naabu: `-exclude-cdn` skips full scans on CDN hosts, only probes 80/443)
- WAF assessment (wafw00f: CDN-fronted hosts often have WAF integrated)
- Direct-IP hunting (the real origin IP may differ from the CDN edge)

ASN information maps hosts to their network operator, revealing hosting provider, colocation relationships, and network-level scope boundaries.

### Full Pipeline Example

Complete DNS recon pipeline from passive discovery through enriched output:

```
subfinder -d target.tld -all -recursive -silent -o passive_subs.txt

dnsx -l passive_subs.txt -a -resp -auto-wildcard -silent -j -o resolved.jsonl

dnsx -l passive_subs.txt -cname -resp -silent -j -o cnames.jsonl

dnsx -d target.tld -w wordlist.txt -a -resp -auto-wildcard \
  -r resolvers.txt -rl 500 -silent -j -o brute.jsonl

cat resolved.jsonl brute.jsonl | jq -r '.host' | sort -u > all_live.txt

dnsx -l all_live.txt -cdn -asn -silent -j -o enriched.jsonl

dnsx -l all_live.txt -recon -resp -silent -j -o full_records.jsonl

cat all_live.txt | httpx -silent -o live_http.txt
```

---

## Detection

DNS queries are inherently less fingerprinted than HTTP traffic — there is no User-Agent, no TLS fingerprint, and standard recursive resolution looks the same regardless of the tool generating it. However, dnsx activity has detectable patterns at several layers.

### Resolver-Side Detection

**Query volume.** Default dnsx settings (`-t 100`, `-rl -1`) can generate thousands of queries per second to a single resolver. Enterprise and public resolver operators (Cloudflare, Google, Quad9) monitor for anomalous query rates and may throttle or block the source IP. ISP resolvers are more likely to rate-limit aggressively.

**Query-type distribution.** Normal client behavior is dominated by A/AAAA queries with occasional MX/TXT. A burst of AXFR, ANY, SRV, SOA, CAA, or PTR queries from a single source is atypical and may trigger alerting on security-aware resolvers or DNS monitoring systems.

**AXFR specifically.** Zone transfer requests are logged by virtually all authoritative nameservers. A refused AXFR still generates a log entry. Multiple AXFR attempts across different zones from the same source IP are a clear reconnaissance signal.

### Authoritative-Server-Side Detection

**Bruteforce pattern.** Subdomain bruteforce generates a high volume of queries for random-looking subdomains against a single authoritative zone. DNS monitoring (passive DNS sensors, authoritative-server logging) can detect this pattern by the NXDOMAIN rate — a spike in NXDOMAIN responses for `<random>.target.tld` is a strong bruteforce indicator.

**Query diversity.** `-recon` mode queries every record type for every host. The resulting query pattern (A, AAAA, CNAME, NS, TXT, SRV, PTR, MX, SOA, AXFR, CAA for each host in sequence) is distinctive and unlikely to originate from normal application behavior.

### Network-Level Detection

**DNS traffic volume.** IDS/NDR systems monitoring DNS traffic volume (queries per second from a single source, aggregate UDP/53 bandwidth) can flag dnsx activity. The signature is sustained high-rate DNS traffic from a single source to one or more resolvers.

**Non-standard transport.** When `-proxy socks5://...` routes DNS through a SOCKS5 proxy, the traffic shifts from UDP/53 to TCP through the proxy. This changes the detection surface — the resolver sees the proxy's IP, but the network between the scanner and the proxy carries SOCKS5 traffic instead of DNS.

### Practical Detection Profile

dnsx is generally low-fingerprint compared to HTTP-based tools. The primary detection vectors are:
- Anomalous query rate (mitigated by `-rl`)
- NXDOMAIN spike during bruteforce (harder to mitigate without slowing the scan)
- Unusual record-type queries (AXFR, ANY, full `-recon` sweeps)
- DNS traffic volume on the network path to the resolver

The tool itself has no distinctive query-level fingerprint (no custom EDNS options, no identifiable query patterns beyond volume and type distribution).

---

## Bypass and Evasion

Reducing the detection footprint of DNS reconnaissance. All effectiveness is situational — these techniques lower visibility, not eliminate it.

### Resolver Selection

The choice of resolver determines who sees the queries and what caching/logging applies.

**Custom resolver list.** Use `-r resolvers.txt` to control which resolvers process queries. Distribute queries across multiple resolvers to avoid single-source volume spikes.

`dnsx -l targets.txt -r resolvers.txt -a -silent -o live.txt`

Resolver list strategies:
- **Public resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9):** high reliability, moderate logging, rate-limited at high volume.
- **Multiple public resolvers:** spread load across providers. Rotate through a list of 10-20 resolvers to keep per-resolver query rate low.
- **Self-hosted resolvers:** maximum control over logging and caching. Run unbound or knot-resolver on a VPS to proxy queries through your own infrastructure.

**Avoid the target's own resolvers.** Querying the target's authoritative nameservers directly (instead of through a recursive resolver) eliminates the caching layer but makes all queries visible to the target's DNS infrastructure.

### Rate Control

**`-rl <n>` (rate limit).** The single most effective evasion control. Public resolvers typically tolerate 100-500 qps before throttling; authoritative servers vary widely.

Conservative rate for stealth:
`dnsx -l targets.txt -a -rl 50 -t 10 -silent -o live.txt`

Moderate rate for balanced speed/stealth:
`dnsx -l targets.txt -a -rl 200 -t 50 -silent -o live.txt`

Aggressive rate for speed (accepts detection risk):
`dnsx -l targets.txt -a -rl 1000 -t 100 -silent -o live.txt`

**`-t <n>` (threads).** Threads interact with rate limit — threads generate the concurrency, rate limit caps the aggregate throughput. Setting `-t 100 -rl 50` means 100 threads sharing 50 queries/second.

### Proxy Routing

**`-proxy socks5://host:port`** routes DNS queries through a SOCKS5 proxy. This changes the source IP seen by the resolver and encrypts the DNS traffic between the scanner and the proxy.

`dnsx -l targets.txt -a -proxy socks5://127.0.0.1:9050 -silent -o live.txt`

Use cases:
- Route through Tor for source-IP anonymization (note: Tor exit nodes are often blocked by DNS resolvers)
- Route through a VPS-based SOCKS5 proxy for IP diversification
- Route through an SSH tunnel (`ssh -D 1080 user@vps`) for encrypted DNS transport to the proxy endpoint

Limitations: SOCKS5 proxying adds latency per query. Combine with lower `-t` and `-rl` to avoid proxy congestion.

### Timing and Retry Tuning

**`-timeout <dur>`** controls how long to wait for each DNS response. Lower timeouts reduce the scan's active time window (less time with queries in flight) but increase missed responses on slow resolvers.

**`-retry <n>`** controls retry attempts. Lower retries reduce query volume per host but increase false negatives. `-retry 1` halves the worst-case query count versus the default of 2.

Stealth-tuned combination:
`dnsx -l targets.txt -a -rl 50 -t 10 -timeout 5s -retry 1 -r resolvers.txt -silent -o live.txt`

### Bruteforce-Specific Evasion

Subdomain bruteforce is the highest-visibility dnsx operation. The NXDOMAIN spike pattern is the hardest to mask because it is inherent to the technique.

Mitigations (reduce visibility, not eliminate):
- Lower `-rl` to spread queries over a longer time window
- Use multiple resolvers (`-r`) to distribute the query load
- Split wordlists into smaller batches and run with delays between batches
- Combine with `-auto-wildcard` — wildcard filtering reduces the number of queries that reach the authoritative server for wildcard-enabled domains (queries that would return positive from the wildcard don't need follow-up)

### Evasion Effectiveness Summary

| Technique | Reduces visibility to | Effectiveness |
|---|---|---|
| `-rl` rate limiting | Resolver operators, network monitors | High — directly controls query rate |
| `-r` resolver rotation | Any single resolver's logging | Moderate — spreads load but total volume unchanged |
| `-proxy` SOCKS5 | Network path monitors, resolver IP logging | Moderate — hides source IP, adds latency |
| `-retry 1` | Total query volume | Low-moderate — reduces worst-case count |
| Wordlist splitting | NXDOMAIN spike detection | Low — pattern is distributed but still visible |

---

## Techniques

### Wildcard Detection Deep-Dive

Wildcard DNS records (`*.target.tld → <IP>`) cause every subdomain query to resolve positively, making bruteforce results meaningless without filtering.

**`-auto-wildcard`** — dnsx automatically detects wildcard domains by querying random non-existent subdomains. If random subdomains resolve to the same IP(s), the domain is flagged as wildcard and those IPs are filtered from results.

`dnsx -d target.tld -w wordlist.txt -a -auto-wildcard -silent -j -o brute.jsonl`

**`-wt, -wildcard-threshold <n>`** — controls how many random subdomain queries dnsx sends to detect wildcards (default 5). Higher values increase detection confidence but add query overhead. Raise when dealing with DNS-based load balancing that returns different IPs per query (which can cause false-negative wildcard detection).

`dnsx -d target.tld -w wordlist.txt -a -auto-wildcard -wt 10 -silent -j -o brute.jsonl`

**`-wd, -wildcard-domain <domain>`** — manual wildcard specification. When you already know a domain uses wildcards, skip the detection phase and directly specify it. Mutually exclusive with `-auto-wildcard`. Recommended with `-j` because `-wd` rewrites result records to indicate wildcard filtering was applied.

`dnsx -d target.tld -w wordlist.txt -a -wd target.tld -silent -j -o brute.jsonl`

**When wildcard detection breaks:**
- **Geo-DNS / anycast with multiple IPs.** The wildcard detection queries random subdomains and checks if they all resolve to the same IP. If geo-DNS returns different IPs per query, the detection may miss the wildcard. Raise `-wt` to 15-20, or use `-wd` if you know the domain is wildcarded.
- **Partial wildcards.** Some domains wildcard only certain subdomain levels (e.g. `*.dev.target.tld` but not `*.target.tld`). `-auto-wildcard` checks at the queried domain level; multi-level partial wildcards require separate bruteforce runs per level.
- **CDN-fronted wildcards.** CDN providers often resolve all subdomains to edge IPs. `-cdn` probe can confirm this; then filter CDN-resolved hosts separately.

### Output Templating

`-ot, -output-template` allows custom output formats using Go template syntax with DNS response fields.

Host with A record:
`dnsx -l hosts.txt -a -ot '{{host}} {{a}}' -silent -o custom.txt`

Host with CNAME chain:
`dnsx -l hosts.txt -cname -ot '{{host}} -> {{cname}}' -silent -o cnames.txt`

Host with multiple fields:
`dnsx -l hosts.txt -a -aaaa -ot '{{host}},{{a}},{{aaaa}}' -silent -o multi.csv`

Available template fields correspond to the queried record types: `{{host}}`, `{{a}}`, `{{aaaa}}`, `{{cname}}`, `{{ns}}`, `{{txt}}`, `{{srv}}`, `{{ptr}}`, `{{mx}}`, `{{soa}}`, `{{caa}}`.

Output templating is the mechanism for building custom CSV/TSV pipelines without post-processing with jq. For complex analysis, prefer `-j` (JSONL) and parse with jq.

### Stream Mode vs Standard Mode

**Standard mode** (default): loads the full target list into memory, supports wordlist bruteforce, wildcard filtering, statistics, and resume. Appropriate for most operations.

**Stream mode** (`-stream`): processes input line-by-line from stdin without loading the full list. Disables wordlist mode, wildcard filtering, stats, and resume. Appropriate for:
- Very large pre-resolved lists that don't fit comfortably in memory
- Pipeline processing where input arrives continuously
- Simple resolution checks where wildcard filtering isn't needed

`cat massive_list.txt | dnsx -stream -silent -o resolved.txt`

Trade-offs: stream mode sacrifices wildcard detection and resume capability for lower memory usage and immediate processing. Never use stream mode for bruteforce (it disables the wordlist feature entirely).

### CNAME Chain Analysis for Subdomain Takeover

The CNAME → takeover workflow is one of dnsx's highest-value outputs.

Step 1 — Extract CNAME records:
`dnsx -l subdomains.txt -cname -resp -silent -j -o cnames.jsonl`

Step 2 — Identify dangling CNAMEs (CNAME target returns NXDOMAIN):
`jq -r '.cname[]' cnames.jsonl | sort -u | dnsx -a -rc nxdomain -silent -o dangling.txt`

Step 3 — Cross-reference dangling targets against known-takeover-vulnerable services (GitHub Pages, Heroku, S3, Azure, Shopify, etc.). Route to `vulnerabilities/subdomain_takeover.md` for the service-specific verification.

The `-resp` flag is essential — without it, the CNAME target hostname is not included in the output.

### MX/TXT/CAA Policy Enumeration

**MX enumeration** reveals email infrastructure dependencies and potential mail-server takeover targets:
`dnsx -d target.tld -mx -resp -silent -j -o mx.jsonl`

MX records pointing to third-party services indicate service dependencies; MX records pointing to non-resolving hostnames are mail-infrastructure takeover candidates.

**TXT enumeration** extracts SPF, DKIM, DMARC, and domain-verification tokens:
`dnsx -d target.tld -txt -resp -silent -j -o txt.jsonl`

Key TXT record signals:
- `v=spf1 ... +all` — permissive SPF allows any sender
- `v=spf1 ... ~all` — soft-fail SPF, often not enforced
- `_dmarc.target.tld` TXT `v=DMARC1; p=none` — DMARC not enforced
- Domain verification tokens (`google-site-verification=...`, `MS=ms...`, `_acme-challenge=...`) — indicate service integrations and sometimes stale verifications

**CAA enumeration** shows which Certificate Authorities are authorized:
`dnsx -d target.tld -caa -resp -silent -j -o caa.jsonl`

Missing CAA records mean any CA can issue certificates for the domain. Overly broad CAA (many issuers) increases the certificate-issuance attack surface.

### DNS Tracing for Delegation Analysis

`-trace` follows the full delegation chain from root servers through TLD servers to the authoritative nameserver.

`dnsx -l targets.txt -trace -silent -j -o trace.jsonl`

Trace analysis reveals:
- **Delegation structure:** which nameservers are authoritative at each level, who operates them, whether they're hosted or self-managed
- **Split-horizon indicators:** different trace paths from different vantage points suggest split-horizon DNS (internal vs external views)
- **DNS hijacking indicators:** unexpected intermediate resolvers or delegation changes compared to known-good traces
- **Glue record issues:** missing or stale glue records in the delegation chain

Limit recursion depth for targeted analysis:
`dnsx -l targets.txt -trace -trace-max-recursion 5 -silent -j -o trace_shallow.jsonl`

### Hostsfile Integration

`-hf, -hostsfile` tells dnsx to consult the system hosts file (`/etc/hosts`) during resolution. This allows pre-seeding DNS responses for:
- Testing against internal/development hostnames that aren't in public DNS
- Overriding DNS responses to test specific IP-to-hostname bindings
- Bypassing DNS-based blocking by specifying known-good IPs in `/etc/hosts`

`dnsx -l internal_hosts.txt -hf -a -resp -silent -j -o internal.jsonl`

### Response-Type Filtering

`-rtf, -response-type-filter` selects entries that have **no** records for specified query types. This is useful for finding hosts that resolve (have A records) but lack expected records:

Find hosts with no MX record (no email infrastructure):
`dnsx -l hosts.txt -a -mx -rtf mx -resp -silent -j -o no_mx.jsonl`

Find hosts with no TXT record (no SPF/DKIM/DMARC):
`dnsx -l hosts.txt -a -txt -rtf txt -resp -silent -j -o no_txt.jsonl`

### CDN Fingerprinting via DNS

`-cdn` identifies CDN providers from DNS response patterns (CNAME chains to CDN domains, IP range matching). Combined with `-asn`, this provides a network-level map of the target's infrastructure.

`dnsx -l hosts.txt -cdn -asn -a -resp -silent -j -o infra_map.jsonl`

CDN-identified hosts inform downstream decisions:
- Skip full port scans on CDN-fronted hosts (only 80/443 are meaningful)
- Adjust WAF assessment expectations (CDN often includes WAF)
- Prioritize origin-IP discovery for CDN-fronted hosts
- Filter CDN hosts from vulnerability scanning that targets origin servers

### Resume for Long-Running Operations

`-resume` continues an interrupted bruteforce or resolution pass from where it left off. dnsx writes a `resume.cfg` file in the current directory during execution.

`dnsx -d target.tld -w massive_wordlist.txt -a -auto-wildcard -resume -silent -j -o brute.jsonl`

Resume is incompatible with `-stream` mode. For very large operations, prefer standard mode with `-resume` over stream mode for reliability.

### Raw DNS Response Inspection

`-raw, -debug` outputs the full DNS response for each query, including all response sections (answer, authority, additional). Useful for debugging resolution issues, analyzing DNS behavior, and understanding server responses beyond what structured output captures.

`dnsx -l targets.txt -a -raw -silent -o raw_responses.txt`

For JSONL output, `-omit-raw` (or `-or`) strips the raw response to reduce output size:
`dnsx -l targets.txt -recon -resp -j -or -o compact.jsonl`

---

## Tool-to-Tool Chaining

### subfinder → dnsx (Validate Passive Results)

The canonical first chain. subfinder discovers subdomain candidates passively; dnsx confirms they actually resolve.

`subfinder -d target.tld -all -recursive -silent | dnsx -silent -o live_subs.txt`

With enrichment:
`subfinder -d target.tld -all -silent | dnsx -a -cdn -asn -resp -silent -j -o validated.jsonl`

### dnsx → httpx (Resolved Hosts → Live Web Check)

Feed resolved hosts to httpx for HTTP/HTTPS probing:

`dnsx -l candidates.txt -silent | httpx -silent -o live_web.txt`

With full response metadata:
`dnsx -l candidates.txt -silent | httpx -status-code -title -tech-detect -silent -j -o web_meta.jsonl`

### dnsx → tlsx (Resolved Hosts → Certificate Analysis)

Feed resolved hosts to tlsx for TLS/certificate reconnaissance:

`dnsx -l candidates.txt -silent | tlsx -san -cn -jarm -silent -j -o cert_data.jsonl`

The cert SANs from tlsx may reveal additional subdomains not found by subfinder, creating a feedback loop:
`tlsx -l hosts.txt -dns -silent -o tlsx_subs.txt`
`dnsx -l tlsx_subs.txt -silent -o newly_resolved.txt`

### dnsx CNAME → Subdomain Takeover Workflow

Full chain from CNAME extraction to takeover candidate identification:
```
dnsx -l subdomains.txt -cname -resp -silent -j -o cnames.jsonl

jq -r '.cname[]' cnames.jsonl | sort -u > cname_targets.txt

dnsx -l cname_targets.txt -a -rc nxdomain -silent -o dangling.txt
```

Route `dangling.txt` to `vulnerabilities/subdomain_takeover.md` for service-specific verification.

### dnsx CDN/ASN → Downstream Tool Decisions

CDN and ASN metadata from dnsx gates decisions for naabu and wafw00f:
```
dnsx -l hosts.txt -cdn -asn -silent -j -o meta.jsonl

jq -r 'select(.cdn == null) | .host' meta.jsonl > non_cdn.txt

jq -r 'select(.cdn != null) | .host' meta.jsonl > cdn_hosts.txt

naabu -l non_cdn.txt -top-ports 1000 -scan-type c -rate 300 -silent -j -o ports.jsonl

naabu -l cdn_hosts.txt -p 80,443 -scan-type c -rate 300 -silent -j -o cdn_ports.jsonl

wafw00f -i cdn_hosts.txt -a -f json -o waf_results.json
```

### dnsx Bruteforce → nuclei (Discovered Subdomains)

Newly discovered subdomains from bruteforce feed directly into vulnerability scanning:
```
dnsx -d target.tld -w wordlist.txt -a -auto-wildcard -silent -o brute_live.txt

httpx -l brute_live.txt -silent -o brute_web.txt

nuclei -l brute_web.txt -severity medium,high,critical -silent -j -o vulns.jsonl
```

### dnsx → naabu (Resolved Hosts → Port Scan)

Feed resolved hosts to naabu for port scanning, optionally using CDN metadata to adjust port sets:

`dnsx -l candidates.txt -silent | naabu -scan-type c -top-ports 100 -rate 300 -silent -j -o ports.jsonl`

### Complete Recon Pipeline

```
subfinder -d target.tld -all -recursive -silent -o passive.txt

dnsx -l passive.txt -a -resp -auto-wildcard -silent -j -o resolved.jsonl
dnsx -l passive.txt -cname -resp -silent -j -o cnames.jsonl
dnsx -d target.tld -w wordlist.txt -a -auto-wildcard -rl 500 -silent -j -o brute.jsonl

cat resolved.jsonl brute.jsonl | jq -r '.host' | sort -u > all_live.txt

dnsx -l all_live.txt -cdn -asn -recon -resp -silent -j -o full_intel.jsonl

cat all_live.txt | httpx -silent -o live_web.txt
cat all_live.txt | tlsx -san -cn -jarm -silent -j -o certs.jsonl
cat all_live.txt | naabu -scan-type c -top-ports 100 -rate 300 -silent -j -o ports.jsonl
```

---

Routed consumers:
- `reconnaissance/*` (resolution + asset discovery)
- `vulnerabilities/subdomain_takeover.md` (CNAME chain + dangling-record check is the primary primitive)
- `tooling/subfinder.md` (dnsx validates subfinder's passive results)
- `tooling/tlsx.md` (cert SAN enumeration complements DNS enumeration)
- `tooling/httpx.md` (resolved hosts → live web check)
- `tooling/naabu.md` (resolved hosts → port scan, CDN-aware port set selection)
- `tooling/wafw00f.md` (CDN-identified hosts → WAF fingerprinting)
- `tooling/nuclei.md` (discovered subdomains → vulnerability scanning)

If uncertain, query web_search with:
`site:docs.projectdiscovery.io dnsx <flag> usage`
