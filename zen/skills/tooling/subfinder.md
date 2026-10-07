---
name: subfinder
description: Subfinder passive subdomain enumeration syntax, source controls, and pipeline-ready output patterns.
---

# Subfinder CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/subfinder/usage
- https://docs.projectdiscovery.io/opensource/subfinder/running
- https://github.com/projectdiscovery/subfinder

Canonical syntax:
`subfinder [flags]`

High-signal flags:
- `-d, -domain <domain>` single domain target
- `-dL, -list <file>` domain list file
- `-all` include all sources (slow, maximum coverage)
- `-recursive` use only recursive-capable sources
- `-s, -sources <list>` include specific sources (comma-separated)
- `-es, -exclude-sources <list>` exclude specific sources
- `-m, -match <list>` only output subdomains matching this list (file or comma-separated)
- `-f, -filter <list>` exclude subdomains matching this list (file or comma-separated)
- `-rl, -rate-limit <n>` global HTTP request rate limit per second
- `-rls, -rate-limits <source=n/unit,...>` per-source rate limits (e.g. `hackertarget=10/m`)
- `-nW, -active` display only actively resolving subdomains
- `-proxy <url>` HTTP proxy for outbound source requests
- `-r <resolvers>` comma-separated custom resolvers
- `-rL, -rlist <file>` resolver list file
- `-mr, -max-results <n>` limit results per source (0 = unlimited; honored by paginating sources)
- `-ei, -exclude-ip` exclude IPs from the domain list
- `-silent` show only subdomains in output
- `-o <file>` output file
- `-oJ, -json` JSONL output
- `-oD, -output-dir <dir>` output directory (one file per domain, `-dL` only)
- `-oI, -ip` include host IP in output (`-active` only)
- `-cs, -collect-sources` include all source names in output (`-json` only)
- `-ls, -list-sources` list all available sources (add `-oJ` for JSON)
- `-stats` report source statistics
- `-timeout <seconds>` per-request timeout (default 30)
- `-max-time <minutes>` overall enumeration time cap (default 10)
- `-t <n>` concurrent goroutines for resolving (`-active` only, default 10)
- `-rsr, -response-size-read <bytes>` max response body from passive sources (0 = unlimited)
- `-config <file>` flag config file (default `~/.config/subfinder/config.yaml`)
- `-pc, -provider-config <file>` provider API key config (default `~/.config/subfinder/provider-config.yaml`)
- `-v` verbose output
- `-nc, -no-color` disable color

Agent-safe baseline for automation:
`subfinder -d example.com -all -recursive -rl 20 -timeout 30 -max-time 10 -silent -oJ -o subfinder.jsonl`

Common patterns:
- Standard passive enum:
  `subfinder -d example.com -silent -o subs.txt`
- Broad-source passive enum:
  `subfinder -d example.com -all -recursive -silent -o subs_all.txt`
- Multi-domain run with per-domain output files:
  `subfinder -dL domains.txt -all -recursive -rl 20 -silent -oD output/`
- Source-attributed JSONL output:
  `subfinder -d example.com -all -oJ -cs -o subfinder_sources.jsonl`
- Active-only resolution with IPs:
  `subfinder -d example.com -all -nW -oI -oJ -o subfinder_active.jsonl`
- Active resolution with custom resolvers:
  `subfinder -d example.com -all -nW -r 8.8.8.8,1.1.1.1 -oI -silent -o subs_resolved.txt`
- Passive enum via proxy:
  `subfinder -d example.com -all -recursive -proxy http://127.0.0.1:48080 -silent -oJ -o subfinder_proxy.jsonl`
- Targeted source selection (CT + threat-intel only):
  `subfinder -d example.com -s crtsh,certspotter,virustotal,securitytrails -oJ -cs -o subfinder_targeted.jsonl`
- Exclude noisy/slow sources:
  `subfinder -d example.com -all -es sitedossier,waybackarchive -rl 20 -silent -o subs.txt`
- Result filtering (match specific pattern):
  `subfinder -d example.com -all -m "api,dev,staging" -silent -o subs_filtered.txt`
- Result filtering (exclude known subdomains):
  `subfinder -d example.com -all -f known_subs.txt -silent -o subs_new.txt`
- Per-source result cap:
  `subfinder -d example.com -all -mr 500 -silent -o subs_capped.txt`
- Per-source rate limits for aggressive providers:
  `subfinder -d example.com -all -rls "github=30/m,securitytrails=1/s,virustotal=4/m" -silent -o subs.txt`
- Source statistics (coverage audit):
  `subfinder -d example.com -all -stats -oJ -cs -o subfinder_stats.jsonl`
- List all available sources:
  `subfinder -ls`
- List sources as JSON (for scripting):
  `subfinder -ls -oJ`
- Resolver list from file (active mode):
  `subfinder -d example.com -all -nW -rL resolvers.txt -oI -silent -o subs_resolved.txt`
- Exclude IPs from domain input:
  `subfinder -dL mixed_input.txt -ei -all -silent -o subs.txt`
- Recursive-only sources:
  `subfinder -d example.com -recursive -silent -o subs_recursive.txt`
- Verbose debug run:
  `subfinder -d example.com -all -v -oJ -cs -o subfinder_debug.jsonl`
- Tight response-size cap for bandwidth-constrained environments:
  `subfinder -d example.com -all -rsr 65536 -rl 10 -timeout 15 -silent -o subs.txt`

Critical correctness rules:
- `-cs` (collect-sources) is meaningful only with `-oJ`; ignored with plain-text output.
- Many sources return zero results without API keys configured in `provider-config.yaml`. Low output is often a config issue, not a target issue.
- `-nW` (active) performs DNS resolution and drops subdomains that don't resolve. This filters out historical/defunct subdomains that passive sources found — use it only when you need confirmed-live hosts.
- `-oI` (include IP) only works with `-nW` (active mode). Without `-nW`, there is no resolution and no IP to include.
- `-recursive` restricts to sources that can enumerate sub-subdomains (e.g. `a.b.example.com`). It does not add depth — it selects source capability.
- `-all` includes slow and unreliable sources; pair with `-max-time` and `-rl` to bound the run.
- `-mr` (max-results) caps per-source, not total. A run with 30 sources at `-mr 500` can return up to 15,000 raw results (before dedup).
- `-m` and `-f` operate on the final result set, not per-source. They take comma-separated values or file paths.
- `-rls` format is `source=count/unit` where unit is `s` (second), `m` (minute), or `ms` (millisecond). Multiple entries comma-separated. Defaults are baked into the binary per source.
- `-t` (goroutine count) only affects `-nW` (active) resolution concurrency. No effect on passive enumeration.
- `provider-config.yaml` composite keys (Censys, PassiveTotal, Fofa, Intelx, ZoomEye) use `:` as separator — `username:api_key`, not separate fields.
- Subfinder deduplicates results internally across sources. The `-stats` flag shows per-source counts before dedup.
- `-proxy` routes subfinder's outbound HTTP requests to passive sources through the proxy. It does not proxy DNS resolution in active mode.

Usage rules:
- Keep output files explicit when chaining to httpx/dnsx/nuclei.
- Use `-rl`/`-rls` when providers throttle aggressively.
- Run passive enumeration first (`-all`), then validate with `-nW` or pipe to `httpx`.
- Do not use `-h`/`--help` for routine tasks unless absolutely necessary.
- Use `-oD` for multi-domain batch runs — one output file per domain keeps results attributable.
- Prefer `-oJ -cs` in automation for source-level traceability.

Failure recovery:
- Zero or very low results: verify `provider-config.yaml` has API keys; re-run with `-v` to see per-source errors; try `-all` to include all sources.
- Provider errors in verbose output: lower `-rl`, apply per-source `-rls`, raise `-timeout`.
- Runs exceed time budget: lower scope with `-es` on slow sources, or cap with `-max-time`.
- Active mode (`-nW`) drops too many results: resolver issues — try `-r 8.8.8.8,1.1.1.1` or `-rL resolvers.txt` with known-good resolvers.
- Proxy errors: verify `-proxy` URL is reachable; the sandbox env already routes through Caido, so `-proxy` is only needed for an alternate proxy.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io subfinder <flag> usage`

---

## Complete Flag Reference (subfinder v2.16.0, verified in zen-sandbox 1.2.2)

### INPUT
- `-d, -domain <string[]>` domains to find subdomains for (comma-separated or repeated)
- `-dL, -list <string>` file containing list of domains

### SOURCE
- `-s, -sources <string[]>` specific sources to use (`-s crtsh,github`); use `-ls` to list all
- `-recursive` use only sources that handle subdomains recursively (sub-subdomain capable)
- `-all` use all sources for enumeration (slow; includes sources without API keys)
- `-es, -exclude-sources <string[]>` sources to exclude (`-es alienvault,zoomeyeapi`)

### FILTER
- `-m, -match <string[]>` only include subdomains matching this list (file path or comma-separated values)
- `-f, -filter <string[]>` exclude subdomains matching this list (file path or comma-separated values)

### RATE-LIMIT
- `-rl, -rate-limit <int>` maximum HTTP requests per second (global across all sources)
- `-rls, -rate-limits <value>` per-source rate limits in `key=value` format (`-rls hackertarget=10/m`); defaults are source-specific and baked into the binary
- `-t <int>` concurrent goroutines for DNS resolving (`-active` only; default 10)

### OUTPUT
- `-o, -output <string>` output file path
- `-oJ, -json` JSONL output format
- `-oD, -output-dir <string>` output directory (one file per domain; `-dL` only)
- `-cs, -collect-sources` include all source names in output (`-json` only)
- `-oI, -ip` include resolved host IP in output (`-active` only)

### CONFIGURATION
- `-config <string>` flag config file (default `~/.config/subfinder/config.yaml`)
- `-pc, -provider-config <string>` provider API key config file (default `~/.config/subfinder/provider-config.yaml`)
- `-r <string[]>` comma-separated list of custom DNS resolvers
- `-rL, -rlist <string>` file containing list of DNS resolvers
- `-nW, -active` display only actively resolving subdomains (performs DNS resolution)
- `-proxy <string>` HTTP proxy for outbound source requests
- `-ei, -exclude-ip` exclude IPs from the domain input list
- `-mr, -max-results <int>` limit results per source (0 = unlimited; honored by paginating sources)

### DEBUG
- `-silent` show only subdomains in output
- `-version` show version
- `-v` verbose output (per-source progress and errors)
- `-nc, -no-color` disable ANSI color
- `-ls, -list-sources` list all available sources (add `-oJ` for JSON format)
- `-stats` report per-source result statistics

### OPTIMIZATION
- `-timeout <int>` seconds to wait before timing out (default 30)
- `-max-time <int>` minutes to wait for enumeration results (default 10)
- `-rsr, -response-size-read <int>` max response body size in bytes to read from passive sources (0 = unlimited)

---

## Source Architecture and Provider Intelligence

Subfinder queries passive online sources — APIs, databases, and indexes that have already crawled, scraped, or indexed subdomain data. No traffic reaches the target domain during passive enumeration. Sources fall into distinct categories, each with different coverage characteristics.

### Source Categories

**Certificate Transparency (CT) logs:**
Sources: `crtsh`, `certspotter`, `google` (CT search).
Coverage: Every publicly-issued TLS certificate is logged. CT sources are the highest-fidelity passive source for subdomains that have ever had a certificate issued — including internal/staging names that were mistakenly certified. Returns the CN and SAN fields. No API key required for `crtsh`.

**DNS databases and aggregators:**
Sources: `dnsdb`, `dnsdumpster`, `hackertarget`, `robtex`, `sitedossier`, `rapiddns`, `dnsrepo`.
Coverage: Databases of observed DNS records from passive DNS sensors. Coverage depends on sensor placement and age. Good for historically-resolved names; may miss subdomains that never appeared in monitored DNS traffic.

**Threat intelligence platforms:**
Sources: `virustotal`, `securitytrails`, `shodan`, `censys`, `binaryedge`, `fullhunt`, `netlas`, `hudsonrock`, `fofa`, `quake`, `threatbook`, `pugrecon`.
Coverage: Aggregated from scanning, crawling, and malware analysis pipelines. Often the richest source for non-obvious subdomains (CDN edges, API backends, internal tooling) because they index traffic patterns, not just DNS. Almost all require API keys.

**Web archives:**
Sources: `waybackarchive`, `commoncrawl`.
Coverage: Subdomains extracted from archived URL sets. Excellent for historical subdomains that have been retired but may still resolve. `waybackarchive` is slow; exclude with `-es` when time-constrained.

**Code and paste repositories:**
Sources: `github`.
Coverage: Subdomains mentioned in code, configs, and documentation. Catches subdomains referenced in client-side code, deployment configs, and leaked internal docs. Requires API key; rate-limited.

**Search engine indexes:**
Sources: `baidu`, `bing`, `yahoo`.
Coverage: Subdomains found via search-engine scraping. Coverage is broad but shallow — only subdomains the search engine has indexed. No API key typically required, but rate limits are strict.

**Specialized / regional:**
Sources: `chinaz`, `urlscan`, `alientvault` (OTX).
Coverage: Regional or niche indexes. `urlscan` provides recently-scanned URLs; `alientvault` aggregates threat-feed data.

### Coverage Characteristics by Source Type

| Source type | Coverage strength | Latency | API key | Recursive |
|---|---|---|---|---|
| CT logs | All certificated names | Fast | Usually no | Some |
| DNS databases | Historically resolved | Medium | Varies | Some |
| Threat intel | Broadest non-obvious coverage | Slow | Yes | Some |
| Web archives | Historical, retired names | Slow | No | No |
| Code repos | Leaked/referenced names | Fast | Yes | No |
| Search engines | Indexed names only | Medium | Usually no | No |

### Recursive vs Non-Recursive Sources

`-recursive` selects only sources that can enumerate sub-subdomains (e.g. finding `a.b.example.com` when given `example.com`). Most CT and DNS database sources support recursion; search engine scrapers typically do not. When `-recursive` is set without `-all`, only recursive-capable sources run.

Without `-recursive`, subfinder queries both recursive and non-recursive sources. The recursive flag does not add recursion depth — it filters the source set to those that inherently support it.

### Listing Sources

`subfinder -ls` prints all available source names, grouped by capability.
`subfinder -ls -oJ` outputs as JSON (for scripting — pipe to `jq` to extract source names).

---

## Provider Configuration

### Config file locations

- **Provider config:** `~/.config/subfinder/provider-config.yaml` — API keys per source. Created on first run with empty entries.
- **Flag config:** `~/.config/subfinder/config.yaml` — default flag values. Override with `-config <path>`.

### provider-config.yaml structure

```yaml
binaryedge:
  - "API_KEY"
censys:
  - "USERNAME:API_SECRET"
certspotter: []
chaos:
  - "API_KEY"
fofa:
  - "EMAIL:API_KEY"
fullhunt:
  - "API_KEY"
github:
  - "TOKEN_1"
  - "TOKEN_2"
intelx:
  - "HOST:API_KEY"
passivetotal:
  - "USERNAME:API_KEY"
securitytrails:
  - "API_KEY"
shodan:
  - "API_KEY"
virustotal:
  - "API_KEY"
zoomeyeapi:
  - "USERNAME:API_KEY"
```

### Composite key format

Sources that require two-part credentials use `:` as separator:
- **Censys:** `username:api_secret`
- **PassiveTotal:** `username:api_key`
- **Fofa:** `email:api_key`
- **IntelX:** `host:api_key` (host is typically `2.intelx.io`)
- **ZoomEye:** `username:api_key`

### Multi-key rotation

Sources that accept multiple API keys (`github` in the example above) rotate through them. This mitigates per-key rate limits — providing 3 GitHub tokens triples effective throughput for that source.

### Verifying provider config

`subfinder -d example.com -all -v` — verbose output shows per-source success/failure. A source returning zero with an authentication error in `-v` output means the API key is missing or invalid.

`subfinder -d example.com -s virustotal -v` — isolate one source to verify its API key.

---

## Methodology

### Standard Passive Enumeration

The baseline workflow for any engagement:

1. **Broad passive sweep:**
   `subfinder -d target.tld -all -recursive -rl 20 -timeout 30 -silent -oJ -cs -o subfinder.jsonl`

2. **Audit source coverage:**
   `subfinder -d target.tld -all -stats` — check per-source result counts. Sources returning zero may need API keys or may not index the target.

3. **Deduplicate and sort:**
   `jq -r '.host' subfinder.jsonl | sort -u > subs.txt`
   (Subfinder deduplicates internally, but `sort -u` after JSONL extraction is a safety net.)

4. **Live-check with httpx:**
   `httpx -l subs.txt -silent -sc -title -td -o live_subs.txt`

5. **Feed downstream:**
   Live subdomains → `wafw00f` (fingerprint), `katana` (crawl), `nuclei` (scan), `naabu` (port scan).

### Source Selection Strategy

**Maximum coverage (`-all -recursive`):**
Use for initial engagement-wide enumeration. Slow but thorough. Pair with `-max-time 15 -rl 20` to bound the run.

**Targeted sources (`-s <list>`):**
Use when you know which data sources are relevant:
- CT-focused: `-s crtsh,certspotter` — fast, no API keys, catches all certificated names.
- Threat-intel enrichment: `-s virustotal,securitytrails,shodan,censys` — requires API keys but surfaces names passive DNS alone misses.
- Code-leak discovery: `-s github` — catches subdomains hardcoded in repos.

**Source exclusion (`-es <list>`):**
Remove sources that are slow, noisy, or irrelevant:
- `-es waybackarchive,sitedossier` — drop the slowest passive sources.
- `-es baidu,chinaz` — skip regional sources for non-Chinese targets.

**Recursive-only (`-recursive`):**
When the target has a deep subdomain hierarchy (e.g. `internal.corp.target.tld`), restrict to recursive-capable sources. Most useful for large organizations with many levels of subdomain delegation.

### Coverage Optimization

- **Run `-all` first**, then analyze `-stats` output to see which sources contributed. On subsequent runs, you can target only productive sources with `-s`.
- **API keys dramatically increase coverage.** A run without API keys hits ~10 free sources; with a full `provider-config.yaml`, 30+ sources contribute.
- **Multiple domains:** Use `-dL` with `-oD` so each domain gets its own output file. Shared output files from multi-domain runs lose per-domain attribution.
- **Iterative refinement:** Run broad, review results, then run targeted sources against interesting sub-zones.

### Diff-Based Enumeration (New Subdomain Discovery)

Compare current results against a known baseline to find newly appeared subdomains:

```
subfinder -d target.tld -all -silent -o subs_current.txt
comm -13 <(sort subs_baseline.txt) <(sort subs_current.txt) > subs_new.txt
```

Or use `-f` to exclude known subdomains directly:
`subfinder -d target.tld -all -f subs_baseline.txt -silent -o subs_new.txt`

New subdomains are high-priority targets — recently provisioned infrastructure is more likely to have misconfigurations, exposed admin panels, or incomplete hardening.

### Continuous Monitoring Workflow

For ongoing engagements, periodic subfinder runs detect infrastructure changes:

1. **Establish baseline:** `subfinder -d target.tld -all -silent -o baseline.txt`
2. **Periodic run:** `subfinder -d target.tld -all -silent -o latest.txt`
3. **Diff:** `comm -13 <(sort baseline.txt) <(sort latest.txt) > new.txt`
4. **Investigate new entries:** pipe `new.txt` through `httpx` and `nuclei`.
5. **Update baseline:** `cp latest.txt baseline.txt`

Pin `-max-time` and `-rl` for predictable run duration in scheduled contexts.

### Source-Level Intelligence Interpretation

The `-cs` flag with `-oJ` reveals which sources found each subdomain. This metadata carries intelligence value:

- **Found only by CT logs** (`crtsh`, `certspotter`): the subdomain has a certificate but may not appear in DNS or web crawlers — check for staging/internal services exposed via TLS.
- **Found only by threat intel** (`virustotal`, `shodan`): the subdomain appeared in scan data or malware C2 infrastructure — investigate for compromise indicators.
- **Found only by code repos** (`github`): the subdomain is referenced in code but may not be live — check for planned/decommissioned infrastructure, or leaked internal naming.
- **Found only by archives** (`waybackarchive`): historical-only, likely decommissioned — check for subdomain takeover potential (CNAME pointing to deprovisioned service).
- **Found by many sources**: well-known, publicly reachable — standard attack surface.
- **Found by exactly one obscure source**: verify independently before spending time on it — single-source results have higher false-positive rates.

`jq -r 'select(.sources | length == 1) | "\(.host) [\(.sources[0])]"' subfinder.jsonl` — list single-source subdomains for manual verification.

### Wildcard DNS Handling

Targets with wildcard DNS records (`*.example.com → 1.2.3.4`) cause every queried subdomain to resolve, producing massive false-positive sets. Strategies:

- **Passive-only (no `-nW`):** wildcard doesn't affect passive enumeration — you get the real subdomain list from sources, not from resolution. This is the cleanest approach.
- **Active mode with dnsx filtering:** pipe subfinder output through `dnsx -wd target.tld` which detects and filters wildcard responses:
  `subfinder -d target.tld -all -silent | dnsx -wd target.tld -silent -o subs_no_wildcard.txt`
- **Active mode with httpx differentiation:** wildcards resolve to the same IP but may serve different content. `httpx -l subs.txt -silent -sc -cl -title` reveals which subdomains have distinct responses vs. the wildcard catch-all.

---

## Active Resolution Mode

`-nW, -active` switches subfinder from pure passive enumeration to passive + DNS resolution. With `-nW`:

1. Subfinder performs normal passive enumeration across all selected sources.
2. Every discovered subdomain is resolved via DNS.
3. Only subdomains that successfully resolve are included in output.
4. With `-oI`, the resolved IP address is appended to each result.

### Resolver Configuration

- `-r 8.8.8.8,1.1.1.1` — use specific resolvers (comma-separated). Critical when the default system resolver is unreliable or rate-limited.
- `-rL resolvers.txt` — load resolvers from a file (one per line). For large target lists, a diverse resolver set prevents any single resolver from rate-limiting.
- `-t <n>` — concurrent resolution goroutines (default 10). Raise for large subdomain sets; lower if resolvers rate-limit.

### Trade-offs

- Active mode **drops** subdomains that don't resolve. Historical/retired subdomains found by passive sources are lost. This is often desirable (you want live hosts), but means the active result set is a subset of the passive result set.
- Active mode **adds latency** — DNS resolution for thousands of subdomains takes time. Use `-t` and reliable resolvers to keep it manageable.
- Active mode **generates DNS traffic** — the target's authoritative nameservers see resolution queries. This is the only traffic subfinder sends toward the target in active mode. It is low-volume and looks like normal DNS, but it is not zero-footprint.

### When to use active mode

- When you need only confirmed-live subdomains for downstream scanning (httpx, nuclei, naabu).
- When the target has a wildcard DNS record and you need to filter out wildcard responses.
- When you need IP addresses alongside subdomains for port scanning (naabu).

### When to keep passive-only

- When you want the full historical subdomain surface (including retired/defunct names).
- When zero-interaction with the target is required.
- When you'll validate with httpx anyway (httpx does its own resolution and is more feature-rich for liveness checking).

---

## Result Filtering and Deduplication

### Match filter (`-m, -match`)

Allow-list: only output subdomains that match the specified patterns.

`subfinder -d example.com -all -m "api,staging,dev" -silent -o filtered.txt`

Accepts comma-separated values or a file path (one pattern per line). Matching is substring-based — `api` matches `api.example.com`, `api-v2.example.com`, and `internal-api.example.com`.

Use cases:
- Focus on a specific subdomain zone (`-m "api"` for API infrastructure).
- Target staging/dev environments (`-m "staging,dev,test,uat"`).
- Narrow output for a specific team's infrastructure.

### Exclusion filter (`-f, -filter`)

Deny-list: exclude subdomains matching the specified patterns.

`subfinder -d example.com -all -f known_subs.txt -silent -o new_subs.txt`

Use cases:
- Diff against known inventory to find new/unknown subdomains.
- Exclude CDN/marketing subdomains that are out of scope.
- Remove noise from large enumeration runs.

### Per-source result cap (`-mr, -max-results`)

Limit the number of results returned per source. Useful when a single source dominates output with thousands of near-duplicate entries (common with CT logs on large organizations).

`subfinder -d example.com -all -mr 500 -silent -o subs.txt`

`-mr 0` (default) means unlimited. The cap is per-source, not total — with 30 sources at `-mr 500`, up to 15,000 results can be returned before dedup.

### IP exclusion (`-ei, -exclude-ip`)

When the input domain list (`-dL`) contains IP addresses mixed with domains, `-ei` strips the IPs so only domains are enumerated.

`subfinder -dL mixed_targets.txt -ei -all -silent -o subs.txt`

### Internal deduplication

Subfinder deduplicates results across sources internally. The `-stats` flag shows raw per-source counts before dedup. A `sort -u` after JSONL extraction is a belt-and-suspenders safety net but not strictly necessary.

---

## Output and Automation

### Plain-text output (default)

One subdomain per line. No metadata.

`subfinder -d example.com -all -silent -o subs.txt`

### JSONL output (`-oJ`)

One JSON object per line. Fields: `host`, `source`, `input` (the queried domain).

`subfinder -d example.com -all -oJ -o subfinder.jsonl`

With `-cs` (collect-sources), the `sources` field lists every source that returned that subdomain:

```json
{"host":"api.example.com","input":"example.com","sources":["crtsh","virustotal","securitytrails"]}
```

### Per-domain directory output (`-oD`)

With `-dL`, write one output file per domain into the specified directory:

`subfinder -dL domains.txt -all -silent -oD output/`

Produces `output/example.com.txt`, `output/other.tld.txt`, etc. Preserves per-domain attribution for multi-target engagements.

### Source statistics (`-stats`)

`subfinder -d example.com -all -stats`

Prints per-source result counts after enumeration. Use to audit which sources are productive and which need API keys. `-stats` output goes to stderr; subdomain output goes to stdout/file as normal.

### Response size control (`-rsr`)

`-rsr 65536` caps the response body read from each passive source at 64KB. Useful in bandwidth-constrained environments or when a source returns oversized responses that slow parsing.

### Parsing JSONL for downstream tools

Extract unique subdomains:
`jq -r '.host' subfinder.jsonl | sort -u > subs.txt`

Extract subdomains with their sources:
`jq -r '"\(.host) [\(.sources | join(","))]"' subfinder.jsonl`

Count results per source:
`jq -r '.sources[]' subfinder.jsonl | sort | uniq -c | sort -rn`

Filter to subdomains found by a specific source:
`jq -r 'select(.sources[] == "crtsh") | .host' subfinder.jsonl | sort -u`

Extract IPs (active mode with `-oI`):
`jq -r 'select(.ip != null) | "\(.host) \(.ip)"' subfinder.jsonl`

Feed directly to httpx:
`jq -r '.host' subfinder.jsonl | httpx -silent -sc -title -td -o live.txt`

Group subdomains by IP (active mode — identify shared hosting / CDN):
`jq -r 'select(.ip != null) | "\(.ip) \(.host)"' subfinder.jsonl | sort | awk '{ips[$1]=ips[$1]" "$2} END {for (ip in ips) print ip, ips[ip]}'`

Single-source subdomains (higher false-positive risk — verify independently):
`jq -r 'select(.sources | length == 1) | "\(.host) [\(.sources[0])]"' subfinder.jsonl`

Multi-source subdomains (high confidence):
`jq -r 'select(.sources | length >= 3) | .host' subfinder.jsonl | sort -u`

### Source Statistics Analysis

`subfinder -d target.tld -all -stats` outputs per-source result counts to stderr. Use to:
- **Identify productive sources:** high-count sources are worth keeping in targeted runs.
- **Detect API key issues:** a source showing 0 results when it should return data means missing/expired API key.
- **Estimate coverage gaps:** if only 5 of 30+ sources returned results, API key configuration needs work.
- **Compare across targets:** a target where only CT sources return results has minimal DNS/web presence; one where threat-intel sources dominate has broader exposure.

---

## Detection Profile

Subfinder is a **passive** tool — it queries third-party APIs and databases, not the target. The target sees no traffic during passive enumeration.

### What is visible

- **Provider APIs** see your queries. Each API call is logged by the provider (VirusTotal, SecurityTrails, Shodan, etc.) and associated with your API key. Some providers log query domains and may share aggregate query data.
- **Your IP** is visible to each provider unless `-proxy` is set. With `-proxy`, the proxy's IP is visible instead.
- **Active mode (`-nW`)** generates DNS queries against the target's authoritative nameservers. This is low-volume, looks like normal DNS, and is unlikely to trigger alerts — but it is target-facing traffic.

### What is not visible

- No HTTP requests to the target domain.
- No port scanning, crawling, or probing.
- The target has no way to know subfinder is running against it (passive mode only).

### Proxy routing

`-proxy http://127.0.0.1:48080` routes outbound HTTP requests to passive sources through the proxy. The sandbox env already routes through Caido via `http_proxy`; `-proxy` overrides that for subfinder specifically. Useful when:
- You want subfinder traffic logged in Caido separately from other tool traffic.
- You need to route provider API calls through a specific egress IP.
- Provider access is geo-restricted and requires a region-specific proxy.

---

## Tool-to-Tool Chaining

### The canonical recon pipeline

```
subfinder → dnsx → httpx → katana → nuclei
```

1. `subfinder -d target.tld -all -recursive -silent -o subs.txt` — passive subdomain enumeration.
2. `dnsx -l subs.txt -a -resp -silent -o resolved.txt` — DNS resolution, wildcard filtering, record extraction.
3. `httpx -l resolved.txt -silent -sc -title -td -o live.txt` — HTTP liveness, technology detection.
4. `katana -list live.txt -d 3 -jc -silent -o crawl.txt` — crawl live hosts for endpoints.
5. `nuclei -l live.txt -as -s critical,high -o findings.txt` — vulnerability scanning.

### Direct subfinder → httpx (skip dnsx)

When DNS resolution is not a separate concern:
`subfinder -d target.tld -all -silent | httpx -silent -sc -title -td -o live.txt`

httpx does its own resolution and filtering. This is simpler but loses the DNS record detail that dnsx provides.

### subfinder → naabu (port discovery)

`subfinder -d target.tld -all -nW -oI -silent -o subs.txt`
`naabu -list subs.txt -top-ports 100 -scan-type c -rate 300 -verify -silent -o ports.txt`

Active mode (`-nW`) is recommended before naabu — no point port-scanning subdomains that don't resolve.

### subfinder → wafw00f (WAF fingerprinting)

`subfinder -d target.tld -all -silent -o subs.txt`
`httpx -l subs.txt -silent -o live.txt`
`wafw00f -i live.txt -a -f json -o wafw00f.json`

Fingerprint WAF/CDN on every live subdomain before injection testing.

### subfinder → subdomain takeover check

Subdomains discovered by passive sources that don't resolve (or point to deprovisioned services) are subdomain takeover candidates:

```
subfinder -d target.tld -all -silent -o subs.txt
dnsx -l subs.txt -cname -silent -o cnames.txt
```

Check CNAME targets against known-takeover-vulnerable services (S3 buckets, Azure, Heroku, GitHub Pages, etc.). Subdomains found only by archive sources (`waybackarchive`) are prime candidates — they existed historically and may now point at deprovisioned infrastructure.

### Parallel passive sources

Combine subfinder with other passive tools for maximum coverage:
```
subfinder -d target.tld -all -silent -o subfinder.txt &
echo target.tld | gau --subs --fp --o gau.txt &
echo target.tld | waybackurls > waybackurls.txt &
wait
cat subfinder.txt | sort -u > subs.txt
```

subfinder enumerates subdomains; gau/waybackurls enumerate historical URLs. Different attack surfaces — combine the outputs for full coverage.

### Multi-domain engagement workflow

For engagements with many root domains:

```
subfinder -dL domains.txt -all -recursive -rl 20 -max-time 10 -silent -oD output/ -oJ
for f in output/*.txt; do
  domain=$(basename "$f" .txt)
  httpx -l "$f" -silent -sc -title -td -o "output/${domain}_live.txt"
done
```

Per-domain output files preserve attribution and enable per-domain downstream processing (different WAFs, different scan configs).

### Feeding downstream — format conventions

- Plain-text (`-o subs.txt`): one subdomain per line. Direct input to `httpx -l`, `dnsx -l`, `naabu -list`, `wafw00f -i`.
- JSONL (`-oJ -cs`): richer metadata for programmatic consumers. Extract subdomains with `jq -r '.host'`.
- Per-domain directory (`-oD`): use when each domain needs separate downstream processing.

---

## Routed Consumers

- `reconnaissance/*` (subdomain enumeration — the foundational recon step)
- `tooling/dnsx.md` (DNS resolution and record extraction on discovered subdomains)
- `tooling/httpx.md` (HTTP liveness and technology detection on discovered subdomains)
- `tooling/naabu.md` (port scanning discovered hosts)
- `tooling/katana.md` (crawling live discovered hosts)
- `tooling/nuclei.md` (vulnerability scanning live discovered hosts)
- `tooling/wafw00f.md` (WAF fingerprinting before injection testing)
- `tooling/gau.md`, `tooling/waybackurls.md` (parallel passive sources for URL-level enumeration)
- `vulnerabilities/subdomain_takeover.md` (discovered subdomains that don't resolve or point to decommissioned services)
- `vulnerabilities/information_disclosure.md` (staging/dev/internal subdomains exposing sensitive data)
