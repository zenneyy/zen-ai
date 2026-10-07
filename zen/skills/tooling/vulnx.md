---
name: vulnx
description: ProjectDiscovery vulnx CLI for vulnerability intelligence — search/analyze/id subcommands, filter grammar, and KEV/PoC/template gating.
---

# vulnx CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/cvemap (vulnx is the current CLI for the vulnerability intel API; the project page redirects from `cvemap`)
- https://github.com/projectdiscovery/cvemap
- https://vulnerability.sh/ (the API backing vulnx)

Canonical syntax:
`vulnx [command] [flags]` where `command` is one of `search | id | analyze | filters | auth | healthcheck | mcp | update | version`

Preinstalled in the sandbox at `/home/pentester/go/bin/vulnx` (version v1.0.0 at build time; `vulnx update` upgrades in place). The command requires PDCP auth for sustained use — run `vulnx auth` once to raise rate limits; unauthenticated reads work but are heavily throttled.

High-signal global flags:
- `-j, --json` raw JSON output (disables yaml); for piping into jq / downstream
- `-o, --output <file>` write output to file (JSON; errors if file exists)
- `--proxy <url>` HTTP proxy
- `--timeout <dur>` HTTP timeout (default `30s`)
- `--silent` suppress banner/non-essential output
- `--no-color` disable colored output
- `--disable-update-check` suppress auto-update check (set in automation)
- `--update` update vulnx to latest version (equivalent to `vulnx update`)
- `-d, --debug` / `--debug-req` / `--debug-resp` request/response dumps
- `-v, --verbose` verbose output

High-signal subcommand flags:

**`vulnx search <query>`** (returns a list of matching vulns):
- `-n, --limit <n>` number of results (default 10)
- `--offset <n>` pagination offset
- `-s, --severity <levels>` filter by severity (comma-separated)
- `--cvss-score <expr>` CVSS filter: `7.5`, `>8.0`, `<=6.0`
- `--epss-score <expr>` EPSS filter: `0.5`, `>0.8`, `<=0.3`
- `-a, --vuln-age <expr>` age filter: `5`, `<10`, `>30`
- `--vuln-status <new|confirmed|unconfirmed|modified|rejected|unknown>`
- `--vuln-type <types>` e.g. `sql_injection,reflected_xss,stored_xss,command_injection`
- `--kev [=true|false]` filter CISA KEV (known exploited vulns)
- `--poc [=true|false]` filter CVEs with public PoCs
- `-t, --template [=true|false]` filter CVEs with nuclei templates
- `--remote-exploit [=true|false]` remotely exploitable only
- `--hackerone [=true|false]` cves reported on HackerOne
- `-p, --product <list>` filter by product
- `--vendor <list>` filter by vendor
- `--tags <list>` filter by tags
- `--detailed` show full vulnerability details (like `vulnx id`)
- `--sort-asc <field>` / `--sort-desc <field>` sort
- `--highlight` return search highlights where supported
- `--term-facets <field=n[,field=n]>` return term facets (e.g. `tags=10,severity=4`)
- `--range-facets <list>` range facets
- `--facet-size <n>` default facet buckets (10)
- `--fields <list>` restrict response fields

**`vulnx id <vulnID...>`** (fetch by ID — CVE, GHSA, etc.):
- Accepts positional IDs (`vulnx id CVE-2024-1234 CVE-2024-5678`), comma-separated (`CVE-2024-1234,CVE-2024-5678`), `--file ids.txt`, or stdin (`echo "CVE-2024-1234" | vulnx id`).

**`vulnx analyze`** (facet aggregation):
- `-q, --query <q>` filter query to run analysis against
- `-f, --fields <list>` fields to facet on (comma-separated)
- `--facet-size <n>` buckets per facet

**`vulnx filters`** prints every searchable field with data type, examples, and whether it's sortable/facetable — **this is the discoverability command, run it before composing a complex `search`**.

Agent-safe baseline for automation:
`vulnx search "is_kev:true severity:high,critical" -n 50 --silent --disable-update-check --json -o kev_high.json`

Common patterns:
- All KEV (known-exploited) CVEs:
  `vulnx search "is_kev:true" --json -o kev.json`
- High+critical with public PoCs on a specific product:
  `vulnx search 'affected_products.product:"confluence" severity:high,critical' --poc --json -o confluence_poc.json`
- One CVE's full detail:
  `vulnx id CVE-2024-1234 --json -o cve.json`
- Multiple CVEs from a file:
  `vulnx id --file cves.txt --json -o cves.json`
- Nuclei-template-available CVEs for a vendor:
  `vulnx search 'affected_products.vendor:"atlassian"' --template --json -o atlassian_templated.json`
- Facet aggregation (what are the top tags across a result set?):
  `vulnx analyze -q 'severity:critical is_kev:true' -f tags --facet-size 20 --json`
- Search with term facets inline (one call, both results and facets):
  `vulnx search 'is_remote:true' --term-facets 'tags=10,severity=4' --json -o remote_with_facets.json`
- Discover available filters (do this FIRST on a new query shape):
  `vulnx filters | less`
- Health check / connectivity verification:
  `vulnx healthcheck`
- Raise rate limits (one-time, interactive):
  `vulnx auth`

Critical correctness rules:
- Unauthenticated calls are **heavily rate-limited** — run `vulnx auth` once per sandbox or expect intermittent `429`s on bulk search. The config lives at `~/.config/pdcp/`.
- Query syntax is a search-DSL (`field:value`, boolean operators, numeric comparators like `>8.0`); run `vulnx filters` to enumerate valid field names and value shapes before composing complex queries. Field names use dot-paths (e.g. `affected_products.product`, `affected_products.vendor`, `affected_products.deployment_model`).
- `-n, --limit` default is 10 — raise explicitly for larger result sets; `--offset` paginates.
- `--output <file>` **errors if the file exists** — pre-delete or use a unique filename in loops.
- `--detailed` on `search` returns the same per-item shape as `vulnx id`; use when you want full records in one call instead of search → id round-trips.
- vulnx is **CVE/vuln-intelligence**, not SCA. It tells you *about* a CVE (is it KEV? has a PoC? has a nuclei template?). It does not scan your software — that's `tooling/trivy.md` / `tooling/retire.md`. The pair is: trivy/retire find the CVE IDs in your deps; vulnx tells you which of those are exploit-ready.
- The MCP server (`vulnx mcp`) is an MCP endpoint for other agents to consume vulnerability.sh — not for direct interactive use here.

Usage rules:
- Start every workflow with `vulnx filters` on an unfamiliar query — the field vocabulary is the main thing that bites.
- `--json --silent --disable-update-check` is the agent-automation triple; the default output is YAML with a banner.
- Chain into `tooling/nuclei.md`: filter CVEs with `--template true`, then feed the IDs into `nuclei -t cves/`.
- Combine with `tooling/trivy.md`: trivy lists found CVEs in a scanned image → `vulnx id --file <cve_list>` enriches them with KEV/PoC/template signals.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- `429` or sustained rate-limit errors: run `vulnx auth` once; verify key with `vulnx healthcheck`.
- Empty results on a known-good CVE ID: use `vulnx id CVE-XXXX-YYYY` directly — `search` requires matching the query DSL exactly, `id` is literal.
- "unknown filter / field": run `vulnx filters | grep -i <field>` to find the canonical dot-path.
- Output file errors with "file exists": delete it or write to a timestamped filename.
- Connectivity failures: `vulnx healthcheck`; if the sandbox proxy is routing vulnx traffic (it is, via `http_proxy`), confirm Caido isn't blocking the vulnerability.sh host.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io cvemap <flag>` or `site:github.com/projectdiscovery/cvemap`

---

## Query DSL

vulnx search accepts a query string — a mini search DSL, not shell glob or regex. Every token is either a field filter (`field:value`) or a freetext term.

### Field Filters

Basic syntax:
```
field:value                    exact match
field:"multi word value"       quoted string (required when value contains spaces)
field:val1,val2                OR within the field (comma-separated)
```

Numeric comparators (for `cvss_score`, `epss_score`, `vuln_age`):
```
cvss_score:>8.0                greater than
cvss_score:>=7.5               greater than or equal
cvss_score:<4.0                less than
cvss_score:<=6.0               less than or equal
cvss_score:9.8                 exact
```

CLI flags (`--cvss-score`, `--epss-score`, `--vuln-age`) accept the same comparator syntax and are equivalent to embedding them in the query string. Use CLI flags for simple single-value filters; embed in the query string when composing complex multi-field queries.

### Nested Field Paths

Product/vendor fields use dot-path notation:
```
affected_products.product:"apache http server"
affected_products.vendor:"microsoft"
affected_products.version:"2.4.49"
affected_products.deployment_model:"on-premises"
```

Always quote multi-word values. The canonical field names are discoverable via `vulnx filters`.

### Boolean Composition

Multiple field filters in the query string are implicitly ANDed:
```bash
vulnx search 'severity:critical is_kev:true is_remote:true' --json
```
This returns CVEs that are critical AND in KEV AND remotely exploitable.

Comma-separated values within a field are ORed:
```bash
vulnx search 'severity:high,critical' --json
```
This returns CVEs that are high OR critical.

Combine AND across fields with OR within:
```bash
vulnx search 'severity:high,critical is_kev:true vuln_type:sql_injection,command_injection' --json
```

### Freetext Terms

Bare words (not `field:value`) are freetext searches across indexed text fields:
```bash
vulnx search 'log4j' --json
vulnx search 'spring framework rce' --json
```

Mix freetext with field filters:
```bash
vulnx search 'log4j severity:critical is_kev:true' --json
```

### Quoting Rules

- Double quotes around multi-word values: `affected_products.product:"apache tomcat"`
- Single quotes around the entire query string for shell safety (prevents `!` and `$` expansion)
- No need to quote single-word values: `severity:critical` not `severity:"critical"`
- Commas inside a value (rare) require quoting: `tags:"rce,authenticated"` for a literal tag vs `tags:rce,authenticated` for OR

### Common Pitfalls

- Using a field name that doesn't exist silently returns zero results. Run `vulnx filters` first.
- Forgetting to quote multi-word product names: `affected_products.product:apache tomcat` parses as `affected_products.product:apache` AND freetext `tomcat`.
- CLI flags and query-string filters for the same field may conflict — prefer one or the other, not both.
- Numeric comparator spacing: `cvss_score: >8.0` (with space after colon) does not parse correctly. Use `cvss_score:>8.0`.
- Boolean field values: `is_kev:true` not `is_kev:yes` or `is_kev:1`.

---

## Filter Vocabulary

Run `vulnx filters` for the authoritative, live field catalogue. This section is a researcher's shortcut — the fields most useful for security triage, grouped by function.

### Severity and Scoring

| Field | Type | Examples | Notes |
|---|---|---|---|
| `severity` | keyword | `low`, `medium`, `high`, `critical` | CLI: `--severity`; comma-separated for OR |
| `cvss_score` | numeric | `7.5`, `>8.0`, `<=6.0` | CLI: `--cvss-score`; CVSS v3.x base score |
| `epss_score` | numeric | `0.5`, `>0.8`, `<=0.3` | CLI: `--epss-score`; probability of exploitation in next 30 days |
| `epss_percentile` | numeric | `>0.95` | Relative ranking among all scored CVEs |

### Status and Age

| Field | Type | Examples | Notes |
|---|---|---|---|
| `vuln_status` | keyword | `new`, `confirmed`, `modified`, `rejected`, `unknown` | CLI: `--vuln-status` |
| `vuln_age` | numeric (days) | `5`, `<10`, `>30` | CLI: `--vuln-age`; days since publication |
| `published_at` | date | (sortable, not directly filterable in query) | Sort: `--sort-desc published_at` |
| `updated_at` | date | (sortable) | Sort: `--sort-desc updated_at` |

### Exploitation Signals

| Field | Type | Examples | Notes |
|---|---|---|---|
| `is_kev` | boolean | `true`, `false` | CLI: `--kev`; CISA Known Exploited Vulnerabilities |
| `is_poc` | boolean | `true`, `false` | CLI: `--poc`; public proof-of-concept exists |
| `is_template` | boolean | `true`, `false` | CLI: `--template`; nuclei template available |
| `is_remote` | boolean | `true`, `false` | CLI: `--remote-exploit`; remotely exploitable |
| `is_hackerone` | boolean | `true`, `false` | CLI: `--hackerone`; reported on HackerOne |

### Product and Vendor

| Field | Type | Examples | Notes |
|---|---|---|---|
| `affected_products.product` | keyword | `"apache http server"`, `"confluence"` | CLI: `--product`; always quote multi-word |
| `affected_products.vendor` | keyword | `"microsoft"`, `"atlassian"` | CLI: `--vendor` |
| `affected_products.version` | keyword | `"2.4.49"` | Specific affected version |
| `affected_products.deployment_model` | keyword | `"on-premises"`, `"saas"` | Deployment context |

### Classification

| Field | Type | Examples | Notes |
|---|---|---|---|
| `vuln_type` | keyword | `sql_injection`, `reflected_xss`, `stored_xss`, `command_injection`, `path_traversal` | CLI: `--vuln-type`; comma-separated |
| `tags` | keyword | `rce`, `auth-bypass`, `ssrf`, `lfi` | CLI: `--tags`; community-assigned |
| `cwe_id` | keyword | `CWE-79`, `CWE-89` | CWE identifier |
| `assignee` | keyword | vendor/org name | CVE assigning authority |

### Reference

| Field | Type | Examples | Notes |
|---|---|---|---|
| `reference` | text | URL substring | Searches across reference URLs for a CVE |

### Sortable Fields

Use `--sort-asc` or `--sort-desc` with:
- `published_at` — chronological; newest-first for monitoring
- `updated_at` — recently modified
- `cvss_score` — most severe first
- `epss_score` — most likely exploited first
- `vuln_age` — newest or oldest

### Facetable Fields

Use in `--term-facets` or `vulnx analyze -f`:
- `severity`, `tags`, `vuln_type`, `vuln_status`
- `affected_products.vendor`, `affected_products.product`
- `assignee`, `cwe_id`

---

## Facet Analysis

Facets aggregate a result set into buckets — what severity distribution, what tags, which vendors dominate. Two ways to get them.

### Inline Term Facets (`--term-facets` on `search`)

One call, results + facets together:
```bash
vulnx search 'is_remote:true severity:high,critical' \
  --term-facets 'tags=10,severity=4,affected_products.vendor=5' \
  --json -o remote_faceted.json
```

The JSON output includes both the result list and a `facets` object with bucket counts per field. `tags=10` means "top 10 tag buckets".

### Dedicated `analyze` Subcommand

When you need facets without result rows — lighter, faster:
```bash
vulnx analyze -q 'severity:critical is_kev:true' -f tags,vuln_type,affected_products.vendor \
  --facet-size 20 --json -o kev_critical_facets.json
```

### Range Facets

Numeric distributions:
```bash
vulnx search 'is_kev:true' --range-facets 'cvss_score' --json -o kev_cvss_dist.json
```

### Facet-Guided Triage

Pattern: run a broad search with facets first to understand the shape of the result set, then narrow:

```bash
# 1. Understand the landscape
vulnx analyze -q 'affected_products.vendor:"microsoft"' \
  -f severity,tags,vuln_type --facet-size 10 --json

# 2. See that "rce" dominates tags — narrow there
vulnx search 'affected_products.vendor:"microsoft" tags:rce severity:critical' \
  --sort-desc epss_score -n 20 --json -o msft_rce_critical.json
```

### `--facet-size` Tuning

Default is 10 buckets per field. For high-cardinality fields like `tags` or `affected_products.product`, raise to 20–50 to see the full distribution. For low-cardinality fields like `severity` (4 values), 4 suffices.

---

## Enrichment Methodology

vulnx is the second stage. SCA tools (trivy, retire) find CVE IDs in your dependencies. vulnx enriches those IDs with exploit-readiness signals.

### The SCA → Enrichment Pipeline

```text
trivy/retire scan → CVE ID list → vulnx id --file → triage matrix
```

Worked example:

```bash
# 1. SCA: find CVEs in a container image
trivy image --scanners vuln --severity CRITICAL,HIGH \
  --format json -o trivy.json --quiet target.tld/app:latest

# 2. Extract CVE IDs
jq -r '.Results[].Vulnerabilities[]?.VulnerabilityID' trivy.json \
  | sort -u > cve_ids.txt

# 3. Enrich with vulnx
vulnx id --file cve_ids.txt --json --silent --disable-update-check \
  -o enriched.json

# 4. Triage: filter to KEV + template-available (immediate action)
jq -r 'select(.is_kev == true or .is_template == true) | .cve_id' enriched.json
```

### Enrichment Fields That Matter

From the `vulnx id` output, the triage-critical fields:
- `is_kev` — in CISA's Known Exploited Vulnerabilities catalogue → mandatory remediation for US federal, strong signal everywhere
- `is_template` — nuclei template exists → can validate exploitability immediately
- `is_poc` — public PoC exists → exploitation is accessible
- `epss_score` — probability of exploitation in next 30 days → predictive triage
- `is_remote` — remotely exploitable → no local access required
- `references` — links to advisories, PoCs, patches

### Enrichment for retire.js Results

retire outputs a different JSON shape:
```bash
# 1. SCA: find vulnerable JS deps
retire --path /workspace --outputformat json --outputpath retire.json --exitwith 0

# 2. Extract CVE IDs (retire uses "identifiers.CVE" in its advisories)
jq -r '.[].results[]?.vulnerabilities[]?.identifiers.CVE[]?' retire.json \
  | sort -u > js_cve_ids.txt

# 3. Enrich with vulnx (same pipeline)
vulnx id --file js_cve_ids.txt --json --silent --disable-update-check \
  -o js_enriched.json
```

### Batch Enrichment Considerations

- `vulnx id --file` accepts one ID per line or comma-separated.
- For large ID lists (>100), expect multiple API calls and potential rate limiting. Authenticate first (`vulnx auth`).
- `--output` errors on existing files — use timestamped filenames in loops: `-o "enriched_$(date +%s).json"`.
- If `--output` is not needed, redirect stdout: `vulnx id --file ids.txt --json --silent > enriched.json` (overwrites safely).

---

## KEV Workflow

CISA's Known Exploited Vulnerabilities catalogue is the strongest exploitation signal available. KEV means confirmed active exploitation in the wild.

### Basic KEV Queries

```bash
# All current KEV entries
vulnx search 'is_kev:true' -n 100 --json --silent --disable-update-check \
  -o kev_all.json

# KEV + critical severity
vulnx search 'is_kev:true severity:critical' -n 50 --json -o kev_critical.json

# KEV + remotely exploitable (highest urgency)
vulnx search 'is_kev:true severity:critical,high is_remote:true' \
  -n 50 --sort-desc published_at --json -o kev_remote.json
```

### KEV + Product Intersection

Asset-specific KEV monitoring — what KEVs affect *your* stack:
```bash
# KEV entries affecting Apache products
vulnx search 'is_kev:true affected_products.vendor:"apache"' \
  --sort-desc published_at --json -o kev_apache.json

# KEV entries for a specific product
vulnx search 'is_kev:true affected_products.product:"confluence"' \
  --json -o kev_confluence.json
```

### New KEV Monitoring

Track recently added KEV entries:
```bash
# KEV entries added in the last 7 days
vulnx search 'is_kev:true vuln_age:<7' --sort-desc published_at \
  -n 20 --json -o kev_recent.json

# KEV entries added in the last 30 days, critical only
vulnx search 'is_kev:true vuln_age:<30 severity:critical' \
  --sort-desc published_at --json -o kev_recent_critical.json
```

### KEV vs EPSS as Prioritization Signals

KEV and EPSS are complementary, not redundant:
- **KEV** = confirmed past exploitation. Binary signal. Strong for compliance and "fix now" decisions.
- **EPSS** = predicted future exploitation probability. Continuous signal. Better for ranking a large backlog.

Cross-reference for maximum signal:
```bash
# High EPSS but NOT yet in KEV — emerging threats
vulnx search 'is_kev:false epss_score:>0.5 severity:high,critical' \
  --sort-desc epss_score -n 20 --json -o emerging_threats.json

# In KEV AND high EPSS — actively exploited and likely to be exploited more
vulnx search 'is_kev:true epss_score:>0.5' \
  --sort-desc epss_score -n 20 --json -o kev_high_epss.json
```

---

## EPSS Scoring

The Exploit Prediction Scoring System predicts the probability that a CVE will be exploited in the wild within the next 30 days.

### Score Interpretation

| EPSS Score | Meaning | Action |
|---|---|---|
| > 0.9 | Near-certain exploitation | Treat as actively exploited |
| 0.5 – 0.9 | High probability | Prioritize remediation |
| 0.1 – 0.5 | Moderate probability | Schedule remediation |
| < 0.1 | Low probability | Standard patching cadence |

### EPSS Percentile

`epss_percentile` ranks a CVE against all scored CVEs:
- `>0.99` means this CVE is in the top 1% of exploitation likelihood
- More stable than raw score for threshold-based automation

### EPSS Filter Patterns

```bash
# Top exploitation probability, any severity
vulnx search 'epss_score:>0.9' --sort-desc epss_score -n 20 --json -o epss_top.json

# High EPSS + high severity (the real priority queue)
vulnx search 'epss_score:>0.5 severity:high,critical' \
  --sort-desc epss_score -n 30 --json -o epss_high_sev.json

# EPSS > 0.5 for a specific vendor
vulnx search 'epss_score:>0.5 affected_products.vendor:"microsoft"' \
  --sort-desc epss_score --json -o msft_epss.json
```

### EPSS vs CVSS for Triage

CVSS measures inherent severity (how bad *if* exploited). EPSS measures exploitation probability (how likely *to be* exploited). A CVSS 9.8 with EPSS 0.01 is theoretically severe but practically low-risk. A CVSS 7.0 with EPSS 0.8 is more likely to cause actual harm.

For triage, prefer EPSS over CVSS when ranking a large backlog. Use CVSS as a minimum threshold (e.g. `severity:high,critical`), then sort by EPSS within that set.

---

## Template Chaining with Nuclei

The `--template` filter identifies CVEs with nuclei templates — meaning you can go from intelligence to validation in one pipeline.

### Discovery → Validation Pipeline

```bash
# 1. Find template-available CVEs for a product
vulnx search 'affected_products.product:"confluence" severity:high,critical' \
  --template --json --silent --disable-update-check -o confluence_templated.json

# 2. Extract CVE IDs for nuclei template paths
jq -r '.cve_id' confluence_templated.json \
  | sed 's/CVE-\([0-9]*\)-/http\/cves\/\1\/CVE-\1-/' \
  > nuclei_template_ids.txt

# 3. Run nuclei with those templates against the target
nuclei -u https://target.tld -t http/cves/ -id "$(cat nuclei_template_ids.txt | tr '\n' ',')" \
  -silent -j -o nuclei_results.jsonl
```

### Simplified Template Chaining

For broad sweeps (all templated CVEs for a vendor, validated against a target):
```bash
# Get all CVE IDs with templates for a vendor
vulnx search 'affected_products.vendor:"atlassian"' --template --json --silent \
  | jq -r '.cve_id' > atlassian_cves.txt

# Run nuclei with all matching templates
nuclei -u https://target.tld -t http/cves/ \
  -id "$(paste -sd, atlassian_cves.txt)" -silent -j -o nuclei_atlassian.jsonl
```

### Template Availability as Prioritization

Not all CVEs have nuclei templates. Those that do are:
- More likely to be exploited (someone wrote the template)
- Immediately validatable (no manual PoC development needed)
- Automatable at scale (nuclei handles the execution)

Use `--template` as a pragmatic filter when you need actionable results now, not an exhaustive catalogue.

### KEV + Template Intersection

The highest-value combination — confirmed exploited AND immediately validatable:
```bash
vulnx search 'is_kev:true severity:critical,high' --template --json \
  --silent --disable-update-check \
  | jq -r '.cve_id' > kev_templated.txt

nuclei -u https://target.tld -t http/cves/ \
  -id "$(paste -sd, kev_templated.txt)" -silent -j -o nuclei_kev.jsonl
```

---

## Product and Vendor Intelligence

vulnx functions as a vulnerability intelligence feed scoped to your technology stack.

### Vendor Monitoring

Track all disclosures for a vendor, newest first:
```bash
# Recent Microsoft CVEs
vulnx search 'affected_products.vendor:"microsoft"' \
  --sort-desc published_at -n 50 --json -o msft_recent.json

# Recent Apache CVEs, critical only
vulnx search 'affected_products.vendor:"apache" severity:critical' \
  --sort-desc published_at -n 20 --json -o apache_critical.json
```

### Product-Specific Tracking

```bash
# All CVEs for a specific product
vulnx search 'affected_products.product:"nginx"' \
  --sort-desc published_at -n 30 --json -o nginx_cves.json

# Product + version intersection
vulnx search 'affected_products.product:"openssl" affected_products.version:"3.0.0"' \
  --json -o openssl_300.json
```

### Disclosure Cadence Analysis

Use facets to understand a vendor's disclosure pattern:
```bash
# Severity distribution for a vendor
vulnx analyze -q 'affected_products.vendor:"apache"' \
  -f severity,vuln_type --facet-size 10 --json -o apache_facets.json

# Tag distribution — what classes of vulns dominate
vulnx analyze -q 'affected_products.vendor:"microsoft"' \
  -f tags --facet-size 20 --json -o msft_tags.json
```

### Multi-Product Stack Query

When monitoring a heterogeneous stack:
```bash
# All high+ CVEs across your stack's vendors
for vendor in "apache" "microsoft" "atlassian" "hashicorp"; do
  rm -f "${vendor}_high.json"
  vulnx search "affected_products.vendor:\"${vendor}\" severity:high,critical" \
    --sort-desc published_at -n 20 --json --silent --disable-update-check \
    -o "${vendor}_high.json"
done
```

Or use comma-separated vendor filter:
```bash
vulnx search 'severity:critical' --vendor apache,microsoft,atlassian \
  --sort-desc published_at -n 50 --json -o stack_critical.json
```

---

## Triage Workflow Patterns

Decision trees for prioritizing vulnx results. Each pattern maps to an action urgency.

### Tier 1: Immediate (drop everything)

**Signal:** KEV + critical/high + remotely exploitable

```bash
vulnx search 'is_kev:true severity:critical,high is_remote:true' \
  --sort-desc published_at -n 20 --json --silent --disable-update-check \
  -o tier1_immediate.json
```

**Action:** Patch or mitigate within 24–48 hours. Validate with nuclei if template exists. Escalate if the affected product is in your stack.

### Tier 2: Validate and Remediate

**Signal:** Has nuclei template + high severity + remotely exploitable

```bash
vulnx search 'severity:high,critical is_remote:true' --template --json \
  --silent --disable-update-check -o tier2_validate.json
```

**Action:** Run nuclei templates against target to confirm exploitability. Schedule remediation within the sprint.

### Tier 3: Monitor and Schedule

**Signal:** High EPSS but not yet KEV — emerging threats

```bash
vulnx search 'is_kev:false epss_score:>0.5 severity:high,critical' \
  --sort-desc epss_score -n 30 --json -o tier3_emerging.json
```

**Action:** Add to the patching queue. Re-check EPSS and KEV status weekly.

### Tier 4: Awareness

**Signal:** Product-specific, any severity, newest first

```bash
vulnx search 'affected_products.vendor:"your-vendor"' \
  --sort-desc published_at -n 20 --json -o tier4_awareness.json
```

**Action:** Review for impact. No immediate action unless signals escalate.

### Combined Triage Pipeline

Run all tiers in one pass, produce a unified report:
```bash
rm -f tier*.json
vulnx search 'is_kev:true severity:critical,high is_remote:true' \
  -n 50 --json --silent --disable-update-check -o tier1.json
vulnx search 'severity:high,critical is_remote:true is_template:true is_kev:false' \
  -n 50 --json --silent --disable-update-check -o tier2.json
vulnx search 'is_kev:false epss_score:>0.5 severity:high,critical' \
  -n 30 --json --silent --disable-update-check -o tier3.json

# Merge and count
echo "Tier 1 (immediate): $(jq -s 'length' tier1.json) CVEs"
echo "Tier 2 (validate):  $(jq -s 'length' tier2.json) CVEs"
echo "Tier 3 (emerging):  $(jq -s 'length' tier3.json) CVEs"
```

### Risk Scoring Formula

When ranking a large backlog, weight these signals:

```text
Priority = (KEV × 10) + (EPSS_score × 5) + (CVSS_score × 1) + (has_template × 3) + (is_remote × 2)
```

This is a heuristic, not a standard. KEV dominates because it's confirmed exploitation. EPSS is weighted above CVSS because prediction outperforms inherent severity for real-world risk. Template availability means validation is immediate.

---

## Output Handling and Pagination

### The Automation Triple

Every automated vulnx call should include:
```bash
--json --silent --disable-update-check
```
- `--json` — structured output (default is YAML with decorative banner)
- `--silent` — suppress banner and log noise
- `--disable-update-check` — prevent version-check network calls and update prompts

### Pagination

Default `--limit` is 10. For larger result sets:
```bash
# First page
vulnx search 'severity:critical' -n 50 --offset 0 --json --silent \
  --disable-update-check -o page1.json

# Next page
vulnx search 'severity:critical' -n 50 --offset 50 --json --silent \
  --disable-update-check -o page2.json
```

Pagination loop:
```bash
OFFSET=0
LIMIT=50
PAGE=1
while true; do
  OUTFILE="results_page${PAGE}.json"
  rm -f "$OUTFILE"
  vulnx search 'severity:critical is_kev:true' -n $LIMIT --offset $OFFSET \
    --json --silent --disable-update-check -o "$OUTFILE" 2>/dev/null
  COUNT=$(jq -s 'length' "$OUTFILE" 2>/dev/null)
  [ "${COUNT:-0}" -lt "$LIMIT" ] && break
  OFFSET=$((OFFSET + LIMIT))
  PAGE=$((PAGE + 1))
done
```

### `--output` File-Exists Handling

`--output` refuses to overwrite. Patterns to handle this:
- Pre-delete: `rm -f output.json && vulnx ... -o output.json`
- Timestamped: `-o "results_$(date +%Y%m%d_%H%M%S).json"`
- Stdout redirect (no file-exists check): `vulnx ... --json --silent > output.json`

### `--fields` for Bandwidth Efficiency

When you need only specific fields, not the full record:
```bash
vulnx search 'is_kev:true severity:critical' \
  --fields cve_id,severity,epss_score,is_template \
  --json --silent --disable-update-check -o kev_slim.json
```

Reduces payload size and API processing time for large result sets.

### `--detailed` vs Search + ID Round-Trips

`vulnx search --detailed` returns the same per-item shape as `vulnx id`. Use when:
- You need full records AND can accept larger payloads
- You want one call instead of search → extract IDs → id lookup

Skip `--detailed` when:
- You only need IDs for enrichment pipelines
- Bandwidth matters (large result sets)
- You'll selectively look up only interesting results via `vulnx id`

### JSON Structure

`vulnx search --json` outputs one JSON object per line (JSONL-style). Key fields:
- `cve_id` — CVE identifier
- `severity` — low/medium/high/critical
- `cvss_score` — numeric CVSS v3 base score
- `epss_score` / `epss_percentile` — EPSS prediction
- `is_kev`, `is_poc`, `is_template`, `is_remote` — boolean exploitation signals
- `affected_products` — array of {vendor, product, version}
- `tags` — array of community tags
- `vuln_type` — classification
- `references` — array of advisory/patch/PoC URLs
- `published_at`, `updated_at` — timestamps

`vulnx id --json` returns the same shape with additional detail (full description, CWE, CVSS vector, reference breakdown).

Parse with jq:
```bash
# Extract CVE IDs where both KEV and template exist
vulnx search 'severity:critical' -n 100 --json --silent | \
  jq -r 'select(.is_kev == true and .is_template == true) | .cve_id'

# Tabular summary
vulnx search 'is_kev:true' -n 50 --json --silent | \
  jq -r '[.cve_id, .severity, (.epss_score // 0 | tostring), (.is_template | tostring)] | @tsv' | \
  column -t -s $'\t'
```

---

## Safety Rules

- vulnx queries an external API (vulnerability.sh). Every `search`/`id`/`analyze` call is an outbound HTTP request. In proxy-routed sandboxes, these requests traverse Caido — verify connectivity with `vulnx healthcheck` before bulk operations.
- `vulnx auth` stores an API key at `~/.config/pdcp/`. Do not commit this path or its contents.
- Template chaining with nuclei (vulnx → nuclei) transitions from intelligence to active testing. Ensure the target is in scope before running nuclei templates discovered via vulnx.
- `--output` writes JSON files that may contain vulnerability details useful to an attacker. Handle output files with the same care as scan results.
- Rate limits are real. Unauthenticated: heavily throttled. Authenticated: higher but not unlimited. Space bulk queries across time and use `--limit`/`--offset` pagination rather than requesting thousands of results at once.

---

Routed consumers:
- `supply_chain/dependency_cve_scanning.md` (post-trivy enrichment — which of the found CVEs are KEV / have templates / have PoCs)
- `tooling/trivy.md`, `tooling/retire.md` (SCA produces IDs; vulnx enriches them)
- `tooling/nuclei.md` (`--template true` filter → `nuclei -t http/cves/<year>/CVE-...` targeted scans)
- Analysis/triage phases in `reconnaissance/*` and `analysis/*` (prioritization by KEV/exploitability)
- `vulnerabilities/sql_injection.md`, `vulnerabilities/rce.md`, `vulnerabilities/ssrf.md` (vuln_type filter maps to these classes)
- `vulnerabilities/information_disclosure.md` (exposed credential/secret CVEs enriched with exploitation signals)
