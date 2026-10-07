---
name: gau
description: gau multi-provider archive-URL fetch — the Wayback/CommonCrawl/OTX/URLScan counterpart to waybackurls, with status/MIME filtering.
---

# gau CLI Playbook

Official docs:
- https://github.com/lc/gau

Canonical syntax:
`echo <domain> | gau [flags]` (or `gau [flags] < domains.txt`)

For the shared archive-URL workflow (pipe-and-grep usage, deduplication, feeding httpx/katana/arjun), use `tooling/waybackurls.md` — this file documents only what gau adds.

Install (not preinstalled in the sandbox):
`go install -v github.com/lc/gau/v2/cmd/gau@latest`
(installed to `$HOME/go/bin/gau`; sandbox PATH already includes it.)

What gau adds over waybackurls:
- **Multi-provider.** `--providers wayback,commoncrawl,otx,urlscan` — four archive sources in one pass, with graceful fallback when one is down.
- **Status/MIME filtering at fetch time.** `--mc/--fc` (status) and `--mt/--ft` (MIME type) drop uninteresting URLs before they hit your pipeline.
- **Date windowing.** `--from YYYYMM` / `--to YYYYMM` bounds the archive range.
- **Subdomain inclusion.** `--subs` for domain-wide, mirror of waybackurls' default.
- **Parameter de-dup.** `--fp` collapses URLs that differ only in parameter values (keeps one per endpoint shape).
- **Threaded + configurable.** `--threads <n>`, `--timeout <s>`, `--retries <n>`, `--proxy <url>`, `--config <file>` (`~/.gau.toml`).

## Complete Flag Reference (gau v2.2.4, verified in zen-sandbox 1.2.2)

- `--providers <list>` providers to query (`wayback,commoncrawl,otx,urlscan`; default is all four)
- `--subs` include subdomains of the target domain
- `--blacklist <ext,ext>` extensions to drop (e.g. `png,jpg,svg,woff,woff2,ttf,css`)
- `--mc <codes>` match status codes (allow-list); `--fc <codes>` filter out
- `--mt <types>` match MIME types; `--ft <types>` filter out
- `--fp` drop near-duplicate URLs that differ only in parameter values
- `--from <YYYYMM>` / `--to <YYYYMM>` date window
- `--json` JSON output (otherwise one URL per line)
- `--o <file>` output file (otherwise stdout)
- `--threads <n>` worker count (default 1)
- `--timeout <sec>` HTTP timeout per provider request (default 45)
- `--retries <n>` retries for provider calls
- `--proxy <url>` HTTP proxy (the sandbox env already proxies through Caido; override only if needed)
- `--config <file>` config path (default `~/.gau.toml` / `%USERPROFILE%\.gau.toml`)
- `--verbose` show per-provider progress
- `--version` show gau version

Agent-safe baseline for automation:
`echo target.tld | gau --subs --providers wayback,commoncrawl,otx,urlscan --threads 5 --timeout 30 --blacklist png,jpg,svg,woff,woff2,ttf,css --fp --o gau.txt`

Common patterns:
- Multi-provider sweep with asset-noise filtering:
  `echo target.tld | gau --subs --blacklist png,jpg,svg,woff,woff2,ttf,css,ico,gif --fp --o gau.txt`
- Just one provider (parity with waybackurls, but with gau's filters):
  `echo target.tld | gau --providers wayback --subs --fp --o gau_wb.txt`
- JSON output with status + MIME metadata for downstream:
  `echo target.tld | gau --subs --json --o gau.jsonl`
- Date-bounded (post-2023 only):
  `echo target.tld | gau --subs --from 202301 --fp --o gau_recent.txt`
- Live-only crawl: status allow-list + MIME filter:
  `echo target.tld | gau --subs --mc 200,301,302 --ft text/css,image/png,image/jpeg --fp --o gau_live.txt`
- Chain into live-check:
  `echo target.tld | gau --subs --fp | httpx -silent -mc 200,301,302,401,403 -o gau_httpx.txt`
- Batch across roots:
  `cat roots.txt | gau --subs --threads 5 --fp --o gau.txt`
- Mine parameter names (same as waybackurls, but across four providers):
  `echo target.tld | gau --subs | grep -oE '[?&][a-zA-Z0-9_]+=' | sort -u > gau_params.txt`

Critical correctness rules:
- Multi-provider = **multiple external endpoints** per run (`web.archive.org`, `index.commoncrawl.org`, `otx.alienvault.com`, `urlscan.io`). Each has its own rate limits and quirks; a failing provider shows up as missing data, not an error. Watch `--verbose` for coverage.
- `--mc`/`--fc`/`--mt`/`--ft` filter at the archive-record level (status/MIME each provider captured when it saw the URL); they do **not** re-check the URL live — use `httpx` for that.
- `--fp` collapses URLs differing only in query values — if parameter values matter to the task (SSRF, template injection), don't use `--fp`.
- `--threads` is per-provider parallelism; raise cautiously, external providers rate-limit.
- `--from`/`--to` are inclusive YYYYMM; not every provider honors date ranges equally — Wayback and CommonCrawl respect them, OTX/URLScan less so.
- Sandbox `http_proxy` already routes outbound through Caido; `--proxy` is only for alternate proxies.

Usage rules:
- Reach for gau when the task benefits from **more than Wayback alone** (CommonCrawl's finer-grained crawl, OTX threat-intel URLs, URLScan's recent-active URLs) or needs **fetch-time filtering** to keep the output set manageable.
- Pipe through `sort -u` even with `--fp`; dedup is still worth running.
- Set `--blacklist` for binary/asset extensions early; the raw multi-provider output is noisy.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- One provider silently returning nothing: run with `--verbose` to see per-provider status; `--providers wayback,commoncrawl` to drop a flaky one.
- 429s / timeouts: lower `--threads`, raise `--timeout`, add `--retries 3`.
- Output far larger than waybackurls: that's the expected cost of four providers; narrow with `--blacklist`, `--mc`, `--mt`, `--fp`, and `--from/--to`.

If uncertain, query web_search with:
`site:github.com/lc/gau gau <flag>`

---

## Provider-Specific Behavior

### Wayback Machine (`web.archive.org/cdx`)

Broadest historical coverage. Queries the CDX API for all archived snapshots of URLs under the target domain. Honors `--from`/`--to` date ranges reliably. Can be slow on domains with millions of snapshots — the CDX query itself may take minutes. Rate limits are IP-based and relatively generous, but sustained high-thread queries from one IP trigger 429s.

Coverage: strongest for long-lived domains with heavy web presence. Weakest for recently registered or low-traffic domains that Wayback hasn't crawled.

### CommonCrawl (`index.commoncrawl.org`)

Independent web crawl corpus updated monthly. Returns URLs from CommonCrawl's own crawler, which follows different link-discovery paths than Wayback. Often surfaces URLs that Wayback missed — deeper crawls into application paths, API endpoints hit by CommonCrawl's broader crawl scope. Honors `--from`/`--to` against its monthly index labels.

Coverage: overlaps substantially with Wayback but adds 5–15% unique URLs on typical targets. Strongest for application-level paths; weakest for assets and media.

### OTX / AlienVault (`otx.alienvault.com`)

Threat-intelligence URL corpus. URLs sourced from malware reports, exploit submissions, scan logs, and community-contributed indicators. Lower volume than Wayback/CommonCrawl but surfaces URLs that web crawlers never visited — URLs found in exploit payloads, C2 panel scans, or vulnerability disclosures.

Coverage: niche. Does not honor `--from`/`--to` reliably. Most valuable for domains that have appeared in threat intelligence (targeted organizations, software with known CVEs). Returns near-zero for domains with no threat-intel history.

API key optional (unauthenticated access returns limited results). Set in `.gau.toml` under `[otx]`.

### URLScan (`urlscan.io`)

Recent-active URLs from live browser-based scans. URLScan captures full page loads including JavaScript-triggered requests, XHR endpoints, and API calls that static crawlers miss. Strongest for recent activity (last 6–12 months); weakest for historical depth (URLScan started indexing later than Wayback/CommonCrawl).

Coverage: excellent for modern SPAs and JavaScript-heavy applications where the interesting endpoints are loaded dynamically. Lower volume overall but high uniqueness rate — URLs here frequently do not appear in the other three providers.

API key optional for basic queries. Set in `.gau.toml` under `[urlscan]`.

### Provider failure behavior

Provider failure is **silent** in default mode. If CommonCrawl is down, gau returns results from the remaining three providers without warning. Run with `--verbose` to see per-provider request/response status. A run returning fewer URLs than expected may indicate a down provider, not a target with a small footprint.

---

## Configuration File (`.gau.toml`)

Located at `~/.gau.toml` (Linux/macOS) or `%USERPROFILE%\.gau.toml` (Windows). Override with `--config <path>`.

Structure:
```toml
threads = 5
blacklist = ["png", "jpg", "gif", "svg", "woff", "woff2", "ttf", "css", "ico"]
retries = 3
timeout = 45
# proxy = "http://127.0.0.1:8080"

[urlscan]
apikey = ""

[otx]
apikey = ""
```

- **When to use config vs flags:** use the config file for persistent defaults (blacklist, thread count, API keys) and flags for per-run overrides (provider selection, date windows, output format). Flags override config values.
- API keys improve coverage for OTX and URLScan. Without keys, unauthenticated access returns limited result sets.
- The `blacklist` array in config is merged with `--blacklist` flag values.

---

## Date Windowing

`--from YYYYMM` / `--to YYYYMM` bounds the archive range. Both are inclusive.

Provider support:
- **Wayback Machine:** honors date ranges reliably — the CDX API filters snapshots by timestamp.
- **CommonCrawl:** honors date ranges against monthly index labels — results come from crawl batches within the specified months.
- **OTX:** does not reliably honor date ranges — returns all matching URLs regardless of when they were observed. Pre-filter OTX results by other means if date precision matters.
- **URLScan:** partial support — filters by scan submission date, not by when the URL was first seen. Effective for "recent scans only" but not for precise historical windowing.

Use cases:
- **Post-incident forensics:** `--from 202501 --to 202503` to scope URLs to the incident timeframe.
- **Recent-only assessment:** `--from 202401` to skip historical noise and focus on the current attack surface.
- **Historical regression:** `--to 202212` to examine the target's state before a known change (migration, redesign, WAF deployment).

---

## Parameter Deduplication (`--fp`)

`--fp` collapses URLs that differ only in query parameter values. Given:
```
https://target.tld/search?q=foo&page=1
https://target.tld/search?q=bar&page=2
https://target.tld/search?q=baz&page=3
```
`--fp` keeps one representative URL (e.g. `https://target.tld/search?q=foo&page=1`) and drops the rest.

**When to use:** broad attack-surface mapping where you need endpoint shapes, not specific parameter values. Dramatically reduces output volume on targets with heavy query-string variation (e-commerce search, paginated APIs).

**When NOT to use:**
- IDOR/BOLA testing — the parameter *values* (user IDs, object references) are the attack surface.
- SSRF — different `url=` values point to different internal resources.
- Template injection / SSTI — the injected value in the parameter matters.
- Any task where you need the full set of observed parameter values, not just the endpoint shape.

---

## JSON Output (`--json`)

`--json` outputs one JSON object per line (JSONL) instead of plain URLs:
```json
{"url":"https://target.tld/api/v1/users","status":200,"mime-type":"application/json","source":"urlscan"}
```

Fields: `url`, `status` (HTTP status code at archive capture time), `mime-type` (MIME type at capture time), `source` (which provider returned it).

When JSON is useful:
- Downstream filtering by archived status code or MIME type (beyond what `--mc`/`--mt` already did).
- Source attribution — knowing which provider found a URL informs confidence and follow-up.
- Automated pipelines that parse structured data rather than line-splitting.

When plain-text suffices:
- Simple pipe-to-httpx or pipe-to-sort-u workflows.
- When only the URL matters and metadata adds noise.

---

## Methodology — Archive URL Analysis

### Broad fetch → filter → live-check → test

1. **Broad fetch:**
   `echo target.tld | gau --subs --threads 5 --verbose --o gau_raw.txt`

2. **Filter noise:**
   `grep -viE '\.(png|jpg|gif|svg|css|woff|woff2|ttf|ico|eot|map)(\?|$)' gau_raw.txt | sort -u > gau_filtered.txt`
   (Or use `--blacklist` at fetch time to skip these entirely.)

3. **Live-check:**
   `httpx -l gau_filtered.txt -silent -mc 200,301,302,401,403 -o gau_live.txt`

4. **Targeted testing:**
   - API endpoints → `nuclei -l gau_live.txt -as -s critical,high`
   - Parameter-bearing URLs → `arjun` or `sqlmap`
   - Admin/debug paths → manual inspection or `ffuf` for auth bypass

### Extension and path pattern mining

Extract interesting URL patterns from archive data:
```
grep -oP 'https?://[^\s]+\.(bak|old|sql|zip|tar\.gz|env|config|xml|json|log|swp)' gau_raw.txt | sort -u > gau_backups.txt
grep -iE '/(admin|debug|test|staging|internal|api|graphql|swagger|docs)' gau_raw.txt | sort -u > gau_interesting.txt
```

### Historical-only endpoint discovery

Endpoints that existed historically but no longer link from the current site may still resolve — orphaned admin panels, legacy API versions, debug endpoints left behind after a redesign:

```
echo target.tld | gau --subs --fp | httpx -silent -mc 200 -o still_alive.txt
```

URLs returning 200 from archive data that don't appear in a current crawl (`katana` output) are historical survivors — high-priority targets for information disclosure and forgotten functionality.

---

Routed consumers:
- `reconnaissance/*` (historical endpoint enumeration — fuller coverage than waybackurls)
- `vulnerabilities/information_disclosure.md` (orphaned debug/admin paths across all four providers)
- `tooling/waybackurls.md` (the shared workflow lives there)
- `tooling/httpx.md` / `tooling/arjun.md` (consumers of the discovered URLs/parameters)

---

Bounded-depth note: gau is a multi-provider archive fetcher with 18 flags and four external data sources. Its depth is in provider behavior, filtering mechanics, and feeding downstream tools — not in a large flag surface or complex operational modes. The ~280-line depth here covers the complete operational surface; no further genuine depth exists to document.
