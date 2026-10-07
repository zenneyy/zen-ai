---
name: gospider
description: gospider crawling syntax, third-party-source enrichment, and scope controls for secondary-pass endpoint discovery.
---

# gospider CLI Playbook

Official docs:
- https://github.com/jaeles-project/gospider

Canonical syntax:
`gospider -s <url> [flags]` (or `-S <sites_file>`)

For the primary crawler role (depth/JS/headless/known-files), `tooling/katana.md` is the dominant tool. Reach for gospider when katana output looks thin, when you need archive/CommonCrawl/VirusTotal/AlienVault third-party enrichment in one command, or when a target handles katana badly.

## Complete Flag Reference (verified against 1.2.2 image — gospider v1.1.6)

Input:
- `-s, --site <url>` single site to crawl
- `-S, --sites <file>` sites list (one URL per line)

Output:
- `-o, --output <dir>` output folder (per-site file inside)
- `--json` JSON output
- `-q, --quiet` suppress all output, show URL only
- `-v, --verbose` verbose output
- `--debug` debug mode
- `-l, --length` display response length
- `-L, --filter-length <len>` filter by response length
- `-R, --raw` raw output mode
- `--version` display version

Request configuration:
- `-u, --user-agent <web|mobi|custom>` UA class or exact string (default `web` = random web UA)
- `--cookie <string>` cookie(s) to carry (`testA=a; testB=b`)
- `-H, --header <header>` extra header (repeat flag for multiple)
- `--burp <file>` load headers + cookie from a raw Burp/Caido request file
- `-p, --proxy <url>` proxy (`http://127.0.0.1:8080`)
- `--no-redirect` disable following 3xx redirects

Crawl control:
- `-d, --depth <n>` max recursion depth (0 = infinite; default 1)
- `-c, --concurrent <n>` max concurrent requests per matching domain (default 5)
- `-t, --threads <n>` number of sites crawled in parallel (default 1)
- `-k, --delay <sec>` delay between requests per matching domain (seconds)
- `-K, --random-delay <sec>` random extra delay added on top of `-k` (seconds)
- `-m, --timeout <sec>` request timeout (default 10)

Content parsing:
- `-B, --base` disable all extras — parse HTML content only (no JS linkfinder, no robots, no sitemap)
- `--js` enable linkfinder in JavaScript files (default on)
- `--sitemap` try to crawl `sitemap.xml`
- `--robots` try to crawl `robots.txt` (default on)

Third-party sources:
- `-a, --other-source` pull URLs from Archive.org, CommonCrawl, VirusTotal, AlienVault
- `-r, --include-other-source` also actively crawl and request the third-party-sourced URLs (not just list them)
- `-w, --include-subs` include subdomains discovered from third-party sources (default: main domain only)

Scope:
- `--subs` include subdomains in crawl scope
- `--blacklist <regex>` blacklist URL regex (exclude matching URLs)
- `--whitelist <regex>` whitelist URL regex (only crawl matching URLs)
- `--whitelist-domain <domain>` restrict crawl to a specific domain

## Agent-Safe Baseline

`mkdir -p crawl && gospider -s https://target.tld -o crawl -d 3 -c 10 -t 10 -m 10 -K 1 --json --quiet > crawl/gospider.jsonl`

## Common Patterns

Secondary-pass enrichment after katana (archive + external sources):
`gospider -s https://target.tld -o crawl -d 2 -a --subs -w --json --quiet > crawl/gospider_enrich.jsonl`

Multi-site batch (one process):
`gospider -S targets.txt -o crawl -d 2 -c 10 -t 20 --json --quiet > crawl/gospider.jsonl`

Headers/cookies replayed from a Caido-exported request:
`gospider -s https://target.tld -o crawl --burp req.txt -d 3 --json --quiet > crawl/gospider_auth.jsonl`

HTML-only pass (ignore JS link extraction):
`gospider -s https://target.tld -o crawl -B -d 3 --json --quiet > crawl/gospider_html.jsonl`

Scope-bound crawl across subdomains:
`gospider -s https://target.tld -o crawl --whitelist-domain target.tld --subs -d 3 --json --quiet > crawl/gospider_subs.jsonl`

Narrow URL filter (regex):
`gospider -s https://target.tld -o crawl --whitelist "/api/|/v[0-9]+/" -d 2 --json --quiet > crawl/gospider_api.jsonl`

Full enrichment pass with active follow-up of third-party URLs:
`gospider -s https://target.tld -o crawl -d 3 -a -r -w --subs --sitemap --json --quiet > crawl/gospider_full.jsonl`

Passive-only third-party collection (list but do not request):
`gospider -s https://target.tld -a --json --quiet > crawl/gospider_passive.jsonl`

Rate-limited crawl on a sensitive target:
`gospider -s https://target.tld -o crawl -d 2 -c 3 -t 1 -k 2 -K 3 -m 15 --json --quiet > crawl/gospider_slow.jsonl`

## Critical Correctness Rules

- `-a/--other-source` reaches external archives directly — expect several minutes of outbound traffic and `.gau`-style noise; follow with `-r` only when you actually want to crawl the fetched URLs.
- Scope: without `--whitelist-domain`/`--whitelist`, gospider crawls everything linked. Pin scope on anything larger than a single site.
- `-c` is **per matching domain** and `-t` is **sites in parallel**; the effective concurrency is `c × t` per unique domain.
- Default `--robots` on; some targets block aggressive crawling via robots.txt but still serve interesting endpoints — pass `--robots=false` only when explicitly allowed to ignore the policy.
- The sandbox `http_proxy` env already routes through Caido; `-p` is for second-proxy overrides, not routine use.
- Output goes to `--output <dir>` as per-site files by default; `--json --quiet` to stdout is cleaner for pipeline consumers (redirect to a jsonl file).
- `-B/--base` disables JS linkfinder, robots, sitemap — everything except raw HTML parsing. Only use when JS extraction is causing false-positive noise or the target serves no JS.
- `--js` is on by default. Passing `--js=false` disables it explicitly; `-B` also disables it. There is no headless/browser mode — gospider parses JS source statically via regex-based linkfinder, not execution.
- `-d 1` (default) means gospider fetches links from the seed page only — no recursion into discovered pages. For meaningful coverage, `-d 2` minimum; `-d 3-5` for deep crawls.

## Usage Rules

- Run gospider as the **secondary** crawler after katana. Reasons to run it: katana returned thin results, the target has heavy archive history worth pulling, or you need the explicit CommonCrawl/VirusTotal/AlienVault/OTX pass that katana doesn't do.
- Keep `--json --quiet` on in automation; the default text output is pipeline-hostile.
- Add `-k`/`-K` delays on targets that rate-limit; gospider is otherwise aggressive.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

## Failure Recovery

- Crawl returns almost nothing: raise `-d`, enable `-a --subs -w` to pull from external sources, verify auth via `--burp`.
- Crawl explodes across the public internet: add `--whitelist-domain target.tld` and `--blacklist "(logout|signout|destroy)"`.
- Rate-limited (429s/timeouts): lower `-c`/`-t`, add `-k 1 -K 2`, confirm UA with `-u web`.
- JSON output corrupted: redirect `--json --quiet` to a file instead of letting gospider write per-site files to `-o`.
- Third-party sources time out: the external APIs (Archive.org, CommonCrawl) can be slow or rate-limit; raise `-m` and accept latency, or drop `-a` and use `tooling/waybackurls.md`/`tooling/gau.md` separately for more control.

---

## Methodology — Crawl Engagement Workflow

### When to use gospider vs katana

katana is the primary crawler — headless browser mode, known-file/tech detection, form filling, scope-aware by design, deeper JS execution. gospider is the secondary enrichment pass:

- **Third-party source enrichment.** `-a` pulls from Archive.org, CommonCrawl, VirusTotal, AlienVault in one command. katana has no equivalent; the dedicated tools (`waybackurls`, `gau`) cover archive sources individually but gospider bundles them with the crawl.
- **Complementary link extraction.** gospider's regex-based JS linkfinder sometimes finds paths that katana's headless DOM-based extraction misses (inline concatenated strings, obfuscated patterns) and vice versa.
- **Lightweight fallback.** No headless browser dependency; works in constrained environments where katana's Chrome instance is impractical.
- **Archive-heavy targets.** Sites with long histories (10+ years) often have rich archive coverage; gospider `-a -r -w` surfaces deleted endpoints, old API versions, and historical subdomains.

Use katana first. Run gospider when: katana output is thin, the target has deep archive history, you need VirusTotal/AlienVault data, or the target's JS framework breaks katana's headless mode.

### Phase 1 — Passive third-party collection

Collect URLs from external sources without touching the target:
`gospider -s https://target.tld -a --json --quiet > crawl/gospider_passive.jsonl`

This contacts Archive.org, CommonCrawl, VirusTotal, and AlienVault APIs. The target sees no traffic. The output is a URL list seeded from historical and third-party data.

Review the passive results before active crawling — they reveal:
- Historical endpoints that may still exist
- Old API versions (`/api/v1/`, `/api/v2/`)
- Subdomains referenced in archive snapshots
- Parameters visible in archived query strings

### Phase 2 — Scoped active crawl

Use the passive results to inform scope, then crawl actively:
`gospider -s https://target.tld -o crawl --whitelist-domain target.tld -d 3 -c 10 -k 1 -K 1 --json --quiet > crawl/gospider_active.jsonl`

Scope controls:
- `--whitelist-domain target.tld` prevents following off-domain links
- `--blacklist "(logout|signout|destroy|unsubscribe)"` avoids destructive endpoints
- `--whitelist "/api/|/app/"` narrows crawl to specific path patterns
- `--subs` includes subdomains discovered during crawl

### Phase 3 — Enriched crawl with active follow-up

Combine passive sources with active crawling of discovered URLs:
`gospider -s https://target.tld -o crawl -d 3 -a -r -w --subs --sitemap --whitelist-domain target.tld --json --quiet > crawl/gospider_enriched.jsonl`

The `-r/--include-other-source` flag is the key difference from Phase 1: it actively requests the URLs found in third-party sources, not just lists them. This discovers:
- Whether archived endpoints still respond
- Redirect chains from old to new paths
- Content at historically-known paths that the base crawl missed

### Phase 4 — Authenticated crawl

For targets requiring authentication:
`gospider -s https://target.tld -o crawl --burp auth_request.txt -d 3 --json --quiet > crawl/gospider_auth.jsonl`

Or with explicit cookie/header:
`gospider -s https://target.tld -o crawl --cookie "session=abc123; csrf=xyz789" -H "Authorization: Bearer TOKEN" -d 3 --json --quiet > crawl/gospider_auth.jsonl`

The `--burp` flag reads a raw HTTP request file (Burp/Caido export format) and extracts headers + cookies. This is the cleanest way to replay authenticated session state.

### Depth strategy by target type

| Target type | Recommended depth | Flags | Rationale |
|---|---|---|---|
| Single-page API | `-d 1` | `-a --json --quiet` | API endpoints are flat; depth adds noise |
| Multi-page web app | `-d 3` | `--subs --sitemap --json --quiet` | Cover app sections without infinite recursion |
| Large CMS (WordPress, Drupal) | `-d 2-3` | `--whitelist-domain -B --json --quiet` | `-B` avoids JS bloat; CMS JS is usually framework noise |
| Archive-heavy target | `-d 2` | `-a -r -w --subs --json --quiet` | Let third-party sources do the heavy lifting |
| Subdomain-diverse org | `-d 2` | `-S subs.txt -t 20 --whitelist-domain *.target.tld --json --quiet` | Parallel multi-site with domain scope |

### Multi-site batch crawling

`gospider -S targets.txt -o crawl -d 2 -c 10 -t 20 -K 1 --json --quiet > crawl/gospider_batch.jsonl`

Tuning for batch:
- `-t 20` runs 20 sites in parallel — effective concurrency is `c × t` (10 × 20 = 200 concurrent requests across all domains)
- Output to `-o <dir>` creates per-site files automatically; `--json --quiet` to stdout merges everything into one stream
- For very large batches (100+ sites), split the file and run separate gospider instances to avoid memory accumulation

### Output management

gospider has two output modes:

**Per-site files** (`-o <dir>`): each site gets its own file in the output directory. Filenames are derived from the target URL. Good for organized multi-target reporting.

**Stdout stream** (`--json --quiet > file.jsonl`): all output to stdout in JSONL format. Redirect to a file. Better for pipeline consumption. `-o` and stdout can be used simultaneously.

JSON output fields include: `input` (source URL), `source` (how found: href/script/form/comment/linkfinder/other-source/archive/etc), `output` (discovered URL), `status_code` (if actively requested), `length` (response size).

`--quiet` suppresses the banner and progress output; only discovered URLs appear. Without `--quiet`, progress messages and banner intermix with URL output.

`-R/--raw` outputs the raw discovered data without URL normalization — useful when specific path fragments or relative references matter.

`-l/--length` adds response length to text output. `-L/--filter-length` filters responses by length — useful for deduplicating responses that return the same-sized error page.

---

## Detection — How gospider Traffic Is Seen

### User-Agent fingerprint

Default `-u web` rotates through a pool of common browser user-agents. This is less distinctive than tools with a fixed default UA (e.g. `feroxbuster/2.13.1`). gospider does not advertise itself in the default UA string.

`-u mobi` rotates through mobile user-agents — may trigger different response content (responsive vs mobile-specific pages).

A custom UA string (`-u "Custom/1.0"`) is fixed for the entire crawl session.

### Crawl pattern fingerprint

gospider's crawl has recognizable characteristics:
- **Rapid sequential requests** to the same domain at `c` concurrent connections — without `-k`/`-K` delays, this appears as a burst pattern
- **Link-follow pattern** is breadth-first per depth level; `-d 1` produces a single burst, higher depths produce waves
- **robots.txt and sitemap.xml** are requested at crawl start (when enabled) — this pair of requests at the beginning of a session is a classic crawler signature
- **JS file requests** followed by requests to paths extracted from those JS files — the linkfinder-then-request pattern is temporally distinctive
- **Third-party source traffic** (`-a`) does not touch the target but generates outbound connections to archive.org, commoncrawl.org, virustotal.com, and otx.alienvault.com — observable on egress

### Rate-based detection

Default `-c 5` with `-t 1` produces 5 concurrent requests per domain. On a single-site crawl this is moderate; on multi-site with `-t 20`, the aggregate burst is 100+ requests/second across domains.

WAF/rate-limiter visibility:
- **Per-domain rate-limiters** see `c` concurrent connections with no delay — trips most commercial WAFs at `c > 10`
- **IP-based rate-limiters** see `c × t` total connections from one source — trips at moderate `-t` values
- **Session-based** tracking sees a single cookieless agent hitting many paths sequentially — classic spider behavior

### Sitemap/robots probing

The `--robots` (default on) and `--sitemap` requests at crawl start are the most distinctive early-crawl signals. Some WAFs specifically flag rapid robots.txt+sitemap.xml+homepage requests from the same IP as automated crawling.

---

## Bypass/Evasion — Reducing the Crawl Fingerprint

All effectiveness statements are situational; none guarantee bypass.

### Rate control

`gospider -s https://target.tld -o crawl -d 3 -c 3 -t 1 -k 2 -K 3 --json --quiet > crawl/gospider.jsonl`

- `-c 3` limits concurrent requests per domain (from default 5)
- `-t 1` processes one site at a time
- `-k 2` adds 2-second base delay between requests
- `-K 3` adds 0-3 seconds of random jitter on top of `-k`

Effective delay range: 2-5 seconds between requests per domain. This is slow enough to fall under most per-IP rate-limiters but still faster than manual browsing.

### User-Agent rotation

`-u web` (default) already rotates through realistic browser UAs. Limitations:
- The rotation pool is static (compiled into the binary); very large WAF fingerprint databases may recognize the specific set
- All requests in a single crawl session use the same UA (rotation is per-session, not per-request)
- `-u mobi` uses a different pool of mobile UAs — switch if the target serves different content to mobile

For a custom UA matching a specific browser version:
`gospider -s https://target.tld -u "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" -o crawl --json --quiet`

### Proxy routing

`gospider -s https://target.tld -p http://127.0.0.1:8080 -o crawl --json --quiet > crawl/gospider.jsonl`

Routes all crawl traffic through a proxy. The sandbox `http_proxy` env already routes through Caido; `-p` is for:
- A second upstream proxy (IP rotation, geographic diversity)
- Explicit SOCKS proxy for source IP control
- Sending traffic through a proxy that adds headers or normalizes behavior

### Scope restriction to avoid noisy paths

`gospider -s https://target.tld -o crawl --blacklist "(logout|signout|destroy|delete|admin/clear|unsubscribe)" --whitelist-domain target.tld -d 3 --json --quiet`

- `--blacklist` prevents gospider from requesting paths that commonly trigger alerts, session invalidation, or destructive actions
- `--whitelist-domain` prevents off-domain link following that can generate suspicious cross-origin traffic
- Combined scope control reduces the total request volume and avoids the most distinctive paths

### Redirect control

`--no-redirect` prevents following 3xx responses. Useful when:
- The target uses redirect chains that lead to login pages or CAPTCHAs (following triggers detection)
- A WAF uses a redirect-to-challenge pattern — following the redirect completes the detection cycle
- Redirect loops would cause gospider to generate excess requests

Trade-off: disabling redirects loses content behind redirects, including moved resources and canonical URL resolution.

### Combined low-profile configuration

`gospider -s https://target.tld -o crawl -d 2 -c 2 -t 1 -k 3 -K 5 -m 15 -u web --whitelist-domain target.tld --blacklist "(logout|admin)" --no-redirect --json --quiet > crawl/gospider_stealth.jsonl`

This configuration:
- 2 concurrent requests, 3-8 second random delays (browsing-like pace)
- Domain-scoped to prevent off-site crawling
- Blacklists noisy paths
- No redirect following
- Random web UA

Effectiveness: reduces rate-based and pattern-based detection. Does not change the fundamental crawl behavior (sequential path requests from one IP). A dedicated WAF analyzing request patterns across time may still identify it as automated.

---

## Techniques — Advanced Usage

### Third-party source deep-dive

`-a/--other-source` queries four external sources simultaneously:

**Archive.org (Wayback Machine):** Historical snapshots of the target. Coverage varies — popular sites have millions of snapshots dating back 20+ years. Returns full URLs including query parameters from historical captures. Best for: old API endpoints, removed pages, historical parameter names.

**CommonCrawl:** Large-scale web index. Broader coverage than Wayback for certain domains. Returns URLs discovered during CommonCrawl's periodic full-web crawl. Best for: URLs not in Wayback, broader coverage of deep-linked pages.

**VirusTotal:** URLs submitted to VT for analysis. Coverage is biased toward URLs that someone suspected were malicious. Returns URLs associated with the domain in VT's database. Best for: URLs that appear in malware campaigns, phishing kits, or security submissions — often surfaces paths not in other archives.

**AlienVault OTX (Open Threat Exchange):** Threat intelligence platform. Coverage is security-focused (similar bias to VT). Returns URLs from OTX indicators. Best for: paths associated with known threats or indicators of compromise.

The overlap between sources varies per target. Running gospider `-a` covers all four in one pass. For individual control, use `tooling/waybackurls.md` (Wayback only) or `tooling/gau.md` (Wayback + CommonCrawl + OTX + URLScan).

### `-a` vs `-a -r` vs `-a -r -w`

| Flag combination | Behavior | Traffic to target |
|---|---|---|
| `-a` | List URLs from third-party sources | None (passive) |
| `-a -r` | List + actively crawl/request third-party URLs | Active requests to discovered URLs |
| `-a -r -w` | Above + include subdomains from third-party results | Active requests including subdomains |

`-a` alone is passive — it contacts the external APIs but does not request the discovered URLs against the target. `-r` makes it active by actually fetching those URLs. `-w` expands the scope to subdomains discovered in third-party results.

### JS linkfinder mechanics

`--js` (default on) applies regex-based link extraction to JavaScript files. It finds:
- Absolute and relative URLs in string literals
- API endpoints in fetch/XMLHttpRequest calls
- Path fragments in route definitions (React Router, Vue Router, Angular patterns)
- URLs in comments and configuration objects

Compared to katana's headless JS execution, gospider's regex approach:
- Is faster (no browser engine overhead)
- Catches string literals that aren't executed in the current page context
- Misses dynamically constructed URLs (string concatenation, template literals built at runtime)
- Has more false positives (matches URL-like patterns in non-URL contexts)

`-B/--base` disables JS linkfinder entirely — only raw HTML `<a href>`, `<form action>`, `<script src>`, etc. are parsed. Use `-B` when:
- The target's JS files are very large and produce excessive false-positive paths
- JS content is not relevant (static HTML site, server-rendered pages)
- Speed matters more than coverage

### Scope control patterns

**Domain-scoped + path-filtered:**
```
gospider -s https://target.tld -o crawl \
  --whitelist-domain target.tld \
  --whitelist "/api/|/app/|/admin/" \
  --blacklist "(logout|signout|\.pdf$|\.zip$)" \
  -d 3 --json --quiet > crawl/gospider_scoped.jsonl
```

- `--whitelist-domain` restricts to target.tld (subdomains excluded unless `--subs`)
- `--whitelist` further narrows to specific path patterns
- `--blacklist` excludes destructive actions and large binary files
- These three controls compose: a URL must match domain AND whitelist AND NOT blacklist

**Subdomain-inclusive:**
```
gospider -s https://target.tld -o crawl \
  --whitelist-domain target.tld \
  --subs \
  -d 2 --json --quiet > crawl/gospider_withsubs.jsonl
```

`--subs` includes subdomains in the crawl scope; `--whitelist-domain target.tld` still prevents off-domain crawling but allows `*.target.tld`.

### Authenticated crawling with Burp/Caido request files

Export a raw HTTP request from Caido or Burp:
```
GET /dashboard HTTP/1.1
Host: target.tld
Cookie: session=abc123; csrf=xyz789
Authorization: Bearer eyJhbGciOi...
Accept: text/html
```

Save as `auth_request.txt`, then:
`gospider -s https://target.tld -o crawl --burp auth_request.txt -d 3 --json --quiet > crawl/gospider_auth.jsonl`

gospider extracts headers and cookies from the raw request and applies them to all crawl requests. This is more reliable than manually passing `--cookie` + `-H` for complex authentication states.

Limitations:
- gospider does not handle token refresh — if the session expires mid-crawl, subsequent requests fail silently (they return login pages / 401s / 302-to-login)
- CSRF tokens embedded in forms are not updated — gospider doesn't execute form logic
- For long crawls on session-limited targets, export a fresh request and re-run

### Sitemap and robots crawling

`--sitemap` explicitly requests `sitemap.xml` (and any nested sitemaps referenced within it) at crawl start. sitemaps reveal the full set of pages the site operator considers canonical — often includes pages unreachable by link crawling.

`--robots` (default on) parses `robots.txt` for `Allow`/`Disallow` paths. gospider does not honor `Disallow` as a hard block — it uses the paths as discovery leads. `Disallow: /admin/` tells gospider `/admin/` exists and is worth crawling.

Combined pattern for maximum known-file coverage:
`gospider -s https://target.tld -o crawl --sitemap -d 3 --json --quiet > crawl/gospider_full.jsonl`

### Output parsing for downstream consumers

Extract unique URLs from JSONL output:
`jq -r '.output' crawl/gospider.jsonl 2>/dev/null | sort -u > gospider_urls.txt`

Extract URLs by source type (linkfinder, archive, href, etc.):
`jq -r 'select(.source == "linkfinder") | .output' crawl/gospider.jsonl | sort -u > gospider_linkfinder.txt`

Extract URLs with query parameters (likely injection points):
`jq -r '.output' crawl/gospider.jsonl | grep '?' | sort -u > gospider_parameterized.txt`

Filter by status code (when `-r` active follow-up is enabled):
`jq -r 'select(.status_code == 200) | .output' crawl/gospider.jsonl | sort -u > gospider_200.txt`

### Response length filtering

`-L/--filter-length` removes responses of a specific length from output — useful when the target returns a fixed-size error page for all missing paths:

1. Identify the error page size: `curl -s -o /dev/null -w '%{size_download}' https://target.tld/nonexistent_path_12345`
2. Filter it: `gospider -s https://target.tld -o crawl -L 4523 -d 3 --json --quiet > crawl/gospider_filtered.jsonl`

This is a rough equivalent of feroxbuster's `--filter-size` / ffuf's `-fs`.

---

## Tool-to-Tool Chaining

### katana primary → gospider secondary

The standard two-pass crawl workflow:
```
katana -u https://target.tld -d 5 -jc -ct 10m -silent -jsonl -o katana.jsonl
jq -r '.request.endpoint' katana.jsonl | sort -u > katana_urls.txt
gospider -s https://target.tld -a -r -w --subs -d 2 --json --quiet > gospider_enrich.jsonl
jq -r '.output' gospider_enrich.jsonl | sort -u > gospider_urls.txt
sort -u katana_urls.txt gospider_urls.txt > all_urls.txt
```

katana provides depth (headless, JS execution, form filling). gospider adds breadth (archive sources, third-party data). The merged set is the complete endpoint inventory.

### subfinder → gospider (subdomain-aware crawl)

```
subfinder -d target.tld -all -recursive -silent -o subs.txt
gospider -S subs.txt -o crawl -t 20 -c 5 -d 2 -k 1 --whitelist-domain target.tld --json --quiet > crawl/gospider_subs.jsonl
```

Crawl every discovered subdomain. `-t 20` processes 20 subdomains in parallel. `--whitelist-domain target.tld` prevents crawling off-domain links found on subdomains.

### gospider → nuclei (discovered URLs for template scanning)

```
jq -r '.output' crawl/gospider.jsonl | sort -u | httpx -silent | nuclei -t http/ -silent -o nuclei_results.txt
```

gospider discovers URLs → httpx validates they're live → nuclei runs templates against live URLs.

### gospider → ffuf (parameter fuzzing on discovered paths)

```
jq -r '.output' crawl/gospider.jsonl | grep -v '?' | sort -u | while read url; do
  ffuf -u "${url}?FUZZ=test" -w params.txt -mc 200,302 -fs 0 -o "ffuf_$(echo $url | md5sum | cut -c1-8).json" -of json
done
```

gospider discovers paths → ffuf fuzzes parameter names on each. Filter `grep -v '?'` strips URLs that already have parameters (handle those separately for value fuzzing).

### gospider → arjun (hidden parameter discovery)

```
jq -r '.output' crawl/gospider.jsonl | sort -u > gospider_urls.txt
arjun -i gospider_urls.txt --stable --rate-limit 30 -oJ arjun_params.json
```

gospider discovers the endpoint inventory → arjun probes each for hidden parameters.

### gospider `-a` overlap with waybackurls/gau

gospider `-a` bundles archive lookups from four sources into the crawl. The dedicated tools provide finer control:

| Capability | gospider `-a` | waybackurls | gau |
|---|---|---|---|
| Wayback Machine | yes | yes | yes |
| CommonCrawl | yes | no | yes |
| VirusTotal | yes | no | no |
| AlienVault OTX | yes | no | yes |
| URLScan | no | no | yes |
| Per-source rate control | no | no | `--providers`, `--blacklist` |
| Date filtering | no | no | `--from`, `--to` |
| Active follow-up crawl | yes (`-r`) | no | no |

Use gospider `-a` when you want archive data bundled with crawling. Use `waybackurls`/`gau` when you need date filtering, per-source control, or URLScan coverage.

### Complete recon pipeline position

```
subfinder -d target.tld -all -silent -o subs.txt          # passive subdomain enum
dnsx -l subs.txt -silent -o live_subs.txt                  # resolve
httpx -l live_subs.txt -silent -o live_http.txt            # live HTTP check
katana -list live_http.txt -d 5 -jc -silent -jsonl -o katana.jsonl  # primary crawl
gospider -S live_http.txt -a -r -w -d 2 -t 20 --json --quiet > gospider.jsonl  # secondary enrichment
cat <(jq -r '.request.endpoint' katana.jsonl) <(jq -r '.output' gospider.jsonl) | sort -u > all_endpoints.txt
```

gospider sits after katana in the pipeline, adding third-party source coverage to katana's headless crawl depth.

---

## Routed Consumers

- `reconnaissance/*` (secondary endpoint-discovery pass)
- `tooling/katana.md` (primary crawler; gospider is the secondary enrichment pass)
- `tooling/waybackurls.md` / `tooling/gau.md` (overlap on archive sources — gospider bundles them; the dedicated tools offer finer control)
- `tooling/arjun.md` (discovered URLs feed parameter discovery)
- `tooling/ffuf.md` (discovered paths feed fuzzing)
- `tooling/nuclei.md` (discovered URLs feed template scanning)
- `tooling/subfinder.md` (subdomain lists feed multi-site crawling)
