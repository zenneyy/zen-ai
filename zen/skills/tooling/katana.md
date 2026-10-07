---
name: katana
description: Katana crawler syntax, depth/js/known-files behavior, and stable concurrency controls.
---

# Katana CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/katana/usage
- https://docs.projectdiscovery.io/opensource/katana/running
- https://github.com/projectdiscovery/katana

Canonical syntax:
`katana [flags]`

## Complete Flag Reference

Verified against `katana --help` in `ghcr.io/zenneyy/zen-sandbox:1.2.2`.

### Input

- `-u, -list <url|file>` — target URL(s) or file of URLs
- `-resume <file>` — resume a previous scan from its `resume.cfg`
- `-e, -exclude <filter[]>` — exclude hosts matching a filter: `cdn`, `private-ips`, CIDR, IP, or regex

### Configuration

- `-r, -resolvers <file|csv>` — custom DNS resolvers (file or comma-separated)
- `-d, -depth <n>` — maximum crawl depth (default `3`)
- `-jc, -js-crawl` — enable endpoint parsing/crawling inside JavaScript files
- `-jsl, -jsluice` — deeper JS parsing via jsluice (memory intensive)
- `-ct, -crawl-duration <s|m|h|d>` — maximum crawl time; unit suffix required (default `s`)
- `-kf, -known-files <all|robotstxt|sitemapxml>` — crawl known files; requires depth ≥3
- `-mrs, -max-response-size <bytes>` — cap bytes read per response (default `4194304`)
- `-timeout <sec>` — per-request timeout (default `10`)
- `-time-stable <sec>` — seconds to wait for page stability after load (default `1`)
- `-aff, -automatic-form-fill` — enable automatic form filling (experimental)
- `-fx, -form-extraction` — extract form/input/textarea/select elements into JSONL output
- `-retry <n>` — per-request retry count (default `1`)
- `-proxy <url>` — HTTP or SOCKS5 proxy URL
- `-td, -tech-detect` — enable technology detection (Wappalyzer-style fingerprinting)
- `-H, -headers <header:value|file>` — custom headers; repeatable or load from file
- `-config <file>` — katana YAML configuration file
- `-fc, -form-config <file>` — custom form-fill configuration
- `-flc, -field-config <file>` — custom field extraction configuration
- `-s, -strategy <depth-first|breadth-first>` — visit strategy (default `depth-first`)
- `-iqp, -ignore-query-params` — collapse URLs that differ only in query-param values
- `-fsu, -filter-similar` — collapse similar-looking URLs (e.g. `/users/123` vs `/users/456`)
- `-fst, -filter-similar-threshold <n>` — distinct values before a path position is treated as parameterized (default `10`)
- `-tlsi, -tls-impersonate` — experimental JA3/ClientHello TLS randomization
- `-dr, -disable-redirects` — do not follow 3xx redirects
- `-pc, -path-climb` — auto-crawl parent path segments (path traversal discovery aid)
- `-kb, -knowledge-base` — enable knowledge-base classification of discovered content
- `-kb-secrets` — enable secrets extraction within the knowledge base
- `-kb-validate-secrets` — validate detected secrets against their provider (**sends live API calls** — OPSEC: confirms the key is real to the provider)
- `-kb-endpoints` — classify discovered endpoints (REST/GraphQL/SOAP/XHR)
- `-mdp, -max-domain-pages <n>` — cap pages crawled per domain (default unlimited)

### Headless

- `-hl, -headless` — enable headless Chrome crawling (experimental)
- `-hh, -hybrid` — enable hybrid headless crawling (standard + headless in one pass; experimental)
- `-sc, -system-chrome` — use locally installed Chrome instead of katana's bundled binary
- `-scp, -system-chrome-path <path>` — explicit path to a Chrome binary
- `-sb, -show-browser` — make the headless browser window visible (debug)
- `-ho, -headless-options <csv>` — additional Chrome launch flags, comma-separated
- `-nos, -no-sandbox` — launch Chrome with `--no-sandbox` (required in most containers)
- `-cdd, -chrome-data-dir <dir>` — persist browser profile/session across runs
- `-noi, -no-incognito` — disable incognito mode (needed for extensions, persistent cookies)
- `-cwu, -chrome-ws-url <url>` — connect to a Chrome instance via its DevTools WebSocket URL
- `-xhr, -xhr-extraction` — extract XHR request URLs and methods in JSONL output
- `-mfc, -max-failure-count <n>` — consecutive headless action failures before aborting (default `10`)
- `-ed, -enable-diagnostics` — headless diagnostic logging
- `-pls, -page-load-strategy <mode>` — when to consider a page loaded: `heuristic` (default), `load`, `domcontentloaded`, `networkidle`, `none`
- `-dwt, -dom-wait-time <sec>` — extra wait after page load when strategy is `domcontentloaded` (default `5`)
- `-csp, -captcha-solver-provider <name>` — captcha solver integration (e.g. `capsolver`)
- `-csk, -captcha-solver-key <key>` — API key for the captcha solver
- `-al, -auto-login <user:pass>` — automatic login before crawl (headless only)
- `-rf, -recorded-flow <file>` — replay a Chrome DevTools Recorder JSON before crawling (headless only)

### Scope

- `-cs, -crawl-scope <regex[]>` — in-scope URL regex (only URLs matching are followed)
- `-cos, -crawl-out-scope <regex[]>` — out-of-scope URL regex (matched URLs are excluded)
- `-fs, -field-scope <dn|rdn|fqdn|regex>` — pre-defined scope field or custom regex (default `rdn`)
- `-ns, -no-scope` — disable host-based default scope entirely
- `-do, -display-out-scope` — include out-of-scope endpoints in output (for external link inventory)

### Filter

- `-mr, -match-regex <regex[]>` — only emit URLs matching this regex (CLI or file)
- `-fr, -filter-regex <regex[]>` — exclude URLs matching this regex (CLI or file)
- `-f, -field <field>` — **(DEPRECATED — use `-ot`)** emit a single field; still functional but removed from new tooling
- `-sf, -store-field <field>` — field to store in per-host output files
- `-em, -extension-match <ext[]>` — only emit URLs with these extensions (e.g. `-em php,html,js,none`)
- `-ef, -extension-filter <ext[]>` — exclude URLs with these extensions (e.g. `-ef png,css`)
- `-ndef, -no-default-ext-filter` — remove katana's built-in extension exclusion list
- `-mdc, -match-condition <dsl>` — match responses by DSL expression (e.g. `status_code == 200 && contains(body, "token")`)
- `-fdc, -filter-condition <dsl>` — filter responses by DSL expression
- `-duf, -disable-unique-filter` — disable exact-content deduplication
- `-pcs, -page-content-similar` — enable page-content similarity filtering (runs after exact dedup)
- `-sdd, -similarity-deduplication` — alias for `-pcs`
- `-pcsm, -page-content-similar-mode <simhash|tfidf|bm25>` — similarity algorithm (default `simhash`)
- `-pcsd, -page-content-similar-distance <n>` — simhash max Hamming distance (default `3`)
- `-pcst, -page-content-similar-threshold <0-1>` — tfidf/bm25 minimum similarity score (default `0.85`)
- `-pcsn, -page-content-similar-budget <n>` — pages to fully process per similarity cluster (default `1`)
- `-fpt, -filter-page-type <type[]>` — filter by page type classification (e.g. `error`, `captcha`, `parked`)

### Rate Limit

- `-c, -concurrency <n>` — concurrent fetchers (default `10`)
- `-p, -parallelism <n>` — concurrent input targets (default `10`)
- `-rd, -delay <sec>` — fixed delay between each request
- `-rl, -rate-limit <n>` — max requests per second (default `150`)
- `-rlm, -rate-limit-minute <n>` — max requests per minute
- `-hrl, -host-rate-limit <n>` — max requests per second per host
- `-hrlm, -host-rate-limit-minute <n>` — max requests per minute per host

### Output

- `-o, -output <file>` — write output to file
- `-ot, -output-template <template>` — custom output template string (replaces deprecated `-f`)
- `-sr, -store-response` — store full HTTP request/response pairs
- `-srd, -store-response-dir <dir>` — custom directory for stored responses
- `-ncb, -no-clobber` — do not overwrite an existing output file
- `-sfd, -store-field-dir <dir>` — custom directory for per-host field files
- `-or, -omit-raw` — omit raw request/response from JSONL output
- `-ob, -omit-body` — omit response body from JSONL output
- `-lof, -list-output-fields` — list available JSONL output fields and exit
- `-eof, -exclude-output-fields <field[]>` — exclude specific fields from JSONL output
- `-j, -jsonl` — JSONL output format
- `-nc, -no-color` — disable ANSI color in terminal output
- `-silent` — suppress all output except results
- `-v, -verbose` — verbose output
- `-debug` — debug-level output
- `-version` — print version and exit

### Debug

- `-hc, -health-check` — run a diagnostic self-check
- `-elog, -error-log <file>` — write request errors to a log file
- `-pprof-server` — enable Go pprof profiling server

### Update

- `-up, -update` — update katana to latest version
- `-duc, -disable-update-check` — disable automatic update check

---

## Agent-Safe Baseline

`mkdir -p crawl && katana -u https://target.tld -d 3 -ct 10m -mdp 2000 -fsu -jc -kf robotstxt -c 10 -p 10 -rl 50 -timeout 10 -retry 1 -ef png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,map -silent -j -or -ob -o crawl/katana.jsonl`

Rationale for each flag:
- `-d 3 -ct 10m -mdp 2000` — bounded depth, time, and page count prevent runaway crawls.
- `-fsu` — collapse parameterized URL variants that add noise.
- `-jc` — parse JS for endpoints; `-jsl` is intentionally excluded from the baseline (memory-heavy, enable it on narrowed targets only).
- `-kf robotstxt` — discover disallowed paths without the heavier `sitemapxml` fetch.
- `-c 10 -p 10 -rl 50` — conservative concurrency and rate; tune upward on targets that tolerate it.
- `-or -ob` — strip raw request/response and body from JSONL; keeps output manageable.
- `-ef <static exts>` — filter static assets that add bulk without endpoints.

---

## Crawl Modes

Katana supports three crawl modes, selectable independently from visit strategy.

### Standard (default)

HTTP-only crawling. No browser — fast, low memory, handles the majority of server-rendered applications. JS files are fetched and optionally parsed (`-jc`/`-jsl`) but not executed.

`katana -u https://target.tld -d 3 -jc -silent`

### Headless (`-hl`)

Launches headless Chrome to render pages. Required for SPAs, client-side routing, JS-generated DOM content, and any target that gates navigation behind JS execution. Significantly slower and heavier than standard mode.

`katana -u https://target.tld -hl -sc -nos -d 3 -jc -xhr -pls heuristic -mfc 10 -silent -j -o crawl/katana_headless.jsonl`

### Hybrid (`-hh`)

Combines standard and headless in a single pass: standard HTTP crawl first, then headless rendering for pages that returned JS-heavy or empty bodies. Balances coverage against resource cost — use it when you suspect mixed server/client rendering and don't want to run two separate crawls.

`katana -u https://target.tld -hh -sc -nos -d 3 -jc -xhr -silent -j -o crawl/katana_hybrid.jsonl`

### Visit Strategy (`-s`)

Orthogonal to crawl mode. Default is `depth-first` — follows links down each path before backtracking. `breadth-first` explores all links at each depth level before going deeper; better for wide, shallow inventories (e.g. sitemap enumeration, multi-section apps where you want breadth over depth).

`katana -u https://target.tld -s breadth-first -d 2 -jc -silent`

---

## JavaScript Parsing and Endpoint Extraction

### `-jc` (js-crawl)

Fetches JavaScript files encountered during the crawl and runs regex-based endpoint extraction over them. Catches API paths, hardcoded URLs, route definitions, and configuration endpoints embedded in JS bundles. Minimal memory overhead; enable it by default on most targets.

### `-jsl` (jsluice)

Invokes the jsluice engine for deeper structural JS parsing — AST-level analysis that catches endpoints buried in template literals, concatenation chains, and function calls that regex misses. **Memory intensive.** On a large SPA with dozens of JS bundles, memory can spike 2–5× over a `-jc`-only crawl.

Use `-jsl` on narrowed targets (single app, bounded `-ct` and `-mdp`) where the extra coverage justifies the cost. Do not enable it on wide multi-subdomain crawls.

### Combining with Knowledge Base

`-jc` and `-jsl` extract raw endpoints. Adding `-kb-endpoints` classifies them (REST vs GraphQL vs SOAP vs XHR), producing structured output that routes directly to the appropriate testing playbook. Adding `-kb-secrets` runs secret-pattern matching against JS file contents — API keys, tokens, credentials embedded in client bundles.

`katana -u https://app.target.tld -d 3 -ct 10m -jc -jsl -kb -kb-secrets -kb-endpoints -mdp 1000 -fsu -silent -j -or -ob -o crawl/katana_js_deep.jsonl`

---

## Knowledge Base

Katana's knowledge base (`-kb`) classifies crawl output into structured categories: content types, technologies, endpoints, and secrets. Each sub-flag enables a classification layer.

- `-kb` — base classification (content types, technology hints, page categorization)
- `-kb-secrets` — run secret-pattern detection over response bodies and JS files (API keys, tokens, connection strings, private keys)
- `-kb-validate-secrets` — send live validation requests to the detected secret's provider to confirm whether the key is active. **OPSEC warning:** this generates outbound API calls to third-party services (AWS, GCP, GitHub, Slack, etc.) from the scanner's IP, confirming to the provider that the key was found and tested. Use only when key validity matters and the exfiltration signal is acceptable.
- `-kb-endpoints` — classify discovered endpoints into REST, GraphQL, SOAP, and XHR categories

### When to use

- **Reconnaissance scans:** `-kb -kb-secrets -kb-endpoints` gives a structured attack surface map. Parse the JSONL for endpoint classifications and secrets separately.
- **Quick secret sweep:** `-kb -kb-secrets` on a narrowed target (single app or domain) to find leaked credentials in client-side code.
- **Do not enable `-kb-validate-secrets` in stealth engagements** — the validation requests are outbound to external providers, not to the target, but they reveal the scanner's IP and the fact that someone is testing those keys.

---

## Scope Controls

Katana's default scope is `rdn` (root domain name) — it follows links to any subdomain of the target's root domain. Scope controls restrict or expand this.

### Field Scope (`-fs`)

Pre-defined scope levels:
- `dn` — exact domain name only (e.g. `app.target.tld` stays on `app.target.tld`)
- `rdn` — root domain + all subdomains (default; `target.tld` includes `api.target.tld`, `admin.target.tld`)
- `fqdn` — exact FQDN only (stricter than `dn` — no subdomain drift)
- Custom regex — e.g. `-fs '(staging\.target\.tld|target\.tld)'` for multi-environment scoping

### Regex Scope (`-cs`/`-cos`)

Fine-grained URL-level regex:
- `-cs <regex>` — only follow URLs matching this pattern (whitelist). Multiple `-cs` values are OR'd.
- `-cos <regex>` — exclude URLs matching this pattern (blacklist). Applied after `-cs`.

`katana -u https://target.tld -cs '/api/' -cos '/api/v1/internal/' -d 5 -jc -silent`

### Host Exclusion (`-e`)

Exclude hosts by category before crawling starts:
- `-e cdn` — skip known CDN hosts (avoid crawling CDN-served assets)
- `-e private-ips` — skip private/internal IP ranges
- CIDR, IP, or regex for custom exclusion

`katana -u https://target.tld -e cdn,private-ips -d 3 -jc -silent`

### No Scope (`-ns`)

Disable all host-based scoping. The crawler follows every link regardless of domain. **Use only for specific external-link mapping tasks** — this will spider the internet otherwise. Always combine with `-ct` and `-mdp`.

### Display Out-of-Scope (`-do`)

Include out-of-scope URLs in the output without following them. Useful for mapping external dependencies (CDNs, analytics, third-party APIs) without crawling them.

### Domain Page Cap (`-mdp`)

`-mdp <n>` caps the total pages crawled per domain. Essential for large targets where the crawl would otherwise run indefinitely. Not a depth limit — it caps total unique pages regardless of depth.

---

## Similarity and Dedup Filtering

Large targets generate thousands of near-identical pages (user profiles, product listings, search results). Katana's filtering stack operates at three levels.

### URL-Level Dedup

- `-fsu` — collapse URLs that differ only in a parameterized path segment (e.g. `/users/123` and `/users/456` → one representative). Uses katana's structural URL normalization.
- `-fst <n>` — number of distinct values a path position must see before it's treated as parameterized (default `10`). Lower values are more aggressive; raise for paths where the first few values are meaningfully different routes, not IDs.
- `-iqp` — collapse URLs that differ only in query parameter values. `/search?q=foo` and `/search?q=bar` → one representative. Useful for search-heavy sites; may suppress valid targets if different query values reach different server-side handlers.

### Page-Content-Level Dedup (`-pcs`/`-sdd`)

Operates after katana's built-in exact-content deduplication. Enables fuzzy similarity comparison of page bodies:

- `-pcs` (or `-sdd`, alias) — enable content similarity filtering
- `-pcsm <simhash|tfidf|bm25>` — similarity algorithm (default `simhash`)
  - `simhash` — locality-sensitive hash; fast, fixed memory, works on large page sets. Best for HTML pages with minor template variations.
  - `tfidf` — term-frequency/inverse-document-frequency vector comparison. Better for text-heavy pages where structural similarity is low but content overlap is high.
  - `bm25` — probabilistic relevance scoring. Similar use case to tfidf but handles variable-length documents better.
- `-pcsd <n>` — simhash max Hamming distance (default `3`). Lower = stricter (only near-identical pages cluster). Raise for sites with aggressive personalization injected into otherwise-identical pages.
- `-pcst <0-1>` — tfidf/bm25 minimum similarity score (default `0.85`). Lower = more aggressive dedup.
- `-pcsn <n>` — pages to fully process per similarity cluster (default `1`). The first `n` pages in each cluster get full processing; the rest are suppressed. Raise when you suspect WAF/CDN caching differences across cluster members.

### Output Filtering

- `-mr <regex>` — emit only URLs matching this regex (whitelist on output)
- `-fr <regex>` — exclude URLs matching this regex from output (blacklist)
- `-em <ext[]>` — emit only URLs with these extensions (e.g. `-em php,html,js,none` where `none` matches extensionless paths)
- `-ef <ext[]>` — exclude URLs with these extensions
- `-ndef` — remove katana's default extension exclusion list (use when the default list suppresses file types you want)
- `-mdc <dsl>` — match responses by DSL expression: `status_code`, `content_length`, `body`, `header`, `url` fields available (e.g. `-mdc 'status_code == 200 && contains(body, "api_key")'`)
- `-fdc <dsl>` — filter (exclude) responses by DSL expression
- `-fpt <type[]>` — filter by page-type classification: `error`, `captcha`, `parked`, etc. Requires page-type detection in the crawl pipeline.
- `-duf` — disable the built-in exact-content unique filter entirely (use when you need to see every response even if duplicated — e.g. timing analysis, cache behavior testing)

---

## Form Filling and Authentication

### Automatic Form Fill (`-aff`)

Experimental. Katana fills and submits HTML forms encountered during crawling using built-in heuristics (username/email/password fields get default values). Expands crawl coverage into post-authentication pages, multi-step wizards, and form-gated content.

Combine with `-fx` to extract form structures in the JSONL output even if you don't want auto-submission.

### Form Configuration (`-fc`)

Custom form-fill rules via a YAML config file. Override the default heuristics with target-specific values (real credentials for a test account, specific search terms, custom field mappings).

`katana -u https://target.tld -hl -sc -nos -aff -fc form_config.yaml -d 5 -silent -j -o crawl/katana_forms.jsonl`

### Field Configuration (`-flc`)

Custom field extraction rules. Define what katana extracts from form/input/textarea/select elements beyond the defaults.

### Auto-Login (`-al`, headless only)

`-al user:pass` performs a login flow before crawling begins. Katana navigates to the target, identifies login form fields, fills username and password, submits, waits for redirect/page load, then starts the crawl from the authenticated state.

`katana -u https://target.tld -hl -sc -nos -al "testuser:testpass123" -d 5 -ct 15m -jc -silent -j -o crawl/katana_authed.jsonl`

### Recorded Flows (`-rf`, headless only)

Replay a Chrome DevTools Recorder JSON export before crawling. Record a complex authentication flow (MFA, CAPTCHA interaction, multi-page wizard) in Chrome DevTools, export the JSON, and katana replays it to establish session state before the crawl starts.

`katana -u https://target.tld -hl -sc -nos -rf auth_flow.json -d 5 -ct 15m -jc -silent -j -o crawl/katana_recorded.jsonl`

### Persistent Sessions (`-cdd`/`-noi`)

`-cdd <dir>` persists the Chrome profile directory across runs — cookies, localStorage, IndexedDB survive between crawls. Combine with `-noi` (no incognito) so the profile actually persists. Useful for targets that require session cookies set by a prior manual login.

`katana -u https://target.tld -hl -sc -nos -cdd ./chrome_profile -noi -d 5 -jc -silent -j -o crawl/katana_persistent.jsonl`

---

## Headless Chrome Configuration

### Page Load Strategy (`-pls`)

Controls when katana considers a page "loaded" and begins link extraction:

- `heuristic` (default) — katana's own heuristic; balances speed and completeness for most SPAs.
- `load` — waits for the `load` event (all resources including images/fonts). Slowest; use when page content depends on late-loading resources.
- `domcontentloaded` — waits for DOM parsing to complete (before images/fonts). Faster than `load`; miss late JS execution. Combine with `-dwt` for an extra wait.
- `networkidle` — waits until the network is idle (no in-flight requests for a threshold). Best for heavily async SPAs that load data after DOMContentLoaded.
- `none` — no wait; extract links immediately. Fastest but catches only server-rendered HTML; misses all client-side rendering.

### DOM Wait Time (`-dwt`)

Extra seconds to wait after the page-load-strategy event fires. Default `5` when strategy is `domcontentloaded`. Increase for SPAs with slow API calls that populate the DOM after the initial load event.

### Captcha Solving (`-csp`/`-csk`)

Integrate a captcha solving service (e.g. CapSolver) for targets that present CAPTCHAs during crawling. `-csp capsolver -csk <api_key>`. The solver runs inline — the headless browser waits for the CAPTCHA to be solved before proceeding.

### Chrome WebSocket URL (`-cwu`)

Connect to an already-running Chrome instance via its DevTools WebSocket URL instead of launching a new one. Useful when Chrome is managed externally (e.g. a browser pool, a debug session with custom extensions loaded).

`katana -u https://target.tld -hl -cwu ws://127.0.0.1:9222/devtools/browser/<id> -d 3 -jc -silent`

### Chrome Path (`-scp`)

Explicit path to a Chrome binary. Use when multiple Chrome/Chromium versions are installed and `-sc` picks the wrong one.

### Failure Handling (`-mfc`)

`-mfc <n>` — maximum consecutive headless action failures before katana aborts (default `10`). Raise on unstable targets with intermittent JS errors; lower for fast-fail behavior on broken targets.

### Diagnostics (`-ed`)

Enable headless diagnostic output — Chrome DevTools Protocol messages, page lifecycle events, JS console output. Noisy; use for debugging headless failures, not routine crawls.

### Show Browser (`-sb`)

Make the headless Chrome window visible. Requires a display server (X11/Wayland). Useful for debugging authentication flows and seeing what katana sees.

### Headless Options (`-ho`)

Pass additional Chrome launch flags as comma-separated values:
- Proxy: `-ho proxy-server=http://127.0.0.1:48080`
- Disable GPU: `-ho --disable-gpu`
- Multiple: `-ho --disable-gpu,proxy-server=http://127.0.0.1:48080,--disable-extensions`

---

## Rate Control and Evasion

### Global Rate Controls

- `-c <n>` — concurrent fetchers (default `10`). Each fetcher handles one request at a time.
- `-p <n>` — concurrent input targets when processing multiple URLs from `-list` (default `10`).
- `-rl <n>` — global max requests per second (default `150`). The primary throttle.
- `-rlm <n>` — global max requests per minute. Use for targets with per-minute rate limits instead of per-second.
- `-rd <sec>` — fixed delay injected between each request. Coarser than `-rl`; use for very aggressive rate limiting where even low `-rl` values burst too fast.

### Per-Host Rate Controls

- `-hrl <n>` — max requests per second to each individual host. Critical for multi-subdomain crawls (`-fs rdn`) where the global rate spreads across hosts but individual hosts need protection.
- `-hrlm <n>` — per-host max requests per minute.

Per-host limits are applied independently of global limits. If `-rl 100 -hrl 10` and 5 hosts are in scope, each host sees ≤10 r/s but total throughput can reach 50 r/s.

### Proxy

`-proxy <url>` — route all katana traffic through the specified proxy. The sandbox sets `HTTP_PROXY`/`HTTPS_PROXY` env vars to route through Caido transparently; `-proxy` is for when you need katana to use a different proxy than the environment default.

- HTTP: `-proxy http://127.0.0.1:8080`
- SOCKS5: `-proxy socks5://127.0.0.1:1080`
- Authenticated: `-proxy http://user:pass@proxy.tld:8080`

### TLS Impersonation (`-tlsi`)

Experimental JA3/ClientHello randomization. Randomizes the TLS fingerprint to evade JA3-based bot detection. Some CDN WAFs (Cloudflare, Akamai) fingerprint the TLS handshake; a Go-default ClientHello is a strong bot signal.

### Custom Headers (`-H`)

Inject headers into every request:
- CLI: `-H "User-Agent: Mozilla/5.0 ..." -H "Cookie: session=abc123"`
- File: `-H headers.txt` where the file has one `Header: Value` per line

Use for API keys, custom auth tokens, cookie injection, and UA spoofing.

### Redirect Control (`-dr`)

`-dr` disables following 3xx redirects. Use when the redirect target is out of scope or when you need to capture the redirect chain itself (login flows, OAuth redirects, open redirect testing).

---

## Output Controls

### JSONL Output (`-j`)

Default JSONL includes the full request URL, method, headers, body, response headers, response body, status code, content length, technologies, and endpoint metadata. This is verbose — a single page can generate several KB per record.

Reduction flags for automation:
- `-or` — omit raw request/response bytes. Keeps the parsed fields; drops the wire-format dump.
- `-ob` — omit the response body. Keeps headers, status, URL, metadata; drops the HTML/JSON/etc body.
- `-mrs <bytes>` — cap bytes read per response (default 4MB). Lower to 1MB or 512KB for large-asset-heavy sites.
- `-eof <field[]>` — exclude specific JSONL fields. Run `-lof` to see available field names, then exclude what you don't need.

### Output Template (`-ot`)

Replaces the deprecated `-f` flag. Custom output format using Go template syntax. Available template variables correspond to JSONL fields.

**Deprecation note for `-f`:** the old `-f url` / `-f path` / `-f fqdn` / etc. flag still works but is deprecated. Use `-ot` instead. Example migration: `-f url` → the equivalent `-ot` template for URL-only output. For a plain URL list, `-silent` output (which prints URLs by default) or piping JSONL through `jq` is simpler.

### Store Response (`-sr`/`-srd`)

`-sr` saves full HTTP request/response pairs to disk. Default directory is a `katana_responses/` subdirectory; override with `-srd <dir>`. Use for offline analysis, evidence preservation, or feeding responses to other tools.

### Per-Host Field Storage (`-sf`/`-sfd`)

`-sf <field>` writes one field per URL to per-host files (e.g. all URLs for `app.target.tld` in one file, all for `api.target.tld` in another). `-sfd <dir>` sets the output directory. Useful for splitting multi-subdomain crawls into per-host inventories.

### No-Clobber (`-ncb`)

Do not overwrite an existing output file. Appends a suffix or errors instead. Use in automation pipelines where re-running a crawl shouldn't destroy previous results.

### Error Log (`-elog`)

`-elog <file>` writes request errors (timeouts, connection failures, TLS errors) to a separate log file. Parse it post-crawl to identify unreachable hosts, rate-limited paths, or TLS configuration issues.

---

## Common Patterns

Fast crawl baseline:
`katana -u https://target.tld -d 3 -jc -silent`

Deep JS-aware crawl (narrowed target, time-bounded):
`katana -u https://target.tld -d 5 -ct 15m -jc -jsl -kf all -c 10 -p 10 -rl 50 -fsu -mdp 2000 -silent -j -or -ob -o crawl/katana_deep.jsonl`

Multi-target batch with JSONL output:
`katana -list urls.txt -d 3 -jc -hrl 20 -fsu -silent -j -or -ob -o crawl/katana_batch.jsonl`

Headless crawl with local Chrome:
`katana -u https://target.tld -hl -sc -nos -xhr -d 3 -pls heuristic -mfc 10 -jc -silent -j -or -ob -o crawl/katana_headless.jsonl`

Hybrid crawl (standard + headless):
`katana -u https://target.tld -hh -sc -nos -xhr -d 3 -jc -fsu -silent -j -or -ob -o crawl/katana_hybrid.jsonl`

Headless crawl through proxy:
`katana -u https://target.tld -hl -sc -ho proxy-server=http://127.0.0.1:48080 -nos -jc -silent -j -or -ob -o crawl/katana_proxy.jsonl`

Knowledge base scan (secrets + endpoint classification):
`katana -u https://app.target.tld -d 3 -ct 10m -jc -jsl -kb -kb-secrets -kb-endpoints -mdp 1000 -fsu -silent -j -or -ob -o crawl/katana_kb.jsonl`

Authenticated crawl (auto-login):
`katana -u https://app.target.tld -hl -sc -nos -al "testuser:testpass123" -d 5 -ct 15m -jc -fsu -silent -j -or -ob -o crawl/katana_authed.jsonl`

Authenticated crawl (recorded flow):
`katana -u https://app.target.tld -hl -sc -nos -rf auth_flow.json -d 5 -ct 15m -jc -fsu -silent -j -or -ob -o crawl/katana_recorded.jsonl`

Form-filling crawl:
`katana -u https://target.tld -hl -sc -nos -aff -fx -fc form_config.yaml -d 5 -ct 15m -jc -fsu -silent -j -or -ob -o crawl/katana_forms.jsonl`

Similarity-filtered wide crawl:
`katana -u https://target.tld -d 4 -jc -fsu -fst 5 -iqp -pcs -pcsm simhash -pcsd 3 -mdp 5000 -ef png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,map -silent -j -or -ob -o crawl/katana_deduped.jsonl`

Technology detection pass:
`katana -u https://target.tld -d 2 -td -jc -silent -j -or -ob -o crawl/katana_tech.jsonl`

Resume an interrupted crawl:
`katana -resume crawl/resume.cfg`

DSL-filtered crawl (only 200 responses containing "token"):
`katana -u https://target.tld -d 3 -jc -mdc 'status_code == 200 && contains(body, "token")' -silent -j -o crawl/katana_tokens.jsonl`

API-path-only output (regex match):
`katana -u https://target.tld -d 3 -jc -mr '/api/' -fsu -silent -j -or -ob -o crawl/katana_api.jsonl`

Extension-targeted crawl (PHP/JSP files only):
`katana -u https://target.tld -d 3 -jc -em php,jsp,none -fsu -silent -j -or -ob -o crawl/katana_dynamic.jsonl`

Breadth-first shallow inventory:
`katana -u https://target.tld -s breadth-first -d 2 -jc -kf all -fsu -silent -j -or -ob -o crawl/katana_breadth.jsonl`

Path-climbing discovery:
`katana -u https://target.tld/app/v2/dashboard -pc -d 3 -jc -silent`

Store full responses for offline analysis:
`katana -u https://target.tld -d 3 -jc -sr -srd crawl/responses -fsu -silent -j -o crawl/katana.jsonl`

Per-host field output:
`katana -list subdomains.txt -d 3 -jc -sf url -sfd crawl/per_host -fsu -hrl 20 -silent`

---

## Keeping Output Small

Katana has **no default page cap** — an unbounded crawl on a large target will fill disk.

### Bound the crawl

- `-fs fqdn` (or `-cs`/`-cos` regex) to prevent subdomain drift
- `-mdp <n>` to cap pages per domain
- `-ct <duration>` to cap wall-clock time
- `-d <n>` to cap depth
- `-e cdn,private-ips` to skip CDN and internal hosts

### Reduce noise before it's written

- `-fsu` + `-fst` to collapse parameterized URL variants
- `-iqp` to collapse query-param-only variants
- `-pcs -pcsm simhash` to deduplicate pages with similar content
- `-ef <static exts>` to drop images, fonts, stylesheets
- `-fpt error,captcha,parked` to drop error pages, captchas, parked domains
- `-fr <regex>` to exclude known-noisy URL patterns (e.g. `/static/`, `/assets/`)
- `-em <exts>` to include only the extensions you care about

### Shrink each record

- `-or -ob` to strip raw bytes and response bodies from JSONL
- `-mrs <bytes>` to cap per-response bytes read (default 4MB — lower to 1MB for most targets)
- `-eof <fields>` to exclude specific JSONL fields
- `-silent` with no `-j` for a plain URL list (smallest possible output)

### Post-crawl cleanup

Once the crawl finishes, extract what you need (endpoint list, interesting paths, secrets from KB output) and delete the raw crawl file. Don't keep large raw crawls around after distillation. `du -sh <out>` — if outsized for scope, tighten filters and re-run.

---

## Critical Correctness Rules

- `-kf` accepts only `all`, `robotstxt`, or `sitemapxml`. Requires depth ≥3.
- `-hl` for headless mode, `-hh` for hybrid. They are mutually exclusive.
- `-proxy` expects a single proxy URL string (e.g. `http://127.0.0.1:8080`).
- `-ho` expects comma-separated Chrome flags (e.g. `-ho --disable-gpu,proxy-server=http://127.0.0.1:8080`).
- `-al` and `-rf` are headless-only — they error without `-hl` or `-hh`.
- `-pls` accepts exactly: `heuristic`, `load`, `domcontentloaded`, `networkidle`, `none`.
- `-dwt` only applies when `-pls domcontentloaded`.
- `-pcsm` accepts exactly: `simhash`, `tfidf`, `bm25`. Default `simhash`.
- `-f` is deprecated; use `-ot` for custom output templates.
- `-fst` default is `10`; lower values are more aggressive dedup.
- `-pcst` range is 0–1 (string, not int); applies only to tfidf/bm25 modes.
- `-kb-validate-secrets` sends live outbound API calls — not passive.
- Ensure parent directory exists before `-o <path>`.
- `-resume` takes a `resume.cfg` file path, not a URL or crawl directory.
- `-e` filter values are additive: `-e cdn,private-ips` excludes both.

---

## Usage Rules

- Keep `-d`, `-c`, `-p`, `-rl` explicit for reproducible runs.
- Use `-ef` early to reduce static-file noise.
- Prefer `-proxy` over environment proxy variables when proxying only katana traffic.
- Use `-hrl`/`-hrlm` for multi-subdomain crawls to protect individual hosts.
- Always combine `-ns` (no scope) with `-ct` and `-mdp` to prevent unbounded crawling.
- Do not enable `-jsl` on wide multi-subdomain crawls — memory intensive.
- Use `-hc` only for one-time diagnostics, not in automation loops.
- Prefer `-ncb` in CI/automation to avoid clobbering previous results.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

---

## Failure Recovery

- **Crawl runs too long:** lower `-d`, add `-ct`, add `-mdp`.
- **Memory spikes:** disable `-jsl`, lower `-c`/`-p`, lower `-mrs`.
- **Headless fails with Chrome errors:** drop `-sc` or specify `-scp <path>` to a known-good binary; add `-nos` in containers; lower `-mfc` for fast-fail.
- **Headless page loads timeout:** raise `-timeout` and `-time-stable`; try `-pls load` or `-pls networkidle` instead of `heuristic`.
- **Captcha pages block the crawl:** add `-csp`/`-csk` for automated solving, or use `-rf` with a recorded flow that solves the CAPTCHA.
- **Output is noisy:** tighten scope (`-fs fqdn`, `-cs`/`-cos`), add `-ef` and `-fpt` filters, enable `-fsu` and `-pcs`.
- **Duplicate content floods output:** enable `-pcs` with `-pcsm simhash`; lower `-pcsd` for stricter dedup; add `-iqp`.
- **Crawl interrupted:** katana writes `resume.cfg` — use `-resume <file>` to continue.
- **TLS errors:** try `-tlsi` for ClientHello randomization; check `-proxy` routing.
- **Rate-limited by target (429s):** lower `-rl`/`-hrl`, add `-rd` for inter-request delay, enable `-retry`.
- **Forms not followed:** add `-aff`; provide `-fc <config>` for custom field values.
- **No JS endpoints found:** verify `-jc` is enabled; try `-jsl` on a narrowed target; check `-ef` isn't filtering `.js` files.

---

## Tool-to-Tool Chaining

**Upstream (feeding katana):**
- `subfinder -d target.tld -silent | dnsx -silent | httpx -silent -o live.txt` → `katana -list live.txt -d 3 -jc -hrl 20 -fsu -silent -j -or -ob -o crawl/katana.jsonl`
- `naabu -host target.tld -p - -silent | httpx -silent -o live.txt` → feed into katana for port-discovered web services

**Downstream (katana output feeding):**
- `katana → nuclei`: extract URLs from crawl output and feed to nuclei for vulnerability scanning
  `jq -r '.request.endpoint' crawl/katana.jsonl | sort -u | nuclei -l /dev/stdin -t cves/ -silent`
- `katana → ffuf`: extract directories and path patterns for targeted fuzzing
  `jq -r '.request.endpoint' crawl/katana.jsonl | unfurl paths | sort -u > paths.txt && ffuf -u https://target.tld/FUZZ -w paths.txt`
- `katana → sqlmap`: extract form endpoints with parameters for injection testing
  `jq -r 'select(.request.method == "POST") | .request.endpoint' crawl/katana.jsonl | sort -u > post_endpoints.txt`
- `katana KB → manual review`: parse knowledge-base output for secrets and classified endpoints
  `jq 'select(.knowledgebase.secrets | length > 0)' crawl/katana_kb.jsonl`

**Full pipeline position:**
`subfinder → dnsx → httpx → katana (crawl + KB) → [nuclei | ffuf | sqlmap with katana-discovered endpoints and parameters]`

---

## Complementary Crawlers / JS Endpoint Extractors

Complementary crawlers / JS endpoint extractors in the sandbox:
- `gospider -s https://target.tld -d 3 -c 10 -t 20` — alternate crawler;
  picks up things Katana misses on weird sites; use it as a second
  pass when Katana output looks thin.
- `~/tools/JS-Snooper/js_snooper.sh <domain>` and
  `~/tools/jsniper.sh/jsniper.sh <domain>` — both take a bare domain and
  run their own JS-file discovery internally (jsniper drives httpx +
  katana + nuclei file templates). Reach for them when you want a quick
  "find endpoints/keys/secrets in any JS this domain serves" sweep
  without wiring it up yourself.

---

If uncertain, query web_search with:
`site:docs.projectdiscovery.io katana <flag> usage`
