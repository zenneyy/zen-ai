---
name: httpx
description: ProjectDiscovery httpx probing syntax, exact probe flags, and automation-safe output patterns.
---

# httpx CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/httpx/usage
- https://docs.projectdiscovery.io/opensource/httpx/running
- https://github.com/projectdiscovery/httpx

Canonical syntax:
`httpx [flags]`

High-signal flags:
- `-u, -target <url>` single or multiple targets (comma-separated or repeat flag)
- `-l, -list <file>` target list (one host/URL per line)
- `-rr, -request <file>` raw HTTP request file
- `-im, -input-mode <mode>` input format (`burp`)
- `-sc, -status-code` display status code
- `-title` page title
- `-server, -web-server` Server header value
- `-td, -tech-detect` Wappalyzer technology detection
- `-cpe` CPE (Common Platform Enumeration) with product version
- `-wp, -wordpress` WordPress plugins and themes
- `-cdn` CDN/WAF in use (default on)
- `-ip` resolved IP address
- `-asn` ASN information
- `-fr, -follow-redirects` follow redirects
- `-mc <codes>` / `-fc <codes>` match or filter status codes
- `-mdc <expr>` / `-fdc <expr>` match or filter by DSL expression
- `-path <path_or_file>` probe specific path(s)
- `-p, -ports <ports>` probe custom ports (nmap syntax: `http:1,2-10,https:80`)
- `-proxy, -http-proxy <url>` HTTP/SOCKS proxy
- `-tlsi, -tls-impersonate <target>` experimental JA3 TLS impersonation (`chrome` or full JA3 string)
- `-ss, -screenshot` headless browser page screenshot
- `-j, -json` JSONL output
- `-sr, -store-response` store request/response artifacts
- `-srd, -store-response-dir <dir>` custom artifact directory
- `-er, -extract-regex <re>` extract matching content from responses
- `-ep, -extract-preset <name>` extract by preset (`url`, `ipv4`, `mail`)
- `-silent` compact output
- `-rl <n>` requests/second cap (default 150)
- `-t <n>` threads (default 50)
- `-timeout <seconds>` request timeout (default 10)
- `-retries <n>` retry attempts
- `-o <file>` output file

Agent-safe baseline for automation:
`httpx -l hosts.txt -sc -title -server -td -fr -timeout 10 -retries 1 -rl 50 -t 25 -silent -j -o httpx.jsonl`

Common patterns:
- Quick live+fingerprint check:
  `httpx -l hosts.txt -sc -title -server -td -silent -o httpx.txt`
- Full recon probe (IP, ASN, CDN, tech, JARM, favicon, CPE):
  `httpx -l hosts.txt -sc -title -server -td -ip -asn -cdn -jarm -favicon -cpe -fr -silent -j -o httpx_recon.jsonl`
- Probe known admin paths:
  `httpx -l hosts.txt -path /,/login,/admin,/.env,/api -sc -title -silent -j -o httpx_paths.jsonl`
- Probe both schemes explicitly:
  `httpx -l hosts.txt -nf -sc -title -silent`
- Multi-port probing:
  `httpx -l hosts.txt -p http:80,8080,8000,https:443,8443 -sc -title -td -silent -j -o httpx_ports.jsonl`
- Vhost detection pass:
  `httpx -l hosts.txt -vhost -sc -title -silent -j -o httpx_vhost.jsonl`
- Proxy-instrumented probing:
  `httpx -l hosts.txt -sc -title -proxy http://127.0.0.1:48080 -silent -j -o httpx_proxy.jsonl`
- Response-storage pass for downstream content parsing:
  `httpx -l hosts.txt -fr -sr -srd recon/httpx_store -sc -title -server -cl -ct -location -probe -silent`
- Screenshot pass:
  `httpx -l hosts.txt -ss -system-chrome -st 15s -sid 2s -sc -title -silent -j -o httpx_screenshots.jsonl`
- Extract emails from response bodies:
  `httpx -l hosts.txt -ep mail -silent -j -o httpx_emails.jsonl`
- Extract API endpoints via regex:
  `httpx -l hosts.txt -er '/api/v[0-9]+/[a-z]+' -silent -j -o httpx_api.jsonl`
- WordPress plugin/theme enumeration:
  `httpx -l hosts.txt -wp -sc -title -silent -j -o httpx_wp.jsonl`
- Filter out CDN-fronted hosts:
  `httpx -l hosts.txt -fcdn cloudfront,fastly,cloudflare -sc -title -silent -j -o httpx_direct.jsonl`
- Match only fast-responding hosts:
  `httpx -l hosts.txt -mrt '< 2' -sc -rt -title -silent -j -o httpx_fast.jsonl`
- DSL condition match (status 200 AND body contains "admin"):
  `httpx -l hosts.txt -mdc 'status_code == 200 && contains(body, "admin")' -silent -j -o httpx_admin.jsonl`
- Probe all IPs behind a hostname:
  `httpx -l hosts.txt -pa -sc -ip -title -silent -j -o httpx_allips.jsonl`
- TLS domain discovery:
  `httpx -l hosts.txt -tls-probe -tls-grab -sc -title -silent -j -o httpx_tls.jsonl`
- Exclude known CDN/private-IP hosts:
  `httpx -l hosts.txt -e cdn,private-ips -sc -title -silent -j -o httpx_filtered.jsonl`
- Resume an interrupted scan:
  `httpx -l hosts.txt -resume -sc -title -silent -j -o httpx.jsonl`
- Store results to database:
  `httpx -l hosts.txt -sc -title -td -rdb -rdbt postgres -rdbcs 'postgres://user:pass@localhost/recon' -silent -j -o httpx.jsonl`

Critical correctness rules:
- For machine parsing, prefer `-j -o <file>`.
- Keep `-rl` and `-t` explicit for reproducible throughput.
- Use `-nf` when you need dual-scheme probing from host-only input.
- When using `-path` or `-ports`, keep scope tight to avoid accidental scan inflation. `-path /,/login,/admin` on 1000 hosts with 5 ports = 15,000 probes.
- Use `-sr -srd <dir>` when later steps need raw response artifacts (JS/route extraction, grepping, replay).
- `-cdn` is on by default — it adds a field, not a filter. Use `-fcdn` / `-mcdn` to filter or match by CDN provider.
- `-pa` (probe-all-ips) multiplies requests by the number of A/AAAA records. Use only when you need to test each backend IP individually.
- `-ss` (screenshot) is slow — one headless browser per host. Lower `-t` and raise `-st` (screenshot-timeout) for large lists.
- `-rdb` inserts every result row into the database. Scope the input tightly or results accumulate fast.

Usage rules:
- Use `-silent` for pipeline-friendly output.
- Use `-mc/-fc` when downstream steps depend on specific response classes.
- Prefer `-proxy` flag over global proxy env vars when only httpx traffic should be proxied.
- Use `-fr` (follow-redirects) to resolve final landing URLs; omit it when you need to see redirect chains (use `-include-chain` with `-j`).
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- If too many timeouts occur, reduce `-rl/-t` and/or increase `-timeout`.
- If output is noisy, add `-fc` filters or `-fd` duplicate filtering.
- If HTTPS-only probing misses HTTP services, rerun with `-nf` (and avoid `-nfs`).
- If a host causes excessive errors, tune `-maxhr` (default 30) or add it to `-e`.
- If screenshots fail, try `-system-chrome` and increase `-st` (default 10s).
- If CDN detection adds noise, filter with `-fcdn` or exclude with `-e cdn`.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io httpx <flag> usage`

## Probe Flags

httpx's probe flags extract metadata from HTTP responses. Each flag appends its field to the output (text and JSON). Combine probes to build a recon profile in a single pass.

**HTTP response probes:**
- `-sc, -status-code` — HTTP status code. The minimum viable probe for any httpx run.
- `-title` — parsed `<title>` tag content. The second most-used probe after `-sc`. Reveals application names, default pages ("Welcome to nginx!"), login portals, and CMS identities at a glance.
- `-cl, -content-length` — response body size in bytes.
- `-ct, -content-type` — Content-Type header value.
- `-location` — redirect Location header (meaningful with or without `-fr`).
- `-rt, -response-time` — time to first byte. Use for performance fingerprinting and slow-response detection.
- `-lc, -line-count` — body line count. Useful for filtering (boilerplate vs. content).
- `-wc, -word-count` — body word count. Same use case.
- `-bp, -body-preview` — first N characters of the response body (default 100). Quick content triage without storing full responses.
- `-method` — the HTTP method used for the request.
- `-probe` — probe status (SUCCESS or FAILED).

**Fingerprinting probes:**
- `-server, -web-server` — Server header. Quick stack identification (nginx, Apache, IIS, Caddy, etc.).
- `-td, -tech-detect` — Wappalyzer-based technology detection. Identifies frameworks, CMSes, CDNs, analytics, languages. Outputs comma-separated tech list.
- `-cff, -custom-fingerprint-file <file>` — load custom fingerprint definitions for `-td`. Extend Wappalyzer with internal/proprietary stack signatures.
- `-cpe` — CPE (Common Platform Enumeration) with product version. Machine-parseable software identity for vulnerability correlation (feed into `vulnx` for CVE lookup).
- `-wp, -wordpress` — enumerate WordPress plugins and themes. Outputs discovered plugin/theme names and versions.
- `-kb, -knowledge-base` — ML-based page classification (login page, error page, API docs, etc.).
- `-favicon` — mmh3 hash of `/favicon.ico`. Favicon hashes are stable fingerprints — Shodan indexes them (`http.favicon.hash`), so a hash identifies a product or stack across instances.
- `-hash <algo>` — body hash using `md5`, `mmh3`, `simhash`, `sha1`, `sha256`, or `sha512`. Use `simhash` for near-duplicate detection; use `sha256` for exact-match dedup or change tracking.
- `-jarm` — JARM TLS fingerprint. JARM hashes fingerprint the TLS server implementation; same JARM across hosts implies same TLS stack (and likely same application server or CDN).

**DNS and network probes:**
- `-ip` — resolved IP address. Essential for mapping hosts to infrastructure.
- `-cname` — CNAME record for the host. Reveals CDN/proxy/hosting relationships.
- `-extract-fqdn, -efqdn` — extract domains and subdomains from response body and headers. Passive subdomain discovery from a single probe pass.
- `-asn` — ASN information (number, name, country). Infrastructure ownership mapping.
- `-cdn` — CDN/WAF provider (on by default). Identifies Cloudflare, Akamai, Fastly, CloudFront, etc.
- `-ws, -websocket` — detect WebSocket support.

**Recon patterns — probe combinations:**

Light fingerprint (fast, low-noise):
`httpx -l hosts.txt -sc -title -server -td -silent -j -o httpx_light.jsonl`

Full infrastructure recon:
`httpx -l hosts.txt -sc -title -server -td -ip -asn -cdn -cname -jarm -favicon -cpe -rt -fr -silent -j -o httpx_full.jsonl`

Content-focused (for downstream analysis):
`httpx -l hosts.txt -sc -cl -ct -lc -wc -bp -hash sha256 -silent -j -o httpx_content.jsonl`

## Matchers and Filters

Matchers keep responses that satisfy a condition. Filters discard them. Both accept the same field types. Use matchers when you want a specific subset; use filters when you want everything except a known-noise pattern.

**Matcher flags:**
- `-mc, -match-code <codes>` — status codes. Comma-separated or ranges: `-mc 200,301,302` or `-mc 200-299`.
- `-ml, -match-length <lengths>` — content-length values.
- `-mlc, -match-line-count <counts>` — body line counts.
- `-mwc, -match-word-count <counts>` — body word counts.
- `-mfc, -match-favicon <hashes>` — favicon mmh3 hash. Identify all instances of a specific application by its favicon.
  `httpx -l hosts.txt -mfc 116323821 -sc -title -silent` (match a known favicon hash)
- `-ms, -match-string <strings>` — literal string in the response body.
  `httpx -l hosts.txt -ms 'Powered by WordPress' -sc -title -silent`
- `-mr, -match-regex <patterns>` — regex match in the response.
- `-mcdn, -match-cdn <providers>` — match by CDN/WAF provider name. Provider list includes cloudfront, fastly, gcore, google, and others.
  `httpx -l hosts.txt -mcdn cloudflare -sc -ip -silent` (find all Cloudflare-fronted hosts)
- `-mrt, -match-response-time <expr>` — response time comparison: `-mrt '< 1'` (under 1 second), `-mrt '> 5'` (over 5 seconds).
- `-mdc, -match-condition <dsl>` — DSL expression. Access any JSON output field programmatically. Use `-ldv` to list available variables.
  `httpx -l hosts.txt -mdc 'status_code == 200 && contains(body, "admin") && content_length > 1000' -silent -j -o matches.jsonl`

**Filter flags (mirror matchers):**
- `-fc, -filter-code <codes>` — drop these status codes. `-fc 404,403,503` is the most common filter.
- `-fl, -filter-length`, `-flc, -filter-line-count`, `-fwc, -filter-word-count` — drop by content metrics.
- `-ffc, -filter-favicon <hashes>` — drop by favicon hash.
- `-fs, -filter-string <strings>` — drop responses containing a literal string.
- `-fe, -filter-regex <patterns>` — drop responses matching a regex.
- `-fcdn, -filter-cdn <providers>` — drop CDN-fronted hosts. Useful for isolating direct-origin hosts:
  `httpx -l hosts.txt -fcdn cloudfront,fastly,cloudflare,akamai -sc -ip -title -silent -j -o direct_origins.jsonl`
- `-frt, -filter-response-time <expr>` — drop by response time: `-frt '> 10'` (drop slow hosts).
- `-fdc, -filter-condition <dsl>` — DSL expression filter.

**Special filters:**
- `-fpt, -filter-page-type <types>` — filter by ML-classified page type. Known types: `login`, `captcha`, `parked`. Useful for stripping noise from large-scale probing.
  `httpx -l hosts.txt -fpt parked,captcha -sc -title -silent -j -o httpx_real.jsonl`
- `-fd, -filter-duplicates` — near-duplicate response deduplication. Only the first response per content fingerprint is retained. Essential for large-scope probing where many hosts serve identical default pages.
- `-strip` — strip HTML or XML tags from the response body before matching/output. Supports `html` (default) and `xml`.

**Output field control:**
- `-lof, -list-output-fields` — list available output fields. Use to discover which fields can be selected or excluded.
- `-eof, -exclude-output-fields <fields>` — exclude specific fields from JSON output. Reduce output size by dropping fields you don't need.

**DSL variables (for `-mdc`/`-fdc`):**

Run `httpx -ldv` to list all fields available for DSL expressions. Key variables include `status_code`, `content_length`, `content_type`, `body`, `header`, `title`, `server`, `host`, `port`, `scheme`, `path`, `response_time`, `technology`, `cdn_name`, `a`, `cname`, `asn`.

DSL supports: `contains()`, `starts_with()`, `ends_with()`, `regex()`, `len()`, `to_upper()`, `to_lower()`, `==`, `!=`, `>`, `<`, `>=`, `<=`, `&&`, `||`, `!`.

**DSL expression examples:**

Match admin panels (200 OK, body contains "admin", non-trivial page):
`-mdc 'status_code == 200 && contains(body, "admin") && content_length > 1000'`

Match potential information disclosure (stack traces, debug output):
`-mdc 'status_code == 500 && (contains(body, "Traceback") || contains(body, "stack trace") || contains(body, "Exception"))'`

Match API endpoints returning JSON:
`-mdc 'contains(content_type, "application/json") && status_code == 200'`

Match hosts running specific technology:
`-mdc 'contains(technology, "Laravel") || contains(technology, "Django")'`

Filter out default/empty pages:
`-fdc 'content_length < 100 || contains(title, "Welcome to nginx") || contains(title, "Apache2 Default")'`

Match hosts with specific server headers (version exposure):
`-mdc 'regex(server, "Apache/2\\.4\\.[0-3][0-9]") && status_code == 200'`

Match slow-responding hosts (potential timing attack surface):
`-mdc 'response_time > 3 && status_code == 200'`

## Extractors

Extractors pull specific content from response bodies and headers. Unlike probes (which add metadata fields), extractors search response content for patterns.

- `-er, -extract-regex <pattern>` — extract content matching a regex. Multiple `-er` flags are accepted. Extracted values appear in the `extracted_data` field in JSON output.
  `httpx -l hosts.txt -er 'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})' -silent -j -o httpx_keys.jsonl`
  `httpx -l hosts.txt -er '/api/v[0-9]+/[a-z_]+' -silent -j -o httpx_endpoints.jsonl`

- `-ep, -extract-preset <name>` — extract using built-in regex presets. Available presets:
  - `url` — extract URLs from response body
  - `ipv4` — extract IPv4 addresses
  - `mail` — extract email addresses
  `httpx -l hosts.txt -ep url,ipv4,mail -silent -j -o httpx_extracted.jsonl`

Extractors pair well with `-fr` (follow-redirects) and `-sr` (store-response) for deep content analysis. They also work with `-path` to extract from specific pages:
`httpx -l hosts.txt -path /robots.txt,/sitemap.xml -ep url -fc 404 -silent -j -o httpx_urls.jsonl`

**Pentesting extraction patterns:**

Extract API keys and secrets from responses:
`httpx -l hosts.txt -er 'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})' -er 'secret["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})' -silent -j -o httpx_secrets.jsonl`

Extract internal IPs from headers and bodies:
`httpx -l hosts.txt -ep ipv4 -er '10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+' -silent -j -o httpx_internal_ips.jsonl`

Extract JavaScript file URLs for downstream analysis:
`httpx -l hosts.txt -er 'src=["\']([^"\']+\.js)' -silent -j -o httpx_js.jsonl`

Extract S3 bucket references:
`httpx -l hosts.txt -er '[a-zA-Z0-9_\-]+\.s3[\.\-]amazonaws\.com' -er 's3://[a-zA-Z0-9_\-/]+' -silent -j -o httpx_s3.jsonl`

Extract subdomains from response bodies (passive discovery):
`httpx -l hosts.txt -efqdn -silent -j -o httpx_fqdn.jsonl`

## Headless Mode and Screenshots

httpx can launch a headless browser to capture page screenshots and execute JavaScript. This enables visual recon at scale — triage hundreds of hosts by their rendered page rather than raw HTML.

- `-ss, -screenshot` — enable page screenshots via headless Chrome. Screenshots are saved alongside stored responses when `-sr` is used. Significantly slower than standard probing — the browser renders each page.
- `-system-chrome` — use the locally installed Chrome instead of httpx's bundled Chromium. Required in sandboxed environments where the bundled browser may not work.
- `-ho, -headless-options <opts>` — additional Chrome launch flags. Multiple flags accepted.
  `httpx -l hosts.txt -ss -ho --disable-gpu -ho --no-sandbox -silent -j -o ss.jsonl`
- `-esb, -exclude-screenshot-bytes` — exclude base64 screenshot bytes from JSON output. Screenshots are still saved to disk but the JSON stays compact.
- `-ehb, -exclude-headless-body` — exclude the headless-rendered HTML body from JSON output. Useful when you only want the screenshot, not the DOM.
- `-no-screenshot-full-page` — capture only the visible viewport, not the full scrollable page. Faster and smaller files.
- `-st, -screenshot-timeout <duration>` — max wait for page render (default 10s). Increase for JavaScript-heavy SPAs.
- `-sid, -screenshot-idle <duration>` — idle time after page load before capturing (default 1s). Increase for pages with deferred rendering.
- `-jsc, -javascript-code <code>` — execute JavaScript after page load, before capture. Multiple `-jsc` flags accepted. Use to interact with the page (dismiss modals, scroll, click) before screenshot.
  `httpx -l hosts.txt -ss -jsc 'document.querySelector(".cookie-banner")?.remove()' -system-chrome -silent -j -o ss.jsonl`
- `-svrc, -store-vision-recon-cluster` — group screenshots by visual similarity (requires `-ss` and `-sr`). Outputs cluster information for triage — visually identical hosts are grouped, letting you focus on unique pages.

Screenshot-optimized run:
`httpx -l hosts.txt -ss -system-chrome -st 15s -sid 2s -esb -no-screenshot-full-page -sr -srd recon/screenshots -sc -title -td -rl 10 -t 5 -silent -j -o httpx_ss.jsonl`

**Visual recon clustering:**
When screenshots are stored (`-ss -sr`), the `-svrc` flag clusters visually similar pages. This groups default pages, error pages, and cookie consent walls together, letting the researcher focus on unique application surfaces.
`httpx -l hosts.txt -ss -system-chrome -svrc -sr -srd recon/screenshots -esb -sc -title -rl 10 -t 5 -silent -j -o httpx_clusters.jsonl`

**JavaScript interaction before capture:**
Use `-jsc` to modify the page before the screenshot captures it. Common uses: dismiss cookie banners, expand collapsed content, authenticate:
`httpx -l hosts.txt -ss -jsc 'document.querySelector("[class*=cookie]")?.remove()' -jsc 'document.querySelector("[class*=modal]")?.remove()' -system-chrome -st 15s -esb -rl 5 -t 3 -silent -j -o ss.jsonl`

**Performance notes:** Screenshot mode is ~10-50x slower than regular probing. For a 1000-host list, expect 30-60 minutes with conservative settings. Lower `-t` to 3-5 threads and keep `-rl` under 10 to prevent browser resource exhaustion.

## Virtual Host Detection

httpx detects virtual host (vhost) configurations — servers that route different content based on the `Host` header. This matters for discovering hidden applications, internal services, and staging environments hosted on the same IP.

- `-vhost` — probe for vhost support by sending requests with alternate Host headers and comparing responses. Adds a `vhost` field to output indicating whether the server differentiates based on the Host header.
  `httpx -l hosts.txt -vhost -sc -title -silent -j -o httpx_vhost.jsonl`

- `-vhost-input` — treat the input list as virtual hostnames. httpx resolves the IP from the URL/host but sets the Host header from the input. Use when you have a list of candidate vhosts to test against a known IP:
  `httpx -l candidate_vhosts.txt -vhost-input -sc -title -cl -silent -j -o httpx_vhost_enum.jsonl`

**Vhost discovery workflow:**

1. Identify a target IP serving HTTP (via `naabu` or direct probing).
2. Generate candidate hostnames — from certificate SANs (`-tls-probe`), DNS records, reverse lookups, or wordlists.
3. Probe each candidate as a vhost:
   `httpx -u https://target-ip -H 'Host: CANDIDATE' -sc -title -cl -silent`
4. Compare response characteristics (title, content-length, body hash) against the default response. Different fingerprints indicate distinct vhost applications.

Automated vhost sweep against a known IP:
`httpx -l candidate_hosts.txt -vhost-input -sc -title -cl -hash sha256 -fd -silent -j -o httpx_vhost_sweep.jsonl`

The `-fd` (filter-duplicates) flag deduplicates responses with near-identical content, surfacing only the unique vhosts.

## Protocol Detection

httpx can probe for protocol-level features beyond basic HTTP:

- `-http2` — probe whether the server supports HTTP/2. Adds a boolean field to output.
- `-pipeline` — probe for HTTP/1.1 pipelining support.
- `-vhost` — probe for virtual host support (sends requests with different Host headers). Identifies hosts that serve different content based on the Host header — useful for vhost bruteforcing candidate identification.
- `-ws, -websocket` — detect WebSocket upgrade support.
- `-tls-probe` — extract domains from TLS certificate SAN (Subject Alternative Name) fields and probe them. Passive subdomain discovery through TLS certificates.
- `-csp-probe` — extract domains from Content-Security-Policy headers and probe them. Discovers connected services and CDN origins.
- `-tls-grab` — perform TLS data grabbing (certificate details, supported protocols, cipher suites). Combined with `-jarm` for comprehensive TLS fingerprinting.
- `-pr, -protocol <proto>` — force a specific protocol. Values: `unknown`, `http11`, `http2` (experimental), `http3` (experimental). Default behavior probes HTTP/1.1 and auto-negotiates.

TLS/protocol reconnaissance pass:
`httpx -l hosts.txt -tls-probe -tls-grab -csp-probe -http2 -jarm -pipeline -sc -title -silent -j -o httpx_proto.jsonl`

## Input Modes

- `-l, -list <file>` — one host or URL per line. The standard input.
- `-u, -target <url>` — inline target(s). Multiple `-u` flags or comma-separated.
- `-rr, -request <file>` — raw HTTP request file (Burp/Caido export). httpx sends the exact request as captured.
- `-im, -input-mode burp` — parse a Burp proxy log as input (multiple targets from Burp export).
- `-vhost-input` — treat input as a list of virtual hostnames (sets the Host header from input while probing the IP).
- stdin — httpx reads from stdin by default. Pipe from `subfinder`, `naabu`, or any host list.
  `subfinder -d target.tld -silent | httpx -sc -title -td -silent -j -o httpx.jsonl`

## Rate Limiting and Performance

- `-rl, -rate-limit <n>` — max requests per second (default 150). The primary throughput control.
- `-rlm, -rate-limit-minute <n>` — max requests per minute. Use when per-second granularity is too coarse.
- `-t, -threads <n>` — concurrent threads (default 50). Controls parallelism. Lower for rate-sensitive targets; raise for bulk probing of tolerant infrastructure.
- `-delay <duration>` — fixed delay between requests (e.g. `200ms`, `1s`). Useful for strict rate-sensitive targets. Default none.
- `-timeout <seconds>` — request timeout (default 10). Increase for slow targets; decrease for fast triage.
- `-retries <n>` — retry failed requests. Default 0 (no retries). Keep low — transient failures on recon don't warrant heavy retrying.
- `-maxhr, -max-host-error <n>` — skip remaining paths/ports for a host after N errors (default 30). Prevents wasting time on dead hosts in multi-path/port scans.
- `-rsts, -response-size-to-save <bytes>` — max response size to save (default 50MB). Cap to prevent disk fill on unexpectedly large responses.
- `-rstr, -response-size-to-read <bytes>` — max response size to read (default 50MB). Cap to prevent memory issues.

**Stream mode:**
- `-s, -stream` — start processing targets immediately without sorting/deduping the input. Useful for very large target lists or continuous pipeline input.
- `-sd, -skip-dedupe` — disable input deduplication in stream mode. Use when the input is already deduplicated and you want maximum throughput.

**Scheme fallback behavior:**
- Default: httpx probes HTTPS first; if it fails, falls back to HTTP. You see one result per host.
- `-nf, -no-fallback` — probe both HTTP and HTTPS independently. Two results per host (if both respond). Use when you need to compare HTTP vs. HTTPS behavior.
- `-nfs, -no-fallback-scheme` — no fallback at all. Probe only the scheme specified in the input. Use when input URLs already have explicit schemes.

## Output Formats and Storage

**Output formats (mutually additive):**
- `-o <file>` — write results to file (default: text format).
- `-j, -json` — JSONL (JSON Lines) format. One JSON object per result. The standard for automation.
- `-csv` — CSV format. `-csvo <encoding>` sets the output encoding.
- `-md, -markdown` — Markdown table format. Useful for human-readable reports.
- `-oa, -output-all` — write results in all available formats simultaneously.

**Response inclusion (JSON only):**
- `-irh, -include-response-header` — include response headers in JSON output.
- `-irr, -include-response` — include full request and response (headers + body) in JSON output.
- `-irrb, -include-response-base64` — include base64-encoded request/response in JSON output. Avoids encoding issues with binary content.
- `-include-chain` — include the full redirect chain in JSON output. Shows every hop.
- `-ob, -omit-body` — omit the response body from output. Reduces output size when you only need headers/metadata.

**Stored responses:**
- `-sr, -store-response` — save full HTTP responses to the output directory (default `output/`).
- `-srd, -store-response-dir <dir>` — custom directory for stored responses.
- `-store-chain` — save redirect chain responses (with `-sr`).

**Result database:**
- `-rdb, -result-db` — enable database storage.
- `-rdbt, -result-db-type <type>` — database type: `mongodb`, `postgres`, or `mysql`.
- `-rdbcs, -result-db-conn <connstring>` — database connection string.
- `-rdbn, -result-db-name <name>` — database name (default `httpx`).
- `-rdbtb, -result-db-table <name>` — table/collection name (default `results`).
- `-rdbbs, -result-db-batch-size <n>` — batch insert size (default 100).
- `-rdbor, -result-db-omit-raw` — omit raw request/response data from database records.
- `-rdbc, -result-db-config <file>` — load database config from file.

Result database is useful for persistent recon across engagements — query historical data, track changes, feed dashboards.

`httpx -l hosts.txt -sc -title -td -ip -asn -cdn -rdb -rdbt postgres -rdbcs 'postgres://recon:pass@localhost/httpx_data' -silent -j -o httpx.jsonl`

**Resume:**
- `-resume` — resume an interrupted scan from `resume.cfg`. httpx saves progress automatically; use this flag to continue after a crash or timeout.

**Error page tracking:**
- `-fepp, -filter-error-page-path <file>` — path to store filtered error pages (default `filtered_error_page.json`). Used with `-fpt` for reviewing what was filtered.

## Authentication and TLS

**Authentication:**
- `-sf, -secret-file <file>` — path to a secrets file for authenticated scanning. Uses the ProjectDiscovery secret file format (shared with nuclei).
- `-H, -header <header:value>` — custom headers for every request. Use for Bearer tokens, API keys, session cookies. Multiple `-H` flags accepted.
  `httpx -l hosts.txt -H 'Authorization: Bearer <token>' -H 'X-Custom: value' -sc -title -silent -j -o httpx_auth.jsonl`
- `-body <data>` — POST body for every request. Combine with `-x POST`.
- `-x <methods>` — HTTP methods to probe. Default is GET. Use `all` to probe all standard methods:
  `httpx -l hosts.txt -x all -sc -method -title -silent -j -o httpx_methods.jsonl`

**TLS configuration:**
- `-tlsi, -tls-impersonate <target>` — experimental JA3/ClientHello impersonation. Accepts `chrome` for Chrome-like fingerprint, or a full JA3 string. Useful when targets reject non-browser TLS fingerprints.
- `-sni, -sni-name <hostname>` — custom TLS SNI hostname. Use when the SNI needs to differ from the Host header (CDN/reverse proxy testing).
- `-ztls` — use the ztls library with autofallback to standard for TLS 1.3.
- `-unsafe` — send raw requests skipping Go's HTTP normalization. Useful for testing request smuggling or path traversal through normalization differences.

**Request behavior:**
- `-random-agent` — random User-Agent for every request (on by default). httpx rotates UAs automatically.
- `-auto-referer` — set the Referer header to the current URL automatically.
- `-fr, -follow-redirects` — follow HTTP redirects.
- `-maxr, -max-redirects <n>` — max redirects to follow (default 10).
- `-fhr, -follow-host-redirects` — follow redirects only to the same host (prevents off-site redirect following).
- `-rhsts, -respect-hsts` — respect HSTS headers for redirect requests.
- `-ldp, -leave-default-ports` — keep default ports in the Host header (e.g. `http://host:80`). Useful for testing port-sensitive routing.
- `-no-decode` — don't decode response bodies. Useful for binary content analysis.

**Scope control:**
- `-allow <ips>` — only process IPs/CIDRs in this allowlist (file or comma-separated).
- `-deny <ips>` — never process IPs/CIDRs in this denylist.
- `-e, -exclude <filter>` — exclude hosts matching a filter. Built-in filters: `cdn`, `private-ips`. Also accepts CIDR, IP, or regex:
  `httpx -l hosts.txt -e cdn,private-ips -sc -title -silent`

**Resolvers:**
- `-r, -resolvers <file_or_list>` — custom DNS resolvers. Useful when default resolvers are unreliable or when you need to query specific nameservers.

## Detection Fingerprint

httpx is a Go-based HTTP client. Its traffic looks like:

**User-Agent:** Randomized browser UA by default (`-random-agent` is on). Defenders cannot trivially fingerprint httpx by UA alone — but the randomization pool is finite, and the request pattern (many hosts, single path, no JS/CSS/image fetches) is distinctive.

**Request pattern:** One request per host per path. No crawling, no JavaScript rendering (unless `-ss` is used), no CSS/image fetches. This "one probe and move on" pattern is visible to network monitors and IDS as anomalous browsing behavior.

**TLS fingerprint:** Default Go TLS stack. Use `-tlsi chrome` to impersonate a Chrome TLS fingerprint. Without it, the Go ClientHello is fingerprintable by JA3-aware defenses.

**Timing:** Default 150 req/s with 50 threads is aggressive. Lower `-rl` and `-t` for stealth. Add `-delay` for per-request throttling.

**Mitigation:** Combine `-tlsi chrome`, lower `-rl`, add `-delay`, use `-proxy` through a residential proxy, and set realistic `-H 'Accept: text/html,...'` headers. None of this guarantees evasion — it reduces the fingerprint.

## CDN and WAF Awareness

httpx identifies CDN/WAF providers for every host by default (`-cdn` is `true`). This information drives routing decisions — CDN-fronted hosts need different testing strategies than direct-origin hosts.

**CDN detection is on by default.** The `-cdn` flag adds a field to output but does not filter. To split targets by CDN status, use `-mcdn` and `-fcdn`:

Split targets into CDN-fronted and direct-origin:
```
httpx -l hosts.txt -fcdn cloudflare,cloudfront,akamai,fastly -silent > direct_origins.txt
httpx -l hosts.txt -mcdn cloudflare,cloudfront,akamai,fastly -silent > cdn_fronted.txt
```

**Known CDN/WAF providers** (from help output): cloudfront, fastly, gcore, google, cdnetworks, gocache, arvancloud, cafe24, qrator, lgtelecom, skbroadband, and several CJK-named providers (百度云加速, 腾讯云, 加速乐, 云盾, kinx).

**Routing implications:**
- **Direct-origin hosts:** route to active scanners (nuclei, sqlmap, ffuf) directly.
- **CDN-fronted hosts:** rate limits, WAF rules, and geographic routing apply. Use `wafw00f` to identify the specific WAF. Lower `-rl` and `-t` to avoid triggering rate-limiting. Some scanning techniques (timing-based SQLi, SSRF to internal IPs) may be unreliable through CDN.
- **Origin discovery:** when httpx identifies CDN fronting, look for the origin IP via `-tls-probe` (certificate SANs), historical DNS records, or direct IP probing. Test the origin separately from the CDN.

CDN-aware recon pass:
`httpx -l hosts.txt -sc -title -td -cdn -ip -cname -asn -fr -silent -j -o httpx_cdn_recon.jsonl`

Then filter and route:
```
cat httpx_cdn_recon.jsonl | jq -r 'select(.cdn_name == "") | .url' > direct.txt
cat httpx_cdn_recon.jsonl | jq -r 'select(.cdn_name != "") | .url' > fronted.txt
```

## Debugging and Diagnostics

- `-debug` — display full request and response content in the terminal.
- `-debug-req` — display request content only.
- `-debug-resp` — display response content only.
- `-tr, -trace` — enable HTTP trace for diagnosing connection issues.
- `-stats` — display scan statistics (processed/total hosts, requests/second).
- `-si, -stats-interval <n>` — seconds between stats updates (default 5).
- `-v, -verbose` — verbose output.
- `-health-check, -hc` — run diagnostic check on the httpx configuration.
- `-nc, -no-color` — disable color output.
- `-profile-mem <file>` — write memory profile (for debugging httpx itself).
- `-version` — display httpx version.

## Knowledge Base Classification

The `-kb, -knowledge-base` flag enables ML-based page classification. httpx categorizes each response page into a functional type — login page, error page, API documentation, parked domain, CAPTCHA challenge, etc.

`httpx -l hosts.txt -kb -sc -title -silent -j -o httpx_kb.jsonl`

The classification appears in JSON output as a `knowledge_base` or page-type field. Combine with `-fpt` to filter out noise categories:
`httpx -l hosts.txt -kb -fpt parked,captcha -sc -title -silent -j -o httpx_real.jsonl`

**Use cases:**
- **Login page discovery:** find authentication surfaces across all subdomains for targeted credential testing.
- **Error page identification:** spot debug/stack-trace pages leaking internal information (route to `vulnerabilities/information_disclosure.md`).
- **API endpoint detection:** identify API documentation pages for downstream API security testing.
- **Parked domain filtering:** remove parked/expired domains from large subdomain lists before wasting scan time.

## ProjectDiscovery Cloud (PDCP)

httpx can upload results to the ProjectDiscovery Cloud Platform for team dashboards and historical tracking.

- `-pd, -dashboard` — upload results to the PDCP dashboard UI.
- `-pdu, -dashboard-upload <file>` — upload an existing httpx JSONL output file to the dashboard.
- `-tid, -team-id <id>` — associate results with a specific team.
- `-aid, -asset-id <id>` — append results to an existing asset group.
- `-aname, -asset-name <name>` — name the asset group.
- `-auth` — configure the PDCP API key (default: on; interactive prompt if not set).
- `-ac, -auth-config <file>` — PDCP API key credential file.

Dashboard-integrated scan:
`httpx -l hosts.txt -sc -title -td -ip -asn -cdn -pd -aname 'target-recon-2025' -silent -j -o httpx.jsonl`

## HTTP API Endpoint (Experimental)

- `-hae, -http-api-endpoint <url>` — expose httpx as an HTTP API. Send targets via POST and receive probe results over the API. Experimental — useful for integrating httpx into custom orchestration pipelines without shelling out.

## Miscellaneous Configuration

- `-config <file>` — load configuration from a YAML file (default `$HOME/.config/httpx/config.yaml`). Persist default flags across runs.
- `-no-stdin` — disable stdin processing. Use when httpx is invoked in a context where stdin is connected to something other than a host list.

## Chaining and Routing

httpx is the universal HTTP probe in the ProjectDiscovery pipeline. It sits between discovery and scanning.

**Inbound chains (feeds httpx):**
- `subfinder -d target.tld -silent | httpx ...` — subdomain discovery → live host filtering (see `tooling/subfinder.md`)
- `naabu -host target.tld -silent | httpx ...` — port discovery → HTTP service identification (see `tooling/naabu.md`)
- `katana -u https://target.tld -f url -silent | httpx ...` — crawled URLs → live endpoint verification (see `tooling/katana.md`)

**Outbound chains (httpx feeds):**
- `httpx ... -silent | nuclei -l - ...` — live hosts → vulnerability scanning (see `tooling/nuclei.md`)
- `httpx ... -silent | ffuf -w - -u FUZZ/... ...` — live hosts → content discovery (see `tooling/ffuf.md`)
- `httpx ... -silent | katana -list - ...` — live hosts → deep crawling (see `tooling/katana.md`)

**Recon workflow:**
1. `subfinder` → subdomains
2. `httpx` → live hosts with tech fingerprint
3. `wafw00f` on live hosts → WAF identification (see `tooling/wafw00f.md`)
4. `nuclei` → vulnerability scanning
5. `ffuf` / `feroxbuster` / `dirsearch` → content discovery (see `tooling/ffuf.md`, `tooling/feroxbuster.md`, `tooling/dirsearch.md`)

**Tech-detect vs. nuclei `-as`:** Both use Wappalyzer for technology detection. httpx `-td` gives you the tech stack for routing decisions; nuclei `-as` maps those techs to template tags internally. They're complementary — httpx for recon, nuclei for scanning.

**Multi-pass recon (httpx feeding itself):**
First pass: broad probe with tech detection. Second pass: targeted probing of interesting hosts.
```
httpx -l hosts.txt -sc -title -td -silent -j -o pass1.jsonl
cat pass1.jsonl | jq -r 'select(.technology | test("WordPress|Drupal|Joomla")) | .url' | httpx -wp -path /wp-login.php,/administrator,/user/login -sc -title -silent -j -o pass2_cms.jsonl
```

**Screenshot-based visual recon:** `httpx -ss` screenshots feed manual triage. Use `-svrc` (vision recon clusters) to group visually identical pages and focus on unique targets.

**CDN/WAF awareness:** httpx `-cdn` identifies CDN/WAF providers. Route CDN-fronted hosts to origin-discovery workflows; route direct-origin hosts to active scanning. Use `-fcdn` or `-mcdn` to split the pipeline:
`httpx -l hosts.txt -fcdn cloudflare,cloudfront -silent > direct.txt`
`httpx -l hosts.txt -mcdn cloudflare,cloudfront -silent > cdn_fronted.txt`

**Result database for persistent recon:** Store httpx results in PostgreSQL/MongoDB with `-rdb` for historical tracking across engagements. Query for new hosts, changed tech stacks, disappeared services.

Routed consumers:
- `vulnerabilities/information_disclosure.md` — httpx `-bp` body preview and `-er` extraction catch leaked data
- `vulnerabilities/subdomain_takeover.md` — httpx probing of CNAME targets (via `-cname` and `-tls-probe`) feeds takeover checks
- `vulnerabilities/browser_security.md` — httpx `-irh` (response headers) exposes missing security headers
- `vulnerabilities/authentication_jwt.md` — httpx `-path` probing of auth endpoints feeds JWT testing
- `vulnerabilities/idor.md` — httpx `-er` extraction of API patterns feeds IDOR enumeration
- `vulnerabilities/open_redirect.md` — httpx `-location` header capture feeds redirect chain analysis
- `tooling/wafw00f.md` — WAF fingerprinting on httpx-confirmed live hosts
- `tooling/tlsx.md` — deep TLS analysis on httpx `-tls-grab` discoveries
- `tooling/katana.md` — deep crawling of httpx-confirmed live hosts
- `tooling/nuclei.md` — vulnerability scanning against httpx-probed targets
