---
name: dirsearch
description: dirsearch deep operational playbook — content-discovery methodology, wordlist management, two-tier filtering, recursion, evasion, authentication, session management, and tool chaining.
---

# dirsearch CLI Playbook

Official docs:
- https://github.com/maurosoria/dirsearch
- https://github.com/maurosoria/dirsearch/wiki

Canonical syntax:
`dirsearch -u <url> [options]` (or `-l <file>` / `--stdin` / `--cidr` / `--raw` / `--nmap-report`)

High-signal flags:
- `-u <url>` single target (repeatable); `-l <file>` URL list; `--stdin` read from stdin
- `--cidr <cidr>` scan a CIDR range (resolves hosts first)
- `--raw <file>` load a raw HTTP request (use `--scheme` to pin https)
- `--nmap-report <file>` seed targets from an `nmap -sV` XML report
- `-e <ext>` extensions (comma-separated, `php,asp,...`); `-f` force-extensions on every entry
- `-w <list>` wordlist file(s) or directories; `--wordlist-categories <names>` curated bundles (`common,conf,web,...` or `all`)
- `-t <n>` threads
- `-r, --recursive` recursive brute-force; `-R <depth>` max recursion depth; `--deep-recursive` recurse at every path segment; `--force-recursive` recurse into every found path (not only dirs)
- `--recursion-status <codes>` which status codes trigger recursion
- `--subdirs <list>` scan sub-dirs of the given URLs (comma-separated); `--exclude-subdirs <list>` skip them
- Status filtering: `-i <codes>` include; `-x <codes>` exclude; `--mc/--fc <codes>` advanced matcher/filter status
- Size filtering: `--ms/--fs <sizes>` match/filter size; `--exclude-sizes <sizes>` quick drop
- Response filters: `--exclude-text <text>`, `--exclude-regex <re>`, `--exclude-redirect <re>`, `--exclude-response <path>` (soft-404 calibration)
- Advanced matchers: `--mw/--fw` words, `--ml/--fl` lines, `--mr/--fr` body regex, `--match-header/--filter-header` text, `--match-header-regex/--filter-header-regex`, `--mt/--ft` elapsed-ms
- `--auto-calibration` force extra wildcard calibration; `--filter-threshold <n>` auto-filter after `n` duplicate responses
- `--max-time <sec>` / `--target-max-time <sec>` runtime caps
- Request: `-m <METHOD>`, `-d <data>`, `--data-file <path>`, `-H <header>`, `--headers-file <path>`, `-F` follow redirects, `--random-agent`, `--auth user:pass`, `--auth-type <basic|digest|bearer|ntlm|jwt>`, `--cookie <c>`
- Connection: `-p`/`--proxy <url>` (HTTP/SOCKS, repeatable), `--proxies-file <path>`, `--proxy-auth <cred>`, `--replay-proxy <url>`, `--tor`, `--delay <sec>`, `--max-rate <n>`, `--timeout <sec>`, `--retries <n>`
- Output: `-o <file>` with `-O`/`--output-formats <plain|json|xml|md|csv|html|sqlite>` (comma-separated for multiple), `--mysql-url`, `--postgres-url`
- `-q, --quiet-mode` suppress non-finding output; `-v, --verbose` show response time and content type
- `-a, --async` enable asynchronous mode; `--sync`/`--no-async` force synchronous

Agent-safe baseline for automation:
`dirsearch -u https://target.tld -e php,html,js,json,txt,bak -t 30 --max-time 600 --random-agent -q -o dirsearch.json -O json`

Common patterns:
- Baseline scan with sane defaults:
  `dirsearch -u https://target.tld -e php,html,js,json`
- JSON output for pipeline consumers:
  `dirsearch -u https://target.tld -e php,html,js,json -o dirsearch.json -O json -q`
- Recursive discovery with depth cap:
  `dirsearch -u https://target.tld -e php,html,js -r -R 3 --recursion-status 200,301,302,403 -q`
- Replay a raw request (preserve exact headers/cookies from Caido):
  `dirsearch --raw req.txt --scheme https -e php,html,js -q -o dirsearch.json -O json`
- Seed from nmap service scan:
  `dirsearch --nmap-report nmap.xml -e php,html,js -t 20 -q -o dirsearch_nmap.json -O json`
- Soft-404 calibration against a known-404 page:
  `dirsearch -u https://target.tld -e php --exclude-response https://target.tld/does_not_exist_404_calibration -q`
- Narrow category sweep (configs/web files only):
  `dirsearch -u https://target.tld --wordlist-categories conf,web -e conf,bak,env -q -o dirsearch_conf.json -O json`
- Authenticated scan with a session cookie:
  `dirsearch -u https://target.tld --cookie "session=<caido-captured>" -e php,html,js -q`
- Proxy-routed with replay:
  `dirsearch -u https://target.tld -e php,html,js -p http://127.0.0.1:48080 --replay-proxy http://127.0.0.1:48081 -q`

Critical correctness rules:
- Always calibrate against soft-404s: use `--exclude-response <known_404_url>` or `--auto-calibration` before trusting the result set. Without calibration, catch-all responders generate thousands of fake positives.
- Status filtering: `-i` and `-x` are quick scope controls; `--mc`/`--fc` are the advanced matcher/filter and win over `-i`/`-x` when both are set.
- `-e` extensions are **appended** to each wordlist entry unless `--force-extensions`/`--overwrite-extensions` change that; the default replaces only `%EXT%` placeholders.
- `--raw` requires a well-formed raw request; pass `--scheme https` when the request line is missing scheme context.
- `--max-time`/`--target-max-time` are honest caps — the scan stops mid-wordlist. Pin them in automation.
- Threading higher than the target tolerates (`-t > ~50`) triggers connection resets that look like 404s and quietly discard real paths; back off before raising.
- The sandbox env already proxies through Caido via `http_proxy`/`https_proxy`. dirsearch also accepts `-p`/`--proxy` for explicit proxy control, plus `--proxies-file` for proxy rotation and `--replay-proxy` for replaying found paths through a separate proxy.

Usage rules:
- Prefer `-O json -o <file>` for downstream consumers; the text/HTML formats drop structure.
- Keep `-q` on in automation (noisy terminal UI otherwise).
- Combine with `wafw00f` first: fingerprint, then throttle `-t`/add headers accordingly.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- Hundreds of 200s from a wildcard responder: add `--exclude-response <soft-404-url>` and/or `--auto-calibration`.
- All requests return 401/403: pass real auth via `--cookie`/`-H`/`--auth`, or scan with `--raw <captured_request>`.
- Scan runs forever: lower `-t`, raise `-e` discipline (fewer extensions), and set `--max-time`.
- Rate-limited by the target: lower `-t`, add `--delay 0.5`, set `--max-rate`, and rotate UAs with `--random-agent`.

If uncertain, query web_search with:
`site:github.com/maurosoria/dirsearch dirsearch <flag>`

Routed consumers:
- `reconnaissance/*` (attack-surface mapping, path discovery)
- `tooling/ffuf.md` (surgical fuzzing of any input position — dirsearch is the broad sweep, ffuf is the targeted follow-up)
- `tooling/feroxbuster.md` (thin sibling — same workflow, feroxbuster differs on recursion defaults and Rust throughput)
- `tooling/wafw00f.md` (throttle decisions)

---

## Content Discovery Methodology

Content discovery follows a structured workflow from reconnaissance through triage. Each phase feeds the next.

### Phase 1 — Target preparation

Before running dirsearch, establish what protects the target:
- `wafw00f <url>` to fingerprint WAF/CDN (see `wafw00f.md`). The result determines thread count, delay, and whether to set custom headers.
- `httpx -l hosts.txt -sc -title -server -td -silent` to confirm live hosts, identify server technology, and detect frameworks. Framework identity drives wordlist and extension selection.
- If the target runs behind a CDN or WAF, lower `-t` (10–20), add `--delay 0.3`, and consider `--random-agent`.

### Phase 2 — Wordlist selection

- Match wordlist to the target's technology stack: PHP sites get `-e php,phtml,inc,bak`; Java/Spring get `-e jsp,do,action,xml,properties`; Node/Express get `-e js,json,env`.
- Use `--wordlist-categories` for curated bundles when no custom list is available: `common` for general paths, `conf` for configuration files, `web` for web-specific paths, `all` for maximum coverage.
- Check effective wordlist before running with `--wordlist-status` to see resolved files and total entry count.
- Set `--wordlist-max-size` to cap generated entries and prevent runaway scans on large wordlists.

### Phase 3 — Soft-404 calibration

Most web applications return custom 200-status error pages. Without calibration, every path "exists."
- `--exclude-response <url_that_returns_404_content>` — dirsearch fetches this page and filters responses that look similar. The most reliable method.
- `--auto-calibration` — automatic wildcard detection from the beginning. Use as a fallback when you don't have a known-404 URL.
- `--filter-threshold <n>` — auto-filter after `n` duplicate responses. Catches uniform catch-all pages that neither method above identifies.
- Stack all three for maximum reliability: `--exclude-response <url> --auto-calibration --filter-threshold 20`.

### Phase 4 — Execution

- Pin resource limits: `-t <threads>`, `--max-rate <rps>`, `--delay <sec>`, `--max-time <sec>`, `--target-max-time <sec>`.
- Use `-q` in automation; `-v` when debugging (adds response time and content type).
- Output to structured format: `-o results.json -O json`.

### Phase 5 — Recursion

When initial results reveal directory structure, recurse:
- `-r` for standard recursion into discovered directories.
- `--deep-recursive` for full depth recursion on every path segment.
- `--force-recursive` to recurse into every found path, not only directories.
- Always cap with `-R <depth>` (2–3 is typical) and `--recursion-status` to avoid recursing into error pages.

### Phase 6 — Result triage and follow-up

- Parse JSON output for status/size/path patterns.
- Interesting 403s: re-test with `-m` method variations (PUT, DELETE, PATCH) or with different `--auth` credentials.
- Discovered API paths: hand off to `ffuf.md` for parameter fuzzing or `sqlmap.md` for injection testing.
- Large response bodies: inspect for information disclosure (stack traces, config dumps, debug pages).


## Wordlist Management

### Wordlist sources

- `-w <path>` one or more wordlist files or directories (comma-separated). When a directory is given, all `.txt` files inside are concatenated.
- `--wordlist-categories <names>` use curated category bundles: `common`, `conf`, `web`, or `all` for every bundled category. Comma-separated.
  `dirsearch -u https://target.tld --wordlist-categories common,conf -e php,bak`

### Wordlist generation control

- `--wordlist-backend <auto|python|native>` wordlist generation backend. `auto` (default) picks the fastest available; `native` uses compiled routines for large lists; `python` for compatibility.
- `--wordlist-status` show resolved wordlist files and generated entry count, then exit. Run this before a scan to verify what will be tested.
  `dirsearch -u https://target.tld -e php -w custom.txt --wordlist-status`
- `--wordlist-max-size <n>` abort if the generated wordlist exceeds `n` entries (default 500000). Safety valve against accidental combinatorial explosion from large extension lists.

### Extension handling

- `-e <ext>` extensions to test, comma-separated. The default behavior replaces `%EXT%` markers in the wordlist with each extension.
- `-f, --force-extensions` append extensions to the end of every wordlist entry (not just `%EXT%` markers). Turns `admin` into `admin.php`, `admin.html`, etc.
- `--overwrite-extensions` (`-O` in v0.4.x context, but v0.5.0 uses `-O` for output formats) replace all existing extensions in the wordlist with the specified ones.
- `--exclude-extensions <ext>` skip entries matching these extensions (e.g., `--exclude-extensions png,gif,ico` to skip static assets).
### Entry transformation

- `--prefixes <list>` prepend custom prefixes to every entry (comma-separated): `--prefixes .,_,~` turns `backup` into `.backup`, `_backup`, `~backup`.
- `--suffixes <list>` append custom suffixes to every entry (ignores directories): `--suffixes .bak,.old,.swp`.
- `-U, --uppercase` uppercase all wordlist entries.
- `-L, --lowercase` lowercase all wordlist entries.
- `-C, --capital` capitalize first letter of each entry.

Combination example — find backup files with common suffixes:
`dirsearch -u https://target.tld -w common.txt --suffixes .bak,.old,.orig,.swp,.save -e php,html -q -O json -o backups.json`


## Status and Response Filtering

dirsearch v0.5.0 provides two tiers of filtering: basic (quick scope controls) and advanced (ffuf-style matcher/filter).

### Basic filtering

Quick include/exclude controls that apply first:

- `-i <codes>` include only these status codes (comma-separated, supports ranges): `-i 200,301-302,403`.
- `-x <codes>` exclude these status codes: `-x 400,404,500-599`.
- `--exclude-sizes <sizes>` drop responses by size: `--exclude-sizes 0,0B,4KB`. Supports unit suffixes (B, KB, MB).
- `--exclude-text <text>` drop responses containing this text (repeatable flag for multiple texts).
- `--exclude-regex <re>` drop responses matching this regex.
- `--exclude-redirect <re>` drop responses whose redirect URL matches this regex or text.
- `--exclude-response <path>` drop responses similar to the page at this URL — the primary soft-404 calibration method.
- `--skip-on-status <codes>` stop scanning the entire target when any of these codes are hit. Useful for detecting bans: `--skip-on-status 429`.
- `--min-response-size <length>` drop responses below this size (supports unit suffixes: `1024`, `1KB`).
- `--max-response-size <length>` drop responses above this size.

### Advanced filtering (v0.5.0)

Full matcher/filter system matching ffuf's semantics. Advanced matchers/filters **override** basic `-i`/`-x` when both are set.

**Status codes:**
- `--mc <codes>` / `--match-status <codes>` match status codes (comma-separated, supports ranges).
- `--fc <codes>` / `--filter-status <codes>` filter (exclude) status codes.

**Response size:**
- `--ms <sizes>` / `--match-size <sizes>` match response sizes (comma-separated, supports ranges).
- `--fs <sizes>` / `--filter-size <sizes>` filter response sizes.

**Word count:**
- `--mw <words>` / `--match-words <words>` match response word counts.
- `--fw <words>` / `--filter-words <words>` filter response word counts.

**Line count:**
- `--ml <lines>` / `--match-lines <lines>` match response line counts.
- `--fl <lines>` / `--filter-lines <lines>` filter response line counts.

**Body regex:**
- `--mr <re>` / `--match-regex <re>` match responses whose body matches this regex.
- `--fr <re>` / `--filter-regex <re>` filter responses matching this regex.

**Response headers:**
- `--match-header <text>` match responses containing this header text (repeatable).
- `--filter-header <text>` filter responses containing this header text (repeatable).
- `--match-header-regex <re>` match responses whose headers match this regex.
- `--filter-header-regex <re>` filter responses whose headers match this regex.

**Response time:**
- `--mt <time>` / `--match-time <time>` match responses by elapsed milliseconds: `--mt ">500"` (slower than 500ms, potential processing-based paths).
- `--ft <time>` / `--filter-time <time>` filter by elapsed time: `--ft "<10"` (drop instant generic responses).

**Operator modes:**
- `--mmode <and|or>` / `--matcher-mode` logical operator for matchers (default `or` — any matcher matches). Set `and` to require all matchers to match.
- `--fmode <and|or>` / `--filter-mode` logical operator for filters (default `or`).

**Auto-calibration:**
- `--auto-calibration` force wildcard calibration at scan start. Sends probe requests to detect catch-all responses and auto-configures filtering.
- `--filter-threshold <n>` auto-filter after `n` duplicate responses (by size/status). Low values (5–10) aggressively suppress uniform responders; higher values (50+) are more permissive.

### Filtering strategy

Pattern: start with `--auto-calibration --filter-threshold 20`, then refine:
- Wildcard 200 pages: `--exclude-response <404_url>` or `--fs <common_size>`.
- Uniform redirect responses: `--exclude-redirect "/login"`.
- Noisy static assets: `--exclude-sizes 0` and add `--exclude-extensions` to the wordlist config.
- Time-based differentiation: `--mt ">200"` to surface paths that trigger backend processing vs instant 404s.

Example — tight filtering for a target with catch-all 200s:
`dirsearch -u https://target.tld -e php --auto-calibration --fc 404 --fs 1234 --fw 50 --fl 12 --fmode and -q -O json -o results.json`


## Recursion

### Recursion modes

- `-r, --recursive` standard recursion — when a directory is found, scan its contents using the same wordlist.
- `--deep-recursive` recurse at every directory depth in discovered paths. Finding `/api/v1/users/` also scans `/api/`, `/api/v1/`, and `/api/v1/users/`. Multiplies scan time — use on narrow targets.
- `--force-recursive` recurse into every found path, not only directories. A found `/admin.php` triggers a scan at `/admin.php/` (relevant for path-based routing frameworks like Laravel, Spring Boot).
- `-R <depth>, --max-recursion-depth <depth>` cap recursion depth. Always set this in automation — unbounded recursion on a large site can run indefinitely. `2` is typical; `3` for thorough coverage.

### Controlling recursion behavior

- `--recursion-status <codes>` which status codes trigger recursion. Default: directories (301/302). Expand to include 200,403 for thorough coverage:
  `--recursion-status 200,301,302,403`
- `--subdirs <list>` seed recursion with known subdirectories: `--subdirs api/,admin/,app/`.
- `--exclude-subdirs <list>` skip these during recursion: `--exclude-subdirs static/,assets/,media/`.

### Crawl mode

- `--crawl` parse discovered pages for new paths and add them to the scan queue. Lightweight alternative to full crawlers — picks up paths that wordlist entries miss. Combines well with `-r` for comprehensive coverage.

### Recursion strategy by target type

- **Small app, unknown structure:** `-r -R 2 --recursion-status 200,301,302,403 --force-recursive` — cast wide net.
- **Large app, known API prefix:** `--subdirs api/v1/,api/v2/ -r -R 2` — targeted recursion in the API tree.
- **CMS (WordPress/Drupal):** `-r -R 3 --subdirs wp-content/,wp-admin/,sites/default/ --recursion-status 200,301,302,403`.
- **Time-constrained:** skip recursion entirely and use `--wordlist-categories all` for breadth at depth-1. Faster than recursion on wide sites.


## Detection Profile

How dirsearch appears to defensive systems:

**Request patterns:**
- Sequential requests to paths from a known wordlist. IDS signatures match against common wordlist entries (`/admin`, `/backup`, `/config`, `/.env`, `/wp-login.php`).
- Extension appending pattern: the same base path appears multiple times with different extensions (`/admin`, `/admin.php`, `/admin.html`, `/admin.bak`) in quick succession.
- Uniform request structure: same method (GET), same headers, same body, varying only the path.
- Consistent inter-request timing at the configured thread rate.

**Default fingerprint:**
- Python `requests` library User-Agent (when `--random-agent` is not set). Many WAF rules match this explicitly.
- No cookies, no referrer, no session state unless explicitly configured.
- Connection pooling behavior from the Python HTTP backend.

**Volume profile:**
- Default thread count generates moderate request rates. A 50k-entry wordlist at `-t 30` completes in minutes — easily spotted in access logs as a burst of 404s from a single source IP.
- Recursive scans multiply volume linearly per depth level.

**WAF/IDS signatures that fire:**
- ModSecurity: `920350` (host header is an IP), `913100`/`913110` (scanner detection).
- Cloudflare: rate-limiting kicks in at sustained high request rates from a single IP.
- Generic: any rule matching a high ratio of 404/403 responses from a single source.

Detection is situational — a scan at `-t 5 --delay 1 --random-agent` with a custom wordlist is much harder to distinguish from organic traffic than a default-config blast.


## Evasion

### Rate and timing

- `--delay <sec>` inter-request delay (supports decimals: `--delay 0.5`). Fundamental evasion against rate-limiters.
- `--max-rate <n>` max requests per second. More predictable than `-t` alone for rate control.
- `-t <n>` threads. Lower thread count reduces burst rate; combine with `--delay` for smooth pacing.
- `--timeout <sec>` connection timeout. Raise on high-latency targets to avoid false negatives from timeouts.
- `--retries <n>` retry failed requests. Keep low (1–2) to avoid amplifying a ban.

### Proxy and routing

- `-p <url>, --proxy <url>` HTTP/SOCKS proxy. Repeatable for multiple proxies (round-robin).
  `dirsearch -u https://target.tld -p socks5://127.0.0.1:9050 -e php,html -q`
- `--proxies-file <path>` load proxy list from a file. One proxy per line. Rotates automatically.
- `--proxy-auth <user:pass>` authentication for the proxy.
- `--replay-proxy <url>` replay only matched/found paths through a separate proxy (e.g., Burp/Caido for manual review). Non-matching requests bypass the replay proxy.
  `dirsearch -u https://target.tld -e php --replay-proxy http://127.0.0.1:8080 -q`
- `--tor` route through Tor (expects Tor running on default SOCKS port).
- `--ip <ip>` connect to this IP instead of resolving the hostname. Bypasses DNS-based blocking; the Host header still carries the original hostname.
- `--interface <iface>` bind to a specific network interface.

### Identity masking

- `--random-agent` rotate User-Agent from a bundled list per request. Always enable in pentest scans — the default Python UA is a signature.
- `--user-agent <string>` set a fixed custom User-Agent.
- `-H <header>` custom headers. Repeatable. Use for source-IP spoofing headers:
  `dirsearch -u https://target.tld -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -e php -q`
- `--headers-file <path>` load headers from a file (one per line).
- `--cookie <cookie>` set a cookie to look like an authenticated session.

### Transport

- `--scheme <http|https>` force a scheme when not specified in the target or raw request.
- `-F, --follow-redirects` follow HTTP redirects. Can help bypass some 301-based WAF responses.
- `--request-backend <python|native>` select the HTTP backend. `native` may have different TLS fingerprints than `python`.

### Effectiveness notes

- `--random-agent` + `--delay 0.5` + `-t 10` is the minimum evasion baseline for targets with any WAF.
- Proxy rotation (`--proxies-file`) distributes source IPs but adds latency and introduces connection failures.
- `--tor` is the most aggressive source-hiding option but the slowest; many targets block known Tor exit nodes.
- `--replay-proxy` is not evasion — it sends additional traffic. Use only for result capture, not stealth.
- No amount of rate control hides a scan from application-level logging. The goal is to avoid automated blocking, not to be invisible.


## Authentication

### Built-in authentication

- `--auth <credential>` authentication credential. Format depends on `--auth-type`.
- `--auth-type <type>` authentication type: `basic`, `digest`, `bearer`, `ntlm`, `jwt`.
  - Basic/Digest: `--auth user:password --auth-type basic`
  - Bearer token: `--auth <token> --auth-type bearer`
  - NTLM: `--auth DOMAIN\\user:password --auth-type ntlm`
  - JWT: `--auth <jwt_token> --auth-type jwt`

### Cookie-based authentication

- `--cookie <cookie>` set a cookie string. The primary method for session-based auth:
  `dirsearch -u https://target.tld --cookie "session=abc123; csrf=xyz" -e php -q`

### Client certificate authentication

- `--cert-file <path>` client-side certificate (PEM).
- `--key-file <path>` client-side private key (unencrypted PEM).
  `dirsearch -u https://mtls.target.tld --cert-file client.pem --key-file client.key -e php -q`

### Raw request authentication

- `--raw <path>` load a captured HTTP request that already contains auth headers/cookies. Preserves exact request state from Caido/Burp:
  `dirsearch --raw captured_auth_request.txt --scheme https -e php -q`
  The raw request's headers (Authorization, Cookie, CSRF tokens) are used for every scan request. Only the path is mutated.

### Session workflow with Caido

1. Browse the authenticated application through Caido.
2. `view_request(request_id, part="request")` to extract a representative authenticated request.
3. Save raw bytes to file, strip the path.
4. `dirsearch --raw req.txt --scheme https -e php -q`
5. Found paths with auth context appear in Caido's history for replay analysis.


## Input Formats

### Target specification

- `-u <url>` single target URL. Repeatable: `-u https://a.tld -u https://b.tld`.
- `-l <path>` / `--urls-file <path>` URL list file, one per line.
- `--stdin` read URLs from stdin. Pipe from httpx/subfinder:
  `httpx -l hosts.txt -silent | dirsearch --stdin -e php -q`
- `--cidr <cidr>` scan a CIDR range. Resolves hosts and scans each.
- `--raw <path>` raw HTTP request file. The path in the request is the base; dirsearch appends wordlist entries. Use `--scheme` to set https if not in the request line.
- `--nmap-report <path>` load targets from an nmap XML report (requires nmap `-sV` for service detection). Extracts HTTP services and their ports:
  `nmap -sV -oX nmap.xml <host> && dirsearch --nmap-report nmap.xml -e php,html -q`

### Request configuration

- `-m <METHOD>, --http-method <METHOD>` HTTP method (default GET). Use `-m POST` with `-d` for POST-based discovery.
- `-d <data>, --data <data>` POST body data.
- `--data-file <path>` load POST body from a file.
- `-H <header>, --header <header>` custom request headers. Repeatable.
- `--headers-file <path>` load headers from a file.
- `-F, --follow-redirects` follow HTTP redirects.
- `--request-backend <python|native>` HTTP backend selection. `python` (default) uses the `requests` library; `native` uses a compiled backend for different performance/TLS characteristics.


## Session Management

dirsearch v0.5.0 provides full session persistence for resuming interrupted scans and managing multi-target assessments.

- `-s <file>, --session <file>` save and resume from a session file. If the file exists, the scan resumes from where it left off; if not, a new session is created.
  `dirsearch -u https://target.tld -e php -s scan_session.db -q`
- `--session-id <id>` resume a session by its numeric ID (as listed by `--list-sessions`).
- `--list-sessions` list all resumable sessions with their IDs, targets, and progress. Exit without scanning.
- `--sessions-dir <path>` directory to search for session files (default: dirsearch path `/sessions` or `$HOME/.dirsearch/sessions`).

Session workflow for large assessments:
1. Start: `dirsearch -l targets.txt -e php,html -s assessment.db -q -O json -o results.json`
2. Interrupt (Ctrl-C) when needed.
3. Resume: `dirsearch -s assessment.db` — picks up where it stopped.
4. Review sessions: `dirsearch --list-sessions --sessions-dir ./`


## Async Mode

- `-a, --async` enable asynchronous request mode. Uses Python's async I/O instead of threading.
- `--sync, --no-async` force synchronous (threaded) Python mode.

When async mode helps:
- Large target lists where I/O wait dominates CPU usage.
- High-latency targets where threads would spend most time waiting.
- Lower memory footprint than equivalent thread count.

When to avoid:
- Targets that are sensitive to connection-level behavior — async may open/close connections differently than the threaded backend.
- When using `--request-backend native` — async applies to the Python backend only.

Default (`auto` in backend selection) picks the appropriate mode. Explicit `-a` forces async regardless.


## Output

### Output files

- `-o <path>, --output-file <path>` output file path.
- `-O <formats>, --output-formats <formats>` output format(s), comma-separated. Available: `simple`, `plain`, `json`, `xml`, `md`, `csv`, `html`, `sqlite`. Multiple formats write multiple files:
  `dirsearch -u https://target.tld -e php -o results -O json,csv,html`
  Generates `results.json`, `results.csv`, `results.html`.

### Database output

- `--mysql-url <url>` write results to MySQL. Format: `mysql://[user:pass@]host[:port]/database`.
- `--postgres-url <url>` write results to PostgreSQL. Format: `postgres://[user:pass@]host[:port]/database`.
- `--log <path>` write a log file (full request/response detail for debugging).

### Display controls

- `-q, --quiet-mode` suppress banner and progress output. Show only findings. Required in automation.
- `--disable-cli` turn off all command-line output entirely (write only to file/database).
- `-v, --verbose` show verbose output including response time and content type per result.
- `--full-url` display full URLs in output (auto-enabled in quiet mode).
- `--redirects-history` show the full redirect chain for each result.
- `--no-color` disable ANSI color codes.

### Runtime limits

- `--max-time <sec>` maximum total runtime. The scan stops mid-wordlist when the limit is hit.
- `--target-max-time <sec>` maximum runtime per target (for multi-target scans). Each target gets its own time budget.
- `--exit-on-error` exit immediately on any error instead of continuing.


## Chaining

### Upstream feeds

- **nmap → dirsearch:** `nmap -sV -oX nmap.xml <host>` then `dirsearch --nmap-report nmap.xml -e php,html -q`. nmap's service detection identifies HTTP services and ports; dirsearch scans each.
- **httpx → dirsearch:** `httpx -l hosts.txt -sc -silent | dirsearch --stdin -e php,html -q`. httpx confirms live HTTP services; dirsearch discovers content on each.
- **subfinder → httpx → dirsearch:** full pipeline from subdomain enumeration to content discovery.

### Downstream consumers

- **dirsearch → ffuf:** dirsearch is the broad sweep; ffuf is the surgical follow-up. When dirsearch finds an interesting endpoint (e.g., `/api/v1/`), hand it to ffuf for parameter fuzzing, header injection testing, or method enumeration:
  `ffuf -w params.txt -u "https://target.tld/api/v1/FUZZ" -mc 200 -ac`
- **dirsearch → sqlmap:** discovered endpoints with parameters go to sqlmap for injection testing:
  `sqlmap -u "https://target.tld/api/v1/users?id=1" -p id --batch`
- **dirsearch → nuclei:** discovered paths feed nuclei for vulnerability scanning:
  `dirsearch -u https://target.tld -e php -q -O plain -o urls.txt && nuclei -l urls.txt -as -s critical,high`

### WAF-informed scanning

- **wafw00f → dirsearch:** fingerprint the WAF first, then configure dirsearch accordingly:
  - Cloudflare: `-t 10 --delay 0.5 --random-agent`
  - AWS WAF: `-t 15 --delay 0.3 --random-agent -H "X-Forwarded-For: 127.0.0.1"`
  - No WAF: `-t 40 --max-rate 200`

### Proxy integration

- The sandbox auto-routes through Caido via `http_proxy`/`https_proxy`. All dirsearch traffic appears in Caido's history for HTTPQL analysis and replay.
- `--replay-proxy` sends only found paths to a separate proxy instance for focused review without replaying the entire wordlist.
- Caido history after a dirsearch run: `await list_requests(httpql_filter='req.path.cont:"/api/" AND resp.status.eq:200', first=100)` (see `caido.md`).

Cross-references:
- `tooling/ffuf.md` — surgical parameter/header/body fuzzing after dirsearch identifies endpoints
- `tooling/feroxbuster.md` — thin sibling, same workflow, Rust throughput and different recursion defaults
- `tooling/wafw00f.md` — WAF fingerprinting to inform thread/delay/header configuration
- `tooling/nmap.md` — upstream port/service discovery feeding `--nmap-report`
- `tooling/httpx.md` — upstream live-host confirmation and technology detection
- `tooling/caido.md` — proxy-driven replay and analysis of discovered endpoints
