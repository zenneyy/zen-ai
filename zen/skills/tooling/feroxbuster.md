---
name: feroxbuster
description: feroxbuster recursive content discovery — Rust-fast counterpart to dirsearch, with aggressive-by-default recursion and composite smart/thorough modes.
---

# feroxbuster CLI Playbook

Official docs:
- https://github.com/epi052/feroxbuster
- https://epi052.github.io/feroxbuster-docs/

Verified version in sandbox image (`ghcr.io/zenneyy/zen-sandbox:1.2.2`): **feroxbuster 2.13.1**.

Canonical syntax:
`feroxbuster -u <url> [options]` (or `--stdin` / `--resume-from <state>` / `--request-file <file>`)

For the shared content-discovery workflow (soft-404 calibration, auth, extensions, output), use `tooling/dirsearch.md` — this file documents only what feroxbuster adds.

## Target Selection

- `-u, --url <URL>` single target URL (required unless `--stdin`, `--resume-from`, or `--request-file` provided)
- `--stdin` read URL(s) from stdin, one per line
- `--resume-from <STATE_FILE>` resume a partially completed scan from a state file (e.g. `ferox-1606586780.state`)
- `--request-file <REQUEST_FILE>` raw HTTP request file used as template for all requests

## Composite Settings

- `--burp` shorthand: sets `--proxy http://127.0.0.1:8080` and `--insecure`
- `--burp-replay` shorthand: sets `--replay-proxy http://127.0.0.1:8080` and `--insecure`
- `--data-urlencoded <DATA>` sets `Content-Type: application/x-www-form-urlencoded`, `--data` to the value (supports `@file`), and `-m POST`
- `--data-json <DATA>` sets `Content-Type: application/json`, `--data` to the value (supports `@file`), and `-m POST`
- `--smart` enables `--auto-tune`, `--collect-words`, and `--collect-backups`
- `--thorough` enables everything in `--smart` plus `--collect-extensions` and `--scan-dir-listings`

## Proxy Settings

- `-p, --proxy <PROXY>` proxy for all requests (`http(s)://host:port`, `socks5(h)://host:port`)
- `-P, --replay-proxy <REPLAY_PROXY>` send only unfiltered/matched requests through this proxy (bulk traffic goes direct)
- `-R, --replay-codes <REPLAY_CODE>...` status codes to forward through the replay proxy (defaults to the `-s` value)

## Request Settings

- `-a, --user-agent <USER_AGENT>` set User-Agent (default `feroxbuster/2.13.1`)
- `-A, --random-agent` randomize User-Agent per request
- `-x, --extensions <FILE_EXTENSION>...` file extensions to append (space/comma/repeat; `@ext.txt` reads from file)
- `-m, --methods <HTTP_METHODS>...` HTTP method(s) (default GET; multiple allowed)
- `--data <DATA>` request body (`@file` reads from disk)
- `-H, --headers <HEADER>...` custom headers (repeat for multiple: `-H Header:val -H 'X-Custom: foo'`)
- `-b, --cookies <COOKIE>...` cookies (e.g. `-b session=abc123`)
- `-Q, --query <QUERY>...` query parameters appended to every request (e.g. `-Q token=abc -Q debug=1`)
- `-f, --add-slash` append `/` to each request URL
- `--protocol <PROTOCOL>` default protocol when targeting via `--request-file` or `--url` with domain only (default `https`)

## Request Filters

- `--dont-scan <URL>...` URL(s) or regex patterns to exclude from recursion and scanning
- `--scope <URL>...` additional domains/URLs considered in-scope (in addition to the target domain)

## Response Filters

- `-S, --filter-size <SIZE>...` filter by response body size in bytes (e.g. `-S 5120 -S 4927,1970`)
- `-X, --filter-regex <REGEX>...` filter by regex matching response body or headers (e.g. `-X '^Not Found$'`)
- `-W, --filter-words <WORDS>...` filter by word count (e.g. `-W 312`)
- `-N, --filter-lines <LINES>...` filter by line count (e.g. `-N 20`)
- `-C, --filter-status <STATUS_CODE>...` filter status codes — deny list (e.g. `-C 404 -C 403`)
- `--filter-similar-to <UNWANTED_PAGE>...` filter pages similar to the given URL (soft-404 calibration)
- `-s, --status-codes <STATUS_CODE>...` status codes to include — allow list (default: all codes)
- `--unique` only display unique responses (dedup by body hash)

## Client Settings

- `-T, --timeout <SECONDS>` HTTP request timeout (default 7)
- `-r, --redirects` follow 3xx redirects
- `-k, --insecure` disable TLS certificate validation
- `--server-certs <PEM|DER>...` custom root certificate(s) for servers with unknown CAs
- `--client-cert <PEM>` PEM-encoded certificate for mutual TLS (mTLS)
- `--client-key <PEM>` PEM-encoded private key for mTLS

## Scan Settings

- `-t, --threads <THREADS>` concurrent threads (default 50)
- `-n, --no-recursion` disable recursive scanning
- `-d, --depth <RECURSION_DEPTH>` maximum recursion depth (default 4; `0` = infinite)
- `--force-recursion` attempt recursion on all found endpoints (still respects `-d`)
- `--dont-extract-links` disable extracting links from HTML/JS response bodies
- `-L, --scan-limit <SCAN_LIMIT>` limit total concurrent directory scans (default 0 = no limit)
- `--parallel <PARALLEL_SCANS>` spawn N child feroxbuster processes (one per stdin URL)
- `--rate-limit <RATE_LIMIT>` max requests per second per directory (default 0 = unlimited)
- `--response-size-limit <BYTES>` max response body bytes to read (default 4 MB)
- `--time-limit <TIME_SPEC>` global runtime cap (e.g. `10m`, `1h`)
- `-w, --wordlist <FILE>` wordlist path or URL
- `--auto-tune` automatically lower scan rate when excessive errors occur
- `--auto-bail` automatically stop scanning when excessive errors occur
- `-D, --dont-filter` disable automatic wildcard response filtering
- `--scan-dir-listings` force recursion into detected directory listings

## Dynamic Collection

- `-E, --collect-extensions` discover extensions from responses and add to `-x` dynamically
- `-B, --collect-backups [<SUFFIXES>...]` request backup variants for found URLs (defaults: `~`, `.bak`, `.bak2`, `.old`, `.1`)
- `-g, --collect-words` discover words from response bodies and add to the wordlist dynamically
- `-I, --dont-collect <FILE_EXTENSION>...` ignore these extensions during `--collect-extensions` (e.g. `-I png -I gif`)

## Output

- `-v, --verbosity...` increase verbosity (`-vv`, `-vvv`; `-vvvv` is likely excessive)
- `--silent` print only URLs (or JSON with `--json`) and suppress logging; suitable for piping
- `-q, --quiet` hide progress bars and banner (good for tmux/screen)
- `--json` emit JSON logs to `--output` and `--debug-log`
- `-o, --output <FILE>` write results to file
- `--debug-log <FILE>` write debug/log entries to file
- `--no-state` disable periodic state file output (`*.state`)
- `--limit-bars <NUM_BARS_TO_SHOW>` limit number of visible progress bars

## Agent-Safe Baselines

Standard recursive scan:
`feroxbuster -u https://target.tld -x php,html,js --smart --time-limit 10m --rate-limit 50 -t 30 -q --json -o feroxbuster.json`

Flat (non-recursive) sweep:
`feroxbuster -u https://target.tld -n -x php,html,js --rate-limit 50 -t 30 -q --json -o feroxbuster.json`

Thorough deep dive:
`feroxbuster -u https://target.tld --thorough -d 3 --time-limit 20m --rate-limit 30 -t 20 -q --json -o feroxbuster.json`

## Common Patterns

Baseline recursive with smart defaults:
`feroxbuster -u https://target.tld -x php,html,js --smart -q --json -o feroxbuster.json`

Thorough mode (adds dir-listings + extension collection):
`feroxbuster -u https://target.tld --thorough --time-limit 20m -q --json -o feroxbuster_thorough.json`

Flat single-level sweep (parity with ffuf-style fuzzing):
`feroxbuster -u https://target.tld -n -x php,html,js -q --json -o feroxbuster_flat.json`

JSON POST API discovery:
`feroxbuster -u https://target.tld/api --data-json '{"id":1}' -w api_wordlist.txt -q --json -o feroxbuster_api.json`

Form POST discovery:
`feroxbuster -u https://target.tld/admin --data-urlencoded 'action=test' -w admin_words.txt -q --json -o feroxbuster_form.json`

Resume an interrupted scan:
`feroxbuster --resume-from ferox-1606586780.state`

Replay-only to Caido (bulk direct, matches through Caido):
`feroxbuster -u https://target.tld --burp-replay -q --json -o feroxbuster.json`

Scope-bound multi-domain:
`feroxbuster -u https://app.target.tld --scope https://api.target.tld --dont-scan "/logout.*" -q --json -o feroxbuster.json`

Multi-target parallel from stdin:
`cat targets.txt | feroxbuster --stdin --parallel 4 --smart --time-limit 10m -q --json -o feroxbuster_multi.json`

Status-code filtered scan:
`feroxbuster -u https://target.tld -s 200,204,301,302,307,401,403,405 -x php,html -q --json -o feroxbuster.json`

Piping results to another tool:
`cat targets.txt | feroxbuster --stdin --silent -s 200,301,302 --redirects -x js | nuclei -t http/ -silent`

Custom request template:
`feroxbuster --request-file raw_request.txt -w wordlist.txt -q --json -o feroxbuster_custom.json`

mTLS authenticated scan:
`feroxbuster -u https://internal.target.tld --client-cert client.pem --client-key client-key.pem --server-certs internal-ca.pem -q --json -o feroxbuster_mtls.json`

Custom root CA (internal PKI):
`feroxbuster -u https://internal.target.tld --server-certs /path/to/ca.pem -k -q --json -o feroxbuster_internal.json`

SOCKS proxy routing:
`feroxbuster -u https://target.tld --proxy socks5://127.0.0.1:9050 -q --json -o feroxbuster_tor.json`

Extension discovery with exclusions:
`feroxbuster -u https://target.tld -E -I png,gif,jpg,svg,css,woff,woff2 --smart -q --json -o feroxbuster.json`

Custom backup suffixes:
`feroxbuster -u https://target.tld -B "~" ".bak" ".old" ".orig" ".save" ".swp" -q --json -o feroxbuster.json`

Query-parameter authenticated scan:
`feroxbuster -u https://target.tld -Q token=0123456789ABCDEF -q --json -o feroxbuster.json`

## Critical Correctness Rules

- Recursion depth defaults to 4 — large sites with link extraction can balloon request count fast. Pin `-d` and `--time-limit` in automation.
- `--smart` and `--thorough` are composite flags. `--smart` = `--auto-tune --collect-words --collect-backups`. `--thorough` = `--smart --collect-extensions --scan-dir-listings`. Do not mix composites with their component flags — later flags do not reset the implied options.
- `--dont-extract-links` disables the HTML/JS scraper that normally feeds recursion. Signal loss is real; disable only when the target serves massive responses making extraction expensive.
- Status allow-list (`-s`) defaults to all codes. Most useful scans want `-s 200,204,301,302,307,401,403,405`.
- `--rate-limit` is **per directory**, not global. With multiple concurrent directory scans (`-L` or `--parallel`), the effective global rate is `rate-limit × active-directories`.
- `--burp`/`--burp-replay` hardcode `127.0.0.1:8080` and set `--insecure`. The sandbox already proxies via `http_proxy` env; these are only needed when the HTTP proxy should differ from env.
- `-x` (extensions) accepts multiple forms: `-x php -x html`, `-x php,html`, `-x php html`, `@ext.txt`. All are equivalent and can be mixed.
- `--data` / `--data-json` / `--data-urlencoded` support `@file` to read body from disk — use for large or binary payloads.
- `--filter-similar-to` compares using a similarity hash — it needs a reachable URL that returns the unwanted response pattern. The URL must be accessible at scan time.
- `--parallel` spawns child processes, each scanning one stdin URL independently. State files are per-child. Memory and CPU multiply by the parallelism factor.
- `--response-size-limit` (default 4 MB) caps how much of each response body feroxbuster reads. Raise for targets serving large pages; lower for bandwidth-constrained scans.

## Methodology

### Phase 1 — Target Assessment and Mode Selection

Before launching feroxbuster, determine the scan strategy:

**Web application (server-rendered HTML):**
`feroxbuster -u https://target.tld -x php,html,asp,aspx,jsp --smart -d 3 --time-limit 15m --rate-limit 50 -q --json -o ferox.json`

The `--smart` composite auto-discovers words from responses and checks backup files, expanding coverage without manual wordlist tuning. Pin `-d 3` to prevent recursion spirals on deep directory trees.

**REST/JSON API:**
`feroxbuster -u https://target.tld/api -x json -m GET,POST -w api_wordlist.txt -n --rate-limit 30 -q --json -o ferox_api.json`

APIs are typically flat (no directory recursion) and benefit from method variation. Use `-n` (no recursion) and a domain-specific wordlist.

**Static file server / CDN origin:**
`feroxbuster -u https://target.tld --thorough -d 2 --time-limit 10m -q --json -o ferox_static.json`

`--thorough` adds extension collection and directory listing scanning — both productive on file servers that expose listings.

**Internal / mTLS-protected target:**
`feroxbuster -u https://internal.target.tld --client-cert client.pem --client-key client-key.pem --server-certs ca.pem --smart -d 2 -q --json -o ferox_internal.json`

### Phase 2 — Extension Strategy

**Static extension set** — when the tech stack is known:
`feroxbuster -u https://target.tld -x php,html,txt,bak,old -q --json -o ferox.json`

**Dynamic extension discovery** — when the stack is unknown or mixed:
`feroxbuster -u https://target.tld -E -I png,gif,jpg,svg,css,woff,woff2,ico,map --smart -q --json -o ferox.json`

`-E` discovers extensions from response content; `-I` excludes static assets that generate noise without security value. The combination is the richest approach but generates more requests.

**Backup-focused extension set** — searching for editor/deployment artifacts:
`feroxbuster -u https://target.tld -B "~" ".bak" ".bak2" ".old" ".orig" ".save" ".swp" ".tmp" -w targeted_wordlist.txt -q --json -o ferox_backups.json`

Custom backup suffixes replace the defaults (`~`, `.bak`, `.bak2`, `.old`, `.1`). Target `.swp` (Vim), `.orig` (patch), `.save` (nano) for editor artifacts.

### Phase 3 — Scope and Recursion Control

**Single-domain bounded scan:**
`feroxbuster -u https://target.tld -d 3 --time-limit 10m --dont-scan "/logout" --dont-scan "/signout" --dont-scan "/api/v[0-9]+/webhook" -q --json -o ferox.json`

Always exclude logout/signout paths (destroy sessions), webhook endpoints (trigger side effects), and other known-dangerous paths.

**Multi-domain scope expansion:**
`feroxbuster -u https://app.target.tld --scope https://api.target.tld --scope https://admin.target.tld --dont-scan ".*\.(css|js|png|jpg)$" -d 2 -q --json -o ferox_multi.json`

`--scope` adds domains that feroxbuster will follow during link extraction. Without it, cross-domain links discovered during recursion are ignored.

**Force-recursion on flat structures:**
`feroxbuster -u https://target.tld --force-recursion -d 2 --time-limit 15m -q --json -o ferox.json`

Normally feroxbuster only recurses into paths it identifies as directories. `--force-recursion` attempts recursion on every discovered endpoint — useful when the target doesn't signal directories with trailing slashes or 301s, but generates significantly more traffic.

### Phase 4 — Authentication and State

**Cookie-based session:**
`feroxbuster -u https://target.tld -b "session=abc123; csrf_token=xyz" -H "X-Requested-With: XMLHttpRequest" -q --json -o ferox_auth.json`

**Header-based auth (Bearer/API key):**
`feroxbuster -u https://target.tld/api -H "Authorization: Bearer <token>" -H "X-API-Key: <key>" -q --json -o ferox_api_auth.json`

**Query-parameter token:**
`feroxbuster -u https://target.tld -Q token=abc123 -Q apikey=def456 -q --json -o ferox_query_auth.json`

**Request-file template** — when the request shape is complex or non-standard:
```
GET /FUZZ HTTP/1.1
Host: target.tld
Authorization: Bearer <token>
X-Custom-Header: value
Cookie: session=abc123
```
`feroxbuster --request-file custom_request.txt -w wordlist.txt -q --json -o ferox_template.json`

The `--request-file` path reads a raw HTTP request; feroxbuster replaces the URL path with wordlist entries. Useful for targets requiring specific header combinations or non-standard request shapes.

### Phase 5 — Wordlist Selection

Default wordlist: feroxbuster uses its built-in `raft-medium-directories.txt` if no `-w` is given.

**Override with a targeted wordlist:**
`feroxbuster -u https://target.tld -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -q --json -o ferox.json`

**URL-based wordlist** (downloaded at runtime):
`feroxbuster -u https://target.tld -w https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -q --json -o ferox.json`

**Wordlist with dynamic word collection:**
`feroxbuster -u https://target.tld -w small_wordlist.txt -g --smart -q --json -o ferox.json`

`-g` / `--collect-words` extracts words from response bodies and adds them to the active wordlist mid-scan. Combined with a small seed wordlist, this builds coverage from the target itself — particularly effective on custom applications with unique naming conventions.

### Phase 6 — Output and Pipeline Integration

**JSON for automation:**
`feroxbuster -u https://target.tld --smart -q --json -o ferox.json`

**Silent mode for piping:**
`feroxbuster -u https://target.tld --silent -s 200,301,302 --redirects | nuclei -t http/ -silent`

**Debug logging alongside results:**
`feroxbuster -u https://target.tld --smart -q --json -o ferox.json --debug-log ferox_debug.log`

**Suppress state files** (disposable scans):
`feroxbuster -u https://target.tld --no-state --smart -q --json -o ferox.json`

**Limit progress bars** (multi-target scans in constrained terminals):
`feroxbuster -u https://target.tld -d 3 --limit-bars 5 -q --json -o ferox.json`

## Detection

### Default Fingerprint

The default User-Agent is `feroxbuster/2.13.1`. Any WAF, IDS, or log analyzer that maintains a scanner-UA signature list will flag this immediately. The string is unique to feroxbuster and not shared with any legitimate browser or crawler.

### Request Pattern Signature

Feroxbuster's recursive scanning creates a distinctive traffic pattern:
- Rapid sequential requests to paths at the same directory depth, each differing only in the final path segment
- When recursion triggers, a burst of requests to a new path prefix appears mid-scan
- Extension probing creates clusters of requests to the same base path with different suffixes (e.g. `/admin`, `/admin.php`, `/admin.html`, `/admin.bak`)
- Dynamic word collection (`-g`) generates additional requests mid-scan as new words are discovered, creating a non-deterministic request pattern

### Rate Profile

Default behavior with `-t 50` and no `--rate-limit` generates aggressive burst traffic — potentially hundreds of requests per second against a single host. This exceeds typical user behavior by orders of magnitude and triggers most rate-limiters within seconds.

With `--parallel`, the rate multiplies by the number of child processes, each scanning independently.

### Recursion Footprint

Each discovered directory spawns a new scan context. On a target with deep nesting, the scan tree grows exponentially. IDS systems that track path-enumeration depth will see feroxbuster exploring directories that no user would navigate to sequentially.

### Extension Probing

`--collect-extensions` and `--collect-backups` generate requests for file variations that no legitimate client would request: `config.php.bak`, `index.html~`, `login.old`. The backup-extension pattern is a strong indicator of content-discovery scanning.

### TLS Fingerprint

Feroxbuster's TLS client hello (built from Rust's `reqwest`/`native-tls` or `rustls` depending on build) has a distinct JA3 hash. TLS-fingerprinting WAFs (Cloudflare, Akamai) may use this to distinguish feroxbuster from browser traffic even when the UA is randomized.

## Bypass and Evasion

### User-Agent Rotation

`-A` randomizes the UA per request from a built-in browser-UA pool:
`feroxbuster -u https://target.tld -A --smart -q --json -o ferox.json`

Effectiveness: situational. Defeats simple UA-string blocklists. Does not defeat TLS fingerprinting, behavioral analysis, or rate-based detection.

### Rate Control

**Per-directory rate limiting:**
`feroxbuster -u https://target.tld --rate-limit 10 -t 10 -q --json -o ferox.json`

`--rate-limit 10` caps each directory scan at 10 req/s. With `-t 10`, the scanner stays below a single directory's limit. The effective global rate depends on how many directories are being scanned concurrently.

**Concurrent scan limiting:**
`feroxbuster -u https://target.tld --rate-limit 10 -L 2 -t 10 -q --json -o ferox.json`

`-L 2` limits to 2 concurrent directory scans. Combined with `--rate-limit 10`, the maximum global rate is 20 req/s — predictable and controllable.

**Combined throttle formula:** effective max rate = `--rate-limit × min(active-directories, -L)`. Pin both for deterministic traffic.

### Adaptive Rate Control

`--auto-tune` reduces scan speed when the target starts returning errors (connection resets, 429s, 5xx bursts):
`feroxbuster -u https://target.tld --auto-tune --rate-limit 50 -q --json -o ferox.json`

`--auto-bail` stops the scan entirely on sustained errors:
`feroxbuster -u https://target.tld --auto-bail --rate-limit 50 -q --json -o ferox.json`

`--smart` includes `--auto-tune` by default. For aggressive-but-adaptive scanning, `--smart` alone adapts; for conservative scanning, add explicit `--rate-limit` and `-L`.

Effectiveness: situational. `--auto-tune` reacts to server-side errors, which means the initial burst has already triggered detection. Useful as a safety valve, not as primary evasion.

### Proxy Routing

**Route through Caido/Burp for inspection:**
`feroxbuster -u https://target.tld -p http://127.0.0.1:8080 -k -q --json -o ferox.json`

**Route through SOCKS proxy for IP rotation:**
`feroxbuster -u https://target.tld --proxy socks5://127.0.0.1:9050 -q --json -o ferox.json`

**Selective replay proxy** — send only interesting responses through the inspection proxy, bulk traffic goes direct:
`feroxbuster -u https://target.tld -P http://127.0.0.1:8080 -R 200,302,401,403 -k -q --json -o ferox.json`

The replay proxy is feroxbuster's distinctive evasion/inspection hybrid: bulk scanning avoids proxy overhead, while only matched responses flow through Caido for manual review. This reduces Caido's log volume to actionable findings.

### Soft-404 Calibration

Many targets return 200 with a custom "not found" page. `--filter-similar-to` hashes a known-bad page and filters responses that resemble it:

1. Identify a soft-404 URL:
   `curl -s -o /dev/null -w '%{http_code} %{size_download}' https://target.tld/definitely-not-a-real-path-12345`
2. If it returns 200, use that URL as the filter baseline:
   `feroxbuster -u https://target.tld --filter-similar-to https://target.tld/definitely-not-a-real-path-12345 -q --json -o ferox.json`

Multiple `--filter-similar-to` URLs are supported for targets with different soft-404 patterns per directory.

Feroxbuster also has built-in wildcard detection (automatic). If it incorrectly filters legitimate responses, disable with `-D`:
`feroxbuster -u https://target.tld -D -S 1234 -q --json -o ferox.json`

Combine `-D` (disable auto-filter) with explicit `-S` (filter by size) to manually calibrate when the auto-detection is wrong.

### Scope Restriction for Noise Reduction

Exclude paths that generate detection noise without security value:
`feroxbuster -u https://target.tld --dont-scan "/health" --dont-scan "/metrics" --dont-scan "/status" --dont-scan ".*\.(css|js|png|jpg|gif|svg|woff|woff2|ico)$" -q --json -o ferox.json`

### Timeout and Runtime Capping

`--time-limit` prevents runaway scans from generating hours of traffic:
`feroxbuster -u https://target.tld --time-limit 10m --smart -q --json -o ferox.json`

Pin `--time-limit` on every automation run. Without it, recursive scans on large sites can run indefinitely.

## Techniques

### Composite Mode Deep-Dive

**`--smart` breakdown:**
- `--auto-tune` — back off on error spikes (adaptive rate)
- `--collect-words` — extract words from HTML/JS responses and add to active wordlist
- `--collect-backups` — for each found URL, request it with backup suffixes (`~`, `.bak`, `.bak2`, `.old`, `.1`)

**`--thorough` breakdown (everything in `--smart` plus):**
- `--collect-extensions` — discover file extensions from responses and add to `-x`
- `--scan-dir-listings` — if a directory listing is detected, recurse into its entries

**When to use each:**
- `--smart` is the default automation choice. Low overhead, high signal.
- `--thorough` is for deep dives on narrowly scoped targets (single app, specific subdirectory). The extension collection and dir-listing recursion generate significantly more traffic.
- Neither composite: when fine-grained control over each component flag is needed, or when `--auto-tune` would interfere with rate testing.

### Dynamic Collection Mechanics

**`--collect-extensions` (`-E`):**
Feroxbuster parses response content for file references (e.g. `src="script.js"`, `href="style.css"`, `<a href="doc.pdf">`), extracts the extensions, and adds them to the `-x` set mid-scan. Subsequent wordlist entries get the new extensions appended.

Exclude noisy static-asset extensions with `-I`:
`feroxbuster -u https://target.tld -E -I png,gif,jpg,svg,css,woff,woff2,ico,map -q --json -o ferox.json`

**`--collect-backups` (`-B`):**
For each discovered URL (e.g. `/admin/config.php`), feroxbuster requests:
- `/admin/config.php~`
- `/admin/config.php.bak`
- `/admin/config.php.bak2`
- `/admin/config.php.old`
- `/admin/config.php.1`

Custom suffixes override the defaults:
`feroxbuster -u https://target.tld -B "~" ".bak" ".orig" ".swp" ".save" -q --json -o ferox.json`

**`--collect-words` (`-g`):**
Feroxbuster tokenizes response bodies and extracts likely path/file names. Found words are added to the wordlist. Particularly effective when:
- The application uses unique naming conventions not in standard wordlists
- Directory listings or navigation menus expose path names
- JavaScript files reference API endpoints or internal paths

### State Persistence and Resume

Feroxbuster writes periodic state files (default: `ferox-<timestamp>.state` in CWD):

**Disable state files** (disposable scans):
`feroxbuster -u https://target.tld --no-state -q --json -o ferox.json`

**Resume from state:**
`feroxbuster --resume-from ferox-1606586780.state`

Resume picks up where the scan left off — completed wordlist entries are skipped, active directory scans restart from their last position. State files include the full configuration, so no other flags are needed.

State files accumulate in CWD. Clean up after completed scans:
`rm -f ferox-*.state`

### Multi-Target Parallel Scanning

**`--parallel` spawns child processes:**
`cat targets.txt | feroxbuster --stdin --parallel 4 --smart -q --json -o ferox_multi.json`

Each child process is an independent feroxbuster instance scanning one URL. Resources (CPU, memory, network) multiply by the parallelism factor. Each child writes its own state file.

**`--stdin` without `--parallel`** scans URLs sequentially in a single process:
`cat targets.txt | feroxbuster --stdin --smart -q --json -o ferox_serial.json`

**Effective concurrency:**
- `--parallel 4 -t 50 -L 2 --rate-limit 20` = 4 processes × 2 concurrent dirs × 20 req/s = up to 160 req/s global
- Without `--parallel`, `--stdin` scans sequentially: one URL at a time

### Request-File Templating

For targets requiring non-standard request shapes:

```
POST /api/FUZZ HTTP/1.1
Host: target.tld
Content-Type: application/json
Authorization: Bearer eyJ...
X-Request-ID: {{unique_id}}

{"action": "lookup"}
```

`feroxbuster --request-file api_template.txt -w api_endpoints.txt -q --json -o ferox_api.json`

The path in the request line is replaced by wordlist entries. Headers and body remain fixed. This covers scenarios where `-H`, `-b`, and `--data` are insufficient (custom methods, specific header ordering, multi-line bodies).

### POST Content Discovery

**Form-encoded endpoint discovery:**
`feroxbuster -u https://target.tld/admin --data-urlencoded 'action=test&csrf=token' -w admin_actions.txt -q --json -o ferox_form.json`

`--data-urlencoded` automatically sets `Content-Type: application/x-www-form-urlencoded` and `-m POST`. The `@file` syntax reads the body from disk:
`feroxbuster -u https://target.tld/admin --data-urlencoded @post_body.txt -w admin_actions.txt -q --json -o ferox_form.json`

**JSON API endpoint discovery:**
`feroxbuster -u https://target.tld/api --data-json '{"query":"test"}' -w api_paths.txt -q --json -o ferox_json.json`

**Multi-method scanning:**
`feroxbuster -u https://target.tld/api -m GET,POST,PUT,DELETE -w api_paths.txt -q --json -o ferox_methods.json`

### mTLS Scanning

For targets behind mutual TLS:
`feroxbuster -u https://internal.target.tld --client-cert client.pem --client-key client-key.pem --server-certs internal-ca.pem -q --json -o ferox_mtls.json`

- `--client-cert` and `--client-key` present the client certificate to the server
- `--server-certs` adds the internal CA to the trust store (avoids needing `-k`)

### Wildcard Override

Feroxbuster auto-detects wildcard responses and filters them. When this detection is wrong (the target legitimately returns the same response for many valid paths):

1. Disable auto-filter: `-D`
2. Set explicit size/word/line filters to replace it:
   `feroxbuster -u https://target.tld -D -S 1234 -W 50 -q --json -o ferox.json`

The combination `-D -S <known-bad-size>` replaces the heuristic with an exact filter.

### Unique Response Deduplication

`--unique` hashes response bodies and only displays the first occurrence of each unique response:
`feroxbuster -u https://target.tld --unique --smart -q --json -o ferox.json`

Useful on targets that return many identical responses for different paths (e.g. SPA catch-all routes).

### Redirect Following

`-r` follows 3xx redirects. Without it, feroxbuster reports the redirect response itself:
`feroxbuster -u https://target.tld -r --smart -q --json -o ferox.json`

Combine with `-R` to send redirect targets through the replay proxy:
`feroxbuster -u https://target.tld -r -P http://127.0.0.1:8080 -R 200,302 -k -q --json -o ferox.json`

## Tool-to-Tool Chaining

### wafw00f → feroxbuster (rate/evasion decisions)

Fingerprint the WAF before scanning to calibrate rate and evasion:
```
wafw00f -a -f json -o wafw00f.json https://target.tld
```
- Cloudflare/Akamai detected: use `-A --rate-limit 10 -L 1 -t 5 --auto-tune --time-limit 10m`
- ModSecurity detected: add `--filter-similar-to` for the block page, lower rate
- No WAF detected: default `--smart` settings are appropriate

### httpx → feroxbuster (live-host pipeline)

Feed httpx-validated live hosts into feroxbuster:
```
httpx -l hosts.txt -silent -o live.txt
cat live.txt | feroxbuster --stdin --smart --parallel 4 -q --json -o ferox.json
```

### feroxbuster → nuclei (discovered-path scanning)

Feed feroxbuster's discovered URLs into nuclei for vulnerability checks:
```
feroxbuster -u https://target.tld --smart --silent -s 200,301,302 | nuclei -t http/ -silent -o nuclei_results.txt
```

Or from the JSON output:
```
jq -r '.url' ferox.json | sort -u | nuclei -t http/ -silent -o nuclei_results.txt
```

### feroxbuster replay-proxy → Caido (selective inspection)

Route only interesting responses through Caido for manual analysis:
```
feroxbuster -u https://target.tld --smart -P http://127.0.0.1:8080 -R 200,301,302,401,403,500 -k -q --json -o ferox.json
```

Only responses matching `-R` codes flow through Caido. Bulk 404s stay direct, keeping Caido's history clean.

### feroxbuster vs dirsearch — when to use which

| Scenario | Tool |
|---|---|
| Deep recursive discovery on a single app | feroxbuster (`--smart`, `-d 3`) |
| Quick flat scan of known paths | dirsearch (faster startup, simpler) |
| Multi-target parallel scanning | feroxbuster (`--parallel`) |
| Backup file hunting | feroxbuster (`--collect-backups`) |
| Extension discovery from responses | feroxbuster (`--collect-extensions`) |
| Wordlist growth from response content | feroxbuster (`--collect-words`) |
| Scan resume after interruption | feroxbuster (`--resume-from`) |
| Strict status-code/size filtering with known patterns | dirsearch (simpler filter config) |
| POST/JSON endpoint discovery | feroxbuster (`--data-json`, `--data-urlencoded`) |

### naabu → httpx → feroxbuster (full pipeline)

Port discovery → live-host validation → content discovery:
```
naabu -l hosts.txt -top-ports 100 -silent | httpx -silent | feroxbuster --stdin --smart --parallel 4 -q --json -o ferox.json
```

## Usage Rules

- Prefer `--smart` as the automation default; add `--thorough` only for narrowly scoped deep dives.
- `--json -o <file>` is the pipeline-friendly output; `--silent` for raw URL piping.
- Use `--time-limit` on every automation run; recursion otherwise overshoots the budget.
- Pin both `-L` (scan limit) and `--rate-limit` for predictable traffic volume.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

## Failure Recovery

- Scan explodes in request count: lower `-d`, add `--dont-scan "/<noisy>.*"`, use `-n` for a flat first pass.
- All responses look like soft-404: use `--filter-similar-to <known_404_url>` to calibrate; feroxbuster also auto-filters wildcards unless `-D` is set.
- Scan errors spike (resets, 5xx): rely on `--auto-tune` (back off) or `--auto-bail` (stop) rather than manual throttling.
- Resume needed after a crash: look for `ferox-*.state` in CWD and pass `--resume-from`.
- TLS errors against internal targets: add `--server-certs <ca.pem>` or `-k` for untrusted certs.
- mTLS handshake fails: verify `--client-cert` and `--client-key` are PEM-encoded and the key matches the cert.
- `--parallel` child processes OOM: lower parallelism factor, add `--response-size-limit` to cap body reads.
- Wildcard auto-filter removes valid results: use `-D` to disable auto-filtering, then set explicit filters (`-S`, `-W`, `-N`, `-C`).

If uncertain, query web_search with:
`site:epi052.github.io/feroxbuster-docs feroxbuster <flag>` or `site:github.com/epi052/feroxbuster`

## Routed Consumers

- `reconnaissance/*` (same recon surface as dirsearch; feroxbuster shines when recursion depth + Rust throughput matter)
- `tooling/dirsearch.md` (the shared content-discovery workflow lives there)
- `tooling/ffuf.md` (surgical fuzzing of individual input positions — feroxbuster is the broad recursive sweep)
- `tooling/nuclei.md` (discovered paths feed nuclei templates)
- `tooling/httpx.md` (live-host validation upstream of feroxbuster)
- `tooling/wafw00f.md` (WAF fingerprint gates rate/evasion decisions for feroxbuster)
- `tooling/caido.md` (replay-proxy sends interesting responses to Caido for inspection)
