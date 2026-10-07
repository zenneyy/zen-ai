---
name: ffuf
description: ffuf fuzzing syntax with matcher/filter strategy and non-interactive defaults.
---

# ffuf CLI Playbook

Official docs:
- https://github.com/ffuf/ffuf

Canonical syntax:
`ffuf -w <wordlist> -u <url_with_FUZZ> [flags]`

High-signal flags:
- `-u <url>` target URL containing `FUZZ` (or custom keyword)
- `-w <wordlist>` wordlist input (supports keyword mapping: `-w file:KEYWORD`)
- `-mc <codes>` match status codes (default `200-299,301,302,307,401,403,405,500`)
- `-fc <codes>` filter status codes
- `-fs <size>` filter by body size
- `-fl <lines>` filter by line count
- `-fw <words>` filter by word count
- `-fr <regex>` filter by regex
- `-ac` auto-calibration (learn baseline response and filter it)
- `-t <n>` threads (default 40)
- `-rate <n>` requests per second (default 0 = unlimited)
- `-p <delay>` delay between requests; accepts range (`"0.1-2.0"`)
- `-timeout <seconds>` HTTP timeout (default 10)
- `-x <proxy_url>` upstream proxy (HTTP/SOCKS5)
- `-replay-proxy <url>` replay matched requests through a separate proxy
- `-ignore-body` skip downloading response body (header-only fuzzing)
- `-noninteractive` disable interactive console mode
- `-recursion` and `-recursion-depth <n>` recursive directory discovery
- `-recursion-strategy <default|greedy>` recursion trigger (default = redirect-based; greedy = all matches)
- `-H <header>` custom headers (repeatable)
- `-b <cookie>` cookie data (`"NAME1=VALUE1; NAME2=VALUE2"`)
- `-X <method>` HTTP method
- `-d <body>` POST data
- `-enc <spec>` keyword encoding chain (`'FUZZ:urlencode b64encode'`)
- `-mode <mode>` multi-wordlist mode (`clusterbomb`/`pitchfork`/`sniper`; default `clusterbomb`)
- `-request <file>` raw HTTP request file (Burp/Caido export)
- `-raw` do not URI-encode the payload
- `-http2` use HTTP/2
- `-cc <cert>` / `-ck <key>` client certificate authentication
- `-sni <hostname>` TLS SNI override
- `-o <file> -of <format>` structured output (`json`/`ejson`/`md`/`html`/`csv`/`ecsv`/`all`)
- `-od <dir>` store per-match response files
- `-audit-log <file>` full request/response audit log
- `-maxtime <sec>` total run time cap
- `-maxtime-job <sec>` per-job time cap

Agent-safe baseline for automation:
`ffuf -w wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403,405 -ac -t 20 -rate 50 -timeout 10 -noninteractive -of json -o ffuf.json`

Common patterns:
- Basic path fuzzing:
  `ffuf -w /path/wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 40 -rate 200 -noninteractive`
- Vhost fuzzing:
  `ffuf -w vhosts.txt -u https://target.tld -H 'Host: FUZZ.target.tld' -fs 0 -ac -noninteractive`
- Parameter name discovery:
  `ffuf -w params.txt -u 'https://target.tld/api/users?FUZZ=test' -mc all -ac -fs 0 -noninteractive`
- Parameter value fuzzing:
  `ffuf -w values.txt -u 'https://target.tld/search?q=FUZZ' -mc all -fs 0 -ac -t 30 -noninteractive`
- POST body fuzzing (form):
  `ffuf -w payloads.txt -u https://target.tld/login -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=admin&password=FUZZ' -fc 401 -noninteractive`
- POST body fuzzing (JSON):
  `ffuf -w payloads.txt -u https://target.tld/api/query -X POST -H 'Content-Type: application/json' -d '{"search": "FUZZ"}' -fr '"error"' -noninteractive`
- Multi-wordlist credential stuffing (pitchfork):
  `ffuf -w users.txt:USER -w passes.txt:PASS -u https://target.tld/login -X POST -d 'user=USER&pass=PASS' -mode pitchfork -fc 401 -noninteractive`
- Multi-wordlist param+value (clusterbomb):
  `ffuf -w params.txt:PARAM -w values.txt:VAL -u 'https://target.tld/api?PARAM=VAL' -mr 'VAL' -ac -noninteractive`
- Recursive discovery:
  `ffuf -w dirs.txt -u https://target.tld/FUZZ -recursion -recursion-depth 2 -ac -t 30 -noninteractive`
- Proxy-instrumented run (replay hits to Caido):
  `ffuf -w wordlist.txt -u https://target.tld/FUZZ -x http://127.0.0.1:48080 -mc 200,301,302,403 -ac -noninteractive`
- Replay only matched requests through Caido:
  `ffuf -w wordlist.txt -u https://target.tld/FUZZ -ac -replay-proxy http://127.0.0.1:48080 -noninteractive -of json -o ffuf.json`
- From raw request file (Burp/Caido save):
  `ffuf -request saved.txt -request-proto https -w wordlist.txt -noninteractive -of json -o ffuf.json`
- Encoded payload fuzzing (URL + base64):
  `ffuf -w payloads.txt -u 'https://target.tld/load?data=FUZZ' -enc 'FUZZ:b64encode' -mc all -ac -noninteractive`
- Path traversal with raw mode (no URI encoding):
  `ffuf -w traversal.txt -u https://target.tld/file?path=FUZZ -raw -mc 200 -mr 'root:' -noninteractive`
- Extension brute-force (DirSearch compat):
  `ffuf -w wordlist.txt -u https://target.tld/FUZZ -D -e php,asp,aspx,jsp,html,js,json,bak,old -ac -noninteractive`
- Time-bounded fuzzing:
  `ffuf -w large_wordlist.txt -u https://target.tld/FUZZ -ac -maxtime 600 -noninteractive -of json -o ffuf.json`

Critical correctness rules:
- `FUZZ` (or the custom keyword) must appear exactly at the mutation point in URL, header, body, or cookie.
- If using `-w file:KEYWORD`, that same `KEYWORD` must be present in the URL/header/body template.
- Always include `-noninteractive` in agent/script execution to prevent ffuf console mode from swallowing subsequent shell commands.
- Save structured output with `-of json -o <file>` for deterministic parsing.
- `-recursion` only works with the `FUZZ` keyword (not custom keywords), and the URL must end with `FUZZ`.
- Multi-wordlist mode (`-mode`) only applies when two or more `-w` flags with different keywords are used.
- `-raw` disables URI encoding of the FUZZ payload — needed for path traversal and encoding-sensitive payloads, but can break normal fuzzing if the wordlist contains special characters.
- `-replay-proxy` is separate from `-x`: `-x` proxies ALL traffic; `-replay-proxy` replays only MATCHED requests to the proxy. Use `-replay-proxy` to avoid flooding Caido/Burp with every request.
- `-rate 0` (the default) means unlimited — always set an explicit rate in automation.

Usage rules:
- Prefer explicit matcher/filter strategy (`-mc`/`-fc`/`-fs`) over relying on defaults.
- Start conservative (`-rate`, `-t`) and scale only if target tolerance is known.
- Use `-ac` for unknown targets; switch to explicit filters once the baseline is understood.
- Prefer `-replay-proxy` over `-x` when you want Caido/Burp to capture only interesting responses.
- Do not use `-h`/`--help` during normal execution unless absolutely necessary.

Failure recovery:
- If ffuf drops into interactive mode, send `C-c` and rerun with `-noninteractive`.
- If response noise is too high, tighten `-mc/-fc/-fs` or add `-fr` regex instead of increasing load.
- If runtime is too long, lower `-rate/-t`, tighten scope, or add `-maxtime`.
- If auto-calibration over-filters, switch to manual `-fs`/`-fc` based on a baseline response.
- If the target returns different-sized responses per path (dynamic content), use `-ac` or combine `-mc all` with `-fw`/`-fl` instead of `-fs`.
- If encoding breaks payloads, verify `-enc` chain order (applied left-to-right per keyword).
- If recursion explodes, switch from `-recursion-strategy greedy` to `default`, lower `-recursion-depth`, or add `-maxtime`.

If uncertain, query web_search with:
`site:github.com/ffuf/ffuf <flag> README`

---

## Matcher and Filter Engine

ffuf's matcher/filter system is its core differentiator — precise control over what constitutes a "hit" vs. noise. Matchers define what to KEEP; filters define what to DROP. Filters run after matchers.

**Matchers (keep responses matching ANY/ALL of these):**
- `-mc <codes>` — HTTP status codes. Comma-separated, supports ranges. Default: `200-299,301,302,307,401,403,405,500`. Use `-mc all` to match everything and rely on filters.
- `-ml <n>` — response body line count.
- `-mr <regex>` — regex match against response body.
- `-ms <n>` — response body size in bytes.
- `-mt <expr>` — response time in milliseconds. Use `>100` (slower than 100ms) or `<100` (faster). Useful for time-based injection signal.
- `-mw <n>` — response body word count.
- `-mmode <and|or>` — matcher set operator (default `or`). With `or`, any matcher hit keeps the response. With `and`, ALL matchers must hit.

**Filters (drop responses matching ANY/ALL of these):**
- `-fc <codes>` — filter by status code. Comma-separated, supports ranges.
- `-fl <n>` — filter by line count. Comma-separated list and ranges.
- `-fr <regex>` — filter by regex match against response body.
- `-fs <n>` — filter by size. Comma-separated list and ranges.
- `-ft <expr>` — filter by response time (`>100` or `<100`).
- `-fw <n>` — filter by word count. Comma-separated list and ranges.
- `-fmode <and|or>` — filter set operator (default `or`).

**Combining matchers and filters:**

Matchers run first — only matched responses pass to the filter stage. The common workflow:
1. Start broad: `-mc all` (match everything).
2. Send a known-bad request to learn the baseline response size/lines/words.
3. Filter the baseline: `-fs <baseline_size>` or `-fw <baseline_words>`.

Alternatively, use auto-calibration (`-ac`) to automate steps 2–3.

Example — parameter discovery with combined matchers:
```
ffuf -w params.txt -u 'https://target.tld/api?FUZZ=test' -mc all -fw 42 -noninteractive
```

Example — timing-based signal (e.g. blind injection probe):
```
ffuf -w payloads.txt -u 'https://target.tld/api?id=FUZZ' -mc all -mt '>5000' -noninteractive
```

Example — regex match + status code filter:
```
ffuf -w dirs.txt -u https://target.tld/FUZZ -mc all -fc 404 -mr 'admin|config|backup' -noninteractive
```

Example — `and` mode (response must match BOTH size AND status):
```
ffuf -w wordlist.txt -u https://target.tld/FUZZ -mc 200 -ms 1024 -mmode and -noninteractive
```

**Auto-calibration:**

`-ac` sends a few baseline requests (random strings) and automatically sets filters to suppress the default response pattern. Crucial for unknown targets where the baseline size/word count isn't known in advance.

- `-ac` — basic auto-calibration. Learns one baseline.
- `-acc <string>` — provide a custom calibration string (repeatable). Implies `-ac`. Use when the target treats specific strings differently (e.g. returns a different page for alphanumeric vs. special characters).
- `-ach` — per-host auto-calibration. When fuzzing across multiple hosts (via multi-wordlist or vhost), calibrate independently per host. Essential for vhost fuzzing where different virtual hosts have different baseline sizes.
- `-ack <keyword>` — which keyword to use for calibration requests (default `FUZZ`). Change when the mutation point is a custom keyword.
- `-acs <strategy>` — custom calibration strategy (repeatable). Implies `-ac`. Controls how the baseline is generated (e.g. different string lengths, character classes).

Auto-calibration is a heuristic — it works well on targets with a single consistent "not found" response. It can over-filter on targets that vary responses based on path structure. In those cases, switch to manual filters.

---

## Multi-Wordlist Modes

When using two or more `-w` flags with different keywords, `-mode` controls how entries are combined:

**Clusterbomb (default):** Cartesian product — every combination of every wordlist entry. If wordlist A has 100 entries and B has 50, clusterbomb sends 5000 requests. Use for exhaustive combination testing.
```
ffuf -w users.txt:USER -w roles.txt:ROLE \
  -u 'https://target.tld/api/users/USER/role/ROLE' -mc 200 -noninteractive
```

**Pitchfork:** Parallel iteration — entry 1 from A with entry 1 from B, entry 2 with entry 2, etc. Stops when the shorter list runs out. Use for correlated pairs (e.g. username:password lists, endpoint:method pairs).
```
ffuf -w users.txt:USER -w passwords.txt:PASS \
  -u https://target.tld/login -X POST -d 'user=USER&pass=PASS' \
  -mode pitchfork -fc 401 -noninteractive
```

**Sniper:** Tests one position at a time — inserts the wordlist entry into each keyword position while keeping others at their first value. Use for single-position isolation across multiple injection points.
```
ffuf -w payloads.txt:FUZZ -w payloads.txt:FUZZ2 \
  -u 'https://target.tld/api?param1=FUZZ&param2=FUZZ2' \
  -mode sniper -mc all -ac -noninteractive
```

The `FUZZ` keyword can appear anywhere in the request:
- URL path: `-u https://target.tld/FUZZ`
- Query parameter value: `-u 'https://target.tld/api?id=FUZZ'`
- Query parameter name: `-u 'https://target.tld/api?FUZZ=test'`
- Header value: `-H 'Authorization: Bearer FUZZ'`
- Header name: `-H 'FUZZ: value'`
- Cookie: `-b 'session=FUZZ'`
- POST body: `-d 'param=FUZZ'`
- Host header (vhost): `-H 'Host: FUZZ.target.tld'`

---

## Input Sources and Encoding

**Wordlists:**

`-w <path>` is the primary input. For custom keywords: `-w /path/to/wordlist.txt:MYKEYWORD`. Multiple `-w` flags with different keywords activate multi-wordlist modes.

`-ic` ignores lines starting with `#` in wordlists (comments). Use when wordlists have header comments.

**DirSearch compatibility:**

`-D -e php,html,js,json` enables DirSearch wordlist compatibility — each wordlist entry is tested with each extension appended. This is equivalent to DirSearch's behavior where `admin` becomes `admin.php`, `admin.html`, `admin.js`, `admin.json`. The `FUZZ` keyword is automatically extended.
```
ffuf -w common.txt -u https://target.tld/FUZZ -D -e php,asp,aspx,jsp,bak,old -ac -noninteractive
```

**Encoding chains:**

`-enc 'KEYWORD:encoder1 encoder2'` applies encoders to a keyword's value before insertion. Encoders are applied left-to-right (chain order matters):
```
ffuf -w payloads.txt -u 'https://target.tld/api?data=FUZZ' -enc 'FUZZ:urlencode' -mc all -ac -noninteractive
ffuf -w payloads.txt -u 'https://target.tld/api?data=FUZZ' -enc 'FUZZ:b64encode' -mc all -ac -noninteractive
ffuf -w payloads.txt -u 'https://target.tld/api?data=FUZZ' -enc 'FUZZ:urlencode b64encode' -mc all -ac -noninteractive
```
The last example first URL-encodes, then base64-encodes. Chain order matters — `urlencode b64encode` produces different payloads than `b64encode urlencode`.

**Raw HTTP request input:**

`-request <file>` reads a full HTTP request from a file (as saved from Caido's "Copy as raw request" or Burp's "Copy to file"). Place the `FUZZ` keyword in the saved request at the injection point. Use `-request-proto <http|https>` to set the protocol (default `https`).
```
ffuf -request saved_request.txt -request-proto https -w wordlist.txt -noninteractive -of json -o ffuf.json
```
This is the most reliable input for fuzzing complex requests with custom headers, cookies, multipart bodies, or non-standard methods — the entire request structure is preserved from the proxy capture.

**Custom input generators:**

`-input-cmd <command>` replaces the wordlist with a command that produces input on stdout. Requires `-input-num <n>` to set how many times to call the command. `-input-shell <shell>` overrides the execution shell.
```
ffuf -input-cmd 'seq 1 10000' -input-num 10000 -u 'https://target.tld/api/users/FUZZ' -mc 200 -noninteractive
ffuf -input-cmd 'python3 -c "import random,string; print(\"\".join(random.choices(string.ascii_lowercase, k=8)))"' \
  -input-num 500 -u 'https://target.tld/reset?token=FUZZ' -mc 200 -noninteractive
```

---

## Recursion

`-recursion` enables recursive directory discovery: when a directory is found, ffuf queues the discovered path as a new base and re-runs the wordlist under it.

- `-recursion-depth <n>` — maximum recursion depth (default 0 = unlimited). Set this explicitly to prevent unbounded recursion.
- `-recursion-strategy <default|greedy>` — what triggers recursion:
  - `default` — recursion follows redirect responses (3xx) to discover nested paths. The redirect target becomes the new base.
  - `greedy` — recursion triggers on ALL matched responses, not just redirects. This discovers more structure but can explode request count on large sites.

Constraints:
- Only the `FUZZ` keyword is supported for recursion (not custom keywords).
- The URL (`-u`) must end with `FUZZ` (e.g. `-u https://target.tld/FUZZ`).
- Combine with `-maxtime` to bound total runtime when recursion depth is uncertain.

```
ffuf -w dirs.txt -u https://target.tld/FUZZ -recursion -recursion-depth 3 \
  -recursion-strategy default -ac -t 20 -rate 50 -maxtime 600 -noninteractive -of json -o ffuf_recursive.json
```

Greedy recursion with tight controls:
```
ffuf -w dirs.txt -u https://target.tld/FUZZ -recursion -recursion-depth 2 \
  -recursion-strategy greedy -mc 200,301,302,403 -t 10 -rate 30 -maxtime 300 -noninteractive
```

---

## Rate Control and Stability

**Throughput controls:**
- `-t <n>` — concurrent threads (default 40). Controls parallelism, not request rate directly.
- `-rate <n>` — requests per second cap (default 0 = unlimited). This is the primary rate limiter. With `-rate 50 -t 40`, ffuf uses up to 40 threads but caps at 50 req/sec.
- `-p <delay>` — delay between requests in seconds. Accepts exact values (`"0.5"`) or ranges for randomized delay (`"0.1-2.0"`). A random range makes traffic less fingerprint-able. `-p` and `-rate` interact — the stricter constraint wins.
- `-timeout <sec>` — HTTP request timeout (default 10). Lower for fast targets; raise for slow/distant ones.

**Time limits:**
- `-maxtime <sec>` — total maximum running time for the entire process. The run stops after this many seconds regardless of progress. Essential for automation.
- `-maxtime-job <sec>` — maximum time per job (relevant with recursion, where each discovered directory spawns a new job).

**Stop conditions:**
- `-sf` — stop when >95% of responses return 403 Forbidden. Indicates a WAF/rate-limiter is blocking. Triggers automatic halt to avoid wasting time.
- `-se` — stop on spurious errors (connection failures, timeouts). Indicates transport instability.
- `-sa` — stop on ALL error cases (implies both `-sf` and `-se`).

**Tuning relationship:**
- Start with `-rate 50 -t 20` for unknown targets.
- If the target handles it well (low error rate, consistent response times), scale up: `-rate 200 -t 50`.
- If you see 403 spikes or connection resets, back off: `-rate 20 -t 10 -p "0.5-1.5"`.
- `-sf` is a useful safety net but not a substitute for choosing a reasonable starting rate.

---

## Replay and Audit

**Replay proxy (`-replay-proxy`):**

The key workflow for combining ffuf's speed with Caido/Burp's manual analysis:

1. Run ffuf at full speed against the target (optionally through `-x` proxy for all traffic, but this is noisy).
2. Use `-replay-proxy http://127.0.0.1:48080` — ffuf re-sends only MATCHED requests through the replay proxy.
3. Caido/Burp receives only the interesting responses, ready for manual inspection, intruder replay, or further testing.

```
ffuf -w wordlist.txt -u https://target.tld/FUZZ -ac \
  -replay-proxy http://127.0.0.1:48080 \
  -noninteractive -of json -o ffuf.json
```

`-replay-proxy` is separate from `-x`: `-x` routes ALL fuzzing traffic through the proxy (useful for visibility but floods the proxy history). `-replay-proxy` only sends hits. In most workflows, prefer `-replay-proxy` and leave `-x` unset so ffuf talks directly to the target at full speed.

**Audit log (`-audit-log`):**

`-audit-log <file>` writes every request AND response (all of them, not just matches) to a log file. This captures the full traffic history for post-hoc analysis, evidence preservation, or debugging false negatives.

```
ffuf -w wordlist.txt -u https://target.tld/FUZZ -ac \
  -audit-log ffuf_audit.log -noninteractive -of json -o ffuf.json
```

The audit log can grow large on big wordlists. Use it selectively for targeted fuzzing runs, not broad sweeps.

**Debug log (`-debug-log`):**

`-debug-log <file>` captures ffuf's internal state transitions, calibration decisions, and error handling. Useful for diagnosing why auto-calibration over-filters or why matches are missed.

---

## Output Formats and Post-Processing

**Output flags:**
- `-o <file>` — write matched results to file.
- `-of <format>` — output format (default `json`). Available: `json`, `ejson` (extended JSON with request/response), `md` (Markdown table), `html`, `csv`, `ecsv` (extended CSV with request/response), `all` (all formats at once).
- `-od <dir>` — store each matched response as a separate file in this directory. Useful when downstream tools need individual response bodies (e.g. for JS analysis, grepping, content extraction).
- `-or` — don't create the output file if there are no results. Avoids empty output files cluttering the workspace.
- `-json` — JSONL output to stdout (independent of `-o/-of`). Each matched result is a JSON line. Use for piping: `ffuf ... -json -s | jq '.url'`.
- `-s` — silent mode; suppresses the banner and progress output, printing only results. Combine with `-json` for pipe-friendly output.
- `-v` — verbose output; prints the full URL and redirect location (if any) with each result. Useful for seeing where 3xx responses point.

**JSON output structure:**

The JSON output (`-of json`) produces an object with `results` array. Each entry contains: `input` (the wordlist entry), `position` (entry number), `status` (HTTP code), `length` (body bytes), `words`, `lines`, `content-type`, `redirectlocation`, `resultfile` (if `-od` set), `url`, `host`, and `duration` (nanoseconds).

Parse with `jq`:
```
jq -r '.results[] | "\(.status) \(.length) \(.url)"' ffuf.json
jq -r '.results[] | select(.status == 200) | .url' ffuf.json
```

**FFUFHASH history:**

`-search <hash>` looks up a payload from ffuf's run history by its FFUFHASH. This allows replaying or inspecting a specific payload from a previous run without re-running the entire wordlist.

---

## Scrapers

ffuf can extract additional information from responses during fuzzing using scrapers — regex-based extractors that parse response bodies for URLs, email addresses, comments, and other artifacts.

- `-scrapers <groups>` — activate specific scraper groups (default `all`). Built-in groups extract links, comments, forms, and other artifacts from HTML responses.
- `-scraperfile <file>` — custom scraper definition file. Define regex-based extractors for domain-specific content (API keys, tokens, internal URLs, etc.).

Scraped results appear in the output alongside match data. Use scrapers to passively collect intelligence from every response during path discovery — endpoints, internal paths, email addresses, and comments that inform further testing.

---

## Detection Fingerprint

How ffuf traffic looks to defenders:

**Default User-Agent:** ffuf sends `Fuzz Faster U Fool v2.1.0-dev` (or similar version string) by default. Override with `-H 'User-Agent: Mozilla/5.0 ...'` — the default UA is a trivial signature.

**Traffic pattern:** Sequential requests to the same URL path with varying path segments/parameters. The pattern is distinctive — hundreds or thousands of requests to the same base URL with only the fuzzing position changing, at a consistent rate. Rate-based IDS/WAF rules catch this readily.

**Timing:** With default settings (`-rate 0 -t 40`), ffuf sends bursts of 40 concurrent requests with no delay — very high request rate that triggers rate limiting on most production WAFs. With `-rate` and `-p`, traffic becomes more regular but the sequential mutation pattern remains visible.

**Response consumption:** Without `-ignore-body`, ffuf downloads the full response body for every request. With `-ignore-body`, only headers are fetched — visible as aborted connections in server logs.

**TLS fingerprint:** Go's default TLS stack has a distinctive JA3 fingerprint. `-http2` changes the fingerprint but doesn't impersonate a real browser. Use `-sni` to set a custom SNI hostname if the target filters by SNI mismatch.

---

## Bypass and Evasion

**Reducing the fingerprint — these are situational, not guarantees:**

Rate and timing:
- `-rate <n>` with conservative values (10–30 req/sec) avoids rate-based triggers.
- `-p "0.5-2.0"` randomizes inter-request delay, breaking the regular timing pattern. More effective than `-p "1.0"` (constant delay) against statistical rate detectors.
- `-t` lower than default (5–10 threads) reduces burst characteristics.

Identity:
- `-H 'User-Agent: <real_browser_UA>'` replaces the ffuf default UA. Essential; the default is an immediate giveaway.
- `-b <cookie>` carries session cookies for authenticated fuzzing behind login.
- `-H 'Referer: https://target.tld/'` sets a plausible referrer.
- `-cc/-ck` provides client TLS certificates where required.

Transport:
- `-x <proxy>` routes through a proxy (rotate proxies externally for source-IP diversity).
- `-http2` uses HTTP/2, changing the connection profile and allowing multiplexed requests.
- `-sni <hostname>` overrides TLS SNI.
- `-raw` disables URI encoding — necessary for path traversal payloads (`../`) that would otherwise be encoded to `%2e%2e%2f` and normalized away by the server. Also useful for testing servers that handle encoded vs. unencoded differently.

Calibration:
- `-ac` establishes a legitimate-looking baseline before fuzzing, reducing false positives that might otherwise cause the operator to run additional noisy requests.

**What these do NOT evade:** Application-layer WAFs that inspect request content (payload patterns), ML-based anomaly detectors that flag unusual parameter values, and logging that captures the full request regardless of rate.

---

## Virtual Host Discovery

ffuf is the primary tool for virtual host (vhost) and subdomain enumeration via Host header fuzzing. The technique discovers hosts that share an IP but respond differently based on the Host header — revealing staging environments, internal apps, admin panels, and API backends not exposed in DNS.

**Basic vhost fuzzing:**
```
ffuf -w subdomains.txt -u https://TARGET_IP -H 'Host: FUZZ.target.tld' \
  -fs 0 -ac -noninteractive -of json -o vhosts.json
```

Key considerations:
- Target the IP address or a known-good hostname in `-u`, not a hostname you're discovering. The Host header carries the mutation.
- `-fs 0` filters empty responses (common when the server doesn't recognize the Host header).
- `-ac` with `-ach` is critical: without per-host calibration, the default response for unknown vhosts becomes the baseline, and all real vhosts get filtered as matching it.

**Per-host calibration (`-ach`):**
```
ffuf -w subdomains.txt -u https://TARGET_IP -H 'Host: FUZZ.target.tld' \
  -ac -ach -noninteractive -of json -o vhosts.json
```
`-ach` calibrates separately per resolved host. Essential when the target IP serves multiple web servers (e.g. behind a reverse proxy) that each have different default responses.

**Vhost fuzzing against multiple IPs:**
When a domain has multiple A records (CDN, load balancer), fuzz each IP separately:
```
for ip in $(dig +short target.tld A); do
  ffuf -w subdomains.txt -u "https://$ip" -H 'Host: FUZZ.target.tld' \
    -ac -ach -fs 0 -noninteractive -of json -o "vhosts_${ip}.json"
done
```

**HTTPS with SNI:**
When fuzzing HTTPS vhosts, the TLS handshake needs the correct SNI. If the target expects SNI matching:
```
ffuf -w subdomains.txt -u https://TARGET_IP -H 'Host: FUZZ.target.tld' \
  -sni FUZZ.target.tld -ac -ach -noninteractive
```
Note: `-sni` does NOT support the `FUZZ` keyword — use it only when the target requires a fixed SNI that differs from the URL hostname (e.g. testing behind a CDN where SNI must match the CDN certificate).

**Distinguishing real vhosts from wildcards:**
Some servers return a valid-looking page for ANY subdomain (wildcard DNS or default vhost). `-ac` handles this when the wildcard response is consistent. If the wildcard response varies slightly (dynamic content, timestamps), combine matchers:
```
ffuf -w subdomains.txt -u https://TARGET_IP -H 'Host: FUZZ.target.tld' \
  -mc all -fw 1234 -fl 50 -fmode and -noninteractive
```
Where 1234/50 are the wildcard response's word/line counts (obtained from a baseline request with a known-invalid subdomain).

---

## Content Discovery Patterns

ffuf excels at targeted content discovery beyond basic directory brute-force. These patterns cover common reconnaissance objectives.

**Backup and configuration file discovery:**
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://target.tld/FUZZ -D \
  -e bak,old,swp,save,orig,backup,conf,config,cfg,ini,env,log,sql,db,tar.gz,zip \
  -mc 200,403 -ac -noninteractive -of json -o backups.json
```

**Hidden API version discovery:**
```
ffuf -w versions.txt -u 'https://target.tld/api/FUZZ/users' \
  -mc 200,301,302,401,403 -ac -noninteractive
```
Where `versions.txt` contains: `v1`, `v2`, `v3`, `v4`, `v5`, `v0`, `beta`, `alpha`, `internal`, `staging`, `dev`, `legacy`, `deprecated`, `private`, etc.

**Admin panel / management interface discovery:**
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
  -u https://target.tld/FUZZ -mc 200,301,302,401,403 -ac -noninteractive -of json -o admin.json
```

**Technology-specific paths (e.g. Spring Boot Actuator, Laravel debug):**
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt \
  -u https://target.tld/FUZZ -mc 200 -ac -noninteractive
```

**File upload destination probing:**
```
ffuf -w filenames.txt -u https://target.tld/uploads/FUZZ \
  -mc 200,403 -fs 0 -noninteractive -od upload_responses/
```
Use `-od` to save response bodies — check whether returned files are served directly (executable), with content-type sniffing, or behind access controls.

**Extension brute-force on a known stem:**
When you know a file exists at `/app/config` but not its extension:
```
ffuf -w extensions.txt -u https://target.tld/app/config.FUZZ \
  -mc 200 -ac -noninteractive
```
Where `extensions.txt` contains: `json`, `yaml`, `yml`, `xml`, `toml`, `ini`, `conf`, `cfg`, `env`, `bak`, `old`, `txt`, `md`, `properties`, `php`, `py`, `rb`, `js`, `ts`, etc.

**HTTP method fuzzing:**
Discover non-standard methods that return different responses (PUT, DELETE, PATCH, OPTIONS, TRACE, CONNECT, PROPFIND, MKCOL):
```
ffuf -w methods.txt -u https://target.tld/api/resource -X FUZZ \
  -mc all -ac -noninteractive
```
Combine with per-endpoint discovery to find method-based authorization bypasses (e.g. GET blocked but PUT allowed).

**Numeric ID enumeration (IDOR probing):**
```
ffuf -input-cmd 'seq 1 10000' -input-num 10000 \
  -u 'https://target.tld/api/users/FUZZ/profile' \
  -mc 200 -ac -t 20 -rate 50 -noninteractive -of json -o idor.json
```

**Wordlist-less fuzzing with input-cmd (UUID brute — impractical but illustrative):**
```
ffuf -input-cmd 'python3 -c "import uuid; print(uuid.uuid4())"' \
  -input-num 10000 -u 'https://target.tld/api/docs/FUZZ' \
  -mc 200 -t 10 -rate 20 -noninteractive
```

---

## API and Parameter Fuzzing

ffuf's ability to fuzz arbitrary request positions makes it the tool of choice for API surface discovery beyond what crawlers find.

**REST endpoint path discovery:**
```
ffuf -w endpoints.txt -u https://target.tld/api/v1/FUZZ \
  -mc 200,201,204,301,302,401,403,405 -ac -noninteractive -of json -o api_endpoints.json
```
Status 405 (Method Not Allowed) confirms the endpoint exists but needs a different HTTP method — follow up with method fuzzing.

**Parameter name discovery:**
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u 'https://target.tld/api/search?FUZZ=test' -mc all -ac -fs 0 -noninteractive
```
Compare response size/words against the no-parameter baseline. A parameter that changes the response is valid.

**POST parameter discovery (JSON body):**
```
ffuf -w params.txt -u https://target.tld/api/update -X POST \
  -H 'Content-Type: application/json' \
  -d '{"FUZZ": "test"}' -mc all -ac -noninteractive
```

**POST parameter discovery (form body):**
```
ffuf -w params.txt -u https://target.tld/api/update -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'FUZZ=test' -mc all -ac -noninteractive
```

**Header-based fuzzing (security header bypass, custom header discovery):**
```
ffuf -w headers.txt -u https://target.tld/admin \
  -H 'FUZZ: 127.0.0.1' -mc 200 -noninteractive
```
Where `headers.txt` contains: `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Forwarded-Host`, `X-Custom-IP-Authorization`, `True-Client-IP`, etc. Discovers IP-based access control bypasses.

**Authenticated API fuzzing (session token):**
```
ffuf -w endpoints.txt -u https://target.tld/api/FUZZ \
  -H 'Authorization: Bearer <token>' \
  -b 'session=<cookie>' \
  -mc 200,201,204,403 -ac -noninteractive -of json -o authed_api.json
```

**GraphQL introspection alternative — field discovery:**
When introspection is disabled, fuzz field names:
```
ffuf -w fieldnames.txt -u https://target.tld/graphql -X POST \
  -H 'Content-Type: application/json' \
  -d '{"query": "{ FUZZ { id } }"}' \
  -mc all -fr '"errors"' -noninteractive
```
Responses without `"errors"` indicate a valid field name.

**Mass assignment probing:**
Discover writable fields by fuzzing JSON body keys against a known-good update endpoint:
```
ffuf -w fields.txt -u https://target.tld/api/profile -X PUT \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' \
  -d '{"FUZZ": "test"}' -mc 200 -ac -noninteractive -of json -o mass_assign.json
```
Fields that return 200 (accepted) may be writable without authorization — check for `role`, `admin`, `is_admin`, `permissions`, `group`, `email_verified`, etc.

**Rate-limited endpoint probing:**
For APIs with tight rate limits, use delay and low thread count:
```
ffuf -w wordlist.txt -u 'https://target.tld/api/FUZZ' \
  -H 'Authorization: Bearer <token>' \
  -mc 200,201,401,403,405,429 -t 5 -rate 10 -p "1.0-3.0" \
  -sf -noninteractive -of json -o api_slow.json
```
`-sf` stops if the API starts returning 403 across the board (rate limit block). Match 429 to detect when throttling kicks in without stopping the scan.

---

## Configuration Files

`-config <file>` loads ffuf options from a TOML-format configuration file. Use for reproducible, shareable fuzzing profiles.

Example config file (`ffuf.toml`):
```toml
[http]
    url = "https://target.tld/FUZZ"
    method = "GET"
    timeout = 10
    headers = [
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept: text/html"
    ]

[general]
    threads = 20
    rate = 50
    noninteractive = true
    colors = false

[input]
    wordlists = ["/usr/share/seclists/Discovery/Web-Content/common.txt"]

[output]
    outputfile = "ffuf_results.json"
    outputformat = "json"

[matcher]
    status = "200,204,301,302,307,401,403"
    mode = "or"

[filter]
    mode = "or"
```

Run with: `ffuf -config ffuf.toml`

Config file options can be overridden by command-line flags — CLI flags take precedence. Use config files for team-standard profiles (rate limits, proxy settings, output formats) while allowing per-run target and wordlist overrides.

---

## Chaining and Routing

**Inbound chains (tools that feed ffuf):**
- `katana`/`gospider` → ffuf: crawled endpoints as a target list. `katana -u <url> -f url | sort -u > endpoints.txt`, then fuzz discovered endpoints.
- `arjun` → ffuf: discovered parameter names. Arjun finds valid parameters; ffuf fuzzes their values.
- `httpx` → ffuf: live hosts as targets. `httpx -l hosts.txt -silent | while read url; do ffuf -w wordlist.txt -u "$url/FUZZ" ...; done`
- `dirsearch` → ffuf: dirsearch for initial broad sweep; ffuf for surgical follow-up on interesting paths with custom filters.

**Outbound chains (ffuf feeds these tools):**
- ffuf → `sqlmap`: discovered injection candidates. `jq -r '.results[] | .url' ffuf.json | sort -u > targets.txt`, then test with sqlmap.
- ffuf → `nuclei`: discovered paths/endpoints. Run nuclei templates against ffuf-discovered URLs.
- ffuf → Caido/Burp: via `-replay-proxy`, matched requests land in the proxy for manual analysis, intruder replay, and session manipulation.
- ffuf → content analysis: `-od <dir>` saves per-match response bodies for grepping, JS analysis, or sensitive data extraction.

**Positioning vs. `dirsearch`:**
- `dirsearch` — quick broad sweep with curated built-in wordlists, sane defaults, extension handling, and report output. Lower setup cost for standard directory/file enumeration.
- `ffuf` — surgical fuzzing of ANY input position (URL path, header, cookie, body, parameter name, parameter value) with precise matcher/filter control, multi-wordlist modes, encoding chains, and replay proxy integration. Higher setup cost but more powerful for targeted fuzzing.

Use dirsearch for the first-pass "what's here" sweep; use ffuf when you need to fuzz a specific position with specific filters, or when fuzzing headers/bodies/parameters (which dirsearch doesn't do).

**Routed vulnerability skills:**
- `vulnerabilities/path_traversal_lfi_rfi.md` — path fuzzing (`../` payloads with `-raw`)
- `vulnerabilities/idor.md` — parameter value fuzzing (numeric IDs, UUIDs)
- `vulnerabilities/authentication_jwt.md` — auth bypass fuzzing (token values)
- `vulnerabilities/information_disclosure.md` — hidden endpoint/file discovery
- `vulnerabilities/broken_function_level_authorization.md` — HTTP method fuzzing (`-X FUZZ`)
- `vulnerabilities/xss.md` — reflected XSS payload fuzzing with `-mr` for reflection detection
- `vulnerabilities/open_redirect.md` — redirect parameter value fuzzing
- `tooling/dirsearch.md` — alternate path enumeration tool (broader wordlists, simpler setup)
- `tooling/arjun.md` — parameter discovery (feeds ffuf for value fuzzing)
- `tooling/caido.md` — proxy integration via `-x` and `-replay-proxy`
- `tooling/katana.md` — crawl → fuzz pipeline
