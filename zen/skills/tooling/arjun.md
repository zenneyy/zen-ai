---
name: arjun
description: Arjun HTTP parameter-discovery syntax, method/body modes, and passive-source enumeration for feeding injection testing.
---

# Arjun CLI Playbook

Official docs:
- https://github.com/s0md3v/Arjun
- https://github.com/s0md3v/Arjun/wiki

Canonical syntax:
`arjun -u <url> [options]`

## Complete Flag Reference (verified against sandbox image)

INPUT:
- `-u <url>` target URL (required unless `-i`)
- `-i [file]` import target URLs from file (one per line)

METHOD:
- `-m <GET|POST|XML|JSON>` request method and body shape (default `GET`)

OUTPUT:
- `-o, -oJ <file>` JSON output path (structured per-URL results)
- `-oT <file>` text output (param names only, no confidence/method)
- `-oB [host:port]` mirror discovery traffic to Burp/Caido proxy (default `127.0.0.1:8080` if omitted)
- `-q` quiet mode (suppress all console output)

WORDLIST:
- `-w <file>` wordlist path (default `{arjun_dir}/db/large.txt`)
- `--casing <like_this|likeThis|likethis>` normalize wordlist casing before probing

DISCOVERY TUNING:
- `-c <n>` chunk size — parameters per probe request
- `--passive [domain]` seed param names from Wayback/CommonCrawl/OTX before active probing
- `--include <data>` extra data appended to every request (fixed params, CSRF tokens, routing state)
- `--stable` prefer stability over speed (smaller chunks, more retries, slower but more reliable)
- `--disable-redirects` do not follow 3xx responses

RATE/TIMING:
- `-t <n>` concurrent threads (default 5)
- `-d <sec>` delay between requests in seconds (default 0)
- `-T <sec>` HTTP request timeout (default 15)
- `--rate-limit <n>` max requests per second (default 9999)

HEADERS:
- `--headers [file]` custom headers (newline-separated); flag alone reads a default headers file

## Agent-Safe Baseline

`arjun -u https://target.tld/api/v1/user -m GET -c 25 -t 10 --rate-limit 50 -T 10 --stable -oJ arjun.json`

## Common Patterns

Baseline GET parameter discovery:
`arjun -u https://target.tld/search -oJ arjun_search.json`

POST form parameter discovery:
`arjun -u https://target.tld/login -m POST -oJ arjun_login.json`

JSON API body-parameter discovery:
`arjun -u https://target.tld/api/v1/items -m JSON -oJ arjun_items.json`

XML body-parameter discovery:
`arjun -u https://target.tld/api/soap -m XML -oJ arjun_soap.json`

Multi-target batch with text output for grep chaining:
`arjun -i urls.txt --stable --rate-limit 30 -oT arjun_params.txt`

Discovery mirrored through Caido (live inspection):
`arjun -u https://target.tld/api/v1/user -oB 127.0.0.1:8080 -oJ arjun.json`

Passive seeding before active probing:
`arjun -u https://target.tld/search --passive target.tld -c 50 --stable -oJ arjun_passive.json`

Carry a required param on every probe (CSRF token, session state):
`arjun -u https://target.tld/profile -m POST --include "csrf=TOKEN&user_id=1" -oJ arjun_profile.json`

Custom wordlist with casing normalization:
`arjun -u https://target.tld/api/v2/data -w custom_params.txt --casing likeThis -oJ arjun_camel.json`

Passive-only enumeration (no active probing):
`arjun -u https://target.tld/search --passive target.tld -oJ arjun_passive_only.json`

## Critical Correctness Rules

- `-m` must match the endpoint's accepted method or every probe returns identically and the heuristic collapses — verify with one `curl` first.
- `--include` is the mechanism for required state (session cookie, CSRF, routing params); without it, probes on authenticated/stateful endpoints return the same error for every param and nothing is discovered.
- `-c` interacts with WAFs and reflection detection — too large hides boundary responses, too small is slow. Default `-c 25` is a sane start; raise only when the target is tolerant.
- `--passive` reaches external sources (Wayback, CommonCrawl, OTX) directly; the Caido proxy env catches it, but expect several minutes of outbound traffic.
- `--casing` only normalizes the wordlist, not the server response — if the target rejects canonicalized param names, strip `--casing`.
- Output: `-oJ` emits a structured JSON object per URL; `-oT` is name-only and loses method/confidence. Prefer `-oJ` for downstream chaining.
- `-oB` sends discovery traffic through a proxy regardless of other output flags — use it alongside `-oJ` for both structured output and live Caido inspection.

## Usage Rules

- Chain into injection testing: feed discovered names to `sqlmap -p "<p1>,<p2>"`, `ffuf` value fuzzing, or targeted XSS payloads.
- Keep `--stable` on in automation; the default is tuned for interactive runs.
- Use `--rate-limit` and `-t` together for predictable throughput; both default very high.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

## Failure Recovery

- Zero params found on an endpoint you know takes params: verify `-m`, add `--include` for required state, and re-run with `--stable` and smaller `-c`.
- All requests fail with timeouts: raise `-T`, lower `-t`, add `-d 1`.
- Rate limited (429s): lower `--rate-limit`, raise `-d`, add `--headers` with a plausible UA.
- Discovery too slow: drop `--passive`, raise `-t` and `-c` on a tolerant target.

---

## Methodology

### Endpoint Assessment

Before running arjun, determine the correct `-m` for each endpoint:

1. Send a baseline request with `curl -v` or `httpx` to confirm the endpoint responds and which methods it accepts.
2. Check `Allow` header from an `OPTIONS` request when available.
3. If the endpoint serves HTML forms, inspect `<form method="...">` and `<input name="...">` for known params (these go into `--include`).
4. For APIs, check `Content-Type` in responses — `application/json` → `-m JSON`, `application/xml`/`text/xml` → `-m XML`, `application/x-www-form-urlencoded` → `-m POST`.
5. Wrong method selection is the most common cause of zero-result runs — arjun cannot self-correct because every probe returns the same method-error response.

### Chunking Strategy

Arjun's core detection heuristic operates in phases:

**Phase 1 — Baseline capture.** Arjun sends a request with no extra parameters and records the response (body length, status code, content hash). This baseline is the "clean" response against which all subsequent probes are compared.

**Phase 2 — Chunk probing.** The wordlist is split into chunks of `-c` parameters each. Each chunk is sent as a single request with all chunk parameters included:
- GET: parameters appended as query string (`?p1=arjun&p2=arjun&...`)
- POST: parameters in form-encoded body
- JSON: parameters as JSON object keys
- XML: parameters as XML elements

If a chunk's response differs from baseline (content-length change, status code change, body hash change, reflection of a parameter value), that chunk is flagged as "interesting."

**Phase 3 — Narrowing.** Interesting chunks are bisected — split in half and re-probed — until individual parameters that cause response changes are isolated.

**Phase 4 — Confirmation.** Each candidate parameter is sent alone to confirm it genuinely changes the response. This eliminates false positives from parameter interactions within a chunk.

Chunk size implications:
- Larger chunks (`-c 50-100`): fewer requests, faster, but WAFs may block param-stuffed requests, and interacting parameters can mask each other during narrowing.
- Smaller chunks (`-c 10-15`): more requests, slower, but cleaner isolation and less likely to trigger WAF param-count limits.
- Default (`-c 25`): balanced trade-off. Start here; adjust based on target behavior.

### Passive Seeding Workflow

`--passive [domain]` queries three external sources before active probing:

1. **Wayback Machine** — historical parameter names from archived URLs. High coverage for established sites; misses parameters added after the last archive snapshot.
2. **CommonCrawl** — similar to Wayback but from Common Crawl's independent corpus. Overlaps with Wayback but occasionally surfaces unique params from crawl-specific paths.
3. **OTX (AlienVault)** — threat-intelligence URL corpus. Lower coverage but may surface parameters from exploit/scan reports not in web archives.

Passive results seed the active wordlist — arjun adds discovered names to the probe queue alongside the standard wordlist. This is most valuable when:
- The target is a mature application with years of web history.
- The built-in wordlist misses domain-specific parameter names (custom API fields, legacy params).
- Active probing is budget-constrained (limited request count) and passive pre-filtering prioritizes likely hits.

Passive-then-active pattern:
`arjun -u https://target.tld/search --passive target.tld -c 25 --stable -oJ arjun.json`

Passive-only (no active probing — useful for recon without touching the target):
`arjun -u https://target.tld/search --passive target.tld -oJ arjun_passive.json`
Note: passive-only still records the target URL for context but the discovered names come from external sources, not from probing the target.

### Multi-Target Batch Processing

`-i <file>` reads URLs one per line and runs discovery against each sequentially:

- Each URL gets its own baseline, chunk cycle, and narrowing pass.
- `-m` applies to all URLs in the batch — if endpoints differ in method, split into separate runs per method.
- `-oJ` writes a single JSON file with per-URL results; `-oT` appends all discovered names (loses per-URL attribution).
- `--stable` is especially important for batch runs — intermittent failures on one URL do not poison the remaining queue.
- Rate limiting (`--rate-limit`, `-d`) applies globally, not per-URL.

Batch from crawled URLs:
```
katana -u https://target.tld -d 3 -jc -silent | grep -E '\?' | sort -u > urls_with_params.txt
arjun -i urls_with_params.txt --stable --rate-limit 30 -oJ arjun_batch.json
```

### Output Format Selection

| Format | Flag | Content | Best for |
|---|---|---|---|
| JSON | `-oJ` | Per-URL object: URL, method, params with confidence | Downstream automation, injection chaining |
| Text | `-oT` | Param names only, one per line | Quick grep, manual review |
| Burp proxy | `-oB` | Live request/response through proxy | Interactive inspection in Caido/Burp |

`-oJ` and `-oB` can be combined — structured file output plus live proxy inspection:
`arjun -u https://target.tld/api -oJ arjun.json -oB 127.0.0.1:48080`

---

## Detection

### Request Pattern Fingerprint

Arjun's chunked probing produces a distinctive traffic pattern visible to WAFs, IDS, and server-side logging:

**Query-string stuffing (GET mode).** Each probe request carries `-c` parameters in the query string, all set to a known sentinel value (e.g., `arjun`). A request with 25 query parameters where every value is the same string is anomalous — normal user traffic rarely exceeds 5-10 query params.

**Body stuffing (POST/JSON/XML modes).** Same pattern in the request body. JSON mode sends `{"p1":"arjun","p2":"arjun",...}` — a large flat object with uniform values is a clear fingerprint.

**Bisection pattern.** When a chunk is flagged interesting, the follow-up bisection requests halve the parameter count each time. The sequence (25 params → 12 → 6 → 3 → 1) is distinctive in request logs.

**Uniform sentinel values.** The default probe value (`arjun`) appears across all parameters. Some WAFs flag requests where many parameters share the same value.

### Rate and Volume

Default settings (`-t 5`, `--rate-limit 9999`, `-d 0`) send requests as fast as five threads allow. For a wordlist of 25,000 params at chunk size 25, that is ~1,000 probe requests plus narrowing passes — a burst of traffic over 1-3 minutes that shows as a spike in request-rate monitoring.

### Logging Visibility

- **Server access logs** record every query parameter name and value — the probe parameter names from the wordlist appear in logs even when they have no effect on the application.
- **WAF logs** may flag the param-count-per-request threshold, uniform values, or the bisection pattern.
- **HTTP proxy logs** (Caido) capture the full probe traffic when the sandbox proxy is active.

---

## Bypass and Evasion

Arjun is a discovery tool, not an exploitation tool — evasion is about completing the probe without being blocked or rate-limited, not about hiding malicious payloads. All techniques are situational; none guarantee bypass.

### Rate and Timing Controls

Reduce request burst visibility:
- `--rate-limit 10` — cap to 10 req/sec (down from default 9999)
- `-d 2` — add 2-second delay between requests
- `-t 2` — reduce threads to 2
- `--stable` — internally reduces chunk size and adds retries, spreading the probe over a longer window

Low-and-slow baseline:
`arjun -u https://target.tld/api -m GET -c 10 -t 2 -d 1 --rate-limit 5 --stable -oJ arjun.json`

### Chunk Size Tuning

WAFs with per-request parameter count limits (common threshold: 30-50 params) block chunked probes outright:
- Lower `-c 10` or `-c 5` to stay under the WAF's param-count ceiling.
- Trade-off: more requests total (wordlist / chunk_size), but each request looks closer to normal traffic.
- At `-c 1` arjun degrades to single-param probing — slowest but least distinctive pattern.

### Header Manipulation

`--headers` replaces arjun's default request headers:
- Set a browser-plausible `User-Agent` to avoid UA-based blocking.
- Add required `Authorization`, `Cookie`, or custom headers for endpoints behind authentication.
- Include `Accept`, `Accept-Language`, `Referer` to make requests resemble browser traffic.

Headers file format (one header per line):
```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
Accept-Language: en-US,en;q=0.5
Cookie: session=abc123
```

`arjun -u https://target.tld/api --headers headers.txt -c 15 --stable -oJ arjun.json`

### Redirect Handling

`--disable-redirects` prevents arjun from following 3xx responses:
- Use when redirects lead to a login page or error page that produces a uniform response regardless of parameters (collapses the heuristic).
- Use when the target redirects param-stuffed requests to a WAF block page.
- Without this flag, arjun follows redirects and baselines on the final response — correct for most applications but wrong when redirects are the WAF's blocking mechanism.

### Casing Normalization

`--casing` normalizes wordlist entries to match the target's parameter naming convention:
- `like_this` — snake_case (Python/Ruby APIs)
- `likeThis` — camelCase (JavaScript/Java APIs)
- `likethis` — lowercase (legacy/case-insensitive systems)

If the target only accepts camelCase params and the wordlist is snake_case, `--casing likeThis` prevents misses from case mismatch. Does not affect server-side behavior — only the names sent in probes.

---

## Techniques

### Method-Specific Behavior

Each `-m` mode changes how arjun serializes parameters and how the detection heuristic interprets responses:

**GET** — Parameters in query string: `?p1=arjun&p2=arjun&...`
- Detection: content-length change, reflection in body, status code change.
- URL-length limits (typically 2048-8192 bytes depending on server) cap effective chunk size.
- Most visible in server logs (query string is always logged).

**POST** — Parameters in form-encoded body: `p1=arjun&p2=arjun&...`
- Content-Type: `application/x-www-form-urlencoded` (set automatically).
- No URL-length limit — larger chunks are feasible.
- Less visible in default access logs (body not logged by most servers unless configured).

**JSON** — Parameters as JSON keys: `{"p1":"arjun","p2":"arjun",...}`
- Content-Type: `application/json` (set automatically).
- Detection: same heuristic on response diff, but JSON APIs often return structured error messages that change with valid params.
- Useful for REST/GraphQL endpoints that reject form-encoded bodies.

**XML** — Parameters as XML elements: `<p1>arjun</p1><p2>arjun</p2>...`
- Content-Type: `application/xml` (set automatically).
- Niche — only for SOAP/XML-RPC endpoints that parse XML bodies.
- XML structure must be valid; malformed XML may cause parse errors that look like parameter acceptance.

### Wordlist Customization

The built-in `large.txt` (~25K params) covers common web parameter names. For better coverage on specific targets:

**JS/HTML mining.** Extract parameter names from the target's JavaScript and HTML:
```
katana -u https://target.tld -d 3 -jc -silent | httpx -silent | \
  grep -oP '(?:name|param|key|field)\s*[=:]\s*["\x27]([a-zA-Z0-9_]+)["\x27]' | \
  sort -u > custom_params.txt
arjun -u https://target.tld/api -w custom_params.txt -oJ arjun_custom.json
```

**API documentation.** If OpenAPI/Swagger specs are available, extract all parameter names:
```
curl -s https://target.tld/api/swagger.json | jq -r '.. | .name? // empty' | sort -u > api_params.txt
arjun -u https://target.tld/api/v1/endpoint -w api_params.txt -m JSON -oJ arjun_api.json
```

**Combined wordlist.** Merge built-in + custom + passive:
```
cat /path/to/arjun/db/large.txt custom_params.txt | sort -u > merged_params.txt
arjun -u https://target.tld/search -w merged_params.txt --passive target.tld -oJ arjun_merged.json
```

### Stateful Endpoint Handling

`--include` appends fixed data to every probe request, solving the "every request returns the same error" problem on authenticated or stateful endpoints:

**CSRF token:**
`arjun -u https://target.tld/profile -m POST --include "csrf_token=TOKEN_VALUE" -oJ arjun.json`

**Session + routing params:**
`arjun -u https://target.tld/api/user -m POST --include "session_id=abc123&org_id=42" -oJ arjun.json`

**JSON body state (with -m JSON):**
`arjun -u https://target.tld/api/v1/data -m JSON --include '{"auth_token":"abc123"}' -oJ arjun.json`

The `--include` data merges with each probe's parameters — arjun's chunked params are appended alongside the fixed include data. Without `--include` on stateful endpoints, every probe request lacks required state and returns the same 401/403/redirect, making all chunks look identical to baseline and collapsing discovery.

### Burp/Caido Proxy Integration

`-oB` sends all discovery traffic through a proxy for live inspection:

**Caido integration (sandbox default port):**
`arjun -u https://target.tld/api -oB 127.0.0.1:48080 -oJ arjun.json`

**Combined workflow — inspect in Caido while saving structured output:**
1. Run arjun with `-oB` + `-oJ`
2. In Caido, filter requests by the arjun sentinel value to see which chunks triggered response changes
3. Use Caido's replay to manually verify discovered parameters with different values
4. Feed confirmed params to sqlmap/ffuf for injection testing

The sandbox already routes through Caido via `http_proxy` env — `-oB` is for explicit proxy targeting when you want a second proxy or to override the env.

### Output Parsing for Injection Chaining

**Extract param names from JSON output for sqlmap:**
```
jq -r '.[] | .params | keys[]' arjun.json | paste -sd, - > params_csv.txt
sqlmap -u "https://target.tld/search?q=test" -p "$(cat params_csv.txt)" --batch
```

**Extract params for ffuf value fuzzing:**
```
jq -r '.[] | .params | keys[]' arjun.json | while read param; do
  ffuf -u "https://target.tld/search?${param}=FUZZ" -w values.txt -mc 200 -o "ffuf_${param}.json"
done
```

**Feed into targeted XSS probing:**
```
jq -r '.[] | .params | keys[]' arjun.json | while read param; do
  echo "https://target.tld/search?${param}=<script>alert(1)</script>"
done | httpx -silent -mc 200 -mr '<script>alert'
```

---

## Tool-to-Tool Chaining

### Upstream — URL Discovery → arjun

Crawled URLs feed arjun for parameter discovery on every unique endpoint:

katana → arjun:
```
katana -u https://target.tld -d 3 -jc -silent | \
  grep -oP 'https?://[^\s"]+' | \
  sed 's/\?.*$//' | sort -u > endpoints.txt
arjun -i endpoints.txt --stable --rate-limit 30 -oJ arjun_batch.json
```

gospider → arjun (with third-party enrichment):
```
gospider -s https://target.tld -a -d 2 --quiet | \
  grep -oP 'https?://[^\s"]+' | \
  sed 's/\?.*$//' | sort -u > endpoints.txt
arjun -i endpoints.txt --stable --rate-limit 30 -oJ arjun_batch.json
```

### Downstream — arjun → Injection Testing

arjun → sqlmap (discovered params as injection targets):
```
jq -r 'to_entries[] | "\(.key)?"+(.value.params | keys | map(.+"=test") | join("&"))' arjun.json | \
  while read url; do sqlmap -u "$url" --batch --risk 2 --level 3; done
```

arjun → ffuf (value fuzzing per discovered param):
```
jq -r '.[] | .params | keys[]' arjun.json | while read p; do
  ffuf -u "https://target.tld/search?${p}=FUZZ" -w /usr/share/seclists/Fuzzing/special-chars.txt -mc all -o "ffuf_${p}.json"
done
```

arjun → IDOR testing (discovered ID-like params):
```
jq -r '.[] | .params | keys[]' arjun.json | grep -iE '(id|uid|user|account|ref|num)' > idor_params.txt
```

### Parallel — arjun + waybackurls/gau

`--passive` overlaps with `waybackurls`/`gau` on source coverage:
- arjun `--passive` queries Wayback + CommonCrawl + OTX and extracts param names automatically.
- `waybackurls`/`gau` return full URLs; param names must be extracted separately.
- For maximum coverage, run both: arjun's passive seeding plus gau's provider set (which includes additional sources beyond arjun's three).

```
gau target.tld | grep -oP '[?&]\K[a-zA-Z0-9_]+(?==)' | sort -u > gau_params.txt
cat gau_params.txt /path/to/arjun/db/large.txt | sort -u > combined.txt
arjun -u https://target.tld/search -w combined.txt -oJ arjun_combined.json
```

---

## Routed Consumers

- `vulnerabilities/sql_injection.md`, `vulnerabilities/xss.md`, `vulnerabilities/ssrf.md`, `vulnerabilities/open_redirect.md`, `vulnerabilities/mass_assignment.md` (every injection class needs the parameter name — arjun supplies it)
- `vulnerabilities/idor.md` (hidden-id parameters often live outside the documented API)
- `vulnerabilities/nosql_injection.md` (JSON-mode discovered params on NoSQL-backed APIs)
- `reconnaissance/*` (parameter inventory is attack-surface mapping)
- `tooling/sqlmap.md` (primary consumer of discovered parameter names for injection testing)
- `tooling/ffuf.md` (value fuzzing on discovered parameters)
- `tooling/katana.md` (upstream URL discovery feeds arjun's `-i`)
- `tooling/gospider.md` (upstream URL discovery with third-party enrichment)
- `tooling/waybackurls.md`, `tooling/gau.md` (parallel passive param sources)
- `tooling/caido.md` (live inspection via `-oB` proxy integration)

If uncertain, query web_search with:
`site:github.com/s0md3v/Arjun arjun <flag>`
