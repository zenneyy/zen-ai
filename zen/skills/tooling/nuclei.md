---
name: nuclei
description: Exact Nuclei command structure, template selection, and bounded high-throughput execution controls.
---

# Nuclei CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/nuclei/running
- https://docs.projectdiscovery.io/opensource/nuclei/mass-scanning-cli
- https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview
- https://github.com/projectdiscovery/nuclei

Canonical syntax:
`nuclei [flags]`

High-signal flags:
- `-u, -target <url>` single target (accepts multiple comma-separated)
- `-l, -list <file>` targets file (one per line)
- `-eh, -exclude-hosts <host>` exclude hosts from input (ip, cidr, hostname)
- `-im, -input-mode <mode>` list/burp/jsonl/yaml/openapi/swagger (default `list`)
- `-t, -templates <path|dir>` explicit template path(s) or directory (comma-separated, file)
- `-turl, -template-url <url>` template URL(s) to fetch and run
- `-w, -workflows <path>` workflow path(s)
- `-tags <tag1,tag2>` run templates matching tags
- `-etags, -exclude-tags <tag1,tag2>` exclude templates by tag
- `-s, -severity <critical,high,...>` severity filter (info, low, medium, high, critical, unknown)
- `-es, -exclude-severity <sev>` exclude by severity
- `-pt, -type <proto>` filter by protocol type (dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript)
- `-as, -automatic-scan` tech-mapped automatic scan (Wappalyzer fingerprint → tag mapping)
- `-tp, -profile <file>` template profile config file
- `-dast` enable DAST fuzzing templates
- `-ni, -no-interactsh` disable OAST/interactsh requests
- `-rl, -rate-limit <n>` global request rate cap (default 150/s)
- `-per-host-rate-limit` per-host rate limiting (disables global cap)
- `-c, -concurrency <n>` template concurrency (default 25)
- `-bs, -bulk-size <n>` hosts in parallel per template (default 25)
- `-ss, -scan-strategy <strategy>` auto/host-spray/template-spray (default auto)
- `-timeout <seconds>` request timeout (default 10)
- `-retries <n>` retries (default 1)
- `-mt, -max-time <duration>` maximum total scan time (e.g. `1h`, `30m`)
- `-p, -proxy <url>` HTTP/SOCKS5 proxy (comma-separated or file)
- `-H, -header <header:value>` custom header for all requests
- `-stats` periodic scan stats output
- `-silent` findings-only output
- `-j, -jsonl` JSONL output
- `-o <file>` output file
- `-se, -sarif-export <file>` SARIF 2.1.0 export
- `-je, -json-export <file>` JSON export
- `-me, -markdown-export <dir>` Markdown export directory
- `-pe, -pdf-export <file>` PDF export

Agent-safe baseline for automation:
`nuclei -l targets.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -mt 30m -silent -j -o nuclei.jsonl`

Common patterns:
- Focused severity scan:
  `nuclei -u https://target.tld -s critical,high -silent -o nuclei_high.txt`
- List-driven controlled scan:
  `nuclei -l targets.txt -as -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl`
- Tag-driven run:
  `nuclei -l targets.txt -tags cve,misconfig -s critical,high,medium -silent`
- Explicit templates:
  `nuclei -l targets.txt -t http/cves/ -t dns/ -rl 30 -c 10 -bs 10 -j -o nuclei_templates.jsonl`
- Deterministic non-OAST run:
  `nuclei -l targets.txt -as -s critical,high -ni -stats -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -j -o nuclei_no_oast.jsonl`
- DAST fuzzing on a single target:
  `nuclei -u https://target.tld -dast -fa medium -rl 30 -c 10 -timeout 15 -j -o nuclei_dast.jsonl`
- Protocol-filtered run (SSL/TLS only):
  `nuclei -l targets.txt -pt ssl -rl 50 -c 25 -j -o nuclei_ssl.jsonl`
- Time-bounded wide scan:
  `nuclei -l targets.txt -as -s critical,high,medium -mt 1h -stats -si 30 -j -o nuclei_timed.jsonl`
- Resume an interrupted scan:
  `nuclei -l targets.txt -as -resume nuclei_scan.cfg -j -o nuclei_resumed.jsonl`
- SARIF export for CI integration:
  `nuclei -l targets.txt -as -s critical,high -silent -se nuclei.sarif -j -o nuclei.jsonl`

Critical correctness rules:
- Provide a template selection method (`-as`, `-t`, `-tags`, `-tp`, or `-dast`); avoid unscoped broad runs.
- Keep `-rl`, `-c`, and `-bs` explicit for predictable resource use.
- Use `-ni` when outbound interactsh/OAST traffic is not expected or not allowed.
- Use structured output (`-j -o <file>`) for automation.
- Use `-mt` for time-bounded runs in automation — nuclei has no default time limit.
- `-dast` is separate from template-based scanning; it enables the fuzzing engine and ignores non-fuzzing templates.

Usage rules:
- Start with severity/tags/templates filters to keep runs explainable.
- Keep retries conservative (`-retries 1`) unless transport instability is proven.
- Use `-stats -si 30` for visibility into long runs without flooding output.
- Do not use `-h`/`--help` for routine operation unless absolutely necessary.

Failure recovery:
- If performance degrades, lower `-c/-bs` before lowering `-rl`.
- If findings are unexpectedly empty, verify template selection (`-as` vs explicit `-t/-tags`); check `-vv` to see templates loaded.
- If scan duration grows, reduce target set and enforce stricter template/severity filters, or add `-mt`.
- If a scan hangs, enable `-hm` (hang monitor) and check `-stats` output.
- If a host causes excessive errors, tune `-mhe` (default 30) or add it to `-eh`.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io nuclei <flag> running`

## Template Selection and Filtering

Nuclei's power comes from its template corpus (v10.5.0: 7119 vuln, 4526 CVE, 3872 discovery, 1424 xss, 1057 rce, 889 lfi, 607 sqli, 383 oast). Precise template selection determines both coverage and runtime.

Selection methods (use exactly one primary method per run):
- `-as` (automatic-scan) — fingerprints the target's tech stack via Wappalyzer and maps detected technologies to template tags. Best default for unknown targets.
- `-t <path>` — explicit template path(s) or directories. Accepts comma-separated values, files listing paths, or multiple `-t` flags. Most precise control.
- `-tags <tag1,tag2>` — run all templates matching any listed tag. Use `-tgl` to list available tags.
- `-tp, -profile <file>` — template profile config file. Use `-tpl` to list community profiles.
- `-w <path>` — workflows (multi-step template chains with conditional logic).
- `-dast` — DAST fuzzing templates only (see DAST section below).

Filtering (combinable with any selection method):
- `-s critical,high` / `-es info,low` — severity include/exclude.
- `-tags cve,misconfig` / `-etags dos,fuzzer` — tag include/exclude. `-itags` forces inclusion even for default-excluded tags.
- `-id, -template-id <id>` / `-eid, -exclude-id <id>` — template ID include/exclude. Supports wildcards (`CVE-2024-*`).
- `-a, -author <name>` — filter by template author.
- `-pt http,ssl` / `-ept headless` — protocol type include/exclude.
- `-tc, -template-condition <expr>` — expression-based filtering (DSL conditions on template metadata).
- `-em, -exclude-matchers <matcher>` — exclude specific matchers from results.
- `-it, -include-templates <path>` / `-et, -exclude-templates <path>` — force include/exclude specific template files or directories even if otherwise filtered.

Template inspection:
- `nuclei -tl -tags cve -s critical` — list matching templates without scanning.
- `nuclei -tgl` — list all available tags with counts.
- `nuclei -td -t http/cves/CVE-2024-1234.yaml` — display template content.
- `nuclei -validate -t custom/` — validate custom templates before running.
- `nuclei -tpl` — list community template profiles.

New template tracking:
- `-nt` — run only templates added in the latest nuclei-templates release. Useful for regression scans against recently published CVEs.
- `-ntv v10.4.0,v10.5.0` — run templates added in specific versions.

Template signing and trust:
- `-sign` — sign templates using `NUCLEI_SIGNATURE_PRIVATE_KEY` env var.
- `-dut` — refuse to run unsigned or signature-mismatched templates.
- `-code` — enable code-protocol templates (disabled by default for safety).
- `-esc` — enable self-contained templates.
- `-egm` — enable global matchers (templates that match across all scan results).
- `-file` — enable file-protocol templates.
- `-nss` — disable strict syntax checking (use only for legacy templates).

Effective template selection patterns:
```
# CVE-only scan, critical+high, last two releases
nuclei -l targets.txt -tags cve -s critical,high -nt -silent -j -o cve_new.jsonl

# Misconfig + exposure, exclude DoS and fuzzer tags
nuclei -l targets.txt -tags misconfig,exposure -etags dos,fuzzer -rl 50 -j -o misconfig.jsonl

# All RCE templates, protocol-filtered to HTTP only
nuclei -l targets.txt -tags rce -pt http -s critical,high -rl 30 -c 10 -j -o rce_http.jsonl

# Template ID wildcard — all 2025/2026 CVEs
nuclei -l targets.txt -id "CVE-202[56]-*" -rl 50 -j -o cve_recent.jsonl

# Authenticated scan with default-login templates
nuclei -l targets.txt -tags default-login -rl 20 -c 10 -j -o default_creds.jsonl
```

## DAST Fuzzing Mode

Nuclei's DAST engine fuzzes HTTP requests dynamically, discovering vulnerabilities without pre-written signatures. It parses requests, identifies fuzzable components (query params, headers, body fields, path segments), and applies transformation rules with payloads. Supports JSON, XML, form data, and multipart request formats.

Enable with `-dast` (replaces the deprecated `-fuzz` flag). DAST templates are separate from standard detection templates — `-dast` runs only fuzzing templates.

Core flags:
- `-dast` — enable the fuzzing engine.
- `-fa, -fuzz-aggression <level>` — payload count: `low` (default, minimal payloads), `medium` (broader coverage), `high` (exhaustive). Higher aggression = more requests = more time.
- `-ft, -fuzzing-type <type>` — override the template's insertion method: `replace` (substitute parameter value), `prefix` (prepend to value), `postfix` (append to value), `infix` (insert within value).
- `-fm, -fuzzing-mode <mode>` — override payload delivery: `single` (one parameter at a time), `multiple` (all parameters simultaneously).
- `-at, -attack-type <type>` — payload combination strategy: `batteringram` (same payload in all positions), `pitchfork` (parallel iteration across payload sets), `clusterbomb` (cartesian product of all payload sets).
- `-cs, -fuzz-scope <regex>` — in-scope URL regex the fuzzer follows.
- `-cos, -fuzz-out-scope <regex>` — out-of-scope URL regex the fuzzer skips.
- `-dfp, -display-fuzz-points` — display identified fuzz points for debugging (shows where the fuzzer will inject before running payloads).
- `-fuzz-param-frequency <n>` — skip parameters seen more than `n` times across different URLs (default 10); reduces redundant testing of common parameters like `page`, `lang`.

DAST server mode (live fuzzing against a proxy-fed request stream):
- `-dts, -dast-server` — enable server mode, listening for requests to fuzz.
- `-dtsa, -dast-server-address <addr>` — listen address (default `localhost:9055`).
- `-dtst, -dast-server-token <token>` — optional auth token.
- `-dtr, -dast-report` — write DAST-specific report.

DAST patterns:
```
# Basic DAST scan with medium aggression
nuclei -u https://target.tld -dast -fa medium -rl 30 -timeout 15 -j -o dast.jsonl

# Scoped DAST — fuzz only within the target's API path
nuclei -u https://target.tld -dast -fa low -cs "https://target\\.tld/api/.*" -cos "https://target\\.tld/static/.*" -j -o dast_api.jsonl

# Debug fuzz points before running
nuclei -u https://target.tld -dast -dfp 2>&1 | head -50

# DAST with clusterbomb attack on multi-param endpoints
nuclei -u https://target.tld -dast -at clusterbomb -fa high -rl 20 -c 5 -j -o dast_cluster.jsonl
```

When to use DAST vs template-based scanning:
- Template-based (`-as`, `-t`, `-tags`): known vulnerability signatures, CVE checks, misconfigs, default credentials. Fast, deterministic, low false-positive.
- DAST (`-dast`): unknown/custom application logic, parameter-level injection testing (SQLi, XSS, SSRF, CMDi), when you need fuzzing without writing custom templates. Slower, higher request count, requires rate-limit tuning.

## Scan Strategies and Optimization

Scan strategy controls how nuclei distributes work across targets and templates:
- `-ss auto` (default) — nuclei picks based on target/template ratio.
- `-ss host-spray` — runs all selected templates against one host before moving to the next. Best when scanning few hosts with many templates — keeps per-host state coherent and finishes hosts sequentially.
- `-ss template-spray` — runs each template across all hosts before moving to the next template. Best when scanning many hosts with few templates — maximizes template-level caching.

Preflight filtering:
- `-preflight-portscan` — resolve DNS + TCP portscan targets before scanning. Filters out unreachable hosts, reducing wasted requests. Disabled by default; enable for large target lists with expected dead hosts.
- `-nh, -no-httpx` — disable the built-in httpx probe for non-URL input. By default nuclei probes inputs that aren't URLs to discover HTTP services; disable when input is already validated URLs.
- `-sa, -scan-all-ips` — scan all IPs behind a DNS record, not just the first. Important for CDN-fronted targets or round-robin DNS.

Input handling:
- `-stream` — start scanning without sorting/deduplicating input. Useful for piped input where you want results as targets arrive, at the cost of potential duplicate scanning.
- `-irt, -input-read-timeout <duration>` — timeout for reading input (default 3m). Increase for slow stdin pipes.
- `-resume <file>` — save and resume scan progress. Disables request clustering.
- `-no-stdin` — disable stdin processing (use when `-l` is the only input).

Request deduplication:
- `-dc, -disable-clustering` — disable request clustering. By default nuclei merges identical requests across templates into single requests; disable when template-specific request modifications (headers, timing) matter.
- `-project` / `-project-path <dir>` — project mode caches request/response pairs on disk, avoiding duplicate requests across runs. Useful for iterative scanning against the same target.

Host error handling:
- `-mhe, -max-host-error <n>` (default 30) — skip a host after `n` errors. Prevents wasting time on hosts that are down or blocking.
- `-te, -track-error <pattern>` — add error patterns to the MHE watchlist.
- `-nmhe` — disable MHE entirely (scan all hosts regardless of errors).
- `-spm, -stop-at-first-match` — stop processing a host after the first finding. Use cautiously: saves time on large scans but misses additional vulnerabilities.

Redirect control:
- `-fr` — follow redirects for HTTP templates (disabled by default).
- `-fhr` — follow redirects only to the same host (safer than `-fr`).
- `-mr <n>` — max redirects to follow (default 10).
- `-dr` — disable redirects entirely.

Optimization patterns:
```
# Large target list with preflight filtering and host-spray
nuclei -l large_targets.txt -as -s critical,high -preflight-portscan -ss host-spray -mhe 10 -rl 100 -mt 2h -stats -j -o large_scan.jsonl

# Iterative scanning with project caching
nuclei -l targets.txt -as -project -project-path ./nuclei_project -j -o scan_iter.jsonl

# Piped input from httpx with streaming
httpx -l hosts.txt -silent | nuclei -as -stream -rl 50 -j -o piped_scan.jsonl

# Scan all IPs behind a CDN-fronted target
nuclei -u target.tld -sa -as -s critical,high -j -o all_ips.jsonl
```

## Rate Limiting and Concurrency

Nuclei has multiple concurrency dimensions. Tune them to the target count, template count, and target tolerance.

Global rate limiting:
- `-rl <n>` — max requests per second across all templates and hosts (default 150). The primary throttle.
- `-rld <duration>` — rate limit window duration (default `1s`). Set to `100ms` for finer granularity or `5s` for bursty patterns.

Per-host rate limiting:
- `-per-host-rate-limit` — enables per-host rate limiting. When enabled, `-rl` applies per host rather than globally, and the global cap becomes unlimited. Use when scanning many hosts at controlled individual rates.

Concurrency knobs (all independent):
- `-c <n>` (default 25) — templates executed in parallel. The main throughput driver.
- `-bs <n>` (default 25) — hosts processed in parallel per template.
- `-hbs <n>` (default 10) — headless hosts in parallel per template.
- `-headc <n>` (default 10) — headless templates in parallel.
- `-jsc <n>` (default 120) — JavaScript runtime concurrency.
- `-pc <n>` (default 25) — payload concurrency per template (relevant for DAST/fuzzing).
- `-prc <n>` (default 50) — httpx probe concurrency for non-URL input.
- `-tlc <n>` (default 50) — template loading concurrency.

Tuning guidance:
- **Many targets, few templates** → increase `-bs`, keep `-c` moderate. `host-spray` strategy.
- **Few targets, many templates** → increase `-c`, keep `-bs` low. `template-spray` strategy.
- **Single target, full template set** → `-c 25 -bs 1 -rl 50` prevents overwhelming one host.
- **DAST fuzzing** → lower `-c` (5–10) and `-rl` (20–50) since fuzzing generates many requests per template.
- **Headless templates** → `-hbs` and `-headc` control Chrome instance count; keep low (5–10) to avoid memory exhaustion.

Rate limiting patterns:
```
# Conservative single-target scan
nuclei -u https://target.tld -as -rl 30 -c 10 -bs 1 -timeout 15 -j -o conservative.jsonl

# High-throughput multi-target with per-host limiting
nuclei -l targets.txt -as -rl 50 -per-host-rate-limit -c 30 -bs 30 -j -o multi.jsonl

# DAST-appropriate rate limiting
nuclei -u https://target.tld -dast -rl 20 -c 5 -pc 10 -timeout 15 -j -o dast.jsonl
```

## OAST and Interactsh Integration

Nuclei uses Interactsh for out-of-band (OAST) vulnerability detection — blind SSRF, blind XSS, blind command injection, log4shell, and similar classes where the confirming signal arrives via a callback (DNS, HTTP, SMTP, LDAP) rather than in-band response. ~383 templates in the corpus use OAST (the `oast` tag).

How it works: nuclei generates unique Interactsh URLs embedded in payloads. If the target processes the payload and triggers an outbound request to that URL, Interactsh captures it and nuclei correlates the callback to the originating template/host.

Default behavior: nuclei uses ProjectDiscovery's public Interactsh servers (`oast.pro`, `oast.live`, `oast.site`, `oast.online`, `oast.fun`, `oast.me`) with automatic rotation.

Self-hosted Interactsh:
- `-iserver <url>` — point to a self-hosted Interactsh server. Required when public servers are blocked by egress filters or when you need full control over callback data.
- `-itoken <token>` — auth token for the self-hosted server.

Timing and cache tuning:
- `-interactions-cache-size <n>` (default 5000) — requests kept in the correlation cache. Increase for large scans generating many OAST payloads.
- `-interactions-eviction <n>` (default 60) — seconds before evicting unmatched requests. Increase for slow targets where callbacks arrive late.
- `-interactions-poll-duration <n>` (default 5) — polling interval in seconds. Lower for faster correlation; higher to reduce Interactsh server load.
- `-interactions-cooldown-period <n>` (default 5) — extra polling time after scan completion. Increase (15–30s) for targets with delayed callback behavior.

Disabling OAST:
- `-ni` — disable Interactsh entirely and exclude all OAST-dependent templates. Use when: outbound traffic from the scanner is restricted, the target is air-gapped, or you need deterministic results without callback dependencies.

OAST patterns:
```
# OAST-only scan (blind vulnerability classes)
nuclei -l targets.txt -tags oast -rl 30 -interactions-cooldown-period 15 -j -o oast.jsonl

# Self-hosted Interactsh for controlled environments
nuclei -l targets.txt -as -iserver https://interact.internal.tld -itoken <token> -j -o oast_self.jsonl

# Extended callback window for slow targets
nuclei -l targets.txt -tags oast -interactions-eviction 120 -interactions-cooldown-period 30 -j -o oast_slow.jsonl
```

## Honeypot Detection

Internet-facing scan targets (especially from Shodan/Censys) frequently include honeypots that deliberately match many vulnerability templates, producing false positives and wasting time.

- `-hpd, -honeypot-detect` — enable honeypot detection. Tracks distinct template IDs matching per host; flags hosts exceeding the threshold.
- `-hpt, -honeypot-threshold <n>` (default 15) — number of distinct template matches before flagging a host as a probable honeypot.
- `-shp, -suppress-honeypot` — suppress all output for flagged honeypot hosts.

Use `-hpd -shp` on internet-scale scans to automatically filter honeypot noise:
```
# Internet-scale scan with honeypot suppression
nuclei -l shodan_targets.txt -as -s critical,high -hpd -shp -hpt 10 -rl 100 -j -o internet_scan.jsonl
```

Lower `-hpt` (e.g. 5–10) for aggressive filtering; raise it (20+) if legitimate targets trigger false honeypot flags due to genuinely vulnerable stacks.

## Headless Browser Templates

Some templates require a real browser — DOM-based XSS, client-side logic flaws, JavaScript-rendered content, headless interaction flows.

- `-headless` — enable headless browser support. Required for templates in the `headless` protocol type.
- `-page-timeout <n>` (default 20) — seconds to wait per page load.
- `-sb, -show-browser` — show the browser window (debugging).
- `-ho, -headless-options <opt1,opt2>` — additional Chrome flags (e.g. `--disable-gpu,--proxy-server=http://127.0.0.1:8080`).
- `-sc, -system-chrome` — use locally installed Chrome instead of nuclei's bundled Chromium.
- `-cdpe, -cdp-endpoint <url>` — connect to a remote Chrome via CDP (e.g. for shared browser pools).
- `-lha` — list available headless actions (click, type, navigate, screenshot, etc.).

Concurrency for headless:
- `-hbs <n>` (default 10) — headless hosts in parallel per template.
- `-headc <n>` (default 10) — headless templates in parallel.

Keep headless concurrency low (5–10) — each Chrome instance consumes significant memory.

```
# Headless scan for DOM-based vulnerabilities
nuclei -u https://target.tld -headless -pt headless -sc -page-timeout 30 -hbs 5 -headc 5 -j -o headless.jsonl

# Headless through proxy
nuclei -u https://target.tld -headless -sc -ho "--proxy-server=http://127.0.0.1:48080" -j -o headless_proxy.jsonl
```

## Uncover Engine Integration

Nuclei can discover targets passively via search engines (Shodan, Censys, Fofa, etc.) and scan them in a single pipeline — no separate recon step.

- `-uc` — enable uncover engine.
- `-uq <query>` — search query (engine-specific syntax).
- `-ue <engine>` — engine selection (default `shodan`). Available: `shodan`, `censys`, `fofa`, `shodan-idb`, `quake`, `hunter`, `zoomeye`, `netlas`, `criminalip`, `publicwww`, `hunterhow`, `google`, `odin`, `binaryedge`, `onyphe`, `driftnet`, `greynoise`, `daydaymap`, `nerdydata`.
- `-uf <fields>` — fields to return: `ip`, `port`, `host` (default `ip:port`).
- `-ul <n>` — max results (default 100).
- `-ur <n>` — rate limit for engines without a known limit (default 60 req/min).

Uncover requires API keys configured for each engine (via environment variables or nuclei config).

```
# Shodan → nuclei pipeline for Apache Struts
nuclei -uc -uq "apache struts" -ue shodan -ul 200 -tags cve -s critical -rl 30 -j -o struts_shodan.jsonl

# Censys for exposed Jenkins, scan with auth-bypass templates
nuclei -uc -uq "services.http.response.html_title: Jenkins" -ue censys -ul 100 -tags auth-bypass,default-login -j -o jenkins.jsonl

# Multi-engine discovery
nuclei -uc -uq "org:target-corp" -ue shodan,censys -ul 500 -as -s critical,high -hpd -shp -j -o corp_scan.jsonl
```

## Output Formats and Reporting

Nuclei supports multiple output formats, all combinable in a single run:

CLI output:
- `-silent` — findings only, no banner/progress.
- `-nc` — no ANSI color codes (for log files).
- `-nm, -no-meta` — suppress result metadata in CLI output.
- `-ts, -timestamp` — add timestamps to CLI output.
- `-ms, -matcher-status` — show match failures (debugging why templates don't fire).

Structured export:
- `-o <file>` — plain text output.
- `-j, -jsonl` — JSONL format (one JSON object per finding per line).
- `-je, -json-export <file>` — JSON file export.
- `-jle, -jsonl-export <file>` — JSONL file export.
- `-se, -sarif-export <file>` — SARIF 2.1.0 (for CI/CD integration, GitHub Code Scanning).
- `-me, -markdown-export <dir>` — Markdown directory (one file per finding, sortable via `MARKDOWN_EXPORT_SORT_MODE` env var).
- `-pe, -pdf-export <file>` — PDF report.

Request/response control:
- `-or, -omit-raw` — omit request/response pairs from JSON/JSONL/Markdown/PDF output. Reduces output size significantly.
- `-ot, -omit-template` — omit encoded template content from JSON/JSONL output.
- `-sresp, -store-resp` — store all request/response pairs to disk (not just findings).
- `-srd, -store-resp-dir <dir>` — custom directory for stored responses (default `output`).

Data redaction:
- `-rd, -redact <key1,key2>` — redact specified keys from query parameters, request headers, and body in output. Use for sensitive parameters (tokens, passwords).

Reporting:
- `-rdb, -report-db <file>` — persistent reporting database. Tracks findings across runs for deduplication and trend analysis.
- `-rc, -report-config <file>` — reporting module configuration (Jira, GitHub, GitLab, Slack, etc. integrations).

Statistics:
- `-stats` — display scan progress statistics.
- `-sj, -stats-json` — statistics in JSONL format (for programmatic consumption).
- `-si <n>` (default 5) — statistics update interval in seconds.
- `-mp <port>` (default 9092) — Prometheus-compatible metrics port.
- `-hps` — experimental HTTP status code capturing.

Output patterns:
```
# Full export suite for a formal assessment
nuclei -l targets.txt -as -s critical,high,medium -silent -j -o nuclei.jsonl -se nuclei.sarif -me nuclei_report/ -pe nuclei_report.pdf

# Lean JSONL output (no raw request/response, no template encoding)
nuclei -l targets.txt -as -or -ot -j -o lean.jsonl

# Stored responses for manual review
nuclei -u https://target.tld -as -sresp -srd ./responses -j -o scan.jsonl

# Redacted output for client delivery
nuclei -l targets.txt -as -rd "api_key,token,password" -j -o redacted.jsonl
```

## Detection Fingerprint

Nuclei's traffic has a recognizable fingerprint. Understanding it matters for both evasion (authorized engagements where WAF/IDS interference produces false negatives) and operational awareness.

Default fingerprint:
- **User-Agent:** `Nuclei - Open-source project (github.com/projectdiscovery/nuclei)` — immediately identifiable by any WAF rule or log grep.
- **Request patterns:** high request volume with template-specific paths/payloads. Signature-based WAFs match known nuclei template payloads.
- **TLS fingerprint:** Go's default TLS stack produces a distinctive JA3 hash.
- **Timing:** default 150 req/s with clustered request patterns per template.

Reducing the fingerprint:
- `-H "User-Agent: Mozilla/5.0 ..."` — override the default UA. Does not eliminate the fingerprint but removes the obvious beacon.
- `-tlsi, -tls-impersonate` — experimental JA3/TLS fingerprint randomization. Defeats JA3-based blocking.
- `-p <proxy>` / `-pi` — route through a proxy (Caido, Burp, or SOCKS5). `-pi` proxies internal requests too.
- `-fh2, -force-http2` — force HTTP/2 connections. Changes the traffic profile; some WAFs handle HTTP/2 differently.
- `-rl 10-30` — lower rate to avoid rate-based detection.
- `--scan-delay` is not available in nuclei; use `-rl` and `-rld` for timing control.
- `-sni <hostname>` — override TLS SNI hostname.
- `-i, -interface <iface>` — bind to a specific network interface.
- `-sip, -source-ip <ip>` — bind to a specific source IP.

Proxy integration:
```
# Route through Caido proxy (sandbox default)
nuclei -l targets.txt -as -p http://127.0.0.1:48080 -j -o proxied.jsonl

# SOCKS5 proxy for network-level routing
nuclei -l targets.txt -as -p socks5://127.0.0.1:9050 -j -o tor.jsonl

# Custom UA + TLS impersonation + low rate
nuclei -l targets.txt -as -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -tlsi -rl 20 -j -o stealth.jsonl
```

## Authentication and Secrets

Nuclei supports authenticated scanning via secret files — YAML configs that define credentials, tokens, cookies, or headers injected into template requests.

- `-sf, -secret-file <file>` — path to secret file(s). Multiple files accepted.
- `-ps, -prefetch-secrets` — load and validate secrets before scanning (fail early on bad credentials).

Client TLS authentication (mTLS):
- `-cc, -client-cert <file>` — PEM-encoded client certificate.
- `-ck, -client-key <file>` — PEM-encoded client private key.
- `-ca, -client-ca <file>` — PEM-encoded CA certificate.

Additional auth mechanisms:
- `-H "Cookie: session=abc123"` — inject session cookies via custom header.
- `-H "Authorization: Bearer <token>"` — inject bearer tokens.
- `-V key=value` — set template variables (credentials, tokens) from CLI.
- `-ev, -env-vars` — allow templates to reference environment variables.

```
# Authenticated scan with secret file
nuclei -l targets.txt -as -sf secrets.yaml -ps -j -o authenticated.jsonl

# mTLS authenticated scan
nuclei -u https://mtls.target.tld -as -cc client.pem -ck client-key.pem -ca ca.pem -j -o mtls.jsonl

# Bearer token via custom header
nuclei -u https://api.target.tld -as -H "Authorization: Bearer eyJ..." -j -o api_auth.jsonl
```

## Input Formats

Beyond plain URL lists, nuclei accepts structured input:
- `-im list` (default) — one URL/host per line.
- `-im burp` — Burp Suite XML export. Nuclei extracts requests and replays them with templates.
- `-im jsonl` — JSONL with request details (URL, method, headers, body).
- `-im yaml` — YAML input with variables. Use `-vtt` for text templating in vars, `-vfp` for external var files.
- `-im openapi` / `-im swagger` — derive targets from OpenAPI/Swagger specs. `-ro` uses only required fields; `-sfv` skips format validation for loose specs.

```
# Scan from Burp export
nuclei -l burp_export.xml -im burp -as -j -o burp_scan.jsonl

# Scan from OpenAPI spec (required fields only)
nuclei -l openapi.json -im openapi -ro -as -j -o api_scan.jsonl
```

## Passive Mode

- `-passive` — process pre-collected HTTP responses without sending requests. Feed nuclei stored responses and it runs matchers/extractors against them offline. Useful for analyzing proxy logs, stored crawl data, or response dumps without touching the target.

```
# Passive analysis of stored responses
nuclei -l response_files.txt -passive -t http/misconfiguration/ -j -o passive.jsonl
```

## Debugging and Diagnostics

- `-debug` — show all requests and responses (very verbose).
- `-dreq` / `-dresp` — show only sent requests / received responses.
- `-tlog, -trace-log <file>` — write request trace log.
- `-elog, -error-log <file>` — write error log.
- `-v` — verbose output. `-vv` — show loaded templates.
- `-svd, -show-var-dump` — dump template variables (debugging custom templates). `-vdl <n>` limits var dump display.
- `-ldf, -list-dsl-function` — list DSL function signatures (for template authoring).
- `-hm, -hang-monitor` — detect and report hung scan states.
- `-hc, -health-check` — run diagnostic check.
- `-profile-mem <file>` — generate heap/trace profiles (Go pprof).
- `-ep, -enable-pprof` — enable pprof debugging server.

```
# Debug a specific template against a target
nuclei -u https://target.tld -t custom/template.yaml -debug -vv -svd

# Trace logging for post-mortem analysis
nuclei -l targets.txt -as -tlog trace.log -elog error.log -j -o scan.jsonl
```

## Miscellaneous Configuration

Response size limits:
- `-rsr, -response-size-read <bytes>` — max bytes to read per response.
- `-rss, -response-size-save <bytes>` (default 1048576) — max bytes to save per response.

Port handling:
- `-ldp, -leave-default-ports` — preserve `:80`/`:443` in URLs instead of stripping them. Required when the target behaves differently with explicit port numbers.

Network:
- `-dka, -dialer-keep-alive <duration>` — TCP keep-alive duration.
- `-lfa, -allow-local-file-access` — allow file payloads from anywhere on the filesystem.
- `-lna, -restrict-local-network-access` — block connections to local/private network ranges. Safety feature for scanning external targets.

TLS:
- `-sni <hostname>` — override TLS SNI (useful for virtual hosting or CDN bypass).
- `-ztls` — deprecated; ztls autofallback is now default.

Reset:
- `-reset` — remove all nuclei configuration and data (including templates). Nuclear option; re-runs template download.

Update:
- `-ut` — update templates to latest release.
- `-ud <dir>` — custom template install directory.
- `-duc` — disable automatic update checks.

## Chaining and Routing

Nuclei fits into recon-to-exploitation pipelines. Key chains:

**Subdomain → probe → scan:**
```
subfinder -d target.tld -silent | httpx -silent | nuclei -as -s critical,high -j -o full_pipeline.jsonl
```

**Port scan → nuclei:**
```
naabu -host target.tld -top-ports 1000 -silent | nuclei -as -j -o portscan_to_nuclei.jsonl
```

**Crawl → scan discovered endpoints:**
```
katana -u https://target.tld -d 3 -jc -silent -f url | nuclei -as -j -o crawl_scan.jsonl
```

**Uncover → scan (built-in, see Uncover section):**
```
nuclei -uc -uq "apache struts" -ue shodan -ul 200 -tags cve -s critical -j -o uncover_scan.jsonl
```

**Nuclei SARIF → CI/CD:**
Nuclei's `-se` SARIF export integrates directly with GitHub Code Scanning, GitLab SAST, and Azure DevOps. See `ci-security-scanning-with-zen` skill.

**Template-to-vulnerability-skill routing:**
Nuclei findings route to the corresponding vulnerability skill by class:
- `xss` tag → `xss.md`
- `sqli` tag → `sql_injection.md`
- `ssrf` tag → `ssrf.md`
- `rce` tag → `rce.md`
- `lfi` tag → `path_traversal_lfi_rfi.md`
- `ssti` tag → `ssti.md`
- `xxe` tag → `xxe.md`
- `idor` tag → `idor.md`
- `default-login`, `auth-bypass` → `authentication_jwt.md`, `broken_function_level_authorization.md`
- `misconfig` → `information_disclosure.md`
- `oast` findings → `ssrf.md`, `rce.md` (depending on callback type)

**Tool-to-tool chains:**
- httpx (`httpx.md`) → nuclei: httpx probes and filters live hosts; nuclei scans them.
- katana (`katana.md`) → nuclei: katana crawls endpoints; nuclei tests them.
- subfinder (`subfinder.md`) → httpx → nuclei: full subdomain pipeline.
- naabu (`naabu.md`) → nuclei: port discovery feeds nuclei targeting.
- nuclei → interactsh-client (`interactsh-client.md`): OAST correlation for blind vulnerability classes.
- nuclei → caido (`caido.md`): proxy nuclei traffic through Caido for request/response inspection.
- Stored responses from caido/agent_browser → nuclei `-passive`: offline analysis.
