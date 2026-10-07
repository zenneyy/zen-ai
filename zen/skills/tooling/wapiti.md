---
name: wapiti
description: Wapiti web vulnerability scanner — module/level selection, scope control, swagger-driven API scanning, and format options.
---

# wapiti CLI Playbook

Official docs:
- https://wapiti-scanner.github.io/
- https://github.com/wapiti-scanner/wapiti

Canonical syntax:
`wapiti -u <url> [options]` (or `--swagger <uri>` for OpenAPI/Swagger-driven, or `--list-modules` to list)

High-signal flags:
- `-u, --url <url>` base URL for the scan
- `--swagger <uri>` Swagger/OpenAPI file (path or URL) to target API endpoints
- `--data <data>` URL-encoded POST data to send with the base URL
- `--scope <url|page|folder|subdomain|domain|punk>` crawl scope (default `folder`)
- `-m, --module <list>` modules to run (comma-separated; `--list-modules` to enumerate)
- `-l, --level <level>` attack level (controls intensity per module)
- `-S, --scan-force <paranoid|sneaky|polite|normal|aggressive|insane>` throttle / request budget
- `-s, --start <url>` additional starting URL (repeatable)
- `-x, --exclude <url>` URL to exclude from scan
- `-r, --remove <param>` remove this parameter from URLs before attack
- `--skip <param>` do not attack this parameter
- `-d, --depth <n>` crawl depth
- `--max-links-per-page <n>` cap in-scope links per page
- `--max-files-per-dir <n>` cap pages explored per directory
- `--max-scan-time <sec>` global wall-clock cap (float)
- `--max-attack-time <sec>` per-module wall-clock cap
- `--max-parameters <n>` erase URLs/forms with more params than N before attack
- `--tasks <n>` crawl concurrency
- `--mitm-port <port>` run as an intercepting proxy instead of crawling (feed real traffic)
- `--headless <no|hidden|visible>` use a Firefox headless crawler
- `--wait <sec>` seconds to wait before analyzing a page (headless only)
- Auth (HTTP): `--auth-user <u>`, `--auth-password <p>`, `--auth-method <basic|digest|ntlm>`
- Auth (form): `--form-user <u>`, `--form-password <p>`, `--form-url <url>`, `--form-data <data>`, `--form-enctype <ct>`, `--form-script <file>` (custom Python auth plugin)
- Cookies: `-c <file>` (JSON or `firefox`/`chrome`), `-C <k=v;k=v>` cookie value, `--drop-set-cookie`
- Session: `--skip-crawl`, `--resume-crawl`, `--flush-attacks`, `--flush-session`, `--store-session <path>`, `--store-config <path>`
- Proxy: `-p, --proxy <url>` (HTTP(S)/SOCKS), `--tor` (Tor at `127.0.0.1:9050`)
- `-sf, --side-file <file>` Selenium IDE `.side` file for authenticated scans
- Output: `-f, --format <csv|html|json|md|txt|xml>` (default `html`), `-o, --output <path>` file/folder
- Detailed report: `-dr, --detailed-report <1|2>` (1 = HTTP requests only; 2 = requests + responses)
- `--log <file>` output log
- `-t, --timeout <sec>` request timeout
- `-H, --header <h>` custom header on every request
- `-A, --user-agent <ua>` custom UA
- `--verify-ssl <0|1>` SSL check (default 0)
- `--dns-endpoint <domain>` DNS endpoint for Log4Shell attack
- `--external-endpoint <url>` / `--internal-endpoint <url>` / `--endpoint <url>` OAST endpoints
- `--cms <drupal|joomla|prestashop|spip|wp>` CMS-targeted scan
- `--wapp-url <url>` / `--wapp-dir <dir>` custom Wappalyzer database location
- `--update` update modules and exit; `--list-modules` list modules; `--no-bugreport` disable auto bug reports
- `-v, --verbose <level>` 0 quiet / 1 normal / 2 verbose
- `--color` colorize

Agent-safe baseline for automation:
`wapiti -u https://target.tld --scope folder -S polite -l 1 --max-scan-time 1800 -f json -o wapiti.json --flush-session --verify-ssl 0 -v 1`

Common patterns:
- Baseline scan with JSON output:
  `wapiti -u https://target.tld -f json -o wapiti.json --flush-session`
- Swagger-driven API scan:
  `wapiti --swagger https://target.tld/openapi.json -f json -o wapiti_api.json --flush-session`
- POST-based base URL:
  `wapiti -u https://target.tld/api/search --data "query=test&page=1" -f json -o wapiti.json --flush-session`
- Narrower scope and level 2 attack intensity:
  `wapiti -u https://target.tld --scope page -l 2 -S polite -f json -o wapiti.json --flush-session`
- Scoped modules (sqli + xss + ssrf only):
  `wapiti -u https://target.tld -m sql,xss,ssrf -f json -o wapiti_focus.json --flush-session`
- Authenticated form-login scan:
  `wapiti -u https://target.tld --form-url https://target.tld/login --form-user admin --form-password hunter2 --form-data 'username=%USERNAME%&password=%PASSWORD%' -f json -o wapiti_auth.json --flush-session`
- MITM-mode (don't crawl; attack whatever traffic flows through the intercept proxy):
  `wapiti --mitm-port 8081 -f json -o wapiti_mitm.json --flush-session`
- CMS-targeted (WordPress):
  `wapiti -u https://target.tld --cms wp -f json -o wapiti_wp.json --flush-session`
- Detailed report with full requests + responses:
  `wapiti -u https://target.tld -f html -o wapiti_report -dr 2 --flush-session`
- Resume an interrupted scan:
  `wapiti -u https://target.tld --resume-crawl -f json -o wapiti.json`
- Headless JS-heavy scan:
  `wapiti -u https://target.tld --headless hidden --wait 3 --scope domain -f json -o wapiti_hl.json --flush-session`
- Full module sweep with OAST confirmation:
  `wapiti -u https://target.tld -m common,log4shell,xxe,ssrf,ldap --external-endpoint https://<id>.oast.pro --dns-endpoint <id>.oast.pro -f json -o wapiti_full.json --flush-session`
- Skip specific parameters:
  `wapiti -u https://target.tld --skip csrf_token --skip session_id -f json -o wapiti.json --flush-session`

Critical correctness rules:
- Pass `--flush-session` on fresh runs — wapiti caches crawled URLs and attack results per target in a session DB; stale sessions silently skip URLs.
- `--scope folder` (the default) means "only within the directory of `-u`" — if the app's attack surface lives above/beside, broaden to `domain`/`subdomain` deliberately.
- `-m <list>` **replaces** the default module set; run `--list-modules` first and compose the list explicitly. The keyword `common` selects all default modules.
- `-S` and `-l` interact: `-S polite -l 2` is a sensible agent baseline; `-S aggressive -l 3` is reserved for authorized destructive scans.
- `--verify-ssl 0` is the default — flip to `1` on TLS-pinned targets so wapiti reports cert errors instead of silently continuing.
- `--mitm-port` disables crawling entirely — wapiti waits for traffic routed through it. Point `agent-browser` / `curl` at that port to drive attacks over observed traffic.
- `--max-scan-time` is wall-clock; the scan stops mid-attack. Pin it in automation.
- OAST endpoints (`--external-endpoint`/`--internal-endpoint`/`--dns-endpoint`) must point to reachable OAST infrastructure (interactsh server, DNS canary). Without them, blind/Log4Shell modules can't confirm.
- `--data` sends its content as POST body with `-u`; the target URL must accept POST. Use `--form-enctype` to override the content type if the API expects JSON.
- `--skip` prevents attacking a parameter but still crawls it; `-r`/`--remove` strips it from URLs entirely before both crawl and attack. Use `--skip` for CSRF tokens and session IDs that must be present but not fuzzed.

Usage rules:
- Position vs. other scanners:
  - `tooling/nuclei.md` for template-driven CVE/misconfig coverage at scale — nuclei wins on breadth.
  - `tooling/sqlmap.md` for deep SQLi — sqlmap wins on technique coverage.
  - `wapiti` fills the single-target per-vuln-class scan gap: more module depth than nuclei on a focused target, broader than sqlmap.
- Prefer `-f json` for pipeline consumers; HTML is for human reports.
- Keep `-v 1` on in automation; `-v 2` is noisy.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- Scan completes instantly with no findings: `--flush-session` was missing; session cached a prior exhausted run.
- Form-auth never logs in: inspect wapiti's generated login requests (`-dr 2`), confirm `--form-data` matches the real body shape, consider `--form-script` for complex flows.
- MITM mode captures nothing: verify the client is actually using `--mitm-port` (e.g. `curl -x http://127.0.0.1:8081 ...`).
- Modules skipped: run `--list-modules` to confirm the module name is valid; names are lowercase and sometimes abbreviated (`sql`, not `sql_injection`).
- Blind module never confirms: configure OAST endpoints and verify the target can reach them (`--external-endpoint https://<interactsh>.oast.pro`).
- Headless mode crashes: ensure Firefox is installed in the sandbox; `--headless hidden` is the most stable mode. If it still fails, fall back to `--headless no` (default non-headless crawler).
- Scan runs too long: add `--max-scan-time` and `--max-attack-time` caps. Reduce scope with `--scope page` or tighter `-d` depth. Lower `-S` from `normal` to `polite` or `sneaky`.

If uncertain, query web_search with:
`site:wapiti-scanner.github.io wapiti <flag>` or `site:github.com/wapiti-scanner/wapiti`

## Module Reference

Wapiti ships 26 modules (v3.2.10). Modules marked *(default)* run when no `-m` is specified. The rest are opt-in. `-m common` selects all defaults; `-m <list>` replaces the defaults entirely.

**Injection modules — active payload injection into parameters:**

- `sql` *(default)* — SQL injection via error-based and boolean-based (blind) techniques. Also tests for XPath injection. Level affects payload count and injection point breadth.
  Routes to: `vulnerabilities/sql_injection.md`
- `timesql` — time-based blind SQL injection. Separate from `sql` because time-based payloads are slower and noisier. Opt-in when boolean/error-based detection fails on a suspected injectable parameter.
  Routes to: `vulnerabilities/sql_injection.md`
- `exec` *(default)* — command injection and code execution. Tests for OS command injection (`; id`, `` `id` ``, `$(id)`) and PHP code injection (`eval`, `assert`).
  Routes to: `vulnerabilities/rce.md`
- `file` *(default)* — directory traversal (`../../etc/passwd`), local file inclusion (LFI), and remote file inclusion (RFI). Level controls traversal depth and inclusion payload variety.
  Routes to: `vulnerabilities/path_traversal_lfi_rfi.md`
- `xss` *(default)* — reflected and stored cross-site scripting. Injects script payloads into all parameters and checks for reflection in the response body. Works alongside `permanentxss`.
  Routes to: `vulnerabilities/xss.md`
- `permanentxss` *(default)* — stored (persistent) XSS. Submits payloads via forms, then revisits other pages to detect the stored payload rendering. Requires a crawl phase that discovered multiple pages to cross-check.
  Routes to: `vulnerabilities/xss.md`
- `ssrf` *(default)* — server-side request forgery. Injects internal/external URLs into parameters. OAST-dependent: uses `--external-endpoint` to detect out-of-band callbacks. Without an endpoint, relies on response-based detection only.
  Routes to: `vulnerabilities/ssrf.md`
- `xxe` — XML external entity injection. Sends crafted XML payloads; detects via error messages or OAST callback (`--external-endpoint`). Opt-in because it requires XML-accepting endpoints.
  Routes to: `vulnerabilities/xxe.md`
- `ldap` — LDAP injection. Injects LDAP filter syntax into parameters. Opt-in; relevant when the target queries LDAP directories.
- `crlf` — carriage return / line feed injection. Injects `%0d%0a` sequences to test for header injection. Opt-in.
  Routes to: `vulnerabilities/header_injection.md`
- `upload` *(default)* — unrestricted file upload. Tests file upload forms for missing extension/content-type validation. Uploads test files and checks whether they execute or are served.
  Routes to: `vulnerabilities/insecure_file_uploads.md`

**Detection modules — detect specific vulnerabilities or misconfigurations:**

- `log4shell` — CVE-2021-44228 (Log4Shell). Injects `${jndi:ldap://...}` payloads. OAST-dependent: **requires** `--dns-endpoint` to confirm exploitation via DNS callback. Without it, payloads are sent but confirmation is impossible.
  `wapiti -u https://target.tld -m log4shell --dns-endpoint <id>.oast.pro -f json -o wapiti_log4j.json --flush-session`
- `shellshock` — CVE-2014-6271 (ShellShock). Tests CGI-like endpoints via crafted `User-Agent`/`Referer` headers. Opt-in.
- `spring4shell` — Spring4Shell (CVE-2022-22965). Tests for the classLoader parameter manipulation. Opt-in.
- `ssl` *(default)* — evaluates SSL/TLS certificate configuration: expiry, self-signed certs, weak protocols, cipher suites.
- `takeover` — subdomain takeover detection. Checks CNAME records pointing to non-existent or claimable domains (S3, Heroku, GitHub Pages, etc.). Opt-in; most useful after subdomain enumeration.
  Routes to: `vulnerabilities/subdomain_takeover.md`
- `methods` — detects uncommon HTTP methods (PUT, DELETE, TRACE, etc.) allowed by scripts. Opt-in.
- `htaccess` — attempts to bypass access controls by using custom HTTP methods (e.g., `GETS` instead of `GET`). Tests whether `.htaccess` Limit directives are misconfigured. Opt-in.
- `backup` — probes for backup files (`.bak`, `.old`, `.swp`, `~`, `.orig`, `.save`) of discovered pages. Opt-in.
  Routes to: `vulnerabilities/information_disclosure.md`
- `nikto` — brute-forces known dangerous scripts/paths from the Nikto database. Opt-in; similar to `buster` but uses a known-dangerous-files list.
- `buster` — brute-forces hidden directories and files. Opt-in; uses an internal wordlist.
- `brute_login_form` — attempts weak credential pairs (admin/admin, admin/password, etc.) against discovered login forms. Opt-in.
  Routes to: `vulnerabilities/weak_password_detection.md`

**Fingerprinting modules — identify technologies without attacking:**

- `wapp` — identifies web technologies via Wappalyzer database (frameworks, CMS, server software, JavaScript libraries). Not an attack module. Use `--wapp-url`/`--wapp-dir` to update the database.
- `htp` — identifies technologies via the HashThePlanet database. Alternative fingerprinting approach to `wapp`.
- `cms` — detects CMS version (base class). Works with `--cms` flag for targeted CMS scanning.
- `wp_enum` — WordPress-specific: enumerates installed plugins and their versions. Identifies plugins with known CVEs. Works best with `--cms wp`.
- `network_device` — detects network device types and versions (routers, switches, firewalls). Opt-in.

**Other vulnerability modules:**

- `redirect` *(default)* — open redirect detection. Tests parameters for URL redirect manipulation.
  Routes to: `vulnerabilities/open_redirect.md`
- `csrf` — detects forms missing anti-CSRF tokens. Does not inject payloads; analyzes form structure. Opt-in.
  Routes to: `vulnerabilities/csrf.md`

Module composition examples:
- All defaults: `-m common` (or omit `-m`)
- Injection-heavy pass: `-m sql,timesql,xss,permanentxss,exec,file,ssrf,xxe,ldap,crlf`
- Detection-only pass: `-m log4shell,shellshock,spring4shell,ssl,takeover,methods,backup`
- Fingerprint-only: `-m wapp,htp,cms,wp_enum`

Module interaction notes:
- `sql` + `timesql`: run `sql` first (faster). If `sql` finds nothing on a suspected injectable parameter, add `timesql` for time-based confirmation. Running both simultaneously is valid but slower.
- `xss` + `permanentxss`: both default-on. `xss` catches reflected; `permanentxss` cross-checks stored payloads across pages. `permanentxss` is only effective when the crawl discovered multiple pages (single-page scans get reflected-only coverage).
- `ssrf` + `xxe`: both inject URLs, but `ssrf` targets parameters while `xxe` targets XML bodies. On an API that accepts XML, run both.
- `wapp` + `cms` + `wp_enum`: `wapp` fingerprints technologies generically; `cms` identifies CMS version; `wp_enum` enumerates WordPress plugins/themes. For WordPress targets: `-m common,wapp,cms,wp_enum --cms wp`.
- `nikto` + `buster` + `backup`: all do path brute-forcing with different databases. `nikto` uses known-dangerous scripts; `buster` uses a generic wordlist; `backup` probes for backup copies of crawled files. For thorough path discovery, run all three — but expect high request volume.

## Scope Mechanics

`--scope` controls how far wapiti crawls from the base URL (`-u`). The scope governs both which links are followed during crawl and which URLs are attacked.

- `url` — attack only the exact base URL. No crawling at all. Use with `--data` for POST-only testing of a single endpoint.
  `wapiti -u https://target.tld/api/search --scope url --data "q=test" -m sql,xss -f json -o wapiti.json --flush-session`
- `page` — attack the base URL and any URL on the same page (same path, different query parameters). Minimal crawl.
  `wapiti -u https://target.tld/app/dashboard --scope page -f json -o wapiti.json --flush-session`
- `folder` (default) — attack URLs under the same directory as the base URL. `/app/` stays within `/app/*`; won't crawl `/admin/` or `/api/` unless they're under `/app/`.
- `subdomain` — attack URLs on the same subdomain. `app.target.tld` stays on `app.target.tld`, won't follow links to `www.target.tld`.
- `domain` — attack URLs anywhere on the domain. `app.target.tld` can follow links to `www.target.tld`, `api.target.tld`, etc. Use for full-site assessments.
  `wapiti -u https://target.tld --scope domain -f json -o wapiti.json --flush-session`
- `punk` — no scope restriction. Follow and attack all discovered links regardless of domain. **Dangerous in production** — will crawl off-site. Use only in isolated environments.

Common mistake: using `-u https://target.tld/` with default `folder` scope. The trailing `/` means the folder is the root, so `folder` and `domain` behave identically for root URLs. The distinction matters for deep paths: `-u https://target.tld/app/v2/` with `folder` scope stays under `/app/v2/`.

Use `-x` (exclude) alongside broad scopes to carve out known-bad paths:
`wapiti -u https://target.tld --scope domain -x https://target.tld/logout -x https://target.tld/api/delete -f json -o wapiti.json --flush-session`

## Crawl Tuning

The crawl phase discovers the attack surface. These flags control its breadth and depth:

- `-d, --depth <n>` — maximum link depth from the start URL. Default is unlimited within scope. Set to `3`–`5` for most applications; deeper crawls on large sites can run for hours.
- `--max-links-per-page <n>` — cap the number of in-scope links extracted per page. Prevents explosion on pages with dense link tables (sitemaps, indexes). A reasonable cap is `50`–`100`.
- `--max-files-per-dir <n>` — cap pages explored per directory path. Prevents over-crawling a single directory with many similar pages (e.g., `/products/1` through `/products/10000`).
- `--max-parameters <n>` — discard URLs/forms with more than N parameters before attack. Complex forms with dozens of parameters generate exponential payload combinations; cap at `10`–`20` to prevent scan explosion.
- `--tasks <n>` — concurrent crawl tasks. Higher values speed up crawling but increase server load. Default is conservative; `4`–`8` is reasonable for most targets.

These interact with `-S` (scan force): `-S polite` reduces the number of URL variations attacked, but the crawl phase still discovers them all. Crawl tuning limits what gets discovered; scan force limits what gets attacked from the discovered set.

Recommended agent crawl config for medium sites:
`wapiti -u https://target.tld --scope domain -d 5 --max-links-per-page 100 --max-files-per-dir 10 --max-parameters 15 --tasks 4 -S polite -f json -o wapiti.json --flush-session`

## Swagger / API Scanning

`--swagger <uri>` accepts a Swagger 2.0 or OpenAPI 3.x specification (local file path or URL). Wapiti parses the spec to discover API endpoints, methods, and parameter schemas, then attacks them using the selected modules — bypassing the crawler entirely for API surface discovery.

Use cases:
- The API has no web UI to crawl.
- The crawler misses API endpoints behind authentication or non-standard routing.
- You want deterministic endpoint coverage matching the spec.

```
wapiti --swagger https://target.tld/openapi.json -m sql,xss,ssrf -f json -o wapiti_api.json --flush-session
```

Swagger + POST data: for endpoints the spec defines as POST, wapiti generates request bodies from the schema. For endpoints not in the spec, combine `--swagger` with `-u` and `--data`:
```
wapiti --swagger https://target.tld/openapi.json -u https://target.tld/api/legacy --data "key=value" -f json -o wapiti_api.json --flush-session
```

Limitations: wapiti does not generate complex nested JSON payloads from OpenAPI schemas — it extracts endpoints and parameters but injects its own payloads. For deep API testing with schema-aware fuzzing, pair with dedicated API fuzzers and use wapiti for injection testing.

Authentication with Swagger: most APIs require auth. Combine `--swagger` with cookie or header-based auth:
```
wapiti --swagger https://target.tld/openapi.json -H "Authorization: Bearer <token>" -f json -o wapiti_api.json --flush-session
```

## Attack Levels and Scan Force

`-l <level>` and `-S <force>` interact to control payload count and request volume.

**Attack level (`-l`):** Controls the depth and aggressiveness of payload injection per module. The exact behavior is module-specific, but the general pattern:

- Level 1 (default) — basic payloads against parameters directly visible in the URL or form. Minimal injection point breadth.
- Level 2 — adds payloads to cookie values, HTTP headers (Referer, User-Agent) in addition to GET/POST parameters. More payload variants per injection point.
- Higher levels add increasingly exotic injection points and payload variations. The payload count per parameter grows with each level.

Levels interact with modules differently: `sql` at level 2 injects into cookies and headers; `xss` at level 2 tests additional encoding bypass payloads; `file` at level 2 tries deeper traversal paths. The effect is always more requests per parameter.

**Scan force (`-S`):** Controls how many URLs/forms wapiti attacks. Wapiti uses a reduction formula: the more parameters a URL pattern has, the fewer variations of that pattern it will attack. `-S` scales this formula:

- `paranoid` — minimal request budget. Attacks very few URL variations. For fragile targets or first-pass validation.
- `sneaky` — low budget, more than paranoid.
- `polite` — moderate budget. Good default for agent use: balances coverage with request volume.
- `normal` (default) — standard budget. Attacks most discovered URL/parameter combinations.
- `aggressive` — high budget. Attacks nearly all variations.
- `insane` — no reduction. Every discovered URL/parameter combination is attacked. Generates the most traffic; use only on authorized targets with known capacity.

**Practical tuning:**
- Agent baseline: `-S polite -l 1` — good coverage without flooding.
- Thorough single-target: `-S normal -l 2` — attacks cookies/headers, standard URL reduction.
- Authorized deep scan: `-S aggressive -l 2` — near-complete parameter coverage with extended injection points.
- Maximum coverage: `-S insane -l 3` — every URL, every parameter, extended payloads. Very noisy.

`--max-scan-time` and `--max-attack-time` are independent of `-S`/`-l` and act as hard time caps regardless of how many URLs remain.

## MITM Proxy Mode

`--mitm-port <port>` switches wapiti from crawl-and-attack to intercept-and-attack mode. Wapiti launches an intercepting proxy on the specified port, captures all traffic routed through it, then attacks the captured endpoints using the selected modules.

When to use MITM mode:
- The application requires complex navigation (multi-step wizards, WebSocket flows, OAuth) that the crawler cannot reproduce.
- You want to attack only the endpoints your manual browsing touched, not the full crawled surface.
- You're driving traffic via `agent-browser` and want vulnerability scanning on the browsed surface.

Workflow:
1. Start wapiti in MITM mode:
   `wapiti --mitm-port 8081 -m sql,xss,ssrf -f json -o wapiti_mitm.json --flush-session`
2. Route browser/client traffic through it:
   `curl -x http://127.0.0.1:8081 https://target.tld/api/endpoint`
   Or configure `agent-browser` to use the MITM port.
3. Stop routing traffic (Ctrl+C or close the client). Wapiti begins attacking all captured endpoints.

HTTPS in MITM mode: wapiti's MITM proxy intercepts HTTPS by generating certificates on the fly. Clients routed through it must either trust wapiti's CA certificate or disable certificate verification (`curl -k -x ...`). The `agent-browser` can be configured to ignore cert errors; for other clients, export wapiti's CA cert from its data directory and install it as a trusted root.

MITM + Caido chaining: wapiti's MITM proxy and the sandbox's Caido proxy serve different roles. Caido captures and replays traffic for manual inspection; wapiti's MITM attacks captured traffic. To chain them, route wapiti's outbound attack traffic through Caido:
`wapiti --mitm-port 8081 -p http://127.0.0.1:48080 -m sql,xss -f json -o wapiti_mitm.json --flush-session`
This captures the original traffic on port 8081, attacks it, and routes the attack requests through Caido on 48080 for traffic inspection.

## Headless Mode

`--headless <no|hidden|visible>` controls whether wapiti uses a Firefox headless browser for crawling instead of its default HTTP-only crawler.

- `no` (default) — standard HTTP crawler. Fast. Misses JS-rendered content, SPAs, and dynamic DOM.
- `hidden` — Firefox headless in background. Renders JavaScript, discovers AJAX-loaded endpoints and client-side routes. Slower but catches what the HTTP crawler misses.
- `visible` — Firefox with visible window. For debugging crawl behavior — you can watch the browser navigate.

`--wait <sec>` adds a delay before wapiti analyzes each page in headless mode. Necessary for SPAs that render asynchronously. Start with `--wait 2`; increase for heavy applications.

Headless + authentication: combine `--headless hidden` with `-sf` (Selenium IDE `.side` file) to replay a recorded login flow in the headless browser before crawling the authenticated surface.

Framework-specific notes:
- React/Vue/Angular SPAs: `--headless hidden --wait 3` is usually sufficient. Increase `--wait` to `5` for applications with heavy API-driven rendering.
- Sites with infinite scroll: wapiti does not scroll the page in headless mode. Links loaded by scroll events are missed. For these, use MITM mode with manual browsing instead.
- Sites requiring WebSocket: headless mode can establish WebSocket connections but wapiti does not inject into WebSocket frames. Use headless for discovery, then test WebSocket endpoints separately.

Performance impact: headless crawling is significantly slower (5–10x) than HTTP crawling. Use `--max-scan-time` to bound it. Reserve headless for JS-heavy SPAs where the HTTP crawler returns a thin crawl surface.

`wapiti -u https://target.tld --headless hidden --wait 3 --scope domain --max-scan-time 3600 -f json -o wapiti_hl.json --flush-session`

## Authentication

Wapiti supports four authentication methods. Choose by context:

**HTTP authentication** — for targets behind Basic/Digest/NTLM auth:
```
wapiti -u https://target.tld --auth-user admin --auth-password secret --auth-method basic -f json -o wapiti.json --flush-session
```
The deprecated `-a user%password` form still works but prefer the explicit flags.

**Form-based authentication** — for login forms (the most common case):
```
wapiti -u https://target.tld \
  --form-url https://target.tld/login \
  --form-user admin --form-password hunter2 \
  --form-data 'username=%USERNAME%&password=%PASSWORD%' \
  -f json -o wapiti.json --flush-session
```
`%USERNAME%` and `%PASSWORD%` are placeholders replaced by `--form-user` and `--form-password`. `--form-enctype` overrides the Content-Type (default `application/x-www-form-urlencoded`); set to `application/json` for API login endpoints, with `--form-data` as JSON: `--form-data '{"user":"%USERNAME%","pass":"%PASSWORD%"}'`.

**Custom Python auth plugin** — for complex auth flows (OAuth, MFA, CAPTCHA bypass):
`--form-script <file>` loads a Python script that implements the authentication. Use when form-based auth can't handle the flow. The script must follow wapiti's plugin API.

**Cookie-based authentication** — for pre-authenticated sessions:
- `-c <file>` loads cookies from a JSON file, or pass `firefox` / `chrome` to load cookies from the installed browser's cookie store.
- `-C 'session=abc123; token=xyz'` injects specific cookie values into every request.
- `--drop-set-cookie` prevents wapiti from accepting new cookies from responses, preserving the injected session throughout the scan.

**Selenium IDE (.side) authentication** — for recorded browser flows:
`-sf auth_flow.side` replays a Selenium IDE recording. Works with headless mode. Record the login in Selenium IDE, export as `.side`, pass to wapiti.

## OAST Integration

Wapiti's blind detection modules (log4shell, ssrf, xxe) rely on out-of-band callbacks to confirm exploitation. Without OAST endpoints, these modules can inject payloads but cannot distinguish between "payload was processed" and "payload was silently dropped."

Three endpoint flags:
- `--external-endpoint <url>` — URL reachable by the target for HTTP-based callbacks. The target's server makes an HTTP request to this endpoint if the payload triggers. Used by `ssrf` and `xxe`.
- `--internal-endpoint <url>` — URL reachable by the attacker for receiving callback data. If the external endpoint collects callbacks, this is where wapiti retrieves them.
- `--endpoint <url>` — shorthand: sets both external and internal to the same URL. Use when attacker and target can reach the same host.
- `--dns-endpoint <domain>` — DNS domain for DNS-based callbacks. **Required for `log4shell`** (JNDI payloads trigger DNS lookups). Used by `ssrf` for DNS-only OAST confirmation.

Integration with interactsh:
```
interactsh-client -v &
# note the assigned subdomain, e.g. abc123.oast.pro
wapiti -u https://target.tld -m log4shell,ssrf,xxe \
  --external-endpoint https://abc123.oast.pro \
  --dns-endpoint abc123.oast.pro \
  -f json -o wapiti_oast.json --flush-session
```
Monitor `interactsh-client` output for DNS/HTTP callbacks that confirm exploitation.

Without OAST: modules still run but report as "potential" rather than "confirmed." Prefer configuring OAST for blind modules — a confirmed finding is qualitatively different from a potential one.

## CMS-Targeted Scanning

`--cms <drupal|joomla|prestashop|spip|wp>` activates CMS-specific detection paths:

- `wp` — WordPress: activates `wp_enum` (plugin and theme enumeration with version detection), checks for known WordPress-specific vulnerabilities, tests `wp-login.php`, `xmlrpc.php`, `wp-json/` API. Combine with `brute_login_form` for wp-admin credential testing.
  `wapiti -u https://target.tld --cms wp -m common,wp_enum,brute_login_form -f json -o wapiti_wp.json --flush-session`
- `drupal` — Drupal: checks for Drupal-specific endpoints (`/CHANGELOG.txt`, `/core/CHANGELOG.txt`), version detection, known module paths.
- `joomla` — Joomla: version fingerprinting, admin path detection, known extension paths.
- `prestashop` — PrestaShop: version detection, admin panel discovery.
- `spip` — SPIP: version fingerprinting and CMS-specific vulnerability checks.

`--cms` selects the CMS and activates the `cms` base module. Combine with `-m` to run injection modules alongside CMS detection. `--cms` does not replace `-m`; it adds CMS-specific behavior to whatever modules are selected.

## Detection Fingerprint

How wapiti traffic appears to defenders and what this means operationally:

**User-Agent:** wapiti identifies itself by default as `Wapiti/<version>` (e.g. `Wapiti/3.2.10`). Override with `-A` for a realistic UA string. WAFs with UA-based blocking will catch the default immediately.

**Crawl pattern:** wapiti's crawl phase generates rapid sequential requests following the link graph from `-u`. The pattern is distinguishable from human browsing by its speed, depth-first traversal, and lack of asset loading (no CSS/JS/image fetches unless headless). Rate-based IDS triggers on the request volume; `-S sneaky`/`paranoid` reduces this.

**Attack signatures:** injection payloads are recognizable by WAF signature sets. `sql` module payloads include `SLEEP()`, `BENCHMARK()`, `' OR '1'='1`, UNION SELECT, and error-triggering functions. `xss` payloads include `<script>`, `onerror=`, `javascript:`. `exec` payloads include `; id`, backtick injection, `$(command)`. `file` payloads include `../../etc/passwd` traversal strings.

**Reducing the fingerprint:**
- `-A <realistic_ua>` — swap the default UA.
- `-S sneaky` or `-S paranoid` — reduce request rate.
- `-t <higher_timeout>` — slower crawl reduces burst detection.
- `--tasks 1` — single-threaded crawl.
- `-p http://127.0.0.1:48080` — route through Caido, which can modify headers.
- `--tor` — route through Tor for source IP obfuscation. Slow but effective against IP-based blocking.

These are situational mitigations, not guaranteed evasion. WAFs with payload-level inspection (ModSecurity CRS, AWS WAF, Cloudflare) will still catch common injection signatures regardless of rate or UA.

WAF interaction patterns:
- If the target returns 403/block pages on attack payloads, wapiti may report "403 Forbidden" as false positive findings. Check the response body in `-dr 2` output to distinguish WAF blocks from genuine access control.
- Wapiti does not have built-in WAF bypass techniques (unlike sqlmap's `--tamper`). For WAF-protected targets, use wapiti for discovery/fingerprinting (`-m wapp,htp,ssl,methods`) and route confirmed injectable parameters to `tooling/sqlmap.md` with tamper scripts for exploitation.
- Run `tooling/wafw00f.md` first to identify the WAF technology, then decide whether wapiti's default payloads are worth running or will be entirely blocked.

## Session Management

Wapiti persists crawl and attack state in a session database. Understanding session mechanics prevents silent re-use of stale data.

- `--flush-session` — deletes all session data for the target (crawled URLs, discovered parameters, attack results, vulnerability findings). **Use on every fresh scan.** Without it, wapiti resumes from cached data and may skip URLs or attacks already performed.
- `--flush-attacks` — clears only attack history and vulnerability findings, keeping the crawled URL set. Use when you want to re-attack the same crawled surface with different modules or levels without re-crawling.
- `--resume-crawl` — resumes both crawling and attacking from where the last run stopped. Use when a scan was interrupted (timeout, Ctrl+C) and you want to continue. Will re-run attacks on pages already crawled if `--flush-attacks` is also passed.
- `--skip-crawl` — skips crawling entirely; attacks only URLs already in the session from a previous crawl. Use when the crawl phase completed but the attack phase was interrupted.
- `--store-session <path>` — custom directory for session storage. Default is wapiti's data directory. Use when running multiple scans in parallel to avoid session conflicts.
- `--store-config <path>` — custom directory for configuration databases (Wappalyzer, HashThePlanet). Separate from session storage.

Decision tree:
- Fresh scan: `--flush-session`
- Same surface, different modules: `--flush-attacks` (keep crawl, re-attack)
- Interrupted scan: `--resume-crawl`
- Re-attack only: `--skip-crawl` + `--flush-attacks`

Parallel scan isolation: when scanning multiple targets concurrently (e.g., from different agent tasks), use `--store-session <path>` with a unique directory per target. Without it, all scans share the default session directory and may corrupt each other's state.
```
wapiti -u https://target1.tld --store-session /tmp/wapiti_sessions/target1 -f json -o wapiti_t1.json --flush-session &
wapiti -u https://target2.tld --store-session /tmp/wapiti_sessions/target2 -f json -o wapiti_t2.json --flush-session &
```

Two-pass workflow: crawl first, then attack with different module sets against the same crawled surface:
```
# Pass 1: crawl + default modules
wapiti -u https://target.tld --scope domain -S polite -f json -o wapiti_pass1.json --flush-session
# Pass 2: keep crawl, swap in opt-in modules
wapiti -u https://target.tld --skip-crawl --flush-attacks -m xxe,log4shell,timesql,ldap,shellshock --dns-endpoint <id>.oast.pro -f json -o wapiti_pass2.json
```

## Output and Reporting

Wapiti supports six output formats via `-f`:
- `json` — structured JSON. Best for automation and pipeline parsing. One file.
- `html` (default) — human-readable HTML report with vulnerability details, affected URLs, and payload used. Output is a directory.
- `xml` — structured XML.
- `csv` — comma-separated values.
- `md` — Markdown.
- `txt` — plain text.

`-dr 1` includes the HTTP request that triggered each finding. `-dr 2` includes both request and response. Use `-dr 2` for debugging false positives and verifying exploitation.

`--log <file>` writes wapiti's internal log (crawl progress, module activity, errors) to a file, independent of the scan report.

Parsing JSON output:
```
cat wapiti.json | python3 -c "import json,sys; d=json.load(sys.stdin); [print(v['method'],v['path'],c) for c in d.get('vulnerabilities',{}) for v in d['vulnerabilities'][c]]"
```

## Chaining and Routing

Wapiti sits between reconnaissance and deep exploitation in the engagement workflow:

**Inbound chains:**
- `tooling/httpx.md` → wapiti: httpx confirms live hosts and tech stack; wapiti scans the confirmed targets. Pipe httpx JSON output to extract URLs for wapiti.
- `tooling/katana.md` / `tooling/gospider.md` → wapiti: crawlers discover the full URL surface; feed discovered URLs via `-s` (additional start URLs) or use `--skip-crawl` on a session seeded by the crawler.
- `tooling/arjun.md` → wapiti: Arjun discovers hidden parameters; feed them to wapiti for injection testing via `--data` or by constructing URLs with the discovered parameters.

**Outbound chains:**
- wapiti SQL findings → `tooling/sqlmap.md`: wapiti detects SQL injection; sqlmap confirms and exploits. Extract the vulnerable URL and parameter from wapiti's JSON output, pass to sqlmap via `-u` and `-p`.
- wapiti XSS findings → manual validation via `tooling/caido.md`: replay the finding's request in Caido, verify the payload renders.
- wapiti SSRF/XXE findings → `tooling/interactsh-client.md`: if wapiti's OAST detection was off, re-test with interactsh for out-of-band confirmation.

**Routing to vulnerability skills:**
- `vulnerabilities/sql_injection.md` (sql, timesql modules)
- `vulnerabilities/xss.md` (xss, permanentxss modules)
- `vulnerabilities/ssrf.md` (ssrf module)
- `vulnerabilities/csrf.md` (csrf module)
- `vulnerabilities/xxe.md` (xxe module)
- `vulnerabilities/open_redirect.md` (redirect module)
- `vulnerabilities/path_traversal_lfi_rfi.md` (file module)
- `vulnerabilities/rce.md` (exec module)
- `vulnerabilities/header_injection.md` (crlf module)
- `vulnerabilities/information_disclosure.md` (backup module)
- `vulnerabilities/insecure_file_uploads.md` (upload module)
- `vulnerabilities/weak_password_detection.md` (brute_login_form module)
- `vulnerabilities/subdomain_takeover.md` (takeover module)
- `tooling/nuclei.md` (broader templated scanning)
- `tooling/sqlmap.md` (deeper SQLi)
- `tooling/caido.md` (`--proxy` and MITM mode integrate with Caido)
- `tooling/interactsh-client.md` (`--external-endpoint`/`--dns-endpoint` for blind confirmation)
