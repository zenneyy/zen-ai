---
name: wafw00f
description: wafw00f WAF/CDN fingerprinting syntax, signature targeting, and output patterns for feeding evasion decisions.
---

# wafw00f CLI Playbook

Official docs:
- https://github.com/EnableSecurity/wafw00f
- https://github.com/EnableSecurity/wafw00f/wiki

Canonical syntax:
`wafw00f [options] <url1> [url2 ...]`

## Complete Flag Reference (wafw00f v2.4.2, verified in zen-sandbox 1.2.2)

Discovery:
- `-a, --findall` do not stop at the first signature match — list every WAF/CDN the fingerprints hit
- `-l, --list` print every WAF signature the binary knows (useful for `-t` targeting)
- `-t, --test <name>` test for one specific WAF (quote names with spaces, e.g. `"AireeCDN (Airee)"`)

Input:
- `<url1> [url2 ...]` positional URL targets
- `-i, --input-file <file>` batch targets from a file (csv/json/text; csv/json need a `url` column/element)

Output:
- `-o, --output <file>` write to file (format inferred from extension: `.csv`/`.json`/`.txt`; `-` for stdout)
- `-f, --format <csv|json|text>` force output format regardless of extension
- `--no-colors` disable ANSI colors (automation)

Connection:
- `-p, --proxy <url>` proxy requests (`http://host:port`, `socks5://host:port`, `http://user:pass@host:port`)
- `-H, --headers <file>` custom headers from file (overwrites the default header set)
- `-T, --timeout <sec>` per-request timeout
- `-r, --noredirect` do not follow 3xx redirections

Info:
- `-v, --verbose` verbose (`-v`/`-vv` increase verbosity)
- `-V, --version` print version

## Agent-Safe Baseline

`wafw00f -a -T 10 -f json -o wafw00f.json https://target.tld`

## Common Patterns

Single-URL fingerprint:
`wafw00f https://target.tld`

All-matching fingerprint pass (don't stop at the first hit — some stacks sit behind two WAFs):
`wafw00f -a -f json -o wafw00f.json https://target.tld`

Batch over discovered live hosts:
`wafw00f -i live_hosts.txt -a -f json -o wafw00f.json`

Target one specific WAF (confirm/deny a hypothesis):
`wafw00f -t "Cloudflare" https://target.tld`

Explicitly proxied (route through Caido for inspection — the sandbox env already does this transparently, flag is for isolation):
`wafw00f -a -p http://127.0.0.1:8080 -o wafw00f.json https://target.tld`

List the full signature database:
`wafw00f -l`

Verbose run to see probe-level reasoning:
`wafw00f -a -vv -f json -o wafw00f.json https://target.tld`

Multi-URL from CLI (no file needed for small sets):
`wafw00f -a -f json -o wafw00f.json https://app.target.tld https://api.target.tld https://admin.target.tld`

Text-only output (name and status, grep-friendly):
`wafw00f -a -f text -o - https://target.tld`

## Critical Correctness Rules

- wafw00f fingerprints **by behavioral signature** — a positive match says "the stack behaved like <WAF>", not "the stack is <WAF>". Multiple matches with `-a` are the honest shape; a single match without `-a` can hide a second layer.
- No-match ≠ no-WAF. Several modern WAFs (particularly cloud API gateways, custom Lua stacks, Cloud WAF-as-a-service tiers) do not emit distinctive signatures. Treat a clean result as "unknown WAF", not "no WAF".
- `-f json` is the only format that preserves confidence/method; `.txt` is name-only.
- `-H` **overwrites** the default header set — most signatures depend on specific requests the defaults send; override only when you know what you're doing.
- The sandbox env already routes outbound HTTP through Caido via `http_proxy`; `-p` is only needed when you want to override that (e.g. second proxy, direct connection).

## Usage Rules

- Run wafw00f once per target before fuzzing/injection — the WAF identity gates throttle, evasion payload sets, and whether to assume blocking.
- Keep `-a` on in automation; the extra wall-clock is small and the second match is often the real one.
- Feed `-i <file>` for multi-host engagements; piping URLs via stdin is not supported.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

---

## Probe Methodology — How wafw00f Detects WAFs

### Probe payloads

wafw00f sends a sequence of requests with hardcoded attack payloads designed to trigger WAF blocking behavior. The exact payloads (from `main.py`):

| Probe | Payload | Delivery |
|---|---|---|
| XSS | `<script>alert("XSS");</script>` | Query parameter with random name |
| SQLi | `UNION SELECT ALL FROM information_schema AND " or SLEEP(5) or "` | Query parameter with random name |
| LFI | `../../etc/passwd` | Appended to URL path |
| RCE | `/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com` | Query parameter with random name |
| XXE | `<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>` | Query parameter with random name |
| Central | XSS + SQLi + LFI combined in one request, each in a separate random-named parameter | Multi-parameter query |

### Detection sequence

1. **Normal request** — baseline response (status, headers, cookies, body).
2. **Central attack** — single request combining XSS, SQLi, and LFI payloads in separate parameters. This is the primary detection request; every plugin runs against both the normal response and the attack response.
3. **Plugin evaluation** — each loaded plugin's `is_waf()` runs against both responses using the detection API. With `-a`, all 172 plugins run; without it, the first match stops.
4. **Generic detection** (runs after plugins, or if no plugin matched) — compares normal vs. attack responses for: status-code changes (XSS, LFI, SQLi probes individually), `Server` header changes, UA-stripped response divergence, connection resets.

### Detection API (what plugins use)

Each plugin combines these methods to identify its WAF:

- `matchHeader(('header_name', 'regex'), attack=False)` — regex match against a response header value (case-insensitive). `attack=True` checks the attack response instead of the normal response.
- `matchCookie('regex')` — shortcut for `matchHeader(('Set-Cookie', regex))`. Matches against cookie names/values in Set-Cookie headers.
- `matchContent('regex', attack=True)` — regex match against response body (case-insensitive). Defaults to attack response because WAF block pages appear only on malicious requests.
- `matchStatus(code, attack=True)` — exact status-code match.
- `matchReason('string', attack=True)` — exact match on HTTP reason phrase (e.g. `ModSecurity Action`).

Plugins typically check the normal response for passive indicators (server headers, cookies set on clean requests) and the attack response for active indicators (block pages, error messages, status-code changes).

### Generic detection (fallback)

When no plugin matches, wafw00f runs generic WAF detection — a series of behavioral tests that don't identify a specific product but indicate that *some* WAF is present:

1. **UA-stripped response test:** Remove the `User-Agent` header and compare the response code to baseline. Many WAFs block or challenge UA-less requests.
2. **XSS probe:** Send `<script>alert("XSS");</script>` in a query param — compare status code to baseline.
3. **LFI probe:** Append `../../etc/passwd` to the URL path — compare status code.
4. **SQLi probe:** Send `UNION SELECT ALL FROM information_schema AND " or SLEEP(5) or "` — compare status code.
5. **Server header divergence:** Compare the `Server` header between normal and attack responses. A WAF that replaces or removes the `Server` header on block responses reveals itself.
6. **Connection reset:** If any probe causes a connection drop (TCP RST or timeout), this indicates packet-level WAF filtering.

A generic detection result means "a WAF is present but unidentified" — proceed with broad-spectrum evasion techniques (cross-DB tampers, moderate rate limiting).

### Random parameter names

wafw00f generates random 8-character lowercase parameter names for each probe (e.g. `?kxmzrtqw=<payload>`). This prevents WAFs that whitelist known parameter names from ignoring the probes, and prevents WAFs that track parameter names across requests from correlating probes into a single scan pattern.

---

## WAF Detection Catalog — Major Signatures

wafw00f v2.4.2 in zen-sandbox 1.2.2 carries **172 WAF/CDN signatures** (defined in `wafprio.py`; one plugin file per WAF under `wafw00f/plugins/`). Run `wafw00f -l` for the complete list. Below are the major WAFs with their **actual detection signatures traced from the plugin source files** and what detection implies for exploitation.

### Cloudflare (Cloudflare Inc.) — `cloudflare.py`

**Signatures:** Header `Server: cloudflare` or `Server: cloudflare[-_]nginx`; header `cf-ray: *` (any value); cookie `__cfduid`.

**Detection mode:** Passive only — all checks run against the normal response. No attack-response probes needed because Cloudflare always emits these headers/cookies regardless of blocking.

**Exploitation implications:** Cloudflare sits at the edge; it terminates TLS (distinct JARM), caches responses, and applies managed rules (OWASP-derived + Cloudflare-proprietary). Bot detection keys on request rate, User-Agent, TLS fingerprint (JA3), and JS challenge response. The managed ruleset is updated frequently — specific bypasses are short-lived.

### Kona SiteDefender (Akamai) — `kona.py`

**Signatures:** Header `Server: AkamaiGHost` — normal and attack mode. **This is the thinnest detection in the entire database** — a single header value. If Akamai strips or customizes the `Server` header (configurable by the customer), wafw00f will not detect it.

**Detection mode:** Header-only, passive + active.

**Exploitation implications:** Akamai operates at the edge with two distinct products: Kona SiteDefender (WAF rules) and Bot Manager (JS challenge + device fingerprinting). sqlmap/ffuf cannot pass Bot Manager's JS challenges — manual session cookies via `--headers`/`-b` are required. Kona's managed rules are updated frequently; edge-node rate limiting is per-PoP and aggressive. Distinguish which product is active: Kona blocks with status codes + block pages; Bot Manager redirects to a JS challenge.

### Incapsula (Imperva Inc.) — `incapsula.py`

**Signatures:** Cookie `^incap_ses.*?=`; cookie `^visid_incap.*?=`; body content matching `incapsula incident id`, `powered by incapsula`, `/_Incapsula_Resource`.

**Detection mode:** Passive (cookies on normal response) + active (body on block page).

**Exploitation implications:** Imperva inspects deeply — POST bodies, JSON payloads, multipart uploads. Fewer blind spots than CDN-only WAFs. Aggressive session tracking and bot detection; testing from multiple IPs is advisable. Imperva's SecureSphere (on-prem, separate plugin `securesphere.py`) checks for body patterns `<(title|h2)>Error`, `The incident ID is`, and `Contact support` — distinguishable from the cloud Incapsula product.

### AWS Elastic Load Balancer (Amazon) — `awswaf.py`

**Signatures:** Header `X-AMZ-ID: .+`; header `X-AMZ-Request-ID: .+`; cookie `^aws.?alb=`; header `Server: aws.?elb` (attack mode); header `X-Blocked-By-WAF: Blocked_by_custom_response_for_AWSManagedRules.*`.

**Critical caveat:** This plugin detects the **ELB/ALB infrastructure**, not AWS WAF rules. A positive match means the target uses AWS load balancing — AWS WAF may or may not be attached. The only WAF-specific signature is the `X-Blocked-By-WAF` header, which only fires when AWS WAF custom responses are configured with that specific header (not the default). A wafw00f match of "AWS Elastic Load Balancer" should not be interpreted as "AWS WAF is present" without further confirmation.

**Exploitation implications:** AWS WAF rate-based rules default to 5-minute evaluation windows. AWS managed rules inspect URL-decoded payloads. Test which headers are inspected vs. passed through — AWS WAF rule groups can be selectively attached.

### ModSecurity (SpiderLabs) — `modsecurity.py`

**Signatures:** Header `Server: (mod_security|Mod_Security|NOYB)`; body content matching `This error was generated by Mod.?Security`, `rules of the mod.security.module`, `mod.security.rules triggered`, `Protected by Mod.?Security`, `/modsecurity[\-_]errorpage/`, `modsecurity iis`; reason phrase `ModSecurity Action` with status 403 or 406.

**Detection mode:** Both passive (Server header) and active (block page body, reason phrase).

**Exploitation implications:** The CRS (Core Rule Set) version matters more than ModSecurity itself. CRS 3.x+ uses anomaly scoring — requests accumulate score across all triggered rules; blocking fires when the score exceeds the paranoia level's threshold. PL1 (default) misses many encoding-based bypasses; PL3/PL4 catches most. A single tamper may not suffice against anomaly scoring — chain multiple to keep per-rule scores low while the overall pattern evades.

### F5 BIG-IP AppSec Manager — `f5bigipasm.py`

**Signatures:** Body content `the requested url was rejected` AND `please consult with your administrator` (both required); cookie `TS[a-fA-F0-9]{8}=.+` (ASM ≥11.4); cookie `TS[a-fA-F0-9]{6}=.+` (ASM 10.0–11.3).

**Detection mode:** Active (body on block page) + passive (TS cookies). The `TS` cookie prefix with hex-digit count distinguishes ASM version ranges.

**Related F5 plugins:** `f5bigipltm.py` (LTM) checks for cookie `^bigipserver` and header `X-Cnection: close` (attack mode). `f5bigipapm.py` (AP Manager) checks for cookies `^LastMRH_Session`, `^MRHSession`, `^F5_fullWT`, `^F5_HT_shrinked`, and header `Server: Big([-_])?IP`.

**Exploitation implications:** ASM performs deep inspection of all request components. It correlates requests across a session and escalates blocking on repeated triggers — `--delay` is essential. Encoding-based tampers are less effective than logic-based bypasses (HPP, chunked encoding). Chunked transfer encoding has historically exposed parsing vulnerabilities in BIG-IP — chunk length integer overflow can cause content interpretation as pipelined requests.

### Sucuri CloudProxy (Sucuri Inc.) — `sucuri.py`

**Signatures:** Header `X-Sucuri-ID: .+`; header `X-Sucuri-Cache: .+`; header `Server: Sucuri(\-Cloudproxy)?`; header `X-Sucuri-Block: .+` (attack mode); body content matching `Access Denied.{0,6}?Sucuri Website Firewall`, `sucuri\.net/privacy\-policy`, `cdn\.sucuri\.net/sucuri[-_]firewall[-_]block\.css`, `cloudproxy@sucuri\.net`.

**Detection mode:** Both passive and active.

**Exploitation implications:** Sucuri is a cloud proxy — the origin IP is the primary bypass target. Check for origin IP leakage via DNS history (SecurityTrails), SPF records (`dig TXT domain | grep ip4:`), certificate SANs (crt.sh), and non-proxied subdomains (mail, cpanel, staging). If the origin IP is found, set the `Host` header to the domain and connect directly — the WAF is out of path entirely.

### NetScaler AppFirewall (Citrix Systems) — `netscaler.py`

**Signatures:** Header `Via: NS\-CACHE`; cookies `^(ns_af=|citrix_ns_id|NSC_)`; body content `(NS Transaction|AppFW Session) id`, `Violation Category.{0,5}?APPFW_`, `Citrix|NetScaler`; **intentionally misspelled headers** `Cneonction: ^(keep alive|close)` and `nnCoection: ^(keep alive|close)` (attack mode only).

**Detection mode:** Passive + active. The misspelled headers (`Cneonction`, `nnCoection`) are a distinctive NetScaler fingerprint — NetScaler sometimes emits these on responses to malformed or attack requests. This is one of the most reliable active-detection signatures in the database.

**Exploitation implications:** NetScaler AppFirewall inspects based on violation categories (SQL injection, XSS, buffer overflow, cookie consistency). Violations are categorized as `APPFW_*` — the block page often leaks the category, revealing which rule class triggered.

### Barracuda (Barracuda Networks) — `barracuda.py`

**Signatures:** Cookies `^barra_counter_session=`, `^BNI__BARRACUDA_LB_COOKIE=`, `^BNI_persistence=`, `^BN[IE]S_.*?=`; body content `Barracuda.Networks`.

**Detection mode:** Passive (cookies) + active (body).

### FortiWeb (Fortinet) — `fortiweb.py`

**Signatures:** Cookie `^FORTIWAFSID=`; body content `.fgd_icon`; combined body check (all required): `fgd_icon` AND `web.page.blocked` AND `url` AND `attack.id` AND `message.id` AND `client.ip`.

**Detection mode:** Passive (cookie) + active (structured block page).

**Exploitation implications:** FortiWeb's block page leaks structured data (attack ID, message ID, client IP) — useful for understanding which rule fired. Newer versions add ML-based detection that adapts to repeated patterns — vary tamper chains across attempts.

### Cloudfront (Amazon) — `cloudfront.py`

**Signatures:** Header `Server: Cloudfront`; header `Via: .+?.cloudfront.net (Cloudfront)`; header `X-Amz-Cf-Id: .+` (attack); header `X-Cache: Error from Cloudfront` (attack); body `Generated by cloudfront (CloudFront)`.

**Note:** CloudFront is a CDN — this detection says the target uses CloudFront, not that AWS WAF rules are attached. CloudFront + AWS WAF is a separate determination from the `awswaf.py` detection.

### Azure Front Door (Microsoft) — `frontdoor.py`

**Signatures:** Header `X-Azure-Ref: .+` — single header check, passive only.

### Wordfence (Defiant) — `wordfence.py`

**Signatures:** Header `Server: wf[_-]?WAF`; body `Generated by Wordfence`; body `broke one of (the )?Wordfence (advanced )?blocking rules`; body `/plugins/wordfence`.

**Exploitation implications:** WordPress-specific WAF. The `/plugins/wordfence` body pattern confirms WordPress as the CMS. Wordfence runs in PHP at the application layer — it doesn't inspect at the network/proxy layer, so it cannot see chunked-encoding or protocol-level tricks. Focus on application-layer evasion (encoding, case manipulation).

### NAXSI (NBS Systems) — `naxsi.py`

**Signatures:** Header `X-Data-Origin: ^naxsi(.+)?`; header `Server: naxsi(.+)?`; body `blocked by naxsi`; body `naxsi blocked information`.

### Wallarm (Wallarm Inc.) — `wallarm.py`

**Signatures:** Header `Server: nginx[\-_]wallarm` — single header check.

### Fastly (Fastly CDN) — `fastly.py`

**Signatures:** Header `X-Fastly-Request-ID: \w+`; header `X-Served-By: ^cache-[a-z]{3}\d+-[A-Z]{3}` (PoP identifier pattern).

### Azure Front Door (Microsoft) — `frontdoor.py`

**Signatures:** Header `X-Azure-Ref: .+` — single header check, passive only.

**Detection mode:** Passive. This is thin detection — `X-Azure-Ref` is an Azure-wide tracing header. Its presence confirms Azure Front Door but does not confirm WAF rules are attached (Azure WAF policy is optionally associated with Front Door profiles).

### Azure Application Gateway (Microsoft) — `applicationgateway.py`

**Signatures:** Body `<center>Microsoft-Azure-Application-Gateway/v2</center>` AND body `<h1>403 Forbidden</h1>` — both required, active mode only.

**Detection mode:** Active only — requires the WAF to block a probe and return its default block page. If the customer has configured a custom error page, this plugin will not fire.

**Exploitation implications:** Azure Application Gateway WAF uses CRS (same as ModSecurity). The `Prevention` vs. `Detection` mode distinction matters — in Detection mode, the WAF logs but does not block, so wafw00f's active probes won't trigger the signature.

### Google Cloud Armor (Google Cloud) — `gcparmor.py`

**Signatures:** Header `Via: 1.1 google` — single header check, passive only.

**Caveat:** This header appears on all Google Cloud infrastructure (load balancers, CDN), not just Cloud Armor. A match indicates Google Cloud, not necessarily active WAF rules.

### Palo Alto Next Gen Firewall — `paloalto.py`

**Signatures:** Body `Download of virus.spyware blocked`; body `Palo Alto Next Generation Security Platform` — block-page only, active mode.

**Exploitation implications:** Palo Alto operates at the network layer with application-layer awareness. Block pages often appear as HTML interstitials on non-HTTP ports too. The block page reveals the product family but not the specific threat prevention profile or rule set.

### SonicWall (Dell) — `sonicwall.py`

**Signatures:** Header `Server: SonicWALL`; body `<(title|h\d{1})>Web Site Blocked`; body `\+?nsa_banner`.

**Detection mode:** Passive (Server header) + active (block page). The `nsa_banner` pattern refers to SonicWall's NSA (Network Security Appliance) series, not the intelligence agency.

### WatchGuard (WatchGuard Technologies) — `watchguard.py`

**Signatures:** Header `Server: WatchGuard`; body `Request denied by WatchGuard Firewall`; body `WatchGuard Technologies Inc\.`.

### ZScaler (Accenture) — `zscaler.py`

**Signatures:** Header `Server: ZScaler`; body `Access Denied.*Accenture Policy`; body `policies\.accenture\.com`; body `Zscaler to protect you from internet threats`; body `Internet Security by ZScaler`.

**Detection mode:** Passive (Server header) + active (block page). ZScaler operates as a cloud-based forward proxy — it inspects outbound traffic from corporate networks, not inbound traffic to web servers. Detecting ZScaler on a target means the target's network routes outbound HTTP through ZScaler, which is unusual in a pentest context (typically seen when scanning from inside a corporate network that uses ZScaler).

### Imunify360 (CloudLinux) — `imunify360.py`

**Signatures:** Header `Server: imunify360.{0,10}?`; body `protected.by.{0,10}?imunify360`; body `powered.by.{0,10}?imunify360`; body `imunify360.preloader`.

**Exploitation implications:** Hosting-panel WAF (cPanel/DirectAdmin environments). Imunify360 integrates with ModSecurity and adds its own proactive defense and malware scanning. The ModSecurity CRS evasion techniques apply.

### Additional notable detections

- **DDoS-GUARD:** Cookies `^__ddg1`, `^__ddg2`, `^__ddgid`, `^__ddgmark`; header `Server: ddos-guard`.
- **Envoy:** Header `server: envoy` plus multiple `x-envoy-*` headers (`upstream-service-time`, `external-address`, `internal`, `force-trace`). Envoy is a proxy, not a WAF — detection indicates the infrastructure, not WAF rules.
- **Vercel WAF:** Body `<title>Vercel Security Checkpoint</title>`; body `/vercel/security/`.
- **Open-Resty Lua Nginx:** Header `Server: ^openresty/[0-9\.]+?` with status 403; body `openresty/[0-9\.]+?` with status 406.
- **Safeline (Chaitin Tech):** Body `safeline|<!-- event id:`.
- **Comodo cWatch:** Header `Server: Protected by COMODO WAF(.+)?` — single passive header check.
- **DenyALL:** Status 200 with reason phrase `Condition Intercepted` — unusual combination; most WAFs return 403.
- **WebKnight (AQTRONIX):** Status 999 with reason `No Hacking`; or status 404 with reason `Hack Not Found` — custom HTTP status codes are a distinctive fingerprint.
- **Shadow Daemon:** Body `<h\d{1}>\d{3}.forbidden</h\d{1}>` AND `request forbidden by administrative rules`.
- **Squarespace:** Header `Server: Squarespace`; cookies `^SS_ANALYTICS_ID=`, `^SS_MATTR=`, `^SS_MID=`; body `status\.squarespace\.com`.

---

## Per-WAF Evasion Recipes

wafw00f is a reconnaissance tool — it does not evade WAFs itself. The value is translating detection results to evasion strategy for downstream scanners. Every tamper script below is verified against the installed sqlmap set at `/usr/share/sqlmap/tamper/`; **database and platform constraints are noted where they apply** because a tamper that works on MySQL is useless against a PostgreSQL backend. All effectiveness is **situational** — WAF rule updates, custom configurations, and paranoia levels change what works.

### Cloudflare

**sqlmap:** `--tamper=between,randomcase,space2comment` — Cloudflare's managed rules are OWASP-derived; `between` replaces `>` and `=` operators (all DBs), `randomcase` randomizes keyword casing (all DBs), `space2comment` replaces spaces with `/**/` (all DBs). For Lua-Nginx WAF layer: `--tamper=luanginx` prepends 100+ junk parameters to overflow Cloudflare's Lua-based parameter processing limit — effective when the WAF stops parsing after ~100 params.

**ffuf/feroxbuster:** Rate-limit to ≤30 req/s; rotate UA with `-H "User-Agent: ..."` or use ffuf's `-random-agent` (see `tooling/ffuf.md`). Cloudflare's bot detection keys on request rate + UA + TLS fingerprint (JA3) — route through Burp/Caido to launder the TLS fingerprint.

**nuclei:** Avoid templates that send blatant payloads in query strings; prefer header/body injection templates. Use `-rl 30` for rate limiting.

### Akamai (Kona SiteDefender / Bot Manager)

**sqlmap:** `--tamper=space2comment,randomcase` with `--random-agent --delay 2`. Akamai's managed rules are updated frequently — tamper effectiveness is short-lived. `space2comment` (spaces → `/**/`, all DBs) and `randomcase` (keyword casing, all DBs) are the broadest-coverage options.

**ffuf/feroxbuster:** Rate-limit to ≤20 req/s — Akamai's rate controls are per-edge-node and aggressive.

**Distinguish Kona from Bot Manager:** Kona blocks with HTTP status codes and a block page (bypassable with payload evasion). Bot Manager issues JS challenges that automated tools cannot solve — for Bot Manager, extract session cookies from a manual browser session and pass them via `--headers`/`-b`. This is a fundamental limitation of all CLI-based scanners.

### Imperva (Incapsula)

**sqlmap:** `--tamper=space2plus,randomcase,between` with `--delay 2`. `space2plus` replaces spaces with `+` (all DBs); `randomcase` (all DBs); `between` (all DBs). Imperva's bot detection is aggressive — `--delay` is essential.

**Key constraint:** Imperva inspects POST bodies, JSON payloads, and multipart uploads — fewer blind spots than CDN-only WAFs. Session tracking is aggressive; test from multiple source IPs if possible.

### AWS WAF (via CloudFront/ALB)

**sqlmap:** `--tamper=charencode,between` — `charencode` URL-encodes all characters (all DBs, all platforms). **Note:** the `charunicodeencode` tamper that uses `%uNNNN` encoding is **ASP/ASP.NET only** — do not recommend it unless the backend is confirmed ASP. AWS managed rules inspect URL-decoded payloads; double encoding (`chardoubleencode`) can bypass rule sets that decode only once.

**Rate control:** AWS WAF rate-based rules evaluate over 5-minute windows. Burst within a window, pause between windows.

**Header-based rules:** AWS WAF rule groups can inspect specific headers — test which headers are inspected vs. passed through.

### ModSecurity (OWASP CRS)

**sqlmap:** `--tamper=space2comment,between,charencode`. For MySQL backends specifically: `--tamper=modsecurityversioned` wraps the payload in a MySQL versioned comment `/*!ver…*/`; `modsecurityzeroversioned` uses `/*!00000…*/`. These two tampers are **MySQL-only** and explicitly designed to target ModSecurity.

**CRS paranoia levels:** PL1 (default) misses many encoding-based bypasses. PL2 catches most common tampers. PL3/PL4 catches nearly everything — at these levels, chaining multiple tampers is required to keep the per-rule anomaly score contribution below the block threshold.

**Anomaly scoring:** CRS 3.x+ accumulates score across all triggered rules rather than blocking on a single rule match. A payload that triggers two low-scoring rules (say, 2 + 2 = 4) passes under a threshold of 5, but adding a third rule match (4 + 2 = 6) blocks. Chain tampers to minimize the number of rules each component triggers.

### F5 BIG-IP ASM

**sqlmap:** `--tamper=charencode,between` with `--delay 3`. `charencode` (URL-encode all chars, all DBs) and `between` (replace operators, all DBs). **Correction:** `space2mssqlhash` (previously recommended) uses `#` followed by a newline — `#` is a **MySQL-only comment character** despite the `mssql` in the script's name. Use it only when the backend is confirmed MySQL.

**ASM correlates requests** across sessions and escalates blocking on repeated triggers. Varying tamper chains across attempts is more effective than repeating the same chain.

**Logic-based bypasses** are more effective than encoding against ASM's deep inspection: HTTP Parameter Pollution (HPP — duplicate parameters; ASM inspects one value, the app uses another), chunked transfer encoding (split payload across chunks), and method override (`X-HTTP-Method-Override: PUT` to route through uninspected methods).

### Sucuri

**sqlmap:** `--tamper=between,randomcase` with `--random-agent`. `between` (all DBs); `randomcase` (all DBs).

**Primary bypass:** Sucuri is a cloud proxy — origin IP discovery is the highest-value bypass path. Check DNS history (SecurityTrails, DNSDumpster), SPF records, certificate transparency logs (crt.sh), and non-proxied subdomains (`mail.*`, `cpanel.*`, `staging.*`). If the origin IP is found, connect directly with the `Host` header set to the domain — Sucuri is entirely out of path.

### Barracuda

**sqlmap:** `--tamper=space2comment,between,randomcase` with `--random-agent`. All three tampers work across all major databases.

**Key tell:** The distinctive cookie names (`barra_counter_session`, `BNI__BARRACUDA_LB_COOKIE`, `BNI_persistence`) confirm Barracuda — these are reliable passive indicators.

### FortiWeb (Fortinet)

**sqlmap:** `--tamper=charencode,space2comment,between`. All three work across all major databases. FortiWeb's ML mode in newer versions can adapt to repeated patterns — vary tamper chains across scan attempts rather than running a fixed chain.

**Rate control:** FortiWeb DoS prevention triggers at sustained volume; burst-then-pause is more effective than a steady rate.

### NetScaler AppFirewall (Citrix)

**sqlmap:** `--tamper=charencode,between,randomcase` — all cross-DB tampers. NetScaler's violation categories (`APPFW_*`) are rule-class-based, not signature-based — encoding bypasses are effective when the WAF checks decoded values but the application processes the encoded form differently.

**Key advantage:** NetScaler's block page often leaks the violation category (`APPFW_STARTURL`, `APPFW_FIELDCONSISTENCY`, `APPFW_CSRF`, etc.), revealing exactly which rule class triggered. This lets you tailor the tamper chain to the specific violation rather than guessing.

### No WAF / Unknown

If wafw00f returns no match, don't assume no protection. Start with moderate rate controls (`--delay 1`, ≤30 req/s) and watch for behavioral signals:
- 429 responses (rate limiting)
- CAPTCHAs or JS challenges appearing
- IP blocks after sustained scanning
- Response times increasing (throttling)

Escalate payloads gradually from benign to malicious to detect transparent inspection.

### Quick-reference: WAF → evasion summary

| WAF | sqlmap tampers | DB constraints | Rate cap | Key evasion note |
|---|---|---|---|---|
| Cloudflare | `between,randomcase,space2comment` | All DBs | ≤30 r/s | `luanginx` for Lua-layer overflow; TLS fingerprint matters |
| Akamai | `space2comment,randomcase` | All DBs | ≤20 r/s | Bot Manager requires manual session cookies |
| Imperva | `space2plus,randomcase,between` | All DBs | `--delay 2` | Deep POST/JSON/multipart inspection; session tracking |
| AWS WAF | `charencode,between` | All DBs; `charunicodeencode` ASP-only | Burst/pause 5-min | Plugin detects ELB, not WAF rules directly |
| ModSecurity CRS | `space2comment,between,charencode` | `modsecurityversioned` MySQL-only | Target-dependent | Anomaly scoring: chain tampers to stay under threshold |
| F5 BIG-IP ASM | `charencode,between` | `space2mssqlhash` MySQL-only | `--delay 3` | Correlates sessions; HPP/chunked more effective than encoding |
| Sucuri | `between,randomcase` | All DBs | ≤30 r/s | Origin IP discovery is the primary bypass |
| FortiWeb | `charencode,space2comment,between` | All DBs | Burst-pause | ML mode adapts — vary tamper chains |

### Tamper script reference (verified against `/usr/share/sqlmap/tamper/`)

Scripts referenced in the evasion recipes above, with their actual transformation and database/platform constraints:

| Script | Transformation | DB/Platform |
|---|---|---|
| `between` | `>` → `NOT BETWEEN 0 AND #`; `=` → `BETWEEN # AND #` | All DBs |
| `randomcase` | `SELECT` → `SEleCt` (random casing) | All DBs |
| `space2comment` | Spaces → `/**/` | All DBs |
| `charencode` | URL-encode all characters: `S` → `%53` | All DBs, all platforms |
| `space2plus` | Spaces → `+` | All DBs |
| `charunicodeencode` | Unicode URL-encode: `S` → `%u0053` | **ASP/ASP.NET only** |
| `space2mssqlblank` | Spaces → random MSSQL whitespace chars | **MSSQL only** |
| `space2mssqlhash` | Spaces → `#` + newline (`%23%0A`) | **MySQL only** (misnamed) |
| `modsecurityversioned` | Wrap in `/*!ver payload */` | **MySQL only**, targets ModSecurity |
| `modsecurityzeroversioned` | Wrap in `/*!00000 payload */` | **MySQL only**, targets ModSecurity |
| `luanginx` | Prepend 100+ junk parameters | All DBs, targets Lua-Nginx WAFs |
| `randomcomments` | Insert `/**/` within keywords: `INSERT` → `I/**/NS/**/ERT` | All DBs |
| `htmlencode` | HTML-entity encode non-alphanumerics: `'` → `&#39;` | All DBs |
| `xforwardedfor` | Add `X-Forwarded-For`/`X-Client-IP`/`X-Real-IP` with random IP | All DBs (rate-limit bypass) |
| `versionedkeywords` | Enclose keywords in `/*!ver keyword */` | **MySQL only** |
| `chardoubleencode` | Double URL-encode: `S` → `%2553` | All DBs |

### When to re-run wafw00f

- After DNS changes (CNAME migration to a different CDN).
- After infrastructure changes (cloud migration, WAF product swap).
- On newly discovered subdomains (different hosts may have different WAF stacks).
- When scan results from downstream tools show unexpected blocking patterns that don't match the original fingerprint.
- After significant time has passed — WAF configurations change, products get replaced.

---

## Manual WAF Fingerprinting Beyond wafw00f

When wafw00f returns no match or the result is ambiguous, these manual techniques can identify or confirm a WAF:

### Response analysis

- **Block-page fingerprinting:** Send a blatant `<script>alert(1)</script>` in a query param and inspect the response. Custom block pages often contain vendor branding, support emails, incident IDs, or CSS references that identify the product even without a wafw00f signature.
- **Status-code divergence:** Compare status codes for a clean request vs. an attack payload. A shift from 200 to 403/406/429/503 indicates active filtering. The specific code can narrow the product (403 is generic; 406 is common with ModSecurity; 429 suggests rate-limiting).
- **Header ordering and casing:** Different reverse proxies emit headers in characteristic orders. Cloudflare places `cf-ray` early; Akamai includes `X-Akamai-*` debug headers when enabled; F5 emits the `TS` cookies.

### TLS-layer fingerprinting

JARM fingerprints (from `tlsx -jarm`, see `tooling/tlsx.md`) identify the TLS stack on the server side. Cross-reference:
- wafw00f identifies the WAF by HTTP behavior; JARM identifies it by TLS behavior. Agreement increases confidence.
- Disagreement may indicate a multi-layer stack (CDN terminates TLS → different JARM from the origin WAF's HTTP fingerprint).
- Known JARM hashes exist for Cloudflare, Akamai, Fastly, and other major CDNs.

`tlsx -l hosts.txt -jarm -silent -j -o jarm.jsonl`

### Timing analysis

- **Response-time variance:** WAFs that perform deep payload inspection add measurable latency on attack requests vs. clean requests. A consistent 50–200ms delta between clean and malicious requests suggests inspection.
- **Rate-limit detection:** Send a burst of 50+ requests in under 5 seconds. If responses shift from 200 to 429/503 or connections drop, rate limiting is active regardless of wafw00f's result.

### Origin IP discovery (CDN bypass)

When the WAF is a cloud proxy (Cloudflare, Sucuri, Akamai, Incapsula), the entire WAF can be bypassed by reaching the origin IP directly:

1. **DNS history:** SecurityTrails, DNSDumpster — look for A records that predate CDN adoption.
2. **Certificate transparency:** crt.sh — SANs on certificates issued to the domain may reveal origin IPs.
3. **SPF records:** `dig TXT domain` — `ip4:` directives in SPF may list the origin server.
4. **Non-proxied subdomains:** `mail.*`, `cpanel.*`, `staging.*`, `dev.*` — these often resolve to the origin directly.
5. **Outbound connections:** If the app sends webhooks, emails, or makes outbound requests, the source IP is the origin.

Once found, connect directly with the target `Host` header: `curl -H "Host: target.tld" https://<origin-ip>/`.

**Verification:** Compare the response from the direct connection to the CDN-proxied response. Matching content confirms the origin; a different response or a block suggests the origin has IP-based filtering (allow-list for CDN ranges only — the recommended mitigation, and a sign the target is security-aware).

**Automated enumeration:** Chain with `subfinder` for subdomain discovery and `httpx` for live-host checking:
`subfinder -d target.tld -silent | httpx -silent | grep -v 'cloudflare\|akamai\|sucuri\|incapsula' > potential_origins.txt`
— then compare response bodies against the CDN-proxied version.

---

## Signature Internals & Custom Plugins

### Plugin structure

Each WAF detection is a standalone Python file under `wafw00f/plugins/`. The structure:

```
NAME = 'Product Name (Manufacturer)'

def is_waf(self):
    if self.matchHeader(('header', 'regex')):
        return True
    if self.matchCookie('regex'):
        return True
    if self.matchContent('body regex'):
        return True
    return False
```

`self` is the WAFW00F instance — plugins access the detection API (`matchHeader`, `matchCookie`, `matchContent`, `matchStatus`, `matchReason`) through it. The `NAME` string must match an entry in `wafprio.py` for priority ordering; plugins not in the priority list still run but are checked last.

### Writing a custom plugin

To detect an unsignatured WAF:

1. Identify the WAF's distinctive response patterns — headers, cookies, body content, status codes — by sending malicious payloads manually and inspecting responses.
2. Create a new `.py` file in the plugins directory following the structure above.
3. Add the `NAME` string to `wafprio.py` if detection priority matters.
4. Test with `wafw00f -t "Your WAF Name" https://target.tld`.

Signature design priorities: prefer passive indicators (headers/cookies on normal responses) over active indicators (body content on block pages) — passive detection is faster and doesn't require triggering WAF rules. Combine multiple weak indicators with AND logic rather than relying on a single strong indicator — reduces false positives.

---

## Detection → Evasion Decision Workflow

End-to-end path from wafw00f output to concrete downstream scanner configuration:

**1. Fingerprint** → `wafw00f -a -f json -o wafw00f.json https://target.tld`

**2. Parse** → `jq -r '.[] | select(.detected == true) | "\(.url) \(.firewall)"' wafw00f.json`

**3. Identify the backend database** (if targeting SQLi). The tamper chain depends on the DB engine, not just the WAF:
- MySQL: `modsecurityversioned`, `space2mssqlhash` (MySQL comment), `versionedkeywords` are available
- MSSQL: `space2mssqlblank` is available; `charunicodeencode` requires ASP
- PostgreSQL/Oracle: `between`, `randomcase`, `space2comment`, `charencode` are the safest cross-DB options
- Unknown: stick to all-DB tampers (`between`, `randomcase`, `space2comment`, `charencode`)

**4. Select evasion strategy** based on the WAF detection catalog above. Key decision points:
- **CDN/proxy WAF (Cloudflare, Akamai, Sucuri, Incapsula, CloudFront):** First check if origin IP is discoverable — if yes, bypass the WAF entirely. If not, apply rate limiting + UA rotation + tamper chain.
- **Appliance WAF (F5, NetScaler, Barracuda, FortiWeb):** No origin bypass path — focus on payload evasion (tamper chains, encoding, HPP, chunked encoding).
- **Application-layer WAF (ModSecurity, Wordfence, NAXSI):** Focus on encoding and keyword obfuscation — these WAFs can't see protocol-level tricks because they run inside the application.
- **CDN-only / no WAF rules:** If wafw00f detects a CDN (CloudFront, Fastly, Envoy) but no WAF product, the CDN may not have WAF rules enabled. Send a test payload to confirm before investing in evasion.

**5. Configure downstream scanners** — apply the WAF-specific tamper chain, rate limit, and UA rotation to `sqlmap`/`ffuf`/`nuclei` (see `tooling/sqlmap.md`, `tooling/ffuf.md`, `tooling/nuclei.md`).

**6. Monitor and adapt** — if the initial configuration hits blocks, check:
- Is the WAF blocking on payload content (try different tamper chain) or on behavioral signals (rate, UA, TLS fingerprint)?
- Is there a second WAF layer that wafw00f detected with `-a` that requires separate evasion?
- Has the WAF escalated blocking (IP ban) — rotate source IP or pause.

---

## Techniques — Advanced Usage

### JSON output structure and automation

wafw00f JSON output (`-f json`) is structured per-URL:
```
[{"url": "https://target.tld", "detected": true, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]
```

Parse in automation:
`jq -r '.[] | select(.detected == true) | "\(.url) \(.firewall)"' wafw00f.json`

Group hosts by WAF for per-WAF evasion strategy:
`jq -r '.[] | select(.detected == true) | .firewall' wafw00f.json | sort | uniq -c | sort -rn`

Filter undetected hosts (may have no WAF or unsignatured WAF):
`jq -r '.[] | select(.detected == false) | .url' wafw00f.json > undetected_hosts.txt`

### Multi-layer WAF detection

Some targets deploy two layers:
1. CDN/DDoS WAF (Cloudflare, Akamai) — terminates TLS, does basic filtering.
2. Origin WAF (ModSecurity, F5) — deep payload inspection at the application server.

wafw00f with `-a` can detect both when each layer's signatures fire. The output may show `["Cloudflare", "ModSecurity"]`. Strategy:
- The CDN layer blocks based on reputation, rate, and coarse patterns — bypass via rate control + header shaping.
- The origin layer blocks based on deep payload inspection — bypass via encoding tampers + logic-based evasion.
- If the CDN layer is bypassed (e.g. via origin IP direct access), only the origin WAF's rules apply.

### Verbose probe analysis

`wafw00f -a -vv https://target.tld` outputs per-probe reasoning: which payload was sent, which response pattern matched, which WAF signature that corresponds to. Use this to understand:
- Whether the match is strong (multiple probes matched) or weak (single probe, could be coincidental).
- Which probe payloads the WAF blocked vs. allowed — reveals the WAF's rule coverage gaps.
- Whether the WAF responded with a block page, a redirect, a connection reset, or a modified response.

### Edge-case interpretation

**Load balancer only, no WAF:** Some HTTP load balancers (AWS ALB, Nginx reverse proxy) add distinctive headers (`server: awselb`, `x-amz-cf-id`) that wafw00f may match as a CDN. This is not a false positive (the CDN is present), but the CDN may not have WAF rules enabled. Verify by sending a blatant XSS payload manually and checking if it's blocked.

**CDN caching vs. WAF blocking:** A CDN returning a cached 200 for a payload-carrying request doesn't mean the WAF allows it — it means the CDN served from cache without checking. Test with cache-busting query params (`?cb=<random>`) to force origin evaluation.

**Geographic variance:** Some CDN WAFs apply different rule sets per PoP or region. A scan from one region may see Cloudflare with standard rules; another may see stricter or lenient rules. The fingerprint itself (Cloudflare) will be the same; the rule behavior differs.

### Known blind spots

- **Custom WAF rules** on generic reverse proxies (Nginx/HAProxy with custom Lua/njs blocking) — no distinctive fingerprint exists because the response shape is operator-defined.
- **API gateways** with WAF functionality (Kong, Apigee, AWS API Gateway with request validation) — these inspect at the API layer and often return clean JSON errors indistinguishable from application errors.
- **Transparent proxies** that inspect but don't modify responses — wafw00f sees the origin response, not the proxy's interception.
- **Rate-limiting-only stacks** — if the WAF only rate-limits and wafw00f's probe volume is too low to trigger it, no signature fires.
- **New/niche WAFs** — any product released after the signature database version.

### False positives and negatives

**False positives:** A CDN that serves a branded error page on 403/503 can match a WAF signature even if no WAF rules are active. Verify with `-t` + `-vv` and inspect which specific probe triggered the match.

**False negatives:** WAFs in "detection-only" or "learning" mode may not block probes, returning 200 for everything. Custom rule sets that only inspect POST bodies or specific URL patterns may not trigger on wafw00f's generic probes.

### Correlating with tlsx JARM fingerprints

`tlsx -l hosts.txt -jarm -silent -j -o jarm.jsonl`
— then correlate JARM hashes with known CDN/WAF fingerprints and compare against wafw00f JSON output.

---

## Failure Recovery

- All targets report "no WAF" on a stack you know is behind one: raise `-T`, add a custom `-H` headers file with a browser-shaped UA, and verify the proxy isn't rewriting responses.
- `-i <csv>` rejected: the file needs a `url` column header; without it, wafw00f treats it as text.
- JSON output empty on error: re-run with `-vv` to see signature-level reasoning.
- Rate-limited by the target: wafw00f is already serial; add `sleep` between batch entries via a wrapper script, or rotate IPs via `-p`.
- Timeout errors on distant targets: raise `-T` to 30+.

---

## Tool-to-Tool Chaining

**Upstream (feeding wafw00f):**
- `httpx -l subdomains.txt -silent -o live.txt` → `wafw00f -i live.txt -a -f json -o wafw00f.json` — fingerprint all live hosts.
- `tlsx -l hosts.txt -jarm -silent -j -o jarm.jsonl` — JARM fingerprints for cross-reference with wafw00f HTTP fingerprints.

**Downstream (wafw00f results feeding):**
- `tooling/sqlmap.md` — WAF identity selects `--tamper` scripts, `--delay`, `--random-agent`.
- `tooling/ffuf.md` / `tooling/feroxbuster.md` / `tooling/dirsearch.md` — WAF identity sets rate-limit thresholds, UA rotation, and whether to expect blocking on common wordlist entries.
- `tooling/nuclei.md` — WAF-aware template selection; avoid templates with payloads the identified WAF will block.
- `vulnerabilities/sql_injection.md`, `vulnerabilities/xss.md`, `vulnerabilities/path_traversal_lfi_rfi.md`, `vulnerabilities/header_injection.md`, `vulnerabilities/open_redirect.md` — WAF-bypass sections reference wafw00f output.

**Full pipeline position:**
`subfinder → dnsx → httpx → wafw00f → [sqlmap|ffuf|feroxbuster|nuclei with WAF-informed config]`

---

If uncertain, query web_search with:
`site:github.com/EnableSecurity/wafw00f wafw00f <flag>`
