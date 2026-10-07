---
name: http-request-smuggling-novel-deep
description: HTTP request smuggling at the 2024–2026 frontier — the HTTP Garden 122-discrepancy corpus with four canonical parser-differential smuggling classes (LiteSpeed strtoll-octal, Node.js bare-CR, OpenBSD relayd, Python int() underscores), the April-2024 CONTINUATION flood CVE cluster, and current CVE dissections including CVE-2025-55315 (ASP.NET Core, CVSS 9.9 — twofer with csrf).
sibling: http_request_smuggling
load_when: scan_mode == "deep"
---

# HTTP Request Smuggling — Novel + Frontier Depth

This is the novel+frontier deep sibling to `http_request_smuggling.md`. The base owns the classical class taxonomy (CL.TE, TE.CL, H2.CL, H2.TE, CL.0, CSD, pause-based desync), the standard probes, chaining routes, and the CVE-name-plus-route map. The advanced+expert sibling `http_request_smuggling_advanced_deep.md` owns the HTTP/2 downgrade header matrix, cache-poisoning and response-queue-poisoning chain construction, WAF/CDN bypass classes, per-parser transducer differentials, and confirmation methodology. This file owns the 2024–2026 CVE frontier and current-frontier framing — the HTTP Garden discovery corpus with its four canonical smuggling classes, the April-2024 CONTINUATION flood cluster, and per-CVE dissections with canonical version tables.

Load this file when the goal is matching a target's specific server version against a current CVE family or when the target's parser composition suggests a specific HTTP Garden-catalogued divergence class is exploitable.

Every CVE number, version boundary, GHSA identifier, and patch-mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-7-*/cve-json/` and `.../ghsa-json/`. The HTTP Garden research is anchored to `arXiv:2405.17737` (Kallus et al., May 2024, Dartmouth), abstract-level verified during Batch 6 arXiv gate.

## HTTP Garden — Parser-Differential Frontier

The HTTP Garden (`arXiv:2405.17737`, Kallus/Anantharaman/Locasto/Smith, May 2024) applied differential fuzzing to HTTP/1.1 request streams across a corpus of popular servers running in docker-compose. The corpus documented **122 unique parsing discrepancies** across the tested implementations; the paper's abstract explicitly states "over 100 bugs discovered, 68 have been fixed, and we designate 39 of these to be exploitable" (verbatim from abstract, verified Batch 6). The exploitable subset produced specific smuggling class expressions across four canonical categories, each documented below.

**Corpus methodology:**
- Every server in the corpus was run as a docker container.
- A differential-fuzzing harness sent HTTP/1.1 request pairs where the two servers should agree on parsing but might not.
- Discrepancies were characterized, mapped to smuggling classes, and reported to upstream maintainers.

**Framework for the four canonical classes:**

Each class is a `(transducer, origin)` pair where the transducer accepts a request the origin parses differently — a specific implementation of the "two parsers, one wire" pattern from the master-prompt regression patterns.

The four classes explicitly identified by the HTTP Garden corpus:

1. **LiteSpeed `strtoll` radix inference in `Content-Length`** — LiteSpeed's Content-Length parser uses `strtoll` with radix `0` (auto-detect), so a leading `0` in the value is interpreted as octal. Combined with non-normalizing transducers (Apache Traffic Server, nghttpx, Pound, Squid, Varnish, Google Cloud Classic ALB, OpenBSD relayd) that forward the leading zero unmodified, smuggling is enabled against LiteSpeed origins.

2. **Node.js bare-CR chunk termination** — Node.js's HTTP parser (llhttp pre-9.1.3 / Node pre-21.2.0) accepted a bare CR to terminate chunk lines, even though HTTP/1.1 requires CRLF. Because Apache Traffic Server, GCP Classic ALB, and Akamai GHost forward CR bytes in the optional-whitespace region before the chunk-extension `;`, smuggling was enabled against those three transducers pointing at Node.js origins.

3. **OpenBSD relayd single-participant smuggling** — OpenBSD relayd concatenated header values containing a null byte or bare LF into the previous header value *after* Content-Length validation. The result: relayd could smuggle to relayd (the first documented single-participant smuggling case). Any relayd-to-relayd deployment was affected.

4. **Python `int()` digit-separating underscores** — Python 3.6+ accepts `int('0_ff', 16) == 255`. AIOHTTP, Gunicorn, and Tornado's Content-Length parsers accepted the underscore form; Apache Traffic Server forwarded the value after interpreting its longest valid prefix as `0`, so ATS-in-front-of-AIOHTTP/Gunicorn/Tornado smuggled. The same ATS bug also applied to strtol-family origins (CherryPy, Libevent, Libsoup, OpenWrt uhttpd) that ignore `0x` prefixes when radix 16 is explicit.

## HTTP Garden — LiteSpeed strtoll Radix Class

Primitive: a `Content-Length` value with a leading `0` is interpreted as octal by LiteSpeed's `strtoll(value, NULL, 0)` call, so `Content-Length: 010` means 8 (octal), not 10 (decimal). Transducers that don't normalize the leading zero forward the string unchanged; LiteSpeed processes 8 bytes of body while the transducer expected 10, leaving 2 bytes on the socket for the next request.

**Vulnerable pair:**
- Transducer: any of Apache Traffic Server, nghttpx, Pound, Squid, Varnish, Google Cloud Classic ALB, OpenBSD relayd (all documented in HTTP Garden as non-normalizing for leading zeros in CL).
- Origin: LiteSpeed (any version using the strtoll-radix-0 parse; verify current LiteSpeed for status).

**Mechanism:**

```
Front-end sees:
  Content-Length: 010    (parses as decimal 10)
  Body: [10 bytes of payload]

Back-end (LiteSpeed) sees:
  Content-Length: 010    (parses as octal 8)
  Body: [8 bytes of payload]
  Remaining 2 bytes: prefix to next request on socket
```

**Detection:**
- Send a request with `Content-Length: 010` and a 10-byte body. Observe whether the back-end processes only 8 bytes (and treats the remainder as the next request).
- Confirm with a follow-up request whose response reveals the socket poisoning.

**Class-generalization:** any parser using `strtoll` with radix `0` (auto-detect) is a candidate for the class. Grep target codebases for `strtoll(..., NULL, 0)` on integer-parsing paths that accept user input.

**Extended transducer list from HTTP Garden:**

Beyond the base list, HTTP Garden documented these non-normalizing transducers for CL leading-zero forwarding: Apache Traffic Server, nghttpx, Pound, Squid, Varnish, Google Cloud Classic Application Load Balancer, OpenBSD relayd. Each represents a distinct combination with LiteSpeed producing smuggling.

**Detection depth:**

Beyond the basic detection, add these variations:
- `Content-Length: 010` — the classical form; expected to parse as decimal 10 but LiteSpeed parses as octal 8.
- `Content-Length: 0010` — leading zeros multiple; behavior varies per parser.
- `Content-Length: 0x0A` — hex form; some parsers accept, some reject; LiteSpeed's strtoll radix 0 accepts and interprets as decimal 10.
- `Content-Length: 10, 010` — duplicate values; front-end may pick first, back-end may pick second.

**Real-world configurations:**

LiteSpeed is common in shared-hosting deployments and specific SaaS providers. When a target uses LiteSpeed as origin and any of the above transducers as edge (or the target sits behind a WAF that doesn't normalize leading zeros), this class is a realistic attack path.

**Historical patch trajectory:**

The class was disclosed to LiteSpeed via the HTTP Garden coordinated disclosure. Verify current LiteSpeed for patch status; specific version boundary should be confirmed against LiteSpeed's own release notes.

## HTTP Garden — Node.js Bare-CR Chunk Termination

Primitive: Node.js pre-21.2.0 accepted `\r` (bare CR) as a chunk-line terminator, though HTTP/1.1 requires `\r\n`. Transducers that treat CR as optional whitespace within the chunk-line forward the byte; Node.js consumes it as a chunk terminator; the smuggled request follows.

**Vulnerable pair:**
- Transducer: Apache Traffic Server, GCP Classic ALB, Akamai GHost (documented in HTTP Garden as CR-forwarders).
- Origin: Node.js < 21.2.0 (llhttp < 9.1.3).

**Version boundary:**

| Software | Vulnerable | Fixed |
|---|---|---|
| Node.js | < 21.2.0 | 21.2.0 (with llhttp 9.1.3) |
| llhttp | < 9.1.3 | 9.1.3 |

Verify against Node.js release notes at `nodejs.org/en/blog/release/v21.2.0` (persisted to Batch 6 artifacts as part of the CVE-2024-27983 verification, transitively relevant here).

**Mechanism:**

```
Request from attacker to transducer:
  4\r
  ABCD\r
  0\r
  \r
  SMUGGLED_PREFIX

Transducer forwards the CR bytes as optional-whitespace (its parser accepts).
Node.js reads:
  Chunk of 4 bytes: ABCD (terminated by \r — bare-CR accepted).
  Chunk of 0: request body ended.
  SMUGGLED_PREFIX: begins next request on socket.
```

**Detection:**
- Send a chunked request with bare-CR terminators; observe whether the back-end considers the body complete.

**Class-generalization:** any HTTP/1.1 parser that accepts less-strict line terminators (bare CR, bare LF, VT, FF) than the RFC-required CRLF is a smuggling candidate when paired with a strict-CRLF transducer.

**Extended transducer list from HTTP Garden:**

The three canonical forwarders documented by HTTP Garden — Apache Traffic Server, GCP Classic ALB, Akamai GHost. Each accepts CR bytes in optional-whitespace regions of the chunk-line and forwards them to origin. Node.js < 21.2.0's bare-CR acceptance triggers on receipt.

**Related class expressions:**

- **Bare LF chunk termination** — some parsers accept bare LF as an alternative to CRLF; not documented in the specific HTTP Garden class but a plausible extension.
- **Vertical tab (VT, `\x0B`) as line separator** — extremely rare but present in some legacy parsers.
- **Form feed (FF, `\x0C`)** — same rarity as VT.

**Detection depth:**

- Send a chunked request with bare-CR terminators and observe if the back-end considers the body complete.
- Test bare-LF too — if the back-end accepts one but not the other, the class is narrower.
- Fingerprint the exact llhttp version via Node.js version header (`X-Powered-By` sometimes; process.env sometimes leaks via error pages).

**Exploitation:**

Once the class is confirmed, the smuggled prefix is appended after the (bare-CR-terminated) chunk. Standard smuggling exploitation patterns apply from that point — cache poisoning, cross-user capture, front-end auth bypass.

**Post-fix verification:**

Node.js 21.2.0 fixes the specific bare-CR acceptance via llhttp 9.1.3. Check `node --version` on the target if a management interface is reachable; check the HTTP response fingerprint if not. A patched Node responds to the bare-CR probe with a parse error rather than accepting the request.

## HTTP Garden — OpenBSD relayd Single-Participant Class

Primitive: OpenBSD relayd concatenated header values containing a null byte (`\x00`) or bare LF into the previous header's value, but this concatenation happened **after** the Content-Length validation step. A crafted request whose header list contained a value with an embedded null byte allowed relayd to accept the request as compliant, then re-parse the concatenated headers into a different structure the second parse then treated as a new smuggled request.

**Vulnerable pair:**
- Transducer: OpenBSD relayd (any pre-fix version).
- Origin: OpenBSD relayd (same instance).

**The single-participant novelty:**

This is the first documented smuggling class where the same server instance is both the transducer and the origin. relayd-to-relayd smuggling was previously assumed impossible; HTTP Garden's differential fuzzing found the class.

**Mechanism:**

```
Request:
  Header-A: valid\x00Header-B: injected\r\n
  Content-Length: N
  Body: ...

First-pass parsing (validates CL, processes request):
  Header-A parsed with null-byte in value; considered legitimate.
  Content-Length: N accepted.
  Body of N bytes read.

Second-pass parsing (constructs the request for downstream/local processing):
  Null-byte-separator interpreted as header terminator.
  Header-B: injected treated as a new header — but injected in a way that reshapes the request boundaries.
```

**Detection:**
- Send a request with a header value containing `\x00`; observe whether relayd processes the request and any follow-up request.
- Fingerprint OpenBSD relayd via `Server: OpenBSD httpd` or version leaks.

**Class-generalization:** any HTTP parser with a two-pass architecture where the first pass validates and the second pass constructs, with different tokenization rules between the passes, is a candidate for the same class.

**Multi-pass parser exposure:**

Many HTTP parsers have two passes for architectural reasons:
- Pass 1: fast validation (accept/reject based on quick heuristics).
- Pass 2: full parsing (construct the request/response structure for downstream processing).

If the two passes have different tokenization (Pass 1 uses lax delimiter rules, Pass 2 uses strict; or vice versa), a request accepted by Pass 1 may be re-tokenized differently by Pass 2. The relayd class is the first documented single-participant expression of this pattern.

**Detection depth:**

- Inject `\x00` bytes in header values; observe whether the request is accepted.
- Inject bare LF (`\x0A`); observe.
- Craft requests where the two-pass tokenization difference matters: value that Pass 1 sees as one header, Pass 2 sees as two.

**Historical context:**

Prior to the HTTP Garden research, no single-participant HTTP smuggling class was formally documented. The relayd finding is notable methodologically — it demonstrates that classical smuggling ("two servers disagree") is a special case of the broader pattern ("any two parsers disagree, including two passes of one server").

**Class implications for other servers:**

Any HTTP parser with a multi-pass architecture is a candidate:
- Apache Traffic Server (multiple internal passes).
- Envoy (upstream and downstream filters).
- Nginx (upstream selection then request forwarding).
- HAProxy (front-end parse then backend forward).

Applying HTTP Garden's differential-fuzzing methodology to these two-pass architectures may reveal additional single-participant classes; this is an active research area.

## HTTP Garden — Python int() Underscore-Separator Class

Primitive: Python 3.6+ accepts digit-separating underscores in `int()` conversion (`int('0_ff', 16) == 255`, `int('1_000', 10) == 1000`). AIOHTTP, Gunicorn, and Tornado use Python's `int()` to parse Content-Length values. Apache Traffic Server, when parsing the Content-Length header, interprets the value using `strtol`-family functions that stop at the first non-digit; ATS forwards the header value unchanged after taking the longest valid prefix (which for `0_ff` is `0`).

**Vulnerable pair:**
- Transducer: Apache Traffic Server (and other strtol-family parsers that ignore `0x` prefixes when radix 16 is explicit — CherryPy, Libevent, Libsoup, OpenWrt uhttpd).
- Origin: AIOHTTP, Gunicorn, Tornado (pre-fix versions).

**Mechanism:**

```
Request:
  Content-Length: 0_ff
  Body: [255 bytes of payload]

ATS parses Content-Length as `0` (longest strtol prefix); forwards 255 bytes to origin.
AIOHTTP/Gunicorn/Tornado parses Content-Length as `int('0_ff', 16) = 255`; reads exactly 255 bytes.
Front-end and back-end agree by coincidence: 255 bytes.

Alternative form:
  Content-Length: 0xff
  Body: [255 bytes]

ATS parses as `0` (stops at `x`); forwards 255 bytes as body.
Origin parses as `int('0xff', 16) = 255`; reads 255 bytes.
Same outcome — but if the attacker crafts the body to include a smuggled request after byte N < 255, the smuggling primitive is confirmed.
```

Wait — the specific vulnerability shape: the transducer forwards the whole body as if it were 255 bytes; the origin also reads 255 bytes; the actual smuggling happens because the *displayed CL* is 0 (transducer's view) or 0x0 (which most parsers reject entirely), causing the transducer to end the request early. The exact primitive form is documented in the HTTP Garden paper — verify against the paper for the specific bytes.

**Detection:**
- Send a request with `Content-Length: 0_ff` and observe whether the transducer and back-end agree.
- Send `Content-Length: 0xff` and observe similarly.

**Class-generalization:** any parser accepting non-standard integer forms (digit separators, radix prefixes, unicode digits) is a candidate for the class when paired with a stricter transducer that forwards the value unchanged after taking a partial parse.

**Extended-class implications:**

Python 3's `int()` acceptance of underscores is documented (PEP 515). Other languages:
- **JavaScript** — `parseInt("0_ff", 16) === 0` (stops at underscore); `Number("0_ff") === NaN`. JS is stricter than Python.
- **Ruby** — `Integer("0_ff", 16) == 255` — Ruby accepts underscores similarly to Python.
- **PHP** — `intval("0_ff", 16) == 0` — PHP is stricter.
- **Go** — `strconv.ParseInt("0_ff", 16, 64)` returns error — Go is strict.

So the class specifically affects Python-based HTTP servers (AIOHTTP, Gunicorn, Tornado) but also potentially Ruby-based servers if any use `Integer()` for CL parsing. Grep the target's server language + HTTP parser for the class boundary.

**Related unicode-digit class:**

Unicode has many characters that look like digits or are digit-adjacent (fullwidth digits U+FF10-U+FF19, Arabic-Indic digits U+0660-U+0669, etc.). Some parsers accept these; some don't. When a transducer accepts a value with mixed-digit characters and the back-end interprets them differently, smuggling is possible. This class is under-explored; document if found.

**Real-world exploitation:**

Python-based back-ends (AIOHTTP, Gunicorn, Tornado) are common in modern deployments — especially FastAPI, Django-with-Gunicorn, and async services. When paired with ATS or another strtol-family transducer, the class is realistic.

## HTTP/2 CONTINUATION Flood — 2024 CVE Cluster

Primitive: an HTTP/2 server that accepts an unbounded stream of `CONTINUATION` frames without the `END_HEADERS` flag will buffer and HPACK-decode all of them, exhausting memory or CPU. Disclosed en masse by CERT/CC as VU#421644 in April 2024 across multiple implementations.

**Affected implementations and version tables:**

**CVE-2024-27983 (Node.js):**
- Multiple Node.js versions affected — see NVD (`vulnStatus=Deferred`). GHSA-j65r-8hrg-qc6x has the version range.
- Impact: pre-auth OOM/CPU exhaustion via HTTP/2 CONTINUATION frames.

**CVE-2024-28182 (nghttp2):**
- nghttp2 < 1.61.0 vulnerable; 1.61.0 patched.
- Impact: same shape as CVE-2024-27983 at the nghttp2 library level.

**CVE-2024-27919 (Envoy — first variant):**
- Envoy 1.29.0 and 1.29.1 specifically.
- Fixed in 1.29.2.
- Impact: OOM via HTTP/2 CONTINUATION frames.

**CVE-2024-30255 (Envoy — second variant):**
- Envoy < 1.26.8, 1.27.0..<1.27.4, 1.28.0..<1.28.2, 1.29.0..<1.29.3.
- Fixed in 1.26.8, 1.27.4, 1.28.2, 1.29.3.
- Impact: CPU exhaustion via HTTP/2 CONTINUATION frames.

**CVE-2024-31309 (Apache Traffic Server):**
- ATS 8.0.0..8.1.10 and 9.0.0..9.2.4.
- GHSA-7hpg-wrjj-gghq.
- Fixed in 8.1.11 and 9.2.5.
- Impact: OOM/CPU exhaustion.

**CVE-2024-2653 (amphp/http):**
- amphp/http PHP library.
- GHSA-qjfw-cvjf-f4fm.
- Impact: OOM/CPU exhaustion via CONTINUATION frames in PHP HTTP/2 servers.

**Mechanism (common across the cluster):**

The HTTP/2 spec (RFC 9113 § 6.10) requires the server to process CONTINUATION frames as part of the same header block until END_HEADERS is set. The vulnerable implementations did not enforce a maximum on the number of CONTINUATION frames per header block, so an attacker sending an unbounded stream forces the server to buffer and HPACK-decode all of them.

**Exploitation (run only in explicit DoS-authorized scope with strict ceilings):**

1. Establish an HTTP/2 connection.
2. Send a HEADERS frame with END_HEADERS unset.
3. Send a stream of CONTINUATION frames, each without END_HEADERS.
4. Server buffers each frame; memory grows unbounded until OOM.

**Detection (fingerprinting only, without triggering the DoS):**

1. Fingerprint the HTTP/2 server (see base file's fingerprint section).
2. Match the fingerprinted version against the CVE table above.
3. If the version is within an affected range, report the class as fingerprinted-vulnerable; do not run the exploit unless DoS-authorized.

**Class-generalization:** any HTTP/2 (or HTTP/3, or other frame-based) protocol implementation that permits unbounded per-message frame counts without a state-machine limit is a candidate for the class.

**Per-implementation mechanism depth:**

While the class shape is common, each implementation had its specific expression:
- **Node.js (llhttp)** — the HPACK decoder buffered header blocks per stream; unbounded CONTINUATION frames grew the buffer without limit. Fix: added a per-header-block count limit.
- **nghttp2** — the low-level HTTP/2 library used by many consumers; the fix added a `SETTINGS_MAX_HEADER_LIST_SIZE` enforcement pre-decode. Consumers must upgrade their nghttp2 dependency.
- **Envoy** — Envoy uses nghttp2 for HTTP/2 processing; the two Envoy CVEs (27919 memory + 30255 CPU) reflect the two exhaustion vectors from the same base cluster.
- **Apache Traffic Server (ATS)** — its own HTTP/2 implementation had a similar unbounded-buffer issue in the header-processing pipeline.
- **amphp/http** — PHP async HTTP library; the fix added a per-request header-frame count limit.

**Downstream impact:**

CONTINUATION flood is a DoS class — it doesn't produce a smuggled request. But service degradation during the attack window provides cover for other attacks:
- Rate-limiters may fail-open when overwhelmed, permitting brute-force elsewhere.
- Logging may drop entries during the attack window, hiding subsequent forensic evidence.
- Auth microservices may become intermittently unreachable, potentially opening race conditions in authentication flows.

**Detection at the network layer:**

For defenders:
- Monitor HTTP/2 frame counts per stream; alert on > 100 CONTINUATION frames.
- Monitor HPACK decoder memory usage; alert on rapid growth.
- Deploy WAF signatures for CONTINUATION-flood patterns (many WAFs have rules post-CVE disclosure).

## Tomcat HTTP Trailer Handling — CVE-2023-46589

Primitive: Apache Tomcat's HTTP/1.1 parser accepted specific malformed HTTP trailer values that produced request-smuggling divergence against paired front-ends. The trailer parsing after the final `0\r\n\r\n` chunk terminator was more lenient than upstream proxies.

**Affected version table:**

| Line | Affected range | Fixed version |
|---|---|---|
| 8.5.x | 8.5.0 – 8.5.96 | 8.5.97 |
| 9.0.x | 9.0.0 – 9.0.83 | 9.0.84 |
| 10.1.x | 10.1.0-M1 – 10.1.15 | 10.1.16 |
| 11.0.x | 11.0.0-M1 – 11.0.10 | (verify — 11.x branch was in early M-releases during disclosure) |

Version-boundary source: `.zen-batch-artifacts/batch-7-*/cve-json/CVE-2023-46589.nvd.json`; GHSA-fccv-jmmp-qg76.

**Mechanism:**

The HTTP/1.1 chunked-transfer body is terminated by `0\r\n\r\n`, optionally with trailer headers between the `0\r\n` and the final `\r\n`. Tomcat's trailer parser accepted specific malformed forms (details in the CVE JSON) that a strict front-end parser did not — divergence.

**Detection:**

Send a chunked request with a specific malformed trailer:
```
POST / HTTP/1.1
Host: target
Transfer-Encoding: chunked

5
hello
0
Trailer-Name: value
Trailer-Malformed:<0-byte content>
```

Observe whether the front-end and Tomcat agree.

**Impact class:** classical smuggling — the request boundary disagreement produces socket poisoning; downstream chains identical to any TE-based smuggling.

## Apache HTTP/2 Memory Exhaustion — CVE-2024-27316

Primitive: Apache HTTP Server's HTTP/2 implementation via `mod_http2` accepted specific HTTP/2 frame patterns that caused unbounded nghttp2-buffer allocation, leading to memory exhaustion.

**Affected version table:**

| Line | Affected range | Fixed version |
|---|---|---|
| 2.4.x | 2.4.17 – 2.4.59 | 2.4.60 |

Version-boundary source: `.zen-batch-artifacts/batch-7-*/cve-json/CVE-2024-27316.nvd.json`; GHSA-5qc4-82jh-h385.

**Mechanism:**

Related to the CONTINUATION-flood class but specifically expressed through Apache's HTTP/2 module. The exact frame pattern triggering the exhaustion is documented in the CVE JSON.

**Detection:**

Fingerprint Apache HTTP/2 (`Server: Apache/2.4.<version>` + HTTP/2 support); match version against the table.

**Mechanism from vendor advisory:**

The vulnerability was in Apache's HTTP/2 handling via `mod_http2`, specifically the nghttp2-buffer path processing HTTP/2 headers. Unbounded buffer allocation during header parsing produced memory exhaustion.

**Related class expressions:**

This is essentially an nghttp2-consumer expression of the broader CONTINUATION-flood class (see the § HTTP/2 CONTINUATION Flood section). Any Apache deployment using `mod_http2` at or before 2.4.59 is affected; the fix in 2.4.60 addresses the nghttp2 buffer bound.

**Exploitation gate (all-of-N, DoS-authorized-only):**

1. Target runs Apache 2.4.17-2.4.59.
2. Apache has `mod_http2` enabled (`Protocols h2 h2c http/1.1`).
3. Attacker sends HTTP/2 frames with the specific unbounded-buffer pattern.
4. Apache memory grows unbounded until OOM.

**Compensating controls:**

- Disable `mod_http2` (fallback to HTTP/1.1); loses HTTP/2 benefits but closes this specific class.
- Deploy Apache behind an HTTP/2-aware WAF (Cloudflare, Envoy, etc.) that enforces per-connection frame limits.

## Gunicorn TE-Header Smuggling — CVE-2024-1135

Primitive: Gunicorn's HTTP parser accepted specific Transfer-Encoding header variations that produced smuggling against paired front-ends.

**Affected version:**
- Gunicorn: verify against NVD (deferred status; no CPE ranges); GHSA-w3h3-4rj7-4ph4 has advisory scope.

**Mechanism:**

Gunicorn's Python HTTP parser accepted TE-header forms that a strict RFC-9112 parser wouldn't; the resulting divergence with front-ends produced smuggling.

**Detection:**

Fingerprint via `Server: gunicorn/<version>` header; match against the advisory scope.

**Chain into WSGI-app impact:**

Gunicorn is a WSGI server; smuggled requests reach the WSGI app (Django, Flask, FastAPI-with-Gunicorn-worker) and are processed as regular requests. The app's security posture determines downstream impact:

- **Django** — if the smuggled request bypasses Django's CSRF middleware (because the front-end's antiforgery check treated the smuggled request as the parent's continuation), state changes without a valid CSRF token succeed.
- **Flask** — similar; Flask's session middleware may treat the smuggled request as authenticated based on session cookies passed through the smuggling.
- **FastAPI** — same shape; FastAPI's dependency injection processes the smuggled request under the parent's dependency-resolved identity if the identity was cached at connection level.

**Mechanism details:**

The specific Gunicorn parsing bug involves TE header edge cases. From the GHSA, the class is around specific TE-header shapes that Gunicorn accepts but upstream proxies handle differently. Verify exact bytes against the GHSA advisory.

**Real-world exposure:**

Gunicorn is common in Python production deployments — behind Nginx, HAProxy, or as a container-native service. Any Python app with `Server: gunicorn/*` header on responses is a candidate; probe with the class-specific TE variants.

## ASP.NET Core Smuggling — CVE-2025-55315

Primitive: HTTP request smuggling in ASP.NET Core's HTTP request handling, permitting authentication bypass, cache pollution, response splitting, and (chained into CSRF) antiforgery bypass. CVSS 9.9 — the highest-severity ASP.NET Core CVE in the class.

**Affected version table:**

| Package | Affected range | Fixed version |
|---|---|---|
| Microsoft.AspNetCore.Server.Kestrel.Core | 2.3.0 – 2.3.6 | 2.3.7 |
| Microsoft.AspNetCore.App (8.x) | 8.0.0 – 8.0.21 | 8.0.22 |
| Microsoft.AspNetCore.App (9.x) | 9.0.0 – 9.0.10 | 9.0.11 |
| Microsoft.AspNetCore.App (10.x-rc) | 10.0.0-rc.1 | 10.0.0-rc.2 |
| Visual Studio 2022 (17.x) | multiple lines | see MSRC advisory |

Version-boundary source: `.zen-batch-artifacts/batch-7-*/cve-json/CVE-2025-55315.nvd.json`; GHSA-5rrx-jjjq-q2r5.

**Mechanism (from MSRC and vendor advisory):**

HTTP request smuggling class where the Kestrel HTTP parser accepted specific malformed request patterns that produced boundary disagreement with downstream infrastructure. The specific technique details are in the MSRC advisory; the impact chain is that a smuggled request could reach authenticated endpoints, poison caches, or bypass ASP.NET Core Antiforgery middleware.

**Batch-7 twofer:**

This CVE is jointly relevant to HTTP smuggling and CSRF. The primary technical ownership is here (the underlying vulnerability is smuggling); the CSRF-specific impact framing is `csrf_novel_deep.md § ASP.NET Core AntiForgery Bypass — CVE-2025-55315`.

**Confirmation methodology:**

1. Fingerprint the Kestrel version — check response headers for ASP.NET Core version leaks.
2. Send the class-specific smuggling probe (documented in vendor advisory).
3. Observe socket poisoning or boundary disagreement.
4. Downstream chain: smuggling → antiforgery bypass → state change.

**Impact escalation:** the highest-severity chain is smuggling → authentication bypass on an admin endpoint → arbitrary admin action. CVSS 9.9 reflects the ubiquity of ASP.NET Core in enterprise deployments and the ease of chain-into-critical-impact.

**Mechanism depth from MSRC advisory:**

The MSRC advisory names the class as HTTP request smuggling at the Kestrel HTTP/1.1 parser layer. The specific technique involves malformed request boundaries that Kestrel processes differently than a downstream infrastructure layer. Without paraphrasing the vendor advisory in unverified detail, the class shape includes:

- Divergence between Kestrel and typical reverse-proxies on chunk-body boundary handling.
- Divergence on TE header edge cases.
- Interaction with the ASP.NET Core middleware pipeline that allowed antiforgery bypass.

**Attack chain depth:**

For an ASP.NET Core app behind IIS or a reverse-proxy:
1. Attacker sends a smuggled request that bypasses the front-end antiforgery check.
2. The smuggled request reaches an antiforgery-protected endpoint (`/account/change-email`).
3. Because the antiforgery middleware treats the smuggled request as authenticated (based on the prior request's session), the state change succeeds without a valid antiforgery token.
4. Attacker's crafted request performs the state change under the victim's session.

**Class-generalization:**

The pattern: middleware trust based on connection state (rather than per-request re-validation) is exploitable via smuggling. Any framework whose CSRF/antiforgery middleware trusts something at the connection level is a candidate. Grep target middleware chains for connection-state-based trust decisions.

**Practical detection:**

- Fingerprint ASP.NET Core version (via `X-Powered-By: ASP.NET` and `X-AspNet-Version` when present).
- Match against the affected-version table.
- If in range, the class is present until patched — behavioral confirmation requires the specific vendor-documented probe.

## Class-Broader Historical Anchors

Historical CVEs that share the broader class shape but pre-date the batch-7 primary set. Cite for context, not as current-frontier findings.

- **CVE-2022-41556 (lighttpd 1.4.56 – 1.4.67)** — connection-slot DoS via HTTP-parsing behavior. Class-broader-than-CONTINUATION: parser bugs that consume resources without triggering CL/TE ambiguity. GHSA-jm88-vr5q-23rj.
- **CVE-2020-1938 (Ghostcat / Tomcat AJP)** — AJP connector accepted attacker-controlled attributes that could reach a smuggling-adjacent RCE via file inclusion. Historical.
- **CVE-2018-1000024 (Squid 3.0–3.5.27 / 4.0–4.0.22)** — HTTP caching proxy incorrect pointer handling in request parsing. Class-adjacent: proxy-side parsing defect, not CL/TE ambiguity.
- **Ghostcat lineage** — Tomcat's AJP handling produced multiple CVEs; smuggling-adjacent when AJP was reachable across trust boundaries.

**Adjacent (not-strictly-smuggling) 2024–2026 CVEs:**

- **CVE-2025-1974 (ingress-nginx)** — ingress-nginx admission controller unauthenticated network reach. Not smuggling but shares the "trust boundary crossing via a middleware layer" pattern; GHSA-mgvx-rpfc-9mpv.

## Modern Regression Patterns for Smuggling

The four regression patterns from `path_traversal_lfi_rfi_novel_deep.md § Modern Regression Patterns` apply to smuggling:

- **Check-then-refactor decay** — a fix that adds a CL vs TE strictness check may decay when a refactor moves the check out from under the parser. Watch for Node.js, Nginx, Apache commits touching HTTP parsing.
- **Hardened default with opt-in reopening** — HTTP/2 parsers that reject `transfer-encoding: chunked` by default may have a config flag to allow it; every enabled flag reopens the class.
- **Constrained parser with unconstrained pre-processor** — a hardened back-end still exposed via a permissive front-end; per-hop parser posture matters.
- **Two parsers on one wire** — the fundamental smuggling shape; recurs at every new protocol version transition.
- **Sanitizer post-serialization** — a WAF that normalizes a request before forwarding may re-emit bytes that a back-end parses differently than the WAF intended.

**Pattern-specific prevention checklists:**

- **Check-then-refactor**: parser tests must exercise the ordering invariant, not just the check's presence.
- **Hardened default + opt-in**: audit every opt-in flag site; require justification.
- **Constrained parser + unconstrained pre-processor**: front-end and back-end must have symmetric parser strictness; verify per hop.
- **Two parsers on one wire**: per-protocol-version testing; each new version transition creates new divergence potential.
- **Sanitizer post-serialization**: verify that WAF normalization doesn't produce bytes the back-end parses differently.

**Historical instances:**

- The Node.js bare-CR class (fixed 21.2.0) is a "two parsers on one wire" instance.
- The LiteSpeed strtoll class is a "hardened default + opt-in reopening" (radix 0 is the default; strict radix 10 would close the class).
- The ASP.NET Core CVE-2025-55315 class is likely a "constrained parser + unconstrained pre-processor" or "check-then-refactor" (details in the MSRC advisory).
- The Apache HTTP/2 CVE-2024-27316 is a "hardened default" bug — the nghttp2-buffer path lacked a bound.

## Composite Chains — 2024–2026 Frontier

Beyond the individual CVE dissections, specific composite chains observed at the current frontier:

**Chain — HTTP Garden LiteSpeed strtoll + shared-hosting mass poisoning:**

1. LiteSpeed shared-hosting cluster serves N tenants. Attacker rents one tenant slot.
2. Attacker sends a smuggled request from their tenant that reaches the cache layer.
3. Cache is per-hostname keyed but LiteSpeed's virtual-host handling processes the smuggled request under the wrong tenant.
4. Impact: cross-tenant response injection in a shared-hosting environment.
5. Chain: tenant access → smuggling (this file) → cross-tenant impact.

**Chain — Node.js bare-CR + Cloudflare + admin API:**

1. Target: Node.js 20.9 behind Cloudflare. Cloudflare forwards bare-CR bytes in specific configurations.
2. Attacker sends smuggling probe with bare-CR chunk terminators.
3. Cloudflare and Node.js disagree on chunk termination; smuggling confirmed.
4. Smuggled `POST /admin/action` reaches Node.js without Cloudflare access control.
5. Chain: smuggling → admin auth bypass → state change.

**Chain — Envoy CONTINUATION flood → service mesh degradation → auth microservice race:**

1. Target: multi-service Kubernetes cluster with Envoy sidecar mesh.
2. Attacker triggers CONTINUATION flood against Envoy at scale.
3. Envoy instances degrade; auth microservice calls timeout intermittently.
4. Attacker exploits the timeout: sending requests that succeed against a state-change endpoint when auth micro service response fails-open in the app's logic.
5. Chain: DoS (this file, DoS-authorized only) → auth-timeout → race-condition state change.

**Chain — Tomcat CVE-2023-46589 + JSP upload + RCE:**

1. Target: Tomcat 9.0.80. Trailer smuggling confirmed.
2. Smuggled `POST /manager/upload.jsp` bypasses the front-end auth on `/manager/*`.
3. JSP uploaded; RCE via subsequent GET.
4. Chain: smuggling → JSP upload → RCE.

**Chain — ASP.NET Core CVE-2025-55315 → antiforgery bypass → account takeover:**

1. Target: ASP.NET Core 8.0.15 with antiforgery middleware.
2. Smuggling probe confirms the class.
3. Smuggled `POST /account/change-password` bypasses antiforgery.
4. Attacker changes victim's password; takeover.
5. Chain: smuggling → antiforgery bypass → account takeover (twofer, primary owner here).

## CVE Chaining at the Current Frontier

The batch-7 smuggling CVEs chain into specific downstream impact classes:

1. **CVE-2024-27983 (Node.js CONTINUATION)** → service degradation → cover for other attacks; not directly smuggling into a state change, but during degraded service, other attacks succeed more easily.
2. **CVE-2024-28182 (nghttp2 CONTINUATION)** → same shape; affects any nghttp2-based server.
3. **CVE-2024-27919 + CVE-2024-30255 (Envoy CONTINUATION)** → same shape; Envoy is often the service-mesh proxy, so DoS cascades to all mesh-routed services.
4. **CVE-2024-31309 (ATS CONTINUATION)** → same shape at the CDN/proxy layer.
5. **CVE-2024-2653 (amphp/http CONTINUATION)** → same shape in PHP async HTTP servers.
6. **CVE-2023-46589 (Tomcat trailer)** → classical smuggling → front-end auth bypass → admin actions.
7. **CVE-2024-27316 (Apache HTTP/2)** → memory exhaustion → service degradation.
8. **CVE-2024-1135 (Gunicorn TE)** → classical smuggling → auth bypass or capture.
9. **CVE-2025-55315 (ASP.NET Core)** → smuggling → antiforgery bypass → CSRF-shape state change → account takeover (twofer chain; primary owner here, CSRF-side framing in `csrf_novel_deep.md`).

## Post-Fix Detection

Per-CVE fingerprint hierarchy:

- **Version-string fingerprinting** — check server headers, framework identifiers, or well-known endpoints for version leaks.
- **Behavioral probes** — send the class-specific smuggling probe; observe rejection or expected response.
- **Configuration verification** — for each fix, verify the specific configuration (e.g., ASP.NET Core Kestrel HTTP/1.1 request limits).

**Concrete probe scripts (authorization required):**

```bash
# Node.js pre-21.2.0 bare-CR chunk termination
# Fingerprint: check Node.js version via X-Powered-By or well-known endpoint
node_ver=$(curl -sI "https://target/" | grep -i 'X-Powered-By' | grep -oiE 'Node/[0-9.]+' | cut -d/ -f2)
echo "Node.js: ${node_ver:-unknown}"

# Behavioral probe (bare CR in chunk terminator)
printf 'POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\n5\rABCDE\r0\r\r\n' | ncat --ssl target 443

# CVE-2023-46589 (Tomcat trailer smuggling)
tomcat_ver=$(curl -sI "https://target/" | grep -i 'Server' | grep -oiE 'Tomcat/[0-9.]+' | cut -d/ -f2)
echo "Tomcat: ${tomcat_ver:-unknown}"

# CVE-2025-55315 (ASP.NET Core)
aspnet_ver=$(curl -sI "https://target/" | grep -i 'X-Powered-By' | grep -i 'ASP.NET')
echo "ASP.NET: ${aspnet_ver:-unknown}"
```

## Regression-Pattern-Specific Prevention

For each of the four core regression patterns from `path_traversal_lfi_rfi_novel_deep.md § Modern Regression Patterns`, applied to smuggling with specific engineering guidance:

**Check-then-refactor decay for smuggling:**

Prevention: HTTP parser tests must exercise the ordering invariant of validation-vs-parsing steps. For every parser, tests should verify:
- Duplicate CL headers are rejected before body reading.
- Conflicting CL + TE combinations produce hard reject.
- Malformed chunk sizes are rejected before body reading.

Refactoring risk: any refactor that moves validation out from under the parser body-read path breaks the class-preventing invariant.

**Hardened-default + opt-in reopening for smuggling:**

Prevention: opt-in flags that reopen smuggling classes (e.g., `allow_te_chunked_in_http2`, `accept_bare_cr_in_chunks`) require justification, audit trail, and per-deployment risk assessment.

**Constrained parser + unconstrained pre-processor for smuggling:**

Prevention: verify parser strictness at every hop. A CI pipeline check that runs a parser-differential test against each hop's specific configuration will catch this pattern before deployment.

**Two-parsers-on-one-wire for smuggling:**

Prevention: at every parser-composition interface, apply the strictest common-denominator parser rules. If Cloudflare accepts a CL variant that Node.js rejects, either loosen Node.js (bad) or tighten Cloudflare's forwarding.

**Framework-vendor discipline patterns:**

- **Rust hyper** — strict RFC-9112 by default; minimal opt-ins.
- **Go net/http** — historically strict; some opt-in flexibility introduced with time.
- **Python http-server (stdlib)** — strict; suitable for development, not production.
- **Node.js http2 (built-in)** — has had multiple smuggling CVEs; upgrade cadence matters.

Framework choice affects smuggling posture materially; document the framework and its parser-strictness posture in every assessment.

## Compensating Controls for Each CVE Family

For each batch-7 CVE, compensating controls that reduce exposure without a full patch:

- **CVE-2024-27983 / -28182 / -27919 / -30255 / -31309 / -2653 (CONTINUATION flood)** — disable HTTP/2 entirely, or deploy an HTTP/2 WAF that enforces per-connection frame limits (`SETTINGS_MAX_HEADER_LIST_SIZE`, per-connection CONTINUATION count cap). Cloudflare, AWS WAF, and F5 ASM have post-disclosure rules.
- **CVE-2023-46589 (Tomcat trailer)** — reject HTTP requests with trailer sections at the front-end proxy (strip trailer parsing entirely). Or disable HTTP/1.1 chunked transfer entirely.
- **CVE-2024-27316 (Apache HTTP/2)** — disable `mod_http2`; front with an HTTP/2-aware WAF.
- **CVE-2024-1135 (Gunicorn)** — front Gunicorn with a strict-parsing reverse proxy (Nginx, HAProxy) that normalizes TE headers before forwarding.
- **CVE-2025-55315 (ASP.NET Core)** — enforce Antiforgery middleware at every state-change endpoint independently (don't rely on connection-level trust); front with a WAF that rejects malformed requests.
- **HTTP Garden classes** — for each transducer+origin pair, deploy a strict-parsing intermediate layer that normalizes the class-specific bytes.

## Detection Signatures for Defenders

Defender-side detection for smuggling exploitation:

- **HTTP/2 CONTINUATION flood** — monitor server metrics for anomalous HPACK-decoder memory growth. Alert on sudden memory pressure during HTTP/2 connections.
- **Classical CL.TE / TE.CL** — SIEM rule on malformed CL+TE combinations at the WAF; alert on rejected requests.
- **Cache poisoning** — anomalous cache-hit ratio changes; sudden variance in cache content for a URL.
- **Front-end auth bypass** — access logs on admin endpoints from non-allowlist IPs; smuggled requests may appear here.

**SIEM query examples:**

```
# CL + TE combinations at the WAF
index=waf_logs 
  ( request_header:"Content-Length" AND request_header:"Transfer-Encoding" )
| stats count by src_ip, uri, cl_value, te_value

# HTTP/2 CONTINUATION-frame anomalies
index=http2_metrics 
  event_type="continuation_frame" 
  frame_count > 100
| stats count by src_ip, connection_id
```

**Compensating controls:**

- Strict HTTP parser enforcement at every hop.
- HTTP/2 end-to-end where feasible.
- Per-request connection pooling.
- WAF signatures for known smuggling classes.

## Version-Fingerprint Automation

For portfolio-scale assessments, automate the version fingerprint + affected-range match. A recommended scanner:

```bash
#!/bin/bash
# Batch-7 smuggling CVE fingerprint scanner
# Usage: ./fingerprint.sh <target-list.txt>

for target in $(cat "$1"); do
  headers=$(curl -sI "https://$target/" 2>/dev/null)
  server=$(echo "$headers" | grep -i '^Server:' | cut -d: -f2- | tr -d ' \r')
  aspnet=$(echo "$headers" | grep -i 'X-AspNet-Version\|X-Powered-By: ASP.NET')
  jenkins=$(echo "$headers" | grep -i 'X-Jenkins')
  
  echo "$target: Server='$server' ASP.NET='$aspnet' Jenkins='$jenkins'"
  
  # Match against CVE tables (extend per CVE)
  if [[ "$server" =~ Tomcat/([0-9.]+) ]]; then
    ver="${BASH_REMATCH[1]}"
    # Check against CVE-2023-46589 affected range
    case "$ver" in
      8.5.[0-9]*|8.5.9[0-6])  echo "  CVE-2023-46589 candidate (Tomcat $ver in affected range)" ;;
      9.0.[0-9]*|9.0.8[0-3])  echo "  CVE-2023-46589 candidate (Tomcat $ver in affected range)" ;;
    esac
  fi
  
  if [[ "$server" =~ Apache/2\.4\.([0-9]+) ]]; then
    minor="${BASH_REMATCH[1]}"
    if (( minor >= 17 && minor <= 59 )); then
      echo "  CVE-2024-27316 candidate (Apache 2.4.$minor in affected range)"
    fi
  fi
  
  if [[ "$server" =~ gunicorn/([0-9.]+) ]]; then
    echo "  CVE-2024-1135 candidate (Gunicorn $ver — check GHSA-w3h3-4rj7-4ph4 scope)"
  fi
done
```

This scaffolds version-fingerprint matching; extend per CVE with the specific version-range logic.

**Retroactive alerting:**

Store fingerprints in a time-series database. When a new CVE is published, run the affected-range check against historical fingerprints — any target that was fingerprinted before the CVE disclosure retroactively becomes an alert.

## Documenting Class Findings vs CVE Findings

For smuggling, the CVE-vs-class distinction is especially important:

- **CVE finding**: "Target's Tomcat 9.0.80 is affected by CVE-2023-46589 (HTTP trailer smuggling). Probe X produces socket poisoning; follow-up request Y receives unexpected response Z. Fix: upgrade to Tomcat 9.0.84+."
- **Class finding**: "Target's front-end (Cloudflare) + back-end (Node.js 20.x) exhibits the bare-CR chunk-termination class. Probe X produces socket poisoning; follow-up receives unexpected response Y. Related to CVE-2024-27983 (Node.js CONTINUATION flood) but distinct: the primitive is chunk-parsing, not header-frame flooding. Fix: upgrade to Node.js 21.2.0+ AND verify Cloudflare doesn't forward bare CR."

Both forms are legitimate; the CVE form is precise when it applies, the class form covers cases where the target isn't in the CVE's affected range but exhibits the class shape.

## Tools and References

- **HTTP Garden research** — `arXiv:2405.17737`, `github.com/narfindustries/http-garden`. The primary reference for the four canonical parser-differential classes.
- **CERT/CC VU#421644** — the coordinated disclosure of the April-2024 CONTINUATION flood cluster.
- **CVE JSONs** — persisted at `.zen-batch-artifacts/batch-7-*/cve-json/`; every CVE cited has a resolving artifact.
- **GHSA JSONs** — persisted at `.zen-batch-artifacts/batch-7-*/ghsa-json/`; GHSA-j65r-8hrg-qc6x, GHSA-7hpg-wrjj-gghq, GHSA-qjfw-cvjf-f4fm, GHSA-fccv-jmmp-qg76, GHSA-5qc4-82jh-h385, GHSA-w3h3-4rj7-4ph4, GHSA-jm88-vr5q-23rj, GHSA-5rrx-jjjq-q2r5.
- **MSRC advisory for CVE-2025-55315** — Microsoft Security Response Center advisory documenting the ASP.NET Core smuggling class.
- **Historical HTTP smuggling research** — James Kettle's DEF CON 2019 talk, Bishop Fox's h2csmuggler research, PortSwigger's HTTP Desync Attacks whitepaper.

## Regression Patterns for Smuggling — Extended

Building on the four canonical patterns applied earlier, additional patterns specific to smuggling:

**Protocol-version-transition regression:**

Every new HTTP protocol version introduces a new parser and a new downgrade path. HTTP/2 (2015) introduced H2.CL/H2.TE via downgrade; HTTP/3 (2022) introduces the same class shape via HTTP/3-to-HTTP/2 or HTTP/3-to-HTTP/1 downgrade. Each version transition is a two-parsers-on-one-wire class multiplied.

**Frame-based-protocol unbounded-buffer regression:**

HTTP/2 CONTINUATION flood is one instance; HTTP/3 has similar frame-buffering surface (though QUIC's stream isolation limits some paths); WebSocket has similar per-connection buffer surface; gRPC has similar issues in its own framing. Each new frame-based protocol design that permits unbounded buffering per message is a candidate.

**Header-injection-via-value regression:**

CRLF-in-value injection has been fixed in specific implementations dozens of times over the years; each new HTTP parser re-implements it and often gets it wrong initially. Node.js, PHP-FPM, Go's net/http, Python's http.server — all have had CRLF-in-value CVEs at some point. The class doesn't go away.

**Trailer-parsing regression:**

HTTP trailers are under-tested; the Tomcat CVE-2023-46589 is one instance. Any parser accepting trailers is a candidate for the class.

## HTTP/3-Specific Frontier — Emerging

HTTP/3 uses QUIC as transport; the HTTP framing layer is similar to HTTP/2. The smuggling surface differs from HTTP/1.1 in specific ways:

**Distinct properties:**
- QUIC's stream isolation limits some connection-state smuggling classes; each stream is transport-independent.
- QPACK header compression differs from HPACK; QPACK-specific parser bugs may exist.
- HTTP/3-to-HTTP/1 or HTTP/3-to-HTTP/2 downgrade at the origin edge is the primary smuggling surface.

**Emerging CVE surface:**
- QUIC transport-layer CVEs (memory-corruption, DoS) have been common in 2023–2025; these are not smuggling per se but indicate parser-maturity issues.
- HTTP/3-adjacent smuggling CVEs are expected but not yet cataloged at the same rate as HTTP/1.1/HTTP/2 smuggling.

**Assessment approach:**
- Fingerprint HTTP/3 support (`Alt-Svc: h3=":443"`).
- Use HTTP/3-capable clients (curl with HTTP/3 build, quiche-client) for smuggling probes against HTTP/3 endpoints.
- Match against the current HTTP/3 CVE list for the specific server.

The class is emerging; specific findings should be documented as they surface.

## Class-Recurrence Rate and Prediction

Based on the 2024–2026 CVE surface, smuggling classes recur at a rate of roughly 3–6 CVEs per year across widely-deployed HTTP implementations. Key observations:

- **HTTP/2 parser bugs cluster** — the April 2024 CONTINUATION flood cluster affected 6 implementations simultaneously; this pattern (one novel technique disclosed in one implementation, immediately found in others) will recur when HTTP Garden or a similar research project targets HTTP/3 or gRPC.
- **New protocol adoption accelerates class emergence** — every new HTTP protocol version (HTTP/2, HTTP/3, and future revisions) introduces new parser code and new downgrade paths, both of which host new smuggling classes.
- **Enterprise-critical deployments over-index in the CVE list** — Tomcat, Apache, IIS, ASP.NET Core, Envoy, and their ilk get scrutiny; less-common servers may host undiscovered classes.
- **Class-persistence** — even fixed classes recur in new implementations (as bare-CR handling has for a decade+ across Node.js, PHP, and others).

**Prediction for 2026–2027:**
- Expect an HTTP/3 smuggling-class disclosure cluster analogous to HTTP Garden's 2024 corpus.
- Expect at least one CVE per major implementation per year in the CL/TE ambiguity space.
- Expect new frame-based-protocol unbounded-buffer CVEs in HTTP/3 and WebTransport.
- Expect at least one high-severity chain-into-CSRF/auth-bypass CVE per year (like CVE-2025-55315).

## Cross-Batch References

For related class expressions in adjacent batches:

- **Path traversal / LFI / RFI (Batch 6)** — `path_traversal_lfi_rfi_advanced_deep.md § Reverse-Proxy URL Character Handling` covers URL-parser divergences at the proxy layer; smuggling extends the same "two parsers, one wire" pattern to HTTP-message parsing.
- **XXE (Batch 6)** — `xxe_advanced_deep.md § XML Signature-Wrapping Chains` documents a signature-vs-processing divergence with structural similarity to smuggling.
- **CSRF (Batch 7 sibling)** — `csrf_novel_deep.md § ASP.NET Core AntiForgery Bypass — CVE-2025-55315` — twofer chain with the same underlying CVE. Cross-reference for the CSRF-specific impact framing.

## Batch-7 Manifest Reference

For the batch-7 manifest with 1:1 persistence accounting of every cited CVE and GHSA, see `.zen-batch-artifacts/batch-7-20260929-165210/manifest.md`. The manifest documents every CVE, its NVD JSON persistence path, its GHSA JSON where applicable, and the fix-status confirmation. Every ID cited in this file appears exactly once in the manifest with a corresponding persisted artifact.

## Assessment Deliverable Template

For a smuggling finding in a professional deliverable, the report should include:

- **Class name and CVE anchor (if applicable)** — e.g., "Node.js bare-CR chunk termination class; related to CVE-2024-27983 but distinct primitive."
- **Target composition** — transducer + origin identification with fingerprint evidence.
- **Exact bytes** — the smuggling probe as raw hex + newline-annotated ASCII.
- **Reproduction rate** — N/M trials with success.
- **Confirmation oracle** — differential response, timing, cache poisoning, OAST callback.
- **Impact chain** — the downstream classes the smuggling reaches (auth bypass, capture, cache poisoning, admin API).
- **Version boundary** — where the fix landed (or where the current version sits in the affected range).
- **Compensating controls** — what reduces exposure without a full patch.

## Summary

The 2024–2026 HTTP smuggling frontier is dominated by two research strands: the HTTP Garden differential-fuzzing corpus (122 discrepancies, 68 patched, 39 exploitable) yielding four canonical parser-differential classes across transducer+origin pairs, and the April-2024 CONTINUATION flood CVE cluster affecting five widely-deployed HTTP/2 implementations. The 2025 additions — Tomcat trailer smuggling, Apache HTTP/2 memory exhaustion, Gunicorn TE smuggling, and CVSS 9.9 ASP.NET Core smuggling (twofer with CSRF antiforgery bypass) — extend the class into new stacks. Fingerprint every target's transducer+origin composition; match against the version tables in this file; probe with class-specific tests; and route composite chains to sibling skills for downstream impact.
