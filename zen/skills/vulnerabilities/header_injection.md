---
name: header-injection
description: HTTP header-injection testing — CRLF response splitting, cache poisoning via unkeyed headers, Host-header password-reset poisoning, X-Forwarded-* trust-boundary abuse, cookie fixation, internal-redirect handler-confusion, method-override classes, and the measured framework Host-trust behavior across Flask / FastAPI / Starlette.
---

# HTTP Header Injection

Header injection turns user input into protocol-level control: response splitting, cache poisoning, session fixation, authentication bypass, and downstream parser confusion can trace back to a server-controlled header value that was not normalized. The bug usually lives in middle layers — frameworks that copy a request value into a response header, proxies that trust forwarded headers, caches keyed on something the attacker influences. Impact depends on which downstream component consumes the injected field and how.

## Attack Surface

**Input shapes that reach headers**

- Query/body/path values echoed into `Set-Cookie`, `Location`, `Content-Type`, `Content-Disposition`, `Link`, custom `X-*`.
- Request headers re-emitted into responses (Referer, User-Agent, X-Forwarded-*, custom correlation IDs).
- Webhook / callback flows where the server constructs outbound requests using user-supplied URLs (Host, Referer).
- Outbound email headers (To/From/Subject) populated from user input (SMTP header injection — separate class, same root cause).

**Code patterns that enable injection**

- Direct concatenation of user input into header values without CR/LF stripping.
- Frameworks that accept header values as strings and serialize verbatim (no normalization).
- Proxy chains trusting `X-Forwarded-*` / `Forwarded` / `X-Real-IP` set by an upstream that anyone can spoof.
- `X-HTTP-Method-Override` and similar method-shaping headers respected past auth layers.
- Flask `url_for(_external=True)` / FastAPI `request.url_for` / Rails `request.host` without a configured canonical host.

**Transports and parser layers**

- HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 each parse framing differently.
- CDN / reverse proxy → application server (where each side may disagree on framing).
- Chunked transfer encoding boundaries and multipart/form-data delimiters.

## High-Value Targets

- Password-reset and account-recovery flows (Host header determines the link sent to the user).
- OAuth / SSO redirect endpoints (`Location`, `redirect_uri` echoes).
- Auth gateways that trust `X-Forwarded-For` / `X-Real-IP` for IP allowlists or rate limits.
- CDN / WAF caches (poisoning a public cache with a per-user response).
- Multi-tenant routing keyed on Host or `X-Tenant-Id`.
- File-download endpoints (`Content-Disposition` filename derived from user input).
- Outbound notification / email systems where user input lands in the message header.

## Measured Framework Host-Trust Behavior

Measured locally (persisted at `.zen-batch-artifacts/batch-11/measurements/host_header_trust.py`+`.out`): three framework host-URL-construction patterns under a Host-spoof probe (`Host: attacker.tld`):

| Framework | `url_for(_external=True)` / equivalent | `request.host_url` / `base_url` |
|---|---|---|
| Flask (no `SERVER_NAME` set — default) | `http://attacker.tld/reset/<token>` | `http://attacker.tld/` |
| Flask (`SERVER_NAME=canonical.example.com`) | `https://canonical.example.com/reset/<token>` | `https://attacker.tld/` (still reflects!) |
| FastAPI / Starlette default | `http://attacker.tld/reset/<token>` | `http://attacker.tld/` |

What this proves:

1. **Flask's `SERVER_NAME` fixes `url_for` but not `request.host_url`.** A codebase that uses `url_for(_external=True)` for links is safe; one that interpolates `request.host_url` into email bodies is not. This is the CVE-2025-61136 (axewater sharewarez) pattern: `url_for(_external=True)` on an unconfigured Flask app.
2. **FastAPI / Starlette has no SERVER_NAME-equivalent.** `request.url_for` and `request.base_url` both reflect Host directly; the only defence is a reverse-proxy-level Host-rewrite or explicit canonicalization in application code.
3. **The CVE pattern across Pimcore / ArrowCMS / scheduleR / Coolify / Kanboard / sharewarez is the same shape.** The application pulls `request.host`/`Host` into the password-reset URL; the attacker spoofs it; the reset token delivers to the attacker's domain via the email.

## Reconnaissance

### Header Inventory

- Enumerate every response header that varies with input — flip query / body / cookie values and diff `Set-Cookie`, `Location`, `Content-Type`, `Content-Disposition`, `ETag`, `Vary`, custom `X-*`.
- For each varying header, identify the source field (user-controlled vs. server-derived).
- Look for request headers reflected into responses (Referer in error pages, User-Agent in correlation IDs, X-Forwarded-Host echoed back).

### CR/LF and Whitespace Variants

- Bare LF (`%0a`), bare CR (`%0d`), CRLF (`%0d%0a`).
- Double encoding (`%250d%250a`) for WAFs that decode once.
- Overlong UTF-8 of CR/LF (`%c0%8d`, `%c0%8a`) — invalid per spec but accepted by some parsers.
- Unicode line/paragraph separators (`%e2%80%a8` U+2028, `%e2%80%a9` U+2029) — sometimes folded to LF by intermediaries.
- Tab (`%09`) — RFC 7230 allows tabs in field values, useful for sneaking past simple `\s+` filters.
- Null byte (`%00`) — can truncate the header value in some parsers.

### Parser and Server Fingerprinting

- `Server`, `Via`, `X-Powered-By`, `X-AspNet-Version`, `X-Served-By`, `CF-Ray`, `X-Amzn-RequestId` reveal the stack.
- `Vary`, `Age`, `X-Cache`, `CF-Cache-Status` reveal caching layer and key composition.
- Same payload over HTTP/1.1 vs HTTP/2 vs chunked — diff status, headers, body length to map parsing differences.
- Compare `Host` and `X-Forwarded-Host` precedence: send both with different values and observe which wins in redirects, links, log entries.

## Key Vulnerabilities

### CRLF Response Splitting

Inject `\r\n\r\n` to terminate the current response and prepend a second attacker-controlled response. Cache or downstream proxy may key on the first response and serve the second to other users.

```
GET /redirect?to=foo%0d%0aSet-Cookie:%20admin=1%0d%0a%0d%0a<html>poisoned</html> HTTP/1.1
```

Request smuggling is a separate request-boundary vulnerability involving disagreement between two HTTP parsers, not simply response header injection at the request layer. Load `http_request_smuggling` when conflicting lengths, transfer coding, HTTP/2 downgrades, or connection desynchronization are in scope.

### Cache Poisoning (Pointer)

Cache-poisoning class is canonically owned by `web_cache_poisoning` + `web_cache_poisoning_advanced_deep` (mechanism, three-step confirmation protocol, per-CDN depth) and `web_cache_poisoning_novel_deep` (CVE catalog with version metadata — Next.js ISR CVE-2024-46982, ATS CVE-2021-27577). Header-injection-side residual primitives routed from this file:

- **Unkeyed input → keyed response**: `X-Forwarded-Host` / `X-Forwarded-Proto` echoed into response body or canonical URL where the header is unkeyed by the cache → the header-injection class is this file; the cache-poisoning consequence routes to `web_cache_poisoning_advanced_deep.md § Cache-Key Composition Reconnaissance` for the full three-step confirmation protocol.
- **CRLF-injected `Vary` or `Cache-Control`**: CRLF injection reaches response headers that control cache fragmentation / TTL → the CRLF-injection primitive is this file; the cache-poisoning consequence (over/under-fragmentation, long-TTL persistence) routes to `web_cache_poisoning_advanced_deep.md § Cache-Key Confusion Primitives`.
- **Web Cache Deception**: appending a cacheable extension to an authenticated URL → the primitive is route-matching behavior; the cache-poisoning class owns it at `web_cache_poisoning_advanced_deep.md § Cache-Key Reconnaissance (Pointer + Header-Injection-Side Residual)`.
- **Next.js cache-poisoning CVE-2024-46982**: `web_cache_poisoning_novel_deep.md § Next.js ISR Cache Poisoning` owns the version metadata and mechanism. The trigger involves a crafted request-header combination; the header-injection framing is minimal and routes to the cache owner.

### Host Header Confusion

Backends often trust `Host` (or `X-Forwarded-Host`) when constructing absolute URLs — password reset emails, OAuth `redirect_uri`, canonical link tags. Sending a forged Host produces a reset link pointing at attacker-controlled infrastructure that still carries the victim's reset token. This is the dominant CVE class in 2024-2026 (Pimcore, ArrowCMS, scheduleR, Coolify, Kanboard, sharewarez — see the novel sibling for CVE-level depth).

```
POST /password-reset HTTP/1.1
Host: attacker.tld
```

Also test: precedence between `Host` and `X-Forwarded-Host`, IPv6 bracketing (`Host: [::1]:80`), trailing dot (`Host: example.com.`), and port confusion (`Host: example.com:@attacker.tld`).

### Cookie / Set-Cookie Manipulation

- Inject `Domain=.example.com` or `Path=/` to widen scope of an attacker-set cookie.
- Inject `SameSite=None; Secure` to allow cross-site inclusion.
- Inject `Max-Age=999999999` for persistence, or `Max-Age=-1` to nuke the victim's session.
- Inject a cookie with the same name as a real session cookie — precedence rules let a same-domain attacker shadow it (cookie tossing).
- Reflected cookie XSS: if a cookie value is later rendered unescaped in HTML, the injection point is the header but the sink is the page.

### Proxy and Forwarding Header Spoofing

The `X-Forwarded-*` family is informational — there is no protocol guarantee about who set them. Any application that trusts them past the boundary it controls is exploitable.

- `X-Forwarded-For: 127.0.0.1` to bypass IP allowlists or rate limits keyed on client IP.
- `X-Forwarded-Proto: https` to satisfy "HTTPS-only" checks while still using HTTP.
- `X-Forwarded-Host: attacker.tld` for the Host-confusion variants above.
- `X-Real-IP`, `Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Forwarded` (RFC 7239) — same trust class under different conventions; select evidence-supported variants for the observed proxy/CDN stack.
- `X-Original-URL` / `X-Rewrite-URL` (IIS, ASP.NET) — server-side URL rewriting after auth check, classic admin-panel auth bypass.

### Content-Type / Encoding Confusion

- Inject `Content-Type: text/html` into an endpoint that returned JSON; browsers may sniff and render → XSS.
- Inject `Content-Disposition: inline` to switch a download into in-page rendering.
- *Absence* of `X-Content-Type-Options: nosniff` is what enables the sniffing attacks above; the header is a hardening control, not an attack surface — but if a server sets it inconsistently across endpoints, target the ones that don't.
- Compare MIME validators with browser parsing of duplicate or comma-joined `Content-Type` values. Record first/last valid member behavior and invalid-parameter recovery for each consumer.

### Internal Redirect and Handler Confusion

- Determine whether CGI/FastCGI/WSGI-style response headers can trigger an internal redirect instead of an external response.
- Trace which request fields survive the redirect: content type, handler, method, authorization result, path, and environment.
- Test whether response metadata is reused as an internal handler, proxy target, template type, or interpreter selection.
- Compare direct access controls with the internally dispatched resource. A protected URL may be unreachable directly while the same handler is invokable through a clean internal redirect.
- Treat CRLF injection and response-controlling SSRF as possible inputs to this chain, then validate handler selection before using a privileged handler.

### XSS via Response Headers

- `Location: javascript:alert(1)` if redirect target is reflected unescaped (browsers usually block, but some legacy clients and Electron-style hosts don't).
- `Location: data:text/html,<script>alert(1)</script>` — same caveat.
- `Refresh: 0; url=javascript:alert(1)` — the legacy `Refresh` header is a JavaScript-free meta-refresh equivalent.
- Reflected request header XSS: `Referer` echoed into a custom error page, `User-Agent` echoed into a debug header — combine CRLF injection with a body-injection sink.

### Open Redirect via Headers

- `Location` is the obvious one.
- `Refresh: 0; url=https://attacker.tld` — bypasses some `Location`-only filters.
- `Link: <https://attacker.tld>; rel="canonical"` — usually informational but consumed by SEO tooling and some clients.
- `X-Accel-Redirect: /internal/file` (Nginx) — if user input reaches this, internal-only files become accessible.

### HTTP/2 Pseudo-Header and Frame Confusion

- HTTP/2 splits headers into pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) and regular fields. Servers downgrading to HTTP/1.1 sometimes mishandle pseudo-header values, enabling smuggling across the H2 → H1 boundary.
- HTTP/2 lowercases header names; an upstream H1 filter that's case-sensitive may miss a lowercase variant that the H2 backend then accepts.
- HEADERS / CONTINUATION frame splitting: payload spans frames, intermediaries differ on whether they reassemble before applying filters.

## 2024-2026 CVE Routing

Instance-level CVEs for the current header-injection frontier. The version/GHSA metadata lives in `header_injection_novel_deep.md`; the base cites by number and route only.

- **CVE-2024-46982** — Next.js cache poisoning via crafted request header; non-dynamic SSR routes in `pages/` router cached with `s-maxage=1, stale-while-revalidate` and poisoned by upstream CDNs. Route: `header_injection_novel_deep.md § Next.js Cache Poisoning`.
- **CVE-2024-23648** — Pimcore Admin Classic Bundle password-reset Host-header injection. Route: `header_injection_novel_deep.md § Pimcore Admin Password Reset`.
- **CVE-2024-42914** — ArrowCMS forgot-password Host-header injection. Route: `header_injection_novel_deep.md § ArrowCMS Password Reset`.
- **CVE-2024-45982** — scheduleR Host-header password-reset. Route: `header_injection_novel_deep.md § scheduleR Password Reset`.
- **CVE-2025-52560** — Kanboard `application_url` default unset → password-reset Host-header injection. Route: `header_injection_novel_deep.md § Kanboard application_url Unset`.
- **CVE-2025-61136** — Sharewarez Flask `url_for(_external=True)` without `SERVER_NAME` configuration. Route: `header_injection_novel_deep.md § Sharewarez Flask SERVER_NAME`.
- **CVE-2025-64425** — Coolify forgot-password Host-header injection. Route: `header_injection_novel_deep.md § Coolify Password Reset`.

The advanced sibling (`header_injection_advanced_deep.md`) owns the per-header exploitation depth, CRLF payload taxonomy, cache-key reconnaissance methodology, X-Forwarded-* precedence testing, internal-redirect / handler-confusion deep catalog, HTTP/2 pseudo-header edges, and composite-chain construction.

## Bypass Techniques

**Encoding**

- URL-encode (`%0d%0a`) and double-encode (`%250d%250a`) for WAFs that decode the wrong number of times.
- Mix encodings within one payload: `%0d%0A`, `%0D\n`, alternating case.
- Newline-equivalent Unicode: U+2028 / U+2029 (sometimes folded to LF), overlong UTF-8 of CR/LF.

**Header normalization edges**

- Leading / trailing whitespace and tabs in header names and values.
- Header folding (obs-fold per RFC 7230 — formally obsolete, but some parsers still accept continuation lines starting with whitespace).
- Duplicate headers — RFC says join with `,`; in practice servers pick first, last, or differ from the proxy in front of them.

**Method and method-override**

- `X-HTTP-Method-Override: PUT` (and `X-Method-Override`, `X-HTTP-Method`) to reach state-changing handlers when the framework consults the override before applying method-based authorization.
- Effective from server-side or non-browser clients (curl, internal tooling, server-to-server proxies); from a browser the header is non-safelisted and triggers a CORS preflight, so it isn't a CSRF primitive on its own.

**Header name games**

- Case mangling for filters that key off exact casing.
- Null byte truncation in header name (`X-Forwarded-For\x00Evil`) on parsers that stop at NUL.

## Testing Methodology

1. **Inventory varying headers** — enumerate every response header whose value moves with input.
2. **Probe CR/LF normalization** — inject `%0d%0a` (and the encoding variants) into each varying header source; observe whether the second line lands as a real header.
3. **Test Host / X-Forwarded-Host** — submit a password-reset or any link-generating flow with attacker-controlled Host; confirm the link in the response or follow-up email.
4. **Probe forwarding headers** — spoof `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` against IP-restricted endpoints (admin, rate-limited).
5. **Test cache key / response content split** — find inputs that change the body but not the cache key; confirm a second request from a different session sees the poisoned response.
6. **Test method override** — `X-HTTP-Method-Override` paired with state-changing endpoints reachable via POST or GET.
7. **Route framing discrepancies** — if evidence indicates request-boundary disagreement, switch to `http_request_smuggling`.
8. **Cross-protocol** — replay payloads over HTTP/1.1 and HTTP/2; diff behavior.
9. **Trace internal reprocessing** — where response headers can cause subrequests/internal redirects, diff retained fields and final handler selection.
10. **Measure the framework's host-trust behavior** — run the local probe script against the detected framework to confirm whether `url_for`/`host_url`/`base_url` reflect attacker-supplied Host.

## Validation

1. Show two distinct users (or sessions) receiving content keyed on attacker-supplied header — proves cache poisoning.
2. Capture a password-reset / OAuth link pointing at attacker-controlled host — proves Host injection.
3. Demonstrate the same endpoint returning different auth decisions with and without a forged forwarding header.
4. For response splitting: show a downstream cache or proxy serving the injected second response to an unrelated request.
5. All findings should produce a durable artifact (cached response, sent email, log entry, session change) — transient anomalies are not validation.
6. For internal redirects, capture both the injected response metadata and the final internally selected route/handler.

## False Positives

- Headers that vary by input but are correctly keyed in the cache (intentional personalization, Vary set correctly).
- `X-Forwarded-*` reflected back but only used for logging — not a security boundary, may not be exploitable.
- Browsers blocking `Location: javascript:` or `Location: data:` — capability exists in the protocol but most modern browsers refuse to navigate.
- CRLF appearing in response headers but stripped by an outer proxy before reaching any client or cache.

## Impact

- Cross-user cache poisoning (defacement, XSS, account takeover via cached auth response).
- Account takeover via Host-confused password-reset / OAuth flows.
- Auth bypass on endpoints trusting forwarding headers.
- Session fixation and cookie tossing leading to account hijack.
- Open redirect for phishing / OAuth `redirect_uri` abuse.
- WAF / detection bypass via header-name and encoding tricks.

## Chaining

Header injection chains by capability transferred. Route each hop by filename:

- **Header injection → Open redirect**: `Location` or `Refresh` injection points to attacker; see `open_redirect.md`.
- **Header injection → Account takeover**: Host-header injection in password-reset flows delivers tokens to attacker; see `authentication_jwt.md § Password-Reset Token Flows`.
- **Header injection → Cache poisoning → Cross-user XSS**: unkeyed-header injection → cached-response-with-XSS → every user hits it; see `xss.md`.
- **Header injection → CSRF amplification**: method-override via header widens the CSRF surface; see `csrf.md § Method-Override Primitives`.
- **Header injection → Request smuggling**: CRLF reaches a parser-disagreement condition; see `http_request_smuggling.md`.
- **Header injection → SSRF**: `X-Forwarded-*` reaches an outbound-request constructor; see `ssrf.md § Header-Mediated Egress`.

## Pro Tips

1. The fastest win is usually Host / `X-Forwarded-Host` in a password-reset or OAuth flow — try first, costs one request.
2. For cache poisoning, find the *unkeyed* input first (header that influences body but not cache key); the rest follows.
3. `X-HTTP-Method-Override` is high-yield against backends that route on it before checking method-based auth — most useful from server-side / non-browser callers (it triggers CORS preflight in a browser, so not a CSRF primitive).
4. If a header test exposes message-boundary disagreement, switch to the dedicated request-smuggling workflow and identify the proxy → backend pair.
5. `X-Original-URL` / `X-Rewrite-URL` against IIS / ASP.NET admin endpoints is still a high-yield bypass.
6. Before claiming a CRLF win, verify the second line landed as a real header in the cache or downstream consumer — many servers strip CRLF silently.
7. Outbound email flows are a separate but related surface — user input flowing into SMTP headers (To, Cc, Subject, Reply-To) is its own injection class with the same root cause.
8. Flask apps without `SERVER_NAME` configured are default-vulnerable to Host-header password-reset injection; this is a one-config-flag check that is high-yield in bug bounty.

## Breadth Note

This base is a reference overview of the header-injection technique surface — class framing, the measured host-trust table, CR/LF encoding variants, parser fingerprinting, every primary primitive family (CRLF splitting, cache poisoning, Host confusion, cookie manipulation, forwarding-header spoofing, content-type confusion, internal-redirect handler-confusion, XSS-via-headers, open-redirect-via-headers, HTTP/2 pseudo-header confusion), and the full 2024-2026 CVE routing map. It is deliberately scoped to be a complete overview of every technique class rather than a full-treatment of each; the advanced sibling owns the full-treatment sub-primitives per technique, and the novel sibling owns current CVE mechanism depth.

## Summary

Header injection is fundamentally a normalization failure: somewhere on the request → response path, user input reached a header value without CR/LF stripping or proper escaping. The impact tiers up from open redirect to cache poisoning to request smuggling depending on which downstream component trusts the resulting header. The dominant 2024-2026 CVE class is Host-header injection in password-reset flows, hitting every stack where the framework pulls `request.host` into URL construction without a configured canonical host — the measurement confirms Flask and FastAPI/Starlette are both default-vulnerable. Audit every header whose value moves with input, and treat every `X-Forwarded-*` / Host trust as a security boundary that needs explicit justification.
