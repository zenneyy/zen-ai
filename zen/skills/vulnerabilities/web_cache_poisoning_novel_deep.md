---
name: web-cache-poisoning-novel-deep
description: 2024–2026 web cache poisoning frontier — verified CVE catalog (Next.js ISR CVE-2024-46982, ATS fragment-unkeying CVE-2021-27577 as canonical mechanism exemplar), measured Rack-3-narrowed Rails semicolon primitive, per-CDN × per-header historical baseline (CERT/CC VU#335217, youst.in cache-poisoning-at-scale) framed as unverified-current, and the bounded-live-frontier reasoning.
sibling: web_cache_poisoning
load_when: scan_mode == "deep"
---

# Web Cache Poisoning — Novel Deep

Load `web_cache_poisoning` for the base-tier framing (unkeyed-input mechanism, three-step confirmation protocol, key-vulnerability class list). Load `web_cache_poisoning_advanced_deep` for cache-key composition reconnaissance, per-CDN behavioral depth, cache-key confusion primitives, chained exploitation, and framework-specific cache-poisoning. This file owns the 2024–2026 verified CVE catalog with version/fix metadata (CVE single-ownership), the measurement-anchored primitive updates, the per-CDN × per-header baseline matrix with unverified-current framing, and the bounded-live-frontier reasoning for the comparatively mature cache-poisoning class.

The cache-poisoning novel-tier frontier is anchored on CVE-2024-46982 (Next.js ISR) as the 2024 CVE instance, CVE-2021-27577 (Apache Traffic Server fragment unkeying) as the canonical mechanism exemplar (historical for current ATS line but structurally illustrative), and the per-CDN × per-header matrix across Cloudflare/Fastly/Akamai/CloudFront/Varnish/Nginx — the matrix is based on CERT/CC VU#335217 (Jan 2020) and youst.in's cache-poisoning-at-scale research with per-CDN entries flagged as unverified-current rather than asserted-2026. The 2024–2026 live frontier beyond these anchors is thin precisely because the class is primarily configuration-driven; a given deployment either has the misconfiguration or does not, and new technique classes beyond the Kettle 2020 primitives are rare.

## Next.js Cache Poisoning — CVE-2024-46982

- **GHSA**: `GHSA-gp8f-8m3g-qvj9`
- **Severity**: High (CVSS 7.5)
- **Affected** (two ranges per GHSA): `next` on npm, versions `>= 13.5.1, < 13.5.7` AND `>= 14.0.0, < 14.2.10`
- **Fix**: `13.5.7` / `14.2.10`
- **Published**: 2024-09-17

**Mechanism** (per GHSA advisory verbatim): "By sending a crafted HTTP request, it is possible to poison the cache of a non-dynamic server-side rendered route in the pages router (this does not affect the app router). When this crafted request is sent it could coerce Next.js to cache a route that is meant to not be cached and send a `Cache-Control: s-maxage=1, stale-while-revalidate` header which some upstream CDNs may cache as well."

**Reachability preconditions** (per advisory):
- Next.js version in affected range (`>= 13.5.1, < 13.5.7` OR `>= 14.0.0, < 14.2.10`)
- Using the **pages router** (`pages/` directory structure); the app router is unaffected
- Using **non-dynamic server-side rendered routes** (e.g., `pages/dashboard.tsx`, NOT `pages/blog/[slug].tsx`)
- An upstream CDN (Cloudflare, CloudFront, Fastly) in front that respects `s-maxage` / `stale-while-revalidate`
- **Deployments on Vercel are explicitly unaffected** per the advisory

**Attack vector**: attacker sends a crafted request with specific headers that cause the Next.js pages-router SSR response to carry `Cache-Control: s-maxage=1, stale-while-revalidate`; the upstream CDN caches the authenticated response for the stale-while-revalidate window; subsequent anonymous requests receive the cached authenticated content.

**Confirmation**: deployed Next.js version in the affected range AND pages router AND non-dynamic SSR route AND upstream CDN AND non-Vercel deployment; three-step protocol — anonymous request to the same path after a victim's authenticated request returns the victim's rendered content with `X-Cache: HIT` or equivalent.

**Primitive class template**: *Framework-emitted short-TTL `Cache-Control` on routes that should be user-specific* — generalize to any framework whose response-caching layer emits CDN-cacheable short-TTL headers for user-specific SSR responses. The structural pattern is "framework assumes CDN won't cache; CDN caches anyway because the header permits it." Audit targets include Nuxt SSR, Remix loader cache, SvelteKit load functions, Rails `fresh_when`/`stale?` fast-path.

## Apache Traffic Server Fragment-Unkeying — CVE-2021-27577

- **GHSA**: `GHSA-3wxc-ff9x-7v29` (where applicable; verify via GitHub Advisories CVE lookup)
- **Severity**: High (CVSS 7.5)
- **Affected**: Apache Traffic Server versions `7.0.0 - 7.1.12`, `8.0.0 - 8.1.1`, `9.0.0 - 9.0.1`
- **Fix**: 7.1.13 / 8.1.2 / 9.0.2
- **Published**: 2021-06-29

**Mechanism**: Apache Traffic Server (ATS) excludes the URL fragment when generating the cache key but still forwards the full URL (including fragment) to the backend. The fragment is attacker-controlled unkeyed input.

**NVD description verbatim** (per the Batch 13 primary-source verification): "Incorrect handling of URL fragment vulnerability of Apache Traffic Server allows an attacker to poison the cache."

**Attack vector**: attacker crafts a request with a URL fragment containing attacker-controlled content; ATS caches the response under the fragment-less URL; the backend's processing may be affected by the fragment (if the backend parses it) producing a response that is then cached under the normal URL and served to subsequent legitimate requests.

**Historical status**: the affected versions are historical for the current ATS line (10.x+); this CVE is cited as **canonical mechanism exemplar** rather than as a currently-exploitable instance against modern ATS deployments. The primitive class — "intermediary that keys on a different URL representation than the backend uses for request handling" — is the generalizable finding.

**Primitive class template**: *URL-component unkeyed-input* — generalize to any intermediary that excludes a URL component from the cache key while the backend uses it. Fragment is one specific component; URL-encoded delimiter normalization (Nginx) is another; the primitive class is the same.

## Measured — Rails Semicolon-Separator Primitive Narrowed

The Kettle 2020 "Web Cache Entanglement" paper documented a Ruby on Rails cache parameter cloaking primitive via Rack 2.x treating `;` as parameter separator equivalent to `&`.

**Batch 13 measurement** (`.zen-batch-artifacts/batch-13/cache-poison/m1_ruby_semicolon.txt`, Rack 3.2.7, Ruby 3.3.8):
- `Rack::Utils.parse_nested_query("a=1&b=2")` → `{"a"=>"1", "b"=>"2"}` (standard & handling)
- `Rack::Utils.parse_nested_query("a=1;b=2")` → `{"a"=>"1;b=2"}` — **`;` NOT a separator**
- `Rack::Utils.parse_nested_query("a=1&b=2;c=3")` → `{"a"=>"1", "b"=>"2;c=3"}` — **`;` NOT a separator**
- `CGI.parse("a=1;b=2")` → `{"a"=>["1"], "b"=>["2"]}` — stdlib CGI module **still treats `;` as separator**

**Measured primitive-class update**: the Kettle 2020 Rails `;`-as-`&` cache parameter cloaking primitive is **not reproducible against current Rack 3.x** at the `parse_nested_query` layer. The primitive remains live for:
- Applications using older Rack 2.x (common in long-running Rails deployments pinned to older versions)
- Applications using Ruby's `CGI.parse` for query parsing (stdlib behavior retained)
- Applications with manual separator-aware parsing

**Live-frontier implication**: before claiming the Rails `;`-as-`&` cache parameter cloaking primitive against a target, verify the deployed Rack version. If Rack 3.x and `parse_nested_query` is the parser, the primitive is likely absent at this layer; test instead for `CGI.parse` usage or application-level manual separator handling.

**Primary-source alignment**: the Rack upstream deprecated `;`-as-separator behavior in Rack 3.0 (per Rack CHANGELOG) in alignment with the broader HTTP spec community move away from treating `;` as separator (RFC 3986's URI generic syntax does not mandate `;` as a query delimiter). The measured update is consistent with the primary-source Rack release.

## Cache-Poisoned DoS (CP-DoS) and HTTP Meta Character (HMC) Class

Primary source: "Your Cache Has Fallen" (Nguyen et al.); youst.in cache-poisoning-at-scale research blog.

**Mechanism**: a request containing an RFC 7230-illegal character (notably backslash, which is only permitted inside a quoted-string per the field-content grammar) causes a cacheable 400 Bad Request on edges that forward invalid headers to the origin without rejecting them. The 400 is cached under the normal URL's key; subsequent clients receive the 400 — denial of service via cache poisoning.

**Edge-specific status** (per primary source, Batch 13 verification):
- **Akamai**: documented cache of 400 responses from backslash-containing headers (per youst.in primary source, named in the specific sentence; the generalization to "multiple CDN edges" was voted 2-1 in Batch 13 cross-check — scope the finding to the specific edge where demonstrated)
- **AWS CloudFront**: historically confirmed, remediated per primary source
- **Other edges**: unverified-current; fresh test required per deployment

**Attack recipe**:
```bash
# Send a header with RFC 7230-illegal backslash character
curl -sI "https://target-via-akamai.tld/" -H "X-Custom-Header: value\with\backslash"
# If Akamai forwards and origin returns 400, Akamai caches
# Subsequent clients: curl "https://target-via-akamai.tld/" → 400
```

**Confirmation**: three-step protocol — poison request produces 400; clean request receives 400 from cache; `X-Cache: HIT` or equivalent signal confirms cache serve.

**Impact**: denial of service on the cached-path for the duration of the cache TTL. Multiply by cached-paths and cache geographic coverage.

**Primitive class template**: *Edge forwards invalid-but-cacheable origin responses* — generalize to any edge where the origin's status-code-only response caches without origin's `Cache-Control: no-store` protection.

## Unkeyed-Header Cluster — youst.in Research

Primary source: youst.in's "Cache Poisoning at Scale" (Iustin Ladunca). Documents multiple unkeyed-header primitives discovered across 70+ findings and $26K+ bounties.

**Confirmed headers** (per Batch 13 2-1-voted scoping — the matrix is per-CDN × per-header, do not generalize across edges):
- **`X-HTTP-Method-Override: HEAD`** on Google Cloud Buckets + GitLab assets: yields a cacheable empty body; **GitLab $4,850 bounty**
- **`X-Forwarded-Scheme: http`** on Shopify: breaks absolute URL generation in response; **Shopify $6,300 bounty**
- **`X-Forwarded-Host`**: documented against multiple targets; variations per CDN
- **`Fastly-Host`**: Fastly-specific (per the Batch 13 2-1 scope vote); do not represent as a universal header primitive — present as per-CDN per-header mapping

**Bounty-tier findings** (as published, 2022):
- GitHub $7,500
- GitLab $4,850 (`X-HTTP-Method-Override: HEAD` on GCP+Fastly)
- Shopify $6,300 (`X-Forwarded-Scheme: http`)
- Exodus/Azure $2,500

**Primitive class template**: *Framework-level unkeyed-header forwarding* — the forwarding is at the application framework level (Rails, Django, Node.js, Rails Direct); the cache is CDN-level; the mismatch is the primitive.

## Per-CDN × Per-Header Matrix (Baseline + Unverified-Current)

**IMPORTANT**: the matrix below is the **CERT/CC VU#335217 (Jan 2020) + youst.in (2022–2023) baseline**. Per-CDN current status requires fresh verification per deployment. **Do not assert 2026 CDN-affected status from this baseline**; use it as a probe-ordering reference and verify the specific edge at engagement time.

**CERT/CC VU#335217 (Jan 2020) enumerated 13 inconsistently-handled headers**:
Content-Security-Policy-Report-Only, Forwarded, Server-Timing, Set-Cookie, Strict-Transport-Security, X-Forwarded-Proto, Location, Accept-Language, Cookie, X-Forwarded-For, X-Forwarded-Host, Referer, Max-Forwards.

CDNs named in the Jan-2020 advisory: Akamai Technologies, Amazon CloudFront, Cloudflare (not exhaustive; the three major commercial CDNs listed). Vendor statements:
- Akamai: "traditional reflected XSS, elevated to stored XSS due to CDN caching"
- Amazon: shared-responsibility framing
- Cloudflare: cache poisoning attributed primarily to origin, not CDN

**Per-CDN primitive catalog** (baseline, each entry unverified-current):

| CDN | Documented primitive | Primary source | Current status |
|-----|---------------------|----------------|----------------|
| Cloudflare | Lowercased Host forwarded as-sent | youst.in | unverified-current |
| Cloudflare | Fat GET body forwarded without body-keying | Cloudflare docs ("Do not trust GET request bodies") | documented in current docs |
| Fastly | Host-header injection via `Fastly-Host` (Fastly-specific) | youst.in | documented, Fastly-specific |
| Fastly | Fat GET body forwarded without VCL handling | Kettle 2020 | documented baseline |
| Akamai | Forwards invalid headers; caches 400 (HMC) | youst.in | documented at primary source |
| Akamai | Pragma debug headers (`akamai-x-cache-on`, `akamai-x-get-cache-key`) | PortSwigger | documented |
| AWS CloudFront | HMC CP-DoS historically confirmed | multiple sources | documented+remediated |
| Varnish | Fat GET body without builtin.vcl | Kettle 2020 | documented baseline |
| Varnish | Capitalized-host edge case Dec 2020 | youst.in | documented baseline |
| ATS | Fragment-unkeying CVE-2021-27577 | Apache + NVD | historical for current ATS line |

**Fresh-verification protocol** per deployment:
1. Fingerprint the CDN layer (`CF-Ray`, `X-Served-By`, `X-Cache`, `X-Akamai-Transformed`, `X-Amz-Cf-Id`, `Via: varnish`)
2. For each applicable row, run the three-step confirmation protocol against the deployment's edge
3. Record the current behavior; the baseline is a probe-ordering, not a finding

## Bounded Live-Frontier Class Reasoning

The cache-poisoning novel-tier frontier is comparatively narrow: the Kettle 2020 paper exhaustively enumerated the primitive classes (unkeyed-header reflection, cache parameter cloaking, fat-GET body, URL-decode normalization, fragment unkeying, cacheable 400s), and the 2021–2026 cycle has largely been (a) specific-vendor CVE instances within those classes and (b) per-CDN behavioral variation. New structural primitives are rare because the primitive space is a product of (keyable component) × (unkeyable component) × (forwarded-to-origin component) — the space is enumerable, and the enumeration is largely complete.

**Why the frontier is bounded**:
1. **The Kettle 2020 taxonomy is comprehensive at the primitive level** — the six classes documented in the base file cover the surface
2. **New findings are configuration-driven**: a given deployment either has the misconfiguration or does not; new technique classes beyond the taxonomy are rare
3. **CDN behavior has evolved toward stricter defaults**: Cloudflare's "do not trust GET bodies" docs, AWS CloudFront's HMC remediation, Varnish's builtin.vcl improvements — the CDN-side mitigations have narrowed specific exploitable configurations
4. **HTTP/2 and HTTP/3 have not opened substantial new cache-poisoning surface** — HTTP/2 header compression (HPACK) and HTTP/3's QUIC layer do not change the fundamental cache-key composition at the application layer
5. **The novel-tier is primarily CVE-instance** (Next.js ISR, ATS fragment unkeying) rather than new primitive classes

**What's not bounded**:
- Per-deployment configuration gaps continue to produce findings; the pentester's enumeration of a specific target remains valuable
- Framework-specific cache implementations (Next.js, Nuxt, Astro, Django cache middleware, Spring @Cacheable) each have their own cache-key quirks that are not captured in the general CDN taxonomy
- The HTTP smuggling + cache poisoning chain (frontend/backend desync poisoning the cache) remains a live research surface; route to `http_request_smuggling_novel_deep.md` for the smuggling-side CVE catalog

## Chaining Depth at the Novel Frontier

**Chain N1 — Next.js ISR CVE-2024-46982 → Cross-user cached content → Information disclosure**:
- Deployed Next.js version in CVE-2024-46982 affected range
- Attacker triggers the specific crafted request shape per the advisory
- ISR cache stores non-static content as if static
- Subsequent legitimate visitors receive the attacker-cached content

**Chain N2 — ATS CVE-2021-27577 → Fragment-smuggled backend parameter → Cache-stored admin response**:
- Deployed ATS in the affected version range (historical for current ATS line)
- Attacker request: `GET /#admin-flag`
- ATS caches response under `/` key; forwards `/#admin-flag` to backend
- Backend processes `admin-flag`; returns admin response
- Cached under `/`; subsequent requests get admin response

**Chain N3 — Rails Rack-2.x cache parameter cloaking → User-ID smuggling → Cross-user data**:
- Deployed Rails on Rack 2.x (verify version; Rack 3.x narrows per Batch 13 measurement)
- Target endpoint: `?user_id=victim`
- Attacker: `?user_id=victim&role=guest;role=admin`
- Cache keys on `?user_id=victim&role=guest;role=admin` (one query string)
- Rack 2.x parses as `{user_id: victim, role: admin}` (last-write)
- Response: admin view of victim data
- Cached; subsequent `?user_id=victim&role=guest` requests get the admin-elevated response

**Chain N4 — CP-DoS / HMC on Akamai → Cacheable 400 → Service DoS**:
- Deployed Akamai edge (CloudFront remediated; verify per edge)
- Attacker: `curl -H "X-Custom-Header: value\with\backslash" https://target.tld/path`
- Akamai forwards; origin returns 400; Akamai caches 400
- Subsequent legitimate `/path` requests receive 400 until cache eviction

**Chain N5 — youst.in X-HTTP-Method-Override:HEAD on GCP+Fastly → Cached empty body → DoS**:
- Deployed on Google Cloud Buckets or GitLab assets fronted by Fastly
- Attacker: `curl -H "X-HTTP-Method-Override: HEAD" https://target.tld/asset.js`
- Backend treats as HEAD; returns empty body
- Fastly caches empty body under `/asset.js` key
- Subsequent legitimate GET requests receive empty body → site breakage
- GitLab $4,850 bounty for this chain

**Chain N6 — HTTP smuggling + cache poisoning composite**:
- Frontend/backend desync vulnerability (`http_request_smuggling`)
- Attacker smuggles a request whose response delivers to the next socket
- Victim's subsequent request receives the attacker-smuggled response
- Response cached under victim's URL
- Primitive: an entire cache entry controlled by the smuggling attacker
- Route to `http_request_smuggling_novel_deep.md` for the smuggling-side CVE catalog and version metadata

## Verification Discipline

- Every CVE claim in this file links to a globally-resolving GHSA REST advisory (persisted in `.zen-batch-artifacts/batch-13/`); the manifest demonstrates 1:1 resolution
- CVE version metadata is single-owned here; base/advanced sibling files reference by CVE number + filename+section pointer only
- The Kettle 2020 Rails `;`-as-`&` primitive is measured non-reproducible on current Rack 3.x per Batch 13; cite the measurement, not the historical primitive
- CDN behavioral baselines (CERT/CC VU#335217 Jan 2020, youst.in) are historical; flag as unverified-current and verify per deployment
- The "multiple CDN edges" generalization of CP-DoS/HMC was voted 2-1 in Batch 13 cross-check — name the specific edge (Akamai primary-source; CloudFront remediated; other edges unverified-current)
- Fastly-Host is Fastly-specific per the 2-1 Batch 13 scope vote; do not represent as universal
- CVE single-ownership: Next.js CVE-2024-46982 version metadata is here (not in base or advanced); same for ATS CVE-2021-27577
- Measured artifacts (Rack, Python, Nginx probes) are preserved at `.zen-batch-artifacts/batch-13/cache-poison/`

## Summary

The 2024–2026 web cache poisoning frontier is anchored on CVE-2024-46982 (Next.js ISR) as the current CVE instance, CVE-2021-27577 (ATS fragment unkeying) as the canonical mechanism exemplar, measured updates to the Kettle 2020 primitives (Rails `;`-as-`&` narrowed on Rack 3.x), and the Jan-2020 CERT/CC + youst.in CDN behavioral baseline framed as unverified-current per deployment. No new structural primitive classes have emerged since Kettle 2020; the live frontier is CVE instances within the known classes and per-deployment configuration gaps. The bounded reasoning: the primitive space is a product of (keyable) × (unkeyable) × (forwarded-to-origin) components, and the enumeration is largely complete; new findings are configuration-driven rather than architectural. Load `web_cache_poisoning` for base framing and the three-step confirmation protocol; load `web_cache_poisoning_advanced_deep` for cache-key reconnaissance methodology and per-CDN behavioral depth; this file is the version-metadata anchor the siblings reference by CVE number.
