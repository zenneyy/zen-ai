---
name: nextjs
description: Security testing playbook for Next.js covering App Router, Server Actions, RSC, and Edge runtime vulnerabilities
---

# Next.js

Security testing for Next.js applications. Focus on authorization drift across runtimes (Edge/Node), caching boundaries, server actions, and middleware bypass.

## Attack Surface

**Routers**
- App Router (`app/`) and Pages Router (`pages/`) often coexist
- Route Handlers (`app/api/**`) and API routes (`pages/api/**`)
- Middleware: `middleware.ts` at project root

**Runtimes**
- Node.js (full API access)
- Edge (V8 isolates, restricted APIs)

**Rendering & Caching**
- SSR, SSG, ISR, on-demand revalidation
- RSC (React Server Components) with fetch cache
- Draft/preview mode

**Data Paths**
- Server Components, Client Components
- Server Actions (streamed POST with `Next-Action` header)
- `getServerSideProps`, `getStaticProps`

**Integrations**
- NextAuth.js (callbacks, CSRF, callbackUrl)
- `next/image` optimization and remote loaders

## High-Value Targets

- Middleware-protected routes (auth, geo, A/B)
- Admin/staff paths, draft/preview content, on-demand revalidate endpoints
- RSC payloads and flight data, streamed responses
- Image optimizer and custom loaders, remotePatterns/domains
- NextAuth callbacks (`/api/auth/callback/*`), sign-in providers
- Edge-only features (bot protection, IP gates) and their Node equivalents

## Reconnaissance

**Route Discovery**

```javascript
// Browser console - list all routes
console.log(__BUILD_MANIFEST.sortedPages.join('\n'))

// Inspect server-fetched data
JSON.parse(document.getElementById('__NEXT_DATA__').textContent).props.pageProps

// List public environment variables
Object.keys(process.env).filter(k => k.startsWith('NEXT_PUBLIC_'))
```

**Build Artifacts**
```
GET /_next/static/<buildId>/_buildManifest.js
GET /_next/static/<buildId>/_ssgManifest.js
GET /_next/static/chunks/pages/
GET /_next/static/chunks/app/
```
Chunk filenames map to routes (e.g., `admin.js` → `/admin`).

**Source Maps**

Check `/_next/static/` for exposed `.map` files revealing route structure, server action IDs, and internal functions.

**Client Bundle Mining**

Search main-*.js for: `pathname:`, `href:`, `__next_route__`, `serverActions`, API endpoints. Grep for `API_KEY`, `SECRET`, `TOKEN`, `PASSWORD` to find accidentally leaked credentials.

**Server Action Discovery**

Inspect Network tab for POST requests with `Next-Action` header. Extract action IDs from response streams and hydration data.

**Additional Leakage**
- `/sitemap.xml`, `/robots.txt`, `/sitemap-*.xml` for unintended admin/internal/preview paths
- Client bundles/env for secret paths and preview/admin flags (many teams hide routes via UI only)

## Key Vulnerabilities

### Middleware Bypass

**Known Techniques**
- `x-middleware-subrequest` header crafting — **CVE-2025-29927**, full middleware bypass (below)
- `x-nextjs-data` probing
- Look for 307 + `x-middleware-rewrite`/`x-nextjs-redirect` headers

**CVE-2025-29927 — `x-middleware-subrequest` middleware bypass.** Next.js uses
the internal `x-middleware-subrequest` header to stop its own middleware
subrequests from recursing; the framework trusts it from *external* callers
and skips `middleware.ts` entirely when present. Since auth/authz is commonly
enforced only in middleware, this is a complete authorization bypass. The
value must match the middleware's module name, and the exact form is
version-dependent:

```http
# 12.2+ (single match): the middleware module name
GET /admin HTTP/1.1
Host: target
x-middleware-subrequest: middleware

# also try src/middleware when the file lives under src/
x-middleware-subrequest: src/middleware

# 13.2.0+ added a max recursion depth, so the value must be repeated 5x
# (colon-separated) to exceed it:
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware

# pre-12.2 (Pages Router): the _middleware path
x-middleware-subrequest: pages/_middleware
```

Detect by sending a protected route twice — once plain (expect 401/403 or a
redirect from middleware), once with the header — and diffing: a `200` with
the header is the bypass. Fixed in **12.3.5**, **13.5.9**, **14.2.25**, and
**15.2.3** (affected: `<12.3.5`, `13.0.0–13.5.8`, `14.0.0–14.2.24`,
`15.0.0–15.2.2`). Fingerprint the version from `/_next/static/<buildId>/` and
`x-powered-by`/build output, and pick the matching value form. Vercel-hosted
apps strip the header at the edge; self-hosted and other-CDN deployments are
the exposed population.

**Path Normalization**
```
/api/users
/api/users/
/api//users
/api/./users
```
Middleware may normalize differently than route handlers. Test double slashes, trailing slashes, dot segments.

**Parameter Pollution**
```
?id=1&id=2
?filter[]=a&filter[]=b
```
Middleware checks first value, handler uses last or array.

### Server Actions

- Invoke actions outside UI flow with alternate content-types
- Authorization assumed from client state rather than enforced server-side
- IDOR via object references in action payloads
- Map action IDs from source maps to discover hidden actions

**Invoking an action directly.** A Server Action is a POST to the page URL
carrying `Next-Action: <actionId>` (the id is a hash discoverable in the
client bundle / source maps). Replay it outside the UI with your own
arguments and a lower-privilege (or no) session to test server-side authz:
```http
POST /dashboard HTTP/1.1
Host: target
Next-Action: 7f9a...c21
Content-Type: multipart/form-data; boundary=----x
------x
Content-Disposition: form-data; name="1_$ACTION_ID"

["<attacker-controlled-arg>"]
------x--
```

**Origin/Host enforcement (and CVE-2024-34351).** Next.js defends Server
Actions against CSRF by requiring `Origin` to match `Host` (a 403 on
mismatch) — test whether that check is present and whether a spoofed/absent
`Origin` or a trusted-`Host` forwarding header bypasses it. **CVE-2024-34351**
(self-hosted, `≥13.4.0 <14.1.1`, fixed **14.1.1**) is an SSRF in that path: a
Server Action performing a redirect to a relative path (`/...`) built the
absolute URL from the attacker-controlled `Host` header, so a forged `Host`
makes the server issue the request to attacker infrastructure. Vercel-routed
deployments are unaffected (they route on Host). Beyond the CVE, any Server
Action that `fetch()`es a URL derived from its arguments is a first-class SSRF
sink — load `ssrf`.

### RSC & Caching

**Cache Boundary Failures**
- User-bound data cached without identity keys (ETag/Set-Cookie unaware)
- Personalized content served from shared cache/CDN
- Missing `no-store` on sensitive fetches

**Flight Data Leakage**

Inspect streamed RSC payloads for serialized sensitive fields in props.

**ISR Issues**
- Stale-while-revalidate responses containing user-specific or tenant-dependent data
- Weak secrets in on-demand revalidation endpoint URLs
- Referer-disclosed tokens or unvalidated hosts triggering `revalidatePath`/`revalidateTag`
- Header-smuggling or method variations to trigger revalidation

**Cache Poisoning (CVE-2024-46982).** On the **Pages Router**, a crafted
request can poison the cache of a *non-dynamic SSR* route (e.g. a page using
`getServerSideProps` at a static path like `/dashboard`), forcing Next.js to
respond with `Cache-Control: s-maxage=1, stale-while-revalidate` — which the
route was never meant to emit and which upstream CDNs then cache, causing
denial of service (and serving stale/cross-user content depending on what the
route renders). Affected `≥13.5.1 <13.5.7` and `≥14.0.0 <14.2.10`; fixed
**13.5.7** / **14.2.10**. App Router and Vercel-hosted sites are unaffected.
Probe by sending the crafted request, then a normal request, and checking
whether the response now carries the injected `Cache-Control` and is served
from cache. (This is a poisoning→DoS bug; the Server Actions Host SSRF above is
the separate SSRF.)

**On-demand revalidation secret.** `/api/revalidate?secret=...` (Pages) and
`revalidatePath`/`revalidateTag` route handlers gate cache invalidation behind
a shared secret. Harvest it from the client bundle, `NEXT_PUBLIC_*` env, or a
Referer leak, then force arbitrary revalidation (cache-bust DoS, or refresh a
poisoned entry). A missing/guessable secret is the finding.

**RSC taint APIs are not sanitizers.** `experimental_taintObjectReference` /
`taintUniqueValue` block a *specific* value/object from crossing the
server→client boundary (a defense against accidental secret serialization).
They do not encode output and are not XSS protection — do not treat their
presence as evidence a `dangerouslySetInnerHTML` sink is safe.

### Authentication

**NextAuth Pitfalls**
- Missing/relaxed state/nonce/PKCE per provider (login CSRF, token mix-up)
- Open redirect in `callbackUrl` or mis-scoped allowed hosts
- JWT audience/issuer not enforced across routes
- Cross-service token reuse
- Session hijacking by forcing callbacks

**Session Boundaries**
- Different auth enforcement between App Router and Pages Router
- API routes vs Route Handlers authorization inconsistency

### Data Exposure

**__NEXT_DATA__ Over-fetching**

Server-fetched data passed to client but not rendered:
- Full user objects when only username needed
- Internal IDs, tokens, admin-only fields
- ORM select-all patterns exposing entire records
- API responses forwarded without sanitization (metadata, cursors, debug info)

**Environment-Dependent Exposure**
- Staging/dev accidentally exposes more fields than production
- Inconsistent serialization logic across environments

**Props Inspection**
```javascript
// Check for sensitive data in page props
JSON.parse(document.getElementById('__NEXT_DATA__').textContent).props
```
Look for `_metadata`, `_internal`, `__typename` (GraphQL), nested sensitive objects.

### Image Optimizer SSRF

**Remote Patterns**
- Broad `images.domains`/`remotePatterns` in `next.config.js`
- Test: internal hosts, IPv4/IPv6 variants, DNS rebinding

**Custom Loaders**
- Protocol smuggling via redirect chains
- Cache poisoning via URL normalization differences affecting other users

### Runtime Divergence

**Edge vs Node**
- Defenses relying on Node-only modules skipped on Edge
- Header trust differs (`x-forwarded-*` handling)
- Same route may behave differently across runtimes

### Client-Side

**XSS Vectors**
- `dangerouslySetInnerHTML`
- Markdown renderers
- User-controlled href/src attributes
- Validate CSP/Trusted Types coverage for SSR/CSR/hydration

**Hydration Mismatches**

Server vs client render differences can enable gadget-based XSS.

### Draft/Preview Mode

- Secret URLs/cookies enabling preview
- Preview secrets leaked in client bundles/env
- Setting preview cookies from subdomains or via open redirects

## Bypass Techniques

- Content-type switching: `application/json` ↔ `multipart/form-data` ↔ `application/x-www-form-urlencoded`
- Method override: `_method`, `X-HTTP-Method-Override`, GET on endpoints accepting writes
- Case/param aliasing and query duplication affecting middleware vs handler parsing
- Cache key confusion at CDN/proxy (lack of Vary on auth cookies/headers)

## Testing Methodology

1. **Enumerate** - Use `__BUILD_MANIFEST`, source maps, build artifacts, sitemap/robots to map all routes
2. **Runtime matrix** - Test each route under Edge and Node runtimes
3. **Role matrix** - Test as unauth/user/admin across SSR, API routes, Route Handlers, Server Actions
4. **Cache probing** - Verify caching respects identity (strip cookies, alter Vary headers, check ETags)
5. **Middleware validation** - Test path variants and header manipulation for bypass
6. **Cross-router** - Compare authorization between App Router and Pages Router paths

## Validation Requirements

- Side-by-side requests showing cross-user/tenant access
- Cache boundary failure proof (response diffs, ETag collisions)
- Server action invocation outside UI with insufficient auth
- Middleware bypass with explicit headers showing protected content access
- Runtime parity checks (Edge vs Node inconsistent enforcement)
- Discovered routes verified as deployed (200/403) not just build artifacts (404)
- Leaked credentials tested with minimal read-only calls; filter placeholders
- `__NEXT_DATA__` exposure: verify cross-user (User A's props shouldn't contain User B's PII), confirm exposed fields not in DOM
- Path normalization bypasses: show differential responses (403 vs 200), redirects don't count
