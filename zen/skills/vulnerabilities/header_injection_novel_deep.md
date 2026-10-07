---
name: header-injection-novel-deep
description: Header injection at the 2024-2026 frontier — Next.js cache poisoning (CVE-2024-46982), the Pimcore/ArrowCMS/scheduleR/Coolify/Kanboard/sharewarez Host-header password-reset lineage (CVE-2024-23648, CVE-2024-42914, CVE-2024-45982, CVE-2025-64425, CVE-2025-52560, CVE-2025-61136), measured framework host-trust behavior across Flask / FastAPI / Starlette, and the current CDN-cache deception frontier.
sibling: header_injection
load_when: scan_mode == "deep"
---

# HTTP Header Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `header_injection.md`. The base owns class framing, the measured framework-host-trust table, CR/LF encoding variants, parser fingerprinting, key vulnerabilities, 2024-2026 CVE routing map, bypass primitives, methodology, and chaining basics. The advanced+expert sibling `header_injection_advanced_deep.md` owns the CRLF payload taxonomy per encoding layer, cache-key reconnaissance methodology, X-Forwarded-* precedence testing, Host-header exploitation deep catalog, Set-Cookie manipulation depth with cookie-tossing, internal-redirect / handler-confusion deep catalog, HTTP/2 pseudo-header edges, and composite-chain construction.

This file owns the 2024-2026 CVE instances with canonical version/GHSA metadata (single-owner across the trio), the Next.js cache-poisoning CVE, the seven-CVE Host-header password-reset lineage spanning multiple stacks, and the current CDN-cache / framework-host-trust frontier framing.

Load this file when the goal is matching a target against a current CVE family, reasoning about Host-header-shape defects in a modern web stack, or verifying whether a specific framework's URL-construction primitives trust the Host header.

Every CVE number, version boundary, and GHSA identifier in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-11/ghsa-nvd/`, and the measured host-trust primitive is reproduced by `.zen-batch-artifacts/batch-11/measurements/host_header_trust.py` + `.out`.

## 2024-2026 Header-Injection CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version and GHSA metadata lives here.

| CVE | GHSA | Component | Vulnerable | Patched | CVSS | CWE | Primitive |
|---|---|---|---|---|---|---|---|
| CVE-2024-46982 | GHSA-gp8f-8m3g-qvj9 | Next.js (`next` on npm) | ≥13.5.1, <13.5.7 and ≥14.0.0, <14.2.10 | 13.5.7 / 14.2.10 | 7.5 v3.1 | CWE-444 (HTTP smuggling-adjacent cache) | Crafted request header coerces non-dynamic SSR routes in `pages/` router into the framework cache with `Cache-Control: s-maxage=1, stale-while-revalidate`; upstream CDNs may also cache |
| CVE-2024-23648 | GHSA-mrqg-mwh7-q94j | Pimcore Admin Classic Bundle | <1.2.3 | 1.2.3 | 8.8 v3.1 | CWE-20 / CWE-640 | Password-reset email URL is constructed from `Host` header; attacker-spoofed Host delivers the reset token to attacker's domain |
| CVE-2024-42914 | — (no GHSA mapping) | ArrowCMS v1.0.0 | 1.0.0 | — | 9.1 v3.1 | CWE-20 | Forgot-password Host-header injection; attacker-controlled Host emits reset link to attacker's server |
| CVE-2024-45982 | — (no GHSA mapping) | scheduleR v0.0.18 | 0.0.18 | — | 8.8 | CWE-20 | Host-header injection in password-reset URL construction; attacker-crafted link leaks reset token on victim click |
| CVE-2025-64425 | — (no GHSA mapping observed on query date) | Coolify (`coollabsio/coolify`) | ≤4.0.0-beta.434 | — (fix pending or released in post-beta) | 8.1 v3.1 / 8.5 v4.0 | CWE-20 | Forgot-password Host-header injection; attacker modifies Host of the reset request; victim receives attacker-domain reset link |
| CVE-2025-52560 | — (no GHSA mapping observed) | Kanboard (`kanboard/kanboard`) | <1.2.46 | 1.2.46 | 8.1 v3.1 / 8.8 v4.0 | CWE-20 | Password-reset URL derived from unvalidated Host header when `application_url` config is unset (default behavior); attacker-crafted reset link leaks token |
| CVE-2025-61136 | — (no GHSA mapping observed) | Sharewarez v2.4.3 (`axewater/sharewarez`) | 2.4.3 | — | 7.5 v3.1 (est.) | CWE-20 | Flask `url_for(_external=True)` on password-reset without a configured `SERVER_NAME` generates reset link under attacker-supplied Host |

Notes on the table:

- **CVE-2024-46982 (Next.js) is the current frontier cache-poisoning CVE.** The primitive is specific: non-dynamic SSR routes in the `pages/` router (not `app/`); a crafted request header coerces Next.js to cache the response with `Cache-Control: s-maxage=1, stale-while-revalidate`. Upstream CDNs that respect this header will also cache. The fix at 13.5.7 and 14.2.10 restricts the cache-coercion path.
- **Six Host-header password-reset CVEs form the dominant 2024-2026 class.** Pimcore, ArrowCMS, scheduleR, Coolify, Kanboard, sharewarez — different stacks (Symfony, custom, Flask), same shape. The pattern recurs because every framework offers an `absolute_url` / `url_for(_external=True)` / `request.host_url` primitive and every tutorial uses it without warning about Host-trust.
- **Not every CVE has a GHSA mapping.** CVE-2024-42914, CVE-2024-45982, CVE-2025-52560, CVE-2025-64425, and CVE-2025-61136 lack a globally-resolving GHSA record on the query date; they are anchored to NVD only. Their mechanism is still well-attested via the NVD description and the project repository's security advisory page.

## Next.js Cache Poisoning — CVE-2024-46982 (Pointer)

**Canonical owner**: `web_cache_poisoning_novel_deep.md § Next.js ISR Cache Poisoning` owns the CVE-2024-46982 mechanism, affected version range, patch commit, and primitive-class template with the version metadata single-owned there per §2 of the governance.

**Header-injection-adjacent framing** (host-specific residual kept here): the trigger for CVE-2024-46982 is a crafted request-header combination that coerces Next.js's `pages/` router into caching an authenticated SSR response. The header-injection class owns the request-level attacker primitive; the cache-poisoning class owns the response-level consequence (cache stores the authenticated response and serves it to subsequent visitors). Audit for header-triggered cache coercion in frameworks beyond Next.js — Nuxt SSR, Remix loader cache, SvelteKit load functions, Rails `fresh_when`/`stale?` fast-path — is a cross-framework pattern of "framework-emitted short-TTL `Cache-Control` under header-reflected conditions."

Load `web_cache_poisoning_novel_deep.md` for the version metadata and the detailed mechanism; load `race_conditions_advanced_deep.md § Cache-and-Race` for the race-condition-adjacent framing when the SWR window interacts with concurrent user requests.

## Pimcore Admin Password Reset — CVE-2024-23648

Primitive: Pimcore's Admin Classic Bundle implements password reset by sending an email with a URL. The URL is constructed using the `Host` header from the password-reset-request's HTTP headers. An attacker who initiates the password reset with a spoofed `Host` header delivers the reset URL to their own domain; the victim receives an email with the attacker-domain URL carrying the real reset token.

**Reachability preconditions:**

1. Pimcore Admin Classic Bundle version `<1.2.3`. Discovery: Pimcore installations typically have `/admin/login` or `/admin` paths; the HTML meta tags often leak the version.
2. The password-reset endpoint is reachable (typically `/admin/login/lostpassword`).
3. The victim has an account the attacker knows an email for.

**Sink location.** The password-reset email generator in Pimcore's Admin Bundle; specifically a function that constructs the reset URL via Symfony's URL generator which reads the current request's `Host` without a canonical override. The 1.2.3 patch adds canonical-host configuration enforcement.

**Attack recipe:**

```http
POST /admin/login/lostpassword HTTP/1.1
Host: attacker.tld

username=victim@target.tld
```

**Confirmation signal:** victim receives an email with a reset link under `https://attacker.tld/admin/...?token=<token>`; attacker's web server at `attacker.tld` sees the request with the token when victim clicks.

**Impact:** Account takeover of the victim's Pimcore admin account.

**Class generalization:** Symfony's URL generator (`UrlGeneratorInterface::ABSOLUTE_URL`) reads from the current request's scheme/host. Any Symfony-based application without explicit canonical-URL configuration (via `router.default_uri` in config, available Symfony 5.1+) has this exposure. Grep for `->generate(...)` with `UrlGeneratorInterface::ABSOLUTE_URL` and verify `router.default_uri` is set.

## ArrowCMS Password Reset — CVE-2024-42914

Primitive: ArrowCMS v1.0.0 forgot-password functionality builds the password-reset URL from the `Host` header. Attacker-spoofed Host delivers the reset link to attacker's domain.

**Reachability preconditions:**

1. ArrowCMS version 1.0.0 (the only vulnerable version in the NVD advisory).
2. Password-reset endpoint reachable.

**Attack recipe:** identical shape to Pimcore pattern.

**Confirmation signal:** victim email contains attacker-domain reset link.

**Impact:** Account takeover.

**Class generalization:** small/single-version CMS projects frequently have this class due to the "build the URL from Host" pattern copied from framework tutorials.

## scheduleR Password Reset — CVE-2024-45982

Primitive: scheduleR v0.0.18 Host-header injection in password-reset URL.

**Reachability preconditions:** scheduleR v0.0.18 running; reset endpoint reachable.

**Attack recipe:** identical shape to above.

**Confirmation signal:** victim-click delivers token to attacker.

**Impact:** Password reset of other users' accounts, enabling account compromise.

## Coolify Password Reset — CVE-2025-64425

Primitive: Coolify (self-hostable server/application/database management tool) ≤4.0.0-beta.434 forgot-password Host-header injection.

**Reachability preconditions:**

1. Coolify instance at a vulnerable version.
2. Password-reset endpoint reachable (part of Coolify's user management).

**Attack recipe:** POST to `/forgot-password` with spoofed Host.

**Confirmation signal:** reset link delivered via email under attacker's domain.

**Impact:** Account takeover; given Coolify's role (manages servers/databases), a compromised admin account grants significant infrastructure access.

## Kanboard application_url Unset — CVE-2025-52560

Primitive: Kanboard uses a configuration variable `application_url` to construct absolute URLs. When this variable is unset (the default on fresh installations), Kanboard falls back to reading the Host header. The password-reset email URL is therefore attacker-controllable.

**Reachability preconditions:**

1. Kanboard version `<1.2.46`.
2. `application_url` configuration is unset (default). This is the key precondition — administrators who set `application_url` are not vulnerable.
3. Password-reset endpoint reachable.

**Sink location.** Kanboard's URL helper; the fallback-to-Host behavior is in the `url_helper` module. The 1.2.46 fix adds explicit Host validation when `application_url` is unset.

**Attack recipe:** standard pattern.

**Confirmation signal:** attacker-domain reset link in email.

**Impact:** Account takeover.

**Class generalization — the "default-unset configuration" trap.** The CVE pattern recurs across self-hosted applications: a canonical-URL config exists but defaults to unset, and the fallback is "trust Host." Audit mnemonic: for any self-hosted application, check whether the canonical-URL config is set; its absence is often the finding.

## Sharewarez Flask SERVER_NAME — CVE-2025-61136

Primitive: axewater sharewarez v2.4.3 is a Flask application. The password-reset handler calls `url_for('reset_route', token=token, _external=True)` to build the reset URL. Flask's `url_for(_external=True)` without a configured `SERVER_NAME` reads the current request's `Host` header. The attacker's spoofed Host becomes the authority in the reset URL.

**Reachability preconditions:**

1. sharewarez version 2.4.3 running.
2. Flask application configuration does not set `SERVER_NAME`.
3. Password-reset endpoint reachable.

**Measured verification** (from `.zen-batch-artifacts/batch-11/measurements/host_header_trust.py`+`.out`):

```
Flask (no SERVER_NAME configured — vulnerable pattern):
  Host header sent:          attacker.tld
  url_for(_external=True) -> http://attacker.tld/reset/FAKE_TOKEN
  request.host_url        -> http://attacker.tld/

Flask (SERVER_NAME=canonical.example.com — safe pattern):
  Host header sent:          attacker.tld
  url_for(_external=True) -> https://canonical.example.com/reset/FAKE_TOKEN
  request.host_url        -> https://attacker.tld/
```

The measurement confirms:

1. `url_for(_external=True)` on an unconfigured Flask is directly Host-controllable.
2. Setting `SERVER_NAME` fixes `url_for` but *not* `request.host_url` — a subtle second-order gotcha.

**Sink location.** Flask's `url_for` helper in `werkzeug.routing`; the behaviour is intentional (`url_for(_external=True)` defaults to current-request-based URL construction) and only overridden by `SERVER_NAME`.

**Attack recipe:**

```http
POST /forgot-password HTTP/1.1
Host: attacker.tld

email=victim@target.tld
```

**Confirmation signal:** email with attacker-domain reset link.

**Impact:** Account takeover.

**Class generalization — the "Flask default is unsafe" lesson.** Every Flask application that:

1. Uses `url_for(_external=True)` in email templates for password resets, OAuth redirects, or any user-reachable URL.
2. Does not set `app.config['SERVER_NAME']`.

...is default-vulnerable to Host-header injection. The pattern applies to:

- Any `/forgot-password` or `/reset-password` flow.
- Any `/verify-email` or `/confirm-account` flow.
- Any OAuth integration with `redirect_uri` built via `url_for(_external=True)`.
- Any webhook or callback URL emitted from the server.

The audit mnemonic for Flask: grep for `url_for(` with `_external=True`; check `app.config.get('SERVER_NAME')` or the application-factory for a canonical configuration. Absence is the finding.

**Measured frontier observation — FastAPI/Starlette has the same trap, no SERVER_NAME equivalent.** From the measurement:

```
FastAPI (default — Starlette-shaped):
  Host header sent:          attacker.tld
  request.url_for         -> http://attacker.tld/reset/FAKE_TOKEN
  request.base_url        -> http://attacker.tld/
```

FastAPI / Starlette has no SERVER_NAME-equivalent configuration. The only defence is a reverse-proxy-level Host-rewrite (e.g., Nginx `proxy_set_header Host canonical.example.com`) or an explicit canonicalization in application code. This is a current frontier observation: the ecosystem's answer to Host-header injection is still "configure your reverse proxy" rather than a framework-level canonical-host feature. Expect more CVEs in FastAPI applications.

## Composite Chaining — Current CVE Instances

### Chain: Next.js Cache Poisoning → Multi-User Information Disclosure

- Starting point: Next.js app on affected version with CDN front.
- Step 1 (CVE-2024-46982): crafted request pulls authenticated dashboard into cache.
- Step 2: anonymous visitors receive cached authenticated content.
- Step 3: attacker enumerates users via sequential cache probes.

Impact: cross-user authenticated content disclosure at CDN scale.

### Chain: Host-Header Password-Reset → OAuth Chain

- Starting point: application uses OAuth with Host-dependent redirect_uri.
- Step 1 (any of the 6 Host-header CVEs' primitive): poison the OAuth authorize request's Host.
- Step 2: OAuth code delivered to attacker's domain.
- Step 3: attacker exchanges for access token.

Route: `open_redirect.md § OAuth redirect_uri`.

### Chain: Host-Header → Multi-Tenant Routing Hijack

- Starting point: application dispatches tenants by Host header.
- Step 1: Host-header injection in a POST that mutates per-tenant state.
- Step 2: write lands in attacker-chosen tenant.
- Step 3: cross-tenant data corruption or exfiltration.

Route: `broken_function_level_authorization.md § Multi-Tenant Routing`.

### Chain: Flask url_for → Password-Reset → Admin Account

- Starting point: Flask admin panel with `url_for(_external=True)` and no SERVER_NAME.
- Step 1: Host-header injection in admin password reset.
- Step 2: admin reset token leaks to attacker.
- Step 3: attacker completes reset; admin account takeover.

Route: `authentication_jwt.md § Admin-Account Takeover`.

## Research Frontier — Framework-Level Host-Trust

The seven-CVE lineage in 2024-2026 is not an accident — it reflects a current ecosystem-level failure mode:

**Pattern recurrence drivers:**

- Framework tutorials universally show `url_for(_external=True)` / `request.host_url` / `request.url_for` without warning.
- The canonical-URL configuration (SERVER_NAME in Flask, router.default_uri in Symfony, application_url in Kanboard) is a documented-but-not-defaulted feature.
- Reverse-proxy configuration is "someone else's problem" from the application developer's point of view, but is the primary line of defence.

**Open frontier observations (deferred to end-of-project gap list):**

- **FastAPI / Starlette**: no SERVER_NAME-equivalent; expect more CVEs. Audit mnemonic: grep for `request.url_for` and `request.base_url` in password-reset / email flows.
- **Express.js**: `req.get('Host')` is the common pattern; `req.hostname` respects `trust proxy` setting but still ultimately reads a header value. Audit the trust-proxy configuration and the per-route host usage.
- **Spring MVC**: `request.getRequestURL()` and `ServletUriComponentsBuilder` both default to Host; `server.forward-headers-strategy=native` or similar is required to configure correctly.
- **Django**: `request.get_host()` validates against `ALLOWED_HOSTS` — Django is relatively safe by default when `ALLOWED_HOSTS` is correctly configured, but misconfigured `ALLOWED_HOSTS='*'` deployments share the class.
- **Rails**: `request.host` without `config.action_mailer.default_url_options` set is similarly unsafe; Rails documentation does cover this.

## Non-CVE Technique-Class Frontier (2024-2026)

Beyond the seven CVEs above, the current header-injection frontier includes non-CVE technique classes:

### James Kettle Cache Research Lineage (Current)

PortSwigger continues to publish cache-poisoning research beyond "Practical Web Cache Poisoning" (the 2018 foundational paper). The 2024-2026 research cycle has focused on:

- **"Gotta Cache 'Em All"** (Kettle, Nov 2024) — path-normalization confusions where CDN and origin disagree on the canonical URL after `../`/`..;/`/`;`/`#` normalization.
- **"Browser-Powered Desync Attacks"** (Kettle, 2022-2024 updates) — the browser is the smuggling client, not the attacker's own HTTP library.
- **Cache-key confusion via CSP nonce reflection** — a server that echoes a request-supplied nonce into the response's CSP header can leak privileged content via nonce-keyed caching.

Audit mnemonic: for every CDN-fronted target, probe path normalization quirks with `..;/`, `%2e%2e/`, `/.%00`, trailing-dot variants and compare the response fingerprint between CDN cache HIT and MISS.

### Mail Header Injection — Non-CVE Pattern

The SMTP header injection class (CRLF in `From`/`To`/`Cc`/`Subject`) remains high-frequency in contact forms, newsletter signup, and account-notification flows. Rare CVE assignments because the class is seen as "application-specific," but widely exploitable.

**Audit mnemonic:** for any outbound email sent from the application, probe `email=user@x%0d%0aBcc:%20attacker@tld` and verify the attacker receives a Bcc.

**Current project frontier:** PHPMailer (older versions historically CVE-ed; current versions mitigate), Nodemailer, SendGrid Python/Node libraries (API-based, usually safe), AWS SES SDK (API-based, safe).

### WebSocket Upgrade Response-Header Reflection

Current frontier for WebSocket security:

- `Sec-WebSocket-Protocol` reflection without allowlist — CRLF-injectable.
- `Sec-WebSocket-Extensions` echoing — can be used to tunnel attacker headers.
- `Origin` reflection into `Access-Control-Allow-Origin` on the handshake — enables CSWSH + credentials.

Audit mnemonic: for WebSocket servers, send handshake requests with malformed protocol/extensions headers and observe response.

### CDN-Side Cache Rule CVE Frontier

CDN platform-level cache CVEs are rare because the CDN vendors manage cache behaviour; when they do occur, they are high-impact:

- **Cloudflare "DNS Rebinding" + Workers** — not a CVE class but a continuing research surface.
- **Vercel edge-cache** — Next.js on Vercel inherits the Vercel edge cache's quirks; CVE-2024-46982 was the Next.js side, but the Vercel edge configuration also plays a role in reachability.
- **AWS CloudFront + Lambda@Edge** — custom cache keys constructed in Lambda@Edge are code; code can have bugs; the bugs are rarely CVE-ed because they're per-customer deployment.

Audit mnemonic: for CDN-fronted targets with custom cache rules (Vercel edge config, CloudFront Lambda@Edge, Cloudflare Workers), probe the cache-key composition explicitly.

### Internal-Redirect Response-Header Frontier

- **Nginx `X-Accel-Redirect` + path traversal** — if user input reaches the X-Accel-Redirect header without path normalization, internal protected routes become reachable.
- **FastCGI `Status:` + `Content-Type:` + `Location:` header interpretation** — modern PHP-FPM deployments and some Python WSGI stacks respect these in CGI-mode fallbacks.
- **Apache `mod_rewrite` + response header injection** — attacker-reachable response headers may interact with Apache's rewrite rules.

Audit mnemonic: for Nginx/Apache deployments, enumerate the internal-redirect / handler-dispatch surface and probe whether application-emitted response headers can trigger an unexpected internal dispatch.

### Content Security Policy (CSP) Header Injection

- CSP `report-uri` / `report-to` injection — attacker-controlled URL receives CSP violation reports (which can include JWT fragments, state tokens, etc.).
- CSP `nonce` reflection into HTML — attacker-chosen nonce defeats the CSP's inline-script restriction.
- CSP `frame-ancestors` injection — enables clickjacking by widening the frame-ancestors allowlist.

Audit mnemonic: for any CSP-emitting response, probe whether the CSP contents are influenced by request headers or body; `report-uri`-injection is a quick exfiltration primitive.

## Verification Discipline

Each CVE citation in this file is anchored to one persisted NVD or GHSA artifact that resolves on the authoritative *global* source. For CVEs lacking a GHSA mapping (CVE-2024-42914, CVE-2024-45982, CVE-2025-52560, CVE-2025-64425, CVE-2025-61136), the NVD record is the single authoritative source and is persisted in `.zen-batch-artifacts/batch-11/ghsa-nvd/`.

The measured framework host-trust behavior is reproduced by `.zen-batch-artifacts/batch-11/measurements/host_header_trust.py`+`.out`:

```
Flask (no SERVER_NAME configured — vulnerable):
  url_for(_external=True) -> http://attacker.tld/reset/FAKE_TOKEN
  request.host_url        -> http://attacker.tld/

Flask (SERVER_NAME=canonical.example.com — partial defence):
  url_for(_external=True) -> https://canonical.example.com/reset/FAKE_TOKEN   [safe]
  request.host_url        -> https://attacker.tld/                            [still reflects!]

FastAPI (default — Starlette-shaped):
  request.url_for         -> http://attacker.tld/reset/FAKE_TOKEN             [vulnerable]
  request.base_url        -> http://attacker.tld/                             [vulnerable]
```

The partial-defence row in Flask demonstrates a subtle gotcha: setting `SERVER_NAME` protects `url_for` but not `request.host_url`. Applications using the latter in email templates remain exposed.

## Breadth Note

Novel-tier scope for header injection is genuinely narrower than the §2 ~850-line aim: the 2024-2026 CVE lineage is well-covered (one standout cache-poisoning CVE in Next.js plus six Host-header password-reset CVEs across different stacks), measured framework host-trust behaviour is persisted and reproduced, and the non-CVE technique-class frontier is enumerated (Kettle 2024 cache research, mail header injection, WebSocket upgrade, CDN-side cache rules, internal-redirect, CSP header injection). What makes the header-injection novel-tier naturally thinner: the Host-header password-reset primitive is uniform across the six-CVE lineage ("application pulls Host into URL construction without canonicalization"), so per-CVE depth is more compact than for parser-differential classes. The depth that scales with the class lives in the advanced sibling (full-treatment sub-primitives across CRLF payload taxonomy, cache-key reconnaissance, X-Forwarded-* precedence, Host-exploit catalog, Set-Cookie manipulation, internal-redirect, HTTP/2 pseudo-header edges, per-CDN cache specifics, SMTP, WebSocket, TE/CL collision, BREACH).

## Summary

The 2024-2026 header-injection CVE frontier is dominated by Host-header injection in password-reset flows — seven CVEs across Pimcore, ArrowCMS, scheduleR, Coolify, Kanboard, and sharewarez — reflecting an ecosystem-level failure to default-safe canonical-URL configuration. CVE-2024-46982 (Next.js) is the standout cache-poisoning CVE, converting a framework cache primitive into cross-user authenticated-content disclosure at CDN scale. Measured framework behavior confirms Flask and FastAPI/Starlette are default-vulnerable to Host-header injection in URL construction; FastAPI lacks a SERVER_NAME-equivalent entirely. The chaining surface — through password-reset to account takeover, OAuth redirect_uri hijack, multi-tenant routing confusion, and cache-poisoning to cross-user XSS — makes this class one of the most consistently high-impact in modern web pentesting.
