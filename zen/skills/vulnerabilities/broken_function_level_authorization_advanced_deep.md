---
name: broken-function-level-authorization-advanced-deep
description: Advanced BFLA depth — verb-tampering variants, URL-rewrite proxy bypass classes, forced-browsing at scale, JWT/role-claim escalation, and adversarial two-role session-swap methodology across REST/GraphQL/gRPC/WebSocket
sibling: broken_function_level_authorization
load_when: scan_mode == "deep"
---

# BFLA — Advanced Deep

Load `broken_function_level_authorization` for base-tier framing (BFLA-vs-IDOR axis, WSTG-ATHZ-02 two-user session-swap, forced browsing, method tampering, X-Original-URL primitives). Load `broken_function_level_authorization_novel_deep` for the 2024–2026 emerging-stack authorization surface, ASVS 5.0 V8 metadata, and LLM-agent function-level primitives. This file owns the advanced/expert layer between them: layered request-stack differentials at the function-authz level, adversarial forced-browsing at scale, JWT-claim escalation shapes, and confirmation methodology for evasive admin endpoints.

## Verb-Tampering Deep

The base file introduces method-override headers and `_method` body parameters. The advanced surface includes framework-idiomatic variants and rare methods:

### Framework-Specific Method-Override Support

- **Rails**: `_method=DELETE` in POST form body is the canonical Rails idiom (`Rack::MethodOverride`). Custom apps sometimes carry `Rack::MethodOverride` into JSON handlers too — send `{"_method":"DELETE"}` in an application/json body.
- **Laravel**: `_method=DELETE` in form body is the canonical Laravel idiom; also `@method('DELETE')` in Blade templates. Middleware order matters: some auth middleware runs before method override, some after — probe both.
- **Django**: no built-in method-override, but `django-rest-framework` supports `X-HTTP-Method-Override`. Custom middlewares in the wild sometimes add `?_method=` support.
- **ASP.NET Core**: `X-HTTP-Method-Override` is supported by default in ASP.NET Core when the `MvcOptions.EnableEndpointRouting` is legacy.
- **Express**: `method-override` npm package is common; supports both header and body override. Check the middleware ordering — auth after method-override is a bypass.

### Rare HTTP Method Bypass

- **TRACE**: some servers echo the request; a TRACE against `/admin/*` may reveal middleware headers and reflect the caller's identity claims.
- **CONNECT**: proxying primitive; on some servers CONNECT to internal admin routes reaches them past the app's proxy config.
- **PATCH, PUT, DELETE via a POST-only middleware**: if the middleware only sees POST bodies, but the router dispatches based on the wire method, an actual PATCH bypasses the middleware.
- **PROPFIND / MKCOL / MOVE / COPY**: WebDAV methods. Legacy IIS installations may respond to these on ASP-adjacent paths; the auth middleware often only recognizes GET/POST.
- **PURGE**: some caches (Varnish, nginx cache module) accept PURGE to invalidate cache entries. A `PURGE /admin/*` may be exposed unauthenticated on the cache layer.
- **REPORT / SEARCH / MERGE**: WebDAV extensions. Rare but present.

### Verb-Case and Normalization Drift

- `get` vs `GET` — HTTP spec says methods are case-sensitive; some routers normalize to uppercase, some don't. A `Get` from a client may reach a case-sensitive router as a distinct method.
- `POST\r\n\r\n` with an extra CRLF — some servers trim, some don't; the trimmed version may reach a different handler.
- Method with trailing space (`POST `) — should be rejected, but some parsers accept it.

## URL-Rewrite Proxy Bypass — Deep

WSTG-ATHZ-02 documents X-Original-URL and X-Rewrite-URL as canonical primitives. The full class:

### Header-Based Rewrite

- `X-Original-URL: /admin/users` — canonical WSTG primitive
- `X-Rewrite-URL: /admin/users` — IIS URL Rewrite convention
- `X-Original-URI: /admin/users` — proxy-vendor variant
- `X-Forwarded-URI: /admin/users` — nginx `proxy_set_header` variant
- `X-Original-Method: DELETE` — combined with URL rewrite for full-primitive
- `X-Override-URL: /admin/users` — custom middleware variant
- `X-Real-URL: /admin/users`, `X-Request-URI: /admin/users` — additional shape variants seen in the wild

### Path Normalization Drift

The primitive is a mismatch between the proxy's URL normalizer and the app's:

- `/public/status;/admin/users` — matrix parameters (RFC 3986 §3.3). Some proxies strip `;<param>=<val>`, some don't.
- `/public/status/../admin/users` — `..` resolution differs across normalizers.
- `/public/status/./admin/users` — `.` resolution.
- `/public/status%2f/admin/users` — encoded slash; some proxies decode, some don't. If the proxy leaves it encoded but the app URL-decodes before dispatch, path-traversal-shape bypass.
- `/public/status%252f/admin/users` — double-encoded; some proxies decode once, apps decode again.
- `/public/status\admin\users` — backslash instead of slash; Windows-shape.
- `/public/status/../../admin/users` — deep traversal; each `..` peels one segment; if the proxy caps at 1 `..` but the app processes multiple.
- Unicode path segments: `/public/status/\u0000/admin/users` — null-byte injection.
- Overlong UTF-8: `/public/status/%c0%af/admin/users` (overlong `/`); rejected by modern parsers but check.

### CDN and WAF Path Handling

- **Cloudflare**: normalizes `..` and `.` before forwarding; `%2f` in path is preserved in the raw URL. Cloudflare's `Transform Rules` may rewrite URLs — a request that survives the transform reaches the origin with a different path than the WAF saw.
- **AWS CloudFront + WAF**: WAF rules apply against the request URL; if a CloudFront function or Lambda@Edge rewrites the URL after WAF, the rewrite is authorization-free.
- **Nginx `proxy_pass` behavior**: `proxy_pass http://backend/` (with trailing slash) strips the location prefix; without it, forwards the full URL. Configuration mistakes leak admin paths through location misconfiguration.

### The 403-Bypass Toolkit

The BurpSuite_403Bypasser extension packages this class. Techniques it applies to each 403-returning path:

- Append trailing characters: `/admin/users/`, `/admin/users/.`, `/admin/users//`, `/admin/users;`, `/admin/users;.php`, `/admin/users..;/`, `/admin/users?`, `/admin/users#`, `/admin/users&`
- Case variations: `/Admin/users`, `/ADMIN/users`, `/aDmIn/users`
- URL-encoding variations: `/%61dmin/users`, `/admin%2fusers`, `/admin%252fusers`
- Insert path segments: `/admin/./users`, `/admin/../admin/users`, `/./admin/users`
- Add matrix parameters: `/admin;anything/users`, `/admin/users;jsessionid=xyz`
- Header combos with each of the above

## Forced Browsing at Scale

The base file introduces `ffuf` with common admin wordlists. The scaling primitives:

### Wordlist Composition

- **Framework-derived**: extract every path from `python manage.py show_urls` (Django), `rails routes` (Rails), `php artisan route:list` (Laravel), `dotnet run -- --list-endpoints` (ASP.NET). These are the real endpoints the target ships.
- **Historical**: `gau target.tld`, `waybackurls target.tld`, Wayback Machine snapshots. Every past path the target ever exposed is a candidate for legacy-route BFLA.
- **Client-derived**: mobile APKs (`jadx`, `apktool`), SPA JS chunks (parse for URL constants), sitemap.xml, robots.txt. The endpoints referenced from client code are the canonical route set.
- **Framework-common**: SecLists' `Discovery/Web-Content/api/`, `common.txt`, `raft-*.txt`. These are the fallback set.
- **Custom-tenant-derived**: for multi-tenant apps, the tenant slugs enumerated via subdomain brute force + `{tenant}` substitution in every path is a targeted wordlist.

### Cross-Version Enumeration

- `/api/v1/*`, `/api/v2/*`, `/api/v3/*`, `/api/mobile/*`, `/api/internal/*`, `/api/legacy/*`, `/api/beta/*` — each version prefix carries its own middleware chain.
- Enumerate versions from OpenAPI, client bundle, or by fuzzing `/api/vN/` up to `N=10` and checking response shapes.

### Wildcard-Route Abuse

- Routes with wildcard segments (`/admin/*`, `/api/**`) may catch unexpected sub-paths. Probe `/admin/anything`, `/admin/foo/bar/baz` — the middleware may pattern-match on `/admin/` but the handler resolves to a specific admin handler.
- Path-parameter overshoots: `/api/orders/{id}` accepting `/api/orders/DELETE` — the ID handler may execute the string as a method.

### Method Fuzzing Combined with Path Fuzzing

- Two-dimensional fuzz: path × method matrix. A `POST /admin/refunds` may be gated but `GET /admin/refunds` may be a listing that leaks refund data.
- `ffuf` with `-request` reads a request template and substitutes; use it for method × path fuzz.

## JWT-Claim Escalation Shapes

The primitive is a JWT that carries elevated role/permission claims. Load `authentication_jwt` for the JWT-side primitive; the BFLA angle is the specific claims-to-endpoints mapping:

### Common Elevated Claims

- `role: "admin"`, `role: "superuser"`, `role: "staff"`, `role: "support"`
- `roles: ["user", "admin"]` (array shape)
- `permissions: ["admin:*", "user:read"]` (scope shape)
- `scope: "admin openid profile"` (space-separated shape)
- `groups: ["/Admins", "/Users"]` (LDAP/AD-style)
- `is_admin: true`, `is_superuser: true` (boolean shape)
- `aud: "admin-api"` (audience shape — different aud reaches different app tier)
- `act: {"sub":"admin-user"}` (RFC 8693 impersonation)

### JWT Tampering Primitives

- **`alg: none`**: unsigned token accepted by naive JWT verifiers. Craft `{"role":"admin"}` payload with `{"alg":"none"}` header.
- **`alg: HS256` with public-key confusion**: verify accepts HMAC with public key as the shared secret. Sign with the RSA public key of the target's JWKS.
- **`kid` header manipulation**: `kid` may reference a URL or filesystem path; a `kid: file:///etc/passwd` or `kid: http://attacker.tld/jwks.json` fetches attacker-controlled key material.
- **JKU header**: `jku: http://attacker.tld/jwks.json` — external key set trust.
- **Expired-token-still-accepted**: apps that log `exp` violations but don't reject.

### Post-JWT-Forgery BFLA Sweep

Given a forged token with elevated claims, sweep every admin endpoint. The forgery is one primitive; the BFLA is the specific endpoints reachable. Report each admin endpoint reached as a separate BFLA finding (some may still gate at a deeper layer even with the forged claims).

## Impersonation Endpoint Deep

Support-agent impersonation is a rich BFLA surface:

- **`POST /admin/impersonate/{userId}`**: standard shape. Should require admin role AND validate target scope. Missing role = BFLA; missing target scope = IDOR.
- **`POST /me/switch-account/{userId}`**: self-service switch-account for multi-account users. Should require the caller to have an established link to the target account. Missing link check = cross-account BFLA.
- **`POST /support/sudo` with `{"user_email":"..."}`**: support-tool sudo endpoint. Should require support role + auditable ticket reference. Missing role = full impersonation.
- **`Cookie: impersonate_as=<email>`**: cookie-based impersonation. Check whether the cookie is server-signed (JWT) or client-declared (plain email). Client-declared is direct impersonation.
- **`X-Impersonate-User: <email>`**: header-based impersonation. Same shape.
- **`GET /admin/user/{id}/masquerade`**: some apps embed a masquerade endpoint in the admin panel that issues a masquerade cookie/token. Direct-call the endpoint under a low-priv token to see if it issues.
- **OAuth Token Exchange for impersonation** (RFC 8693): `POST /oauth/token` with `grant_type: urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token: <caller>`, `requested_subject: <target>` — the exchange endpoint may issue a target-scope token if the caller has an "impersonate" permission but no target restriction.

### Impersonation Session Persistence

Once impersonated, the session may persist across page loads. A masquerade cookie that survives the auth-boundary is a durable primitive. Test:

- Log out — does the masquerade session persist?
- Rotate the underlying admin credential — does the masquerade session survive?
- Cross-device — does the masquerade session apply on another device?

## Feature-Flag Bypass Deep

Feature flags gate function-level access; the flag-store is an authorization boundary:

### Flag-Value Retrieval

- **`GET /flags?userId=<foreign>`**: returns the flags applied to a foreign user. Even without exploiting the flags, this reveals the target's feature set.
- **`GET /flags/{flagName}`**: reveals the flag's rollout rules, targeting, and current values.
- **`GET /flags?environment=production`**: environment-specific flag dumps.
- **SDK-key exposure**: the flag SDK's client-side key (LaunchDarkly `client-side-id`, Split `client-api-key`) often ships in the JS bundle; enumeration reveals every flag the client-side has visibility to.

### Flag Override

- **`POST /flags/{flagName}/override` with `{"userId":<foreign>,"value":true}`**: overriding a flag for a foreign user in a specific state. If the endpoint isn't scoped, cross-user flag manipulation.
- **`X-Flag-Overrides: admin_console=true`**: some SDKs support in-request flag overrides via header for debugging; production instances forgetting to disable this in prod are BFLA-shape.
- **`?flag_override[admin_console]=true`**: query-param override.

### Percentage-Rollout Bucket Manipulation

- Rollouts bucket by hash of user ID modulo N. An attacker who can influence their own user ID (via account creation, email change, or ID reset) may land in a bucket that grants access.
- Attributes-based targeting: LaunchDarkly `custom_attributes` — an app that passes user-controlled attributes to the SDK may allow the attacker to declare themselves as an admin.

### Flag-Store SaaS Console BFLA

- LaunchDarkly, Split, Optimizely all expose an admin console. An API key with over-broad scope (`sdk-*`, `api-*`) reaches the console API and can toggle flags globally.

## Cache-Layer BFLA

Caches interact with function-level authz in three failure modes:

### Cache-Key Omission

- URL-only keying: a CDN that keys on `URL + Vary headers` without including `Authorization` or `Cookie` serves the first user's admin response to any subsequent request. An admin action taken by an admin populates the cache; a subsequent low-priv request hits the cached response.
- Vary header manipulation: send `Vary: X-Requested-With` in a response you can influence (via webhook response, redirect target). Subsequent requests differing only in that header share the cached entry.
- Cache-Control abuse: `Cache-Control: public, max-age=3600` on admin responses leaks them into shared caches.
- Session-cookie omission from cache key: cookies frequently excluded from cache keys for performance; but session cookies carry identity. Any cache that excludes them and includes admin responses is cross-user leak.

### Cache Poisoning for BFLA

- Reflected-header poisoning: response includes a value from the request (`X-Forwarded-Host`). Cache that keys on URL but ignores the poisoning header caches the poisoned response.
- Content-negotiation via unkeyed headers: `Accept-Language`, `User-Agent` — some routes select content by these but don't include them in the cache key.
- Response-split under method-override: a proxy that treats the raw method as GET (and caches) but the app treats the override method as POST (mutation) gets a cached mutation-effect served on subsequent GETs.
- Vary-poisoning: control the response's Vary header via a header that's echoed back; cache uses the poisoned Vary for keying, subsequent requests hit the poisoned entry.

### Cache-Purge as BFLA

- `PURGE /admin/*` — the cache-purge endpoint may be exposed unauthenticated at the cache layer (Varnish, nginx cache module); an attacker who can purge invalidates admin cache and forces re-fetch under attacker context.
- `X-Purge-Cache: 1` custom header — some proxies accept a purge header on any request.
- Cache-invalidation API: some CDNs expose an invalidation API. If an admin's invalidation credentials are enumerable or leaked, attacker triggers cache invalidation as a DoS-BFLA.

### CDN Origin-Direct Bypass

If the CDN is enforcing auth and the origin isn't, a request that reaches origin directly (via leaked origin IP, wildcard SNI, alternate DNS) bypasses cache-layer auth entirely. Enumerate: DNS records, historical DNS, subdomain scans, certificate transparency for hosts pointing at origin.

## Race-Window Exploitation — Deep

Base file introduces TOCTOU races. The advanced surface:

### Two-Phase Commit Races

- **Approve/execute race**: `POST /admin/orders/{id}/approve` writes state; `POST /admin/orders/{id}/execute` reads the state. Between approve and execute, mutating the caller's role (via a parallel demote) — the execute may still proceed under the pre-demote authorization decision.
- **Draft/publish race**: `POST /admin/pages/{id}/draft` (permitted for editors) followed by `POST /admin/pages/{id}/publish` (permitted for admin). Between draft and publish, if the publish endpoint doesn't re-check role, editor-role can publish.

### Concurrent Session-Modification

- Two sessions of the same user, one with elevated permissions temporarily granted (e.g., via re-auth). If the elevated permission is revoked in one session but the other session's cached authz state retained the elevation, the retained session persists admin access.
- Admin logs into browser A; admin's role revoked; admin logs out of A but session B remains with cached admin state.

### Token-Rotation Mid-Request

- OAuth refresh happens mid-request. If auth was checked with the old token (admin scopes) but the request executes with the new token (basic scopes) — or vice versa — the outcome depends on which token was cached.

### Async-Consumer Race

- Message published to queue under admin session; the message-processor consumes it under service identity minutes later. If admin's role was revoked in between, the message still executes at the (old) admin authorization state.

## Cookie-Path, Domain, and Same-Site Scope BFLA

Cookie scoping is authorization-adjacent:

### Cookie-Path BFLA

- **Cookie set with `Path=/admin`**: intended to bind only to admin routes; but if the app doesn't strictly enforce path scoping and a client-side gadget can retrieve the cookie, cross-path submission.
- **Path-scope confusion**: `Set-Cookie: session=xxx; Path=/api/admin` may not be sent to `/api/staff` — but if `/api/staff` is also admin-shape, the different cookie surface may reveal role structure.

### Cookie-Domain Overreach

- `Set-Cookie: role=admin; Domain=.app.tld` — the cookie is sent to every subdomain including `www.app.tld` and any subdomain an attacker may control. Subdomain takeover (load `subdomain_takeover`) into an app.tld subdomain then delivers admin cookies to the attacker's page.
- Cross-subdomain identity: `admin.app.tld` and `www.app.tld` sharing a session cookie — if `www.app.tld` is XSS-reachable, the XSS reads the admin session cookie.

### Same-Site Cookie Bypass

- `SameSite=Lax` cookies are sent on top-level GET navigations but not cross-origin POSTs. A BFLA that also accepts GET (verb-tamper) is deliverable cross-origin under Lax.
- `SameSite=None; Secure` cookies are sent on any cross-origin request. Combine with a CSRF-shape delivery for cross-origin BFLA.
- Missing `SameSite` attribute — browser default varies by version; older browsers treat as `None`.

### Cookie-Prefix Confusion

- `__Host-` prefix requires `Secure`, `Path=/`, no `Domain`. Enforcement varies; some browsers permit malformed prefix cookies.
- `__Secure-` prefix requires `Secure`. A missing `Secure` on such a cookie is a config error.

## OAuth Authorization Server — Admin Function BFLA

OAuth authorization servers (Keycloak, Auth0, Okta, AWS Cognito, self-hosted) expose administrative endpoints for user/client management:

### Realm / Tenant Administration

- `POST /admin/realms/{realm}/users` (Keycloak) — create user in a realm. If cross-realm auth is misconfigured, cross-tenant user creation.
- `POST /admin/realms/{realm}/users/{id}/reset-password` — password reset by admin. Cross-realm invocation grants password reset of any user.
- Auth0 Management API: `POST /api/v2/users` — management API endpoints gated by M2M token scope. An over-broad M2M token (`create:users`, `read:users`, `update:users`) is a persistent BFLA primitive.
- Cognito: `AdminInitiateAuth`, `AdminCreateUser`, `AdminSetUserPassword` — admin operations gated by IAM. IAM policy overrides can be BFLA-shape.

### Client-Credentials Grant Scope Expansion

- Client-credentials tokens carry `scope: "admin:*"`. An enumerable client-ID with a leaked or guessable client-secret grants admin scopes.
- Scope narrowing in token exchange: `POST /oauth/token` with `grant_type: token-exchange` and `scope: admin:*` — narrowing to a scope the caller shouldn't have.

### Service-Account Impersonation

- Service accounts often have broad scopes; a compromised service account is a durable BFLA vector.
- Cross-service-account impersonation via token exchange (RFC 8693): `subject_token: <caller-token>`, `requested_subject: <service-account>` — issues a token as the service account.

### OIDC Session-Management BFLA

- `/session/end`, `/logout`, `/oidc/session-end` — session-termination endpoints. If invoked with a foreign session ID, the endpoint may terminate the target's session (DoS-shape BFLA).
- `/session/inspect` — some OIDC providers expose a session-introspection endpoint under admin scope; a mis-scoped token reads session details across users.

## Server-Side Request Handler Discovery — Deep

The advanced discovery beyond OpenAPI/introspection:

- **Client bundle static analysis**: extract every URL, GraphQL operation, and gRPC method reference from the compiled JS/mobile bundle. Even minified bundles preserve string literals.
- **Historical URL corpus**: `waybackurls`, `gau`, `hakrawler`, `katana` extract every path the target has ever exposed.
- **Application binary strings**: `strings` on the mobile APK or Windows/Mac binary reveals baked-in endpoints and service names.
- **Framework debug endpoints**: `django-extensions show_urls`, `rails routes`, `php artisan route:list`, `dotnet run --list-endpoints` may be exposed as HTTP endpoints (`/debug/routes`, `/_rails_info`) under a debug flag.
- **Container-level introspection**: Docker labels, Kubernetes annotations, Consul service registry entries — a leaked container manifest reveals every service endpoint.
- **Log correlation**: an attacker with log access (via `information_disclosure`) sees which endpoints admins actually invoke — the "warm path" that's likely to be admin-shape.

## Race-Window Exploitation for BFLA

The primitive is a state-change endpoint that authorizes at request start and executes state changes at the end:

- **Approve/reject race**: `POST /admin/orders/{id}/approve` — the approve endpoint reads the caller's role at request start, but the approval writes to the DB at the end. Change the caller's role mid-request (via a parallel demote) — the mutation lands under the wrong role.
- **Long-running admin action mid-race**: `POST /admin/reports/generate` initiates a long-running job; the auth check runs at start, the job runs under service context. If the caller can influence which service credentials the job runs under, cross-role admin.
- **Token-rotation race**: token refresh between auth check and business logic — the new token has different claims. An admin token that refreshes mid-request to a lower-role token still executes the admin action.

## Debug, Actuator, and Info Endpoint Deep

Framework-provided introspection endpoints are a rich BFLA surface:

### Spring Boot Actuator

- `/actuator/env`: environment variables including credentials (JDBC URLs, API keys, service tokens).
- `/actuator/heapdump`: process memory dump (`.hprof` file). Grep for tokens/secrets in the dump.
- `/actuator/loggers`: read/modify logger levels; enabling DEBUG level exposes internal state.
- `/actuator/threaddump`: current thread stacks.
- `/actuator/gateway/routes`: Spring Cloud Gateway route table.
- `/actuator/mappings`: request-mapping table (route discovery).
- `/actuator/beans`: Spring beans (dependency graph).
- `/actuator/health/{component}`: detailed per-component health, often revealing DB, cache, and dependency status.
- Configuration mistakes to search for: `management.endpoints.web.exposure.include=*` (all endpoints exposed to authenticated), `management.security.enabled=false` (no auth on Actuator).

### Rails and Sinatra

- `/rails/info/routes`: route table.
- `/rails/info/properties`: Rails environment properties.
- `/rails/info`: general info page.
- `/mailers/*/preview`: development mailer previews; in production reveal templates and sample data.

### Django

- `/admin/`: full admin console.
- Django Debug Toolbar (`/__debug__/`): request/response introspection with SQL query logs.
- `?debug=1` on views with `django-debug-toolbar` installed.
- `DEBUG=True` in `settings.py` — the debug 500 page reveals full stack traces, settings, request context.

### Node / Nest

- `/health/detailed`: some NestJS apps expose per-service health details.
- `/api-docs`, `/swagger`, `/redoc`: OpenAPI UI often unauthenticated in dev/staging.
- Node inspector (`--inspect-brk`): if the debug port is exposed, arbitrary code execution.

### .NET

- `/swagger`: OpenAPI UI.
- ELMAH (`/elmah.axd`): unhandled exception log.
- `/trace.axd`: request trace log.
- App Service Editor and Kudu (`https://<app>.scm.azurewebsites.net/`): full app management on Azure App Service.

Each of these framework introspection surfaces is a candidate for BFLA testing — verify the current role has permission to read/modify each. Publicly-reachable in production is the finding.

## GraphQL Function-Level Authz Deep

Base-file GraphQL coverage introduces resolver-level checks. The advanced surface:

### Admin-Mutation Discovery via Introspection

GraphQL introspection returns the full schema; every `Mutation` field is a candidate. Filter for admin-shape:

```graphql
{
  __schema {
    mutationType {
      fields {
        name
        args { name type { name } }
        description
      }
    }
  }
}
```

Look for names containing `admin`, `internal`, `system`, `sudo`, `promote`, `impersonate`, `override`, `force`, `set`, `create` on high-privilege types (`User`, `Organization`, `Payment`).

### Resolver-Level Enforcement Drift

- **Type-level `@auth` decorator only**: `type Query @auth(role: "admin")` decorates the whole type, but the resolver may not actually consult the decoration. Frameworks require explicit resolver wiring; the decoration is documentation-shape.
- **Field-level check missing on some fields of an admin type**: `type AdminUser { name: String; hashed_password: String @auth(role: "superadmin") }` — the `name` field may be reachable under admin role while `hashed_password` requires superadmin. But the resolver may return the whole object without per-field filtering.
- **Interface-fragment leakage**: `... on AdminUser { hashed_password }` on a `User` interface may reach the AdminUser subtype's fields under a base-User query context.

### Alias-Based BFLA Sweep

- Multi-mutation batching: `mutation { a: deleteUser(id: 1) { ok } b: deleteUser(id: 2) { ok } c: promoteUser(id: 3, role: ADMIN) { ok } }`. Each alias's resolver runs; asymmetric authz may permit some.
- Query-cost analyzer bypass: cost analyzers assign a cost to fields; low-cost admin fields fired in batch may bypass total-cost budget.

### Persisted-Query BFLA

- **Persisted-query hash mapping**: apps that use `Apollo Persisted Queries` map a SHA-256 hash to a query text. If the persisted-query layer runs before authorization and the cache is unbounded, register a persisted query for an admin mutation, then re-send the hash alone — the auth layer sees only the hash.
- **Automatic Persisted Queries (APQ)**: same shape at Apollo's auto-persisting layer.

### Federation Subgraph Admin-Endpoint Direct Call

Load `idor_novel_deep.md § Novel Stack Authorization Surface — GraphQL Federation` for the `_entities` shape; the BFLA angle is that subgraph endpoints often expose admin mutations that the gateway hides. Direct call to the subgraph reaches them.

## gRPC Function-Level Authz Deep

Base-file gRPC coverage introduces per-RPC metadata. The advanced surface:

### Method-Set Discovery

- Reflection (`grpcurl -plaintext target list`) returns every service; each service's methods (`grpcurl -plaintext target list <service>`) reveals the admin methods.
- Reflection-off ≠ safe: enumerate methods from the client's `.pb.go`/`.js`/`Grpc.d.ts` symbol names; probe by fully-qualified method name.
- Health-check probing: `grpc.health.v1.Health/Check` returns per-service status; enumerating services this way is a lower-noise alternative.
- `.proto` files in the mobile app bundle reveal the full service catalog; extract with `apktool` + `protoc --decode_raw`.

### Method-Level Interceptor Drift

- Some interceptors have per-method exemption lists (`GetHealth`, `Login`); legacy methods sometimes end up on the exemption list.
- **Streaming methods**: unary interceptors don't cover streaming; a streaming admin method may skip the per-message authz. Open a bidi stream and probe.
- **Client-streaming under-auth**: client-streaming methods (`ClientStreamingRPC`) accept many messages before returning; auth on stream open + first message but not per-message is a bypass.
- **Transcoded HTTP vs native gRPC**: `grpc-gateway`/`envoy` transcode HTTP-JSON to gRPC. The HTTP-side authz middleware and the gRPC-side interceptor are separate code paths; test the same admin method both ways.
- **`grpc-timeout` header manipulation**: extreme timeouts may cause the interceptor to skip.
- **`GRPC_ARG_MAX_METADATA_SIZE`**: exceeding max metadata may bypass some interceptors that fail-open on parse errors.

### Metadata-Based Impersonation

- Send `authorization: Bearer <admin-jwt>` alongside `authorization: Bearer <basic-jwt>` — multimap; some implementations pick first, others last.
- `-bin` suffix keys: `authorization-bin` treated as base64 by the interceptor but raw by the method — a differential.
- Custom metadata: `x-role: admin`, `x-impersonate: <victim>` — servers that trust these without validation are direct impersonation.

## WebSocket and SSE Function-Level Authz Deep

Real-time transports frequently authorize at connect but not per-message:

### Handshake-Only Auth Bypass

- Connect with a low-priv session; send admin-scope events after subscribe. If the emit handler doesn't re-authorize, cross-role emit.
- Reconnect drift: WebSocket reconnect re-authorizes; if the client's auth token has rotated (privileges reduced), but the server-side sub-registry retained the original auth context, the reconnected stream runs with stale (higher) privileges.
- SSE endpoints (`Content-Type: text/event-stream`): the auth check runs at connection open; each event's content is decided by the emitter, not per-subscriber authz. Admin-emitted events may leak into lower-privilege subscribers.
- GraphQL subscriptions: subscription resolvers may not enforce the same authz as the query/mutation resolvers of the same field.

### Per-Channel Admin-Event Enumeration

- Wildcard subscribes: MQTT `#`, `+/admin/#`, Redis-Streams `XREADGROUP` with attacker-chosen group.
- Channel name convention: guess `admin.events`, `admin.audit`, `system.alerts`, and subscribe under low-priv session.

## CORS Preflight and Authorization Boundary

CORS preflight (`OPTIONS`) is often not treated with the same authz discipline as the underlying request:

- **Preflight returning 200 with permissive headers**: `Access-Control-Allow-Origin: *` on admin endpoints indicates preflight succeeded; the actual request may still be gated but the preflight leaks the endpoint's existence.
- **Preflight indicating the method is allowed**: `Access-Control-Allow-Methods: DELETE, POST, PUT` — reveals what verbs the endpoint accepts.
- **`Access-Control-Allow-Credentials: true` on admin endpoints**: enables the browser to send credentials cross-origin. If the endpoint doesn't validate the origin, a browser-driven cross-origin BFLA is possible.
- **`OPTIONS` bypass**: some middlewares exempt OPTIONS from auth checks (correctly, per CORS spec); but if the app's OPTIONS handler returns admin metadata (route details, allowed methods) that isn't safe to reveal, the preflight is disclosure.
- **Preflight injection via `Access-Control-Request-Headers`**: request headers on preflight — some apps process them to decide what to allow, which may reveal endpoint structure.

## CSRF-Delivered BFLA

Load `csrf` for the CSRF primitive; the BFLA-adjacent angle is that a BFLA that requires a state change can be delivered under the victim's session via CSRF:

- **Same-site cookie without SameSite=Strict**: a cookie without SameSite=Lax/Strict is deliverable cross-origin. If a BFLA on `POST /admin/refunds` doesn't require CSRF token, an attacker's page forms a POST that fires under the victim admin's session.
- **`SameSite=Lax` with GET-shape BFLA**: `SameSite=Lax` blocks POST but permits GET. A BFLA that also accepts GET (verb-tamper primitive) is deliverable.
- **CSRF token bypass**: apps that check for CSRF token existence but not validity (see the CSRF primitive). If BFLA is coupled with a broken CSRF check, cross-origin delivery becomes trivial.

## Content-Type Handler Drift

The base file introduces content-type drift. Advanced surface:

- **JSON vs form vs multipart with different middleware chains**: `POST /admin/refund` with `application/json` may pass through JSON-body middleware including auth; with `application/x-www-form-urlencoded` may reach a form-parser that skips the same middleware.
- **YAML on a JSON endpoint**: some frameworks accept `application/yaml` alongside JSON on the same endpoint. YAML deserialization may reach a different code path than JSON.
- **XML on legacy endpoints**: `application/xml` reaches SOAP or WCF handlers with different middleware chains.
- **Multipart with alternate field encoding**: `multipart/form-data` with fields in various character encodings — some middlewares don't decode all encodings.
- **`application/protobuf` fallback**: some gRPC-transcoded endpoints accept protobuf directly on the HTTP surface, bypassing the JSON-parsing middleware.

## Idempotency and Retry-Header Abuse

- **`Idempotency-Key` reuse across users**: an idempotency key that echoes back the previous call's response may return an admin-scope response to a low-priv user if the previous call was admin.
- **`Retry-After` gating bypass**: a `429` with `Retry-After` may be silently retried by the client SDK; the retry may reach a different endpoint under a different auth context.
- **`If-Match` write conditional**: `PUT /admin/config` with `If-Match: <known-etag>` — if the app processes the conditional before auth, the ETag comparison itself is an existence oracle.

## Second-Order and Stored BFLA

BFLA delivered through a stored write and a delayed consume:

- **Store a foreign action reference**: `POST /me/scheduled-actions` with `{"action": "delete_user", "target": <foreign>}`. The scheduler runs the action under service context; if it doesn't re-authorize, cross-user delete at scheduled time.
- **Import a role-carrying record**: CSV/JSON import that contains role fields. The importer resolves references under service identity — attacker imports rows that establish elevated roles.
- **Webhook-triggered BFLA**: register a webhook with `payload: {"action":"admin_operation"}` — the webhook handler on the server side may process the payload and invoke the action under service identity.
- **Delayed-execution job**: `POST /admin/jobs` with a scheduled admin action — auth check at create time, execution under service context.

## CDN-Layer Function Authz

Edge-layer authorization decouples from origin:

- **Cloudflare Access-gated admin routes**: Access enforces auth at the edge. A request that reaches the origin bypassing Access (direct-to-origin IP, misconfigured firewall) skips the check.
- **Cloudflare Workers-injected identity headers**: `Cf-Access-Authenticated-User-Email` — origin trusts this header; a direct origin-IP request with a spoofed header impersonates.
- **Vercel middleware**: `middleware.ts` runs at edge; a `matcher` config that misses admin paths yields a gap.
- **CloudFront Functions and Lambda@Edge**: URL-rewrite/auth logic at edge; check whether the origin re-authorizes the rewritten path.
- **Fastly VCL admin protection**: VCL scripts frequently enforce auth. A VCL bypass (direct backend access, VCL config oversight) reaches origin unauthenticated.

## Batch-Endpoint Per-Item Authz Drift

Batch operations often authorize once and iterate without re-authorizing each item:

- **Mixed-role batch**: `POST /admin/bulk-approve` with `[{action: "approve", id: <mine>}, {action: "approve", id: <foreign>}]` — the handler that reads the role once and applies to all items fails per-item scoping.
- **Mixed-action batch**: `[{action: "read"}, {action: "delete"}]` — the action-level authz check may only run for the first item.
- **First-item authz pattern**: the handler authorizes on the first item's action-and-role; the rest inherit.
- **Skip-on-error pattern**: batch handlers that continue on per-item error may silently execute privileged items despite others being denied.

## Testing Methodology Deep — WSTG-ATHZ-02 Canonical

WSTG-ATHZ-02 prescribes the two-user session-swap methodology. The canonical extension:

1. **Register or generate two users with identical privileges** (horizontal). For vertical BFLA, additionally register one lower-privilege user.
2. **Establish and keep two sessions active concurrently** — one per user; parallel session management is key.
3. **For every state-changing request**, swap the session identifier between the tokens and evaluate responses. WSTG verbatim: "an application will be considered vulnerable if the weaker privileged session contains the same data, or indicates successful operations on higher privileged functions."
4. **Enumerate every action the admin role can perform** — the "target set" for the sweep.
5. **Re-fire each action** under each of: admin, basic, unauthenticated. The three-column matrix.
6. **Diff outcomes against the app's documented role capability matrix** — deviation is the finding.
7. **Repeat under alternate transports** (REST, GraphQL, gRPC, WebSocket) — a REST-only finding often has a GraphQL/gRPC sibling.
8. **Repeat under alternate method encodings** (JSON, form, multipart, YAML) — content-type drift may bypass on some encodings.
9. **Persistence test**: after the fix, re-run the sweep. Adjacent endpoints often regress.

## Framework-Specific BFLA Sinks

Grep patterns per framework for missing function-level checks:

### Django/DRF

- Grep `class .*ViewSet` and `class .*View`; each without `permission_classes = [SpecificPermission]` or with `permission_classes = [AllowAny]` is a candidate.
- Function-based views with `@api_view(['POST'])` but no `@permission_classes([...])` decorator.
- Custom permission classes with a bug: `def has_permission(self, request, view): return True` — always-allow.

### Rails

- Grep controllers for `before_action` chains; each controller without `authorize` (Pundit) or role-check is a candidate.
- Skipping filters: `skip_before_action :authenticate_user!` in a controller that inherits from an admin base — attacker unauthenticated access.

### Node/Express

- Grep `router.post|put|patch|delete` and check for auth middleware in the chain.
- `router.use(authMiddleware)` at the top of the router — missing `authMiddleware` on a specific route.

### Nest

- `@UseGuards(AuthGuard)` — auth-only unless combined with role guard.
- `@Roles('admin')` — check `RolesGuard` is registered.
- Class-level `@UseGuards` vs method-level — method-level overrides class-level.

### Spring

- `@PreAuthorize("isAuthenticated()")` — auth-only, no role.
- `@Secured({"ROLE_USER"})` — too permissive for admin endpoints.
- Missing method-security config (`@EnableMethodSecurity` not present); annotations are ignored.

### Laravel

- `middleware('auth')` on route — auth-only.
- Missing `middleware('role:admin')` or `Gate::allows('admin', ...)` in the controller.
- Policies not registered in `AuthServiceProvider::$policies`.

### Go

- Middleware chains in `gorilla/mux`, `chi`, or manual `http.HandlerFunc` wrapping. Each route needs explicit auth wiring.
- Framework doesn't have a decoration model like Django/Rails; audit route-by-route.

## Multi-Tenant Cross-Tenant Admin BFLA

The admin action's tenant scope may not match the caller's tenant:

- **Path-scoped admin**: `POST /admin/tenants/{tenantId}/users` — the path carries the target tenant; the app should cross-check against the token's tenant claim. Missing check = cross-tenant admin.
- **Header-scoped admin**: `X-Tenant-ID: <foreign>` with a role-carrying token. The endpoint reads the header for tenant but the token for role; if roles are cross-tenant-recognized, an admin-in-A becomes admin-in-B.
- **Subdomain-scoped admin**: `admin.tenant-b.app.tld` accessed under a tenant-A token that includes admin role.
- **Impersonation cross-tenant**: `POST /admin/impersonate/{userId}` where `userId` may exist in any tenant. Combine with tenant-selector primitive.

## Header-Trust Advanced

The base file introduces header-trust bypasses. The advanced surface:

- **Layered proxies**: request passes through CDN → WAF → LB → app; each layer may set different identity headers. Contradictory headers reveal which layer's assertion wins.
- **`X-Forwarded-User` from a trusted proxy that's also reachable directly**: if the app trusts `X-Forwarded-User` from any request, a direct-to-origin call with the header spoofs identity.
- **JWT-derived headers from a gateway**: `X-JWT-Sub`, `X-JWT-Roles` — some gateways parse the JWT and inject claims as headers. If the app trusts the headers over the JWT itself, tampering the outer JWT to influence the injected headers is a chain.
- **HTTP/2 pseudo-headers**: `:authority`, `:path`, `:method` are HTTP/2 pseudo-headers. Middleware that reads regular headers may not see the pseudo-header content the app dispatches on.
- **Trailer headers**: HTTP/1.1 chunked-body trailers may carry identity headers that arrive after the middleware has decided.

## Legacy Route Shadowing — Deep

Legacy routes retained for backward compatibility frequently miss the middleware chain added later:

### Version-Prefix Enumeration

- Iterate `/api/v1/*`, `/api/v2/*`, `/api/v3/*`, `/api/mobile/*`, `/api/internal/*`, `/api/legacy/*`, `/api/beta/*` up to `/api/v10/*`. Each version prefix may route to distinct handlers or share handlers under different middleware.
- Framework-specific: Django's URL versioning via `include('api.v1.urls')`, Rails's namespace scoping, Laravel's route groups. Grep the router config for versioning boundaries.
- Some routes carry no version prefix (`/api/admin/*`) but have version-prefix aliases (`/api/v1/admin/*`, `/api/mobile/admin/*`) with different middleware chains.

### Extension-Based Shadowing

- `/admin/users` reaches modern handler; `/admin/users.php` may reach a legacy PHP handler; `/admin/users.aspx` a legacy .NET handler; `/admin/users.jsp` a legacy JSP.
- URL-suffix routing (`RewriteRule ^admin/(.*)\.php$ admin.php?path=$1`) — the rewrite may bypass the middleware that gates the modern route.

### HTTP-Version Shadowing

- HTTP/1.1 vs HTTP/2 routing: some servers route HTTP/1.1 requests through a legacy reverse proxy and HTTP/2 directly to origin, with different middleware.
- Chunked-transfer encoding on HTTP/1.1 vs HTTP/2 framing — may hit different parsers.

### Mobile-Only and Legacy-App Endpoints

- Mobile apps often carry endpoints the web client never emits; decompile the app (jadx, apktool) to enumerate.
- Deprecated endpoints retained for older app versions: check the target's app-version support matrix.

### Case-and-Encoding Shadowing

- Case-insensitive path handling drift: `/Admin/users` may reach a case-normalizing router while `/admin/users` reaches the modern router.
- URL encoding drift: `/%61dmin/users` may bypass string-comparison middleware while resolving to `/admin/users` in the router.
- Double-slash normalization: `/admin//users` may skip middleware that pattern-matches `/admin/*`.

## Blind BFLA and Response-Shape Fingerprinting

When the response is masked, the finding requires inferential confirmation:

### Response-Size Differential

- Admin endpoints tend to return richer responses (more fields, larger bodies). Compare Content-Length between the low-priv probe and the admin ground truth; a size within N bytes of the admin shape is a candidate.
- 403 shapes: `{"error":"forbidden"}` (~25 bytes) vs `{"error":"forbidden","code":"AUTHZ_DENIED","reason":"missing_admin_role"}` (~90 bytes) — the richer 403 leaks the specific reason.

### Header Differential

- **`X-Powered-By`, `X-Request-Id`, `X-Trace-Id`**: some are set before auth, some after — a header present on admin responses but absent on 403 indicates the request reached deeper into the stack, which is a partial-execution BFLA signal.
- **`ETag` presence**: an ETag computed from the resource body may be emitted even on 403 if the auth check runs after body construction.
- **Cache headers**: `Cache-Control`, `Age` — admin endpoints often have distinct cache policy.
- **Rate-limit headers**: `X-Ratelimit-Remaining` per-endpoint tier — admin-tier rate limits may leak endpoint identity.

### Timing-Based Confirmation

- Admin actions take longer than 403 rejections (DB access, business logic). Under moderate load, an admin action takes 10-100ms while a 403-at-middleware takes <5ms. Statistical timing separation confirms the request reached the handler.
- **Cache-vs-origin timing**: an admin action from cache is fast; from origin is slow. Timing differential reveals cache hit even when body is masked.

### Error-Text Shape

- Structured error codes distinguish "not authorized" from "not found" from "invalid input". A 403 with `{"error_code":"AUTHZ_DENIED"}` on one probe and `{"error_code":"RESOURCE_NOT_FOUND"}` on another reveals which resources exist, which is a partial BFLA signal.
- Debug/traceback: verbose errors in staging often leak the stack trace of the auth failure, distinguishing role-check from resource-not-found.

### Side-Channel via Related Endpoints

- Admin actions frequently trigger audit-log emission; a low-priv session that reads its own audit log may see admin actions attributed to it as a signal.
- Notification/webhook side-effects: an admin action may fire a downstream webhook. If the attacker controls a webhook endpoint (Object Rebinding + BFLA), the webhook receipt confirms the action ran.
- Rate-limit budget consumption: admin actions consume from an admin-tier budget; observing budget decrease under a low-priv session confirms the action reached the handler.

## Adversarial Two-Role Session Swap

The base file's WSTG-ATHZ-02 methodology is the canonical baseline. The adversarial extension for evasive apps:

### Sound Ground Truth for BFLA

- **Admin-side capture must precede attacker-side**: capture the admin's successful request under admin session; retain the exact request bytes (headers, body, verb). Any deviation between admin and attacker probes is a discipline error, not a finding.
- **Freshness**: for endpoints with server-side idempotency, capture the admin request right before the attacker probe; a stale capture may fail on server-side dedup.

### Confirming Non-Findings

- **Silent 200-empty**: an admin endpoint that returns 200 with an empty body to a low-priv session may be silent-enforcement rather than BFLA. Compare against admin's response — if admin sees data and low-priv sees empty, silent enforcement is applied. Not a BFLA finding directly but reveals the app's auth-response design.
- **Cached admin-response served to low-priv**: if the response has `X-Cache: HIT`, the app did not authorize this request; the previous admin request's response is being served. Report as cache-layer BFLA distinct from handler-layer BFLA.
- **Auto-scoped 200**: a 200 that returns data-shape but with content limited to the caller's scope. Not BFLA on the endpoint (auth is enforcing scope) — but the endpoint's design may still be a smell.

### Three-Role Matrix

The two-account probe is horizontal (same role, different objects); the three-role probe is vertical (different roles):

- **(unauth, basic, admin) × endpoint matrix**: 3-column output per endpoint. Any admin endpoint with 200 under basic or unauth is BFLA.
- **(basic, premium, admin, superadmin) × endpoint matrix**: 4-column for multi-tier apps. Middleware often correctly gates admin but permits premium-and-above; if a premium-only endpoint responds to basic, that's the finding.

### Volume and Rate-Limit Considerations

- Force-browsing at scale triggers rate limiters. Space with jitter; distribute across identities; use `retry-after` as a signal not a stop condition.
- Load-based state changes: some apps escalate protections under load. A probe at 10k requests/minute may induce protections that mask the finding at the next test cycle.
- Distributed rate-limit shard collision: rate limiters that hash by IP or user-ID with shard collision may block probes as a side-effect.

## Blue-Green Deployment and Rolling-Update BFLA

Deployment mechanics expose transient authorization drift:

- **Blue-green deployment mid-cutover**: a request routed to the new (green) deployment may see updated middleware; a request routed to the old (blue) may see legacy. During the cutover window, force-browse admin endpoints under a low-priv session to see which side responds.
- **Rolling update mid-progress**: pods updating one at a time — some pods run the fixed image, others don't. Repeated requests may hit either, depending on load-balancer sticky-session config.
- **Canary deployment routing**: 5% of traffic to canary. A probe repeated 100 times will hit canary ~5 times; a BFLA that regressed in canary is intermittently exposed.
- **Feature-flag rollout with cache**: a flag change takes time to propagate through the SDK cache; a probe during the propagation window may see stale flag state.

## Cross-Region and Multi-Region Admin Endpoint Reachability

Globally-deployed apps expose per-region admin surfaces:

- **Region-scoped admin**: `admin.us-east-1.app.tld` vs `admin.eu-west-1.app.tld` — each region's admin console may have its own auth config. Probe each region.
- **Region-selector header**: `X-Region: eu-west-1` — the caller selects the region. If the region-specific admin config is more permissive, cross-region admin.
- **Failover-time authz drift**: during region failover, the standby may run stale auth config for minutes. Findings under failover may not reproduce steady-state.
- **Data-residency-based admin scope**: some apps restrict admin actions to data in the caller's residency. Cross-residency admin (a US admin acting on EU data) may be enforced only via IP-allowlist rather than tenant.
- **Multi-region JWT `aud`**: JWT issued in region A may include `aud: region-a-services`; a JWT presented to region B that's not audience-checked crosses regions.

## Session-Store BFLA

The session store is a shared resource; the store's key is the identifier:

### Cross-Session Attribute Injection

- **`role` attribute stored in server-side session**: some apps store the user's role in the session record and read it per-request. If the session-modification endpoint (e.g. `POST /session/update`) accepts a `role` field, the caller sets their own role.
- **Session-transfer**: log in as admin in browser A; log in as basic in browser B; if the session store keys by session-ID and both sessions become active, a request from B carrying A's session-ID reaches admin context.
- **Cross-device session leak**: a session ID leaked between devices (via clipboard, shared computer, log copy) grants access to any device with the ID.

### Session-Fixation for Role Escalation

- If the app accepts a client-supplied session ID at login (session fixation), an attacker can fix a session, wait for the admin to log in under that session ID, and inherit the admin's role.

### Refresh-Token BFLA-Adjacent

- Refresh tokens with claims: some refresh tokens carry `role` and `scope`. A refresh that issues a new access token from a refresh with elevated claims perpetuates the elevated access.

## Multi-Session Per-User Authorization Drift

Some apps permit multiple concurrent sessions per user; each session's authz state may drift:

- **Log in on device A, upgrade to admin, log in on device B**: device B's session may not reflect the admin upgrade until refresh. If device B's cached authz state permits admin actions but device A's refresh-forced-logout doesn't invalidate device B, device B holds admin persistently.
- **Session downgrade race**: admin role revoked, but active sessions keep the cached role until their next re-check. Test the re-check cadence.
- **Cross-session shared state**: if authz state is per-user (not per-session), any modification on session A applies to session B — including malicious downgrades or elevations.

## Chaining Depth

Beyond the base-file worked examples, advanced compositions:

### Chain A: JWT-Forgery + BFLA Full-Admin Sweep

1. **Preconditions**: target uses a JWT with `alg: HS256` and the signing key is derivable (via `kid` header manipulation or algorithm confusion).
2. Forge a JWT with `role: admin`, `permissions: ["admin:*"]`. Load `authentication_jwt` for the forgery primitive.
3. Sweep every admin endpoint discovered via force-browsing. Each 2xx response is a separate BFLA finding.
4. **Postcondition**: attacker holds admin-shaped session; every admin endpoint that trusts the forged token is a distinct finding.

### Chain B: X-Original-URL + Method-Override + Impersonate

1. **Preconditions**: target uses a reverse proxy that honors X-Original-URL.
2. Send `GET /public/status` with `X-Original-URL: /admin/impersonate/{victim-user-id}` and `X-Original-Method: POST`.
3. The proxy authorizes `/public/status`; the app dispatches to the impersonate handler with the victim's ID.
4. The impersonate handler grants a session as the victim (if the impersonate endpoint doesn't re-check the caller's role — many don't, on the assumption the front-end already gated).
5. **Postcondition**: attacker holds session as victim; all subsequent actions carry victim's identity.

### Chain C: Feature-Flag Toggle + Admin-Console Reach + BFLA

1. **Preconditions**: attacker has a low-priv account; the admin console is feature-flag-gated.
2. `POST /me/preferences` with `{"beta_admin_console": true}` — self-service flag toggle.
3. Refresh session; admin console UI is now visible.
4. Force-browse `/admin/*` under the newly-toggled flag session; endpoints gated on flag existence are now reachable.
5. **Postcondition**: attacker has access to the admin console's endpoints under the toggled flag context; each admin endpoint is a distinct BFLA finding.

### Chain D: Mass-Assignment Self-Promotion + Downstream BFLA

1. **Preconditions**: target has a self-registration or profile-update endpoint that mass-assigns fields.
2. Register or update profile with `{"is_admin": true, "role": "admin"}`. Load `mass_assignment` for the write primitive.
3. Every subsequent admin endpoint under the promoted session succeeds.
4. **Postcondition**: attacker is admin; the BFLA is now the sweep of every admin endpoint under the promoted role — each is a distinct finding.

### Chain E: Legacy Route Discovery + BFLA on Legacy Middleware

1. **Preconditions**: target has both `/api/v1/*` and `/api/v2/*`; v2 has updated middleware but v1 retains the old chain.
2. Force-browse `/api/v1/admin/*` under a low-priv session; v1 legacy routes may skip the v2-added role check.
3. Any 2xx response is BFLA against v1.
4. **Postcondition**: attacker reaches admin actions via the legacy path even though v2 has been patched.

Each chain requires per-hop confirmation.

## Confirmation Methodology — BFLA-Specific

The base file introduces the three-part confirmation. Advanced discipline:

### Distinguishing State-Change from Read-Only BFLA

- **Read-only BFLA** (admin `/audit-logs` visible to basic users): confirmation is the disclosure itself. No state change required.
- **State-change BFLA** (admin `/refund` under basic user): confirmation requires the state change actually landed. Read the state under the target's identity or query the DB directly.
- **Silent-execution BFLA**: `202 Accepted` for an async admin action — the action queues but hasn't fired. Wait for the async completion; verify state change or lack thereof.

### Cross-Transport Verification

An admin endpoint accessible under a low-priv role via REST may or may not be accessible via GraphQL/gRPC of the same action. Test all transports; report each transport as a separate finding (the fix may only cover REST).

### Time-of-Day and Configuration-Dependent BFLA

Some BFLA findings only fire under specific config (feature flag on, staging environment, admin console explicitly enabled). Document the exact condition; the fix must cover that condition.

## Anti-Automation and WAF Bypass for BFLA Probing

Function-level probes at scale trigger WAFs:

- **Positive-model WAFs**: allow only known good; force-browsing raises noise. Craft probes with syntactic siblings of legitimate requests.
- **Rate-limit and IP block**: authz probes trigger rate limiters. Distribute across identities and IPs.
- **Behavioral fingerprinting**: WAF profiles request-shape; vary between probe batches.
- **CAPTCHA on 403**: some WAFs demand CAPTCHA on repeated 403 responses. Solve or work around.
- **Response-shape uniformity**: some WAFs replace 403 responses with a generic error; the shape may still leak (differential Content-Length, ETag, timing).

## Tooling — Advanced Modes

- **Autorize interceptor rules**: configure scope filters to skip static/CSS/JS. Use the "unauthenticated" replay column for admin-endpoints-callable-without-auth cases.
- **AuthMatrix DSL**: define per-endpoint expected access as a matrix. Better than Autorize for role-heavy apps with structured role hierarchy.
- **`ffuf` with per-role runs and diff**: as shown in the base file's concrete probe scripts. Persist runs; diff between roles.
- **`param miner`** (Burp): hidden-parameter discovery — surface `?admin=1`, `?debug=1`, `?impersonate=<uid>`, `?_method=DELETE`.
- **BurpSuite_403Bypasser**: the header-and-normalization sweep. Run against every 403-returning admin endpoint.
- **JWT_Tool** (`https://github.com/ticarpi/jwt_tool`): JWT tampering; combine with BFLA sweep after forging.
- **`nuclei`** with authz templates: templated authz probes via variable substitution. Scale a specific probe across a large target catalog.
- **`grep`/`rg` for source review**:
  ```
  rg -tp '@PreAuthorize|@Secured|@RolesAllowed|permission_classes|@Roles|middleware\("role|Gate::allows'
  ```
  Cross-reference against the route table.

## False Positives — Advanced

- **CORS OPTIONS success**: OPTIONS preflight returning 200 with `Access-Control-Allow-Methods: POST` for an admin endpoint is a preflight response, not authorization. The actual POST may still be gated.
- **Cached 200 from a previous authorized request**: if the response has `X-Cache: HIT`, the app didn't actually authorize this request. Re-run with cache-busting.
- **Rate-limit prevented full test**: a 429 blocking the probe may look like a 403; confirm from status-code trending across a period.
- **Response body carries a role-mismatch error**: 200 with `{"error":"Not authorized"}` is silent enforcement, not BFLA. Read the body, not just the status code.
- **Staging environment leak**: an admin endpoint reachable in staging but gated in production. Confirm the target is production.
- **Endpoint intentionally open with policy**: some endpoints are documented as "any authenticated user can invoke" (e.g., `/api/notifications/preferences`). Verify against the app's documented role capability matrix.

## Validation Depth

Beyond the base file:

- **Regression scope after fix**: re-run the entire role-matrix probe. A fix on one endpoint often misses siblings.
- **Adjacent-endpoint sweep**: for every confirmed BFLA, probe adjacent endpoints (sibling actions on the same resource, alternate methods, alternate transports).
- **Fix-verification methodology**: after fix, confirm (a) the specific request is now denied, (b) the fix pattern generalized to sibling routes, (c) legacy routes and alternate transports do not regress the class.
- **Audit log verification**: some fixes add logging without adding enforcement. Confirm the fix actually denies, not just logs.
- **Report generation**: for chained findings, include the precondition/postcondition graph and per-hop evidence.

## Post-Fix Adjacent-Bug Prediction

The most productive audit lens is "what did this fix change, and where else does the same shape live?" When a fix adds a role check, the class of the fix predicts the sibling bugs:

- **A `@PreAuthorize` added to one controller method**: grep for every other method in the same controller lacking the annotation.
- **A middleware added to one route file**: check every other route file for missing middleware.
- **A permission-class added to one Django View**: grep every other View for missing `permission_classes` or `AllowAny`.
- **A guard added to one Nest handler**: check every other handler in the same module.
- **A role check added to one GraphQL resolver**: audit every resolver in the same schema module.

Grep patterns after a fix ships:

```
rg 'permission_classes\s*=\s*\[' <path>                     # Django permission decoration
rg '@PreAuthorize|@Secured' <path>                          # Spring role annotation
rg '@UseGuards\(' <path>                                    # Nest guard decoration
rg 'before_action\s*:\s*authorize' <path>                   # Rails before_action
rg 'authorize\("|Gate::allows' <path>                       # Laravel gate calls
rg 'middleware\("role|hasRole' <path>                       # Laravel/Spring role checks
```

Every match without a caller-role-check in the expression is a candidate. Cross-reference against the fixed-CVE mechanism to catch the whole family.

## Rate-of-Change Signals During Engagement

- **Deploy cadence**: apps that deploy frequently frequently regress. If a probed endpoint returns different responses across the engagement window, the endpoint's authz middleware may be actively churning.
- **Feature-flag toggles during engagement**: findings that appear only under specific flag configurations. If a flag is toggled during the engagement, retest.
- **Traffic-based rollout**: canary deployments may return different responses per-request based on the rollout bucket. Set a session-affinity cookie or repeat requests to confirm consistency.
- **A/B tested authz changes**: some apps A/B-test authz-behavior changes; the finding is per-cohort.
- **Emergency rollback windows**: incidents may prompt emergency rollbacks that briefly re-expose fixed BFLA. Note incident timing; retest in a follow-up window.
- **Time-of-day authz drift**: some apps apply distinct authz during business hours (e.g., support tools active). A finding that reproduces only during business hours has narrower impact but is still valid.

## Summary

Advanced BFLA is layered differentials at the function-authz level: verb-tampering variants beyond `_method`, URL-rewrite proxy bypass with normalization drift, forced-browsing at scale using framework-derived wordlists, JWT-claim forgery, impersonation endpoint abuse, and cache/race primitives that collapse function checks against actual state changes.

The confirmation is a role-differential — same request, two roles, one succeeds when it should not — measured across every transport, method, and normalization variant with WSTG-ATHZ-02's two-user session-swap as the canonical methodology.
