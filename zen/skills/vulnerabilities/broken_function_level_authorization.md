---
name: broken-function-level-authorization
description: BFLA testing for function/action-level authorization failures — verb tampering, forced browsing, X-Original-URL/X-Rewrite-URL bypasses, param/role escalation, mass-assignment crossover, two-user session-swap methodology, and admin-endpoint direct invocation
---

# Broken Function Level Authorization (BFLA)

BFLA is the function axis of authorization: callers invoking endpoints, mutations, or admin tools they are not entitled to. It appears when enforcement differs across transports, gateways, roles, or when services trust client hints. Bind subject × action at the service that performs the action.

BFLA and IDOR are **different axes**: BFLA asks *can this principal invoke this action at all* (function-level — a basic user calling an admin endpoint); IDOR asks *which objects can this action touch* (object-level — reaching another user's record). Load `idor` for object-level testing; the highest-impact findings chain both — a privileged action (BFLA) applied to a foreign object id (IDOR). OWASP API Security Top 10 lists BFLA as API5:2023; OWASP Top 10 2025 rolls it under A01:2025 Broken Access Control.

## Attack Surface

- Vertical authz: privileged/admin/staff-only actions reachable by basic users
- Feature gates: toggles enforced at edge/UI, not at core services
- Transport drift: REST vs GraphQL vs gRPC vs WebSocket with inconsistent checks
- Gateway trust: backends trust `X-User-Id`/`X-Role` injected by proxies/edges
- Background workers/jobs performing actions without re-checking authz
- Impersonation endpoints: support-agent impersonate, admin sudo, "act-as" flows
- Legacy/deprecated routes retained for compatibility with different (usually weaker) middleware chains

## High-Value Actions

- Role/permission changes, impersonation/sudo, invite/accept into orgs
- Approve/void/refund/credit issuance, price/plan overrides
- Export/report generation, data deletion, account suspension/reactivation
- Feature flag toggles, quota/grant adjustments, license/seat changes
- Security settings: 2FA reset, email/phone verification overrides
- Audit-log manipulation, security-event acknowledgment
- Tenant-scoped admin actions applied cross-tenant

## Reconnaissance

### Function-Level Endpoint Enumeration

- OpenAPI/Swagger spec (`.well-known/openapi.json`, `/api-docs`, `/swagger.json`) advertises every endpoint the API exposes and often the role required. Endpoints tagged `admin`, `staff`, `internal`, `support`, `backoffice` are the primary BFLA candidates.
- GraphQL introspection returns the full schema; every `Mutation` field, every `admin*` query, every `_internal*` type is a candidate.
- gRPC reflection (`grpc.reflection.v1.ServerReflection`) lists all services and methods; probe with `grpcurl -plaintext target list`.
- Client bundles (mobile APKs, SPA JS chunks) frequently reference endpoints the current user role never invokes — grep for admin/staff/internal path patterns.
- Framework introspection: Django's `admin.site.urls`, Rails's `rails routes`, Laravel's `route:list`, ASP.NET's `/swagger` — each may leak the route table when accessible.

### Forced Browsing

The classical function-level probe: guess admin endpoints by wordlist:

- `ffuf -w common-admin.txt -u https://target/FUZZ -H "Authorization: Bearer <basic-user-jwt>" -mc 200,201,204` — enumerate admin paths under a low-priv token; 2xx responses are direct BFLA candidates.
- Wordlists to prefer: SecLists `Discovery/Web-Content/api/` and `common.txt`; the target's own OpenAPI-derived path list; historical URL archives (web.archive.org, Wayback Machine, `gau`).
- Common admin path prefixes: `/admin`, `/staff`, `/backoffice`, `/console`, `/api/admin`, `/api/internal`, `/v1/admin`, `/manage`, `/dashboard/admin`, `/_admin`, `/admin.php`, `/admin.aspx`, `/actuator`, `/rails/info`.
- Terminal patterns worth guessing: `/users`, `/orgs`, `/tenants`, `/impersonate`, `/settings`, `/config`, `/refunds`, `/audit`, `/exports`, `/webhooks`, `/api-keys`, `/tokens`.

### Signals

- 401/403 on UI but 200 via direct API call; differing status codes across transports
- Actions succeed via background jobs when direct call is denied
- Changing only headers (role/org) alters access without token change
- The UI hides a button for a role but the endpoint is reachable directly
- OpenAPI spec declares an endpoint but the current session's role should not have access — spec is a candidate list
- Client bundle references an endpoint the current role never invokes — often means the endpoint is used by an admin console and forgotten to be gated at the API layer
- Response includes fields like `is_admin`, `can_impersonate`, `role_permissions` in error responses — the response builder ran before the auth check
- Rate-limit headers differ per-endpoint tier — sometimes admin endpoints have separate quotas; hitting the admin quota from a low-priv session confirms the endpoint accepted the request
- `X-Ratelimit-Limit: 1000` on a supposedly-admin endpoint served to a basic user is a signal that the endpoint recognized the caller as admin-tier
- `Access-Control-Allow-Origin` set on admin endpoints — the CORS preflight succeeds, indicating the OPTIONS handler doesn't enforce role gating (only GET/POST may)

### Post-Fix Regression Signals

Function-level fixes frequently regress in adjacent code paths. Signals that a fix may not have generalized:

- The fix landed on one specific method (`DELETE`) but not others (`PATCH`, `PUT`) of the same endpoint.
- The fix landed on the REST route but not the GraphQL mutation or gRPC method of the same action.
- The fix landed on the v2 API but v1 still routes to the same handler without the check.
- The fix landed at the gateway middleware but the direct-to-service path (SSRF-reachable) is unchanged.
- A new admin endpoint added post-fix inherits the same missing-middleware pattern the fix corrected — do not assume the fix generalized to new routes.

## Key Vulnerabilities

### HTTP-Method Tampering

The primitive is a mismatch between the middleware's expectation of the request method and the framework's actual dispatch:

- **Alternate verbs**: an endpoint gated for `POST` may accept `GET` and still execute state changes. Probe every state-changing endpoint with `GET`, `HEAD`, `OPTIONS`, `TRACE`, `PROPFIND` and observe.
- **Method-override headers**: `X-HTTP-Method-Override: PATCH`, `X-Method-Override: DELETE`, `X-HTTP-Method: PUT`, `_method=DELETE` query parameter. Middleware that authorizes based on the wire method (`POST`) but the framework dispatches based on the override (`DELETE`) is a bypass.
- **Method spoofing via form body**: Rails and Laravel accept `_method=DELETE` in a POST form body. Some middleware doesn't parse the body and authorizes only on the outer POST.
- **Case sensitivity**: `Method: get` vs `GET` — some routers normalize, others don't.
- **HEAD as GET fallback**: HEAD is often routed to the GET handler; a middleware that only gates GET may pass HEAD through.

### X-Original-URL / X-Rewrite-URL Header Bypass

WSTG-ATHZ-02 documents a canonical function-level bypass class. Some applications support non-standard headers to override the target URL:

```
GET /public/status HTTP/1.1
Host: target.tld
X-Original-URL: /admin/users
Authorization: Bearer <low-priv-token>
```

The reverse proxy or WAF applies access control against the request-line URI (`/public/status`) while the application dispatches on the header value (`/admin/users`). The classic check-time-vs-use-time differential. The class primitives:

- `X-Original-URL: /admin/*` — reaches admin routes past the front-end gate
- `X-Rewrite-URL: /admin/*` — same shape (IIS URL Rewrite convention)
- `X-Forwarded-URI`, `X-Original-URI` — proxy-vendor variants
- `X-Original-Method: DELETE` — combined with method-override for full-primitive
- `X-Override-URL: /admin/users` — some custom middlewares honor this
- Path-parameter smuggling: `/public/status;/admin/users` — matrix parameters (RFC 3986 §3.3) may be parsed differently by proxy and app
- Path normalization drift: `/public/../admin/users`, `/public/./admin/users`, `/public/%2e%2e/admin/users`, `/public\admin\users` — check every normalization variant

The BurpSuite_403Bypasser extension packages these headers as canonical bypass primitives; each unique 2xx/3xx response to a header-swap variant is a candidate.

### Parameter and Role Escalation

Client-side role fields that reach the server:

- **`role` in registration**: `POST /auth/register` with `{"email":"...","password":"...","role":"admin"}` — some apps mass-assign the role directly. Load `mass_assignment` for the write-shape primitive; the BFLA angle is that a self-registered admin bypasses every subsequent role check.
- **`role` in profile update**: `PATCH /me` with `{"role":"admin"}` — same shape at the profile-update endpoint.
- **Role-request endpoints**: `POST /me/request-role` with `{"role":"admin"}` that auto-grants without approval workflow.
- **JWT claim tampering**: forge a JWT with elevated `role`/`permissions`/`groups` claims (requires JWT-side primitive — load `authentication_jwt`).
- **`X-Role` / `X-Permissions` request headers**: some gateways inject roles from JWT; if the client can send a contradictory value and the app trusts it over the token, direct impersonation.
- **Role via URL param**: `?role=admin`, `?as_admin=true`, `?impersonate=true` — dev-flag-style parameters that survived to production.

### Mass-Assignment Crossover

BFLA and mass-assignment overlap when a mutation endpoint over-accepts fields that carry privilege. A `PATCH /me` that accepts an `is_admin` or `role_id` field despite the app's role hierarchy is Object Rebinding at the *permission field* level. Load `mass_assignment` for the field-side primitive; the BFLA angle is the permission field itself.

### Impersonation and Sudo Endpoints

Support-agent impersonation is a first-class function-level surface:

- `POST /admin/impersonate/{userId}` — should require admin role AND scope the target. Missing role check is BFLA; missing target scope is IDOR; both together is the highest-impact chain.
- `POST /me/switch-account/{userId}` — self-service switch-account endpoints for multi-account users often lack cross-account isolation.
- `POST /support/sudo` with `{"user_email":"..."}` — support-tool endpoints that grant a support session as any user by email.
- `Cookie: impersonate_as=<email>` — cookie-based impersonation surface.
- OAuth impersonation via `subject_token` exchange (RFC 8693) — see the token-exchange primitives at `authentication_jwt`.

### Feature-Flag Bypass

Feature flags are often used as an authorization signal — a flag off = feature-disabled:

- Client-side flag check: the SDK reads the flag and hides UI. The backend endpoint is still live; call it directly.
- Flag-check middleware that trusts a client-declared user attribute: `POST /me/set-flag {"flag":"beta_feature","value":true}` — self-service flag toggling.
- Backend endpoints gated on flag existence in a shared config: an attacker who can influence the flag store (via SDK API keys, target user impersonation) enables the feature.
- Percentage-rollout targeting: hash-of-user-id modulo N. An attacker who can control their own user-ID or force rehashing (email change, ID reset) may land in a target bucket.

### GraphQL Function-Level Authz

- Resolver-level checks per mutation/field: do not assume top-level auth covers nested mutations or admin fields. Every `admin*` mutation needs its own resolver-side check.
- Abuse aliases/batching to sneak privileged fields; persisted queries sometimes bypass auth transforms:
  ```graphql
  mutation Promote($id:ID!){
    a: updateUser(id:$id, role: ADMIN){ id role }
  }
  ```
- Admin-only mutations may be introspection-hidden; probe by name-guess (`__resolveType`, `updateUser`, `setRole`, `promoteUser`).
- `@auth(role: "admin")` directives that only decorate the schema — the resolver may not actually enforce.

### gRPC Function-Level Authz

- Method-level auth via interceptors must enforce audience/roles; probe direct gRPC with tokens of lower role.
- Reflection lists services/methods; call admin methods that the gateway hid.

Enumerate and invoke directly — gRPC method authz frequently lives in an interceptor the gateway applies but the backend, reached directly, does not:
```bash
grpcurl -plaintext target:443 list                          # services (server reflection)
grpcurl -plaintext target:443 list admin.AdminService       # methods on a privileged service
grpcurl -plaintext target:443 describe admin.AdminService.DeleteTenant
# call an admin method with a LOW-privilege token in metadata
grpcurl -H "authorization: Bearer <basic-user-jwt>" -d '{"tenant_id":"t1"}' \
  target:443 admin.AdminService.DeleteTenant
```

- **Per-RPC metadata**: auth is carried in gRPC metadata (`authorization`, `x-role`), not the message — strip it, downgrade the token, or inject `x-role: admin` and observe whether the interceptor or the method enforces.
- **Reflection off ≠ safe**: if reflection is disabled, recover the method set from the client's `.proto`/generated stubs (mobile/JS bundles) and call by fully-qualified name anyway.
- **Transcoding drift**: a gRPC-gateway/HTTP-transcoded route and the native gRPC port can enforce differently — test both for the same method.
- **Streaming methods**: authorize per-message, not just at stream open; emit a privileged request mid-stream.

### WebSocket Function-Level Authz

- Handshake-only auth: ensure per-message authorization on privileged events (`admin:impersonate`, `admin:refund`).
- Try emitting privileged actions after joining standard channels.
- GraphQL subscriptions over WebSocket may skip resolver-level checks the HTTP-mutation path enforces.

### Multi-Tenant Function Authz

Actions requiring tenant admin may be enforced only by header/subdomain, not by role:

- Same-token, different-tenant selector: send with `X-Tenant-ID: <foreign-tenant>` and the endpoint may switch tenant while keeping your user role, which may map to admin in the foreign tenant.
- Cross-tenant admin actions: an admin-in-tenant-A endpoint may not check that the target is in tenant A. Chain with the tenant-selector primitive for full-tenant compromise.

### Microservice / Edge-vs-Core Mismatch

Internal RPCs trust upstream checks; reach them through exposed endpoints or SSRF; verify each service re-enforces authz:

- Edge blocks an action but core service RPC accepts it directly.
- Gateway-injected identity headers override token claims; supply conflicting headers to test precedence.
- Message queues consumed by workers under service identity — a message with a foreign action target may be processed under elevated privilege.

### Batch and Background Job BFLA

- Create export/import jobs where creation is allowed but finalize/approve lacks authz; finalize others' jobs.
- Replay webhooks/background tasks endpoints that perform privileged actions without verifying caller.
- Cron/scheduled-task endpoints exposed via management API without role gates.

### Legacy Route Shadowing

- API versions coexist (`/api/v1`, `/api/v2`, `/api/mobile`, `/api/internal`) with different middleware chains — a v2 endpoint gated by a new authorization layer may have a v1 sibling that skips it.
- Backup path variants (`.bak`, `.old`, `~1`, `.php`, `.aspx`, `.jsp`) may bypass filtering.
- Debug/preview routes preserved beyond intent: `/api/dev`, `/api/preview`, `/api/staging`.
- Mobile-only endpoints: mobile clients often carry endpoints the web client never emits; decompile the app or intercept mobile traffic. Mobile-only routes often skip web-added middleware.
- Case sensitivity: `/Admin/users` vs `/admin/users` — reverse proxy may normalize one, app the other.

### Debug, Actuator, and Info Endpoint BFLA

Framework-provided introspection endpoints frequently expose privileged actions:

- **Spring Boot Actuator** (`/actuator/*`): `/actuator/env`, `/actuator/heapdump`, `/actuator/loggers`, `/actuator/gateway/routes`. `/actuator/env` leaks configuration including credentials; `/actuator/heapdump` dumps process memory. `management.endpoints.web.exposure.include=*` exposes all endpoints to any authenticated user.
- **Rails `/rails/info/routes`**: dumps the entire route table including admin paths. `/rails/info/properties` leaks environment.
- **Django `/admin/` and `?debug=1`**: the Django admin UI is a full-privilege console; `DEBUG=True` in production surfaces the debug-error page with full request context and settings.
- **NestJS `/health` variants**: some NestJS apps expose `/health/detailed` including DB connection strings and dependency versions.
- **Prometheus `/metrics`**: labels frequently include user IDs, tenant IDs, endpoint counts — enumeration by label value.
- **`.git`, `.env`, `.DS_Store`**: not BFLA strictly, but the credentials/session tokens leaked from these enable subsequent function-level access.
- **Kubernetes-hosted `/healthz`, `/readyz`, `/livez`**: on some ingresses, forwarded from external directly to the pod — an exposed pod IP reaches these without gateway auth.

### Health-Check and Metrics Endpoint Exposure

- `/health/details` — some healthcheck endpoints return per-service health including versions, connection state, and identity. An unauthenticated `/health/details` reveals the tenant list, active connections, and downstream service state — enumeration of function-level infrastructure.
- `/metrics` with per-user labels: `authz_check{user="alice",role="admin"} 42` reveals user-role mapping.
- `/status` and `/ping` — often lightly authenticated, sometimes exposing deployment IDs, region, feature-flag state.

### Per-Tenant Admin Function BFLA

Multi-tenant apps often scope admin actions per tenant; the primitive is cross-tenant admin invocation:

- `POST /admin/tenants/{tenantId}/users` under a token issued for a different tenant — some apps read the path's `tenantId` and never cross-check the token's tenant claim.
- `X-Tenant-ID: <foreign>` header combined with a role-carrying token — if the endpoint's role check passes but tenant scoping is only via the selector, cross-tenant admin.
- `POST /admin/impersonate/{userId}` where `userId` may exist in any tenant — if the impersonate endpoint doesn't restrict targets to the caller's tenant, cross-tenant impersonation is trivially IDOR-shaped.

### Audit-Log and Security-Event Manipulation

- `DELETE /admin/audit-logs/{id}` — logs are typically append-only; a delete endpoint (if present) is a repudiation primitive.
- `POST /admin/audit-logs/{id}/ack` — acknowledging security events under a lower role hides them from operator queues.
- `PATCH /admin/audit-logs/{id}` — mutating log content is repudiation-shape.
- `POST /admin/audit-logs/purge` — bulk purge of logs before a specific timestamp.

Log-manipulation BFLA is often subject to more scrutiny than read-side BFLA; if present in the target, it's usually a critical-severity finding regardless of the specific action authorized.

## Bypass Techniques

### Header Trust and Injection

- Supply `X-User-Id`/`X-Role`/`X-Organization` headers; remove or contradict token claims; observe which source wins.
- `X-Original-URL`/`X-Rewrite-URL` per WSTG-ATHZ-02 above.
- `X-Custom-IP-Authorization: 127.0.0.1` — some apps trust an app-layer IP claim for IP-allowlist admin endpoints.
- `X-Forwarded-For: 127.0.0.1` for IP-gated admin routes.

### Content-Type and Body-Format Drift

JSON vs form vs multipart handlers using different middleware: send the action via the most permissive parser. A `POST /admin/*` gated at JSON may accept `application/x-www-form-urlencoded` with a different authz path.

### Idempotency-Key and Retry Abuse

Retry or replay finalize/approve endpoints that apply state without checking actor on each call. Idempotency-key reuse against a foreign key may return the previous call's result.

### Cache-Layer BFLA

Cached authorization decisions at edge leading to cross-user reuse; test with `Vary` and session swaps. A cached admin-only response served to a lower-privilege user is direct disclosure.

## Detection Signals

- Autorize/AuthMatrix flags admin endpoints as `Bypassed!` under a low-priv session
- The UI hides a button but Chrome DevTools reveals a live event listener wired to `/admin/*`
- The OpenAPI spec declares an endpoint tagged `admin` under a permission the current session does not carry
- `403 Forbidden` from the gateway on `/admin/users` but `200 OK` on `/admin/users?_method=DELETE` — verb-tamper primitive
- Response headers show `X-Cache: HIT` on an admin-scoped endpoint under a non-admin session
- gRPC reflection lists admin methods; direct invocation returns data or state change

## Chaining

**Upstream — preconditions granted by other primitives:**

- `authentication_jwt` → *any authenticated session*: BFLA needs at least one authenticated identity to probe from.
- `ssrf` → *internal-only admin endpoint reachability*: some admin endpoints are unreachable except from internal IPs; SSRF surfaces them.
- `mass_assignment` → *self-promoted role*: a mass-assignment on registration or profile-update that grants admin claims transforms into BFLA-bypass (attacker is now admin).
- `information_disclosure` → *endpoint discovery*: leaked API docs, admin URLs, or client bundle references surface the endpoint set.

**Downstream — capabilities granted by BFLA:**

- BFLA on impersonate → `authentication_jwt`: obtaining a session as any user via impersonate.
- BFLA on role/permission mutation → any downstream primitive at admin privilege.
- BFLA on audit-log deletion → repudiation of subsequent attacks.
- BFLA + IDOR → highest-impact composition: privileged action applied to foreign object. Load `idor`.
- BFLA on refund/approve → direct financial impact.
- BFLA on webhook/callback registration → `ssrf` / `open_redirect` at admin privilege.
- BFLA on tenant admin → cross-tenant admin.

**Composite chains — worked examples:**

- **Force-browse + method-tamper = admin delete**: force-browse discovers `/admin/users/{id}`; `GET` returns 403; `DELETE` also 403; `_method=DELETE` in a POST form body reaches the delete handler and executes. The middleware gated on POST but the framework dispatched on the `_method` override.
- **Mass-assignment self-promotion → subsequent BFLA**: register with `{"email":"...","password":"...","is_admin":true}`; the field is mass-assigned; every subsequent admin endpoint accepts the new role. Load `mass_assignment` for the write-side; the BFLA angle is that all subsequent function-level checks pass under the elevated role.
- **X-Original-URL + admin impersonate + IDOR**: send `GET /public/status` with `X-Original-URL: /admin/impersonate/{victim-user-id}` and a low-priv token. The gateway authorizes `/public/status`; the app dispatches to the impersonate handler with the victim's ID; the impersonate handler grants a session as the victim. Three primitives compounded.
- **JWT `role` claim tampering + admin endpoint**: token with `alg: none` (or with `kid` header manipulation) minted with `role: admin`; every admin endpoint accepts the forged token. Load `authentication_jwt` for the JWT primitive; the BFLA angle is the specific admin endpoints reachable under the forged role.
- **Feature-flag toggle + gated admin action**: `POST /me/set-flag {"flag":"admin_console","value":true}` under a self-service flag toggle; the flag-gated admin console is now client-visible and its backend endpoints accept the user under the flag context.
- **Legacy-route BFLA + audit-log manipulation**: `POST /api/v1/admin/audit-logs/{id}/delete` where the v1 middleware doesn't enforce audit-log-write permission but the v2 sibling does. Delete a target's log entry to repudiate a subsequent attack.

## Confirmation Methodology

A BFLA finding needs three-part evidence:

1. **Action succeeded under the wrong role**: the response status indicates success (2xx). For write endpoints, a 202 or 204 with an empty body may still be a state change — always verify with a subsequent read.
2. **Durable state change (for write actions)**: read the target's state under the target's identity or (with permission) query the underlying DB. Screenshot before/after. An app-layer artifact that resets on session refresh is not a durable finding.
3. **Confirmation of correct role gating**: repeat the request under a role that *should* have permission and confirm success; repeat under a role that *should not* and confirm failure. This distinguishes "the endpoint is broken for all roles" (a different bug) from "the endpoint is broken for this specific role" (BFLA).

For read-only BFLA (e.g., an admin `/audit-logs` visible to basic users), state change doesn't apply; the disclosure is the finding.

## Framework-Specific Function-Level Patterns

Each framework has a distinct place where function-level authz is expressed; grep the codebase there first:

- **Django/DRF**: `permission_classes = [IsAdminUser]` — decorator on view or method. Missing decorator on a view that mutates state is a candidate. Grep `class .*ViewSet` and `class .*View` for missing `permission_classes` or `permission_classes = [AllowAny]`.
- **Rails**: `before_action :authorize_admin` or `authorize_by_role(:admin)` (Pundit/CanCanCan). Grep controllers for `authorize` calls and cross-reference against the actions that mutate state.
- **Node/Express**: `router.post('/admin/users', requireAdmin, handler)`. Missing `requireAdmin` middleware is direct BFLA.
- **Nest**: `@Roles('admin')` decorator + `RolesGuard`. If the guard is not registered globally, per-endpoint decoration is required.
- **Spring**: `@PreAuthorize("hasRole('ADMIN')")` on the controller method. `@Secured({"ROLE_ADMIN"})` is equivalent. Missing annotation is a candidate.
- **Laravel**: `middleware('role:admin')` on the route or `$this->authorize('update', $model)` in the controller. Missing gate/policy call is a candidate.
- **Go**: middleware stacks explicitly wired per route; grep the router config for auth middleware application.
- **ASP.NET Core**: `[Authorize(Roles = "Admin")]` attribute. `[AllowAnonymous]` on a specific action overrides.

Cross-reference the auth middleware map against the route map; every endpoint that mutates state but has no role annotation is a BFLA candidate.

## Testing Methodology

The canonical BFLA probe is WSTG-ATHZ-02's two-user session-swap:

1. **Actor × Action matrix** — Unauth, basic, premium, staff/admin, superadmin; enumerate actions per role. Sources: OpenAPI spec, GraphQL introspection, gRPC reflection, admin UI walk-through.
2. **Obtain tokens/sessions** — For each role. Keep sessions concurrent (WSTG-ATHZ-02 explicit: "establish and keep two different sessions active, one for each user").
3. **Direct-invocation baseline** — Log in as the highest role; capture the full request set. Under a lower-privilege session, replay each request and observe: `Bypassed!` (200/201) is the finding; `Enforced` (401/403) is the baseline.
4. **Session-token swap** — For each request, swap the session identifier from the high-role token to the low-role token. WSTG-ATHZ-02 canonical: "for every request, change the session identifier from the original to another role's session identifier and evaluate the responses."
5. **Transport variation** — Repeat under REST, GraphQL, gRPC, WebSocket. A `/admin/users` REST endpoint gated at the gateway may have an unguarded GraphQL `adminUsers` query.
6. **Header/body variation** — Each request re-fired with method-override headers, X-Original-URL, contradictory identity headers, alternate content-types.
7. **Verify against role matrix** — the outcome table should match the app's documented role capability matrix; any cell that deviates is the finding.

## Validation

The canonical anchor for BFLA validation is ASVS 5.0 V8.2.1 (L1) — "the application ensures that function-level access is restricted to consumers with explicit permissions." A finding shape: "the request $R$ (method=X, path=Y, headers=H) under principal $A$ (role=r) succeeds; the app's role matrix declares role $r$ has no permission to invoke $Y$; the endpoint violates V8.2.1." V8.1.1 (L1, documentation prerequisite) and V8.3.1 (L1, trusted-service-layer) apply as well when the documentation is missing or the check is client-side. See `idor_novel_deep.md § ASVS 5.0 V8 — Canonical Authorization Mapping` for the full V8 table.

1. Show a lower-privileged principal successfully invokes a restricted action (same inputs) while the proper role succeeds and another lower role fails.
2. Provide evidence across at least two transports or encodings demonstrating inconsistent enforcement.
3. Demonstrate that removing/altering client-side gates (buttons/flags) does not affect backend success.
4. Include durable state change proof: before/after snapshots, audit logs, and authoritative sources.

## False Positives

- Read-only endpoints mislabeled as admin but publicly documented.
- Feature toggles intentionally open to all roles for preview/beta with clear policy.
- Simulated environments where admin endpoints are stubbed with no side effects.
- 2xx-empty responses on foreign admin actions — silent enforcement, not the finding; confirm state change or lack thereof.
- Response includes only public/generic content — verify the action actually mutated backend state.

## Impact

- Privilege escalation to admin/staff actions
- Monetary/state impact: refunds/credits/approvals without authorization
- Tenant-wide configuration changes, impersonation, or data deletion
- Compliance and audit violations due to bypassed approval workflows
- The impact scales with the enumerable set of privileged actions the BFLA class covers, not the single demonstrated action

## Pro Tips

1. Start from the role matrix; test every action with basic vs admin tokens across REST/GraphQL/gRPC.
   The matrix is the audit deliverable; individual findings are cells that deviate from the expected matrix.
2. Diff middleware stacks between routes; weak chains often exist on legacy or alternate encodings.
   Version-alternate paths (`/v1` vs `/v2`) and method-override toggles are frequent regression sources.
3. Inspect gateways for identity header injection; never trust client-provided identity.
   Test with contradictory headers under a valid token; the app's precedence is the signal.
4. Treat jobs/webhooks as first-class: finalize/approve must re-check the actor.
   Async consumers run under service identity by default and often skip the caller-role check entirely.
5. Prefer minimal PoCs: one request that flips a privileged field or invokes an admin method with a basic token.
   The reader wants to see the differential, not the whole workflow — a one-line curl is the strongest PoC shape.
6. Force-browse every prefix (`/admin`, `/api/admin`, `/api/v1/admin`, `/staff`, `/backoffice`, `/_admin`).
   The OpenAPI spec and client bundle are your prior on likely paths; a wordlist derived from the target's own surface beats a generic list.
7. Every state-changing endpoint gets a method-tamper probe.
   `_method=DELETE`, `X-HTTP-Method-Override`, and verb-swap variants are the primary bypasses; TRACE, PROPFIND, MKCOL are the rarer ones worth checking.
8. WSTG-ATHZ-02's X-Original-URL/X-Rewrite-URL is a canonical function-level bypass class — always test.
   Combine with method-override for the full primitive; test both header variants regardless of the proxy shipping documented behavior for only one.
9. Chain BFLA with IDOR for maximum impact: admin action on foreign object.
   The BFLA alone is often mitigated at the role layer; the IDOR-chained variant reaches the durable-finding depth.
10. Never accept "the button is hidden" as authorization; the endpoint is still there.
    A missing button is a UX-layer control, not a security control — always probe the underlying endpoint directly.
11. Framework introspection endpoints (`/actuator`, `/rails/info`, `/admin/`, `/_debug`) are the first-round force-browse targets.
    They are configured by default; a production instance forgetting to gate them is common enough to expect.
12. Test admin endpoints under an unauthenticated session — some apps have "internal" endpoints that skip auth entirely on the assumption they're not internet-reachable.
    The internet-reachable version is the finding.

## Concrete Probe Scripts

For a discovered admin endpoint, the following scripts are the canonical probes:

**Method-tampering matrix (bash + curl):**

```bash
for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE PROPFIND; do
    echo "=== $METHOD ==="
    curl -sI -X "$METHOD" \
        -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
        "https://target/admin/users/{id}" | head -1
done
```

Any 2xx/3xx response is a method-tamper candidate. `OPTIONS` returning `Allow: GET, POST, PUT, DELETE` reveals the endpoint's declared method set.

**X-Original-URL / X-Rewrite-URL sweep:**

```bash
for header in "X-Original-URL" "X-Rewrite-URL" "X-Original-URI" "X-Forwarded-URI" "X-Override-URL"; do
    echo "=== $header ==="
    curl -s -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
        -H "$header: /admin/users" \
        "https://target/public/status" | head -20
done
```

A response that contains admin content (user list, tenant data) is the finding.

**Forced-browsing with per-role diff:**

```bash
ffuf -w admin-paths.txt -u https://target/FUZZ \
    -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
    -mc 200,201,202,204 -fs 0 -o low-priv.json

ffuf -w admin-paths.txt -u https://target/FUZZ \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -mc 200,201,202,204 -fs 0 -o admin.json

# Compare: any path 2xx under low-priv is a BFLA candidate
diff <(jq -r '.results[].url' low-priv.json | sort) \
     <(jq -r '.results[].url' admin.json | sort)
```

**Session-swap harness (per WSTG-ATHZ-02):**

```python
import httpx, itertools

roles = {"unauth": None, "basic": BASIC_TOKEN, "premium": PREMIUM_TOKEN, "admin": ADMIN_TOKEN}
endpoints = [(method, path) for ...]  # from OpenAPI/GraphQL/gRPC introspection

for (role_name, token), (method, path) in itertools.product(roles.items(), endpoints):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = httpx.request(method, f"https://target{path}", headers=headers)
    print(f"{role_name:8} {method:6} {path:40} → {r.status_code}")
```

The output is the role × endpoint matrix; any cell that grants access to a role that should be denied is the finding. Cross-check against the app's documented role capability matrix.

## Tooling

Same replay tools as IDOR, but configured for the **role** differential rather than the object differential:

- **Autorize** (Burp) — browse as **admin** with the *low-privilege* role's token/cookie pasted into its config; every admin action you click is replayed with the basic-user creds and labeled `Bypassed!` / `Enforced`. Where IDOR usage swaps a same-role *user*, BFLA usage swaps to a *lower role* (and an unauthenticated column) to catch admin functions callable by basic users.
- **Auth Analyzer** (Burp) — multiple named role sessions at once (admin, user, unauth) with per-response token extraction; best for a full role matrix in one pass.
- **AuthMatrix** (Burp) — table-shaped role/endpoint matrix; declare expected accessible/denied cells, and any deviation is the finding. Better than Autorize for role-heavy apps with structured role hierarchy.
- **grpcurl** — enumerate and invoke gRPC admin methods directly (above).
- **BurpSuite_403Bypasser** (extension) — packages the X-Original-URL/X-Rewrite-URL header set and other 403-bypass variants; run against every 403-returning admin endpoint.
- **ffuf / gobuster / dirb** — forced-browsing wordlists against admin-path prefixes.
- **Param miner** (Burp) — hidden-parameter discovery to surface `?admin=1`, `?debug=1`, `?impersonate=<uid>`.
- **Scripted role matrix** — for APIs, replay each discovered `METHOD path` (from OpenAPI/Swagger, the client bundle, or a crawl) with each role's token and diff the status/body; a `200` under a role that should get `403` is the candidate. Load `hurl` for a reviewable version.

Every tool hit is a candidate — confirm with a durable state-change PoC and the role-separated evidence (basic-user succeeds, control shows the proper role is required).

## Reporting

Per-finding minimum evidence:

- The exact request (method, path, headers, body) that succeeded under the wrong role
- The role of the session that fired it
- The expected role required for the action (from the app's documented role matrix or the equivalent-endpoint gate that *did* fire under the correct role)
- The specific ASVS 5.0 V8.x.y control violated (typically V8.2.1 for function-level access; V8.3.1 additionally if the check was client-side)
- Before/after state proof for write actions

For chained findings (BFLA + IDOR, BFLA + mass-assignment), report per-hop evidence separately; the chain-postcondition is the impact summary, but each hop's finding shape must independently support the primitive it claims.

## Summary

BFLA is confirmed by a two-user session-swap: same request, two roles, the lower-role session succeeds where it should have been denied. Cover every action verb across every transport; do not stop at admin URLs — legacy routes, method-override headers, GraphQL mutations, and gRPC admin methods are the sibling surface.

BFLA is the function axis; load `idor` for the object axis and chain both for maximum impact.
