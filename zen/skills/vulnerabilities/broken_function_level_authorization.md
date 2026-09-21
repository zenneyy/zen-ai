---
name: broken-function-level-authorization
description: BFLA testing for action-level authorization failures across endpoints, admin functions, and API operations
---

# Broken Function Level Authorization (BFLA)

BFLA is action-level authorization failure: callers invoke functions (endpoints, mutations, admin tools) they are not entitled to. It appears when enforcement differs across transports, gateways, roles, or when services trust client hints. Bind subject × action at the service that performs the action.

BFLA and IDOR are **different axes**: BFLA asks *can this principal invoke this
action at all* (vertical — a basic user calling an admin endpoint); IDOR asks
*which objects can this action touch* (horizontal — reaching another user's
record). Load `idor` for object-level testing; the highest-impact findings chain
both — a privileged action (BFLA) applied to a foreign object id (IDOR).

## Attack Surface

- Vertical authz: privileged/admin/staff-only actions reachable by basic users
- Feature gates: toggles enforced at edge/UI, not at core services
- Transport drift: REST vs GraphQL vs gRPC vs WebSocket with inconsistent checks
- Gateway trust: backends trust X-User-Id/X-Role injected by proxies/edges
- Background workers/jobs performing actions without re-checking authz

## High-Value Actions

- Role/permission changes, impersonation/sudo, invite/accept into orgs
- Approve/void/refund/credit issuance, price/plan overrides
- Export/report generation, data deletion, account suspension/reactivation
- Feature flag toggles, quota/grant adjustments, license/seat changes
- Security settings: 2FA reset, email/phone verification overrides

## Reconnaissance

### Surface Enumeration

- Admin/staff consoles and APIs, support tools, internal-only endpoints exposed via gateway
- Hidden buttons and disabled UI paths (feature-flagged) mapped to still-live endpoints
- GraphQL schemas: mutations and admin-only fields/types; gRPC service descriptors (reflection)
- Mobile clients often reveal extra endpoints/roles in app bundles or network logs

### Signals

- 401/403 on UI but 200 via direct API call; differing status codes across transports
- Actions succeed via background jobs when direct call is denied
- Changing only headers (role/org) alters access without token change

## Key Vulnerabilities

### Verb Drift and Aliases

- Alternate methods: GET performing state change; POST vs PUT vs PATCH differences; X-HTTP-Method-Override/_method
- Alternate endpoints performing the same action with weaker checks (legacy vs v2, mobile vs web)

### Edge vs Core Mismatch

- Edge blocks an action but core service RPC accepts it directly; call internal service via exposed API route or SSRF
- Gateway-injected identity headers override token claims; supply conflicting headers to test precedence

### Feature Flag Bypass

- Client-checked feature gates; call backend endpoints directly
- Admin-only mutations exposed but hidden in UI; invoke via GraphQL or gRPC tools

### Batch Job Paths

- Create export/import jobs where creation is allowed but finalize/approve lacks authz; finalize others' jobs
- Replay webhooks/background tasks endpoints that perform privileged actions without verifying caller

### Content-Type Paths

- JSON vs form vs multipart handlers using different middleware: send the action via the most permissive parser

## Advanced Techniques

### GraphQL

- Resolver-level checks per mutation/field; do not assume top-level auth covers nested mutations or admin fields
- Abuse aliases/batching to sneak privileged fields; persisted queries sometimes bypass auth transforms

```graphql
mutation Promote($id:ID!){
  a: updateUser(id:$id, role: ADMIN){ id role }
}
```

### gRPC

- Method-level auth via interceptors must enforce audience/roles; probe direct gRPC with tokens of lower role
- Reflection lists services/methods; call admin methods that the gateway hid

Enumerate and invoke directly — gRPC method authz frequently lives in an
interceptor the gateway applies but the backend, reached directly, does not:
```bash
grpcurl -plaintext target:443 list                          # services (server reflection)
grpcurl -plaintext target:443 list admin.AdminService       # methods on a privileged service
grpcurl -plaintext target:443 describe admin.AdminService.DeleteTenant
# call an admin method with a LOW-privilege token in metadata
grpcurl -H "authorization: Bearer <basic-user-jwt>" -d '{"tenant_id":"t1"}' \
  target:443 admin.AdminService.DeleteTenant
```
- **Per-RPC metadata**: auth is carried in gRPC metadata (`authorization`,
  `x-role`), not the message — strip it, downgrade the token, or inject
  `x-role: admin` and observe whether the interceptor or the method enforces.
- **Reflection off ≠ safe**: if reflection is disabled, recover the method set
  from the client's `.proto`/generated stubs (mobile/JS bundles) and call by
  fully-qualified name anyway.
- **Transcoding drift**: a gRPC-gateway/HTTP-transcoded route and the native
  gRPC port can enforce differently — test both for the same method.
- **Streaming methods**: authorize per-message, not just at stream open;
  emit a privileged request mid-stream.

### WebSocket

- Handshake-only auth: ensure per-message authorization on privileged events (e.g., admin:impersonate)
- Try emitting privileged actions after joining standard channels

### Multi-Tenant

- Actions requiring tenant admin enforced only by header/subdomain; attempt cross-tenant admin actions by switching selectors with same token

### Microservices

- Internal RPCs trust upstream checks; reach them through exposed endpoints or SSRF; verify each service re-enforces authz

## Bypass Techniques

### Header Trust

- Supply X-User-Id/X-Role/X-Organization headers; remove or contradict token claims; observe which source wins

### Route Shadowing

- Legacy/alternate routes (e.g., /admin/v1 vs /v2/admin) that skip new middleware chains

### Idempotency and Retries

- Retry or replay finalize/approve endpoints that apply state without checking actor on each call

### Cache Key Confusion

- Cached authorization decisions at edge leading to cross-user reuse; test with Vary and session swaps

## Testing Methodology

1. **Build Actor × Action matrix** - Unauth, basic, premium, staff/admin; enumerate actions per role
2. **Obtain tokens/sessions** - For each role
3. **Exercise every action** - Across all transports and encodings (JSON, form, multipart), including method overrides
4. **Vary headers and selectors** - Org/tenant/project; test behind gateway vs direct-to-service
5. **Include background flows** - Job creation/finalization, webhooks, queues; confirm re-validation

## Validation

1. Show a lower-privileged principal successfully invokes a restricted action (same inputs) while the proper role succeeds and another lower role fails
2. Provide evidence across at least two transports or encodings demonstrating inconsistent enforcement
3. Demonstrate that removing/altering client-side gates (buttons/flags) does not affect backend success
4. Include durable state change proof: before/after snapshots, audit logs, and authoritative sources

## False Positives

- Read-only endpoints mislabeled as admin but publicly documented
- Feature toggles intentionally open to all roles for preview/beta with clear policy
- Simulated environments where admin endpoints are stubbed with no side effects

## Impact

- Privilege escalation to admin/staff actions
- Monetary/state impact: refunds/credits/approvals without authorization
- Tenant-wide configuration changes, impersonation, or data deletion
- Compliance and audit violations due to bypassed approval workflows

## Pro Tips

1. Start from the role matrix; test every action with basic vs admin tokens across REST/GraphQL/gRPC
2. Diff middleware stacks between routes; weak chains often exist on legacy or alternate encodings
3. Inspect gateways for identity header injection; never trust client-provided identity
4. Treat jobs/webhooks as first-class: finalize/approve must re-check the actor
5. Prefer minimal PoCs: one request that flips a privileged field or invokes an admin method with a basic token

## Tooling

Same replay tools as IDOR, but configured for the **role** differential rather
than the object differential:

- **Autorize** (Burp) — browse as **admin** with the *low-privilege* role's
  token/cookie pasted into its config; every admin action you click is replayed
  with the basic-user creds and labeled `Bypassed!` / `Enforced`. Where IDOR
  usage swaps a same-role *user*, BFLA usage swaps to a *lower role* (and an
  unauthenticated column) to catch admin functions callable by basic users.
- **Auth Analyzer** (Burp) — multiple named role sessions at once (admin,
  user, unauth) with per-response token extraction; best for a full role matrix
  in one pass.
- **grpcurl** — enumerate and invoke gRPC admin methods directly (above).
- **Scripted role matrix** — for APIs, replay each discovered `METHOD path`
  (from OpenAPI/Swagger, the client bundle, or a crawl) with each role's token
  and diff the status/body; a `200` under a role that should get `403` is the
  candidate. Load `hurl` for a reviewable version.

Every tool hit is a candidate — confirm with a durable state-change PoC and the
role-separated evidence (basic-user succeeds, control shows the proper role is
required).

## Summary

Authorization must bind the actor to the specific action at the service boundary on every request and message. UI gates, gateways, or prior steps do not substitute for function-level checks.
