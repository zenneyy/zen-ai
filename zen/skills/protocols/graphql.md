---
name: graphql
description: GraphQL security testing covering introspection, resolver injection, batching attacks, and authorization bypass
---

# GraphQL

Security testing for GraphQL APIs. Focus on resolver-level authorization, field/edge access control, batching abuse, and federation trust boundaries.

## Attack Surface

**Operations**
- Queries, mutations, subscriptions
- Persisted queries / Automatic Persisted Queries (APQ)

**Transports**
- HTTP POST/GET with `application/json` or `application/graphql`
- WebSocket: graphql-ws, graphql-transport-ws protocols
- Multipart for file uploads

**Schema Features**
- Introspection (`__schema`, `__type`)
- Directives: `@defer`, `@stream`, custom auth directives (@auth, @private)
- Custom scalars: Upload, JSON, DateTime
- Relay: global node IDs, connections/cursors, interfaces/unions

**Architecture**
- Federation (Apollo, GraphQL Mesh): `_service`, `_entities`
- Gateway vs subgraph authorization boundaries

## Reconnaissance

**Endpoint Discovery**
```
POST /graphql         {"query":"{__typename}"}
POST /api/graphql     {"query":"{__typename}"}
POST /v1/graphql      {"query":"{__typename}"}
POST /gql             {"query":"{__typename}"}
GET  /graphql?query={__typename}
```

Check for GraphiQL/Playground exposure with credentials enabled (cross-origin with cookies can leak data via postMessage bridges).

**Schema Acquisition**

If introspection enabled:
```graphql
{__schema{types{name fields{name args{name}}}}}
```

If disabled, infer schema via:
- `__typename` probes on candidate fields
- Field suggestion errors (submit near-miss names to harvest suggestions)
- "Expected one of" errors revealing enum values
- Type coercion errors exposing field structure
- Error taxonomy: different codes for "unknown field" vs "unauthorized field" reveal existence

**Schema Mapping**

Map: root operations, object types, interfaces/unions, directives, custom scalars. Identify sensitive fields: email, tokens, roles, billing, API keys, admin flags, file URLs. Note cascade paths where child resolvers may skip auth under parent assumptions.

## Key Vulnerabilities

### Authorization Bypass

**Field-Level IDOR**

Test with aliases comparing owned vs foreign objects in single request:
```graphql
query {
  own: order(id:"OWNED_ID") { id total owner { email } }
  foreign: order(id:"FOREIGN_ID") { id total owner { email } }
}
```

**Edge/Child Resolver Gaps**

Parent resolver checks auth, child resolver assumes it's already validated:
```graphql
query {
  user(id:"FOREIGN") {
    id
    privateData { secrets }  # Child may skip auth check
  }
}
```

**Relay Node Resolution**

Decode base64 global IDs, swap type/id pairs:
```graphql
query {
  node(id:"VXNlcjoxMjM=") { ... on User { email } }
}
```
Ensure per-type authorization is enforced inside resolvers. Verify connection filters (owner/tenant) apply before pagination; cursor tampering should not cross ownership boundaries.

**Mutation Bypass**
- Probe mutations for partial updates bypassing validation (JSON Merge Patch semantics)
- Test mutations that accept extra fields passed to downstream logic

This section covers the *resolver-structure* angle (where enforcement lives in
the graph). For the object-level ownership depth — Relay global-ID decode/swap
mechanics, time-based ID prediction, and the two-account differential — load
`idor`; for extra-field writes reaching the model, load `mass_assignment`.

### Batching & Alias Abuse

**Enumeration via Aliases**
```graphql
query {
  u1:user(id:"1"){email}
  u2:user(id:"2"){email}
  u3:user(id:"3"){email}
}
```
Bypasses per-request rate limits; exposes per-field vs per-request auth inconsistencies.

**Array Batching**

If supported (non-standard), submit multiple operations to achieve partial failures and bypass limits.

### Input Manipulation

**Type Confusion**
```
{id: 123}      vs {id: "123"}
{id: [123]}    vs {id: null}
{id: 0}        vs {id: -1}
```

**Duplicate Keys**
```json
{"id": 1, "id": 2}
```
Parser precedence varies; may bypass validation. Also test default argument values.

**Extra Fields**

Send unexpected keys in input objects; backends may pass them to resolvers or downstream logic.

### Cursor Manipulation

Decode cursors (usually base64) to:
- Manipulate offsets/IDs
- Skip filters
- Cross ownership boundaries

### Directive Abuse

**@defer/@stream**
```graphql
query {
  me { id }
  ... @defer { adminPanel { secrets } }
}
```
May return gated data in incremental delivery. Confirm server supports incremental delivery.

**Custom Directives**

@auth, @private and similar directives often annotate intent but do not enforce—verify actual checks in each resolver path.

### Complexity Attacks

**Deep nesting via cyclic type relationships.** A *self-referential fragment*
(`fragment x on User { ...x }`) is **rejected by GraphQL validation** (fragment
spreads must not form cycles), so it is not the DoS. The real depth attack nests
a **cyclic type relationship** as deep as the server allows:
```graphql
query { user(id:"1"){ posts{ author{ posts{ author{ posts{ author{ id }}}}}} } }
```
Each level multiplies resolver work; without a depth limit this exhausts CPU/DB.
Test depth/complexity limits, query-cost analyzers, and timeouts.

**Alias amplification** — the cheapest DoS: repeat one expensive field under
hundreds of aliases in a single (valid) operation, multiplying cost while
staying one request:
```graphql
query { a1:expensiveSearch(q:"*"){id} a2:expensiveSearch(q:"*"){id} ... a500:... }
```
Combine with **batching** (an array of operations) and `@stream`/`@defer` for
further amplification. Introspection itself can be costly — a full `__schema`
walk on a large schema is a mini-DoS.

**Defenses to probe (and confirm actually enforced):**
- **graphql-armor** — `maxDepth`, `maxAliases`, `maxDirectives`, `maxTokens`,
  `costLimit`, and `blockFieldSuggestion` (turns off the field-suggestion oracle
  used for schema inference). Check which are on.
- Apollo/others: operation-complexity/`@cost` plugins, `max_depth`, and a
  **persisted-query allowlist** (only pre-registered operations run) — the
  strongest control; test whether arbitrary ad-hoc queries are still accepted.

**`@oneOf` input objects** — a `@oneOf` input type requires **exactly one**
member field set. Test the invariant: send **zero** fields or **multiple**
fields and see whether the server rejects it or picks a branch (a lax
implementation lets you combine mutually exclusive inputs, reaching unintended
resolver paths).

**Wide Selection Sets**

Abuse selection sets and fragments to force overfetching of sensitive subfields.

### Federation Exploitation

**SDL Exposure**
```graphql
query { _service { sdl } }
```

**Entity Materialization**
```graphql
query {
  _entities(representations:[
    {__typename:"User", id:"TARGET_ID"}
  ]) { ... on User { email roles } }
}
```
Gateway may enforce auth; subgraph resolvers may not. Look for cross-subgraph IDOR via inconsistent ownership checks.

**The federation trust boundary** (technique class — version-fingerprint the
router/gateway, don't assume a CVE):
- **Subgraphs trust the gateway.** Subgraph services typically assume the
  gateway already authenticated/authorized and only trust gateway-injected
  headers. If a subgraph port is **reachable directly** (internal network, SSRF,
  a misconfigured ingress), you query it *bypassing the gateway's auth entirely*
  — spoof the gateway's identity headers (`x-user-id`, `apollo-*`) and read any
  entity. Scan for subgraph ports and hit `_service`/`_entities` there.
- **`_entities` reference-resolver trust** — the gateway synthesizes an entity
  reference (`{__typename, <key>}`) and the subgraph's `__resolveReference`
  returns the object, frequently **without an ownership check** (it assumes the
  gateway validated access). This is the canonical federation IDOR: enumerate
  keys via `_entities` and read cross-tenant data. It is exposed on any subgraph
  you can reach, and sometimes through the gateway if `_entities` isn't blocked.
- **`@key`/`@requires`/`@external`/`@provides`** widen the surface: a `@requires`
  field pulls data from another subgraph; test whether that cross-subgraph fetch
  re-checks authorization. `_service{sdl}` leaks the full federated schema
  (including `@key` fields = the enumerable identifiers).
- Apollo Router/Gateway have had CVEs across releases (query-planning DoS,
  header-forwarding/CORS issues); fingerprint the exact version and match its
  advisory rather than assuming — the trust-boundary bugs above are
  configuration/technique classes independent of any single CVE.

### Subscription Security

- Authorization at handshake only, not per-message
- Subscribe to other users' channels via filter args
- Cross-tenant event leakage
- Abuse filter args in subscription resolvers to reference foreign IDs

Subscriptions run over WebSocket (`graphql-transport-ws` — the modern protocol —
or the legacy `graphql-ws`/`subscriptions-transport-ws`). The auth model is the
gap:
- **Auth is passed in `connection_init` `payload` (`connectionParams`)**, not the
  HTTP `Authorization` header, so the **HTTP auth middleware/guards don't run on
  the WS upgrade** — the app must re-authenticate inside `onConnect`. Test a
  `connection_init` with no/invalid/expired token, and a token for a lower role.
- **Connection-level auth ≠ per-subscription auth.** `onConnect` may authenticate
  the socket once, but each `subscribe` message names a subscription + filter
  args that must be authorized *per subscription* — subscribe to
  `orderUpdates(orgId: <foreign>)` after connecting as yourself.
- **Missing origin check on the upgrade** → cross-site WebSocket hijacking of the
  subscription stream (load `csrf` for CSWSH and `browser_security` for the
  handshake origin semantics).
- **Filter-arg IDOR / broadcast leakage** — the resolver publishes to all
  subscribers matching a topic; if the topic/filter isn't bound to the caller,
  you receive other tenants' events. Confirm you receive events you shouldn't.

### Persisted Query Abuse

- APQ hashes leaked from client bundles
- Replay privileged operations with attacker variables
- Hash bruteforce for common operations
- Validate hash→operation mapping enforces principal and operation allowlists

### CORS & CSRF

- Cookie-auth with GET queries enables CSRF on mutations via query parameters
- GraphiQL/Playground cross-origin with credentials leaks data
- Missing SameSite and origin validation
- The GraphQL-specific vector is a **GET query carrying a mutation** (or a
  `application/x-www-form-urlencoded`/`text/plain` POST that the server parses as
  GraphQL) — no preflight, so a cross-site form/`<img>` fires it. Load `csrf` for
  the general defenses this defeats (the SameSite Lax+POST window, Fetch
  Metadata, double-submit tokens); GraphQL's own guard is to reject mutations
  over GET and non-JSON content-types.

### File Uploads

GraphQL multipart spec:
- Multiple Upload scalars
- Filename/path traversal tricks
- Unexpected content-types, oversize chunks
- Server-side ownership/scoping for returned URLs

## WAF Evasion

**Query Reshaping**
- Comments and block strings (`"""..."""`)
- Unicode escapes
- Alias/fragment indirection
- JSON variables vs inline args
- GET vs POST vs `application/graphql`

**Fragment Splitting**

Split fields across fragments and inline spreads to avoid naive signatures:
```graphql
fragment a on User { email }
fragment b on User { password }
query { me { ...a ...b } }
```

## Bypass Techniques

**Transport Switching**
```
Content-Type: application/json
Content-Type: application/graphql
Content-Type: multipart/form-data
GET with query params
```

**Timing & Rate Limits**
- HTTP/2 multiplexing and connection reuse to widen timing windows
- Batching to bypass rate limits

**Naming Tricks**
- Case/underscore variations
- Unicode homoglyphs (server-dependent)
- Aliases masking sensitive field names

**Cache Confusion**
- CDN caching without Vary on Authorization
- Variable manipulation affecting cache keys
- Redirects and 304/206 behaviors leaking partial responses

## Testing Methodology

1. **Fingerprint** - Identify endpoints, transports, stack (Apollo, Hasura, etc.), GraphiQL exposure
2. **Schema mapping** - Introspection or inference to build complete type graph
3. **Principal matrix** - Collect tokens for unauth, user, premium, admin roles with at least one valid object ID per subject
4. **Field sweep** - Test each resolver with owned vs foreign IDs via aliases in same request
5. **Transport parity** - Verify same auth on HTTP, WebSocket, persisted queries
6. **Federation probe** - Test `_service` and `_entities` for subgraph auth gaps
7. **Edge cases** - Cursors, @defer/@stream, subscriptions, file uploads

## Validation Requirements

- Paired requests (owner vs non-owner) showing unauthorized access
- Resolver-level bypass: parent checks present, child field exposes data
- Transport parity proof: HTTP and WebSocket for same operation
- Federation bypass: `_entities` accessing data without subgraph auth
- Minimal payloads with exact selection sets and variable shapes
- Document exact resolver paths that missed enforcement
