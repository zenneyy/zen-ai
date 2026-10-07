---
name: race-conditions
description: Race-condition testing — single-packet HTTP/2 request alignment, multi-endpoint and partial-construction races, idempotency and dedup bypass classes, atomicity-gap classes across SQL/Redis/distributed locks, and the chaining surface into IDOR, business-logic, and auth.
---

# Race Conditions

Concurrency bugs enable duplicate state changes, quota bypass, financial abuse, and privilege errors. Treat every read-modify-write and every multi-step workflow as adversarially concurrent until proven atomic. The question to answer in every test is not "can parallel requests overlap" (they always can) but "which invariant breaks when they do, and what durable artefact proves it broke?"

## Attack Surface

**Read-modify-write without atomicity**

- `SELECT ... → check → UPDATE` in two statements instead of one `UPDATE ... WHERE predicate`.
- Cache or Redis `GET → compare → SET` without `SETNX`/`WATCH`/Lua-script atomicity.
- In-process counters mutated from more than one worker/thread without a lock.

**Multi-step workflows with observable intermediate state**

- `check → reserve → commit` where a second request can observe the reservation but a third can observe the pre-reservation balance.
- Payment auth → capture → settle; coupon validate → apply → consume.
- File upload init → chunk → finalize; webhook register → verify → activate.

**Cross-service workflows**

- Sagas, event-driven jobs with eventual-consistency windows.
- Retry-with-at-least-once on an endpoint whose consumer is not idempotent.
- Compensation steps that undo part of a workflow but leave side effects (emails sent, credits issued).

**Rate limits and quotas**

- Counters implemented at the edge (CDN, API gateway) only, with the application permitting any volume once past.
- Sharded counters whose shards sync late; windows aligned to shard boundaries pass.
- Rate buckets keyed on IP or session but not on the mutated resource.

## High-Value Targets

- Payments: auth/capture/refund/void; store credit, loyalty points, gift cards.
- Coupons/discounts: single-use codes, stacking checks, per-user limits.
- Quotas/limits: API usage, inventory reservations, seat counts, vote limits.
- Auth flows: password reset consumption, OTP/MFA validation, session minting, device trust.
- File/object storage: multi-part finalize, versioned writes, share-link generation.
- Background jobs: export/import create/finalize endpoints; job cancellation and approve.
- GraphQL mutations and batched operations; WebSocket actions; Server-Sent Event consumers.

## Reconnaissance

### Identify Race Windows

- Look for explicit sequences in logs or source: "check balance then deduct", "verify coupon then apply", "check inventory then purchase", "reset token already used? no → mint session, mark used".
- Watch for optimistic concurrency markers: `ETag`/`If-Match`, `version`/`updated_at` fields, `row_version`.
- Examine idempotency-key support: scope (path vs principal vs resource), TTL, and persistence (cache vs DB).
- Map cross-service steps: *when* is state written vs *when* is it published, what retries/compensations exist, which hop is idempotent and which is not.
- A sync endpoint that returns before a background job finishes writing durable state is a candidate: the response says "done" but the DB write is still inflight.

### Signals

- Sequential request fails but parallel succeeds.
- Duplicate rows, negative counters, over-issuance, inconsistent aggregates.
- Distinct response shapes/timings for simultaneous vs sequential requests.
- Audit logs out of order; multiple 2xx for the same intent; missing or duplicate correlation IDs.
- The response body says "already used" but a side effect (email sent, credit granted) happened anyway.

## Request Synchronization

**The single-packet attack** (James Kettle, Black Hat USA 2023 / DEF CON 31) is the current best HTTP/2 technique: pack 20–30 complete requests into a **single TCP packet** so the server receives them at once and network jitter is eliminated entirely. Each HTTP/2 HEADERS+DATA pair occupies a few hundred bytes; a modern MTU holds enough streams for 20–50 complete requests. The server reads the TCP segment, demultiplexes the H2 streams, and dispatches all of them to worker threads within sub-millisecond slack — far more reliable than last-byte sync.

Over HTTP/1.1, last-byte sync (send all but the final byte of each request, then release the final bytes together on a warmed pool) is the fallback. The tool is **Turbo Intruder** (Burp), set to `Engine.BURP2` for H2 single-packet:

```python
# Turbo Intruder — single-packet race: queue N identical requests, fire as one packet
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                           engine=Engine.BURP2)          # HTTP/2 single-packet
    for i in range(30):
        engine.queue(target.req, gate='race1')           # hold at the gate
    engine.openGate('race1')                             # release all 30 together
```

Burp Repeater also carries this as **"Send group in parallel"** — select a tab group and the Burp HTTP/2 engine fires them in a single packet. Faster to iterate than Turbo Intruder for small groups; use Turbo Intruder once a window is confirmed.

**Measured race-window result** (persisted at `.zen-batch-artifacts/batch-11/measurements/race_counter.py`+`.out`): a single-use coupon starting at `uses=1`, hit by 50 parallel requests on a Python 3.14 FastAPI server with a 5ms work-window inside the critical section, three run shapes side by side:

| Pattern | Granted (per 50) | Final counter |
|---|---|---|
| `uses = uses - 1` after check (assign; multiple writers converge on 0) | 1 – 5 | 0 |
| `uses -= 1` after check (read-at-write; counter can go negative) | 6 – 9 | −5 to −8 |
| Explicit `threading.Lock` wrapping check+write | 1 | 0 |
| Compare-and-swap retry loop | 1 | 0 |
| Single-statement `UPDATE ... WHERE uses > 0` (SQL-side atomic) | 1 | 0 |

What this proves: the race window is *not* a function of request-arrival alignment alone; it is the server-side critical-section shape. Even a sub-millisecond alignment is useless against a correctly atomic update, and even a loose alignment breaks a check-then-act counter. The single-packet attack is a *window-widening* tool; the finding is the critical section itself. The `uses = uses - 1` (ASSIGN) vs `uses -= 1` (DECREMENT) distinction matters — both are bugs, but their outcome differs: ASSIGN caps duplicate grants at the initial value; DECREMENT drives the counter negative and produces runaway over-issuance.

### Connection Warming and Alignment

Not every race is one endpoint hit N times. The *first* request on a fresh connection pays TLS + server-side first-request costs and lands late, desynchronizing the group. Prime a benign endpoint on each connection first so the raced requests all hit an already-warm path. Turbo Intruder's `RequestEngine` reuses warmed connections; add a warm-up request before opening the gate. For single-packet via Burp Repeater, the engine warms transparently.

Watch for a response-order dependency: if two endpoints must arrive in a specific order, tune packet ordering rather than assuming simultaneity. HTTP/2 does not guarantee frame-order of concurrent streams at the server; the stream IDs are ordered but their worker-dispatch is not.

### Race-Window Timing

The exploitable window is bounded by the server-side critical section, not by the client-side alignment. The two timing quantities to measure:

- **Alignment slack** — the time between the earliest and latest request landing at the server. Single-packet achieves <1ms on a modern H2 server; last-byte sync achieves ~4ms; naïve `curl` loops produce ~tens of ms.
- **Critical-section window** — the time between the "check" and the "write" of the vulnerable code path. A pure in-memory read-modify-write is on the order of microseconds; a check that includes a database roundtrip, a cache lookup, or a remote API call extends it to milliseconds; a check with an external authorization call can stretch to hundreds of milliseconds.

Any race requires `alignment_slack < critical_section_window`. If the ratio is marginal, add server load (slow upstream, large payloads) to lengthen the critical section, or add synchronization precision to shrink the slack. Measurement discipline: pair every alleged "race" with a timing diagnostic showing the two quantities independently; a race claim without that pair is a conjecture.

## Multi-Endpoint Races

Fire requests to *different* endpoints simultaneously to exploit a state that is only briefly consistent across a multi-step flow — `POST /cart/add` and `POST /checkout` together so checkout reads the cart mid-mutation, or apply a discount and finalize the order in the same packet. Sub-millisecond alignment is what makes the cross-endpoint window reachable; over seconds, the window closes.

- Order a product and apply a coupon in the same packet; the order-total calculation runs between the two writes, catching the pre-coupon total but allowing the coupon-used flag to flip anyway.
- Transfer funds between accounts and request a statement in the same packet; the statement renders before the transfer debit lands, showing the pre-transfer balance available for a second transfer.
- Add a user to a tenant and remove them in the same packet; the removal race-window can leave orphaned role bindings a later request can exploit.

## Partial-Construction Races

An object often passes through a **half-initialized** state that is briefly usable before the process finishes securing it. Race to use it during that window:

- A user/account created *before* its role, tenant binding, email-verified flag, or 2FA is set — authenticate or act in the gap.
- A session/token issued *before* it is bound to its scopes/device — replay it during the unbound window.
- A password-reset or invite record valid *before* a later step invalidates the old one — consume both.
- An order/payment object readable *before* its authorization/price is finalized.
- An uploaded file's row written *before* virus-scan or MIME-check runs — fetch it during the gap.

Find these by mapping each multi-write construction sequence and firing a read/use request into the gap between the first write (object exists) and the last (object secured).

## Idempotency and Dedup Bypass

- Reuse the same idempotency key across different principals/paths if scope is inadequate — some stacks key only on the key value, not on `(key, principal, path)`.
- Hit the endpoint before the idempotency store is written (cache-before-commit windows); the second request looks like the first.
- App-level dedup drops only the response while side effects (emails/credits/webhooks) still occur — observe side-effect telemetry, not the HTTP response.
- Idempotency key respected but TTL short; replay after expiry with the same payload grants again.
- Idempotency store is a cache (Redis), reset on failover; the retry after a shard-outage window is treated as fresh.

## Atomicity Gaps

- **Lost update** — read-modify-write increments without atomic DB statements. Replace with `UPDATE t SET v = v + 1 WHERE id = ?` or an advisory/row lock.
- **Partial two-phase workflows** — success committed before validation completes. Common with payment captures that write the ledger before the gateway's capture response is confirmed.
- **Unique checks done outside a unique index** — `if not exists(...) then insert(...)` creates duplicates under load. The fix is a unique index + `INSERT ... ON CONFLICT`; the application-level check is a hint, not a guarantee.
- **Serializable vs READ COMMITTED** — the default isolation is READ COMMITTED on PostgreSQL/MySQL/Oracle; serializable needs explicit opt-in per transaction. A test under single-threaded load can pass while a REPEATABLE READ anomaly fires under contention.

## Cross-Service Races

- **Saga/compensation timing gaps** — the compensation step runs before the forward step blocks a second attempt, so both attempts proceed and both are "compensated" later with a net duplicate side effect.
- **Eventual consistency windows** — act in Service B before Service A's write is visible. Common in event-sourced architectures where the read model lags.
- **Retry storms** — at-least-once delivery without idempotent consumers. If a webhook retries on a timeout and the first delivery succeeded, two side effects occur.
- **Dual-write anti-pattern** — write to DB and publish to Kafka/SNS without a transactional outbox. A race in the publish step double-publishes or drops the message entirely.

## Rate Limits and Quotas

- Per-IP or per-connection enforcement: bypass with multiple IPs/sessions.
- Counter updates not atomic or sharded inconsistently; send bursts before counters propagate across shards.
- Edge-level rate limits (CDN, API gateway) only; application has no further check. Confirm by hitting the origin directly where discoverable.
- Rate limit keyed on client-visible token; rotate tokens between requests (per-request OAuth refresh is a known footgun).
- The CVE-2025-55003 pattern (OpenBao MFA): rate-limit keyed on *normalized* code value while the auth check accepts a *non-normalized* code — the attacker's whitespace-prefixed OTP goes through validation but misses the rate counter's hash. See `race_conditions_novel_deep.md § OpenBao TOTP Rate-Limit Bypass`.

## Optimistic Concurrency Evasion

- Omit `If-Match`/`ETag` where optional; supply stale versions if server ignores them silently.
- Version fields accepted but not validated across all code paths — GraphQL vs REST, or admin vs user endpoints that each have their own binder.
- `updated_at` compared with `>=` instead of `=`; a stale value equals or exceeds the recorded one on clock skew.

## Database Isolation

- Exploit READ COMMITTED / REPEATABLE READ anomalies: phantoms, non-serializable sequences, write skew.
- Upsert races: use unique indexes with proper `ON CONFLICT`/`MERGE` or exploit naive existence checks.
- Lock granularity issues: row vs table; application locks held only in-process; advisory locks that only cover one code path.
- MySQL default `REPEATABLE READ` with `SELECT ... FOR UPDATE` on a non-indexed column locks every scanned row — but a different code path reading without `FOR UPDATE` races the lock holder.

**SQL anomalies by isolation level** (defaults in parentheses):

| Isolation | Dirty read | Non-repeatable read | Phantom | Write skew | Lost update |
|---|---|---|---|---|---|
| READ UNCOMMITTED | Allowed | Allowed | Allowed | Allowed | Allowed |
| READ COMMITTED (PG, Oracle, SQL Server) | Prevented | Allowed | Allowed | Allowed | Allowed |
| REPEATABLE READ (MySQL InnoDB) | Prevented | Prevented | *Allowed* | Allowed | Allowed |
| SERIALIZABLE | Prevented | Prevented | Prevented | Prevented | Prevented |

MySQL InnoDB's REPEATABLE READ is strictly stronger than the SQL-92 definition — it uses gap locks that eliminate most phantoms — but the lock-free `SELECT` path (consistent reads without `FOR UPDATE`) can still race a concurrent `INSERT`. PostgreSQL REPEATABLE READ uses MVCC snapshot isolation; a write-skew anomaly (two transactions each read the same rows, each updates disjoint rows based on the read, both commit) remains possible unless upgraded to SERIALIZABLE.

**Write skew** is the race condition SQL-isolation defaults do not prevent: two sessions each check "at least one on-call doctor is present" and each marks themselves off-call, each sees the other as present at check time, both commit; the invariant breaks. Defence is a `SELECT ... FOR UPDATE` lock that promotes read to write intent, or SERIALIZABLE isolation.

## Distributed Locks

- Redis locks without `SET key value NX EX ttl` and fencing tokens allow multiple winners after a node failover. Redlock is widely critiqued (Martin Kleppmann, 2016) for exactly this: a lock acquired on one node can time-out and be re-acquired on another while the first holder is still in its critical section.
- Locks stored in memory on a single node; bypass by hitting other nodes/regions.
- ZooKeeper/etcd ephemeral-node locks are stronger (fencing is built in) but require every consumer to check the fencing token, not just acquire the lock.

**Correct Redis-based mutual exclusion** uses `SET key uuid NX EX ttl` for acquire, a Lua script that `DEL`s only when the value matches `uuid` for release, and a monotonic fencing token the protected resource validates. Observable failures to look for:

- `SETNX` without `EX`: lock held forever on crash; one stuck lock permanently excludes all later holders (DoS), but a code-path that falls through on timeout re-enters without the lock.
- `SET ... NX EX ttl` without the uuid-match release: a late-timeout holder can `DEL` another holder's lock.
- No fencing token: the protected resource (DB write, file-write) accepts a late-but-still-authorized operation after a new holder has taken over; the serialization property is lost even with correct Redis locking.

**Database-level alternatives** that avoid the distributed-lock problem entirely:

- PostgreSQL `pg_advisory_xact_lock(key)` — session-scoped lock tied to the transaction; cannot leak past commit.
- MySQL `GET_LOCK(name, timeout)` — connection-scoped; released on disconnect.
- SQL `UPDATE t SET v = v - 1 WHERE id = ? AND v > 0` — the predicate and the write are a single critical section; the row-level write lock serializes concurrent entrants.

## Bypass Techniques

- Distribute across IPs, sessions, and user accounts to evade per-entity throttles — the race window is global, the rate counter is often local.
- Switch methods/content-types/endpoints that trigger the same state change via different code paths — a `PUT /resource` and a `PATCH /resource/field` often share state but not throttling.
- Intentionally trigger timeouts to provoke retries that cause duplicate side effects.
- Degrade the target (large payloads, slow endpoints) to widen race windows — a 100ms server round-trip is a comfortable window; a 5ms one needs single-packet alignment.
- GraphQL alias-batching: a single request with N aliased mutations is one HTTP request to the rate limiter but N state changes to the resolver. See `race_conditions_novel_deep.md § GraphQL Alias Rate-Limit Bypass`.

## Special Contexts

### GraphQL

- Parallel mutations and batched operations may bypass per-mutation guards.
- Resolver-level idempotency and atomicity must hold; the HTTP-level check is not enough.
- Persisted queries and aliases can hide multiple state changes in one request.
- Alias batching is a rate-limit-bypass primitive: `mutation { a: redeem(code:"X"), b: redeem(code:"X"), c: redeem(code:"X"), ... }` is one HTTP call. See the novel sibling.

### WebSocket / SSE

- Per-message authorization and idempotency must hold; the handshake-only check is a common gap.
- Concurrent emits can create duplicates if only the handshake is checked.
- Server-Sent-Event consumers often lack per-event auth entirely — a race on the connection-establishment side can push privileged events to an unprivileged consumer.

### Files and Storage

- Parallel finalize/complete on multi-part uploads can create duplicate or corrupted objects.
- Re-use pre-signed URLs concurrently; S3's `Signature` is replayable until expiry.
- Virus-scan race: file row written synchronously, scan runs asynchronously; a GET during the window returns the unscanned file.

### Auth Flows

- Concurrent consumption of one-time tokens (reset codes, magic links) to mint multiple sessions.
- Password reset consumed in parallel: one request establishes the new password; a concurrent request with the same token mints a session on the *old* password's identity. CVE-2026-4208 (TYPO3 MFA bypass — generated code not reset after authentication, enabling empty-string replay) is a related class.
- MFA code validation that normalizes whitespace in one path but not the other.

## 2024-2026 CVE Routing

Instance-level CVEs for the current race-condition frontier. The version/GHSA metadata lives in `race_conditions_novel_deep.md`; the base cites by number and route only.

- **CVE-2024-50379 / CVE-2024-56337** — Apache Tomcat JSP compilation TOCTOU on case-insensitive filesystems, RCE class. The incomplete-mitigation follow-up (CVE-2024-56337) carries a stricter patch. Route: `race_conditions_novel_deep.md § Apache Tomcat JSP Compilation TOCTOU`.
- **CVE-2025-55003** — OpenBao Login MFA whitespace-normalization gap: rate-limit keyed on raw code, validation keyed on normalized code. Enables TOTP reuse and rate-limit bypass. Route: `race_conditions_novel_deep.md § OpenBao TOTP Rate-Limit Bypass`.
- **CVE-2025-67505** — Okta Java Management SDK `ApiClient` thread-unsafety: a response's status code or headers can leak into a concurrent request's result. Route: `race_conditions_novel_deep.md § Okta Java SDK ApiClient Response-Mixing`.
- **CVE-2026-71537** — Paymenter `doUpgrade` credit-refund double-spend: non-transactional `increment('amount', abs($price))` outside `DB::transaction()`. Race class: multiple downgrades of the same service each refund. Route: `race_conditions_novel_deep.md § Paymenter Credit-Refund Double-Spend`.

The advanced sibling (`race_conditions_advanced_deep.md`) owns multi-endpoint window construction, cross-service race depth, distributed-lock-shape failures with worked Redlock critiques, SQL anomaly taxonomy (write-skew, phantom-read, lost-update) with per-engine isolation defaults, and auth-flow race depth including OAuth state-reuse races.

## Chaining Attacks

Chaining is capability transfer: the race condition grants a *second* primitive that the next skill owns. Route each hop by filename.

- **Race + IDOR** — mint a second resource reference in parallel so one reference is validated and the other is accessed; see `idor.md § Partial-Construction` and `broken_function_level_authorization.md § Role-Binding Race`.
- **Race + CSRF** — trigger parallel actions from a victim's authenticated session to amplify effects; the CSRF endpoint accepts N calls, the state check only sees the first; see `csrf.md`.
- **Race + Caching** — stale caches re-serve privileged states after concurrent changes. The cache sees a 2xx response for an action that later rolled back; see `header_injection.md § Cache Poisoning`.
- **Race + Business Logic** — violate conservation invariants: double-refund, limit slicing, coupon stacking; see `business_logic.md`.
- **Race + MFA bypass** — race the OTP-consumption vs the token-blacklist write; see `authentication_jwt.md § Token Revocation Race`.

## Testing Methodology

1. **Model invariants** — Conservation of value (sum of balances is constant), uniqueness (one row per `(user, code)`), maximums (per-user limits) for each workflow.
2. **Identify reads/writes** — Where they occur (service, DB, cache); for each, identify the critical section.
3. **Baseline** — Single requests to establish expected behaviour and response timing.
4. **Concurrent requests** — Issue parallel requests with identical inputs; observe deltas.
5. **Scale and synchronize** — Ramp up parallelism, use HTTP/2 single-packet, align timing (last-byte sync as fallback).
6. **Cross-endpoint** — Pair state-mutating endpoints that read shared state; fire together.
7. **Cross-channel** — Test across REST, GraphQL, WebSocket, SSE.
8. **Confirm durability** — Verify state changes persist and are reproducible under cold-cache conditions.

## Validation

1. Single request denied; N concurrent requests succeed where only 1 should.
2. Durable state change proven (ledger entries, inventory counts, role/flag changes) — not only HTTP status.
3. Reproducible under controlled synchronization (single-packet or last-byte sync) across multiple runs.
4. Evidence across channels (e.g., REST and GraphQL) if applicable.
5. Include before/after state and exact request set used; a minimal PoC is a run script with the gated-release pattern.

## False Positives

- Truly idempotent operations with enforced ETag/version checks or unique constraints.
- Serializable transactions, correct advisory locks, or queue-based consumers with idempotency keys that scope to `(key, principal, resource)`.
- Visual-only glitches without durable state change.
- Rate limits that reject excess with atomic counters (Redis `INCR` + `EXPIRE` in a Lua script).
- "Parallel succeeded sequentially" where sequence order happened to interleave benignly — repeat the test N times.

## Impact

- Financial loss (double spend, over-issuance of credits/refunds).
- Policy/limit bypass (quotas, single-use tokens, seat counts, concurrent-session limits).
- Data integrity corruption and audit-trail inconsistencies.
- Privilege or role errors due to concurrent updates (mid-flight role assignment on a half-initialized user).
- Rate-limit evasion that enables credential stuffing or MFA brute-force.

## Pro Tips

1. Favour HTTP/2 single-packet with warmed connections; add last-byte sync as HTTP/1.1 fallback.
2. Start small (N=5–20), then scale; too much noise can mask the window.
3. Target read-modify-write code paths and endpoints with idempotency keys — the keys are often where the gap is.
4. Compare REST vs GraphQL vs WebSocket; protections often differ.
5. Look for cross-service gaps (queues, jobs, webhooks) and retry semantics.
6. Check unique constraints and upsert usage; avoid relying on pre-insert checks.
7. Use correlation IDs and logs to prove concurrent interleaving.
8. Widen windows by adding server load or slow backend dependencies (large payloads, slow upstream calls).
9. Validate on production-like latency; some races only appear under real network RTT.
10. Document minimal, repeatable request sets that demonstrate durable impact — a single-script reproducer wins the triage conversation.

## Breadth Note

This base is a reference overview of the race-condition technique surface — class framing, single-packet basics, the measured counter result, every primary primitive family, the SQL anomaly table, distributed-lock reference, and the full 2024-2026 CVE routing map. It is deliberately scoped to be a complete *overview* of every technique class rather than a *full-treatment* of each; the two deep siblings carry the full-treatment sub-primitives (Primitive / Preconditions / Attack recipe / Confirmation / Impact) per technique. Load the advanced sibling for exploitation depth against a hardened target; load the novel sibling for the current CVE instances and non-CVE research frontier.

## Summary

Concurrency safety is a property of every path that mutates state, measured by whether the critical section is atomic across all concurrent entry paths. The single-packet attack has removed network jitter as the exploitation barrier; what remains is whether the code's read-modify-write, idempotency, isolation, and locking collectively guarantee the invariant. If any path lacks atomicity, parallel requests will eventually break it, and the exploit will be shaped by whatever the broken invariant permits — double-spend, role-flip, limit-slice, or token-reuse.
