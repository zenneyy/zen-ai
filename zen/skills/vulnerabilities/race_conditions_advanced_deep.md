---
name: race-conditions-advanced-deep
description: Advanced race-condition exploitation — single-packet HTTP/2 mechanics at the wire level, multi-endpoint window construction, partial-construction and idempotency scoping failures, distributed-lock Redlock critique with fencing-token discipline, SQL anomaly catalog with per-engine defaults, cross-service saga and dual-write patterns, OAuth and OTP consumption races, and composite chaining into IDOR, caching, and auth.
sibling: race_conditions
load_when: scan_mode == "deep"
---

# Race Conditions — Advanced + Expert Depth

This is the advanced+expert deep sibling to `race_conditions.md`. The base owns class framing, the measured counter table, request synchronization fundamentals, idempotency and dedup bypass basics, atomicity gaps, SQL isolation anomaly reference, Redis-lock reference, and the 2024-2026 CVE routing map. The novel+frontier sibling `race_conditions_novel_deep.md` owns the current CVE instances (Tomcat JSP TOCTOU, OpenBao TOTP, Okta SDK, Paymenter double-spend) with canonical version/GHSA tables, and the research-grade techniques published 2024-2026.

This file owns the expert-tier exploitation mechanics: wire-level single-packet construction, multi-endpoint window patterns with worked recipes, partial-construction race catalog, idempotency scoping failures with worked attack flows, distributed-lock failure patterns including the full Redlock critique and fencing-token discipline, SQL anomaly exploitation (write-skew, phantom-race, lost-update) with per-engine detail, cross-service race patterns (saga, outbox, dual-write), OAuth and MFA consumption races, cache-and-race patterns, and composite-chain construction routed to sibling skills.

Load this file when the goal is to construct a reliable race exploit against a hardened target — single-packet alignment is already understood, the simple counter race has already failed, and the target has at least one layer of concurrency defence (lock, isolation, idempotency key) to be worked around.

## Single-Packet HTTP/2 — Wire-Level Mechanics

The single-packet attack (James Kettle, PortSwigger, BH USA 2023) works because HTTP/2 multiplexes concurrent streams over one TCP connection and the server reads a TCP segment atomically before dispatching streams to worker threads. Pack 20–50 complete requests into one TCP segment and the server-side arrival-time variance drops to the TCP-stack scheduling slack — sub-millisecond. Over an intercontinental link the window measured by Kettle (Melbourne to Dublin, 17,000 km) remained <1ms vs ~4ms for last-byte sync.

**Preconditions for single-packet alignment:**

1. Target advertises HTTP/2 (ALPN `h2` or Upgrade). Confirm with `curl --http2 -I`; mixed-support targets will auto-downgrade.
2. The intermediate network path does not fragment the segment at an intermediate MTU below the request bytes. In practice, 20 requests of ~500 bytes each + H2 framing fits comfortably in a single Internet MTU (1500 bytes) only for very small requests; larger requests force 2-3 segments, which Kettle's updated technique accommodates via "sequence-based synchronization."
3. The server's H2 implementation respects stream concurrency limits. `SETTINGS_MAX_CONCURRENT_STREAMS` defaults to 100-250 on major servers; staying under this avoids reset.
4. The server dispatches streams to independent workers rather than serializing them on a single-threaded H2 handler.

**Packing calculation.** Burp's Turbo Intruder uses the `BURP2` engine which implements the single-packet attack natively. The number of requests packed depends on:

- Each HTTP/2 HEADERS frame carries a HPACK-compressed header set; the first request on a connection pays the full dictionary cost (~100-200 bytes), subsequent requests use incremental compression (~50-80 bytes).
- Each HTTP/2 DATA frame carries the body; for a small POST body (~50 bytes), the DATA frame overhead is ~9 bytes.
- MTU=1500 typical: ~20-25 requests per packet after HPACK compression.

**Fallback: last-byte sync.** On HTTP/1.1 (no multiplexing), send all but the final byte of each request on each warmed connection, then release the final bytes together. The slack is bounded by the server's `read()` loop granularity (~4ms on Linux) vs sub-ms for single-packet.

```python
# Turbo Intruder — single-packet attack (HTTP/2)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req, gate='r')
    engine.openGate('r')

# Turbo Intruder — last-byte sync (HTTP/1.1 fallback)
def queueRequests_lbs(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30,
                           engine=Engine.THREADED)
    for i in range(30):
        engine.queue(target.req, gate='r')
    engine.openGate('r')
```

**Confirming alignment.** On a target under test, instrument the request handler (or a middleware) to log a nanosecond-precision arrival timestamp; the max-min spread is the alignment slack. For a black-box target without instrumentation, measure the response-time variance across a batch — low variance implies good alignment.

**Impact.** Without alignment, races that depend on <1ms windows are unreachable; with alignment, any race window the server-side critical section opens is exploitable. Alignment is a necessary but not sufficient condition — a correctly atomic server defeats single-packet just as cleanly as it defeats sequential requests.

## Multi-Endpoint Window Construction

The common misconception: all requests in a race go to the same endpoint. The exploitable class is often *cross-endpoint* — endpoint A's write and endpoint B's read-of-A's-state race, exposing a transient inconsistency.

### Primitive: Checkout-During-Cart-Mutation

Primitive: `POST /cart/add` and `POST /checkout` fire together; checkout reads the cart's state mid-mutation, catching a transient subtotal and a pre-write coupon-count.

**Preconditions:**

1. Cart mutations are not transactional with the checkout read; the application computes the cart total on each `/checkout` call rather than caching it in a transactionally-written field.
2. The coupon-consumed flag is written as a separate step from the subtotal calculation.
3. The HTTP connection can carry both endpoints in a single packet.

**Attack recipe:**

```python
# Turbo Intruder cross-endpoint
engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                       engine=Engine.BURP2)
# Request 1: /cart/add with coupon that would normally fail validation on repeat
r1 = request_add_coupon(code="SAVE50")
# Request 2: /checkout which reads cart.total and marks coupon-used
r2 = request_checkout()
engine.queue(r1, gate='r')
engine.queue(r2, gate='r')
engine.openGate('r')
```

Alignment ensures `/cart/add`'s write of `coupon.used=false → true` and `/checkout`'s read of `cart.total` interleave such that `/checkout` captures the discounted total but then also applies the coupon as if it were fresh.

**Confirmation signal:** `/checkout` returns a discounted-total order; a follow-up `/orders/<id>` shows the discount applied; the coupon's `used_count` is now 2 (coupon-use + checkout-attached-use) despite a single-use coupon.

**Impact:** Order placed at discounted price with coupon that should have been consumed on first use. In chains, this amplifies into stacking: two coupons that each pass "already-used-check-false" at check time both apply.

### Primitive: Transfer-During-Statement

Primitive: `POST /transfer` and `GET /balance` race, allowing a double-spend based on the pre-transfer balance.

**Preconditions:** `/balance` reads the account's balance without a serializable snapshot; `/transfer` decrements the balance but the decrement is not visible to a concurrent reader.

**Attack recipe:** fire `/transfer -> A` and `/transfer -> B` together, both based on a `/balance` that saw $100. If the two transfers each decrement by $100, the account goes to -$100 (both debit succeeded against the same $100 reading).

**Confirmation signal:** account balance negative after two transfers that each "succeeded".

**Impact:** Double-spend of a user's balance; in a crypto/wallet context, the exploited user is the attacker but the victim is the exchange.

### Primitive: Role-Assignment-During-User-Creation

Primitive: `POST /users` and `POST /users/<id>/role` race, where the role assignment can target the user-being-created with higher privileges than the user's intended default.

**Preconditions:** User creation and role assignment are separate endpoints with no transactional link; the role endpoint's permission check reads a role-table that is empty for the new user (default role not yet applied).

**Attack recipe:** fire user-create and role-assign-as-admin together; the role check runs on the half-created user whose current role is NULL (not yet "user"), and NULL-role may bypass the "cannot elevate" check.

**Confirmation signal:** new user with admin role; audit log shows role assignment timestamp before user creation finalize.

**Impact:** Privilege-escalation on creation; new user has admin role from first login.

## Partial-Construction Race — Deep Catalog

An object passes through a half-initialized state briefly usable before the process finishes securing it. Each pattern below has its own window:

### Primitive: Email-Verification-Window

Primitive: A user is created and immediately usable before the `email_verified` column is set to `false` (common bug: ORM `.create()` returns an object with `email_verified` set to the model-default `true` and then async-updates it to `false`).

**Preconditions:** The user row is `INSERT`ed with a default-true `email_verified`, then an UPDATE sets it to false pending verification. Login handler checks `email_verified` from a stale replica.

**Attack recipe:** register the user, then race the login endpoint against the UPDATE that sets `email_verified=false`. If the login read runs on the replica before replication catches the UPDATE, login succeeds without verification.

**Confirmation signal:** session minted for an unverified user; verification email arrives after the session already exists.

**Impact:** Verification bypass; attacker uses the unverified session to perform state changes requiring verification.

### Primitive: Session-Scope-Binding-Window

Primitive: A session is minted and then bound to the device/scopes/MFA factors in a second step. During the gap, the session is valid for anything.

**Preconditions:** `POST /sessions` returns a bearer with no scopes; the subsequent `POST /sessions/<id>/scopes` assigns scopes atomically but after the bearer is already usable.

**Attack recipe:** acquire the bearer via the first endpoint, immediately present it to a scope-sensitive endpoint; the authz layer sees `scopes=*` (default) because the scope-restriction has not been written yet.

**Confirmation signal:** scoped operation succeeds using a bearer that should have been limited to a subset.

**Impact:** Scope-bypass; the attacker exercises capabilities beyond the bearer's intended scope.

### Primitive: Payment-Capture-Before-Validation

Primitive: A payment capture writes the ledger before the gateway's validation response is confirmed.

**Preconditions:** The capture endpoint issues the gateway call and writes `payment.status=captured` optimistically, rolling back on the gateway's reject. A read during the window sees `captured` and triggers downstream fulfillment.

**Attack recipe:** issue a capture that the gateway will reject (e.g., with a known-reject test card), then race `/orders/<id>/fulfill` against the rollback. Fulfillment reads `captured`, dispatches the order, before the rollback completes.

**Confirmation signal:** order dispatched despite payment reject; ledger shows reverted capture but order status is fulfilled.

**Impact:** Goods shipped without payment; the fulfilled order remains in a "to-be-reconciled" state the finance team may miss.

### Primitive: Password-Reset-Dual-Consumption

Primitive: A password-reset token is consumed in parallel: one request establishes the new password, a concurrent request with the same token mints a session on the old password's identity.

**Preconditions:** The reset handler validates the token, mints a session, and marks the token used — in that order, without a transactional lock. The second concurrent handler sees the token still unused.

**Attack recipe:** acquire the reset token (user-side action — password-reset request), fire two concurrent `POST /reset-password` calls with the same token. Both pass the "token-valid" check; both proceed to mint sessions.

**Confirmation signal:** two valid sessions on the account post-reset; the password gets written twice (second write wins).

**Impact:** Session persistence after password change — the attacker's second session, minted during the race, survives the user's successful password change and remains logged in.

### Primitive: Invite-Record-Pre-Invalidation

Primitive: An invite record is accepted and converted into a membership before the old invite is invalidated; a concurrent accept of the same invite creates two memberships.

**Preconditions:** Invite acceptance is a multi-step `check-exists → create-member → mark-invite-used` with no transaction; the invite is still "valid" during the first two steps.

**Attack recipe:** fire two parallel `POST /invite/<token>/accept` with the same token; both pass the exists check, both create a membership.

**Confirmation signal:** two members in the tenant from one invite; invite audit log shows one issued and two accepted.

**Impact:** Membership-count inflation; in a billing-per-seat SaaS, this is directly monetizable (one invited seat yields two active seats).

## Idempotency Scoping Failures

Idempotency keys are a defence against duplicate side effects, but their *scope* must cover the attack surface. The scope dimensions are the tuple `(key, principal, path, body-hash, time-window)`; each one that is omitted or trivially controllable by the attacker is a gap.

### Primitive: Shared-Scope Across Principals

Primitive: Idempotency key is scoped by key value only, not by principal; two principals using the same key race the same "first-call-wins" bucket, allowing one of them to seize the other's response.

**Preconditions:** Server implementation like `redis.setex("idem:" + key, ttl, response)` without a principal in the Redis key. A legitimate client's second call sees the attacker's response.

**Attack recipe:** observe a legitimate client's idempotency key (via a leaky log, interception, or shared infrastructure), then issue a request with the same key before the legitimate client's call completes. The attacker's response (your choice of state change) is written to the Redis store; the legitimate client's retry sees that response, treating the attacker's state change as their own.

**Confirmation signal:** legitimate client's reconciliation shows an unexpected state change attributable to their action; the attacker's action is reflected in the legitimate client's account.

**Impact:** State-change confusion between principals; in payment stacks, this can authorise an attacker's charge against a victim's gateway-authorised context.

### Primitive: Scope-Not-Path

Primitive: Idempotency key scoped by `(principal, key)` but not by `path`; a key used for `POST /transfer` can collide with the same key used for `POST /refund`, allowing a cross-endpoint response reuse.

**Preconditions:** Server stores idempotency entries keyed on `(user, key)` without the path.

**Attack recipe:** issue a `POST /transfer` with key `K`; after it succeeds, issue a `POST /refund` with the same key `K`. The idempotency cache returns the transfer response for the refund call; the attacker observes the refund didn't happen but the response says it did.

**Confirmation signal:** `/refund` response body matches an earlier `/transfer`; no refund in the ledger.

**Impact:** Depending on the client's reconciliation logic, the attacker's downstream reads may skip the "refund failed" path and leave the state inconsistent — or the gap can be used to extract balances the server thinks it refunded.

### Primitive: TTL-Expiry Replay

Primitive: Idempotency entry has a short TTL (e.g., 5 minutes); replay the request after expiry with the same key and the same body, and the server treats it as fresh.

**Preconditions:** Idempotency store is a cache (Redis, Memcached) with a TTL; no durable record of the key use.

**Attack recipe:** wait for the TTL to expire, then replay. The side effect fires again.

**Confirmation signal:** two state changes from the same request bytes with time-separated timestamps.

**Impact:** Replay-with-amplification over time; a bulk-refund button becomes a drain.

### Primitive: Cache-Miss-During-Shard-Failover

Primitive: Idempotency Redis cluster undergoes a shard failover; during the window, the new primary has not yet replicated the entries; a replay during the window hits the new primary and sees no entry.

**Preconditions:** Redis cluster, no AOF-persist on write, failover during the attack window.

**Attack recipe:** harder to engineer deliberately, but observed in production disaster scenarios. A monitored target undergoing failover (CDN failover event, DNS change) is a soft signal.

**Confirmation signal:** cluster failover event in the vendor's status page coincides with duplicate side effects in the ledger.

**Impact:** Opportunistic replay during ops events; a bounty-worthy finding on a hardened target that otherwise correctly scopes idempotency.

## Distributed-Lock Failure Patterns — Redlock Critique

Martin Kleppmann's 2016 critique of Redlock remains the canonical analysis. Three failure modes:

**1. Clock skew.** Redlock's safety argument relies on bounded clock drift across Redis nodes. If a GC pause, a VM migration, or a monotonic-clock-not-wall-clock bug extends a holder's elapsed time, the holder may believe it still holds the lock while the lock has already expired and been handed to another holder.

**Attack recipe:** engineer a long-pause event (large allocation, serialization burst) in the first holder's process; a concurrent attempt wins the lock during the pause; both holders proceed in the critical section.

**Confirmation signal:** both holders write to the protected resource; the fencing-token mechanism (if present) rejects one of them, but if absent, both writes persist.

**2. No fencing tokens.** Without a monotonic fencing token the protected resource checks, a late-arriving write from an expired-lock holder succeeds. The lock serializes acquisition but not the critical-section effects.

**Attack recipe:** acquire the Redis lock, pause (via network partition, GC, scheduling), observe the lock expire, allow a second holder to acquire. The first holder's eventual write (if it still submits one) is accepted.

**Confirmation signal:** protected resource has two writes with the same lock-generation stamp.

**3. Partial-partition split-brain.** A majority of Redis nodes are reachable to holder A; a minority is reachable to holder B after a partition. In some Redlock configurations, both can succeed.

### Primitive: Advisory-Lock-One-Code-Path

Primitive: PostgreSQL advisory lock protects the common read-modify-write path but not an administrative bulk-mutation path.

**Preconditions:** `pg_advisory_lock(resource_id)` on the write path; a separate `UPDATE WHERE id IN (...)` on an admin endpoint does not acquire the advisory lock.

**Attack recipe:** issue the admin bulk mutation (via a leaked admin credential or an authorized admin endpoint) while the write path's lock is held. The bulk mutation bypasses the lock entirely.

**Confirmation signal:** bulk mutation modifies rows the lock holder is operating on; the lock holder's write overwrites the bulk mutation (or vice versa).

**Impact:** Admin-path races that the application assumed were defended by the advisory lock; silent data loss or audit-log inconsistency.

### Primitive: Lock-Timeout-Shorter-Than-Operation

Primitive: Lock TTL is 5 seconds; the protected operation takes 10 seconds. Mid-operation, the lock expires and another holder enters.

**Preconditions:** Hard-coded TTL in the lock-acquire call; variable-length critical section.

**Attack recipe:** engineer a long operation (large payload, slow upstream call) to force the critical section past the TTL. A concurrent attempt immediately after TTL expiry enters.

**Confirmation signal:** two state changes from the "serialized" code path; durations in the audit log exceed the TTL.

**Impact:** Lock-serialization property is defeated for long-running operations; the application must either extend the lock, use fencing tokens, or shorten the critical section.

## SQL Anomaly — Worked Exploitation

### Primitive: Write-Skew — The On-Call Doctor Pattern

The canonical SERIALIZABLE-required example: two doctors both check "at least one on-call doctor is present"; each marks themselves off-call; both see the other as present at check time; both commit; the invariant breaks.

Translated to a web application: two users each check "at least one admin remains in the tenant"; each demotes themselves (or an admin they control); both proceed; the tenant ends with zero admins and no admin can re-promote.

**Preconditions:** PostgreSQL READ COMMITTED or REPEATABLE READ (snapshot isolation); the admin-count check and the role-demotion are in the same transaction but do not use `SELECT ... FOR UPDATE`.

**Attack recipe:**

```sql
-- Transaction A (concurrent with B):
BEGIN;
SELECT count(*) FROM roles WHERE tenant_id=1 AND role='admin';  -- returns 2
UPDATE roles SET role='user' WHERE user_id=42 AND tenant_id=1;
COMMIT;

-- Transaction B (concurrent with A):
BEGIN;
SELECT count(*) FROM roles WHERE tenant_id=1 AND role='admin';  -- also returns 2
UPDATE roles SET role='user' WHERE user_id=43 AND tenant_id=1;
COMMIT;

-- Result: both see count=2 at check time, both proceed; tenant has 0 admins.
```

**Confirmation signal:** post-attack admin count is 0 in a tenant that required at least 1 admin.

**Impact:** Tenant lockout from admin operations; recovery requires out-of-band intervention.

### Primitive: Phantom-Read — Unique-Index-Via-Query

Primitive: Application checks "does a row with (tenant, email) exist?" via `SELECT`; if not, `INSERT`s. Under concurrent entrants, both see no existing row and both insert.

**Preconditions:** No unique index on `(tenant_id, email)`; the application-level uniqueness check runs as a `SELECT` outside the `INSERT`'s transaction (or READ COMMITTED).

**Attack recipe:** fire two parallel user-create requests with the same email; both see "no existing user", both insert; duplicate rows result.

**Confirmation signal:** duplicate `(tenant, email)` rows; a later login flow may pick either row inconsistently.

**Impact:** Account duplication; downstream reconciliation is lossy; a login grants access to whichever row the ORM returns first.

### Primitive: Lost-Update — Counter-Via-Select-Then-Update

Primitive: `SELECT balance FROM accounts WHERE id=?` followed by `UPDATE accounts SET balance=? WHERE id=?` with the computed new value. Two concurrent sessions both see the old balance, both compute the same new balance, both write — the second write silently loses the first's increment.

**Preconditions:** Application code performs the arithmetic in-process rather than in SQL.

**Attack recipe:** race two "credit the account by $100" requests; both read the old balance, both compute +$100, both write the same new value. Net credit is $100 (not $200), and the first increment is lost.

**Confirmation signal:** audit log shows two credits of $100, ledger shows a single +$100 increase.

**Impact:** Lost-update race against the attacker's own debit flows loses the attacker money; against the attacker's own credit flows (if the server is naive) can also drive negative balances by the inverse pattern.

## Cross-Service Race Patterns

### Primitive: Saga Compensation Race

Primitive: A saga comprises forward steps A→B→C and compensations C′→B′→A′. If the forward and compensation can execute in parallel for two concurrent attempts, the net outcome is one forward and one compensation — a free C.

**Preconditions:** Saga orchestrator does not serialize per-saga-instance; multiple concurrent attempts of the same logical operation each spin up a saga.

**Attack recipe:** fire two parallel `POST /checkout` requests. Both start sagas: `charge → reserve → ship`. First succeeds; second's `reserve` fails (inventory exhausted) and triggers compensation `refund → unreserve`. Net: one shipment, one refund that undoes a charge that already shipped.

**Confirmation signal:** shipment dispatched; refund issued; audit log shows the refund corresponded to a *successful* checkout.

**Impact:** Free goods; a well-funded reconciliation team catches this but the attacker already received the shipment.

### Primitive: Dual-Write Anti-Pattern

Primitive: An endpoint writes to the DB and publishes to Kafka/SNS without a transactional outbox. A race in the publish step either double-publishes or drops the message.

**Preconditions:** The write-and-publish pair is `db.write(); kafka.publish();` — two separate IOs with no outbox table.

**Attack recipe:** engineer a Kafka timeout (via large payload or saturated producer) between the DB write and the publish. The handler retries, publishing twice; downstream consumers process both.

**Confirmation signal:** two Kafka messages for one DB row; two downstream side effects.

**Impact:** Depending on the downstream, duplicates are state-changing (fulfilment, notification, billing).

### Primitive: Eventual-Consistency Read Lag

Primitive: Service A writes to its primary; Service B reads from a replica of A. Window between primary write and replica catch-up allows B to read stale state.

**Preconditions:** Microservices with eventually consistent cross-service reads; the staleness window is bounded by the replication lag (ms to seconds).

**Attack recipe:** write to A (grant a permission); race a read-from-B (that would deny the permission based on the pre-write state). If B's read runs on a stale replica, the denial fires despite A's successful write.

Alternatively, revoke in A; race the privileged operation in B before replica catches the revocation. The privileged operation succeeds using B's stale view.

**Confirmation signal:** operation denied/granted inconsistently with the primary's committed state; audit log shows the discrepancy.

**Impact:** Policy-decision inconsistency; a revoked user can perform one more privileged action per replication-lag window.

## OAuth and Authorization Races

### Primitive: Authorization-Code Dual-Exchange

Primitive: OAuth authorization code is exchanged in parallel; two concurrent `POST /token` calls with the same code succeed. Both issue bearers for the same user.

**Preconditions:** The authorization server does not atomically burn the code; the "code-used" flag is written after the token is minted.

**Attack recipe:** acquire a legitimate auth code (via normal flow); fire two parallel exchanges. Both pass the "code-valid" check and both mint tokens.

**Confirmation signal:** two distinct bearer tokens for the same code; the user's audit log shows two issue events for one authorization.

**Impact:** Token duplication; one of the tokens may escape detection and persist beyond the user's revocation of the first.

### Primitive: Refresh-Token-Rotation Race

Primitive: OAuth refresh token rotation (RFC 6749 §5.2.3 with RFC 8693 rotation) issues a new refresh on each use and invalidates the old. A race on refresh gets two active refreshes.

**Preconditions:** The rotation handler validates the refresh token, mints a new access + refresh, and marks the old refresh used — in that order, without a transactional lock.

**Attack recipe:** fire two parallel `POST /token (grant_type=refresh_token)` with the same refresh. Both pass validation; both mint new refresh tokens. Attacker now has two live refresh tokens for the user.

**Confirmation signal:** two distinct refresh tokens for one user that both independently work for subsequent refreshes.

**Impact:** OAuth refresh-token rotation defence defeated; attacker's token survives the user's rotation.

### Primitive: PKCE Verifier-Reuse Window

Primitive: Public clients using PKCE (RFC 7636). The server validates the verifier against the challenge, exchanges the code, and marks the code used — but the verifier check doesn't serialize across concurrent token requests.

**Preconditions:** PKCE verifier is only valid for one exchange per the spec; a race before the burn step allows two exchanges.

**Attack recipe:** same as auth-code dual-exchange, plus a PKCE verifier.

**Confirmation signal:** two tokens issued for one code+verifier pair.

**Impact:** Same as auth-code dual-exchange; PKCE does not add race protection, only MITM protection.

## OTP / MFA Consumption Races

### Primitive: Dual-OTP Submission

Primitive: One-time password submitted in parallel; both validations pass before either marks the OTP used.

**Preconditions:** OTP validation is `check-matches → consume` in two steps without a transaction.

**Attack recipe:** acquire the OTP (via phishing, SIM swap, or legitimate user coercion in a bug bounty context). Fire two parallel `POST /mfa/verify` calls. Both pass; both mint sessions.

**Confirmation signal:** two authenticated sessions after one OTP; OTP is marked used after both sessions exist.

**Impact:** Session duplication; the attacker's second session persists.

### Primitive: TOTP Window-Overlap

Primitive: TOTP accepts the current and previous time-step; a code valid at second 29 is still valid at second 31. Submit in parallel at the boundary.

**Preconditions:** TOTP implementation permits code reuse within the time window; no additional consumption-tracking.

**Attack recipe:** at the time-step boundary (e.g., second 29.5), fire two parallel submits with the same code. Both are within the acceptance window.

**Confirmation signal:** two sessions from one TOTP code separated by the time-step boundary.

**Impact:** TOTP reuse enables session duplication; see also OpenBao CVE-2025-55003 in the novel sibling for a whitespace-normalization twist.

## Cache-and-Race

Caches sit between the client and the authoritative store; a race between the cache's refresh and the store's write exposes stale privileges or state.

### Primitive: Stale-While-Revalidate Grant

Primitive: `Cache-Control: stale-while-revalidate=60` tells the cache to serve stale while fetching a fresh copy. A revocation of permission that lands on the authoritative store during the SWR window is not reflected in the cache's served response.

**Preconditions:** The cache (CDN, API gateway, nginx cache) serves authorization-sensitive responses with SWR; the revocation path does not purge the cache.

**Attack recipe:** victim revokes an attacker's access (API key, role). Attacker continues to hit the resource; the cache serves stale 200 responses for up to the SWR window.

**Confirmation signal:** access logs show 2xx responses to the attacker after the authoritative revocation timestamp.

**Impact:** Access-revocation lag; attacker retains access during the SWR window.

### Primitive: Cache-Fill Race (Thundering Herd)

Primitive: Cache miss triggers an upstream fetch; concurrent misses each trigger their own fetch. If the upstream has rate limits per-key, concurrent fetches can bypass them.

**Preconditions:** Cache implementation does not deduplicate concurrent misses (no "cache-fill lock" or "single-flight" pattern).

**Attack recipe:** flush the cache entry (via a cache-key-controlling input, or wait for TTL), then fire N parallel requests. The cache dedup is bypassed; N upstream fetches hit.

**Confirmation signal:** upstream logs show N fetches where 1 was expected; rate-limit on the upstream bypassed.

**Impact:** Cost amplification (billing for N upstream calls); rate-limit evasion.

## Queue and Background-Job Races

### Primitive: Dedup-Before-Enqueue vs Dedup-In-Worker

Primitive: Queue producer and worker both implement idempotency, but at different scopes; a race between them permits duplicate processing.

**Preconditions:** Producer dedups by `(job_type, args)` cache; worker dedups by `(job_type, args, idempotency_key)` DB record. If the producer's cache misses but the DB record hasn't been written yet, two jobs enqueue; both workers see "no DB record" and both execute.

**Attack recipe:** issue two parallel enqueue requests immediately after a job that just completed (whose cache entry just expired); both producers miss the cache and enqueue; both workers process.

**Confirmation signal:** two completed jobs for one logical intent; cache metrics show two misses in the same TTL window.

**Impact:** Duplicate work; billing/notification side effects fire twice.

### Primitive: Job-Cancellation-Vs-Execution

Primitive: Cancel request writes `job.status=cancelled`; worker reads `job.status` at start, proceeds if not cancelled. A race between cancel-write and worker-read permits execution of a cancelled job.

**Preconditions:** Worker reads status at job-start only; no mid-execution re-check.

**Attack recipe:** enqueue a job (via the normal path); immediately issue the cancel; race the worker's dispatch. Worker reads status before the cancel writes it; proceeds.

**Confirmation signal:** audit log shows job cancelled, then executed anyway.

**Impact:** Workflow-cancellation defence defeated.

## WebSocket and SSE Message-Layer Races

### Primitive: Handshake-Only Auth

Primitive: WebSocket authentication is enforced at the handshake (HTTP upgrade) but not re-validated per message. A session's privileges can change mid-connection (user demoted, token revoked), but the live socket continues to accept and act on messages at the pre-change privilege level.

**Preconditions:** WebSocket endpoint checks auth on connect; no per-message re-authorization callback; session can be invalidated while a socket is open.

**Attack recipe:** attacker connects as privileged user → victim demotes/revokes the role from a separate session → attacker continues to send privileged messages. The server dispatches each because the connection-level principal is still "privileged."

**Confirmation signal:** audit log shows privileged actions after the revocation timestamp from the same session.

**Impact:** Revocation lag; privilege persists across session boundaries that should have invalidated it.

### Primitive: Concurrent Send Duplication

Primitive: An authenticated WebSocket client sends N identical messages faster than the server's per-message idempotency check writes. If the handler is `check-not-processed → process → mark-processed` in three steps, the race window permits all N to pass the first step.

**Preconditions:** Per-message idempotency implemented at the handler layer with a non-atomic check-then-mark.

**Attack recipe:** send `{"type":"transfer","nonce":"X","amount":100}` as 50 identical frames on one open socket; the server's `nonces[X] ∈ processed?` check runs for each before any marks `nonces[X] = true`.

**Confirmation signal:** 50 transfers for one nonce; ledger shows duplicate side effects.

**Impact:** State-change duplication at the per-message layer; same shape as HTTP race but inside one WebSocket session.

### Primitive: SSE Consumer Race

Primitive: Server-Sent Event streams typically carry per-user events keyed on a path parameter (`/events/user/{id}`). The authorization check runs once at connect; the event dispatcher pushes events for the subscribed user ID. A race between the subscription write and the first event dispatch can allow a lower-privilege subscriber to receive events for a higher-privilege user.

**Preconditions:** SSE handler writes the subscription record and begins dispatching from a shared queue before the write is visible to the dispatcher's filter.

**Attack recipe:** fire two parallel SSE connections — one subscribing to `/events/user/attacker` and one to `/events/user/victim`. The race window between subscription-write and dispatcher-read may permit the attacker's socket to see the victim's events.

**Confirmation signal:** victim-specific events arrive on the attacker's SSE stream.

**Impact:** Cross-user event leakage; chains to information disclosure.

## Multi-Tenant Shared-State Races

### Primitive: Cross-Tenant Cache Pollution

Primitive: A multi-tenant application shares a cache key namespace (e.g., `Redis "config:global"`); a tenant-specific update is intended but the race window permits a different tenant's write to land on the shared key, leaking state across tenants.

**Preconditions:** Cache key is tenant-prefixed in one code path but not another; two concurrent writes land in the wrong-prefixed slot.

**Attack recipe:** fire `POST /settings` on tenant A and `POST /settings` on tenant B simultaneously. If the handler uses `config = get("config:global")` instead of `get("config:tenant:{id}")` in a code path, the merge-and-write races.

**Confirmation signal:** tenant A's settings appear in tenant B's response.

**Impact:** Cross-tenant information disclosure or state corruption; chains to `broken_function_level_authorization.md § Multi-Tenant Confusion`.

### Primitive: Shared Connection Pool State Leakage

Primitive: Database or HTTP client connection pools share connection-level state (session variables, prepared statements, transaction state). A request that sets a session variable (`SET application_name = 'tenant_A'`) and returns the connection to the pool exposes that state to the next request pulling the connection.

**Preconditions:** Connection pool is shared across tenants; application sets session-level state on checkout.

**Attack recipe:** request A sets `SET ROLE tenant_a_role`; connection returned to pool before `SET ROLE DEFAULT` runs; request B pulls connection and operates with tenant_a_role.

**Confirmation signal:** request B's DB queries succeed with tenant A's privileges.

**Impact:** Horizontal privilege escalation across tenants.

## Verification-Burn Races

### Primitive: JWT Blacklist Race

Primitive: JWT revocation implemented as a blacklist that validators check *after* signature verification. If the validation path is `verify-sig → check-blacklist → serve`, a race between the blacklist write and a validation that reads the pre-write blacklist permits one more use of a revoked token.

**Preconditions:** Non-atomic blacklist implementation; blacklist is a cache (Redis) or append-only log.

**Attack recipe:** victim revokes a token; attacker races a request with the token against the blacklist-write propagation. On a Redis blacklist with a replication lag, the attacker's validator may read a replica that hasn't caught up.

**Confirmation signal:** request succeeds with a token the audit log shows as revoked.

**Impact:** Token revocation lag; chains to session persistence.

### Primitive: One-Time URL Burn Race

Primitive: A one-time URL (file-download link, magic auth link, invitation link) is validated and consumed in two steps. Concurrent accesses before the consume step both pass validation.

**Preconditions:** Separate validation and consumption DB operations.

**Attack recipe:** acquire the one-time URL; fire two concurrent fetches; both pass validation.

**Confirmation signal:** both fetches return the resource; the audit log shows the URL marked consumed after both responses.

**Impact:** Multi-use of a nominally single-use resource; chains to information disclosure or session minting depending on the URL's purpose.

## File-Upload-Finalize Races

### Primitive: Scan-Finalize Race

Primitive: An uploaded file is written to storage before virus/content scanning completes; the scan runs asynchronously and the file row's `scan_passed` flag flips later. A GET request between upload and scan returns the file.

**Preconditions:** Upload handler writes the file row synchronously, dispatches scan async; download handler does not re-check scan status.

**Attack recipe:** upload the malicious file; immediately race `GET /files/<id>` to fetch it before the scan flips the flag.

**Confirmation signal:** download returns the file content with scan status still "pending" or "not run."

**Impact:** Virus/content-scan bypass; chains to `insecure_file_uploads.md`.

### Primitive: Multi-Part Upload Finalize Race

Primitive: S3-shape multi-part upload has `initiate → upload-parts → finalize`. Concurrent finalize calls on the same upload ID can create duplicate or corrupted objects.

**Preconditions:** Finalize endpoint non-atomic with the parts-list read; two concurrent finalizes race the parts-list.

**Attack recipe:** fire two parallel `POST /uploads/<id>/finalize` with different parts selections; the second one may finalize with the first's parts list.

**Confirmation signal:** finalized object has unexpected part composition.

**Impact:** Object-content confusion; chains to `insecure_file_uploads.md § Multi-Part Finalize`.

## GraphQL Mutation Races

### Primitive: Alias-Batching for Rate-Limit Bypass

Primitive: A single GraphQL request with N aliased mutations is one HTTP call to the rate limiter but N resolver invocations. The rate limit counts HTTP requests, the state changes count resolver calls.

**Preconditions:** Server rate-limits at the HTTP layer; the GraphQL resolver layer has no per-operation counter.

**Attack recipe:**

```graphql
mutation BulkRedeem {
  a: redeem(code: "SAVE50")
  b: redeem(code: "SAVE50")
  c: redeem(code: "SAVE50")
  # ... N aliases
}
```

Fire one HTTP request; N resolver invocations execute. If the coupon's "already used" check runs per-resolver and the resolver layer has no transactional serialization, all N succeed.

**Confirmation signal:** N successful redemptions from one HTTP request; coupon's used-count is N.

**Impact:** Rate-limit × batch-amplification; a 100-req/hour rate limit with N=500 batching = 50,000 state changes per hour. See `race_conditions_novel_deep.md § GraphQL Alias Rate-Limit Bypass` for the Directus CVE-2024-39895 instance.

### Primitive: Batched-Operation Transaction Scoping

Primitive: GraphQL batching (`[{query: ...}, {query: ...}]` array) is parsed as multiple operations, each resolved in its own transaction. A race between the operations' internal transactions permits cross-operation state staleness.

**Preconditions:** Resolver uses per-operation transactions, not per-request.

**Attack recipe:** send a batch of `[writeOp, readOp]` where `readOp` depends on `writeOp`'s state. If the batch is parallelized at the resolver layer, `readOp` can run before `writeOp` commits.

**Confirmation signal:** `readOp` returns pre-`writeOp` state despite the batch ordering.

**Impact:** State-visibility inconsistency within a batch; usable as a primitive to observe pre-write state in combination with a mutation.

## Composite Chain Construction

The race condition grants a transient inconsistency the next skill owns. Chain by capability transferred:

### Chain 1: Race → IDOR → Data Exfiltration

**Nodes:**

- Race precondition: unauthenticated access to the registration endpoint.
- Race postcondition: new user record with incomplete scope-binding (partial-construction window).
- IDOR precondition: valid session on an unscope-bound user.
- IDOR postcondition: read on another user's resource.
- Exfiltration: data of other users.

Attack: register a user; race the scope-binding step; use the unscoped session to IDOR other users' resources. See `idor.md § Partial-Construction` for the IDOR layer.

### Chain 2: Race → Cache Poisoning → Cross-User Impact

**Nodes:**

- Race precondition: endpoint that computes a per-user response but writes a cache entry keyed on something attacker-controlled.
- Race postcondition: cache contains the attacker's response under a cache key other users will hit.
- Cache-poisoning: other users receive the attacker's response.

Attack: race the response-generation vs the cache-write to inject attacker-chosen cache contents. See `header_injection.md § Cache Poisoning` for the delivery layer.

### Chain 3: Race → Business-Logic Invariant Break → Financial Impact

**Nodes:**

- Race precondition: check-then-act on a conservation invariant (balance, coupon, inventory).
- Race postcondition: invariant broken by one unit (double-spent, over-redeemed).
- Business-logic exploit: amplify the one-unit break into material value (sell the over-redeemed coupon, cash out the over-credited balance).

Attack: race the invariant-check endpoint; cash out via a legitimate withdrawal. See `business_logic.md` for the amplification layer.

### Chain 4: Race → OAuth Code Duplication → Session Persistence

**Nodes:**

- Race precondition: valid OAuth authorization code or refresh token.
- Race postcondition: two tokens for one grant.
- Session persistence: one token escapes the user's revocation.

Attack: dual-exchange the OAuth code; the second token persists past the user's revoke-all-sessions action. See `authentication_jwt.md § Token Revocation Race` for the session layer.

### Chain 5: Race → Rate-Limit Bypass → MFA Brute-Force

**Nodes:**

- Race precondition: MFA endpoint that validates OTP with a race window.
- Race postcondition: effective rate limit of N × window (where N is the parallelism factor).
- Brute-force: 10^6 OTP space becomes practical.

Attack: fire parallel OTP guesses faster than the rate counter updates. See `authentication_jwt.md` for the MFA layer and `race_conditions_novel_deep.md § OpenBao TOTP Rate-Limit Bypass` for a worked instance.

## Verification Discipline

Every race claim must survive these checks:

1. **Alignment check** — measure the server-side arrival slack of the batch; if the slack exceeds the critical section window, the race is unreproducible and the claim is a conjecture.
2. **Repetition** — run the attack 10 times; report the success rate. A one-shot success at 1-in-10 is a weak claim; one at 10-in-10 is strong.
3. **Durability** — the state change must survive a request/response cycle; a cached-only effect that disappears after cache TTL is not a durable finding.
4. **Isolation of cause** — pair the attack run with a control run under lock/transaction; if the control also produces the same outcome under high load, the race is not the cause.
5. **Narrow the critical section** — identify the exact source lines that constitute the check and the write; the finding is the gap between them.

## Summary

Advanced race-condition exploitation moves past the single-counter demo into cross-endpoint window construction, partial-construction catalog, idempotency scope diagnostics, distributed-lock Redlock critique, SQL anomaly worked examples, cross-service saga analysis, OAuth / OTP consumption races, and the GraphQL alias-batching rate-limit bypass. Each primitive is reachable when the server-side critical section is wider than the client-side alignment slack; single-packet HTTP/2 compresses the slack to sub-millisecond, and the exploitation question becomes which critical section is exploitable, not whether alignment is achievable. The chaining surface — into IDOR, business-logic, caching, OAuth, and MFA — is what turns a one-unit invariant break into material impact.
