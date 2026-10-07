---
name: business-logic-advanced-deep
description: Advanced business-logic exploitation — state-machine formalism, concurrency and idempotency primitives, saga/compensation attacks, cross-service invariant drift, approval binding, timing-boundary exploitation, monetary primitives, and entitlement-transition attacks
sibling: business_logic
load_when: scan_mode == "deep"
---

# Business Logic — Advanced Deep

Advanced-tier primitives for business-logic exploitation. The base skill owns scope, standards mapping, and basic invariant classes; this sibling owns full technique treatments at the concurrency, saga, cross-service, approval-binding, and monetary-primitive tier. Load the base in parallel for the WSTG-BUSL and API6:2023 standards framing and the entry-level worked scenarios; load `business_logic_novel_deep` for the 2024–2026 frontier.

Every sub-primitive below carries Primitive / Preconditions / Attack recipe / Confirmation / Impact. The content unit is the exploitation primitive, not the CVE — business logic is per-application and the technique class is what transfers between targets.

## State-Machine Formalism

Business logic is a finite-state machine with invariants attached to states and transitions. Modeling the machine before testing turns `BUSL-06 Workflow Circumvention` from a guess into a search over edges that lack a server-side guard.

### Primitive: Transition Guard Omission

**Primitive**: a state transition `S → S'` enforced client-side but not server-side.

**Preconditions**:
- The service exposes the transition as a direct API endpoint (or the same handler is reachable through a background job, retry queue, or admin tool).
- The client wizard enforces an ordering (`A → B → C`) that the server accepts in any order.
- A transition reads a precondition from in-request state (a signed token, a client-supplied flag) rather than from the authoritative store.

**Attack recipe**:
1. Walk the happy path through the UI; capture every request.
2. Draw the state machine; note the state after each hop.
3. For each transition `T`, call it from a prior state the UI never sends it from (e.g. call `confirm_order` before `apply_coupon`; call `refund` before `capture`; call `review_approve` before `review_submit`).
4. For each transition that uses a token (`stepToken`, `approvalId`), re-present it from a different session or principal.
5. For transitions behind a feature-gated UI, call the endpoint directly even when the UI does not expose it (BUSL-02 Forge Requests).

**Confirmation**: the resource reaches a state the state-diagram does not permit — a shipped order with no payment, a refunded transaction with no capture, an approved review with no submission. The authoritative store (not the UI) shows the illegal state.

**Impact**: free goods or services, premature privileges, bypassed step-up/anti-fraud, lost audit trail integrity.

### Primitive: Terminal-State Re-Entry

**Primitive**: a state marked terminal (`canceled`, `refunded`, `expired`, `completed`) accepts another transition that logically only applies to a live state.

**Preconditions**:
- The transition handler does not check `is_terminal(state)` as a guard.
- The audit log is append-only but the state transition itself overwrites.

**Attack recipe**:
1. Drive a resource to a terminal state (`cancel` an order; `refund` a payment).
2. Re-issue the live-state operation (`ship`, `fulfill`, `capture`).
3. If the second operation succeeds, the resource has resurrected from terminal — the state machine admits a cycle it shouldn't.

**Confirmation**: audit log shows `canceled` → `fulfilled` transition; or `refunded` → `captured`.

**Impact**: ship after cancel keeps goods and refund; capture after refund over-charges; shipment of a refunded order lets attacker keep goods.

### Primitive: Parallel-Terminal-State Fork

**Primitive**: two concurrent requests drive the same resource into two mutually-exclusive terminal states.

**Preconditions**:
- Terminal-state transitions share no mutual-exclusion lock.
- The state field is written as a single column but no `CHECK` constraint enforces one-terminal-at-a-time.

**Attack recipe**:
1. Identify two terminal transitions on the same resource (`cancel` and `complete`; `refund` and `settle`; `approve` and `reject`).
2. Fire both in parallel via a single-packet request pair.
3. Each writer commits; the final state is non-deterministic but both side-effects have fired (`cancel` released inventory AND `complete` charged the customer).

**Confirmation**: inventory decremented AND customer charged for a canceled order; or refund issued AND capture settled for a single payment.

**Impact**: double-dip (fulfillment + refund, or inventory consumed + credit issued).

## Concurrency and Race-Shaped Business Logic

Concurrency primitives in business logic rarely require microsecond-tight races — a 10–100ms window is enough to double-apply a coupon, double-claim a seat, or double-redeem a credit. The exploitation technique is in the business flow, not the network timing. Load `race_conditions` for the single-packet technique and request-tightening; this section covers the business-shaped primitives.

### Primitive: Decrement-Guard Race on Shared Counter

**Primitive**: `read; check (balance ≥ amount); write (balance -= amount)` without an atomic guard allows two concurrent withdrawals to each pass the check and the counter to go negative or over-consume.

**Preconditions**:
- Business counter stored as a mutable integer with no `WHERE balance >= $amount` guard on the UPDATE.
- No row-level lock or optimistic-concurrency-control (OCC) `version` column.
- Business invariant: `balance ≥ 0` (or `remaining_uses ≥ 0`).

**Attack recipe**:
1. Provision an account with `balance = 100`.
2. Fire two requests `POST /withdraw {amount: 100}` as a single-packet pair.
3. Both read `balance = 100`, both pass `≥ 100` check, both write `balance = 0` (or in some implementations `balance = -100` because each writer subtracts from its own stale read).

**Confirmation**: ledger shows two withdrawals of 100 against a 100 starting balance; final balance is 0 or negative; two "success" responses.

**Impact**: double-spend of credit, double-redemption of coupon, double-claim of seat/trial, double-apply of discount.

### Primitive: Idempotency-Key Scope Collision

**Primitive**: the service dedups on `Idempotency-Key` alone; a key reused across principals or across bodies returns a cached response or executes the newer body under the older identity.

**Preconditions**:
- `cache[idempotency_key] -> cached_response` keyed only on the header.
- The attacker can obtain or guess a victim's `Idempotency-Key` (shared log, server-generated sequential key, HAR capture, dev-tool dump).

**Attack recipe (variant A — read someone else's result)**:
1. Observe victim's key `IK-abc`.
2. Send `POST /charge` with `Idempotency-Key: IK-abc` and your own body.
3. Service returns the victim's cached response, which may include their `payment_method_id`, `charge_id`, `customer_id`.

**Attack recipe (variant B — overwrite behind the key)**:
1. Send `POST /create-order` with `Idempotency-Key: IK-attacker` and body A, succeeding.
2. Immediately send `POST /create-order` with the same key but body B.
3. If the service only consults the key, it returns the cached success for body A; but if the retry logic retroactively bills body B against the first result, body B is effectively free.

**Confirmation**: cached response reveals cross-user data (variant A); or two orders created with one payment (variant B).

**Impact**: cross-user data leak; free order via retry collision.

### Primitive: Compensating-Transaction Elision

**Primitive**: a saga's forward step commits but the compensating step is skipped because the orchestrator classifies the failure as "transient" and retries forward.

**Preconditions**:
- Saga orchestrator distinguishes "transient" vs "permanent" failure of each step.
- Compensation runs only on "permanent" failure.
- Attacker can induce a condition the orchestrator classifies as transient (connection reset, 503, timeout) between steps.

**Attack recipe**:
1. Trigger a multi-step business flow (place order → charge → fulfill).
2. Allow the charge step to commit.
3. Induce a transient failure between charge and fulfill (close the connection on the webhook, time out the downstream service). Depending on the compensation policy, charge may be retained while fulfill is retried indefinitely — net: pay once, fulfilled many times.
4. Alternatively: induce the failure before charge and after a "credit check" step that pre-reserves budget — budget-reservation holds forever.

**Confirmation**: audit log shows charge committed, fulfill retried N times, no compensation; or budget-reservation that outlives its parent saga.

**Impact**: over-fulfillment (goods shipped per retry); frozen inventory/budget without matching commit.

### Primitive: Outbox Dedup Window Insufficient

**Primitive**: an outbox-pattern publisher dedups events within a window; events published outside the window are treated as new.

**Preconditions**:
- Outbox publisher uses `event_id` + a 5-minute dedup window.
- Attacker can delay or replay from a dead-letter queue after the window closes.

**Attack recipe**:
1. Observe or trigger an event (`payment.succeeded`).
2. Capture it from a replay-visible endpoint (webhook retry UI, DLQ dashboard, developer-mode replay button).
3. Replay after the dedup window closes.
4. Consumer treats it as a fresh event and re-runs fulfillment.

**Confirmation**: downstream service runs fulfillment twice on a single business event; audit log carries two `fulfilled_at` timestamps for the same `order_id`.

**Impact**: duplicate fulfillment, duplicate refund, duplicate notification/communication, duplicate loyalty-point grant.

## Idempotency Primitives at Depth

The idempotency contract is: `(principal, action, idempotency_key)` → one effect. Weaknesses live in the key scope, storage, and body-binding.

### Primitive: Key Not Bound to Body Hash

**Primitive**: the server treats `(principal, idempotency_key)` as the dedup key; a second request with the same principal and key but a different body returns the cached response for the original body or (worse) runs the new body and still returns the original response.

**Preconditions**:
- Idempotency storage: `redis.set(f"idem:{principal}:{key}", response)` without binding the request body.

**Attack recipe**:
1. Send `POST /transfer {idempotency_key: K, to: alice, amount: 1}` → succeeds.
2. Send `POST /transfer {idempotency_key: K, to: attacker, amount: 1000}` → service returns success, but which transfer actually happened?
3. If the second request writes before responding and the cache returns the first response, the attacker transfer happened and the client sees the "success" of the first — this is a bypass of the user's intent.

**Confirmation**: ledger shows the second body's transfer with the first response's framing.

**Impact**: silent redirection of value or action, with the audit response signaling the "approved" original.

### Primitive: Key Stored in Cache That Evicts

**Primitive**: idempotency keys stored only in Redis with LRU eviction; under memory pressure the key disappears and a retry runs again as if new.

**Preconditions**:
- Idempotency state in a cache (not a durable store).
- Attacker can induce cache pressure (fill the cache with other keys).

**Attack recipe**:
1. Capture or wait for a billable event with an idempotency key.
2. Flood the cache with other idempotency keys (if the service accepts arbitrary keys and stores them).
3. Replay the original with the same key — if evicted, it re-runs.

**Confirmation**: double-execution of a billable action against a single idempotency key.

**Impact**: double-charge, double-refund, double-notification.

### Primitive: Key Scoped to Request Line Only

**Primitive**: idempotency key included in path but not re-verified against the auth principal or tenant — cross-principal reuse of the key cross-pollutes dedup.

**Preconditions**:
- Idempotency key stored under `{action}:{key}` without principal in the composite.

**Attack recipe**:
1. User A sends `POST /transfer idempotency_key=K`.
2. Attacker (user B, different account) sends `POST /transfer idempotency_key=K`.
3. Dedup matches; B gets A's cached response or A's state write.

**Confirmation**: cross-principal cross-pollination visible in audit log.

**Impact**: cross-user state capture.

## Saga, Compensation, and Outbox Attacks

Sagas are long-running transactions decomposed into local commits + compensations. Every saga carries three invariants: **progress** (steps advance), **termination** (saga ends in commit or full-compensation), and **isolation** (concurrent sagas don't trample each other). Each invariant is a bug class.

### Primitive: Compensation Without Forward

**Primitive**: the compensating endpoint is directly callable without the forward step having happened — a direct POST to `/refund` without a prior `/charge`, or `/release-inventory` without a prior `/reserve`.

**Preconditions**:
- Compensation handler exposed as an API endpoint.
- Compensation reads from request body (resource ID) rather than from a saga-state store that verifies the forward step completed.

**Attack recipe**:
1. Create a resource (`order_id = 42`) that normally only passes through the saga's forward path.
2. Call the compensating endpoint directly: `POST /orders/42/refund-shipping-cost`.
3. If the compensation runs without checking that shipping was ever charged, you receive a refund for a non-event.

**Confirmation**: ledger shows refund entry with no matching charge.

**Impact**: synthetic credits/refunds; ability to bank store credit without purchase.

### Primitive: Partial Rollback with Side Effects

**Primitive**: a saga step's compensation reverts the primary effect but leaves a side effect (notification sent, loyalty points awarded, inventory decremented) intact.

**Preconditions**:
- Compensation function updates only the primary table.
- Side effects are published to other services that have no compensation listener.

**Attack recipe**:
1. Trigger the forward path and let it reach the step that fires the side effect.
2. Cause the saga to fail after that step (induce a downstream service error).
3. Compensation reverts the primary; side effects persist.
4. Repeat to accumulate side-effect value.

**Confirmation**: side-effect records (loyalty points, communications, warehouse-pick-pack events) accumulate while primary ledger shows no corresponding orders.

**Impact**: unauthorized accrual of side-effect value; inventory corruption; notification spam.

### Primitive: Double-Forward Through Idempotent-Looking Compensation

**Primitive**: a compensation endpoint accepts the forward's parameters and, under some error paths, executes the forward instead.

**Preconditions**:
- Shared handler for `charge` and `refund` dispatched by a `direction` field.
- Error-recovery code falls back to the default `direction`.

**Attack recipe**:
1. Trigger a refund with a crafted body (missing field, type mismatch) that drives the handler into the error branch.
2. The error branch logs and silently defaults to `direction = charge`.
3. The user is charged instead of refunded.

**Confirmation**: ledger shows a charge where a refund was requested; audit log notes the fallback.

**Impact**: direction inversion of a monetary flow.

## Cross-Service Invariant Drift

In a microservice system, each service enforces its local invariants; the system-level invariants that cut across services often have no owner.

### Primitive: Pricing Service vs Fulfillment Service Divergence

**Primitive**: pricing-service calculates a total from line items at step 1; fulfillment-service re-reads line items at step 3 and bills based on *current* catalog price.

**Preconditions**:
- Two services with their own data stores or caches.
- No signed "quote" bound to specific line-item snapshots.

**Attack recipe**:
1. Add a cart with item X at price P.
2. Capture the quote.
3. Change the item (increase quantity, swap for a more expensive variant via a `PATCH /cart/item`).
4. Finalize. Pricing-service sees the quote; fulfillment-service sees the new items. Which one is billed depends on the stale-read ordering.

**Confirmation**: billed total differs from invoice line items.

**Impact**: pay less than fulfilled, or in reverse be billed for items not received.

### Primitive: Header-Trust at Internal Hop

**Primitive**: an internal service trusts `X-User-Id` or `X-Role` from an edge that is reachable externally without the expected auth check.

**Preconditions**:
- Internal service bound on `0.0.0.0` or reachable through SSRF.
- Internal service's `request.user_id = request.headers['X-User-Id']` without consulting a signed principal.

**Attack recipe**:
1. From the public surface, find an endpoint that performs SSRF (`url_import`, `webhook_forward`, `preview_render`), or reach an exposed internal port.
2. Send a request to the internal service with forged `X-User-Id: 1` or `X-Role: admin`.
3. The internal service accepts the identity and performs the privileged action.

**Confirmation**: ledger shows action under victim's identity, logs show origin IP from an unexpected source.

**Impact**: privilege escalation to any identity the attacker can enumerate; `broken_function_level_authorization` chain to admin functions. Load `header_injection` for the smuggling primitives that put forged headers on an internal-service request.

### Primitive: Event-Schema Drift

**Primitive**: producer and consumer services evolved their event schema at different rates; a producer-side optional field is read authoritatively by the consumer.

**Preconditions**:
- Shared event schema versioned loosely (JSON-with-optional-fields, additive compat but no semantic contract).
- Producer accepts attacker influence over the optional field.

**Attack recipe**:
1. Identify an event the consumer reads with a new optional field (e.g. `admin_override: true`, `trusted: true`, `priority: urgent`).
2. From the producer's input surface, inject the optional field.
3. Consumer processes the event with the attacker-authored metadata.

**Confirmation**: downstream behavior changes to match the attacker-controlled flag; audit log shows the event carried the flag with the producer's identity.

**Impact**: cross-service privilege; bypass of consumer-side policy; approval-free elevation.

### Primitive: GraphQL Resolver Authorization Drift

**Primitive**: a GraphQL mutation enforces authorization on the root field but a nested field in the same selection set resolves through a different authorization code path.

**Preconditions**:
- GraphQL schema with field-level resolvers.
- Root mutation guarded by `@requires(role: USER)`; a nested field's resolver has no guard because it was written as "read-only" but mutates on a lazy backend.

**Attack recipe**:
1. Introspect the schema; identify fields whose resolvers call out to privileged backends.
2. Compose a mutation that reaches the nested field (via a field alias or nested selection in a mutation response).
3. Verify the nested resolver fired despite the root being otherwise innocuous.

**Confirmation**: audit log on the backend shows a call from the GraphQL layer under the attacker's identity for an operation the root mutation shouldn't have reached.

**Impact**: access to privileged backend operations through a schema-side-channel.

## Approval Binding and Separation of Duties

Approval workflows add a human (or second-service) checkpoint. The invariant is **approval binds the exact arguments** and **approver ≠ requester**. Both are frequently broken.

### Primitive: Approval Binds Signature, Not Arguments

**Primitive**: approval token is a signed blob; executor verifies the signature but not that the arguments at execution time still match the signed arguments.

**Preconditions**:
- Approval token: `sign({request_id, approver_id, timestamp})` without a hash of the request body.
- Executor: `verify(token); execute(current_request)`.

**Attack recipe**:
1. Submit a benign request (`transfer $1 to self`).
2. Get it approved.
3. Capture the approval token.
4. Submit a malicious request (`transfer $10,000 to attacker`) with the same request_id.
5. Executor verifies the token (valid), executes current request.

**Confirmation**: ledger shows the malicious request executed; audit log shows the benign request was approved.

**Impact**: approval laundering — turn any benign approval into an arbitrary action.

### Primitive: Approver = Requester via Role Transition

**Primitive**: separation-of-duties enforced by requester-ID ≠ approver-ID, but a user can transition between roles (requester → approver) and then approve their own prior request.

**Preconditions**:
- Approval queue persists requests across role transitions.
- Approval check reads the current approver's ID vs the requester's ID at approval time, not at request time.

**Attack recipe**:
1. As user U in role Requester, submit a privileged request.
2. Transition U to role Approver (via a legitimate role-change workflow, perhaps triggered by a prior privilege escalation).
3. Approve the queued request as U.
4. The system logs `requester=U, approver=U` but applies the privileged action.

**Confirmation**: audit log shows the same principal in both slots.

**Impact**: self-approval of privileged actions.

### Primitive: Approval TTL Honored at Approve-Time Only

**Primitive**: approval expires 24h after issuance; executor verifies the token's `exp` claim but not that the executed action occurs within an additional business-tight window.

**Preconditions**:
- Approval TTL enforced only via JWT `exp`.
- Executor accepts and executes approved actions at any time within TTL, including after the business state has shifted.

**Attack recipe**:
1. Request and get approval for a `transfer $1000` action.
2. Wait 23h59m.
3. Execute. The transfer completes against the current balance, which may have changed significantly since approval.

**Confirmation**: large time-gap between `approved_at` and `executed_at` with no re-validation of underlying state.

**Impact**: delayed execution against stale state; the approval conveys authority that outlives its risk assessment.

### Primitive: Out-of-Band Approval Channel Divergence

**Primitive**: approval accessible via multiple channels (dashboard, email magic-link, Slack bot); one channel's approval endpoint does not consult the current state.

**Preconditions**:
- Multi-channel approval infrastructure.
- At least one channel's handler lacks a state consistency check.

**Attack recipe**:
1. Submit a request.
2. Approve via Slack bot — Slack handler calls `/internal/approve?request_id=X&token=T` which only verifies the token.
3. The dashboard would have shown the request as `withdrawn`; Slack approves it anyway and the executor runs it.

**Confirmation**: audit log shows approval source as Slack; dashboard shows the request was never un-withdrawn.

**Impact**: approve-after-withdrawal; weakest-channel-wins.

## Timing-Boundary Exploitation

Business logic often has calendar-shaped guards (trial expires at midnight; grace period ends 24h after cancellation; subscription cycles at month-start). These boundaries become race windows.

### Primitive: Trial Expiry at Clock-Skewed Services

**Primitive**: trial expiry enforced at service A at `T = midnight`; service B's clock is 30 seconds behind; a request at `T + 15s` is treated as live at B but expired at A, or vice versa.

**Preconditions**:
- Trial expiry stored as a timestamp.
- Services do not share a clock-synchronized source of truth for "now".

**Attack recipe**:
1. Observe trial expiry time (`exp = 2026-10-04T00:00:00Z`).
2. Submit a privileged request at `T = exp + 10s`.
3. If service B (slow clock) processes the request before service A (fast clock) checks expiry, B treats the trial as live.

**Confirmation**: successful privileged request after documented expiry.

**Impact**: free trial extension; one-time per-trial actions re-triggerable.

### Primitive: Daylight-Saving Boundary

**Primitive**: a daily counter resets at midnight local time; during a DST transition, "midnight" occurs twice (fall back) or not at all (spring forward), driving the counter to either reset twice or never.

**Preconditions**:
- Counter reset keyed to local-time midnight rather than UTC day boundary.
- No special-case handling for DST transition dates.

**Attack recipe**:
1. On the fall-back date (02:00 → 01:00 local), consume the daily quota in the hour before 02:00.
2. Wait for the DST rollback; the counter resets at the second 01:00.
3. Consume the daily quota again.

**Confirmation**: counter shows two full-period consumptions on a single calendar day.

**Impact**: 2× daily-limit on DST transition dates (per year, per user).

### Primitive: Grace-Period Overlap

**Primitive**: a canceled subscription enters a 30-day grace period during which cancellation is reversible; a user cancels, re-subscribes within grace, retains the old period plus the new.

**Preconditions**:
- Grace-period handling re-enables the old subscription without pro-rata adjustment.
- New-subscription path treats the user as a fresh signup, awarding promotional pricing.

**Attack recipe**:
1. Hold an active paid subscription.
2. Cancel at day 5 of a 30-day cycle; grace through day 35.
3. On day 10 (within grace), re-subscribe via the "new signup" flow with a promo code.
4. Grace period re-activates the first subscription; promo flow creates a second; now you have 55+ paid days for the price of ~5 + promo.

**Confirmation**: billing log shows overlapping subscription periods.

**Impact**: paid service for below cost; stacking of promos with existing subscriptions.

### Primitive: Rate-Limit Window Pre-Warm

**Primitive**: rate-limit window `[T, T+60s]`; attacker fires the budget in the final second of one window and the first second of the next, doubling throughput at the boundary.

**Preconditions**:
- Fixed-window rate limiter (not sliding window).

**Attack recipe**:
1. Observe the rate-limit window (e.g., 100 req/min, resets on-the-minute).
2. At `T + 59.5s`, fire 100 requests.
3. At `T + 60.5s`, fire 100 more.
4. Total: 200 requests in ~1s.

**Confirmation**: 200 requests served in <2s; rate-limit returned 200 OK for both bursts.

**Impact**: bypass of per-minute rate limits by 2×; applied to credential-stuffing, scraping, inventory-hoarding.

## Monetary Primitives

Money has unique invariants: conservation, non-negativity, finite precision. Each is a bug class.

### Primitive: Decimal/Float Rounding Favor

**Primitive**: price computations in floats accumulate error; rounding at the wrong step favors the attacker.

**Preconditions**:
- Prices stored or computed in `float` or `double` rather than fixed-point/decimal.
- Rounding applied at each line item (not at the final total).

**Attack recipe**:
1. Order 1,000,000 items at $0.00001 each. Total should be $10.
2. Per-item cost rounds down to $0.00000 (zero). Total: $0.
3. Order ships; billed $0.

**Confirmation**: large quantity of a cheap item fulfilled at zero cost.

**Impact**: free goods at scale; this is a measured primitive on real e-commerce stacks that use per-item rounding.

### Primitive: Signed-Amount Reversal

**Primitive**: a monetary amount field accepts a negative value, inverting the direction of flow.

**Preconditions**:
- Transfer/refund/credit handler accepts an `amount` field without `amount > 0` validation.
- Downstream processor executes the operation without re-checking the sign.

**Attack recipe**:
1. Submit `POST /refund {amount: -100}` to a service that normally refunds positive amounts.
2. The refund logic computes `balance += amount` → `balance -= 100` (the inverse of a refund — a charge).
3. Or submit `POST /transfer {from: me, to: alice, amount: -1000}` → funds flow from alice to me.

**Confirmation**: ledger shows a value flowing in the direction opposite the intent.

**Impact**: attacker-initiated charges or pulls against other accounts.

### Primitive: FX Round-Trip Arbitrage

**Primitive**: convert currency A → B → A within a quote window; the FX markup differs between the two conversions, netting a positive amount.

**Preconditions**:
- Multi-currency wallet.
- FX conversion applies a markup/spread.
- Round-trip conversions permitted within a short window.

**Attack recipe**:
1. Hold $100 in USD.
2. Convert to EUR; receive €85 at mid-rate × (1 - spread).
3. Immediately convert back to USD at the current mid-rate × (1 - spread).
4. If one of the two conversions runs on a stale rate (cached quote), the round-trip may net positive.

**Confirmation**: USD-denominated balance after round-trip > starting USD.

**Impact**: synthetic value creation; at scale (automated), extracts predictable yield.

### Primitive: Tax Rounding Per-Item vs Per-Order

**Primitive**: tax computed per line item rounds to the nearest cent; summing per-item taxes drifts from a per-order tax computation.

**Preconditions**:
- Tax applied per line item.
- Rounding at each line.

**Attack recipe**:
1. Build a cart with many low-value items where per-item tax is $0.004 (rounds to $0.00).
2. Total tax: $0 (per-item sum). Per-order tax (if it had been applied): $0.40.
3. Service bills per-item; tax undercollected.

**Confirmation**: tax ledger discrepancy; VAT/sales-tax auditor flags under-collection.

**Impact**: tax leakage; at e-commerce scale this is also a compliance issue.

## Entitlement and Role-Transition Primitives

### Primitive: Stale Entitlement Cache

**Primitive**: entitlement reads cached for N minutes; downgrade reflected at the policy service but not in the cache.

**Preconditions**:
- Entitlement check: `cache.get(user_id) ?? refetch()`.
- Cache TTL > revocation requirement.
- No cache invalidation on downgrade.

**Attack recipe**:
1. Hold premium.
2. Trigger a cache warm (any premium-feature access).
3. Downgrade (cancel; the server records non-premium).
4. Access the premium feature again within TTL; cache returns `premium`.

**Confirmation**: paid feature usable after downgrade for the cache-TTL duration.

**Impact**: premium access for one TTL window per downgrade cycle; iterate.

### Primitive: Downgrade-Then-Refund-Then-Upgrade Loop

**Primitive**: downgrade issues a pro-rata refund; refund credited; immediate upgrade billed from the new credit; result: free month.

**Preconditions**:
- Pro-rata refund on downgrade.
- Credit stored as redeemable balance (not immediately refunded to card).
- Upgrade bills from available credit before charging card.

**Attack recipe**:
1. On day 1, upgrade to premium at $30/mo.
2. On day 15, downgrade to basic — service refunds $15 to balance.
3. On day 15, upgrade back to premium — service bills $15 from balance (free) + $0 (new charge, no pro-rata because of same-month).
4. On day 30, repeat.

**Confirmation**: ledger shows multiple cycles with net cost < nominal subscription.

**Impact**: paid service for below cost.

### Primitive: JWT Role Not Revoked on Transition

**Primitive**: user's role revoked server-side; outstanding JWTs with the old role claim still authorize.

**Preconditions**:
- Role encoded in JWT claim.
- No token revocation list, or revocation applies only on next refresh.

**Attack recipe**:
1. Hold a JWT with `role: admin`.
2. Admin privileges revoked server-side (user demoted).
3. Replay the JWT for the remainder of its lifetime; privileged endpoints still succeed.

**Confirmation**: admin-only endpoint returns 200 for a user whose authoritative role is non-admin.

**Impact**: unauthorized privilege retention until JWT expires (minutes to hours).

### Primitive: Seat-Over-Allocation via Parallel Grant

**Primitive**: `grant_seat` increments the used-seats counter and checks against purchased-seats; two parallel grants both pass the check.

**Preconditions**:
- Seat counter stored without atomic guard.
- Concurrency reaches the seat-grant handler.

**Attack recipe**:
1. Account has 10 seats purchased, 9 used.
2. Fire two parallel `POST /seats {user: new1}` and `POST /seats {user: new2}` requests.
3. Both read `used=9`, both pass `9 < 10`, both write `used=10` — but the actual users granted is 11.

**Confirmation**: user count > purchased seat count.

**Impact**: seats-for-free; multiply with repeated iteration.

## Fraud-Detection and Misuse-Defense Evasion (BUSL-07)

WSTG-BUSL-07 Application Misuse Defenses covers the service's ability to detect that it is being abused. Attackers who understand the detection surface shape their traffic to pass through it.

### Primitive: Velocity-Threshold Evasion by Account Rotation

**Primitive**: fraud detection flags high-velocity actions per account; attacker spreads the action across many accounts to stay below each account's threshold.

**Preconditions**:
- Detection: `account.action_count_last_minute > N` triggers block.
- No cross-account or cross-identity correlation (device, IP, payment-fingerprint, email-domain pattern).

**Attack recipe**:
1. Discover the per-account threshold N.
2. Mint accounts at a rate that produces aggregate throughput ≥ target while each account stays below N.
3. For each account, perform N-1 actions.

**Confirmation**: aggregate harm matches intent; per-account logs stay below threshold; no fraud block.

**Impact**: scaled abuse (scalping, scraping, trial farming) that evades the velocity signal.

### Primitive: Device-Fingerprint Rotation Across Identity

**Primitive**: fraud detection correlates accounts via device fingerprint (canvas, WebGL, audio, font stack). Attacker randomizes fingerprint per account.

**Preconditions**:
- Detection relies on device fingerprint for cross-account correlation.
- No higher-order signal (behavioral biometrics, mouse-dynamics timing, network ASN patterns).

**Attack recipe**:
1. Use a fingerprint-randomization browser extension or headless-browser cluster with per-profile randomized fingerprints.
2. Each account registers from a unique fingerprint; correlation score stays below threshold.

**Confirmation**: fraud graph shows no cluster despite coordinated behavior.

**Impact**: trial farming, synthetic identity generation.

### Primitive: Behavioral-Baseline Priming

**Primitive**: an account's fraud score drops after N days of benign behavior; attacker pre-primes accounts with low-value legitimate activity, then executes the abuse once scored "trusted."

**Preconditions**:
- Trust score computed over account age + benign activity.
- Score is monotonic (does not drop quickly on single bad event).

**Attack recipe**:
1. Age accounts for the baseline-trust window (often 30–90 days) with low-value legitimate purchases.
2. On the Nth day, execute the abuse (large refund-and-rebook, coupon-stack, mass seat-grant).
3. The service's trust gate waives the extra verification step.

**Confirmation**: the aged accounts' actions bypass a step the fresh accounts hit.

**Impact**: higher-value abuse per account; evasion of signup-time fraud checks.

### Primitive: Honeytoken and Canary-Account Evasion

**Primitive**: the service plants honeypot resources (fake accounts, fake credit codes) that only an abuser would access; attacker enumerates and avoids them.

**Preconditions**:
- Honeypots have detectable patterns (sequential IDs that aren't real, obviously-high balances, specific metadata flags).
- Attacker can discover the pattern through normal enumeration.

**Attack recipe**:
1. Enumerate IDs via IDOR primitive; cluster responses by shape.
2. Honeypots often return anomalously (always-200 with fake data; or always-403 with a specific message).
3. Skip the honeypots; target real resources.

**Confirmation**: successful abuse of real resources; no detection trigger.

**Impact**: silent abuse that doesn't tip off the fraud team.

## Draft, Preview, and Shadow-Order Primitives

Business flows commonly expose draft, preview, or shadow versions of the committed flow. The shadow versions bypass validators the committed flow enforces.

### Primitive: Draft-Order Finalization With Stale Pricing

**Primitive**: a draft order is a saved cart with locked prices; finalizing a long-aged draft commits at the stale (lower) price even after catalog changes.

**Preconditions**:
- Draft orders persist price snapshots.
- Finalization does not re-price.

**Attack recipe**:
1. Create draft orders when prices are low (sale periods, promotional launches, pricing errors).
2. Hold the drafts indefinitely.
3. Finalize when prices have risen; service bills the draft's locked price.

**Confirmation**: order billed below current catalog price; invoice line items show historical prices.

**Impact**: attacker pays sale price indefinitely; at scale, undermines margin.

### Primitive: Preview-Rendered-As-Final

**Primitive**: a `preview` endpoint computes a response (invoice, shipment label, PDF) that is nearly identical to the finalized version; preview output is accepted as proof.

**Preconditions**:
- Preview and final share the same renderer.
- Preview output is accepted by downstream systems (shipping carrier, tax authority, insurance claim).

**Attack recipe**:
1. Generate a `preview` response for a scenario that would be rejected at finalize (negative amount, cross-tenant customer).
2. Capture the preview artifact (PDF, label, signed URL).
3. Present the preview artifact to a downstream system that doesn't verify finality.

**Confirmation**: downstream system acts on preview output as if it were a committed transaction.

**Impact**: fraudulent documents accepted; shipment labels generated without payment.

### Primitive: Admin-Impersonation Preview With Durable Side Effects

**Primitive**: an admin "preview as user" mode renders what the user would see; the preview mode has write side effects (writes to user's recently-viewed, warms their cache, triggers notification).

**Preconditions**:
- Impersonation preview reads from user context AND writes to user-side state.
- No separation between read-only "view-as" and side-effectful "act-as."

**Attack recipe**:
1. Confused-deputy: trick admin into "preview as attacker" where the preview itself writes to attacker's benefit (adds a credit, marks a reward "redeemed by admin").
2. Or audit-laundering: perform an action in "preview" mode where the audit log misattributes.

**Confirmation**: side effect visible in user state after an admin preview.

**Impact**: audit-trail laundering; cross-identity-boundary action.

## API Key and Service-Account Attacks

API keys and service accounts carry authority that is often broader than individual users', and their lifecycle controls are frequently weaker.

### Primitive: API-Key Quota Multiplication

**Primitive**: quota enforced per API key; attacker generates N keys to multiply quota.

**Preconditions**:
- Rate-limit or usage-quota keyed on API key.
- Per-tenant quota is absent or significantly higher.
- Key creation is unlimited or weakly rate-limited.

**Attack recipe**:
1. Enumerate the key-creation endpoint rate.
2. Create N keys.
3. Distribute workload across them.

**Confirmation**: aggregate throughput exceeds any single key's quota.

**Impact**: effectively unmetered usage; billed at per-key tier when effective usage is enterprise.

### Primitive: Service-Account-As-User

**Primitive**: a service account's token is accepted on endpoints meant for user tokens; the service account's broader scopes grant access to resources users shouldn't reach.

**Preconditions**:
- Token verification checks signature + expiry but not token-type (`user` vs `service`).
- Service account has broader scopes.

**Attack recipe**:
1. Obtain a service account token (CI/CD leak, config file, exposed `.env`).
2. Use it against user-facing endpoints.
3. The user-facing handler's authorization layer sees the service account's scopes and permits actions.

**Confirmation**: user-scoped endpoint returns data a normal user wouldn't see (e.g., cross-tenant data via a service account scoped broadly).

**Impact**: cross-tenant access; privilege escalation to service-account tier.

### Primitive: Key Rotation Window Overlap

**Primitive**: when a key is rotated, the old key is accepted for a grace period; the grace period's end is enforced at the authentication layer but not the authorization layer.

**Preconditions**:
- Keys have `active_until` after rotation.
- Checks at authentication but not at authorization.

**Attack recipe**:
1. Compromise key K at time T.
2. User rotates to K' at time T+1; K's `active_until = T+24h`.
3. Attacker continues to use K for 24h, performing actions attributed to the pre-rotation state.

**Confirmation**: K accepted after rotation; audit log shows pre-rotation state continuing.

**Impact**: 24h-of-persistence on a compromised credential post-rotation.

## Multi-Tenant Isolation at Depth

### Primitive: Tenant-Key Missing From UPDATE

**Primitive**: a mutation `UPDATE table SET x = y WHERE id = $1` without `AND tenant_id = $2` is cross-tenant exploitable if the `id` is predictable or enumerable.

**Preconditions**:
- Row-level data store without row-level security.
- Application-layer tenant enforcement by convention (vulnerable to omission).

**Attack recipe**:
1. Enumerate IDs across tenants (via IDOR primitive — load `idor`).
2. Submit a mutation on an ID from another tenant.
3. If the UPDATE lacks `tenant_id = <my-tenant>`, the write succeeds.

**Confirmation**: cross-tenant state write visible in audit log and in the victim tenant's dashboard.

**Impact**: cross-tenant data integrity breach; often also PII exfil.

### Primitive: Shared Rate-Limiter Across Tenants

**Primitive**: rate-limit keyed on IP or API key without tenant scoping — tenant A's noisy neighbor exhausts tenant B's budget.

**Preconditions**:
- Rate limiter keyed on a shared axis (IP, API key, user) not on tenant.
- Shared infrastructure visible to multiple tenants.

**Attack recipe**:
1. From tenant A, fire the rate budget.
2. Tenant B, sharing the same IP via NAT or shared hosting, is also throttled.

**Confirmation**: tenant B receives 429s driven by tenant A's traffic.

**Impact**: denial of service to co-tenants; at scale, DoS against competitors on the same shared SaaS infrastructure.

### Primitive: Admin Aggregate View With Mutating Links

**Primitive**: a cross-tenant admin UI lets a privileged user see aggregated resources across tenants; action links on each row execute against the tenant whose row is clicked, without a per-click confirmation.

**Preconditions**:
- Admin UI with cross-tenant visibility.
- Action endpoints that trust the admin's identity but execute in the tenant's context.

**Attack recipe**:
1. As a staff admin, open the aggregate view.
2. Submit an action against a tenant's row — the admin's authority extends into that tenant's data.
3. If a lower-privileged staff role has the view but not the action, a confused-deputy via CSRF or a cross-tab navigation can re-authorize the action.

**Confirmation**: tenant audit log shows a staff-admin action without any approval or ticket.

**Impact**: staff-side insider risk; abuse surface for compromised admin accounts.

## Confirmation Methodology

A business-logic finding is confirmed by:

1. **Ledger evidence**: the authoritative store shows an invariant-violating state (`refunds > captures`, `used > purchased`, `balance < 0`, two terminals at once).
2. **Audit-log evidence**: the invariant-violating action is logged with its principal, timestamp, and arguments.
3. **Reproducibility**: the same sequence of requests, same timing, same accounts reproduces the violation on a fresh test tenant.
4. **Impact-direction evidence**: the violation benefits the attacker (not a visual-only inconsistency); the attacker holds a positive economic outcome.
5. **Durability**: the violation persists through the next reconciliation cycle (daily job, batch close, monthly billing).
6. **Isolation**: no legitimate feature produces the same state through its normal path.

A finding that fails any of these is a lead, not a confirmation. For time-bound exploits (DST, grace period), the proof includes the specific window; for concurrency, the proof includes the single-packet or parallel-tightened request pair.

## Chaining Depth

Advanced business-logic primitives compose with the full vulnerability surface:

- **BUSL + race + IDOR**: enumerate target IDs via IDOR, apply a racing coupon-redeem primitive against each (`idor` + `race_conditions` + this skill).
- **BUSL + mass assignment**: an under-protected DTO lets you set `credit_balance` or `role` directly — `mass_assignment` upstream, business-logic downstream.
- **BUSL + CSRF**: a victim is forced to approve a transition they didn't intend — `csrf` upstream, approval-binding downstream.
- **BUSL + SSRF → internal service**: SSRF reaches an internal service that trusts headers; forge `X-User-Id` to execute the business flow as another identity — `ssrf` + `header_injection` + this skill.
- **BUSL + GraphQL**: enumerate schema, discover field-level authorization drift, mutate privileged backends.
- **BUSL + webhook replay**: a captured webhook event is replayed outside its dedup window; downstream fulfillment runs twice — chain with `http_request_smuggling` to inject into internal consumers.
- **BUSL + JWT algorithm confusion**: a token's role claim bypasses signature verification; the business-logic layer trusts the role — load `authentication_jwt`.
- **BUSL + prototype pollution**: a merge sets `isAdmin` on the user object; the business-flow authorization reads the polluted field — load `prototype_pollution`.

Every chain's upstream primitive produces a precondition for the business-logic step: a predictable ID, a forged identity, a signed payload, a reached internal service, an elevated role claim.

## Verification Discipline

Before reporting:

- **Reproduce on a fresh test tenant** with no inherited state.
- **Test the fix candidate**: if the proposed fix is "add a WHERE clause," test the exploit after the fix; many fixes close only the visible path.
- **Measure impact at scale**: a $0.01 per-cycle exploit at 1000 cycles/day is a $3650/year loss. Report both unit and annualized impact.
- **Check for related invariants**: if `refund` is unbounded, is `credit_issue` also unbounded? Find class siblings before closing a report.
- **Confirm no pre-existing legitimate reason**: a goodwill-credit policy may explain some apparent discrepancies; the finding must be reproducible via policy-violating input.
- **Document the invariant class** in the finding — not just the single exploit sequence. The report should enable the engineering team to find class siblings they didn't ask about.

## Summary

Advanced business-logic exploitation reduces to four moves: break conservation at the ledger, break exclusivity at the state machine, break monotonicity at the counter, break closure at the saga. Each primitive here is a specific break: double-decrement races, idempotency-scope collisions, saga compensation-elision, approval-binding attacks, timing-boundary doubling, FX round-trips, entitlement-cache races. Chain upstream (IDOR → cross-tenant mutation; mass-assignment → role grant; CSRF → victim-driven approval; SSRF → internal-service header-trust) and downstream (audit log laundering, reconciliation evasion). The reusable unit is the invariant and the step that breaks it; CVEs are rare because the invariant lives in the application, not in a shared library. Load `business_logic_novel_deep` for the 2024–2026 frontier framing including API6:2023 scalping research and automated invariant-discovery methodology.
