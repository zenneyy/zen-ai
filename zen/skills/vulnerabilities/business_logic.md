---
name: business-logic
description: Business logic testing for workflow bypass, state-machine abuse, domain invariant violations, financial/entitlement flows, idempotency gaps, quota slicing, and multi-tenant isolation drift
---

# Business Logic Flaws

Business logic flaws exploit intended functionality to violate domain invariants: move money without paying, exceed limits, retain privileges after downgrade, split one action into unbilled fragments, or bypass approvals by racing them. They require a model of the business — ledgers, state machines, quotas, approvals — not just payloads. A request that is syntactically valid, authenticated, and authorized at the HTTP boundary can still break conservation of value, uniqueness, monotonicity, or exclusivity at the business layer. These flaws rarely carry CVEs because they are per-application; the content unit is the **invariant class**, and each test ends by proving a durable state change in the authoritative ledger or audit log.

## Standards Mapping

Business logic lives in two load-bearing OWASP sections, both current as of this writing:

- **OWASP WSTG v4.2 chapter 4.10 (Business Logic Testing)** enumerates nine numbered tests — `BUSL-01` Data Validation, `BUSL-02` Forge Requests, `BUSL-03` Integrity Checks, `BUSL-04` Process Timing, `BUSL-05` Function-Use Limits, `BUSL-06` Workflow Circumvention, `BUSL-07` Application Misuse Defenses, `BUSL-08` Upload of Unexpected File Types, `BUSL-09` Upload of Malicious Files. WSTG v5.0 is in development on `github.com/OWASP/wstg` but not yet stable — cite v4.2 numbering. The last two tests overlap with `insecure_file_uploads` and route there; the first seven are this skill's primary surface.
- **OWASP API Security Top 10:2023** introduced **API6:2023 Unrestricted Access to Sensitive Business Flows** (new in 2023 — in 2019 the API6 slot was Mass Assignment, now folded into API3:2023 BOPLA). API6:2023 codifies this class: workflows that pass authentication/authorization but violate business invariants — scalping limited inventory, reservation monopolization, fraudulent referrals, mass-coupon redemption. The 2023 edition is current; no 2024/2025 revision has been published.

Supporting standards: ASVS 5.0.0 (tag `v5.0.0_release`, 2025-05-30, launched at Global AppSec Barcelona 2025) is current; its section V11 covers business-logic requirements. OWASP Top 10:2025 (8th edition, Nov 2025) places Broken Access Control at A01 and Insecure Design at A06 — business-logic flaws commonly map to A06 when a workflow is designed without the required invariant.

## Attack Surface

- Financial logic: pricing, discounts, payments, refunds, credits, chargebacks, FX
- Account lifecycle: signup, upgrade/downgrade, trial, suspension, deletion
- Authorization-by-logic: feature gates, role transitions, approval workflows
- Quotas/limits: rate/usage limits, inventory, entitlements, seat licensing
- Multi-tenant isolation: cross-organization data, action, or counter bleed
- Event-driven flows: jobs, webhooks, sagas, compensations, idempotency keys
- Fraud/abuse: referrals, loyalty, waitlists, scalping, synthetic identity

## High-Value Targets

- Pricing/cart: price locks, quote-to-order, tax/shipping computation, bundle pricing
- Discount engines: stacking, mutual exclusivity, scope (cart vs item), once-per-user enforcement
- Payments: authorize/capture/void/refund sequences, partials, split tenders, chargebacks, idempotency keys, 3-D Secure step-up thresholds
- Credits/gift cards/vouchers: issuance, redemption, reversal, expiry, transferability
- Subscriptions: proration, upgrade/downgrade, trial extension, seat counts, meter reporting
- Refunds/returns/RMAs: multi-item partials, restocking fees, return window edges, double-channel refund
- Admin/staff operations: impersonation, manual adjustments, credit/refund issuance, account flags
- Quotas/limits: daily/monthly usage, inventory reservations, feature usage counters, API rate ceilings
- Referral/loyalty: self-referral, tier promotion, point accrual on refunded orders

## Threat Modeling and Scoping

Before testing, scope with intent — business-logic surfaces are large and generic fuzzing wastes effort.

- **Pick a money-shaped object**: order, invoice, transfer, refund, credit, voucher, seat, reservation, usage counter. Trace its lifecycle end to end.
- **Name actors**: unauth, basic user, premium, staff, admin, partner API, internal service, cron job, webhook sender. Each may enforce a different subset of invariants.
- **Name states**: inventory `on_hold | reserved | committed | released`; payment `pending | authorized | captured | settled | refunded`; subscription `trial | active | paused | canceled | past_due`.
- **Name invariants**: the four classes above (conservation, exclusivity, monotonicity, closure, scope) applied to this object.
- **Name adversarial goals**: free goods, free service, over-refund, dodge-step-up, grief denial, cross-tenant leak, inventory hoard, loyalty inflation.

The output of scoping is a short written list — one object, five actors, seven states, four invariants, three goals — before any request is sent.

## Reconnaissance

### Workflow Mapping

- Derive endpoints from the UI and proxy/network logs; map hidden/undocumented API calls, especially `finalize`, `confirm`, `complete`, `capture`, `settle`, `release` endpoints that transition state
- Identify tokens/flags: `stepToken`, `paymentIntentId`, `orderStatus`, `reviewState`, `approvalId`, `idempotencyKey`; test reuse across users/sessions, after partial failures, and after cancellation
- Document invariants in writing before testing: conservation of value (ledger balance), uniqueness (idempotency), monotonicity (non-decreasing counters), exclusivity (one active subscription), closure (every reservation ends in commit-or-release)

### Invariant Discovery

Start from the ledger, not the UI. For each monetary or quota-bearing object, name:

- **Conservation**: sum of credits = sum of debits across all accounts touched; `authorized ≥ captured ≥ settled`; `Σ refunds ≤ Σ captures`
- **Monotonicity**: refund windows close one way; subscription periods only advance; usage counters do not decrement after billing
- **Exclusivity**: one active trial per identity (by email, by phone, by payment instrument, by device); one role at a time; one active cart
- **Scope**: a discount applies to cart or item, not both; a coupon's `max_uses` is global, not per-channel; a credit cannot be applied to its own issuance
- **Closure**: a reservation ends in commit OR release; a saga runs to completion OR compensates; an approval binds to the exact arguments at approval time

If you cannot write down the invariant, the test is unfocused. Every finding is an invariant violation; the finding statement names which one.

### Input Surface

- Hidden fields and client-computed totals; server must recompute on trusted sources — flag any `total`, `tax`, `discount`, `price` field that the request *supplies* rather than the response *returns*
- Alternate encodings and shapes: arrays instead of scalars, objects with unexpected keys, null/empty/0/negative, scientific notation (`1e308`), ISO 8601 vs epoch time, decimal strings vs numbers
- Business selectors: currency, locale, timezone, tax region, shipping tier; vary to trigger rounding, ruleset changes, and jurisdiction-specific logic
- Draft/preview endpoints that mirror finalize behavior but skip some validations

### State and Time Axes

- Replays: resubmit stale finalize/confirm requests after state has moved; verify server rejects by state, not just by signature
- Out-of-order: call finalize before verify; refund before capture; cancel after ship; approve after reject; redeem a credit before it is issued (where issuance is async)
- Time windows: end-of-day/month cutovers, daylight saving, grace periods, trial expiry edges, warranty cutoffs, FX quote expiry

## Key Vulnerabilities

### State Machine Abuse (WSTG-BUSL-06 Workflow Circumvention)

- Skip or reorder steps via direct API calls; verify the server enforces preconditions on each transition rather than relying on a client wizard
- Replay prior steps with altered parameters (swap price after approval but before capture; change recipient after review but before send)
- Split a single constrained action into many sub-actions each under the threshold (**limit slicing**) — one $10k transfer disallowed, 100×$100 transfers allowed
- Skip optional-looking steps that turn out to carry invariants (skip terms-of-service to avoid a `requires_tax_region` check)
- Enter a terminal state through an unintended path (cancel-after-ship to retain goods; refund-after-benefit-consumed on digital goods)

### Concurrency and Idempotency (WSTG-BUSL-04 Process Timing)

- Parallelize identical operations to bypass atomic checks (create, apply, redeem, transfer, provision, grant seat) — classic single-packet race on `apply_coupon`, `redeem_credit`, `claim_seat`
- Abuse idempotency: key scoped to path but not principal → reuse other users' keys; or idempotency stored only in a cache that evicts under load; or the same key allowed if the body differs
- Message reprocessing: queue workers re-run tasks on retry without idempotent guards; cause duplicate fulfillment/refund by replaying a dead-letter payload
- Load `race_conditions` for exact race-window measurement and single-packet technique

### Numeric and Currency (WSTG-BUSL-01 Data Validation)

- Floating point vs decimal rounding; rounding/truncation favoring attacker at boundaries ($0.004 rounds down to $0.00 ⇒ item free)
- Cross-currency arbitrage: buy in currency A, refund in B at stale rates; tax rounding per-item vs per-order (per-item cents accrete into cumulative skim at scale)
- Negative amounts, zero-price, free-shipping thresholds, minimum/maximum guardrails, overflow boundaries (max int, max BigDecimal)
- Decimal-string vs number coercion: `"1e-500"` parses to 0 in one layer, to a tiny positive in another ⇒ differential bypass of a "amount > 0" check

### Quotas, Limits, and Inventory (WSTG-BUSL-05 Function-Use Limits)

- Off-by-one and time-bound resets (UTC vs local); pre-warm at T-1s and post-fire at T+1s across the midnight boundary
- Reservation/hold leaks: reserve multiple, complete one, release not enforced; backorder logic inconsistencies; dangling holds expire slowly and block legitimate purchase
- Distributed counters without strong consistency enabling double-consumption; CRDT-style eventual counters that converge upward only
- Per-user limits enforced per authenticated principal while per-tenant limit silently absent

### Refunds, Chargebacks, and Reversals

- **Double-refund**: refund via UI and support tool and API — three independent authorization paths that do not consult each other's history
- Refund partials summing above captured amount via timing between partial-ledger updates
- Refund after benefits consumed (downloaded digital goods, shipped items, services rendered) due to missing post-consumption checks
- Reverse-and-rebook: cancel a confirmed booking to release inventory, then rebook at a different price, keeping the delta

### Feature Gates and Roles

- Feature flags enforced client-side or at edge but not in core services; toggle names guessed or fallback to default-enabled
- Role transitions leaving stale capabilities (retain premium after downgrade; retain admin endpoints after demotion; JWT not revoked after role change)
- Entitlement caches: a user's entitlement cached for N minutes; downgrade reflected at the gateway but not the cached handler
- Workflow approval bound to a user, not to the user's current role — approval survives role revocation

### Multi-Tenant Isolation (API Top 10 adjacency)

- Tenant-scoped counters and credits updated without tenant key in the where-clause; leak across orgs
- Admin aggregate views allowing actions that impact other tenants due to missing per-tenant enforcement
- Shared pool resources (seat licenses, credit pools) where consumption from tenant A is accounted to tenant B through a stale join

### Null, Default, and Absent-Field Semantics

- **`null` as "unset the field"**: `PATCH /subscription {"end_date": null}` makes a trial permanent if the handler treats `null` as a sentinel for "no expiry" rather than "no change"
- **Missing field defaults to permissive**: a request without `country` defaults to US tax rules; without `tier` defaults to premium; without `role` defaults to the ambient session role
- **Empty list as "unrestricted"**: `allowed_regions = []` interpreted as "all regions" rather than "no regions"; or `scopes = []` as "every scope"
- **Explicit `false` vs absent**: `require_2fa` absent is treated as `true`, but explicit `false` is honored — attacker provides `false`
- **Zero as sentinel**: `price = 0` treated as "unset, use catalog price" rather than "free" — or vice versa

### Approval Workflow Weaknesses

- **Approval bound to a token, not to the arguments** — a signed approval token
  covers `{amount: 100, to: A}` but is re-presented against a mutated body;
  the executor only verifies the signature. Approval must bind the exact
  arguments by hash and re-verify immediately before execution.
- **Approval reuse across requests** — one approval drives many executions;
  server-side, mark the approval as consumed on first use.
- **Approver has the same role as the requester** — a self-approval loophole:
  two accounts in the same role sign off on each other's privileged requests.
  Separation of duties is a business invariant, not a role check.
- **Approval expires but the state does not** — approval token valid for 10
  minutes; executed at second 601 if the clock is per-service.
- **Out-of-band approval channels** (email-link approval, Slack approval) that
  do not consult the current state — approve, then the state changes, but the
  approval token still works.

## Fraud and Abuse Patterns (API6:2023 adjacency)

API6:2023 Unrestricted Access to Sensitive Business Flows targets flows that
pass authentication/authorization but are abused through scale, timing, or
identity multiplication. The abuse is the vulnerability.

### Identity Multiplication

- **Email `+tag` aliasing**: `alice+1@gmail.com`, `alice+2@gmail.com` normalize
  to the same inbox but the service treats them as distinct identities for
  trial/referral/promo tracking.
- **Dot-insensitivity** in Gmail: `a.l.i.c.e@gmail.com` ≡ `alice@gmail.com`.
- **Email provider diversity**: trial-stripping services (mailinator, tempmail)
  mint unlimited addresses for free-trial farming.
- **Phone-number recycling**: a canceled virtual phone is reissued; the next
  owner inherits a trial state tied to that number.
- **Payment-instrument reuse**: enforce one-trial-per-card at the card-fingerprint
  level, not the full PAN — otherwise a `Z` suffix or re-encoded card bypasses
  dedup.

### Scalping and Monopolization

- **Headless-browser scripted purchase** of limited inventory (concert seats,
  console drops, limited-release goods) at scale.
- **Reservation farming**: hold inventory in cart for the maximum allowed
  duration without purchase intent, denying legitimate users.
- **Queue abuse**: multiple accounts in a lottery or queue to increase odds.
- **Waitlist position manipulation**: cancel-and-rejoin at the top if the queue
  re-sorts by join time rather than original enqueue.

### Loyalty and Referral Abuse

- **Self-referral**: register, invite yourself from a secondary identity, both
  parties collect the bonus.
- **Chain-referral**: `A→B→C→A` cycles where each step pays a bonus but the
  cycle sums to zero net new customers.
- **Points inflation**: earn tier-boosting points on a purchase, refund the
  purchase, retain the tier because tier calculation is monotonic.
- **Review-for-reward**: paid reviews that satisfy a reward threshold without
  genuine purchase intent.

### Resale and Drip-Pricing Games

- **Price-lock gaming**: hold a locked quote and only convert when market has
  moved favorably (FX, commodity-indexed pricing, dynamic ride pricing).
- **Return-and-rebook**: cancel at the current price, rebook if the price has
  dropped; service refunds the delta between the two prices rather than voiding
  the original.

## Advanced Techniques

### Event-Driven Sagas

- **Saga/compensation gaps**: trigger compensation without original success (invoke the refund-step directly, without the capture-step having happened); or execute success twice without compensation (two commits, one compensate — net surplus)
- **Outbox/Inbox patterns missing idempotency** → duplicate downstream side effects when the outbox-publisher retries
- **Cron/backfill jobs** operating outside request-time authorization; mutate state broadly without consulting the per-request policy that normally gates it
- **Dead-letter replay**: replay a DLQ entry whose business state has moved on in the meantime (refund a canceled order; charge for a terminated subscription)

### Microservices Boundaries

- **Cross-service assumption mismatch**: one service validates total, another trusts line items; alter line items between the two calls — the orchestrator computes total once, the fulfillment service re-reads items without re-computing
- **Header trust**: internal services trusting `X-Role`, `X-User-Id`, `X-Tenant` from an untrusted edge (load `header_injection` for header-smuggling primitives). Each hop must re-derive the principal from a verifiable token, not trust a forwarded header
- **Partial failure windows**: two-phase actions where phase 1 commits without phase 2, leaving exploitable intermediate state (payment captured, order not placed — but credit issued on "failed" order via a goodwill reconciliation job)
- **Service mesh retries** that re-authorize at the client service but not at the backend, allowing a stale allowed-decision to be reused — retry policy should bind to the request ID that was authorized
- **GraphQL field-level drift**: a mutation's authorization is enforced on the root field but child-field resolvers consult a different authorization layer with a different role model
- **Internal RPC without principal propagation**: service A, as a trusted caller, invokes service B with service-A's credentials; the originating user's constraints are lost at the hop
- **Event-schema evolution**: service A publishes event `v1`; service B consumes `v2` with new optional fields; attacker who can influence the publish side injects the new fields that B treats as authoritative

### Signed-URL and Pre-Signed Resource Weaknesses

- **Signature covers URL path, not query parameters**: a signed S3 URL honors `?versionId=` or `?response-content-type=` overrides without those being covered by the signature
- **Signature TTL loose**: a pre-signed download link valid for 7 days is captured and reused long after the user's authorization has changed
- **Signed URL re-signable**: the signing key is scoped to a tenant but the resource is cross-tenant — the sign-cross-tenant path is accessible if the signer accepts an arbitrary bucket/key input

### Multi-Tenant Isolation

- Tenant-scoped counters and credits updated without tenant key in the where-clause; leak across orgs
- Admin aggregate views that allow mutative actions affecting other tenants due to missing per-tenant enforcement
- Shared infrastructure pricing where one tenant can consume another's committed-use discount

## Bypass Techniques (WSTG-BUSL-02 Forge Requests)

- **Content-type switching** (JSON/form/multipart) to hit different parser code paths with different coercion behavior
- **Method alternation** (GET performing state change; overrides via `X-HTTP-Method-Override`, `_method` form field, `?_method=` query)
- **Client recomputation**: totals, taxes, discounts computed on client and accepted by server — any `total: 42.00` field in the request body is a candidate
- **Cache/gateway differentials**: stale decisions from CDN/APIM that are not identity-aware; a feature gate reads from a per-URL cache that was warmed by an admin
- **Mobile vs web vs API vs GraphQL channels**: each channel may enforce a different subset of invariants; find the channel where the weakest check runs
- **Legacy endpoint shadows**: `/v1/` still handles the same action without a validator that `/v2/` added

## Special Contexts

### E-commerce

- Stack incompatible discounts via parallel apply; remove qualifying item after discount applied; retain free shipping after cart changes
- Modify shipping tier post-quote; abuse returns to keep product and refund
- Price-lock expiry: a quote-token good for 15 minutes is honored at second 901 if clock-skew is per-service
- Loyalty points: earn on a purchase, then refund — points not clawed back; or earn tier-up after refund-reduced spend

### Banking/Fintech

- Split transfers to bypass per-transaction threshold; schedule-vs-instant path inconsistencies
- Exploit grace periods on holds/authorizations to withdraw again before settlement
- Interest-day boundary games (compound daily — borrow at 23:59, repay at 00:01 across a day boundary with no interest accrued)
- ACH return handling: funds credited optimistically, used before the return clears

### SaaS/B2B

- Seat licensing: race seat assignment to exceed purchased seats; stale license checks in background tasks
- Usage metering: report late or duplicate usage to avoid billing or to over-consume
- Plan downgrades: feature access gated by cached plan; cache survives downgrade until next cycle
- API-key quotas enforced per-key while per-tenant quota is absent — spawn N keys to multiply quota

### Payment Platform Integrations

- **Stripe `Idempotency-Key`** is honored by the Stripe API but a wrapper service may route the same key to a different Stripe account on retry, bypassing dedup. The dedup key must be scoped to the merchant account, not globally.
- **PayPal IPN / Stripe webhook replay**: endpoints that do not verify both the signature and the event's `livemode` + `created` timestamp accept replayed events from a test environment or from a prior success.
- **Chargeback / dispute flows**: a dispute marks a transaction `charge.dispute.created` but the fulfillment service does not reverse the shipment because its state model does not include `disputed`.
- **Split tender (gift card + credit card)**: refund the full amount to the credit card while the gift card balance remains credited; or redeem a gift card for a purchase that is immediately refunded to a different method.
- **Subscription anchoring**: `billing_cycle_anchor` set to a past date to trigger an immediate pro-rata credit without an actual service change.

### Shopify / E-commerce Platform Quirks

- **Draft orders**: a draft order that bypasses inventory holds can be finalized to a committed order with stale pricing.
- **Checkout tokens**: a checkout token issued at session start may remain honored after the authenticated user has logged out, allowing session-fixation-like checkout.

### Worked Scenarios

Concrete recipes — each states the invariant, the attack, and the proof:

- **Auth/capture double-capture** — invariant: captured ≤ authorized. Authorize
  $100, then fire two `capture` calls (single-packet race) before the auth is
  marked captured → $200 captured on a $100 auth. Proof: ledger shows two
  captures against one authorization.
- **Negative-amount reversal** — invariant: amounts are non-negative. Send a
  negative `amount` to transfer/refund/credit (`{"amount": -500}`); if the sign
  isn't validated, money flows *toward* the attacker (a `-$500` refund credits
  their card, a `-$500` transfer pulls from the payee). Proof: attacker balance
  increases.
- **Partial-refund oversum** — invariant: Σ refunds ≤ captured. Issue several
  partial refunds each ≤ captured but summing above it (e.g. 3×$40 on a $100
  order via UI + support tool + API). Proof: net refunded > paid.
- **Currency / rounding arbitrage** — invariant: value conserved across FX.
  Buy in a currency where per-item rounding favors you, refund in another at a
  stale rate; or exploit per-item vs per-order tax rounding to skim cents at
  scale. Proof: repeated cycle nets positive.
- **Discount stacking to negative total** — invariant: order total ≥ 0. Apply a
  percentage discount and a fixed store-credit that together drive the total
  below zero; if the negative is stored as redeemable balance, it's withdrawable.
  Proof: account carries a positive balance created from nothing.
- **Limit slicing** — invariant: cumulative ≤ limit. A "$10k/day transfer limit"
  enforced *per transaction* is bypassed by 100×$100. Proof: daily total ≫ limit.
- **Reservation/hold leak** — invariant: reserved released on abandon. Reserve
  10 units, complete 1, abandon the rest; if holds aren't released, you deny
  inventory (or the resell path double-sells). Proof: available count wrong.
- **Trial / entitlement reset** — invariant: one trial per identity. Re-trigger
  a free trial by delete-recreate, email `+tag` alias, or a plan-change that
  resets the trial flag; or **downgrade retention** — cancel premium but keep
  premium features because the gate reads a cached entitlement. Proof: paid
  feature usable without payment.
- **3DS/step-up split** — invariant: step-up above a threshold. Split one large
  payment into sub-threshold charges that each skip 3-D Secure / fraud review.
  Proof: total charged with no step-up.
- **Approval binds body, not fields** — invariant: approved action equals
  executed action. An approval token issued for `{amount: 100, to: alice}` is
  re-presented with `{amount: 100, to: attacker}` and the executor only
  verifies the token's signature, not that the arguments still match. Proof:
  funds routed to a recipient who was never approved.
- **Idempotency key reused across principals** — invariant: idempotency scoped
  to actor + action. Capture the victim's `Idempotency-Key` header (seen in a
  shared log or guessable sequence), replay with your own body; the service
  deduplicates on key alone and returns the stored (victim-authored) result,
  or the attacker-authored body overrides the victim's state. Proof: cross-user
  state write.
- **Referral self-dealing** — invariant: referrer ≠ referred. Register, invite
  yourself from a secondary identity (alt email, same payment instrument,
  different device fingerprint), both parties collect the signup bonus. Proof:
  one net new customer, two bonuses paid.
- **Webhook replay** — invariant: a webhook event drives at most one business
  action. Capture a `payment.succeeded` webhook (shared log, HAR, replay from a
  developer dashboard), replay it; the consumer re-runs fulfillment because the
  dedup key is the delivery ID, not the business event ID. Proof: duplicate
  fulfillment on a single payment.
- **Scope collapse via content-type switch** — invariant: `amount` is a scalar.
  Submit `{"amount": [100, 200]}` or `{"amount": {"$numberLong": "100"}}` as
  JSON, then as form-encoded `amount=100&amount=200`; different parsers coerce
  to different values, and one of them (first vs last vs array vs object) ends
  up charged. Proof: ledger shows a value that was never in any single field.
- **Monotonic counter reset by role transition** — invariant: usage counters
  advance only. A plan downgrade resets the usage counter to zero to match the
  new plan's budget; the user has already consumed the old budget. Proof:
  consume beyond either plan's allowance by downgrading at the top of the
  period.

## Audit, Reconciliation, and Observability

Business-logic bugs leave fingerprints in reconciliation reports. During
testing and after triage:

- **Daily reconciliation deltas**: compare the ledger total to the sum of
  individual transactions; a non-zero drift is prima facie evidence of a
  conservation violation.
- **Per-user sum-of-refunds vs sum-of-captures**: a user with Σ refund > Σ
  captured is a smoking gun.
- **Webhook idempotency logs**: look for duplicated event IDs with different
  resulting state changes.
- **Approval audit trail**: approvals whose executed arguments differ from the
  approved arguments.
- **Trial-tracking by payment-instrument-fingerprint vs by account**: a card
  fingerprint attached to >1 trial is identity multiplication.
- **Cross-channel discrepancies**: a credit issued via support tool with no
  corresponding support-ticket; a refund via API with no CSAT trail.

Audit visibility is an operational control, not a prevention — but it is where
the first evidence of exploitation appears. For attackers, the audit trail is
also the detection surface they must evade (WSTG-BUSL-07 Application Misuse
Defenses — the service should flag misuse via rate-of-impossible-events,
velocity-of-reversal, cluster-of-identity-reuse).

## Chaining Attacks

Business logic flaws rarely stand alone — they amplify when chained with other primitives:

- **Business logic + race** (`race_conditions`): duplicate benefits before state
  updates close the window (single-packet apply-coupon, parallel claim-seat).
- **Business logic + IDOR** (`idor`): operate on others' resources once a
  workflow leak reveals IDs — refund someone else's order, change their plan,
  grant yourself a seat on their org.
- **Business logic + mass assignment** (`mass_assignment`): add a privileged
  field (`is_admin`, `plan`, `credit_balance`) to a request that otherwise
  passes authorization because the endpoint accepts the DTO wholesale.
- **Business logic + CSRF** (`csrf`): force a victim to complete a sensitive
  step sequence (grant you a seat; approve your request; apply a refund).
- **Business logic + BFLA** (`broken_function_level_authorization`): invoke
  the admin-only `issue_credit` or `adjust_quota` endpoint directly from a
  non-admin principal once URL enumeration finds it.
- **Business logic + header injection** (`header_injection`): forge
  `X-Tenant`/`X-Role` to escalate at an internal service that trusts headers
  from a reverse proxy.

## Code Review Signals

Source review of a business-logic surface should hunt for these patterns:

- **Client-trusted fields**: any `total`, `tax`, `discount`, `price`, `amount`, `role`, `tenant_id`, `is_admin` arriving in a request body — flag unless the server recomputes.
- **Missing WHERE clauses**: `UPDATE user_credits SET balance = balance - $1 WHERE user_id = $2` — missing `AND credit_id = $3` leaks across the user's own credits; worse, missing `AND tenant_id = $4` leaks across tenants.
- **Non-atomic read-modify-write**: `balance = read(); write(balance - amount)` without a `WHERE balance >= amount` guard or an atomic decrement. Load `race_conditions`.
- **Idempotency key scope**: `cache.get(idempotency_key)` keyed on header alone rather than `(principal, action, idempotency_key, body_hash)`.
- **Approval verification by signature only**: `verify_signature(token)` without re-checking that the current arguments match the signed arguments.
- **Role check at wrong layer**: `@require_admin` at the HTTP route while background jobs invoke the same handler as the service account.
- **Cache-level feature gates**: `@cached(ttl=300) def can_access_feature(user)` — stale decisions survive downgrades.
- **Business invariant in logs only**: ledger reconciliation lives in a nightly cron that logs discrepancies but does not block transactions.
- **Signed webhook with wide replay window**: Stripe-style webhooks accept events with timestamp up to 5 minutes old by default; the window must be tight and the event ID must be deduped.
- **"Mode" or "channel" string that selects validator strength**: `if request.channel == "mobile": skip_fraud_check()` is a classic bypass.

## Testing Methodology

1. **Enumerate state machine** — Per critical workflow, draw states, transitions, and pre/post-conditions. Mark every edge where client-supplied input changes outcome. Note the invariant each transition is supposed to protect.
2. **Build Actor × Action × Resource matrix** — Unauth, basic user, premium, staff/admin, API key, partner integration; identify actions per role and the invariants bound to each.
3. **Test transitions** — Step skipping, repetition, reordering, late mutation, early entry; probe `BUSL-06` directly.
4. **Introduce variance** — Time, concurrency, channel (mobile/web/API/GraphQL), content-types, locales, currencies. Each dimension is an axis where an invariant may silently vanish.
5. **Validate persistence boundaries** — All services, queues, and background jobs re-enforce invariants; the request handler's enforcement does not protect a later async consumer.
6. **Prove ledger impact** — The finding statement names the invariant and shows the ledger line that broke it. Visual-only inconsistencies are false positives.
7. **Fix verification** — Re-run the exploit against the proposed fix with the same timing/concurrency; a fix that only closes the happy path is incomplete.

## Validation

A business-logic finding should include:

1. The invariant stated in writing (conservation, exclusivity, monotonicity, closure, scope).
2. The attack as a reproducible request sequence (ordering, timing, parallelism, headers).
3. Side-by-side evidence for intended vs abused flows with the same principal where possible.
4. Durability: the undesired state persists and is observable in authoritative sources (ledger, admin views, emails, downstream analytics).
5. Impact quantified per action and at scale (unit loss × feasible repetitions × realistic attacker throughput).
6. Prerequisites: role, feature flag, time window, data state, concurrency, channel.

## False Positives

- Promotional behavior explicitly allowed by policy (documented free trials, goodwill credits, intentional multi-channel discounts)
- Visual-only inconsistencies with no durable or exploitable state change
- Admin-only operations with proper audit and approvals that the attacker cannot invoke
- A race-window that empirically never closes within the attacker's reachable timing
- An invariant violation that reverses before the next business cycle (optimistic UI, eventually consistent, auto-reconciled nightly)
- A client-side limit that is actually re-enforced server-side on commit

## Impact

- Direct financial loss (fraud, arbitrage, over-refunds, unpaid consumption)
- Regulatory/contractual violations (billing accuracy, consumer protection, financial-services oversight, PCI/PSD2 strong-customer-authentication bypass)
- Denial of inventory/services to legitimate users through resource exhaustion (scalping, reservation monopolization, seat hoarding)
- Privilege retention or unauthorized access to premium features
- Reputation and trust damage when ledger integrity is publicly compromised
- Downstream compounding: a business-logic flaw in billing may propagate to analytics, forecasts, and partner payouts

## Pro Tips

1. Start from invariants and ledgers, not UI — prove conservation of value breaks before investigating ergonomics
2. Test with time and concurrency; many bugs only appear under pressure
3. Recompute totals server-side; never accept client math — flag when you observe otherwise
4. Treat idempotency and retries as first-class: verify key scope (actor + action + body hash) and persistence
5. Probe background workers and webhooks separately; they often skip auth and rule checks that request-time handlers enforce
6. Validate role/feature gates at the service that mutates state, not only at the edge — gateway enforcement does not survive internal retries
7. Explore end-of-period edges (month-end, trial end, DST, FX quote expiry, grace windows) for rounding and window issues
8. Use minimal, auditable PoCs that demonstrate durable state change and exact loss — a $0.03 proof is more credible than a $1M claim
9. Chain with authorization tests (`idor`, `broken_function_level_authorization`) to magnify impact
10. When in doubt, map the state machine; gaps appear where transitions lack server-side guards

## Summary

Business logic security is the enforcement of domain invariants under adversarial sequencing, timing, inputs, and channels. If any step trusts the client or prior steps, expect abuse. Model the state machine, name the invariant, break it with a minimal reproducible sequence, prove the ledger impact, and chain with authorization and race primitives to amplify. For deeper advanced-tier concurrency and saga primitives, load `business_logic_advanced_deep`; for 2024–2026 frontier framing including API6:2023 business-flow abuse patterns and automated invariant discovery, load `business_logic_novel_deep`.
