---
name: business-logic-novel-deep
description: 2024-2026 frontier for business-logic exploitation — OWASP API6:2023 Unrestricted Access to Sensitive Business Flows, scalping and bot economics, agentic-era business-flow attacks, automated invariant discovery research, and fraud-detection evasion
sibling: business_logic
load_when: scan_mode == "deep"
---

# Business Logic — Novel Deep

Novel-tier content for business-logic exploitation covering the 2024–2026 frontier reframing of the class. The base owns scope and standards mapping; the advanced-deep sibling owns full technique treatments for concurrency, saga, approval-binding, cross-service drift, timing, monetary, and entitlement primitives; this file owns the frontier below — the formal API6:2023 abuse model, scalping and bot economics as a 2024–2026 phenomenon, agentic-era business-flow attacks (routing to `agentic_system_security`), automated invariant-discovery research, and fraud-detection evasion research.

Business logic is definitionally per-application: there is no shared library that owns the invariant, and the CVE/GHSA pipeline accordingly does not surface this class. The frontier material is thinner than CVE-heavy classes — this is a class-structural property, not under-research. The content unit is the technique-class reframing, not a CVE catalog.

## OWASP API6:2023 as the 2024–2026 Reframing

The 2023 edition of the OWASP API Security Top 10 introduced **API6:2023 Unrestricted Access to Sensitive Business Flows**. This is the single most consequential reframing of the business-logic class in a decade. The 2019 edition had no equivalent category — API6:2019 was Mass Assignment (now folded into API3:2023 BOPLA). The new category codifies that *authentication and authorization are not sufficient*: a workflow that passes both can still be abused through scale, speed, timing, or identity multiplication to inflict business harm.

The 2023 definition names three archetypal flows:

1. **Buying a product for scalping/reselling** — automated purchase of limited inventory at human-infeasible rates.
2. **Reserving seats or appointments** — monopolizing a shared resource to deny legitimate users.
3. **Posting comments at scale** — manipulating review/reputation flows beyond the intended organic rate.

Each archetype is a *flow*, not an endpoint. The vulnerability is that the service does not detect or constrain the flow at business speed, even though every individual request is well-formed, authenticated, and authorized. The 2023 edition explicitly notes that fixing this requires knowing the business model — "no exciting new technical vulnerability" — and therefore automated scanners do not detect it.

### Primitive: Business-Flow Rate as the Invariant

The core API6:2023 insight is: **the rate at which a flow executes is itself a business invariant**. One ticket purchase per minute per account is intended; 10,000 ticket purchases per minute from the same bot network is harm. Yet both scenarios may be fully authenticated, authorized, and HTTP-valid.

The invariant has four axes:

- **Volume**: aggregate throughput over a time window.
- **Concentration**: fraction of a limited resource consumed by a single actor cluster.
- **Timing**: temporal distribution (burst vs. steady).
- **Identity**: the actors executing the flow (natural persons vs. identity-multiplied bot network).

A violation along any axis is an API6:2023 finding. Each axis is a dimension of attack and detection.

### Primitive: Identity Multiplication as the Enabling Capability

Scalping is the archetypal API6:2023 scenario because the attacker multiplies identity to make the per-identity throttle irrelevant. The 2024–2026 identity-multiplication surface:

- **Mint-time**: unlimited free account creation.
- **Verification evasion**: SMS-OTP via disposable virtual numbers; email-OTP via domain-rented catch-alls.
- **Payment-instrument multiplication**: prepaid cards minted at scale; crypto wallets as pseudonymous instruments; stolen cards for one-shot use.
- **KYC-bypass**: for KYC-gated flows, synthetic-identity generation (name + DOB + address combos that pass basic bureau checks without a real person behind them).
- **Device fingerprint rotation**: headless-browser clusters with per-profile randomization.

The attack is to produce enough valid-looking identities to render per-identity throttles non-binding, while the per-tenant / per-infrastructure / per-flow throttle is absent.

### Primitive: Reserve-and-Resell as a Flow Attack

The reservation flow is a classic API6:2023 target because the reservation itself consumes shared resource (inventory, seats) long before payment commits. Attackers hold reservations as inventory options, then resell them.

**Preconditions**:
- Reservation TTL ≥ a market timeframe (minutes to hours).
- Reservation does not require an irrevocable commitment (hold, authorization-but-not-capture).
- Secondary market exists for the resource.

**Attack recipe**:
1. Reserve 100× the normal quantity across the identity-multiplied cluster.
2. List the reservations on a secondary market or wait for the resource to appreciate.
3. Transfer the reservation to a legitimate buyer at a markup, or let the service's "resell to waitlist" path propagate.

**Confirmation**: aggregate reservation count on a limited resource far exceeds organic demand; secondary market exists.

**Impact**: inventory monopolization; price arbitrage on the primary; service's margin collapse to the secondary market.

### Primitive: Review and Rating Flow Manipulation

Comment/review flows are often API6:2023 vulnerable because each individual review passes content moderation but the *rate* of reviews from a coordinated cluster swamps organic signal.

**Preconditions**:
- Review posting rate not throttled per-tenant/per-item.
- Review eligibility (purchased, verified) has a cheap bypass (purchase trivially; return quickly).
- Review score drives downstream economics (search ranking, display, trust).

**Attack recipe**:
1. For a target product/service, acquire N reviews from the identity-multiplied cluster.
2. Each review individually passes moderation (unique phrasing from an LLM; reasonable spelling; mix of 4- and 5-star to avoid pure-positive filters).
3. The ranking algorithm reads aggregate rating; target rises or competitor falls.

**Confirmation**: a product's review growth rate exceeds plausible organic rate (sales volume vs. review volume ratio); reviews cluster from identity-correlated accounts.

**Impact**: ranking manipulation; competitor suppression; consumer trust corrosion.

## Scalping and Bot Economics as a 2024–2026 Phenomenon

Scalping has moved from "unofficial resellers" to a formal economy with its own tooling, infrastructure, and legal regime. The 2024–2026 landscape:

### Pattern: AIO (All-in-One) Sneaker/Drop Bots

The sneaker-drop market produced the modern scalping-bot infrastructure, since generalized to concert tickets, event tickets, limited gaming hardware, and limited luxury goods. Characteristics:

- **Multi-site**: a single bot handles 100+ retailers.
- **CAPTCHA solver integration**: paid CAPTCHA-solver services (2captcha-class) are inline.
- **Proxy rotation**: residential-proxy networks providing per-identity egress IPs.
- **Checkout-automation profiles**: pre-populated credit card + address + account per profile.
- **Queue-bypass logic**: specific exploitation of each site's checkout flow (fast-pass endpoints, cart-persistence, pre-warm).

Defender implication: the bot operator has read your flow in depth and found every API6:2023 edge; the defense must assume the attacker has end-to-end instrumentation and that any per-request heuristic will be defeated. The defense surface is cross-flow correlation (device cluster, payment cluster, address cluster, behavior-timing cluster) and rate caps on the business flow itself (per-item per-minute global ceiling, per-tenant price-elasticity bounds).

### Pattern: Residential-Proxy IP Washing

The 2024–2026 attacker's "IP" is no longer a datacenter IP from a cloud provider — it is a residential IP from a legitimate consumer's compromised router or installed-SDK device. Correlation-by-IP is defeated. Correlation must move to higher-order signals.

### Pattern: Human-in-the-Loop Verification Farms

Where CAPTCHA solvers lack sophistication, 2024–2026 operations use human workers (often in low-wage markets) solving verification steps in parallel. This defeats behavior-biometric detection that assumes an automated signature. Correlation on timing (seconds-to-decision patterns across accounts) remains viable.

### Pattern: LLM-Written Review and Comment Content

LLMs produce review content indistinguishable from human writing at scale. The 2024–2026 defense cannot rely on language-model-based review authenticity detection — it is adversarial. Shift to purchase-verified-reviews-only, rate caps, and reviewer-cluster-correlation.

## Agentic-Era Business-Flow Attacks

AI agents (per `agentic_system_security`) interact with services on behalf of users and *at machine speed*. This is a new API6:2023 attack vector — the agent is not an attacker, but the agent amplifies both legitimate use and abuse. The 2024–2026 frontier:

- **Agent-driven scalping**: a user operates an AI agent authorized to execute business flows ("buy me the first available ticket under $100"). The agent executes at API latency, not human reaction time.
- **Confused-deputy via agent**: an attacker influences retrieved content (RAG result, email, document) that the agent executes as instruction, causing it to perform business flows the user did not authorize.
- **Agent-to-agent trade**: agent A on service X executes a sell flow; agent B on the same or related service executes the matching buy flow; neither user is in the loop. Price-discovery and market-manipulation primitives apply.
- **Agent-identity ambiguity**: the service sees an authenticated user; the user sees an authorized agent. API6:2023 traditionally counted actions per authenticated identity, but the authenticated identity is a passthrough — the agent is the actor.

The 2024–2026 defense requires:
1. **Explicit human-in-the-loop binding** for consequential business flows (confirming a $500+ purchase, confirming an irreversible action).
2. **Agent-identification signals** so the service can distinguish agent-driven from human-driven traffic.
3. **Per-flow rate caps independent of per-user caps** — because the agent legitimately operates at machine speed on behalf of a user, the per-user cap doesn't bind.

Agent-side attacks (prompt-injection, tool-misuse, cross-agent confused-deputy) are owned by `agentic_system_security`; this skill owns only the business-flow-level consequences.

## Automated Invariant Discovery — Academic Frontier

Automated discovery of business-logic invariants is an active research area but has not matured into production tooling. The academic literature establishes:

- **Model inference from traces**: train a probabilistic finite-state model from observed request/response pairs; flag transitions in novel sequences as potential invariant violations. (General technique class; see Daikon and successors from the invariant-inference literature.)
- **Property-based testing against learned specifications**: express the inferred model as hypothesis-style properties; generate adversarial sequences within the state space.
- **LLM-assisted invariant extraction**: 2024–2026 preprints propose that LLMs can read specifications (API docs, Swagger, user flows) and output invariants in machine-checkable form. The output quality remains the open problem.

For zen-ai operators, the practical consumption is: the state-machine model and invariant list that `business_logic_advanced_deep` requires can be partially auto-generated from recorded traces, but hand-curation of invariants (the "what should be conserved" question) is where the signal is. Automation accelerates enumeration; it does not replace the business-model understanding.

### Primitive: Response-Clustering as Invariant Fuzzing

The one production-grade automated technique that transfers from parser-differential fuzzing to business-logic:

**Primitive**: send sequences of varying inputs through a business flow; cluster responses by (status, body shape, timing). A response that falls in a sparse cluster is a candidate for manual inspection.

**Preconditions**:
- The flow is probable (replayable with varying arguments; writeable to a test tenant without consequence).
- A corpus of baseline sequences exists.

**Attack recipe**:
1. Record baseline sequences for the critical flows.
2. Mutate one axis at a time (per-item quantity, per-order currency, timing between steps, concurrency, headers).
3. Cluster responses.
4. Investigate rare clusters manually; they are often places where the service's invariant check didn't fire as expected.

**Confirmation**: a rare cluster corresponds to a reproducible invariant violation.

**Impact**: finds invariant edges that a human-driven test matrix misses; the "unknown unknown" surface in a complex business flow.

## Fraud-Detection Evasion as Frontier

Fraud-detection systems in 2024–2026 use ML models to score transactions. Attacks on these systems form a new frontier:

### Primitive: Shadow-Scoring the Fraud Model

**Primitive**: the attacker runs probes to learn the fraud model's thresholds, then operates just below each threshold.

**Preconditions**:
- Fraud scoring is deterministic (same input → same decision).
- The attacker can submit probes without immediate blocking (soft decline → learn; hard decline → block).

**Attack recipe**:
1. Submit transactions varying one axis (amount, country, device, time-of-day).
2. Record which pass and which fail; interpolate the decision boundary.
3. Operate just below the boundary.

**Confirmation**: attacker transactions consistently approved while matching the aggregate pattern of blocked transactions.

**Impact**: fraud throughput sustained; attacker model-aware.

### Primitive: Adversarial-ML Against Fraud Score

**Primitive**: for services that use ML-based fraud scoring, craft input features that score low (benign) despite the aggregate behavior being abuse.

**Preconditions**:
- The attacker has partial model knowledge (via shadow-scoring or model leakage).
- The feature set is attacker-controllable (device, timing, product basket, address).

**Attack recipe**:
1. Build a surrogate model by sampling the decision boundary.
2. Compute minimal-perturbation adversarial examples that stay benign-scored while achieving the abuse goal.
3. Execute at scale.

**Confirmation**: aggregate abuse continues; fraud model does not block.

**Impact**: fraud team's ML spend is wasted; blind spot in the detection surface.

### Primitive: Timing-Normalization to Human-Baseline

**Primitive**: bot detection reads inter-action timing; attacker normalizes bot timing to a learned human distribution.

**Preconditions**:
- Bot detection uses time-between-clicks, time-to-form-fill, mouse-trajectory variance.
- The signal is attacker-controllable.

**Attack recipe**:
1. Collect a corpus of human-driven sessions.
2. Draw bot timings from the human distribution.
3. Add Gaussian jitter to form-fill rates, mouse paths.

**Confirmation**: bot sessions pass human-vs-bot classifiers.

**Impact**: bot detection evasion; the bot-detection vendor's product becomes unreliable.

### Primitive: Feedback-Loop Poisoning

**Primitive**: fraud models retrain on recent decisions; attacker's benign-labeled abuse becomes training signal, drifting the model.

**Preconditions**:
- Online or near-online retraining.
- Attacker's successful (not-caught) abuse is labeled "benign" in the training set.

**Attack recipe**:
1. Operate below detection for a period.
2. The model learns from these transactions as benign.
3. The decision boundary drifts in the attacker's favor.
4. Attacker gradually escalates.

**Confirmation**: longitudinal drift in detection rate on constant-complexity attacks.

**Impact**: fraud posture degrades over time without any infrastructure change.

## Modern Loyalty, Rewards, and Points Economy

Loyalty programs in 2024–2026 operate as de facto financial instruments. The invariants they must enforce are harder than nominal:

### Primitive: Point-Accrual-On-Refund Asymmetry

**Primitive**: points earned on a purchase are not clawed back on refund; attacker purchases, refunds, retains points.

**Preconditions**:
- Loyalty-point accrual fires on purchase; no reverse-event on refund.
- Points redeemable for value (statement credit, gift cards, flights).

**Attack recipe**:
1. Purchase a redeemable item (gift card, high-points item).
2. Refund the purchase.
3. Points remain.
4. Redeem points for value.

**Confirmation**: ledger shows refunded purchase; loyalty ledger shows retained point grant.

**Impact**: synthetic point creation; scalable in direct proportion to purchase/refund cycle rate.

### Primitive: Tier-Promotion Monotonicity

**Primitive**: tier status computed as a monotonic max over period; attacker reaches tier via spike then declines, keeping tier.

**Preconditions**:
- Tier derived from current-period spending threshold.
- Threshold is "ever reached" not "sustained".
- Tier status includes material benefits (lounge access, upgrade priority, redemption bonus).

**Attack recipe**:
1. In one period, drive spending just past the threshold.
2. Refund the spending (point-accrual-on-refund retains the activity record).
3. The activity record satisfies the threshold even though the net spending did not.
4. Tier status locks for the subsequent year.

**Confirmation**: tier status with no sustained spending.

**Impact**: year-long free premium benefits.

### Primitive: Program-Transfer Rate Arbitrage

**Primitive**: cross-program point transfers (airline → hotel, bank → airline) have transfer rates; attacker finds a cycle where the aggregate transfer rate rounds in their favor.

**Preconditions**:
- Multiple partner programs with directed transfer rates.
- Transfer rounding at each step favors the attacker (round-up at destination).

**Attack recipe**:
1. Enumerate transfer rates: 1 pt A → 1.5 pt B, 1 pt B → 0.7 pt A.
2. Compose: 1 A → 1.5 B → 1.05 A (gain of 0.05 A per cycle).
3. Automate.

**Confirmation**: closed cycle produces positive net; same points re-cycled N times inflate to N × (1 + ε)^N.

**Impact**: unbounded point creation via a transfer cycle.

## Crypto / DeFi / Agentic-Finance Business-Logic Surface

The 2024–2026 crypto landscape embeds business logic in smart contracts; the business-flow attacks still apply. This is a hybrid surface where traditional business-logic flaws meet on-chain primitives — the invariants are the same, the enforcement medium differs.

### Primitive: Oracle-Price Manipulation for Business Decisions

**Primitive**: a service makes business decisions (collateral valuation, insurance payout, pricing) based on a price oracle; the oracle is manipulable within the attacker's window.

**Preconditions**:
- Oracle reads an external price source (DEX pool, published feed).
- Attacker can influence the price source (large swap in a thin pool, cross-pool arbitrage).
- Business decision commits irrevocably at the oracle-read moment.

**Attack recipe**:
1. Observe when the business decision reads the oracle.
2. Immediately before the read, manipulate the price (flash-loan swap on a thin pool).
3. The business decision commits at the manipulated price.
4. Reverse the manipulation.

**Confirmation**: business decision ledger entry at an off-market price; corresponding on-chain manipulation visible.

**Impact**: insurance over-payout, collateral under-valuation, DEX price arbitrage against the service.

### Primitive: Multi-Chain State Divergence

**Primitive**: a service operates across multiple chains with shared state; the state is eventually consistent but attackers exploit the eventual window.

**Preconditions**:
- Cross-chain messaging latency measured in minutes.
- Business decisions made per-chain without a global lock.

**Attack recipe**:
1. On chain A, perform an action that credits state.
2. Before the state propagates to chain B, perform the same action on chain B.
3. Both chains credit; the global reconciliation sees a conflict but may resolve in the attacker's favor depending on bridge policy.

**Confirmation**: cross-chain reconciliation log shows the duplicate; attacker holds credit on both.

**Impact**: double-dip of cross-chain rewards or state.

## Public 2024–2026 Business-Logic Cases to Study

Public write-ups of 2024–2026 business-logic flaws cluster around a few patterns. Each is a class instance, not a CVE:

- **Promo-code mass-redemption on consumer brands**: 2024–2025 incidents at major retailers where a leaked promo code was mass-applied before the retailer could rescind. Pattern: `max_uses` enforced per-code but attacker-controlled identity multiplication meant per-code was per-identity.
- **Loyalty-point arbitrage on airlines and hotels**: 2024 reports of accrual-vs-redemption rate mismatches where points-for-X-earned-on-refunded-stay were not clawed back.
- **Ride-share surge gaming**: 2024 research on how trips may be artificially routed to maximize surge pricing where drivers coordinate.
- **Delivery-service refund abuse**: "item missing" claims flow abuse where the refund process is cheaper than the dispute process.
- **Social-platform engagement bot scale**: 2025 academic analyses of engagement-bot populations.
- **Crypto DEX price-oracle manipulation**: not purely business-logic (also smart-contract), but the business-flow surface is where oracles are read against user-controllable state.

Each pattern reduces to one invariant class: `max_uses`, monotonic-point-accrual, pricing-invariance-under-user-action, cost-of-reversal-asymmetry, aggregate-rate-of-flow, oracle-honesty. These are the same invariants as the base skill; the 2024–2026 novelty is their expression in agent-driven, bot-driven, and ML-driven adversarial landscapes.

## Verification Discipline for Frontier Findings

Novel-tier findings are harder to confirm because the harm is often aggregate and reputational, not per-request. Confirmation requires:

1. **Aggregate measurement over time**: a single success is weak evidence; a reproducible rate is strong.
2. **Business-side owner buy-in**: the engineering fix requires understanding the attacker's economics, which the engineering team may not know. Pair findings with the business owner.
3. **Economic model**: unit cost × attacker throughput × attacker reach = annualized harm. This is often $100k+/year even for individually-small flaws.
4. **Detection-feasibility statement**: can the service detect this at all? Many API6:2023 flaws persist because they are structurally undetectable without a model change.

## Chaining Depth at the Frontier

Novel-tier chains:

- **API6:2023 + agentic**: an attacker operates an AI agent that performs the abusive business flow at machine speed. The agent is the identity multiplier. Load `agentic_system_security`.
- **API6:2023 + mass-assignment**: identity multiplication requires account creation; mass-assignment on signup grants attacker-chosen roles that bypass the per-tenant throttle.
- **API6:2023 + IDOR + race**: enumerate target resources, race the claim operation across the identity-multiplied cluster.
- **Fraud-detection evasion + credential stuffing**: `authentication_jwt`/`weak_password_detection` provides the account inventory; this skill's shadow-scoring tells the attacker which accounts to use.
- **Fraud-detection evasion + CSRF**: a victim is the identity-vehicle for a flow that passes fraud scoring under their reputation.

## Breadth of the Live Frontier

The genuine 2024–2026 novel-tier frontier for business logic is: (1) the OWASP API6:2023 reframing, (2) scalping/bot economics with 2024–2026 identity-multiplication tooling, (3) agent-era flows that route to `agentic_system_security`, (4) a thin academic literature on automated invariant discovery, and (5) fraud-detection-ML evasion. Beyond these five, further depth is per-application and does not generalize into a reusable technique class — this is a class-structural limit (business logic is definitionally per-application; no shared library owns the invariant and no CVE pipeline surfaces it), not under-research, so this novel sibling lands below the 850-line aim point by design rather than through tangential-topic padding.

## Summary

The 2024–2026 business-logic frontier is less a parade of new techniques and more a reframing of the class around three forces: the OWASP API6:2023 formal recognition that flow-rate is itself an invariant, the maturation of a scalping/bot economy that defeats per-identity throttles through identity multiplication, and the agentic-era shift of actor identity from "authenticated user" to "agent operating with user's authority." The automated-invariant-discovery literature and fraud-detection-ML evasion complete the picture. The reusable unit remains the invariant and its break — the novel content is the attacker's new reach (machine-speed, identity-multiplied, ML-aware), not a new category of invariant.
