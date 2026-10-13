---
name: payment_gateways
description: Payment gateway integration security testing covering Stripe, Adyen, and Braintree — webhook signature bypass, test/live key confusion, idempotency abuse, and amount/currency tampering
---

# Payment Gateways

Payment gateway integrations (Stripe, Adyen, Braintree) expose a consistent class of integration-layer bugs: webhook signature verification bypass, test/live key confusion, idempotency-key races, and client-side amount tampering. The vulnerabilities are almost never in the gateway platform itself — they are in how the application integrates it. This skill owns the gateway-specific technical surface; payment flow logic (authorize/capture/refund state machines, double-refund, conservation invariants) routes to `business_logic`. Generic token and session handling routes to `authentication_jwt`.

## Attack Surface

**Stripe**
- Client: Stripe.js (`js.stripe.com/v3/`), Elements, Checkout, Payment Links
- Server: `/v1/` REST API, PaymentIntents, SetupIntents, Subscriptions, Customers
- Webhooks: HMAC-SHA256 with `whsec_` signing secret, tolerance window
- Keys: `pk_live_`/`pk_test_` (publishable), `sk_live_`/`sk_test_` (secret), `rk_live_`/`rk_test_` (restricted)

**Adyen**
- Client: Drop-in, Components, Secured Fields (CSE), `/sessions` API
- Server: `/v71/payments`, `/v71/payments/details`, Checkout API
- Webhooks: HMAC-SHA256 per endpoint, Basic Auth (legacy)
- Keys: API key (server), Client key (client-side encryption), webhook HMAC key

**Braintree (PayPal)**
- Client: Drop-in UI, Hosted Fields, client token / tokenization key
- Server: gateway API (Ruby/Python/Node SDKs), GraphQL API
- Webhooks: signature verification via public key + payload digest
- Keys: merchant ID, public key, private key; sandbox vs production credentials

## Reconnaissance

**Fingerprinting in client bundles**
```
# Stripe
grep -r 'pk_live_\|pk_test_\|js.stripe.com\|Stripe(' <source>
# Publishable keys in HTML/JS: pk_live_... or pk_test_...

# Adyen
grep -r 'adyen\|AdyenCheckout\|adyen-checkout\|clientKey.*live_\|clientKey.*test_' <source>
# Client keys: live_... or test_...

# Braintree
grep -r 'braintree\|client-token\|braintree-web\|BraintreeClient' <source>
# Client tokens are base64-encoded JSON containing the environment and merchant ID
echo '<client_token>' | base64 -d | jq .   # reveals environment, merchantId, challenges
```

**Webhook endpoint discovery**
- Common paths: `/webhooks/stripe`, `/api/webhooks`, `/hooks/payment`, `/stripe/webhook`
- Grep application routes/configs for webhook handler registrations
- Check for webhook endpoint URLs in admin panels or gateway dashboards

**Key classification**
- `pk_*` / client keys are public by design — the finding is when `sk_*` / API keys / private keys appear in client bundles, CI logs, git history, or error responses
- `sk_test_` accepted in production paths is a finding (test/live confusion)

## Key Vulnerabilities

### Webhook Signature Verification Bypass

The canonical payment-integration bug. Gateways sign the **raw HTTP request body** with HMAC-SHA256; the application must verify against the identical raw bytes. The mismatch class:

- **Re-serialization before verification:** framework middleware parses JSON, then the verification function re-serializes it — `json.dumps()` default separators add spaces, reorder keys, or normalize Unicode, producing a different byte sequence than what was signed. Measured locally: a 136-byte raw body re-serialized to 148 bytes with Python's default `json.dumps()`, producing a completely different HMAC.
- **Encoding normalization:** the framework decodes the body (charset conversion, form-urlencoded parsing) before passing it to the signature check.
- **Verification disabled entirely:** teams encountering persistent signature failures disable verification rather than fixing the body-passing pipeline — grep for `verify_signature=False`, `STRIPE_WEBHOOK_SIGNING_SECRET` empty/commented, `constructEvent` wrapped in try/catch that swallows failures.
- **Tolerance window abuse:** Stripe's default ±5-minute tolerance allows event replay within that window; a captured webhook can be replayed to trigger duplicate processing if the handler lacks idempotent guards.

**Impact of bypass:** an attacker sends forged webhook events (e.g., `checkout.session.completed`, `payment_intent.succeeded`) to the application's webhook endpoint, triggering fulfillment, account upgrades, or credit issuance without any actual payment.

**Adyen specifics:** HMAC key is per-webhook-endpoint; legacy integrations use Basic Auth instead of HMAC — test for both. Adyen's docs explicitly warn against deserializing before HMAC verification.

**Braintree specifics:** signature is a public-key digest scheme, not shared-secret HMAC; the bypass class is the application skipping `Braintree::WebhookNotification.parse` validation entirely.

### Test / Live Key Confusion

- Secret key `sk_test_*` accepted by production application paths — test-mode charges succeed without real payment; the application fulfills the order.
- Publishable key `pk_test_*` used in production frontend — creates test-mode PaymentIntents that the backend may accept.
- Restricted keys (`rk_live_*`) with overly broad permissions — a key intended for webhooks also has `charges:write`.
- Leaked secret keys in repositories: documented at scale (50,000+ Stripe merchant secrets found in public repos, GitHub Actions logs, and misconfigured servers).

### Idempotency Key Abuse

Stripe uses client-supplied `Idempotency-Key` headers to deduplicate requests. The race:

- Two concurrent requests with the same idempotency key arrive before either commits — both pass the key-existence check and execute, producing duplicate charges.
- Attacker-supplied idempotency keys on refund endpoints: replay a refund request with the same key after the refund window has logically closed but before the key expires (Stripe keys expire after 24 hours).
- Adyen's idempotency is per-reference (`merchantReference`); Braintree uses its own deduplication — test each gateway's mechanism independently.

### Amount and Currency Tampering

- **Client-submitted amount trusted:** the backend creates a PaymentIntent with the amount from the client request instead of computing it server-side from the cart/order. Change `amount: 50000` (representing $500.00) to `amount: 1` in the API call.
- **Currency downgrade:** switch `currency: "USD"` to `currency: "JPY"` (zero-decimal currency) — $500.00 becomes ¥500 (~$3.30). Or switch to a weaker currency at a favorable rate.
- **Capture vs authorize gap:** PaymentIntent authorized for $X, but the capture request accepts a different amount from the client; capture $0.01 on a $500 authorization.
- **3DS/SCA step-up threshold:** transactions below the SCA threshold (€30 under PSD2) skip 3DS challenge; split a large transaction into sub-threshold parts.

Route the state-machine logic (authorize→capture→settle→refund invariants, double-refund, conservation violations) to `business_logic`.

### 3DS / SCA Step-Up Bypass

PSD2 Strong Customer Authentication (SCA) in Europe and similar regulations require 3D Secure challenges above certain thresholds. Bypass patterns:

- **Amount splitting:** break a single €100 transaction into sub-threshold (€29) parts to avoid the 3DS challenge on each.
- **Soft-decline mishandling:** when the issuer soft-declines a non-3DS attempt, the application should retry with 3DS; if it instead fails the payment or retries without 3DS, the attacker can exploit the retry logic.
- **Exemption flag manipulation:** Stripe and Adyen accept exemption indicators (`request_three_d_secure: "any"` vs `"challenge"`; Adyen `executeThreeD: false`); if the application passes client-controlled parameters to these fields, the attacker can request exemptions.
- **Fallback to non-3DS flow:** test whether the application has a legacy payment flow (direct charge vs PaymentIntent) that skips 3DS entirely.

### Stripe Connect and Multi-Party Payment Abuse

Stripe Connect (platforms with connected accounts) adds:

- **Direct charges on connected accounts:** if the platform creates charges on behalf of connected accounts, test whether a connected account ID swap (`stripe_account` header) processes the charge under a different merchant.
- **Transfer manipulation:** platform transfers from platform account to connected account; test whether the transfer amount or destination can be modified via the API.
- **Account impersonation:** leaked platform secret key allows creating charges, transfers, and payouts under any connected account.

### Metadata and Object Exposure

- Stripe object IDs (`cus_*`, `pi_*`, `sub_*`, `ch_*`) are sequential/predictable within a merchant — enumerate customers or charges if the API endpoint lacks per-object authorization.
- Stripe `/v1/customers` or `/v1/charges` with a leaked secret key returns all merchant data.
- Webhook payloads in application logs expose full payment objects including card fingerprints, billing addresses, and metadata fields teams use for internal notes.
- Adyen shopper references and PSP references in URLs/responses may be enumerable.

### Refund and Capture Flow Abuse

Beyond the state-machine invariants owned by `business_logic`, the gateway integration layer has its own refund/capture bugs:

- **Refund to different destination:** some gateways allow specifying a refund destination (e.g., Stripe `refund` with `instructions.destination_details`); test whether the application validates the destination matches the original payment method.
- **Capture amount mismatch:** PaymentIntent authorized for $500, capture request sent for $5000 — gateways may enforce the authorized amount, but the application's logic may not check the gateway's response for partial/failed captures.
- **Void after partial capture:** authorize $500, capture $200, then void the remaining $300 — test whether the application's inventory/fulfillment logic handles the partial correctly or fulfills the full order.

## Testing Methodology

1. **Fingerprint** the gateway (Stripe/Adyen/Braintree) from client bundles; classify all discovered keys (publishable vs secret, test vs live, restricted scope).
2. **Webhook endpoint** — identify the handler path; test with a forged event (correct structure, no valid signature) to check if verification is enforced.
3. **Amount/currency** — intercept the payment creation request; modify amount and currency; confirm the backend re-derives from server-side state.
4. **Idempotency** — send concurrent duplicate requests; verify atomic deduplication.
5. **Test/live confusion** — submit a test-mode key or test-mode PaymentIntent to production flows; confirm rejection.
6. **Key exposure** — grep bundles, git history, CI logs, error responses for secret keys; check restricted-key scope.
7. **3DS/SCA bypass** — test amount splitting below the €30 SCA threshold; manipulate exemption flags in the payment creation request; check for legacy non-3DS flows.
8. **Connect / multi-party** — for Stripe Connect integrations, swap the `stripe_account` header to a different connected account; test transfer amount/destination manipulation.
9. **Flow abuse** — route authorize/capture/refund state-machine testing through `business_logic`.

## Validation

1. Webhook bypass: show a forged event (unsigned or mis-signed) accepted by the application and triggering a downstream action (fulfillment, credit, account upgrade).
2. Amount tampering: show the modified amount in the PaymentIntent/charge object after the payment completes.
3. Key exposure: show the leaked key and demonstrate its scope (e.g., list customers, create charges).
4. Idempotency race: show two fulfilled orders/charges from a single intended payment.
5. 3DS bypass: show a transaction above the SCA threshold completing without a 3DS challenge, or an exemption flag accepted from client input.
6. Connect abuse: show a charge or transfer processed under a connected account the attacker does not own.

## False Positives

- Publishable keys (`pk_*`, Adyen client keys) in client bundles — these are **public by design** and are not a finding on their own.
- Webhook endpoint returning 200 on unsigned requests but not actually processing the event (some apps ACK and then verify asynchronously).
- Test/sandbox environments intentionally using test keys — confirm the environment is production before reporting.
- Amount differences due to tax/shipping calculation, not client-submitted amount trust.
- Braintree client tokens — these are short-lived, scoped tokens intended for client use; their presence in client code is expected.
- 3DS challenges triggered correctly on above-threshold transactions — the control is working as designed.
- Stripe Connect platform charges going to the correct connected account — verify the account swap is actually exploitable, not just an expected routing.

## Impact

- Fraudulent order fulfillment via forged webhook events — goods/services delivered without payment.
- Financial loss from amount/currency tampering — payments processed at attacker-chosen amounts.
- Mass customer data exposure from leaked secret API keys.
- Duplicate charges or over-refunds from idempotency races — direct financial loss.
- Regulatory exposure (PCI DSS) from improper key handling or card data in logs.
- SCA/3DS bypass enabling fraud on European transactions without strong customer authentication.
- Connected-account abuse on platform integrations — charges and payouts routed to attacker-controlled merchants.

## Pro Tips

1. Always test the webhook handler with a correctly-structured but unsigned/mis-signed event first — the most common payment-integration finding.
2. `sk_test_*` in production is often more impactful than `sk_live_*` in a repo — it means the application accepts test-mode payments for real fulfillment.
3. For Stripe, the raw body must be passed to `constructEvent` — if the framework auto-parses JSON middleware (Express `express.json()`, Django, etc.) before the webhook route, the signature will always fail and teams often disable verification as a "fix."
4. Check Stripe Dashboard → Webhooks → "Signing secret" rotation; a never-rotated signing secret increases the replay window.
5. Pair with `business_logic` for authorize/capture/refund state machines; pair with `information_disclosure` for key leakage patterns; pair with `cryptographic_failures` for HMAC implementation review.

## Summary

Payment gateway security is integration security — the gateway platform is sound; the bugs are in how the application verifies webhooks, handles keys, trusts client-submitted amounts, and enforces idempotency. The webhook signature bypass (raw-body re-serialization mismatch or verification disabled) is the canonical finding; test/live key confusion and amount tampering are the next tier. Route payment flow logic to `business_logic`.
