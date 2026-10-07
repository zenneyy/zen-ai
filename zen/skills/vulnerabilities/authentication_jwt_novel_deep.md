---
name: authentication-jwt-novel-deep
description: JWT/OIDC at the 2024–2026 frontier — python-jose CVE-2024-33663 and the CVE-2026-85394 incomplete-fix, PyJWT CVE-2026-48523 PyJWK algorithm-binding bypass and CVE-2026-103001 options-dict mutation regression, jose-swift GHSA-88q6-jcjg-hvmw alg:none, measured per-library primitive matrix, and the PyJWT 2024–2026 advisory-wave class-recurrence pattern.
sibling: authentication_jwt
load_when: scan_mode == "deep"
---

# Authentication / JWT / OIDC — Novel + Frontier Depth

This is the novel+frontier deep sibling to `authentication_jwt.md`. The base owns the class framing, the measured PyJWT-hardening finding, the CVE-2022-21449 ECDSA all-zeros per-algorithm table, JWKS-spoofing basics, and the testing-methodology spine. The advanced+expert sibling `authentication_jwt_advanced_deep.md` owns JWS/JWE edge-case verification, JWKS rotation and SSRF chain construction, kid-injection sub-classes, header-trust-hierarchy confusion, cross-service aud/typ confusion, OIDC mix-up and PKCE/DPoP depth, and composite-chain construction. This file owns the 2024–2026 CVE mechanism decompositions with the canonical version/GHSA table, the measured per-library algorithm-confusion and alg:none matrix, the PyJWT advisory-wave class-recurrence pattern, cross-ecosystem frontier comparison, and the RFC-9700 / OAuth-2.1 verifier-side implications.

Load this file when the goal is matching a target against a current CVE, reasoning about the measured per-library primitive status before firing, or planning a chain whose first hop depends on which library version is actually deployed.

Every CVE number, version boundary, GHSA identifier, and patch-mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch9-20261003/{ghsa,nvd,docs}/` per the 1:1 manifest at `.zen-batch-artifacts/batch9-20261003/manifest/manifest.md`, and every measured primitive is reproduced by a persisted script+output under `.zen-batch-artifacts/batch9-20261003/measurement/`.

## 2024–2026 JWT CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version and GHSA metadata lives here.

| CVE | GHSA | Package | Vulnerable | Patched | CVSS | CWE | Primitive |
|---|---|---|---|---|---|---|---|
| CVE-2024-33663 | GHSA-6c5p-j8vq-pqhj | python-jose | `<3.4.0` (CPE: `<=3.3.0`) | 3.4.0 | 6.5 v3.1 | CWE-327 | Algorithm confusion via OpenSSH-encoded ECDSA keys passed as HMAC secret |
| CVE-2026-85394 | *(no GHSA mapping; VulnCheck-assigned)* | python-jose | `<=3.5.0` (per description; NVD has no CPE config yet) | **not yet released** (no 3.5.1 tag at verification) | 9.3 v4 / 9.1 v3.1 | CWE-347 | DER-encoded public key accepted as HMAC secret — incomplete fix of CVE-2024-33663 |
| CVE-2026-48523 | GHSA-jq35-7prp-9v3f | PyJWT | `>=2.9.0,<2.13.0` | 2.13.0 | 5.4 v3.1 | CWE-347 | `PyJWK` algorithm allow-list bypass — header `alg` checked, signature verifies with the PyJWK-bound algorithm |
| CVE-2026-103001 | GHSA-gvp8-978c-rx2q | PyJWT | `>=2.11.0,<=2.13.0` | **2.14.0** (measured, see note below) | 6.5 v3.1 | CWE-471 | `_merge_options()` mutates caller-supplied options dict in place, silently disabling claim validation on reuse |
| *(no CVE assigned)* | GHSA-88q6-jcjg-hvmw | jose-swift | `<=6.0.1` | 6.0.2 | high (GHSA; no numeric CVSS published) | CWE-327 | `alg:none` short-circuit in `JWS+Verify.swift` returns `true` without any cryptographic check |
| CVE-2022-21449 | *(none)* | Oracle JDK | 17 ≤ 17.0.2; 18 GA; GraalVM EE 21.3.1 / 22.0.0.2 | Oracle April 2022 CPU (JDK 17.0.3 / 18.0.1) | 7.5 v3.1 | CWE-347 (industry mapping; NVD lists `NVD-CWE-noinfo`) | ECDSA `(r,s)=(0,0)` "psychic signatures" — the all-zeros per-algorithm table lives in the base |
| CVE-2022-29217 | GHSA-ffqj-6fqr-9h24 | PyJWT | `>=1.5.0,<2.4.0` | 2.4.0 | 7.4 v3.1 | CWE-327 | Historical class-shape kin to CVE-2024-33663 and CVE-2026-85394 — PEM-encoded public key accepted as HMAC secret |

Notes on the table:

- **CVE-2026-103001 fix version is a measured correction.** The GHSA advisory record at persist time (2026-10-03, three days after publication) lists `first_patched_version: null`. Local measurement against PyPI-published PyJWT releases (`.zen-batch-artifacts/batch9-20261003/measurement/output/04_merge_options_mutation__*.out`) shows the mutation primitive injects seven `verify_*=False` keys on 2.11.0 / 2.12.1 / 2.13.0 and zero keys on 2.14.0 — the fix shipped in 2.14.0 even though the GHSA record has not been updated. Cite 2.14.0 as the OSS fix; do not propagate the null.
- **CVE-2026-85394 has no GHSA mapping and no NVD CPE configuration yet.** The description chains it explicitly to CVE-2024-33663 as an incomplete-fix bypass. Reference the VulnCheck advisory URL and the python-jose issue #414 that NVD lists; cite affected as "python-jose through 3.5.0" and fixed as "not yet released; the maintainer repository is unarchived but has no 3.5.1 tag at verification time."
- **GHSA-88q6-jcjg-hvmw (jose-swift) has `cve_id: null`.** Cite the GHSA only. The primitive is the classic alg:none bypass — the finding is its 2026 recurrence in a freshly maintained JOSE ecosystem (Swift), not a new primitive class.
- **CVE-2022-21449 is the historical anchor.** The all-zeros per-algorithm forgery table is in `authentication_jwt.md § Signature Verification`. This file references it by number without re-stating the table.
- **The two 2022 CVEs anchor the class-recurrence pattern.** CVE-2022-29217 is the primitive's first appearance in Python; CVE-2024-33663 is its OpenSSH recurrence; CVE-2026-85394 is its DER recurrence. The pattern is in § Class-Recurrence Pattern below.

## python-jose Algorithm Confusion with OpenSSH ECDSA Keys — CVE-2024-33663

Primitive: python-jose's `jws.verify()` resolves the signing algorithm from the token header's `alg` and dispatches to an algorithm handler. The handler for HMAC families (`HS256`/`HS384`/`HS512`) accepts a `key` argument of arbitrary type and feeds it to HMAC's `.update()` as bytes. When the server-side key material is a public key encoded in a format python-jose does not reject as asymmetric-shaped (OpenSSH `ssh-ed25519` / `ecdsa-sha2-nistp256` wire format, raw-DER-encoded public keys, SEC1-formatted elliptic-curve public keys), the handler hashes the public-key bytes as an HMAC secret. An attacker who has the public key — which is public by definition — forges tokens by signing them with HS256 using the same key bytes.

**Reachability preconditions:**

1. Application uses python-jose for JWT verification in a version matching `<3.4.0` (CPE: `<=3.3.0`). Discovery: `pip freeze | grep python-jose`, `requirements.txt` leakage, error-string fingerprint (`JWKError: Unable to find an algorithm` is the python-jose signature; `JOSEError` is sibling), or inferred from framework defaults (Starlette-based projects, FastAPI-oauth2-flows, and Flask projects documented against python-jose are the common surfaces).
2. The verifier reads a public key from a source whose encoding python-jose does not detect as asymmetric. PEM encoding is detected post-CVE-2022-29217 (the blocklist checks for `-----BEGIN PUBLIC KEY-----` and sibling markers); OpenSSH wire format (`ssh-ed25519 AAAA...`) and raw-DER buffers (binary bytes with no textual markers) are not. The verifier `open('ec_pub.pem').read()` is caught by the blocklist; `open('ec_pub_openssh').read()` is not; `open('ec_pub.der', 'rb').read()` is not.
3. The server does not pin the algorithm in `jwt.decode(..., algorithms=["RS256"])`; a caller that passes `algorithms=["HS256","RS256"]` or inherits the default list permits the HMAC path. The default is library- and version-dependent — python-jose required `algorithms` to be non-empty but did not require it to be a single-element list until the fix.

**Sink location.** The vulnerable path is in `jose/backends/cryptography_backend.py` and sibling backends: the HMAC algorithm handler's constructor accepts arbitrary byte-containing key material without inspecting whether the bytes correspond to a public-key encoding. NVD's description (`nvd/CVE-2024-33663.json`): "python-jose through 3.3.0 has algorithm confusion with OpenSSH ECDSA keys and other key formats. This is similar to CVE-2022-29217."

**Payload shape:**

```python
# Server trusts an ECDSA public key, in SSH wire format
key_bytes = open('/etc/trust/ssh_pub.key', 'rb').read()  # 'ssh-ed25519 AAAA...' content

# Attacker reads the public key (world-readable, or from a key-publishing endpoint)
pub = key_bytes  # or a DER-encoded version produced by `openssl ec -pubout -outform DER`

# Attacker forges HS256 token using the public key as HMAC secret
import hmac, hashlib, base64, json

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
claims = b64u(json.dumps({"sub": "admin", "role": "root", "iat": 1700000000, "exp": 1900000000}).encode())
sign_input = (header + "." + claims).encode()
sig = b64u(hmac.new(pub, sign_input, hashlib.sha256).digest())
token = f"{header}.{claims}.{sig}"
```

The server reads its public key, calls `jwt.decode(token, pub, algorithms=["HS256","RS256"])` (or defaults), python-jose dispatches to `HS256`, the HMAC handler receives `pub` as the key, computes `hmac.new(pub, sign_input, sha256)`, and the result matches the attacker's signature.

**Payload-shape variants.** The primitive accepts any encoding that reaches HMAC's `.update()` without being blocked. OpenSSH wire format is the most common; raw-DER-encoded SubjectPublicKeyInfo is the sibling that CVE-2026-85394 exploits; raw-SEC1 EC-point encoding is a lesser-tested variant; PKCS#1-DER for RSA is the RSA-side equivalent. For each, the HMAC secret is the exact byte sequence the server passes to the handler — not a transform of it.

**Patch shape.** Version 3.4.0 extends the blocklist that CVE-2022-29217 established to cover OpenSSH-encoded and DER-encoded asymmetric-key material. The guard checks the key bytes for the asymmetric-key markers of each supported encoding before accepting the HMAC path. The patch diff (persisted at `.zen-batch-artifacts/batch9-20261003/other-sources/python-jose-3.4.0-diff.txt` where available via the GHSA references) shows a new helper function that detects OpenSSH magic bytes and PKCS#8/SPKI DER structures.

**Confirmation.**

1. Fetch the server's public key via a key-publishing endpoint (`/.well-known/openid-configuration` → `jwks_uri` → `/jwks.json`, or any introspection endpoint that returns keys).
2. Attempt the forged HS256 token with the public key as the HMAC secret, under both the raw PEM form and an OpenSSH-encoded form.
3. Positive signal: the server returns a 200 response as if the token were valid; the response is consistent with the forged `sub`/`role` (admin-only data, elevated response shape).
4. Negative-control: a token signed with a *different* value (random HMAC secret of the same length as the public key bytes) is rejected. The pair establishes the forgery is bound to the pub-key-as-secret primitive, not accepted-but-ignored.
5. Pre-fix vs post-fix differential: against a 3.4.0+ deployment the OpenSSH form rejects; against a 3.3.0 deployment both accept.
6. Error-string fingerprint: a 3.3.0 python-jose rejecting the forgery (because of some other check, like allowlist mismatch) produces a distinct error from `jose.exceptions.JWTError` versus a 3.4.0 blocklist rejection; capturing the exact error text locates the version band.

**Impact framing.** Direct impact is full forgery of any JWT the server would accept — the attacker controls `sub`, `aud`, `scope`, every claim. For microservice fabrics with cross-service token acceptance (see `authentication_jwt_advanced_deep.md § Cross-Service aud / typ Confusion`), the chain reaches every service that verifies with the same public key. For first-party-only servers the impact is bounded by the server's own authorization logic — but any claim-based decision (role, scope, group, tenant) is attacker-controlled.

**Class generalization — asymmetric-key format inventory as the hunt lead.** CVE-2022-29217 fixed PEM. CVE-2024-33663 fixed OpenSSH. CVE-2026-85394 is DER. The pattern is: every public-key encoding the server might read into bytes that python-jose does not detect is a candidate for the next advisory. Hunt leads for the current frontier: JWK-formatted bytes passed as HMAC secret, X.509-certificate-raw-DER bytes passed as HMAC secret, PKCS8-DER-encoded private key material (if any server mistakenly serves one), BER encodings. The CVE-2026-85394 incomplete-fix pattern is explicitly documented below.

## python-jose DER-Encoded Public Key as HMAC Secret — CVE-2026-85394 (Incomplete Fix of CVE-2024-33663)

Primitive: python-jose 3.4.0 added the OpenSSH/raw-DER blocklist in response to CVE-2024-33663, but the blocklist's DER detection is incomplete — specific DER encodings of the same public key fall outside the pattern python-jose inspects. An attacker who DER-encodes the server's public key (via `openssl ec -pubout -outform DER` for an EC key, or via a direct `cryptography.hazmat.primitives.serialization.PublicFormat.PKCS1` serialization) reconstructs the CVE-2024-33663 primitive against patched 3.4.0 / 3.5.0 deployments.

**Reachability preconditions:**

1. Application uses python-jose in a version matching `<=3.5.0` (the current repository head at verification time has no 3.5.1 tag; the maintainer repository is unarchived but has not shipped the next fix).
2. The server passes public-key bytes to `jwt.decode()` as the `key` argument; the bytes are DER-encoded in a form the 3.4.0 blocklist does not catch — specifically PKCS#1-DER for RSA (the raw `RSAPublicKey` sequence without the SubjectPublicKeyInfo wrapper) or SEC1-DER for EC keys.
3. The server does not pin the algorithm to the asymmetric family it expects.

**Sink location.** Same handler as CVE-2024-33663 — the HMAC algorithm handler accepts the DER bytes as a secret and HMAC-signs the input. The patch gap is in the blocklist, not the handler; the handler cannot distinguish an attacker-crafted DER buffer from a legitimate HMAC secret of similar length. The relevant source file is still `jose/backends/cryptography_backend.py` at the same handler as CVE-2024-33663; the fix added OpenSSH and SPKI-DER detection but did not catch the sibling encodings.

**Patch shape.** Not yet released. The maintainer repository has no 3.5.1 tag at verification time (2026-10-03); the fix pattern will presumably extend the blocklist to recognize the DER-PKCS1/SEC1 variants, or (preferably) rewrite the asymmetric-key-detection to use the `cryptography` library's own key-loading, which would recognize every encoding uniformly. Mitigation shape in the interim: pin algorithms explicitly (`algorithms=["ES256"]` not `["ES256","HS256"]`); do not pass raw public-key bytes as a `key` argument — pass the `cryptography`-library key *object*, which routes through a different code path that does not reach the HMAC handler.

**Payload shape:**

```python
# Server passes DER-encoded public key as the 'key' argument
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
pem = open('ec_pub.pem', 'rb').read()
pub = load_pem_public_key(pem)

# SPKI-DER (standard, caught by 3.4.0 blocklist)
der_spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

# PKCS#1-DER for RSA (not caught by 3.4.0 blocklist — the CVE-2026-85394 variant)
# For an RSA key:
pkcs1_der = pub.public_bytes(Encoding.DER, PublicFormat.PKCS1)

# SEC1-DER for EC (variant to try on EC keys)
# cryptography's PublicFormat.SubjectPublicKeyInfo for EC includes the OID wrapper;
# the raw SEC1 EC-point encoding is distinct and may fall outside the blocklist
# depending on the exact 3.4.0 patch logic.

# Attacker signs HS256 with the un-caught DER buffer as HMAC secret
# ... HMAC construction identical to the previous section, using `pkcs1_der` instead of PEM text
```

**Confirmation.** Identical to CVE-2024-33663 but with DER-encoded key material. Positive-control: a 3.3.0-era payload (OpenSSH or SPKI-DER) fails on 3.4.0; a PKCS#1-DER or SEC1-DER payload succeeds on 3.4.0 and 3.5.0. The exact DER variant the blocklist misses must be matched to the python-jose 3.4.0 patch; read the patch diff to pick the right one.

**Impact framing.** Same as CVE-2024-33663 — full forgery. The incremental value of knowing about CVE-2026-85394 specifically is that it reaches targets that have patched to 3.4.0 and 3.5.0, which are the common recommendations in advisory feeds through 2026.

**Class generalization — the blocklist-extension anti-pattern.** When the fix is "add this encoding to the blocklist," the adjacent-bug prediction is "find the sibling encoding." The hunt lead for the python-jose line specifically: the next encoding to try after DER is a hex-encoded or base32-encoded wrapper of the same bytes (surprising, but libraries that accept flexible key material can land on these), or a JSON-serialized representation (`'{"kty":"EC","x":"...","y":"..."}'` as literal string bytes, hashed as HMAC secret). See also `authentication_jwt_advanced_deep.md § Post-Fix Adjacent-Bug Prediction` for the general shape.

## PyJWT PyJWK Algorithm-Binding Bypass — CVE-2026-48523

Primitive: PyJWT 2.9.0 introduced the ability to pass a `PyJWK` object (or a `PyJWKClient`-sourced key) as the `key` argument to `jwt.decode()`. The code path for `PyJWK` keys reads the algorithm from the key's binding (`key.Algorithm`) and uses it for signature verification, while the `algorithms` allowlist check compares against the token header's `alg`. An attacker who controls a token signed under an algorithm the key's binding does not match — but whose header `alg` is in the caller's allowlist — passes the allowlist check and reaches signature verification under the key's bound algorithm. On a mismatch the signature does not verify, but the allowlist bypass is itself the primitive: it widens the set of tokens the verifier will attempt to verify, enabling confusion attacks that the allowlist was supposed to prevent.

**Reachability preconditions:**

1. Application uses PyJWT in a version matching `>=2.9.0,<2.13.0`. Discovery: `requirements.txt` leakage, dependency-manifest endpoints, the error-string fingerprint `InvalidKeyError: asymmetric key ...` (PyJWT ≥ 2.0), and the response-time differential between HS and RS verification (RS is slower than HS by a measurable floor).
2. The verifier calls `jwt.decode(token, key=<PyJWK>, algorithms=[...])` where `<PyJWK>` is a `PyJWK` object bound to one algorithm, and `algorithms` includes a different algorithm family. The common code pattern is `jwt.decode(token, key=client.get_signing_key_from_jwt(token).key, algorithms=["RS256","HS256"])` — a double-algorithm allowlist for compatibility with legacy signers.
3. The attacker can present a token whose header `alg` claims the different family (passing the allowlist check), while being signed in a way that verifies against the PyJWK's bound algorithm — or triggers a cross-family primitive the earlier allowlist would have blocked.

**Sink location.** `jwt/api_jwt.py` and `jwt/api_jws.py` — the key resolution path when `key` is a `PyJWK`. The pre-fix code read `key.Algorithm` to pick the verification algorithm after the header-alg check passed; the fix at commit `0540c6b` (PyJWT 2.13.0) rejects the token when the token header's `alg` does not match the key's bound algorithm with the error string `"Token algorithm '{header_alg}' does not match the key's algorithm '{key_alg}'"`.

**Measured primitive — pre-fix vs post-fix.** From `.zen-batch-artifacts/batch9-20261003/measurement/output/03_pyjwk_algorithm_binding__pyjwt-2.12.1.out` and `.../pyjwt-2.13.0.out`:

- **PyJWT 2.12.1 (vulnerable):** `jwt.decode(hs_signed_token, pyjwk_bound_to_RS256, algorithms=["RS256"])` reaches HMAC verify (the allowlist check saw header `alg="HS256"` is in `["RS256"]`? no — see the broader allowlist scenario below); the test harness demonstrates the primitive reaches the signature-verification step rather than being rejected at allowlist-check time, falling off into an `InvalidSignatureError` only because the HMAC signature does not match the attacker's secret-of-choice.
- **PyJWT 2.13.0 (fixed):** `jwt.decode(...)` raises before signature verification with `Token algorithm 'HS256' does not match the key's algorithm 'RS256'` — the exact error string the fix added.

**Exploitation refinement.** The simple PyJWK-bound-to-RS256-plus-caller-allowlist-is-RS256 case does not grant forgery because the allowlist check still catches the HS256 header. The exploitable case is the broader-allowlist scenario: `jwt.decode(token, key=<PyJWK bound to RS256>, algorithms=["RS256","HS256"])`. In that case the HS256 token passes the allowlist, PyJWT routes to the PyJWK-key-selection, the pre-fix code uses the PyJWK's bound algorithm (RS256) for verification against the HS-signed token — resulting in signature failure, which is still just an error — but combined with a secondary primitive where the key material can serve both algorithms (RSA public key bytes HMACed as the HS secret, the RS→HS confusion variant on the PyJWK code path), the attacker constructs a token that verifies.

**Practical primitive requires one of:**

- (a) A weak HMAC secret the attacker can brute-force (see `authentication_jwt_advanced_deep.md § HS-Family Secret Discovery Depth`), and a PyJWK bound to an HS algorithm that is in the caller's allowlist.
- (b) A server that passes the raw RSA public-key bytes as the `PyJWK` secret for the HS path and accepts an HS-signed-under-the-public-key token (the RS→HS confusion variant on the PyJWK code path).
- (c) A `PyJWKClient` with a weakness in the JWKS fetch (see the advisory wave below — CVE-2026-102267 redirects, CVE-2026-48522 scheme-allowlist). The chain upstream of CVE-2026-48523 provides attacker-controlled key material.

**Patch shape.** The 2.13.0 fix adds a token-header-alg vs key-bound-alg comparison before any verification attempt. If the two disagree the function raises the quoted error string. The fix is implemented as a guard at the entry of the verification path, not inside the algorithm handler — the guard reads both `header.alg` and `key.algorithm_name` and compares before dispatch.

**Confirmation.**

1. Construct a `PyJWK` bound to one algorithm (e.g., `RS256`).
2. Issue a token with header `"alg":"HS256"`, signed with a known HMAC secret (any value).
3. Call `jwt.decode(token, key=<PyJWK>, algorithms=["RS256"])`. On PyJWT 2.12.1 the call reaches signature verification; on 2.13.0 the call raises the exact "Token algorithm '...' does not match the key's algorithm '...'" error. The verbatim measured string is captured at `.../03_pyjwk_algorithm_binding__pyjwt-2.13.0.out`.
4. Then call `jwt.decode(token, key=<PyJWK>, algorithms=["RS256","HS256"])`. Observe whether PyJWT reaches HMAC verify (pre-fix path exposed) or rejects early (fix path).
5. Error-string fingerprint lands the version: the "Token algorithm ... does not match the key's algorithm" string identifies 2.13.0+; the fall-through to `InvalidSignatureError` identifies 2.9.0–2.12.1.

**Impact framing.** The direct impact is a signature-verification allowlist bypass — the attacker reaches the verification path the allowlist was supposed to block. Combined with one of the three secondary primitives above the chain is full forgery; without one of them the primitive is bounded to the information-disclosure value of "my token reached signature verify" (useful for side-channel timing, less so for direct impact).

**Class generalization — the "two-source-of-truth" verification anti-pattern.** When one source (token header) and another source (key metadata) each independently specify the algorithm, and the verifier picks one without reconciling the two, the primitive is the mismatch. The hunt lead: any JWT library that supports typed key objects (not just raw bytes) and does not require the caller to pin algorithms twice (allowlist + key-level binding). Node's `panva/jose` library has a similar design and may be a candidate for a sibling advisory; the Go `go-jose` library's handling of `JSONWebKey` as a key-with-metadata is another candidate. See § Cross-Ecosystem Frontier Comparison below.

## PyJWT `_merge_options` Dict-Mutation Regression — CVE-2026-103001

Primitive: PyJWT's internal `_merge_options()` function merges caller-supplied `options` with library defaults. The 2022-era fix (PR #743, shipped in 2.4.0) wrapped the merge in a shallow-copy so the caller's dict was never mutated. A 2025 refactor (PR #1045, merged 2025-03-05 by @auvipy) dropped the shallow-copy as part of a typing cleanup, reintroducing the pre-2.4.0 bug. The regression affects PyJWT 2.11.0 through 2.13.0 inclusive. When a caller passes `options={"verify_signature": False}` for an insecure-peek operation and later reuses the same dict for a verified decode, the first call silently mutates the dict to add `verify_exp=False`, `verify_nbf=False`, `verify_iat=False`, `verify_aud=False`, `verify_iss=False`, `verify_sub=False`, and `verify_jti=False` — the "verify_signature is falsy so skip claim-validation defaults" code path writes these flags into the caller's dict. The second verified decode reads the now-mutated dict and skips all claim validations.

**Reachability preconditions:**

1. Application uses PyJWT in a version matching `>=2.11.0,<=2.13.0`. (Fix landed in 2.14.0 — measured correction; see table note.)
2. The application's code reuses a single `options` dict across two `jwt.decode()` calls: one with `verify_signature=False` (a token peek, typically for inspecting claims before verification), then a second with the key and signature verification turned back on.
3. The attacker can present a token whose claim validation would otherwise reject it (expired `exp`, wrong `iss`, wrong `aud`, future `nbf`, missing `jti` where enforced).

**Common exposed code patterns.** The reused-dict shape is unusual in isolation but common in specific middleware designs:

- **Audit logger** that reads token claims before verification for log enrichment, then passes the same dict to the real verifier.
- **Token-type routing middleware** that peeks `typ` or `aud` to pick the right verifier (ID-token verifier vs access-token verifier), then calls the chosen verifier with the same options.
- **SSO claim-extraction** that reads `sub`, `iss` for session-building before signature verify, then verifies.
- **Dev-mode debug middleware** that logs full claim sets insecurely and in production forgets to reset the options dict.
- **Caching layer** that stores a parsed-but-unverified claim set in a cache keyed by signature-hash, then re-verifies on each access with the shared options.

**Sink location.** `jwt/api_jwt.py` — the `_merge_options()` call site inside `_decode()` and sibling internal functions. The vulnerable code mutates the caller's mapping in place when `verify_signature` is falsy; the fix wraps the mutation with `options = dict(options)` before any assignment.

**Measured primitive — pre-fix vs post-fix.** From `.zen-batch-artifacts/batch9-20261003/measurement/output/04_merge_options_mutation__pyjwt-2.11.0.out` and `.../pyjwt-2.14.0.out`:

- **PyJWT 2.11.0 / 2.12.1 / 2.13.0 (vulnerable):** calling `jwt.decode(token, options={"verify_signature": False})` with `options` as a reused dict mutates the dict in place; the measured delta is 7 keys injected (`verify_exp`, `verify_nbf`, `verify_iat`, `verify_aud`, `verify_iss`, `verify_sub`, `verify_jti`, each set to `False`). A subsequent `jwt.decode(expired_token, key, options=<same dict>, algorithms=["HS256"])` accepts the expired token because the mutated dict said "do not verify exp."
- **PyJWT 2.14.0 (fixed):** 0 keys injected. The caller's dict is untouched after the insecure-peek call. The subsequent verified decode uses the library defaults and rejects the expired token.

**Patch shape.** The 2.14.0 fix (not 2.13.0 — the GHSA record at persist time listed `first_patched_version: null`; local measurement against PyPI releases proved 2.14.0 is the first unaffected version) restores the pre-regression `options = dict(options)` shallow-copy at the entry of `_merge_options()`. The exact commit lands upstream of the 2.14.0 release tag.

**Payload shape:**

```python
# Vulnerable application code pattern (common in SSO / introspection / audit flows)
import jwt

reused_opts = {"verify_signature": False}

def peek_claims(token):
    """Insecure peek used by audit logger before verification."""
    return jwt.decode(token, options=reused_opts)  # mutates reused_opts in place on <=2.13.0

def verify_token(token, key):
    """Supposed to actually verify."""
    return jwt.decode(token, key, options=reused_opts, algorithms=["HS256"])  # reads mutated opts

# Attacker presents an expired token
# peek_claims -> opts is mutated to disable all claim validation
# verify_token -> validates signature only; expired / wrong-audience token is accepted
```

**Advanced exploitation — single-call primitive.** The simplest exposed pattern (two calls to `jwt.decode`) is not the only exploit. Any caller that uses the mutated-dict output of one call as input to another verification layer propagates the mutation. The chain shape: insecure peek in one framework layer, pass the options to a sibling framework layer that reads from it, bypass claim validation in the second layer. Common in multi-stage auth middleware stacks.

**Confirmation.**

1. Identify a code path in the target that invokes an insecure-peek on inbound tokens (common for audit, SSO claims introspection, or token-type routing).
2. Present a token in the same session whose signature is correct (brute-force the HMAC secret, use a captured legitimate token, or supply a signed token under any accepted key) but whose claim validation should fail — expired `exp`, wrong `aud`, missing `sub`.
3. Positive signal: post-peek endpoint accepts the expired token.
4. Negative control: against PyJWT 2.14.0+, the same payload is rejected on claim validation (`InvalidAudienceError`, `ExpiredSignatureError`, etc.).
5. Confirmation via side-channel: issue the same token twice back-to-back — first time with the peek-triggering path, second time without. If the second-time response differs on identical signature but different claim-time, the mutation is the mechanism.

**Impact framing.** The primitive is a session-scoped claim-validation bypass; it preserves the signature-verification layer. For deployments where the token's `aud`/`iss` is the only cross-service boundary (common in microservice fabrics using signed-but-not-sender-constrained tokens), this is cross-service access. For deployments where `exp` is the only revocation surface (common for long-session SSO), this is session-after-revocation access. The scope is bounded by what the signature-verified-but-claim-ignored token can reach.

**Class generalization — the refactor-regression pattern.** The 2022 fix was a shallow-copy; the 2025 refactor dropped it as part of a typing cleanup. The hunt lead for the frontier: any library whose test suite does not include an aliasing-detection assertion (did the caller's input mutate?) is one refactor away from reintroducing the mutation bug. The adjacent-bug prediction after CVE-2026-103001: audit the full PyJWT 2025 refactor diff for other defensive measures the typing pass might have dropped — argument shallow-copies, defensive `is None` checks on previously-defaulted parameters, immutability guards on module-level constants.

## jose-swift `alg:none` Short-Circuit — GHSA-88q6-jcjg-hvmw

Primitive: jose-swift (SwiftPM, `github.com/beatt83/jose-swift`) through 6.0.1 implements signature verification in `Sources/JSONWebSignature/JWS+Verify.swift` with a guard at the top of the verify function:

```swift
guard SigningAlgorithm.none != protectedHeader.algorithm else {
    return true
}
```

The intent of such a guard in a library that explicitly supports the `none` algorithm is to short-circuit on tokens with `alg:none` and skip the signature step. The implementation returns `true` unconditionally — any token with `"alg":"none"` passes verification regardless of signature content, regardless of claim content, regardless of the caller's allowlist. The primitive is the classic alg:none bypass recurring in a freshly maintained JOSE ecosystem.

**Reachability preconditions:**

1. Application uses jose-swift in a version matching `<=6.0.1`. Discovery is more constrained than Python-side libraries: swift projects pin via `Package.swift` or `Package.resolved`; mobile apps bundle the library in the compiled binary and library discovery requires either binary analysis (strings on the binary + known jose-swift class names) or metadata-based attribution.
2. The verifier calls the JWS verification entry point with an attacker-supplied token.
3. The attacker sets `"alg":"none"` in the header. No caller-side opt-in to `none` is required — the library's `else` arm applies unconditionally.

**Common exposed deployments:**

- iOS and macOS apps using jose-swift for session JWTs read from the Keychain or deep links.
- Server-Swift deployments (Vapor, Hummingbird) using jose-swift for API authentication.
- Linux Server-Swift workloads running as auth gateways.
- Build-pipeline tools that use jose-swift to validate signed artifacts.

**Sink location.** `Sources/JSONWebSignature/JWS+Verify.swift` lines 34–37 at the pre-fix revision; the fix at commit `13e5ae6f23ef1487b0dad72540eff414272bd7ca` (PR #62) layers two guards: it rejects `alg:none` when the signature field is non-empty, and it adds a JWT-level algorithm blocklist defaulting to exclude `"none"`.

**Payload shape:**

```swift
// Attacker constructs an alg:none JWT with elevated claims
let header = """{"alg":"none","typ":"JWT"}""".data(using: .utf8)!
let claims = """{"sub":"admin","role":"root"}""".data(using: .utf8)!
let token = header.base64URLEncodedString() + "." + claims.base64URLEncodedString() + "."
// Present `token` to the server; server calls JWS.verify(token); verify returns true; token is accepted
```

```bash
# Equivalent construction from the shell for firing against a Server-Swift target
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '/+' '_-' | tr -d '=')
CLAIMS=$(echo -n '{"sub":"admin","role":"root"}' | base64 -w0 | tr '/+' '_-' | tr -d '=')
TOKEN="${HEADER}.${CLAIMS}."
curl -H "Authorization: Bearer ${TOKEN}" https://target.example/api/me
```

**Patch shape.** Version 6.0.2 (PR #62). The fix is defense-in-depth: the first guard checks the signature-field-non-empty invariant for `alg:none` (rejects a token with `alg:none` and a non-empty signature); the second guard checks the algorithm is in an opt-in allowlist that defaults to excluding `none`. The caller must now explicitly opt into `none` to accept such tokens — a configuration opt-in that is unlikely to appear in production.

**Confirmation.** Issue a token with `alg:none` and attacker-chosen claims; present to the server; observe acceptance. The primitive is unconditional on jose-swift ≤ 6.0.1 — no key knowledge, no HMAC secret, no public key. Negative-control: a token with `alg:none` and a non-empty random signature on 6.0.2+ is rejected by the first fix-guard; on ≤ 6.0.1 it is still accepted (the guard short-circuits before signature inspection). The pair distinguishes 6.0.2+ from ≤ 6.0.1 by one byte in the signature field. Measured verification requires a Swift toolchain; the measurement attempt is captured at `.../05_jose_swift_alg_none.out` with the skip note (no Swift toolchain available on the measurement host).

**Impact framing.** Full forgery of any token the server would accept. If the server reads any claim from the token for authorization decisions, the attacker controls the decision. For mobile apps where the token sources user identity and session scope, the primitive is immediate account takeover.

**Class generalization — the alg:none-support-with-wrong-default anti-pattern.** The JWT spec permits `alg:none` for use cases where signature verification is handled out-of-band. Libraries that implement it must default to refusing unless the caller opts in; libraries that implement it by returning `true` default to accepting. The hunt lead: any JWT library that advertises `alg:none` support should be audited for the default — fetch the implementation, check whether the `none` arm is `return true` or `require explicit allowlist`. Historical siblings in the pattern: the 2015 jsonwebtoken (Node) `alg:none` bug; the 2016 go-jose variant; the 2018 inversoft/prime-jwt variant; the pattern has recurred every ~3 years in different language ecosystems.

## Measured Per-Library alg:none and Algorithm-Confusion Matrix

Measured against PyPI-published versions on 2026-10-03. Reproduced by `.zen-batch-artifacts/batch9-20261003/measurement/scripts/01_alg_none_matrix.py` and `.../02_rs_hs_confusion.py` with outputs under `.../output/`.

| Library / Version | `alg:none` accepted | RS→HS encode (PEM as HMAC) | RS→HS decode (PEM as HMAC) | `PyJWK` alg-binding gap | `_merge_options` mutation |
|---|---|---|---|---|---|
| PyJWT 2.8.0 | No (`InvalidSignatureError` / `InvalidKeyError`) | Blocked at key-prep (asymmetric-key guard) | Blocked (alg allowlist) | — | — |
| PyJWT 2.9.0 | No | Blocked | Blocked | **Yes** (reaches HMAC verify) | — |
| PyJWT 2.11.0 | No | Blocked | Blocked | — | **Yes** — 7 keys injected |
| PyJWT 2.12.1 | No | Blocked | Blocked | **Yes** | **Yes** — 7 keys injected |
| PyJWT 2.13.0 | No | Blocked | Blocked | Fixed (`Token algorithm 'HS256' does not match the key's algorithm 'RS256'`) | **Yes** (still) |
| PyJWT 2.14.0 | No | Blocked | Blocked | Fixed | **Fixed** (0 keys injected) |
| python-jose 3.3.0 | No (`JWKError: Unable to find an algorithm`) | Blocked | Blocked | n/a | n/a |
| python-jose 3.4.0 | No | Blocked | Blocked | n/a | n/a |
| authlib 1.8.0 | **Yes** when caller passes `JsonWebToken(["none"])` — returns `{'sub':'admin','role':'root'}` | Blocked (`ValueError: This key may not be safe to import`) | Blocked | n/a | n/a |
| jwcrypto 1.6.1 | No (`InvalidJWSOperation('Algorithm not allowed')`) | **Succeeds via oct-JWK wrap of PEM** at encode | Blocked (loaded RSA PyJWK carries binding) | n/a | n/a |

Four load-bearing readings from this matrix:

1. **PyJWT's modern defense-in-depth holds** — the asymmetric-key guard at encode and the algorithm-allowlist at decode together block the headline RS→HS confusion across every tested version. An attacker who finds a target with PyJWT ≥ 2.0 must break *both* defenses to execute the classic confusion. The practical attack surface moved to the PyJWK code path (CVE-2026-48523) and the options-dict mutation (CVE-2026-103001) — both are listed above.

2. **authlib's `alg:none` is caller-opt-in but trivially caller-reachable.** If any code path constructs a `JsonWebToken` with `"none"` in its algorithm list — for test fixtures, for a feature flag, for a legacy compatibility hook — authlib accepts alg:none tokens on that path. The measured output shows a successful decode of `{"sub":"admin","role":"root"}`. Hunt lead: `grep -rn 'JsonWebToken(\[' <target_source>` for any list containing `"none"`; `grep -rn '"none"' <target_source>` for any string-literal `"none"` in auth-adjacent code.

3. **jwcrypto's RS→HS encode primitive is partial.** The encode step accepts a PEM-wrapped-as-oct-JWK key, producing a token. The decode step blocks because the loaded RSA PyJWK carries a binding. This is still a primitive against any downstream consumer that accepts the attacker-produced token without re-binding — a cross-library confusion chain where jwcrypto signs and a less-strict verifier accepts. The chain shape: jwcrypto-produced token → network → consumer-side verifier (python-jose 3.3.0, old express-jwt, pre-2.4.0 PyJWT) that accepts the HS-signed-under-public-key token.

4. **PyJWK-alg-binding and options-dict-mutation are the live-frontier PyJWT bugs.** 2.9.0–2.12.1 is PyJWK; 2.11.0–2.13.0 is options-dict; 2.11.0–2.12.1 overlaps. A target on PyJWT 2.12.1 is exposed to both; a target on PyJWT 2.13.0 is exposed only to options-dict until 2.14.0. The exposed-version matrix for a dependency-pinned deployment is:

   | PyJWT version | PyJWK bug | options-dict bug | Combined attack surface |
   |---|---|---|---|
   | ≤ 2.8.0 | No | No | Classic primitives only (patched) |
   | 2.9.0 | **Yes** | No | PyJWK path exposure only |
   | 2.10.x | **Yes** | No | PyJWK path exposure only |
   | 2.11.0 | **Yes** | **Yes** | Both — fingerprint for both primitives |
   | 2.12.1 | **Yes** | **Yes** | Both |
   | 2.13.0 | Fixed | **Yes** | Options-dict primitive only |
   | 2.14.0 | Fixed | Fixed | None |

The reproduction harness is in `.zen-batch-artifacts/batch9-20261003/measurement/`. Fingerprint the target's library via error strings, `requirements.txt` leakage, or dependency-manifest exposure (see `authentication_jwt_advanced_deep.md § HS-Family Secret Discovery Depth` for the discovery techniques), then look up the row.

**Measurement reproduction playbook.** To re-measure against a target version not in the matrix:

```bash
# Create a version-pinned venv
cd .zen-batch-artifacts/batch9-20261003/measurement/
python3 -m venv venvs/pyjwt-<version>
source venvs/pyjwt-<version>/bin/activate
pip install "PyJWT==<version>" cryptography

# Run the primitive scripts
python3 scripts/01_alg_none_matrix.py 2>&1 | tee output/01_alg_none_matrix__pyjwt-<version>.out
python3 scripts/02_rs_hs_confusion.py 2>&1 | tee output/02_rs_hs_confusion__pyjwt-<version>.out
python3 scripts/03_pyjwk_algorithm_binding.py 2>&1 | tee output/03_pyjwk_algorithm_binding__pyjwt-<version>.out
python3 scripts/04_merge_options_mutation.py 2>&1 | tee output/04_merge_options_mutation__pyjwt-<version>.out
```

The scripts emit explicit per-primitive accept/reject lines and the exception types; grep for `ACCEPTED:` and `REJECTED:` prefixes to build the matrix row for a new version.

## PyJWT 2024–2026 Advisory Wave — Class-Recurrence Pattern

The two in-scope PyJWT CVEs sit in a larger 2024–2026 advisory wave. Verification of the `repos/jpadilla/pyjwt/security-advisories` endpoint on 2026-10-03 surfaced twenty advisories; the seven closest-related to the measured primitives each get a mini-decomposition below. Six resolve against the global GHSA endpoint and are persisted by GHSA/CVE identifier; one — the OKP x/d JWK consistency gap — exists only in the PyJWT repository's unpublished draft/triage lifecycle state (the global `/advisories/<id>` and GraphQL `securityAdvisory` endpoints both return 404 / NOT_FOUND at verification time) and is anchored to a behavior fingerprint rather than an identifier per §6.

### CVE-2026-102271 (GHSA-p4g4-x82p-q773) — DER public keys as HMAC secret

Direct Python-side kin to python-jose CVE-2026-85394. PyJWT's asymmetric-key blocklist, which caught PEM-encoded public keys since CVE-2022-29217, did not catch DER-encoded variants until this patch. The sink is the same HMAC construction as the python-jose case: raw public-key bytes pass through the asymmetric-key-detection check and reach HMAC. Confirmation: pass a DER-encoded public key as the server's HMAC secret source; attempt an HS256 forgery with the DER bytes as the signing key. Impact: full forgery, same shape as python-jose CVE-2026-85394 but on PyJWT's side.

### CVE-2026-102268 (GHSA-ffc3-869f-jxw9) — PEM-whitespace detection bypass

The CVE-2022-29217 fix detected PEM-encoded keys by the `-----BEGIN PUBLIC KEY-----` marker. An attacker can mutate the marker's whitespace or line-ending to bypass the regex: `-----BEGIN  PUBLIC KEY-----` (double-space), `-----BEGIN\r PUBLIC KEY-----` (CR-space), `-----BEGIN PUBLIC KEY-----` (non-breaking space). Vulnerable detection matches the exact literal; mutated markers slip through and the handler accepts the key as an HMAC secret. The fix tightens the detection to canonicalize whitespace before comparison. Hunt lead: any blocklist based on exact-literal matching is vulnerable to canonicalization bypasses — Unicode-normalization forms (NFC/NFD/NFKC/NFKD) are the sibling class.

### CVE-2026-102266 (GHSA-9j54-fg26-wv3r) — PyJWK empty-HMAC-key bypass

PyJWT guards against empty HMAC keys at the raw-key API (`jwt.encode('', ..., algorithm='HS256')` raises). The PyJWK code path reaches HMAC via a sibling layer that lacked the guard: a `PyJWK` of type `oct` with an empty `k` field reaches HMAC construction with an empty secret. Attack: construct the empty-key JWK, use it to sign a token, present to a server that resolves JWKs via the vulnerable path. Confirmation: HMAC with an empty key is a known-output function (HMAC-SHA256 of any input with an empty key produces the HMAC of input XORed with the ipad/opad constants); the exact signature of a given payload is computable offline. Impact: full forgery via a known key.

### PyJWT OKP x/d JWK consistency gap — behavior-fingerprinted class (no stable CVE/GHSA)

OKP (Octet Key Pair) JWKs — `Ed25519`, `Ed448`, `X25519`, `X448` — have two components: `x` (public) and `d` (private). PyJWT's `OKPAlgorithm.from_jwk()` constructs the private key from `d` without checking that the public key derived from `d` matches the declared `x`. The result: a JWK can declare one public-key identity (`x`) while the private key PyJWT uses for cryptographic operations corresponds to a different keypair (`d`). The two components can belong to entirely different owners. In DPoP integrations that compute `cnf.jkt` thumbprints from `x` and pass the same JWK to PyJWT for proof verification, an attacker who steals a sender-constrained access token can forge a DPoP proof using their own private key while declaring the legitimate holder's public `x` — the thumbprint matches, the signature verifies, and the token is accepted without the attacker holding the legitimate private key. Behavior-fingerprint: construct an OKP JWK with mismatched `x` and `d`; call `jwt.PyJWK.from_dict()`; observe that no `InvalidKeyError` is raised and `.key.public_key()` returns the public key derived from `d`, not the declared `x`. This primitive is intentionally cited as a behavior-fingerprinted class rather than by advisory identifier: the GitHub advisory for this class exists in the PyJWT repository's unpublished draft/triage lifecycle state and does not resolve on the global advisory endpoints (both the REST `/advisories/<id>` and the GraphQL `securityAdvisory` return 404 / NOT_FOUND at verification time); per §6 the primitive is anchored to the behavior rather than an unpublished identifier. Fix lands in the PyJWT 2.x branch once released; confirmed on `master` by maintainer sign-off.

### CVE-2026-102273 (GHSA-w2cx-738m-mc7w) — public JWK containers as HMAC secret

JWK-shape sibling of the DER-shape and PEM-shape bugs. A JWK container (`{"kty":"RSA","n":"...","e":"AQAB"}`) serialized as JSON and passed as the `key` argument to `jwt.decode()` is treated as literal bytes by the HMAC handler; the JSON-serialized bytes become the HMAC secret. Attack: fetch the server's JWK from `/jwks.json`, re-serialize the JWK container to JSON, HMAC-sign with that string. Confirmation: HMAC with the exact JSON bytes the server sees is reproducible. Impact: full forgery.

### CVE-2026-102267 (GHSA-9v7f-9g4p-ffgj) — PyJWKClient redirect-follow

`PyJWKClient` fetches a JWKS URL and does not disable HTTP redirects. A malicious or malfunctioning `jku`/configured-JWKS URL can redirect the client to an attacker-controlled JWKS endpoint; the client follows and trusts the final response. Chain: use any open redirect on an allowlisted host (see `open_redirect.md` and `open_redirect_novel_deep.md`) to redirect the JWKS fetch to the attacker's response. Impact: attacker-controlled JWKS → forgery via any `jku`-primitive. Compose with `authentication_jwt_advanced_deep.md § JWKS SSRF Chain Construction`.

### CVE-2026-48522 (GHSA-993g-76c3-p5m4) — PyJWKClient scheme-allowlist missing

`PyJWKClient` accepts any URL scheme — `http://`, `https://`, `file://`, `data:`, `gopher://` depending on the underlying HTTP library's support. A `jku="file:///etc/ssh/ssh_host_rsa_key"` reaches the server's local filesystem and loads the private key as the JWKS. Primitive: local-file read reaching private signing-key extraction. Combined with any path-traversal-adjacent primitive (`path_traversal_lfi_rfi.md`) that identifies the private-key file path, the chain is full forgery via the server's own private key. The fix adds a scheme allowlist defaulting to `[https:, http:]`.

### Three class-recurrence patterns across the wave

1. **Blocklist-extension never ends.** CVE-2022-29217 fixed PEM. CVE-2024-33663 added OpenSSH. CVE-2026-85394 adds DER. CVE-2026-102271 adds PyJWT's DER variant. CVE-2026-102268 adds the PEM-whitespace-mutation bypass. CVE-2026-102273 adds the JWK-container shape. The hunt lead: any new asymmetric-key encoding is a candidate for the next advisory; the hunt method is to enumerate the server's key-reading code path and test every encoding its downstream consumers might accept. The disposition for a defender: rewrite the detection to use a positive-identification approach (does the material decode as a valid asymmetric key via the `cryptography` library? if so, refuse the HMAC path) rather than a blocklist.

2. **PyJWK path is a parallel verification surface.** CVE-2026-48523 (PyJWK alg-binding), CVE-2026-102266 (PyJWK empty-key), CVE-2026-102267 (PyJWKClient redirect-follow), CVE-2026-48522 (PyJWKClient scheme-allowlist). The PyJWK code path was added in 2.9.0 and has accumulated its own CVE wave at a cadence of roughly one every few months since. The hunt lead: when the target uses `PyJWKClient` or passes `PyJWK` objects into `decode`, assume the PyJWK path is less-hardened than the raw-bytes path. The disposition for an attacker: fingerprint the specific key-input shape and look up the exposed primitive.

3. **JWKS-fetch chains the SSRF frontier.** Three of seven advisories in this wave are JWKS-fetch bugs. The chain route is through `authentication_jwt_advanced_deep.md § JWKS SSRF Chain Construction` to `ssrf.md`; the primitive granted is "fetch arbitrary URL under the server's identity and trust whatever comes back as a signing key."

## RFC 9700 / OAuth 2.1 BCP Shift and Verifier-Side Implications

OAuth 2.1 (consolidated 2024) and the OAuth 2.0 Security Best Current Practice (RFC 9700, published 2025) make several previously-recommended behaviors mandatory. For JWT verifiers the mandatory shifts most consequential for the frontier each get a subsection below.

### Mandatory PKCE for all clients

RFC 9700 §2.1.1 requires PKCE for every client, confidential and public. Pre-2025 deployments permitted confidential clients to skip PKCE because the client credential already bound the token-exchange request. The RFC-9700 shift closes that gap: an authorization server that advertises PKCE support must enforce it on every exchange. Transition deployments where some clients were migrated and others were not expose the policy-disagreement attack: issue a code from a non-PKCE-enforcing endpoint, cross-present at a PKCE-enforcing endpoint (fails), or vice versa (succeeds if the attacker's client is non-PKCE and the resource endpoint doesn't check). Hunt lead: inspect the authorization server's metadata (`code_challenge_methods_supported`) and probe actual enforcement by presenting a token-exchange request without `code_verifier`.

### Mandatory sender-constrained tokens for cross-origin API access

RFC 9700 §4.1.3 recommends DPoP or mTLS for API access tokens where cross-origin requests are involved. Non-sender-constrained tokens must be rejected if the resource server supports sender-constrained alternatives. Transition deployments where the resource server reads `cnf` but doesn't enforce it fall into `authentication_jwt_advanced_deep.md § DPoP / mTLS / Sender-Constrained Token Bypass`. Hunt lead: a token with a `cnf.jkt` claim presented without the matching `DPoP:` header should be rejected on a RFC-9700-conformant resource server; acceptance is the attack signal.

### Mandatory `iss` identification in authorization responses

RFC 9207 (incorporated by reference in RFC 9700) requires authorization-response `iss` for multi-IdP clients. Deployments without `iss` are vulnerable to the OIDC mix-up class (`authentication_jwt_advanced_deep.md § OIDC Mix-Up`). The verifier-side implication is specifically for the client code — the client reading the authorization response must now check `iss` matches the expected authorization server. Clients that trust the response without `iss` or fall through to a default authorization server are the exposed set.

### Strict `redirect_uri` matching

Full string comparison, no prefix or regex. Deployments with regex-based redirect URI validation fall into the authentik CVE-2024-52289 class (`open_redirect_novel_deep.md § authentik Redirect-URI Regex-Metacharacter Bypass`). Verifier-side implication: the authorization server must stop interpreting the registered `redirect_uri` as a pattern. The adjacent-bug class after RFC 9700: deployments that migrate from regex to prefix-matching (also disallowed by the RFC) rather than strict equality still carry a residual bypass.

### Mandatory `aud` enforcement at the resource server

Pre-2024 verifiers that checked signature and `iss` but not `aud` are explicitly flagged as non-conformant. The verifier-side implication: a resource server must know its own audience identifier and reject tokens whose `aud` does not include it. The transition failure mode: a resource server reads `aud` from a configuration string but accepts a comma-separated list or an array mixing allowed-and-disallowed identifiers. Hunt lead: present a token with `aud: ["expected_svc", "attacker_svc"]` (array including both) to a resource server; acceptance is the signal of substring-contains comparison rather than array-equals.

### Composite impact of the five shifts

The five shifts together narrow the attack surface for a conformant deployment, but widen the surface during the transition. The attacker's position: find the deployments that are partway through adoption. The hunt method: for each service in a federation, probe the five requirements (PKCE enforcement, DPoP/mTLS enforcement, `iss` in response, strict redirect_uri, strict `aud`) and build a conformance matrix. The services with the lowest conformance score are the entry points; the services with highest conformance accept tokens from the lowest-conformance ones through cross-service aud/typ confusion.

## Cross-Ecosystem Frontier Comparison

The 2024–2026 CVE catalog on PyJWT and python-jose above sits in the context of other-language JOSE library ecosystems. The frontier status of each on 2026-10-03 informs chain construction across language boundaries.

**Node.js `jsonwebtoken`.** Historical home of the 2015 `alg:none` and 2016 RS→HS confusion. Current branch (`jsonwebtoken@9.x`) hardened against both; the algorithm must be pinned explicitly. No 2024–2026 CVEs that match the PyJWT advisory wave class-recurrence surfaced in the hard-verification pass; the library's position in the Node ecosystem is settled, with the frontier having moved to downstream wrappers (NestJS Passport-JWT, express-jwt). Watch for callback-mode bugs where `keyFunc` returns an unexpected key.

**Node.js `panva/jose`.** The successor library favored by modern Node TypeScript projects. Supports JWT, JWS, JWE. The library has a strict algorithm-pinning design — the caller passes an explicit `KeyLike` object with a bound algorithm and the library verifies both the header and the key agree. The design is closer to PyJWT's PyJWK model (bound algorithm per key) and might be exposed to the CVE-2026-48523 class of bug by analogy — the hunt lead is: does `panva/jose` reconcile the header algorithm against the key's bound algorithm before verification? Not surfaced in the 2024–2026 hard-verification pass, but worth testing against the local sandbox.

**Go `golang-jwt/jwt`.** The historical home of the Keyfunc-callback-returns-wrong-key class (RS→HS confusion via caller-side bugs). Library-side defaults are hardened; the exposure is almost always in the caller's `Keyfunc` implementation. No library-side 2024–2026 CVEs in the hard-verification pass; the frontier for Go is caller-side audits.

**Go `go-jose`.** Supports JWT, JWS, JWE. Historical home of invalid-curve ECDH attacks (the 2016-era ECDH-ES bug class). Current branch hardened. The design uses `JSONWebKey` objects with embedded algorithm metadata; by analogy to PyJWK, the "two-source-of-truth" verification anti-pattern is a candidate for the next advisory.

**Rust `jsonwebtoken` crate.** Rust's dominant JWT library. Algorithm pinning is enforced by type: the `DecodingKey` carries algorithm metadata and `decode()` requires an explicit `Validation` struct listing the allowed algorithms. The compile-time typing closes most of the Python-side attack surface. No 2024–2026 library-side CVEs in the hard-verification pass.

**Java `nimbus-jose-jwt` and `jjwt`.** Nimbus-JOSE-JWT is the de facto standard for Java JWT. Historical hardening against RS→HS confusion is deep. The current frontier for Java is Spring Security's `JwtDecoder` configuration — see `authentication_jwt_advanced_deep.md § Framework-Specific JWT Middleware Depth`. The CVE-2022-21449 ECDSA all-zeros bug is a JDK bug, not a Nimbus bug — Nimbus delegates ECDSA verification to the JDK and is affected via the JDK.

**.NET `System.IdentityModel.Tokens.Jwt` and `jose-jwt` (NuGet).** Microsoft's JWT handling for ASP.NET Core. The `TokenValidationParameters.ValidAlgorithms` opt-in-only pattern is the frontier risk; see the advanced sibling's ASP.NET Core section. The `jose-jwt` NuGet package is an older third-party library with historical RS→HS confusion bugs; audit the version pinning carefully.

**Swift `jose-swift` and sibling libraries.** `jose-swift`'s GHSA-88q6-jcjg-hvmw is covered above. Sibling Swift libraries (CryptoKit's JWT bridges, Vapor's `JWTKit`) use different implementations; `JWTKit` has algorithm pinning via Swift's type system and is the mainstream server-Swift choice.

The cross-ecosystem comparison is a chain-construction tool. When the target spans multiple languages (microservices with mixed Python / Node / Go / Java backends), the attacker's hunt is for the weakest-link verifier among the services sharing a signing key. The RFC 9700 cross-service shift makes the shared-key approach less common post-adoption, but the transition deployments have mixed enforcement.

## Historical Anchor — CVE-2022-21449 ECDSA Psychic Signatures

The all-zeros per-algorithm forgery table (ES256 / ES384 / ES512 signature byte lengths and the base64url all-A forged signatures) lives in `authentication_jwt.md § Signature Verification`. This section covers the frontier status of the primitive in the 2024–2026 landscape without re-stating the table.

**Deployment status.** Oracle's April 2022 CPU patched Java 17 at 17.0.3, Java 18 at 18.0.1, and GraalVM EE at the corresponding patch. Four years later, the fix is universal on current Oracle JDK; the attack surface persists only on frozen deployments — embedded Java workloads, legacy enterprise appliances, air-gapped systems, and specific vendor-maintained JDK forks that lag Oracle's CPU cadence. OpenJDK downstream distributions typically patch within one to two weeks of the Oracle CPU; vendor-pinned JDKs (IBM, Zulu, Corretto, SapMachine) all shipped within a quarter.

**Current frontier.** The primitive itself is no longer live against mainstream deployments, but three class-generalizations remain actively exploited:

- **Signature-non-canonicalization in non-Java ecosystems.** The underlying bug — accepting an ECDSA signature where `(r,s)=(0,0)` or `r=0` or `s=0` — has recurred in less-maintained libraries. Any library that reimplements ECDSA verification without checking `0 < r < n` and `0 < s < n` is a candidate. The hunt method is to feed `(0,0)`, `(0, s_arbitrary)`, `(r_arbitrary, 0)` to the target's ECDSA verification and observe acceptance.
- **Signature-malleability in blockchain-adjacent code.** Bitcoin's BIP 146 and Ethereum's EIP-2 require canonical signatures (low-s). Libraries that verify signed messages from the ECDSA family without enforcing low-s accept malleable signatures; the primitive is less-dramatic than full forgery but matters for replay-protection and transaction-uniqueness assumptions. Chain into transaction-replay or front-running attacks downstream.
- **Non-ECDSA all-zero equivalents.** EdDSA (Ed25519 / Ed448) has its own canonicalization requirements. Libraries that skip the `s < L` canonicalization check accept non-canonical signatures that correspond to real signing-key work but violate the format; the forgery variant is less direct but similar in shape. The PyJWT OKP x/d-JWK-consistency gap (see § PyJWT 2024–2026 Advisory Wave) is adjacent to this class.

**Frontier library audit targets.** Any library whose ECDSA verification is implemented in-source rather than delegated to a hardened crypto library — specifically custom-crypto in embedded firmware, non-mainstream languages (Nim, Zig, Crystal), and freshly-written libraries. Fingerprint by binary strings or source audit; feed the all-zeros signature. The pattern repeats roughly every two years in a different ecosystem.

Fingerprint by banner — JDK version in the server header, `Server: Apache` with a known JDK pinning, error strings. If the target is on a vulnerable 15–18 JDK validating ES* JWTs, the base-file table is the forgery recipe; otherwise, read the deployment's ECDSA-verification code against the canonicalization-check class.

## Chaining Depth — Frontier Compositions

The 2024–2026 CVE primitives chain with the sibling-skill primitives through the specific capability each one grants. Chains below use the precondition/postcondition shape: predecessor-postcondition grants successor-precondition.

### Chain: python-jose CVE-2024-33663 → cross-service forgery → full fabric compromise

- **Upstream node:** discover the server's public key via `/.well-known/openid-configuration` (information disclosure) → `authentication_jwt_advanced_deep.md § HS-Family Secret Discovery Depth` and `information_disclosure.md` for the discovery techniques.
- **Postcondition of upstream:** attacker holds the public key.
- **Successor precondition:** HMAC the public key bytes to forge an HS256 token (this file § CVE-2024-33663).
- **Postcondition of successor:** token verifies at any python-jose < 3.4.0 service using the same key.
- **Terminal precondition:** cross-service aud/typ confusion → `authentication_jwt_advanced_deep.md § Cross-Service aud / typ Confusion`.
- **Terminal postcondition:** full fabric compromise.
- **Routing:** `information_disclosure.md` → this file § CVE-2024-33663 → `authentication_jwt_advanced_deep.md § Cross-Service aud / typ Confusion`.

### Chain: CVE-2026-48522 (PyJWKClient `file://`) → local-file read → signing-key extraction → forgery

- **Upstream node:** PyJWKClient with scheme-allowlist missing (this file § PyJWT Advisory Wave § CVE-2026-48522).
- **Successor precondition:** `jku="file:///path/to/private.key"` with the server reading the file via PyJWKClient; the attacker must know a reachable private-key file path.
- **Postcondition of successor:** attacker reads the private key from a world-readable location (`/tmp` artifact, backup file, test fixture, Kubernetes secret mounted as a file).
- **Terminal precondition:** sign tokens with the extracted key.
- **Terminal postcondition:** full forgery.
- **Routing:** this file § PyJWT Advisory Wave → `path_traversal_lfi_rfi.md § File Discovery` for the target file path → this file § JWKS-Spoofing (base) for the sign-and-present step.

### Chain: CVE-2026-48523 (PyJWK alg-binding) + weak HMAC → forgery

- **Upstream node:** target server uses PyJWT 2.9.0–2.12.1 and passes a `PyJWK` wrapping an HS secret (unusual but observed in deployments that use `PyJWKClient` with a `kty:oct` entry) with a caller-allowlist of multiple algorithms.
- **Successor precondition:** brute-force the HMAC secret → `authentication_jwt_advanced_deep.md § HS-Family Secret Discovery Depth`.
- **Postcondition of successor:** attacker holds the HMAC secret.
- **Terminal precondition:** construct an HS-signed token that passes the broadened allowlist (this file § CVE-2026-48523).
- **Terminal postcondition:** forgery.
- **Routing:** this file § PyJWT Advisory Wave § PyJWK → `authentication_jwt_advanced_deep.md § HS-Family Secret Discovery Depth` → this file § CVE-2026-48523.

### Chain: CVE-2026-103001 (`_merge_options`) + session-reuse → claim-validation bypass → cross-service access

- **Upstream node:** target server with an insecure-peek code path (audit logger, token-inspection middleware, SSO claims-extraction flow) that reuses an options dict (this file § CVE-2026-103001).
- **Successor precondition:** present a token with signature-correct but claim-invalid structure (expired `exp`, wrong `aud`, missing `iss`).
- **Postcondition of successor:** claim validation is bypassed; token is accepted.
- **Terminal precondition:** cross-service presentation → `authentication_jwt_advanced_deep.md § Cross-Service aud / typ Confusion`.
- **Terminal postcondition:** access to services the token's `aud` would otherwise block.
- **Routing:** this file § CVE-2026-103001 → `authentication_jwt_advanced_deep.md § Cross-Service aud / typ Confusion`.

### Chain: jose-swift alg:none + mobile app token store → account takeover

- **Upstream node:** iOS or macOS app using jose-swift ≤ 6.0.1 for JWT verification.
- **Successor precondition:** construct `alg:none` token with elevated claims and inject into the app's token store via a URL scheme, deep link, or clipboard primitive (see `authentication_jwt_advanced_deep.md § Second-Order Token Confusion`).
- **Postcondition of successor:** stored token is read by the app on next session restore.
- **Terminal postcondition:** app verifies with jose-swift, accepts due to the `return true` guard, treats the attacker as the elevated user.
- **Routing:** this file § jose-swift → `authentication_jwt_advanced_deep.md § Second-Order Token Confusion`.

### Chain: python-jose CVE-2026-85394 (DER) + public-key published → forgery (incomplete-fix path)

- **Upstream node:** target server uses python-jose 3.4.0 or 3.5.0 and publishes its public key.
- **Successor precondition:** DER-encode the public key and HMAC-sign a token with it (this file § CVE-2026-85394).
- **Postcondition of successor:** forgery, bypassing the 3.4.0 OpenSSH blocklist.
- **Terminal precondition and postcondition:** same downstream chains as CVE-2024-33663 — cross-service aud/typ confusion to full fabric compromise.
- **Routing:** this file § CVE-2026-85394 → `authentication_jwt_advanced_deep.md § Cross-Service aud / typ Confusion`.

### Chain: open redirect on registered redirect_uri + OAuth client → code interception → token issuance

- **Upstream node:** registered OAuth client with an exact `redirect_uri` on a host that also hosts an open redirect — `open_redirect.md § OAuth/OIDC` + `open_redirect_advanced_deep.md § OAuth redirect_uri Chain`.
- **Successor precondition:** issue authorization request with `redirect_uri = https://registered.host/out?url=https://attacker.tld/`.
- **Postcondition of successor:** code lands at attacker.tld.
- **Terminal precondition:** exchange code at the token endpoint (as the client, or via a client-impersonation path).
- **Terminal postcondition:** access the account.
- **Routing:** `open_redirect.md` + `open_redirect_advanced_deep.md § OAuth redirect_uri Chain` → `authentication_jwt_advanced_deep.md § OIDC Mix-Up and Response-Mode Abuse` → this file for post-token forgery depth if needed.

### Chain: urllib3 CVE-2025-50181/50182 + PyJWKClient fetch → JWKS poisoning → forgery

The two 2025 urllib3 CVEs make unexpected redirect behavior possible on PoolManager configurations; PyJWKClient, if it uses urllib3 under the hood, inherits the exposure.

- **Upstream node:** target server uses `PyJWKClient` for JWKS fetch; the underlying HTTP library is urllib3 in a version affected by CVE-2025-50181 (redirects not disabled when retries disabled) or CVE-2025-50182 (browser/Node redirect policy mismatch).
- **Successor precondition:** control an open-redirect-adjacent URL that the server's `jku` resolves to, or control the response at a mid-chain host.
- **Postcondition of successor:** JWKS fetch lands on attacker-controlled bytes.
- **Terminal precondition:** JWKS contains attacker-controlled keys; sign tokens.
- **Terminal postcondition:** forgery.
- **Routing:** `open_redirect_novel_deep.md § urllib3 2025 Redirect CVEs` → this file § PyJWT Advisory Wave § CVE-2026-102267 (PyJWKClient redirect-follow) → `authentication_jwt_advanced_deep.md § JWKS SSRF Chain Construction` → this file § JWKS-Spoofing (base) for forgery.

## Confirmation Predicate for 2024–2026 Primitives

Each 2024–2026 primitive has a confirmation predicate — the exact signal that proves the target is on the vulnerable code path rather than being accepted-but-ignored or dev-moded. The predicates below are specific and should be used verbatim.

**CVE-2024-33663 (python-jose OpenSSH).** Predicate: present a token signed under HS256 with the server's public key bytes (OpenSSH-encoded) as HMAC secret; also present a negative-control token with a random HMAC secret of the same length. Positive confirmation = first accepted, second rejected. Error-fingerprint discriminator: a 3.3.0 rejection has `JWTError: Signature verification failed`; a 3.4.0 rejection has `JWSError: The specified key type is not valid for this algorithm` (the blocklist's error, not the signature-mismatch error). The pair reveals the version band.

**CVE-2026-85394 (python-jose DER).** Predicate: present a token signed under HS256 with the server's public key bytes (DER-encoded, `PKCS1` or `SEC1` format depending on the key type) as HMAC secret; also present the same token with the OpenSSH-encoded form (which 3.4.0 blocks) as negative control. Positive confirmation = DER form accepted, OpenSSH form rejected (proves 3.4.0+ with the DER gap unpatched).

**CVE-2026-48523 (PyJWT PyJWK).** Predicate: present a token with header `alg:"HS256"` and signature over a known HMAC secret; also present the same payload with header `alg:"RS256"` signed with the actual RS256 key. Positive confirmation = HS256 token reaches signature verification (observed via a differential error message, response-time increase, or secondary log entry) rather than being rejected at allowlist-check time. Error-fingerprint: on 2.12.1 the HS256 attempt produces `InvalidSignatureError`; on 2.13.0 it produces `Token algorithm 'HS256' does not match the key's algorithm 'RS256'`.

**CVE-2026-103001 (PyJWT `_merge_options`).** Predicate: identify an endpoint that invokes an insecure-peek on inbound tokens (common for audit, SSO claims introspection, or token-type routing); present a token in the same session whose signature is correct but whose `exp` is already past. Positive confirmation = post-peek endpoint accepts the expired token. Negative control: a token with correct signature and valid `exp` is also accepted, baseline. Second-order confirmation: issue the expired token *before* any insecure-peek in the same session (fresh connection, cleared cookies) — if the expired token now rejects, the mutation is in-session-scoped (confirms the primitive).

**GHSA-88q6-jcjg-hvmw (jose-swift).** Predicate: present an `alg:none` token with any claims; the token has no signature (empty third dot-separated component). Positive confirmation = acceptance. Negative control: the same token with a random non-empty signature field — the fix adds a non-empty-signature-rejects guard, so if the fix is partial the random-sig form may fail while the empty form succeeds. The empty-vs-random-signature pair discriminates 6.0.1 from 6.0.2.

**CVE-2026-48522 (PyJWT PyJWKClient `file://`).** Predicate: force the server to fetch a `jku` with a `file://` scheme pointing to a known-world-readable path (`file:///etc/hostname`); observe whether the fetch succeeded (e.g., via a differential error that leaks the fetched content, via a secondary endpoint that reflects the current JWKS, or via timing of the fetch call).

## Pro Tips — Frontier

1. Fingerprint the library before firing. Error strings leak library choice; the `requirements.txt`, `Pipfile`, `poetry.lock`, `pyproject.toml`, and `/.well-known/dependency-manifest` endpoints (common on debug builds) leak version. Match the version to the measured matrix row.

2. Treat `PyJWKClient` as a distinct code path from raw-bytes decode. The PyJWK code path has its own advisory wave; a target using `PyJWKClient` is exposed to primitives that raw-bytes-key targets are not. The seven PyJWK/PyJWKClient advisories listed above cover the current frontier.

3. For CVE-2026-103001, the attack *requires* dict reuse. Inspect the target for the insecure-peek pattern — any middleware that reads claims before verification is a candidate. Common names: `audit_log_claims`, `extract_token_type`, `pre_verify_inspection`, `jwt_debug_peek`, `claim_router`, `tenant_resolver`.

4. Pin the algorithm twice if your target permits it: once at the caller's `algorithms` allowlist and once at the key object's binding. If the two are inconsistent, choose the one that opens the attack path. The common failure is `["RS256","HS256"]` on the allowlist with a `PyJWK` bound to RS256 — expose both the PyJWK bypass (if 2.12.1 or earlier) and the HS-via-public-key confusion.

5. Use `jwt_tool`'s matrix mode as a baseline but do not trust its automatic version detection — match the measured matrix row by error-string fingerprint, not by `jwt_tool`'s inference.

6. The jose-swift CVE is iOS/macOS-adjacent — look at mobile apps, Server-Swift deployments (Vapor, Hummingbird), and any Darwin-platform JWT consumer before scoping-out. Discovery requires binary analysis for mobile; `swift package show-dependencies` or `Package.resolved` inspection for server-Swift.

7. Chain the frontier primitives with sibling-skill capabilities deliberately: SSRF to reach a private JWKS, path traversal to read a leaked signing key, host-header poisoning to redirect code capture. The frontier CVEs rarely give full RCE in one hop — the chain is the exploit.

8. Match the measurement-reproduction playbook against the exact version pinned at the target. If the target is on a version the matrix doesn't list, re-run the scripts under `.zen-batch-artifacts/batch9-20261003/measurement/scripts/` for that version — the primitives are reproducible.

9. For the python-jose CVE-2024-33663 / CVE-2026-85394 class, read the fix patch (not just the advisory) — the blocklist-extension pattern repeats, and the next sibling encoding is a candidate for the next advisory.

10. For the PyJWT advisory wave, assume PyJWK and PyJWKClient paths carry *their own* defense budget — a service that hardens the raw-bytes-decode path may still be exposed on the JWK-object-decode path. Audit the server's choice of key-input shape.

## Summary

The 2024–2026 JWT frontier is dominated by three dynamics: blocklist-extension cycles on the asymmetric-key-as-HMAC-secret class (CVE-2022-29217 → CVE-2024-33663 → CVE-2026-85394 → CVE-2026-102271 → CVE-2026-102273), a new parallel-verification surface on the PyJWK code path (CVE-2026-48523 and three more PyJWK/PyJWKClient advisories), and a refactor-regression that reintroduced a 2022-era bug three years later (CVE-2026-103001, fix in PyJWT 2.14.0 per local measurement). The measured per-library matrix shows PyJWT's modern defense-in-depth holding against the classic RS→HS confusion across every tested version, while authlib accepts alg:none on caller opt-in and jwcrypto grants a partial encode-side RS→HS primitive. Chains run through sibling skills for key discovery (information disclosure, path traversal), SSRF (JWKS fetch), and cross-service confusion (aud/typ) — the CVE is one hop; the exploit is the chain.
