---
name: authentication-jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion (incl. ECDSA psychic signatures / CVE-2022-21449), JWKS-spoofing key injection (jwk/jku/x5u/kid), JWE attacks, cross-service token confusion, and claim manipulation
---

# Authentication / JWT / OIDC

JWT/OIDC failures often enable token forgery, token confusion, cross-service acceptance, and durable account takeover. Do not trust headers, claims, or token opacity without strict validation bound to issuer, audience, key, and context.

For 2024–2026 CVE mechanism decompositions (python-jose CVE-2024-33663 and CVE-2026-85394, PyJWT CVE-2026-48523 and CVE-2026-103001, jose-swift's `alg:none` short-circuit bug), the measured per-library primitive-status matrix, and the PyJWT advisory-wave class-recurrence pattern, load `authentication_jwt_novel_deep.md`. For JWS/JWE edge-case verification, JWKS rotation and SSRF chain construction, kid-injection sub-classes, header-trust-hierarchy confusion, cross-service aud/typ confusion depth, OIDC mix-up and PKCE/DPoP depth, and composite-chain construction, load `authentication_jwt_advanced_deep.md`.

## Attack Surface

- Web/mobile/API authentication using JWT (JWS/JWE) and OIDC/OAuth2
- Access vs ID tokens, refresh tokens, device/PKCE/Backchannel flows
- First-party and microservices verification, gateways, and JWKS distribution
- Second-order consumption: audit loggers, SSO claim-extraction middleware, background job workers that store and re-present tokens
- Mobile deep links and WebView bridges that read tokens from URL schemes or clipboard

## Reconnaissance

### Endpoints

- Well-known: `/.well-known/openid-configuration`, `/oauth2/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`
- Keys: `/jwks.json`, rotating key endpoints, tenant-specific JWKS, `/certs` (keycloak-style), `/discovery/v2.0/keys` (Microsoft identity)
- Auth: `/authorize`, `/token`, `/introspect`, `/revoke`, `/logout`, device code endpoints, CIBA endpoints
- App: `/login`, `/callback`, `/refresh`, `/me`, `/session`, `/impersonate`
- Debug / introspection leaks: `/.well-known/dependency-manifest`, `/debug/jwks`, `/__internal/keys`, `/healthz` with detailed component banners

### Token Features

- Headers: `{"alg":"RS256","kid":"...","typ":"JWT","jku":"...","x5u":"...","jwk":{...}}`
- Claims: `{"iss":"...","aud":"...","azp":"...","sub":"user","scope":"...","exp":...,"nbf":...,"iat":...,"jti":...,"cnf":{...}}`
- Formats: JWS (signed), JWE (encrypted). Note unencoded payload option (`"b64":false`) and critical headers (`"crit"`)
- Sender-constrained markers: `cnf.jkt` (DPoP key thumbprint), `cnf.x5t#S256` (mTLS certificate thumbprint)

### Library Fingerprinting

Identify the server's JWT library before firing — the measured per-library matrix in the novel sibling tells you which primitives are live. Fingerprint signals:

- **Error strings**: `InvalidKeyError: asymmetric key ... should not be used as an HMAC secret` → PyJWT ≥ 2.0; `JWKError: Unable to find an algorithm` → python-jose; `JsonWebTokenError: invalid signature` → jsonwebtoken (Node); `JOSEError` → jose (Node); `InvalidJWSOperation` → jwcrypto
- **Response-time by algorithm**: HMAC verification is uniform fast; RSA verification has a floor; alg:none has none. A measurable differential by algorithm class reveals the dispatch
- **Dependency manifests**: `requirements.txt`, `Pipfile.lock`, `package-lock.json`, `poetry.lock`, `Cargo.lock` served via `/static/` or similar paths
- **Server banner**: often names the framework (Spring, Flask, Express), which pins the typical JWT middleware

## Key Vulnerabilities

### Signature Verification

- RS256→HS256 confusion: change alg to HS256 and use the RSA public key as HMAC secret if algorithm is not pinned
- "none" algorithm acceptance: set `"alg":"none"` and drop the signature if libraries accept it
- ECDSA malleability/misuse: weak verification settings accepting non-canonical signatures

**These are technique classes, and modern libraries are hardened — fingerprint
the library and version.** Measured on PyJWT 2.13: `jwt.decode` **requires** an
explicit `algorithms=` list (omitting it raises), `alg:none` is refused unless
deliberately allowed, and the **RS256→HS256 forge is blocked at key-prep** —
`jwt.encode(..., key=<PEM public key>, algorithm="HS256")` raises
`InvalidKeyError: asymmetric key ... should not be used as an HMAC secret`. So
the confusion attacks land on **older versions, other languages, or code that
passes a non-pinned algorithm / a raw public-key string**, not on an up-to-date
PyJWT. Confirm the server library (error strings, `/.well-known`, headers) and
match a version that lacks the guard; do not assume a bare `alg:none`/HS-confusion
works on a current stack.

For 2024–2026 python-jose confusion (CVE-2024-33663 OpenSSH-encoded key as HMAC secret; CVE-2026-85394 DER-encoded key as HMAC secret, incomplete fix of the former) and PyJWT PyJWK-path primitives (CVE-2026-48523 algorithm-binding bypass; CVE-2026-103001 options-dict mutation regression), load `authentication_jwt_novel_deep.md`. For jose-swift's `alg:none` unconditional-verify-true bug, same route. For the measured per-library alg:none and algorithm-confusion matrix across PyJWT, python-jose, authlib, and jwcrypto, same route.

**ECDSA "psychic signatures" (CVE-2022-21449).** The pure-Java ECDSA
verifier introduced in **Java 15** fails to check that `r` and `s` are non-zero,
so a signature with `r=0, s=0` — an **all-zeros signature** — validates for
*any* message and *any* public key. A JWT signed `ES256`/`ES384`/`ES512` with an
all-zeros signature is accepted by a vulnerable JDK (the disclosure explicitly
covers signed JWTs, SAML, and OIDC id tokens). The forged token is
`base64url({"alg":"ES256"}).base64url(claims).<all-zeros-sig>`, where the
signature is the base64url of N zero bytes:

| alg | sig bytes | all-zeros signature (base64url) |
|---|---|---|
| ES256 | 64 | `AAAA…AA` (86 `A`s) |
| ES384 | 96 | 128 `A`s |
| ES512 | 132 | 176 `A`s |

Affected: **JDK 15, 16, 17 (≤17.0.2), 18 GA**; fixed in Oracle's April 2022 CPU
(17.0.3, 18.0.1, and the 15/11 update lines). JDK ≤11 uses the older native
ECDSA and is **not** affected. Fingerprint the verifier's JDK (server banner,
`Server`/error strings, behavior) — if it's a vulnerable 15–18 build validating
ES* JWTs, an empty signature is a full forgery primitive. For the 2024–2026
status of the signature-non-canonicalization class across non-Java ecosystems
(blockchain libraries, non-Oracle Java forks, EdDSA canonicalization), load
`authentication_jwt_novel_deep.md § Historical Anchor — CVE-2022-21449`.

### Header Manipulation

- **kid injection**: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or pointing to world-readable files
- **jku/x5u abuse**: host attacker-controlled JWKS/X509 chain; if not pinned/whitelisted, server fetches and trusts attacker keys
- **jwk header injection**: embed attacker JWK in header; some libraries prefer inline JWK over server-configured keys
- **SSRF via remote key fetch**: exploit JWKS URL fetching to reach internal hosts

**Full JWKS-spoofing forgery (the self-contained one).** When the verifier
derives the key from the token's *own* header rather than a pinned JWKS, you
sign with a key you control and tell the server which key to trust:

1. Generate an RSA (or EC) keypair.
2. Sign the tampered token (elevated `sub`/`role`/`aud`) with your **private** key.
3. Point the verifier at your **public** key via one of:
   - **`jwk`** — embed your public key as an inline JWK in the header. Libraries
     that read `header.jwk` verify against it → instant forgery, no network.
   - **`jku`** — set `jku` to an attacker-hosted `jwks.json` serving your public
     key. Works if `jku` isn't allowlisted; often SSRF-gated (must be reachable
     from the server, or via an open redirect / a trusted host you can write to).
   - **`x5u` / `x5c`** — attacker X.509 URL or embedded cert chain.
   - **`kid`** — path-traverse / inject to a key whose value you know
     (`kid: "../../dev/null"` → empty key, then sign HS with empty secret; or
     `kid` SQLi returning a controlled key; or point at a world-readable file).
4. Ensure `kid`/`alg` line up so the server selects your key.

`jwt_tool` automates each: `-X i` (inject inline `jwk`), `-X s -ju <url>`
(`jku` spoof, hosts the JWKS for you), `-X k` (`kid` key-confusion). Prove the
server accepted a token you signed with a key it never trusted.

For `kid` injection sub-classes at depth (SQL, template, nested-lookup, command, NoSQL), for the header-trust-hierarchy confusion when multiple key-source headers co-exist, and for JWKS SSRF chain construction (including the `file://` scheme bypass and the redirect-follow primitive — CVE-2026-48522 and CVE-2026-102267 in the PyJWT advisory wave), load `authentication_jwt_advanced_deep.md § kid Injection Sub-Classes` and `§ JWKS SSRF Chain Construction`.

### Key and Cache Issues

- JWKS caching TTL and key rollover: accept obsolete keys; race rotation windows; missing kid pinning → accept any matching kty/alg
- Mixed environments: same secrets across dev/stage/prod; key reuse across tenants or services
- Fallbacks: verification succeeds when kid not found by trying all keys or no keys (implementation bugs)
- Grace-period acceptance of retired keys after rotation

For rotation-race exploitation depth, fallback-fetch-on-unknown-kid primitives, and the cache-poisoning path against JWKS caches, load `authentication_jwt_advanced_deep.md § JWKS Rotation and Cache Races`.

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; accept tokens from any issuer or wrong audience
- scope/roles fully trusted from token: server does not re-derive authorization; privilege inflation via claim edits when signature checks are weak
- exp/nbf/iat not enforced or large clock skew tolerance; accept long-expired or not-yet-valid tokens
- typ/cty not enforced: accept ID token where access token required (token confusion)
- `cnf` ignored: sender-constrained tokens treated as bearer

The RFC 9700 BCP shift makes `aud` enforcement mandatory and `azp` enforcement recommended; deployments in the transition window (some endpoints enforce, others don't) expose the policy-disagreement attack. Load `authentication_jwt_novel_deep.md § RFC 9700 / OAuth 2.1 BCP Shift` for the verifier-side implications.

### Token Confusion and OIDC

- Access vs ID token swap: use ID token against APIs when they only verify signature but not audience/typ
- OIDC mix-up: redirect_uri and client mix-ups causing tokens for Client A to be redeemed at Client B
- PKCE downgrades: missing S256 requirement; accept plain or absent code_verifier
- State/nonce weaknesses: predictable or missing → CSRF/logical interception of login
- Device/Backchannel flows: codes and tokens accepted by unintended clients or services

This skill owns the **token layer** (format, signature, keys, claims,
confusion above). For the **authorization-flow layer** — redirect_uri
validation, PKCE, state/nonce, mix-up, DPoP/sender-constrained tokens, PAR,
RAR, and token-exchange semantics — load `oauth`. For **Auth0-tenant** specifics
(Actions, Management API, custom DB scripts, tenant config) load `auth0`. Keep
the token-forgery/confusion evidence here; pointer the flow reproduction there.

For OIDC mix-up depth (classic Mainka attack, response-mode abuse, nonce/state replay), PKCE downgrade variants, DPoP/mTLS sender-constrained token bypass classes, and device-code/CIBA flow abuse, load `authentication_jwt_advanced_deep.md § OIDC Mix-Up and Response-Mode Abuse`, `§ PKCE Downgrade`, `§ DPoP / mTLS / Sender-Constrained Token Bypass`, and `§ Device Code and CIBA Flow Abuse`.

### Refresh and Session

- Refresh token rotation not enforced: reuse old refresh token indefinitely; no reuse detection
- Long-lived JWTs with no revocation: persistent access post-logout
- Session fixation: bind new tokens to attacker-controlled session identifiers or cookies

For refresh-token reuse-detection depth (no rotation / rotation without invalidation / reuse detection without family invalidation / grace window), load `authentication_jwt_advanced_deep.md § Refresh Token Reuse Detection Depth`.

### Transport and Storage

- Token in localStorage/sessionStorage: susceptible to XSS exfiltration; cookie vs header trade-offs with SameSite/CSRF
- Insecure CORS: wildcard origins with credentialed requests expose tokens and protected responses
- TLS and cookie flags: missing Secure/HttpOnly; lack of mTLS or DPoP/"cnf" binding permits replay from another device
- Second-order storage: audit logs with full Authorization headers, backup files containing JWT secrets, environment variables leaked via `/proc/<pid>/environ`

For second-order token confusion (admin-impersonation via stored token, service-account tokens in secrets managers, audit-log-stored tokens), load `authentication_jwt_advanced_deep.md § Second-Order Token Confusion`.

## Advanced Techniques

### JWS Edge Cases

- Unencoded payload (`"b64":false` with `"crit":["b64"]`) RFC 7797 form; vulnerable libraries recompute the signing input wrong
- `crit` header with unknown extension names causes silent skip rather than reject
- Nested JWT (JWT-in-JWT) verification order: outer verified, inner trusted without its own signature check

For the full JWS edge-case treatment with payload shapes and confirmation, load `authentication_jwt_advanced_deep.md § JWS Edge-Case Verification`.

### Microservices and Gateways

- Audience mismatch: internal services verify signature but ignore aud → accept tokens for other services
- Header trust: edge or gateway injects X-User-Id; backend trusts it over token claims
- Asynchronous consumers: workers process messages with bearer tokens but skip verification on replay

### JWE (Encrypted Tokens)

A JWE has **five** dot-separated parts (`header.encrypted_key.iv.ciphertext.tag`)
vs a JWS's three; the header carries `alg` (key management: `RSA-OAEP`,
`RSA1_5`, `ECDH-ES`, `dir`, `A128KW`) and `enc` (content encryption: `A128GCM`,
`A256CBC-HS512`). Attack surface, largely technique classes to match against the
library/version:

- **Key-management downgrade / type confusion** — a consumer that decrypts a JWE
  may also accept a JWS (or `alg:none`) where it should require encryption; or
  accept `alg:"dir"` with a guessable/empty/default CEK. Test presenting a JWS,
  a `none`, and a `dir` token to a JWE endpoint.
- **`RSA1_5` Bleichenbacher (Million-Message Attack)** — if `alg` is PKCS#1 v1.5
  (`RSA1_5`) and the endpoint leaks a padding-validity oracle (error/timing
  differential on malformed `encrypted_key`), you can recover the CEK and
  decrypt/forge. Confirm `RSA1_5` is accepted and an oracle exists before
  claiming it — it is version- and config-specific.
- **Invalid-curve attack on `ECDH-ES`** — submitting an ephemeral public point
  not on the named curve recovers the static private key on libraries that skip
  point-on-curve validation. Technique class; match the library.
- **`zip:"DEF"` decompression bomb** — a JWE whose plaintext is highly
  compressible causes a decompression-DoS on decrypt; DoS-scope only.
- **`crit` / unknown-header handling** — a `crit` header naming a parameter the
  library ignores can skip a check it should enforce.

JWE is less common than JWS; when present, fingerprint `alg`/`enc` first and
select the matching class. `jwt_tool` handles JWE inspection and some of these. For the full JWE attack-class treatment with per-primitive confirmation (Bleichenbacher chosen-ciphertext methodology, invalid-curve point recovery, dir-mode default-CEK, PBES2 iteration bounds, content-encryption downgrade), load `authentication_jwt_advanced_deep.md § JWE Attack Classes`.

## Special Contexts

### Mobile

- Deep-link/redirect handling bugs leak codes/tokens; insecure WebView bridges exposing tokens
- Token storage in plaintext files/SQLite/Keychain/SharedPrefs; backup/adb accessible
- iOS/macOS JWT libraries: jose-swift is a current frontier target (`alg:none` short-circuit bug — identifier and mechanism in `authentication_jwt_novel_deep.md`); fingerprint the JWT library by binary strings or framework search

### SSO Federation

- Misconfigured trust between multiple IdPs/SPs, mixed metadata, or stale keys lead to acceptance of foreign tokens
- OIDC mix-up on multi-IdP clients (see advanced sibling)
- SAML signature-wrapping is a related but distinct class; load `vulnerabilities/xxe.md` and SAML-specific coverage for XML-signature-wrapping and XSW variants

## Chaining Attacks

- XSS → token theft → replay across services with weak audience checks
- SSRF → fetch private JWKS → sign tokens accepted by internal services
- Host header poisoning → OIDC redirect_uri poisoning → code capture
- IDOR in sessions/impersonation endpoints → mint tokens for other users
- Open redirect on registered `redirect_uri` host → OAuth code interception → token issuance
- Request smuggling → session splice → JWT swap via injected `Set-Cookie`
- Prototype pollution → kid-lookup bypass (Node) → forgery via polluted key cache

Chains compose with capabilities from sibling skills by the exact capability transferred. Load `authentication_jwt_advanced_deep.md § Composite Chain Depth` for the full chain catalog with upstream/downstream/transition anatomy per chain and the sibling-skill routing table.

## Testing Methodology

1. **Inventory issuers/consumers** — Identity providers, API gateways, services, mobile/web clients
2. **Capture tokens** — Access and ID tokens for multiple roles; note header, claims, signature
3. **Map verification endpoints** — `/.well-known`, `/jwks.json`, library-specific debug endpoints
4. **Fingerprint libraries** — error strings, response-time differentials, dependency-manifest leaks → match to the measured matrix in the novel sibling
5. **Build matrix** — Token Type × Audience × Service; attempt cross-use
6. **Mutate components** — Headers (alg, kid, jku/x5u/jwk), claims (iss/aud/azp/sub/exp), signatures
7. **Verify enforcement** — What is actually checked vs assumed
8. **Scope sender-constraint enforcement** — DPoP proof required? mTLS thumbprint matched? Test the `cnf` claim ignored path

## Validation

1. Show forged or cross-context token acceptance (wrong alg, wrong audience/issuer, or attacker-signed JWKS)
2. Demonstrate access token vs ID token confusion at an API
3. Prove refresh token reuse without rotation detection or revocation
4. Confirm header abuse (kid/jku/x5u/jwk) leading to key selection under attacker control
5. Provide owner vs non-owner evidence with identical requests differing only in token context
6. Pair positive-control (correctly-signed token) with negative-control (random-signature token) to prove the signature path is live, not bypassed

## False Positives

- Token rejected due to strict audience/issuer enforcement
- Key pinning with JWKS whitelist and TLS validation
- Short-lived tokens with rotation and revocation on logout
- ID token not accepted by APIs that require access tokens
- Signature verified but claim ignored (authorization reads from session store, not token)
- Mock / development verifier accepting any signature in non-production environments
- Token accepted but response masked (admin responses redacted at a middleware layer)

For the detailed false-positive discipline including the authorization-vs-authentication distinction, load `authentication_jwt_advanced_deep.md § False Positives — Advanced`.

## Impact

- Account takeover and durable session persistence
- Privilege escalation via claim manipulation or cross-service acceptance
- Cross-tenant or cross-application data access
- Token minting by attacker-controlled keys or endpoints
- Session-scoped claim-validation bypass (CVE-2026-103001 class) enabling expired or wrong-audience token acceptance
- Full forgery via public-key-as-HMAC-secret in older python-jose (CVE-2024-33663, CVE-2026-85394) or any JWT library on the DER/OpenSSH/PEM blocklist-extension cycle

## Pro Tips

1. Pin verification to issuer and audience; log and diff claim sets across services
2. Attempt RS256→HS256 and "none" first only if algorithm pinning is unclear; otherwise focus on header key control (kid/jku/x5u/jwk)
3. Test token reuse across all services; many backends only check signature, not audience/typ
4. Exploit JWKS caching and rotation races; try retired keys and missing kid fallbacks
5. Exercise OIDC flows with PKCE/state/nonce variants and mixed clients; look for mix-up
6. Try DPoP/mTLS absence to replay tokens from different devices
7. Treat refresh as its own surface: rotation, reuse detection, and audience scoping
8. Validate every acceptance path: gateway, service, worker, WebSocket, and gRPC
9. Favor minimal PoCs that clearly show cross-context acceptance and durable access
10. When in doubt, assume verification differs per stack (mobile vs web vs gateway) and test each
11. Fingerprint the library and match to the measured per-library matrix in the novel sibling before firing — don't fire blind against a hardened PyJWT, don't skip the authlib-opt-in alg:none check

## Tooling

- `jwt_tool -t <url> -rh "Authorization: Bearer <token>" -M at` runs the
  full attack matrix (alg=none, RS→HS confusion, kid injection, claim
  edits) and reports which mutations the server still accepts.
- `jwt_tool <token> -C -d <wordlist>` brute-forces HMAC secrets when an
  HS-family signature is in use.
- Use `jwt_tool` to mint a token under a key you control once you find an
  acceptance path (kid/jku/x5u/jwk), then replay via `repeat_request`.
- For deeper per-library testing against specific CVEs, the measurement scripts under `.zen-batch-artifacts/batch9-20261003/measurement/scripts/` reproduce the primitives against known-vulnerable versions on PyPI.

## Summary

Verification must bind the token to the correct issuer, audience, key, and client context on every acceptance path. Any missing binding enables forgery or confusion. The 2024–2026 frontier concentrates on blocklist-extension cycles (encodings of the asymmetric-key-as-HMAC-secret class), parallel verification surfaces (the PyJWK code path), and refactor-regressions that reintroduce old bugs — load the deep siblings for the mechanism, measurement, and chain depth.
