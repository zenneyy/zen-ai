---
name: authentication-jwt-advanced-deep
description: JWT/OIDC at advanced+expert depth — JWS/JWE edge-case verification, JWKS rotation and SSRF chain construction, kid injection sub-classes, header-trust-hierarchy confusion, OIDC mix-up and PKCE/DPoP depth, cross-service aud/typ confusion, multi-tenant shared-key confusion, framework-specific middleware depth, and composite-chain exploitation.
sibling: authentication_jwt
load_when: scan_mode == "deep"
---

# Authentication / JWT / OIDC — Advanced Depth

This is the advanced+expert deep sibling to `authentication_jwt.md`. The base owns the class framing, the measured PyJWT-hardening finding, the CVE-2022-21449 ECDSA all-zeros per-algorithm table, JWKS-spoofing basics, the testing-methodology spine, and the primary chains. The novel+frontier sibling `authentication_jwt_novel_deep.md` owns the 2024–2026 CVE mechanism decompositions (python-jose CVE-2024-33663 / CVE-2026-85394, PyJWT CVE-2026-48523 / CVE-2026-103001, jose-swift's `alg:none` short-circuit) with the canonical version/GHSA table, the measured per-library algorithm-confusion matrix, cross-ecosystem comparison, and current-frontier technique framing. This file owns the operational depth in between — JWS/JWE edge-case verification, JWKS rotation and SSRF chain construction, kid-injection sub-classes, header-trust-hierarchy confusion, cross-service aud/typ confusion depth, OIDC mix-up and PKCE/DPoP depth, framework-middleware depth, and composite-chain construction.

Load this file when the target has moved past a trivial PoC — the library accepts the token but a claim or binding check needs breaking, the JWKS surface is reachable but hardened against the base-file forgery flow, the chain requires composing JWT primitives with CORS/SSRF/IDOR/host-header capabilities, or verification happens across multiple services with disagreeing policies.

Every framework-specific behavior in this file is anchored to primary sources or measured. Every version-boundary claim referencing a specific CVE lives in the novel sibling per §2 CVE single-ownership; this file references by CVE number + route.

## JWS Edge-Case Verification

The base-file "signature verification" treatment covers RS→HS confusion, alg:none, and the ECDSA all-zeros class. Three JWS edge cases sit one tier below those primitives and routinely survive hardening against the headline attacks.

**Unencoded Payload (`"b64":false` + `"crit":["b64"]`).** RFC 7797 defines an unencoded-payload JWS form where the payload between the two dots is the raw payload bytes, not its base64url encoding. The protected header must set `"b64":false` and `"crit":["b64"]`. Vulnerable libraries mishandle verification in three ways: (a) they recompute the signing input as `base64url(header) + "." + base64url(payload)` rather than `base64url(header) + "." + payload`, producing a signature that validates against the attacker's choice; (b) they accept `b64:false` without the `crit` marker, which the RFC forbids; (c) they strip the `b64:false` from the critical-header list on canonicalization. The primitive is signature-forgery when the signing input the library computes diverges from the input the signer computed. Confirm by presenting the same payload bytes under both forms and watching for differential verification outcomes against the same key. The historical PHP-JWT b64:false variants and sibling bugs in Erlang's jose are the anchor cases; the frontier for the primitive is in libraries that added RFC 7797 support late (2022–2024 adds in Java, Rust, Go JOSE libraries).

**`crit` Header with Unknown Extension Names.** The `crit` header lists header parameter names the verifier must understand. If an attacker adds a name the library ignores entirely (not just a parameter whose value is ignored — the *name* is unknown), vulnerable libraries silently skip verification of that parameter rather than rejecting the token. Combined with a critical-marker on an input the library normally honors (e.g., `"crit":["kid","x5u"]`), the attack extends: the critical mark says "this must be understood," the library accepts without checking understanding, and a downstream code path that cares about `kid`/`x5u` is bypassed. Test by crafting `"crit":["example.invalid-param"]` with a corresponding `"example.invalid-param":true` and watching whether the token is accepted. Variant: `"crit":[]` empty-list acceptance (some libraries treat as "no criticals" rather than "malformed"); `"crit":["alg"]` where `alg` is a reserved header name and the library's handling of a reserved-in-crit is undefined.

**Nested JWT (JWT-in-JWT) Verification Order.** A JWS wrapping an inner JWS (indicated by `"cty":"JWT"`) requires the verifier to first verify the outer signature, then parse the inner payload as a JWT and verify *that* signature with the inner's own key/algorithm — not reuse the outer key. Libraries that short-circuit on the outer-only verification pass tokens whose inner claims are entirely attacker-controlled. The reciprocal nested JWS-in-JWE variant has the same shape: the JWE decryption succeeds, the inner JWS payload is extracted, and the verifier accepts the inner payload without re-verifying its own signature. Primitive: full claim-set forgery when the verifier stops at one layer. Confirm by presenting a nested token with an inner signature made against a key the server does not know; outer verification succeeds against a key the server does know; inner acceptance proves the bug.

**Signature-Required Header Combinations.** Several header combinations should force rejection but do not on vulnerable libraries. `"alg":"none"` with a non-empty signature should reject (an alg:none token has no signature); some libraries accept it because they short-circuit on `alg=="none"` before inspecting the signature field. `"alg":"HS256"` with a token that has four dots (JWE shape) should reject at parse time; libraries that key off the first-component `alg` without checking the overall structure will proceed to HMAC-verify a JWE payload and succeed in trivial cases. `"alg":"RS256"` with a signature longer than any legitimate RSA signature should reject; libraries that trim or hash the oversize signature before verification may accept forgeries built on the trimmed form.

**Payload Charset Confusion.** JWT payloads are JSON; the JSON spec permits any Unicode. Attackers craft payloads with homoglyph characters in claim names — `"role":"admin"` vs `"rοle":"admin"` (Greek omicron instead of Latin o) vs `"role":"admin"` with a zero-width-space. Vulnerable verifiers process one form, downstream authorization reads another; the attacker's `"role"` with a homoglyph is a different claim from the real `"role"` but may be interpreted as equivalent by weak comparison. The chain is unusual but observed in multi-encoding deployments; load `semantic_confusion.md` for the general comparison-vs-interpretation differential.

**JOSE Media Type Confusion.** `cty` ("content type") in the header disambiguates the payload's semantics. Vulnerable libraries that honor `cty` for parsing but not for verification scope accept a payload typed as `cty:"application/jwt"` (nested JWT) when the verifier expected raw claims. Variants: `cty:"application/jose"` wrapping a JWE inside a JWS; the outer verification succeeds, the inner JWE's content-encryption-key is attacker-chosen (`alg:"dir"` with guessable CEK), the inner plaintext becomes trusted. The chain is in § JWT Downgrade (JWS ↔ JWE) below.

## JWE Attack Classes

A JWE has five dot-separated parts (`header.encrypted_key.iv.ciphertext.tag`) versus a JWS's three. The header carries `alg` (key-management: `RSA-OAEP`, `RSA-OAEP-256`, `RSA1_5`, `ECDH-ES`, `ECDH-ES+A128KW`, `dir`, `A128KW`, `A128GCMKW`, `PBES2-HS256+A128KW`) and `enc` (content-encryption: `A128CBC-HS256`, `A128GCM`, `A192GCM`, `A256GCM`, `A256CBC-HS512`). Attack surface is almost entirely version- and configuration-specific; fingerprint `alg`/`enc` first, then select the matching class.

**RSA1_5 Bleichenbacher ("Million-Message Attack") on JWE.** PKCS#1 v1.5 RSA key-management (`alg:"RSA1_5"`) is vulnerable to Bleichenbacher's adaptive chosen-ciphertext attack when the decryption endpoint leaks a padding-validity oracle. For JWE the oracle is a differential response to malformed `encrypted_key` values — distinct error messages, distinct response codes, timing differences, or secondary side-effects (log entries, counter advances). The attack recovers the content-encryption key (CEK) one bit at a time via carefully-chosen multiplicative transformations; recovery requires on the order of 2^20 queries for a 2048-bit key. On recovery the attacker decrypts the JWE and can re-encrypt a forged payload for the same key. Preconditions: (1) endpoint accepts `RSA1_5`; (2) a usable oracle exists; (3) the attacker can issue the required queries without rate-limiting cutoff. Modern deployments should refuse `RSA1_5` in favor of `RSA-OAEP`; test by presenting a `RSA1_5` token first. The Jager–Schwenk 2015 oracle-against-JWE paper documents the specific JWE-oracle shapes; the mitigation hardening across most libraries happened 2016–2018 and the primitive is now mostly historical, but target-specific deployments still carry it.

**Invalid-Curve Attack on `ECDH-ES`.** `ECDH-ES` key agreement uses an ephemeral public key submitted in the header's `epk` parameter. Libraries that fail to validate the ephemeral point lies on the named curve (`P-256`, `P-384`, `P-521`) agree on a shared secret in a small subgroup, recoverable with a few hundred queries. The attack recovers the server's static ECDH private key — the one the server uses to compute the shared secret in every incoming `ECDH-ES` token. Primitive: full private-key extraction, enabling forgery of any future token. Confirm by submitting an ephemeral point from a curve-twist and watching whether the server computes a shared secret with it or rejects at parse time; a repeated-query attack with twist-curve points of small order reconstructs the private scalar via CRT. The historical anchors are the 2016–2017 python-jose and go-jose invalid-curve bugs; the current frontier is any new JOSE implementation that reimplements ECDH without the point-on-curve check.

**`dir` Key-Management with Default or Guessable CEK.** `alg:"dir"` means the content-encryption key is used directly — no key wrapping, no key agreement. The CEK must be a pre-shared symmetric key. Deployments that use `dir` with a key derived from a tenant identifier, a hostname, a well-known constant, or an environment variable with a predictable value are forgeable: generate a candidate CEK, construct a JWE with the correct `enc`, and present it. Fingerprint `dir` via the `alg` header; attempt forgery with candidate keys matching the discovered tenant structure. Hunt lead: enterprise SSO deployments that use `dir` with a tenant-derived key often leak the derivation algorithm in configuration documentation or admin UI.

**`PBES2-*` Low-Iteration Count Oracle.** `PBES2-HS256+A128KW` and family derive a key-wrapping key via PBKDF2 using the `p2c` (iteration count) and `p2s` (salt) header parameters. Vulnerable libraries honor an attacker-supplied `p2c` of arbitrarily large magnitude without clamping, enabling a decryption-DoS; vulnerable deployments with low `p2c` on legitimate traffic are brute-forceable offline with modest resources. The symmetric headline is DoS, but when the application's password is weak the full key derivation is reversible. Historical anchors in the `p2c`-DoS line include jsrsasign's jose-library CVE class; the brute-force variant depends entirely on the password strength.

**Key-Management Downgrade / Type Confusion.** A consumer that decrypts JWE may also accept a JWS (three-part token) or an `alg:none` token where it should require encryption. Present each of (a) a plain JWS with elevated claims, (b) an alg:none token, (c) a `dir` token with a guessable CEK, (d) a mixed-mode token with `alg:"RSA-OAEP"` in the header but no `encrypted_key` present. The weakest acceptance path defines the primitive. The classic PyJWT key-confusion class (see novel-deep's historical table) is a JWS-side variant; JWE-side downgrade bugs are rarer in Python but observed in Node and Java JOSE libraries.

**`zip:"DEF"` Decompression Bomb.** A JWE whose plaintext decompresses to orders of magnitude more bytes than the ciphertext causes a decompression-DoS on decrypt — the server allocates the full output buffer before validating further. Scope is DoS unless the inflated output lands in a secondary attack path (log pipeline overflow, downstream buffer bug). The DEFLATE-bomb pattern is identical to the one in zip-slip and web-upload DoS; feed highly-redundant plaintext (`"A" * 1000000`) to the compressor and watch the compression ratio.

**Content-Encryption Downgrade.** A library that accepts both `A128GCM` and `A128CBC-HS256` without a server-side policy pins neither; an attacker who recovers one key via one of the attacks above forges tokens under the other. Combined with Bleichenbacher: recover CEK via `RSA1_5+A128CBC-HS256`, re-encrypt under `A128GCM` to avoid the oracle on subsequent verifications. The downgrade attack extends the recovery primitive to persistence.

**JWE Oracle Confirmation.** The confirmation signal for all JWE classes is a differential response to malformed cryptographic material (padding, point, length, tag). Capture a baseline (valid token, success) and a counterfactual (same token with one bit flipped in each cryptographic component in turn). Any component whose single-bit flip produces a distinguishable response is an oracle candidate. For padding attacks the single-bit mutation is in the `encrypted_key` component; for AEAD-tag attacks it is in the `tag` component; for IV attacks it is in `iv`. Oracle presence does not prove exploitability — the attack may require millions of queries and the deployment may rate-limit. Confirm by issuing a small sample (~1000) of malformed queries and watching for the predicted non-uniform response distribution; the full key-recovery run is a scope decision.

**JWE AEAD-Tag Truncation.** Some libraries accept a truncated `tag` component (shorter than the AEAD's native tag length). The attacker reduces the tag to a few bytes; the forgery search becomes brute-forceable (16 bytes of search for a 128-bit tag reduces to <1 second if the attacker can truncate to 2 bytes). Vulnerable libraries: those that measure `tag` length against expected and emit a warning but still verify; those that use string comparison that succeeds on a prefix match.

## JWKS Rotation and Cache Races

JWKS endpoints advertise multiple keys with `kid` identifiers; verifiers cache the set with a TTL and refetch on expiry. Rotation introduces a race window: the server starts signing with a new key before all verifier caches have refreshed, so verifiers temporarily see tokens signed by a key not in their cache. Vulnerable rotation handling takes one of three shapes.

**Fallback-Fetch-On-Unknown-Kid.** When the token's `kid` is not in the cached set, the verifier refetches the JWKS. An attacker who controls a reachable JWKS URL (via `jku`/`x5u`, SSRF to an internal mirror, or an open-redirect on an allowlisted host) induces the refetch with a token whose `kid` identifies a key under attacker control. If the verifier's refetch URL derives in whole or part from the token header, the primitive is immediate forgery. If the refetch URL is pinned but the server trusts whatever JWKS it fetches without re-pinning, poisoning the pinned JWKS (via a cache-poisoning attack upstream of the verifier) grants the same primitive. The attack requires `kid` mutation on the token and either a URL-derivation-from-header or a cache-poisoning capability upstream.

**Accept-Any-Key-On-Unknown-Kid.** Some libraries try all keys in the cached set when `kid` does not match. If one of the cached keys is weaker (shorter HMAC, retired keypair kept for grace-period compatibility, test key never rotated out), the attacker signs under that weaker key and the token passes without the `kid` match. Confirm by enumerating `kid`s from the JWKS, generating a candidate token signed under each key you can derive from public information, and observing acceptance. The hunt lead for a mixed-key JWKS: look for keys with `use:"sig"` and `kty:"oct"` (symmetric), which are rarer than RSA/EC and more likely to be test keys left in the set.

**Grace-Period Key Acceptance.** During rotation the old key stays active for a grace period (hours to days). If the old key leaks (ex-employee has access, log scrape, test environment reuses it), tokens signed under the retired key are still accepted until the grace period expires. Confirm by signing under a key suspected of leakage and matching the token's `iat` to within the grace window.

**JWKS Cache TTL as an Attack Window.** Short TTLs (<1 minute) widen the refetch window: more refetches per hour, more opportunities to inject. Long TTLs (hours) widen the leak window: a key compromise is exploitable for the full TTL after a rotation. The sweet spot deployments miss produces either frequent fetch-driven primitives or long-lived leaked-key primitives. Fingerprint TTL by watching the refetch timing against the response's `Cache-Control` / `max-age`.

**Confirmation of a Rotation Race.** Instrument time: capture a baseline JWKS fetch (`t0`), rotate the signing key out of band (via an admin interaction or by observing a natural rotation), and present a token signed under a key you planted in a reachable location at `t1 > t0`. Acceptance proves the fallback-fetch path. If rotation is not observable, synthesize one: a token whose `kid` names a key not yet in the cache forces the primitive at the next verification.

**JWKS Cache Poisoning via HTTP Cache Layer.** If the JWKS endpoint sits behind a CDN or caching reverse proxy, cache-poisoning attacks against the cache layer poison the verifier's JWKS. Common vectors: `Vary` header manipulation, cache-key-smuggling via unkeyed headers, parameter-cloaking on query strings the cache does not key on. Load `http_request_smuggling.md § Cache Poisoning` for the primitive construction; the chain is upstream of this file's JWKS consumption.

## JWKS SSRF Chain Construction

The base file names `jku`/`x5u` SSRF as a technique class. The chain surface is deeper than "point `jku` at an attacker URL."

### jku-Pinned-But-Resolver-Permissive

**Primitive.** The verifier pins the `jku` host at the configuration layer (`jku` must be `https://auth.example.com/.well-known/jwks.json`), but the HTTP resolver used to fetch the URL does not honor the pin — it follows redirects, honors DNS-rebinding, resolves `localhost` subdomains that happen to match the pinned-host string, or performs a case-insensitive host comparison that the DNS resolver treats differently.

**Preconditions.** (1) The verifier accepts a `jku` header on each token. (2) The pin is enforced via string comparison or regex on the raw URL string, not on the resolved IP. (3) The HTTP resolver follows redirects by default (any mainstream HTTP client does, unless explicitly disabled). (4) The pinned host hosts an open-redirect endpoint OR the resolver's DNS lookup can be influenced (rebinding, split-horizon DNS misconfigurations).

**Attack recipe.** Point `jku` at `https://auth.example.com/redirect?to=https://attacker.tld/jwks.json` where `/redirect` is an open-redirect on the pinned host; the resolver fetches the pinned URL (passing the pin check), the first-hop 302s to attacker.tld, the resolver follows, the attacker's JWKS is served. Alternatively, use DNS rebinding on an attacker-controlled subdomain of the pinned apex that the resolver's TTL-ignorant cache resolves first to the pinned IP (passing the pin) and then to the attacker's IP on the fetch.

**Confirmation.** Present a token signed by an attacker key with the redirect-laden `jku`. Positive signal: the server accepts the token (verification succeeded against the attacker's key). Negative control: the same token with a non-redirect `jku` on the pinned host should fail (the pinned JWKS does not contain the attacker's key). The pair discriminates "resolver followed the redirect" from "pin was ignored."

**Impact.** Full token forgery across every token the attacker can sign. Chain into `open_redirect.md § OAuth/OIDC` for the open-redirect primitive, `open_redirect_advanced_deep.md § OAuth redirect_uri Chain — Advanced Depth` for the chain composition, and `vulnerabilities/ssrf.md § DNS Rebinding` for the rebind variant.

### jku-Via-Internal-SSRF

**Primitive.** The verifier accepts any `jku` under the organization's domain or its wildcard. A common misconfiguration: `jku` host must match `*.example.com`. An internal service reachable only from the organization's network — a test instance, a legacy auth service, a diagnostic endpoint — hosts a JWKS the attacker controls or can seed.

**Preconditions.** (1) `jku` validation accepts wildcards or substring-match on the organization's domain. (2) An internal service exposes JWKS content the attacker can influence: a test instance with public write access, a diagnostic endpoint reflecting input, a WebDAV / S3-adjacent mount the attacker can write to via a lower-trust vector, or an internal service already compromised in a prior hop. (3) The internal service is reachable from the verifier's network position (common for microservices sharing a service-mesh).

**Attack recipe.** Discover internal JWKS endpoints via `ssrf.md` reconnaissance against the verifier (internal-IP enumeration, service-mesh service listing, DNS brute force on `*.svc.cluster.local`). Pick an internal service you can seed (write-primitive on a dev service, SSRF-write to an S3-compatible bucket, etc.). Place your attacker JWKS at `https://internal-svc.example.com/jwks.json`. Sign the token with the matching private key, set `jku=https://internal-svc.example.com/jwks.json`, present to the verifier.

**Confirmation.** The verifier accepts a token signed by a key only in the attacker-written internal JWKS. Negative control: a token signed by a key not in the internal JWKS rejects. The pair confirms the fetch landed and the key was trusted.

**Impact.** Full forgery via a controlled internal resource. Combined with any ssrf-write primitive (`ssrf_advanced_deep.md § Server-Side Fetcher SSRF Chain Depth` + the appropriate framework skill for the write primitive) the attack is end-to-end exploitable without needing an external attacker-reachable network host — useful against targets with egress firewalls.

### jku-with-Local-File-Scheme

**Primitive.** The HTTP library used by the verifier honors the `file://` URL scheme (or `data:` / `gopher:` / `ftp:`) in `jku` resolution. The attacker points `jku` at a world-readable local file the attacker can either (a) seed via a secondary primitive, or (b) rely on existing deployment residue to contain usable JWKS content.

**Preconditions.** (1) The verifier's HTTP library does not restrict `jku` schemes (urllib accepts `file://` in its default dispatcher; requests does not; httpx does; urllib3 does). (2) A world-readable path on the verifier's host contains JWKS-shaped content, or a path the attacker can write to via a secondary primitive. CVE-2026-48522 (PyJWKClient scheme-allowlist missing — mechanism and version metadata in `authentication_jwt_novel_deep.md § PyJWT Advisory Wave`) is this class in PyJWT.

**Attack recipe.** Enumerate `file://` scheme acceptance by presenting `jku="file:///etc/passwd"` with a token signed under an attacker-controlled key; measure for differential responses (JSON parse error leaking the file content, timing, specific error strings). If `file://` is honored, locate a path containing JWKS content: common defaults include `/tmp/jwks-cache.json`, `/var/lib/<service>/keys.json`, container-image residue in `/opt/app/test-fixtures/`, or `~/.<service>/keys.json` for user-level services. Write a target-controlled JWKS to a writable path via any secondary primitive (log injection to a world-readable log, SMB upload to a shared mount, Docker-registry blob planting), then set `jku` to that path.

**Confirmation.** Positive signal: the verifier accepts a token signed by a key in the planted JWKS. Negative control: an `jku="file:///nonexistent"` returns a differential error (file-not-found rather than JWKS-parse-failed).

**Impact.** Full forgery via local-file read-and-trust. The PyJWKClient variant (CVE-2026-48522) permits a direct chain from `file://`-reach to private-key extraction when a signing key is stored on-disk; the chain terminates at full forgery under the server's own key.

### jku-Followed-By-Cache-Poisoning

**Primitive.** The verifier fetches `jku` and caches the response per the HTTP cache semantics (`Cache-Control`, `Expires`). An attacker who serves different JWKS responses on different fetches poisons the cache: a benign JWKS for a monitoring/health-check probe, an attacker-controlled JWKS for the attack-token verification.

**Preconditions.** (1) The verifier respects HTTP cache headers from the fetched JWKS. (2) The attacker controls the JWKS endpoint (via the open-redirect or internal-SSRF variants above) OR controls a mid-chain cache. (3) The attacker can predict or observe the fetch rhythm — monitoring probes typically fire on a known interval.

**Attack recipe.** Serve attacker-controlled JWKS from `attacker.tld/jwks.json` with `Cache-Control: public, max-age=5` (short TTL). On each fetch rotate between benign content (correct JWKS matching the server's expected keys) and attacker content (adding the attacker's key). The verifier caches whichever is served at fetch time; if the attack token verification happens between cache populations with the attacker variant, verification succeeds. Alternatively use `Vary` header manipulation to serve different content to the verifier versus a human-navigable probe URL — a Vary-on-User-Agent or Vary-on-Accept trick differentiates the request shapes.

**Confirmation.** Capture the verifier's fetch stream (via `interactsh` or a self-hosted collaborator); observe the alternating responses. Verification of the attack token when the attacker JWKS was last served proves the primitive.

**Impact.** Timing-sensitive forgery. The exploitability window is bounded by the TTL × cache-rotation frequency. Combined with cache-key manipulation at an upstream CDN (load `http_request_smuggling.md § Cache Poisoning`), the attack extends to multi-user impact.

### x5u Variant

**Primitive.** `x5u` is the X.509 analogue of `jku` — a URL from which the verifier fetches a certificate chain. Vulnerable libraries fetch and trust the chain without pinning the issuing CA; attackers who host a self-signed `.pem` on an allowlisted URL (or on `file://`) extend their public key into the trusted set.

**Preconditions.** (1) The verifier honors `x5u`. (2) Chain validation is skipped on fetched chains (several JOSE libraries have this bug). (3) The attacker can host a `.pem` on an allowlisted URL or has `file://` reach.

**Attack recipe.** Generate a self-signed certificate for a vanity Common Name. Host at `https://allowlisted.tld/attacker.pem`. Set `x5u` on the forged token to the hosted URL. Sign the token with the private key matching the self-signed cert. Present to the verifier.

**Confirmation.** Positive signal: verification succeeds. Negative control: a token with a `x5u` pointing to a hosted chain whose certificate's public key does not match the token's signing key fails — proves the chain fetch is being evaluated.

**Impact.** Full forgery, same shape as `jku`. The x5u-specific adjacency is that the fetched chain can be arbitrarily deep; some verifiers validate chain-depth-N but not chain-depth-N+1 edge cases.

### jwk Inline Header Injection

**Primitive.** `"jwk":{...public key...}` embeds a public key directly in the token header. Libraries that read `header.jwk` and verify against it accept any token the holder of the matching private key signs — no network fetch, no cache, no allowlist. The attack is pure header injection with the attacker's own public key.

**Preconditions.** (1) The verifier's library has an inline-`jwk` code path that triggers without explicit opt-in. (2) The caller does not override the key source with a pinned key.

**Attack recipe.** Generate an RSA (or EC) keypair. Serialize the public key as a JWK (`{"kty":"RSA","n":"...","e":"AQAB"}`). Set `header.jwk` to this JWK and `header.alg` to the matching family (`RS256`). Sign the token with the matching private key. Present to the verifier.

**Confirmation.** Verification succeeds. The library's fingerprint determines whether this path is reachable — the `jwt_tool -X i` injection shape exercises exactly this header. The attack is the strongest JWKS-adjacent primitive because it needs no attacker-reachable network host and no file-write.

**Impact.** Full forgery, self-contained. The hunt method is to try the injection against every JWT library whose code path for inline `jwk` is not explicitly opt-in; the pattern recurs because many libraries treat `jwk`/`jku`/`x5u` symmetrically despite the first being self-contained.

### jku-Redirect-Follow Variant

**Primitive.** CVE-2026-102267 (PyJWT PyJWKClient follows redirects on JWKS fetch; mechanism in `authentication_jwt_novel_deep.md § PyJWT Advisory Wave`) widens the resolver-permissive variant by removing the host-pin pretense: a `jku` on an allowlisted host that returns a 302 to an attacker-hosted JWKS endpoint reaches the attacker's content without any `jku`-value spoofing.

**Preconditions.** (1) Target uses PyJWT's PyJWKClient (or sibling redirect-following HTTP library). (2) An open-redirect exists on an allowlisted host, or the attacker can register under the wildcard.

**Attack recipe.** Chain with any open-redirect primitive on the allowlisted host: craft `jku=https://allowed.host/open-redirect?url=https://attacker.tld/jwks.json`. The verifier fetches `allowed.host`, which 302s to attacker.tld. PyJWKClient follows (default behavior pre-fix). Attacker-controlled JWKS is loaded.

**Confirmation.** Signature verification against the attacker-chosen key succeeds.

**Impact.** Full forgery with a simpler exploitation chain than classic `jku`-value spoofing: the attacker needs an open redirect, not host-value acceptance. The chain is especially impactful against targets that have hardened against classic `jku` abuse (restricted hostname check) but kept PyJWKClient without redirect-follow mitigation.

## kid Injection Sub-Classes

`kid` is the key identifier the verifier uses to select from its known set. When `kid` resolves through a sink that interprets it (SQL query, file-path join, template render, cache-key hash), injection into the sink is injection into the key-selection logic.

**Path Traversal.** `kid="../../etc/passwd"` with a verifier that joins `kid` into a key-file path yields a known-content key (an empty file, `/etc/passwd` contents, a predictable artifact). Signing under the known content (empty string, the known file bytes as a key) forges a token. Confirm by signing with the empty secret under HS256 and setting `kid="../../dev/null"`. The variant with world-readable in-container paths (`/proc/self/environ`, `/etc/mtab`) yields a known-but-non-empty content; HMAC-signing with the file bytes as the key and the resulting signature match proves the primitive. Load `path_traversal_lfi_rfi.md` for the general file-reach primitive.

**SQL Injection.** `kid="x' UNION SELECT '<base64url-of-known-key>' --"` injected into the kid-lookup SQL returns the known key as a result row. The verifier accepts a token signed with that key. Confirmation requires observing the SQL error-vs-success differential; load `sql_injection.md` for the primitive construction, this file for the sink-reach. The variant with a Boolean-blind SQL injection on the lookup grants a slower-but-still-exploitable primitive: enumerate the key column of a known row, assemble it character-by-character, use the enumerated key for signing.

**Template / Interpolation Injection.** `kid` interpolated into a template expression (Jinja, Thymeleaf, ERB, SpEL) that then resolves to a key fetches an arbitrary resource. The chain goes through `ssti.md` for the interpolation primitive and lands in a key-fetch where the attacker controls both the resource location and its content. The SSTI variant specifically targets configurations where `kid` becomes part of a template URL or template path — a common CDN-friendly indirection pattern.

**Nested-Lookup Confusion.** The `kid` lookup is a two-step process: resolve `kid` to a key *reference*, then resolve the reference to key *bytes*. Libraries that cache the first step but not the second accept a stale reference when the underlying key rotates. The attack: trigger a rotation (or observe one), then present a token whose `kid` names a cache-fresh reference that resolves to a key the attacker now controls (via `jku`, SSRF, or a prior compromise of the reference-resolution path).

**Command / NoSQL Injection via kid.** Rarer but observed: `kid` passed to `exec`/`spawn` (library builds a shell command to fetch the key — "fetch-key-by-id.sh $kid") grants command injection; load `rce.md`. `kid` passed to a NoSQL query as an operator (`$ne`, `$gt`) grants NoSQL injection; load `nosql_injection.md`. The kid-as-sink pattern is the common thread: anywhere `kid` is a string that goes through an interpreter, the interpreter class names the primitive.

**kid Format Confusion.** `kid` can be a string, a URL, a UUID, or a cert thumbprint; the verifier's interpretation determines the sink. A verifier that treats `kid` as a URL and fetches it is a `jku`-equivalent via `kid`; a verifier that treats `kid` as a UUID and looks it up in a database is SQL-adjacent; a verifier that treats `kid` as a thumbprint and compares bytes is safer. Fingerprint the verifier's interpretation by presenting varied `kid` shapes and watching for differential handling (fetch, lookup, compare).

**kid-Case-Sensitivity Bypass.** Some verifiers normalize `kid` comparisons (uppercase, lowercase, Unicode fold) before lookup, while the JWKS lookup is case-sensitive. A `kid` that normalizes to a known key but is literally different passes the comparison and selects an attacker-plantable sibling. Rare but observed in multi-vendor federation stacks.

## Header-Trust Hierarchy and Mixed-Priority Confusion

A JWT header can carry `kid`, `jku`, `x5u`, and `jwk` simultaneously. Vulnerable verifiers process one, ignore the others, and skip signature validation of header consistency.

**jwk-Over-kid.** A token with both an inline `jwk` and a `kid` referencing a server-known key: libraries that prefer `jwk` verify against the attacker's inline key and ignore the trusted `kid`. The acceptance is a full forgery; the attacker's inline `jwk` is the only key that matters.

**jku-Over-kid.** With both `jku` (attacker-reachable URL) and `kid` set: libraries that fetch `jku` first and treat the fetched set as authoritative, then look up `kid` in the fetched set, grant forgery when the attacker's JWKS contains a key with the stated `kid`.

**Priority-Dependent on Algorithm.** Some libraries pick the key source based on `alg`: HS* keys from a configured server secret, RS*/ES* keys from `jwk`/`jku`/`kid`. An attacker can downshift from the configured path to the header-controlled path by picking an algorithm the library routes through header-sourced keys.

**Mixed-Priority Confusion.** When the verifier reads one header for key selection and another for algorithm selection, the two need not be consistent. A token with `"alg":"HS256"` and `"jwk":{<RSA public key>}` claims HMAC verification against an RSA key; libraries that pass the RSA key material straight to the HMAC primitive hash the public-key bytes as an HMAC secret — the RS→HS confusion class, triggered via the header-trust path rather than the configured-key path.

**Confirmation.** Issue a token with each header combination (`jwk+kid`, `jku+kid`, `jwk+alg-mismatch`, four-header overlap) and watch which combination verifies. The acceptance pattern reveals the library's trust hierarchy; the hierarchy is the attack surface. Build a matrix: rows = header combinations, columns = acceptance / rejection / error class. The library's choice is often undocumented but observable.

## Cross-Service aud / typ Confusion

The `aud` claim names the intended audience; `typ` names the token type (`JWT`, `at+jwt`, `id_token`). Verifiers that check signature-and-nothing-else accept any valid token at any endpoint.

**Access-vs-ID Token Swap.** OIDC issues an ID token (`typ:"id_token"`, carries user identity) and an access token (`typ:"at+jwt"` or no explicit typ, carries authorization). APIs that verify signature but not `typ`/`aud` accept an ID token where an access token is required. Primitive: present at a user's own ID token (available to the client-side app) against an API that was supposed to require the access token's scopes. Confirmation: the API returns a response consistent with ID-token-granted authority (user profile, limited scope) rather than the richer access-token response.

**Service-to-Service aud Reuse.** Service A verifies signature-only; it accepts a token issued for Service B. The chain: compromise a weakly-protected endpoint on B that mints or exposes tokens; replay against A. Fingerprint by capturing legitimate tokens for each service, reading the `aud`, and attempting cross-presentation. The hunt lead is a shared signing key across services (common in monolith-to-microservice migrations) with per-service `aud` claims but no per-service `aud` enforcement.

**typ:JWT vs typ:at+jwt.** RFC 9068 defines `at+jwt` for access tokens; adoption is partial. Verifiers that pin `typ:"at+jwt"` reject OIDC-style ID tokens; verifiers that accept any `JWT`-typed token conflate the two. The downgrade path is "sign a new token with `typ:"JWT"`" when a stricter `typ:"at+jwt"` is required — only exploitable when the signing key is attacker-controlled, but combined with any of the key-source primitives above, is immediate.

**Azp (Authorized Party) Checks.** In multi-client OIDC the `azp` claim names the client the token was issued to. A verifier that trusts `aud` but not `azp` accepts a token intended for a different client of the same audience; combined with a client that is less-trusted (a mobile app, a less-protected third-party), the attack cross-presents.

**Composite Confusion Chain.** Compromise a lower-trust service's token endpoint (via SSRF, IDOR, or a weak auth mechanism), extract an access token for a lower-trust audience, present it to a higher-trust audience that reuses the same signing key or accepts tokens cross-audience. The composite primitive is privilege escalation across trust boundaries without any key compromise — only policy drift.

**aud-as-Array Confusion.** RFC 7519 permits `aud` as either a string or an array of strings. Verifiers that handle both inconsistently expose confusion attacks: a verifier that uses `aud in token.aud` (Python `in` on a list) matches any substring on a string-shaped `aud` ("servicA" in "myservice-aud" is False, "servicA" in ["servicA", "attacker-aud"] is True). The attacker controls the array shape via token forgery (combined with any key-control primitive); the verifier accepts.

**iss-as-URL Confusion.** `iss` is often a URL. Verifiers that compare `iss` string-equality against a configured value are safe; those that parse and compare host-only are vulnerable to URL-parser-differential bypasses (see `open_redirect_novel_deep.md § URL-Parser Differentials`). The attack: forge an `iss` of `https://trusted.iss@attacker.tld/` where the host-only comparison returns `trusted.iss` but the actual host is `attacker.tld`.

## Multi-Tenant Shared-Key JWT Confusion

Multi-tenant systems that share a single signing key across tenants are exposed to cross-tenant primitives whenever any claim-based tenant check is weak.

**Tenant-ID Claim Not Enforced.** The token contains `tenant:"customerA"` but the server reads tenant from the URL path (`/api/customerA/data`); the two can disagree. An attacker who holds a legitimate token for customerA presents it against `/api/customerB/data`; the signature verifies (shared key), the server reads tenant from the URL, serves customerB data under customerA's identity. The primitive is horizontal privilege escalation across tenant boundaries.

**Shared-Signing-Key as a Lateral-Move Vector.** When a token's signing key is shared across environments (dev, staging, prod) or across tenants, a compromise in a lower-value environment yields the key for the higher-value environment. Fingerprint by observing the token's signature across environments and checking whether the key is reused (same HMAC produces same signature for same input).

**Tenant-Scoped `aud` Not Enforced.** A multi-tenant SaaS issues tokens with `aud:"tenant-A"` for customerA, `aud:"tenant-B"` for customerB. A service that verifies signature only accepts both. The chain combines signature forgery (via any of the primitives in the novel sibling) with cross-tenant `aud` confusion.

**Signing-Key per Tenant with Shared Issuer.** Even when each tenant has its own signing key, if the issuer is shared the verifier may try all tenant keys. An attacker who controls one tenant's key forges tokens claiming other tenants; the verifier tries each key in turn and the attacker's own key succeeds for their own tenant, but if the verifier reads the tenant from a signature-independent source (URL path, cookie, Host header), the attacker crosses tenants.

**Confirmation.** Capture two tokens from two tenants; compare the signatures of identical claim payloads. If identical, the key is shared. Present each at the other tenant's endpoint; acceptance proves cross-tenant primitive.

## JWT Claim Injection and Manipulation Depth

Beyond aud/typ confusion (§ above), individual claim values are attack surfaces when the verifier or downstream consumer processes them without defensive parsing.

**`sub` Claim Spoofing via Normalization.** The `sub` (subject) claim identifies the principal. Verifiers that normalize `sub` before lookup — lowercasing, Unicode NFC/NFKD normalization, whitespace trimming — accept a `sub` that differs from the canonical form but resolves to the same account. An attacker who forges a token (via any key-control primitive) sets `sub` to a visually-identical but bytewise-different string that normalizes to the victim's `sub`. The chain requires both forgery capability and a normalization-dependent lookup. Fingerprint by observing how the target's account-lookup handles case and Unicode variants of known `sub` values.

**Numeric Claim Type Confusion.** Claims like `exp`, `iat`, `nbf` are defined as NumericDate (integer seconds since epoch). Verifiers that accept string-typed values (`"exp":"99999999999"`) or floating-point values (`"exp":1.7e10`) may parse them differently than expected. A string `exp` that passes a `typeof` check but fails a comparison check bypasses expiration enforcement in weakly-typed languages. A floating-point `exp` that truncates on integer cast extends the token's lifetime. Confirm by issuing tokens with string-typed and float-typed temporal claims and observing acceptance past the intended expiration.

**Nested Object Injection in Claims.** JWT claims are JSON; a claim value can be an object rather than a scalar. A verifier that reads `token.role` and expects a string but receives `{"role":{"$gt":""}}` passes the object to a downstream comparison that interprets it as a NoSQL operator — a claim-to-query-injection chain. The primitive is the type mismatch between the verifier's expectation (string) and the attacker's injection (object). Load `nosql_injection.md` for the downstream primitive; this section owns the injection vector through the claim.

**Array-Typed Claim Exploitation.** Claims like `scope`, `groups`, `roles` are often arrays. Verifiers that check `"admin" in token.roles` are safe against scalar injection but vulnerable to array pollution: `"roles":["user","admin"]` passes the membership check. When the attacker can forge claims, injecting the privileged value into an array-typed claim grants escalation if the verifier checks membership without validating the issuer's authority to grant that value.

**Claim Shadowing via Duplicate Keys.** The JSON specification does not forbid duplicate keys in an object. A token with `{"role":"user","role":"admin"}` has two `role` keys; the JSON parser's behavior is implementation-defined. Parsers that take the last value grant `admin`; parsers that take the first grant `user`. An attacker who forges a token with duplicate keys exploits parser-differential behavior between the verifier (which may read `user` and accept) and the downstream consumer (which may read `admin` and authorize). Confirm by issuing a duplicate-key token and observing which value the application acts on.

**Custom Claim Trust Without Schema Validation.** Applications that define custom claims (`tenant_id`, `department`, `feature_flags`) and trust them for authorization without validating against an issuer-approved schema accept any value the forger injects. The primitive is that custom claims are application-defined but not application-validated — the JWT standard defines no schema enforcement, and most libraries pass custom claims through without inspection. The finding is: every custom claim the application reads for authorization is an injection point when the signing key is compromised.

## OIDC Mix-Up and Response-Mode Abuse

OIDC's authorization-code flow issues a `code` at the authorization endpoint, redeemed at the token endpoint for ID+access tokens. Mix-up attacks arise when a client supports multiple IdPs, picks one at authorization time, and loses track of which IdP's token endpoint to redeem at. Response-mode abuse widens the channel the token can arrive on; state/nonce bugs weaken the authorization-response-to-request binding.

### Classic Mix-Up (Mainka et al.)

**Primitive.** The attacker-controlled IdP (IdPA) is one of the client's supported IdPs. The attacker initiates authorization at the client, selecting a benign IdP (IdPB) with elevated privileges. The attacker's IdPA intercepts the authorization response (via a phishing step or a TLS-stripping position) and reflects it to the client as if from IdPB. The client, unable to distinguish, redeems the code at IdPB's token endpoint — which rejects it (it issued no such code). But the client exposes the code in the process, and the attacker captures it. For deployments where the client redeems at the wrong IdP without rejection — multiple IdPs sharing a token-endpoint path, or no issuer check — the attacker's IdPA receives the code intended for IdPB and exchanges it for a token with IdPB's identity.

**Preconditions.** (1) Multi-IdP client (common in SSO federation, consumer-identity-providers, mobile apps supporting Google/Apple/Facebook login). (2) Absent `iss` identification in the authorization response (pre-RFC-9207 behavior). (3) No state-binding between authorization request's IdP selection and token-endpoint redemption. (4) Attacker position on the authorization-response channel (phishing, network MitM, open-redirect on the client's registered callback host).

**Attack recipe.** Register as an IdP with the target client (public-IdP registration is common; alternatively compromise an existing IdP). Issue an authorization request through the client against IdPB (the elevated IdP). Position to intercept the authorization response from IdPB. Reflect the intercepted response to the client, framed as if from IdPA. Client redeems at IdPA's token endpoint under attacker control — attacker exchanges the IdPB-issued code and receives tokens for IdPB.

**Confirmation.** The attacker successfully logs in as a victim account with claims from IdPB (the privileged provider). Negative control: without the mix-up (client correctly identifies IdPB), the attacker is logged in as their own IdPA account.

**Impact.** Full account takeover of victim users on IdPB. Mitigation per RFC 9207: `iss` parameter in the response identifies the authorization server; the client checks it against the expected IdP. RFC 8414 metadata-authenticated issuer discovery closes the issuer-impersonation hop. Class generalization: any multi-source authentication that lacks source-identification in the response is a candidate — the broader shape appears in SAML (relying-party-initiated SSO without issuer check), WebAuthn multi-rp flows, and OpenID Federation deployments.

### Response-Mode Abuse

**Primitive.** OIDC supports response modes beyond the standard `query` and `fragment`: `form_post`, `web_message`, `fragment.jwt`, `query.jwt`. Clients that accept any response mode without pinning expose tokens via unexpected channels. The attack is a channel-smuggling bypass of the client's expected response path.

**Preconditions.** (1) Authorization server supports and advertises alternative response modes in metadata (`response_modes_supported` in `/.well-known/openid-configuration`). (2) Client does not pin the response mode it requested — a token arriving in a response mode the client did not request is still processed. (3) The alternative response mode's channel is reachable by the attacker.

**Attack recipe.** `response_mode=web_message` posts the token to a `window.postMessage` listener; craft an authorization request specifying `web_message` even if the client requests `query`. A client that honors the received `web_message` response without verifying the response-mode matches what was requested leaks the token to any `window.opener`. For `response_mode=form_post`, the server wraps the token in an HTTP form POST to the `redirect_uri`; if the `redirect_uri` host has lax CSP (`form-action` directive missing or permissive), the form can be redirected to attacker-reachable listeners via a client-side XSS or a reflected HTML sink.

**Confirmation.** Capture the token on the alternative channel (postMessage listener, redirected form POST). Negative control: an authorization request with the standard `query` mode delivers via query string; comparing the two channels locates the acceptance.

**Impact.** Token-channel smuggling without any JWT verification bug — the token is legitimate; it just arrives at an attacker-controlled handler. Mitigation: pin the response mode at the client; compare the received mode to the requested mode on every response.

### Nonce Replay

**Primitive.** The ID token's `nonce` must match the nonce the client supplied at authorization time, binding the response to the specific request. Clients that generate `nonce` once per session (rather than once per flow) accept replayed tokens; clients that skip `nonce` entirely accept any ID token for a victim user.

**Preconditions.** (1) Client generates `nonce` with insufficient uniqueness (session-level, user-level, or static) OR skips `nonce` verification. (2) Attacker can capture a legitimate ID token for the victim (via network observation, log scrape, or a prior flow).

**Attack recipe.** Capture a legitimate ID token for the victim account (via one of the above). Initiate a fresh authorization flow at the client. Instead of carrying through to a real authorization at the IdP, replay the captured ID token as if it were the response. The client verifies signature (succeeds — ID token is legitimate), checks `nonce` against the fresh request's nonce. If the nonce check is skipped or the client's nonce is predictable/reused, verification succeeds and the client treats the attacker as the victim.

**Confirmation.** Login as the victim without needing the victim's credentials. Negative control: a token with a different `nonce` (random replay) fails nonce comparison on a correctly-implemented client, but not on a vulnerable one.

**Impact.** Full account takeover for any user whose ID token can be captured. The exposure window is bounded by the token's `exp`; for long-lived ID tokens, the window is wide. Mitigation: generate `nonce` per flow, store it bound to the request (session cookie, encrypted state), verify every response's `nonce` against the stored value.

### State Replay and Fixation

**Primitive.** `state` binds the authorization response to the request. Clients with no `state` check accept any response for any request; clients with a static `state` accept replays. The attack is CSRF-equivalent on the OAuth flow: force the victim onto an attacker-chosen flow outcome.

**Preconditions.** (1) Client does not generate `state` per flow, or does not verify `state` on response. (2) Attacker can trigger the victim to initiate or complete an OAuth flow.

**Attack recipe.** Issue a fresh authorization at the client; capture the `state` and the authorization URL. If the attacker needs the authorization-response delivered to their own account's redemption endpoint, race the victim's browser to the authorization URL and submit the authorization-response with attacker-controlled values; the client's missing-state-check accepts. Alternatively, the attacker's authorization-response can be delivered to the client, which — missing the `state` check — treats it as the victim's response (login-as-attacker on the victim's session, account-linking under attacker identity).

**Confirmation.** The victim's session is now logged in as the attacker, or an account-linking record ties the victim's session to the attacker's identity. The attacker gains access to the victim's local data via the linked identity.

**Impact.** Session fixation and account-linking confusion. Chain into `csrf.md` for the CSRF-primitive on the authorization request. Mitigation per RFC 6819 / RFC 9700: generate `state` per flow with cryptographic randomness, store bound to the request, verify on every response.

### Issuer Confusion Across Discovery Metadata

**Primitive.** The OIDC discovery document (`/.well-known/openid-configuration`) names the authorization server. A client that caches the discovery doc without re-verifying issuer on each flow accepts a response from a cached-stale server even after the server rotates. The attack targets long-lived clients (mobile apps, desktop apps) that cache discovery infrequently.

**Preconditions.** (1) Client caches discovery metadata with a long TTL (days or indefinite). (2) The authorization server rotates issuers or hostname at some point. (3) Attacker can control the pre-rotation host (via subdomain-takeover, DNS compromise, legacy-domain acquisition).

**Attack recipe.** Monitor the authorization server's issuer configuration (DNS records, metadata URLs). When the server rotates, immediately set up an attacker-controlled service at the pre-rotation hostname — subdomain takeover is the common vector; load `subdomain_takeover.md`. Any client that still has the pre-rotation discovery metadata cached contacts the attacker's hostname for authorization and redemption.

**Confirmation.** A client that resolves authorization URLs to the attacker's host is observed via log analysis or the attacker's own fetch counter. Mitigation: cache metadata for short TTLs; validate issuer on every flow against the top-level identity (not the cached metadata); use RFC 8414 metadata signing.

**Impact.** Long-tail client compromise, especially mobile apps. The exposure window is bounded by cache TTL and app-update frequency.

### Confirmation of a Mix-Up Primitive

**Primitive.** The composite confirmation for the full OIDC mix-up class.

**Attack recipe.** Register two IdPs with the target client (one attacker-controlled, one legitimate). Issue authorization request against the legitimate IdP; present authorization response from attacker IdP. Client proceeds — fetches tokens, logs the user in, accepts the `sub`.

**Confirmation.** Successful login as a victim account, with the attacker in control of IdPA. The response-side logs on the attacker's IdPA show a code redemption that corresponds to the legitimate IdPB-issued code. Negative control: the same attack against a client with proper `iss`-identification fails at the client-side `iss`-check — the client rejects the response before redemption.

**Impact.** The full mix-up class is live when confirmation succeeds. The composite finding is "the client does not verify the authorization-response source and does not verify the token's `iss`/`aud` combination against the expected IdP for the specific flow."

## PKCE Downgrade and Code-Verifier Confusion

PKCE binds the code-exchange request to the authorization request by requiring a `code_verifier` whose SHA-256 matches the `code_challenge` sent at authorization time. Weak enforcement grants code-interception primitives.

**PKCE Not Required.** Authorization servers that advertise PKCE as supported but don't require it accept code-exchange requests without `code_verifier`. If any code the attacker captures was issued without PKCE binding, redeeming it requires only the code — no verifier.

**Plain Challenge Accepted.** `code_challenge_method=plain` sends the challenge in clear; a man-in-the-middle on the authorization channel captures the challenge and can forge the verifier. Hardened deployments force `S256`; weak ones advertise `plain` as an accepted method.

**Mismatched-Verifier Not Rejected.** A buggy authorization server accepts a `code_verifier` whose hash does not match the stored `code_challenge`; the attacker guesses or supplies a verifier of their choice. Confirm by presenting a code with a verifier the server could not have issued; non-rejection proves the bug.

**Cross-Flow Verifier Reuse.** Clients that use a static or session-level `code_verifier` (rather than a per-flow value) grant replay primitives — any captured code pairs with the known verifier. Fingerprint the client by observing its PKCE pattern across multiple flows.

**Public-Client Secret Confusion.** Public clients (SPAs, mobile apps) do not have a client secret. Authorization servers that require a client secret for the token-exchange request, but accept any string from a public client, enable confused-deputy attacks. The attack: pose as the public client with any secret; the server accepts because the public-client flag is set.

**PKCE Bypass Via Second-Order Token.** If the server's authorization-code storage can be read or written through a different vulnerability (SQL injection, IDOR on a code-record), the attacker modifies the stored `code_challenge` to match a verifier they know, then redeems with the matching verifier. The chain requires a secondary primitive on the storage; load `idor.md` or `sql_injection.md` for the entry.

## OAuth 2.0 Token Exchange Attack Surfaces

RFC 8693 token exchange permits a client to swap one token for another — exchanging an access token for a different-audience token, an ID token for an access token, or a SAML assertion for a JWT. The exchange endpoint (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) is a privileged token-minting surface; weak enforcement on its inputs grants cross-boundary escalation.

**Subject-Token Type Confusion.** The exchange request carries `subject_token` (the token being exchanged) and `subject_token_type` (its declared type: `urn:ietf:params:oauth:token-type:access_token`, `...id_token`, `...jwt`, `...saml2`). Authorization servers that trust the declared type without verifying the token's actual shape accept a less-constrained token as a more-constrained one. The attack: present an ID token (which the client-side app can read) with `subject_token_type` claiming access-token type; the exchange endpoint treats it as an access token and mints a new token with the access token's broader scopes.

**Actor-Token Impersonation.** The optional `actor_token` identifies the actor performing the exchange on behalf of the subject. Authorization servers that accept any actor token without validating the actor's authorization to impersonate grant delegation abuse: an attacker who holds any valid token uses it as `actor_token` and exchanges a captured `subject_token` for a new token that carries the subject's identity under the attacker's delegation chain.

**Audience Escalation via Requested-Token-Type.** The `audience` parameter names the target service the exchanged token is for; `requested_token_type` names the desired output type. Servers that honor any requested audience without checking whether the subject has authority to reach that audience grant lateral movement: exchange a token scoped to Service-A for one scoped to Service-B, where Service-B has higher privilege.

**Scope Widening on Exchange.** The `scope` parameter in the exchange request names the desired scopes on the output token. Servers that grant any requested scope — rather than intersecting with the subject token's existing scopes and the client's allowed scopes — permit privilege escalation through scope widening. The attack: exchange a read-only token for a read-write token by requesting `scope=read write` in the exchange.

**Chained Exchange Amplification.** Nothing in RFC 8693 limits the depth of exchange chains: Token-A exchanges to Token-B, Token-B exchanges to Token-C. Each hop can widen audience, scope, or lifetime. Servers that do not track exchange depth or provenance permit unbounded escalation through repeated exchanges — each hop incrementally widens the token's reach.

**Exchange Endpoint as an Open Token Mint.** If the exchange endpoint's client authentication is weak (public client, `client_secret` in query string, no client authentication at all), any party who can reach the endpoint and present a valid subject token mints arbitrary tokens. The endpoint becomes a self-service forgery surface. Fingerprint by probing the endpoint with and without client credentials.

**Confirmation.** Capture a legitimate token for a low-privilege scope. Submit a token-exchange request with `audience` set to a higher-privilege service and `scope` set to broader permissions. Acceptance of the exchange (a new token is returned) plus successful use of the new token at the higher-privilege service proves the escalation. Negative control: the same exchange with the correct (narrow) audience and scope should also succeed but produce a token with no additional privilege.

## DPoP / mTLS / Sender-Constrained Token Bypass

DPoP (RFC 9449) and mTLS-sender-constrained tokens (RFC 8705) bind a token to a proof-of-possession artifact — a signed JWT proof (DPoP) or the TLS client certificate (mTLS). Bypass primitives center on how the resource server verifies the binding. Each sub-primitive weakens one specific binding check; combined with a token-theft primitive (XSS, log leak, device compromise), the binding bypass turns a sender-constrained token back into a bearer token.

### DPoP Proof Not Validated

**Primitive.** The resource server reads the `cnf` claim in the token (containing a thumbprint of the proof's key) but does not require a DPoP proof header on each request. The token is bearer-equivalent — any holder uses it.

**Preconditions.** (1) The access token carries a `cnf.jkt` claim marking it as DPoP-bound. (2) The resource server verifies the token's signature and `cnf` presence but does not inspect the `DPoP:` request header. (3) Attacker has obtained the token (via XSS, log scrape, cookie theft on a mishandled DPoP token store).

**Attack recipe.** Capture the DPoP-bound token. Present at the resource server with any `Authorization: DPoP <token>` and either no `DPoP:` header or a syntactically malformed one. A server that enforces proof-of-possession rejects at this step; a server that only requires the token's `cnf` claim to be present passes through.

**Confirmation.** The resource responds with success data. Negative control: a token *without* `cnf` is also accepted on a non-enforcing server (baseline); a token *with* `cnf` and *without* the DPoP header should fail — if it doesn't, the primitive is live.

**Impact.** Bearer-equivalent reuse of DPoP tokens. For services that use DPoP as the only proof-of-possession layer (no mTLS fallback), token theft becomes immediately exploitable without the private key.

### DPoP Proof Replay Within Time Window

**Primitive.** DPoP proofs carry a `jti` (unique proof ID) and `iat` (timestamp). The resource server must track seen `jti` within an acceptable time window to prevent replay. Servers that enforce a time window (reject proofs older than N seconds) without maintaining a replay cache accept the same proof twice within the window.

**Preconditions.** (1) Resource server accepts DPoP proofs with a time-window check (e.g., `iat` within last 30 seconds). (2) No per-request `jti` deduplication is enforced server-side. (3) Attacker has captured one legitimate DPoP proof (via a MitM position, a logged request, or a browser-side observable).

**Attack recipe.** Capture a legitimate DPoP proof from a victim session (via XSS logging the DPoP header, network observation, or a vulnerable proxy that logs headers). Within the server's time window (typically seconds to a minute), replay the exact same proof on the attacker's own request. The server verifies `iat` is within window, `jti` is well-formed, signature is correct — but does not check whether `jti` was previously seen.

**Confirmation.** The second request with the replayed proof succeeds. Negative control: present the same proof after the time-window expires — server should reject on `iat` out-of-window.

**Impact.** Short-window replay of DPoP-bound requests. Bounded by the time window but adequate for single targeted actions (one API call, one money-moving request). Mitigation: server-side `jti` cache with TTL matching the time window; CVE-2026-101917 (PyJWKClient still amplifies unauthenticated JWKS fetches on unknown kid; see `authentication_jwt_novel_deep.md § PyJWT Advisory Wave`) is adjacent to this replay-cache absence pattern.

### DPoP Thumbprint Not Matched to Proof Key

**Primitive.** The server reads `cnf.jkt` (the thumbprint of the proof key the token is bound to) but verifies the proof's signature using the key embedded in the proof's own `jwk` header, without comparing the thumbprint of that key to `cnf.jkt`. An attacker who holds *any* keypair signs their own DPoP proof; the server verifies against the attacker's key.

**Preconditions.** (1) Access token has `cnf.jkt` claim. (2) Resource server extracts the proof's `jwk` header and verifies against that JWK's public key. (3) The verification code path does not compute the proof-JWK's thumbprint and compare against `cnf.jkt`.

**Attack recipe.** Capture a DPoP-bound access token. Generate the attacker's own keypair. Construct a DPoP proof signed by the attacker's private key, with the attacker's public JWK embedded in the proof's header. Present `Authorization: DPoP <token>` and `DPoP: <attacker-signed-proof>`.

**Confirmation.** The request succeeds. Negative control: the OKP x/d consistency gap (behavior-fingerprinted class in `authentication_jwt_novel_deep.md § PyJWT 2024–2026 Advisory Wave`) is the specific PyJWT shape where the mismatch is on the key-import side rather than the thumbprint-compare side; distinguish by observing whether an OKP JWK with mismatched `x` and `d` is accepted.

**Impact.** Full bypass of the sender-constraint. The attacker's proof satisfies the resource server's verification without ever needing the legitimate holder's private key.

### mTLS Thumbprint Not Checked

**Primitive.** The access token's `cnf.x5t#S256` is the SHA-256 thumbprint of the TLS client certificate the token is bound to. Resource servers that verify TLS termination happened (TLS session established, client cert presented) but do not compare the certificate thumbprint to `cnf.x5t#S256` accept any valid-TLS-authenticated request as if it were the right client.

**Preconditions.** (1) Access token has `cnf.x5t#S256` claim. (2) Resource server has mTLS termination that produces a client-certificate record. (3) The authorization logic reads the token's `cnf` and the TLS session's certificate but does not compute `SHA256(DER(cert))` and compare.

**Attack recipe.** Obtain any valid client certificate accepted by the mTLS layer (the attacker's own, if they have mTLS-authenticated access to any service in the trust bundle). Present `Authorization: Bearer <mTLS-bound-token>` over an mTLS session with the attacker's certificate. The TLS layer accepts (attacker's cert is valid); the token's signature verifies; the `cnf.x5t#S256` is read but not compared.

**Confirmation.** The request succeeds under the attacker's TLS identity. Negative control: a request without any client cert fails the mTLS termination step; the pair discriminates "TLS termination enforced" from "thumbprint compared."

**Impact.** Full bypass of sender-constraint. The attacker's own cert replaces the legitimate holder's. Mitigation: compute the thumbprint and compare on every request.

### mTLS Terminated at the Edge, Thumbprint from Header

**Primitive.** When mTLS terminates at a load balancer or reverse proxy, the client certificate is passed to the backend via a header (`X-Client-Cert`, `X-Forwarded-Client-Cert`, `X-SSL-Client-Cert`, `ssl-client-cert`). The backend reads the header to determine the client identity. Header-injection attacks forge the thumbprint.

**Preconditions.** (1) mTLS terminates at an edge proxy. (2) Backend trusts a specific header for client-certificate identity. (3) The backend does not verify the header's source — missing shared-secret header, missing IP allowlist, or trusted-proxy list is permissive enough to accept forged requests.

**Attack recipe.** Enumerate the edge's client-cert header name via vendor fingerprinting (nginx uses `X-SSL-Client-Cert`; AWS ALB uses `X-Amzn-MTLS-Clientcert`; Envoy uses `X-Forwarded-Client-Cert`). Craft a request with the correct header name set to a certificate whose thumbprint matches `cnf.x5t#S256`. If the backend accepts the header without verifying the request originated from the edge, the attack lands. Chain with `header_injection.md § Trust Boundary Primitives` for the general class.

**Confirmation.** A request with the forged header succeeds; a request without the header or from an untrusted-IP source fails. The pair discriminates whether the header is the identity source.

**Impact.** Full forgery of the mTLS binding. The chain requires reaching the backend network path directly (common in cloud-adjacent networks, container-level attacks, misconfigured ingress rules).

### Proof-of-Possession Bypass at the Introspection Endpoint

**Primitive.** Reflected introspection responses (RFC 7662) include `cnf` claims when the token is sender-constrained. A caller that introspects a token for authorization decisions but ignores `cnf` in the introspection response grants bearer-equivalent authority — the introspection endpoint said "yes, this token is valid" but the caller doesn't check the proof-of-possession binding.

**Preconditions.** (1) Resource server uses introspection (not local signature verification) for token validation. (2) Introspection response includes `cnf` field. (3) Resource server trusts introspection's `active: true` but doesn't propagate `cnf` enforcement.

**Attack recipe.** Capture a sender-constrained token via any token-theft primitive. Present at a resource server that introspects. The introspection endpoint returns `{"active": true, "sub": "...", "cnf": {"jkt": "..."}}`. The resource server sees `active=true` and proceeds; the `cnf` field is logged but not enforced.

**Confirmation.** The request succeeds under the stolen token without any proof-of-possession artifact. Negative control: direct signature verification path on the same token (if the server has one) might enforce `cnf`; the differential locates the introspection weakness.

**Impact.** Bearer-equivalent reuse of sender-constrained tokens on introspection-based resource servers.

### DPoP Nonce Lifecycle

**Primitive.** RFC 9449 permits a server-issued `nonce` in DPoP proofs for additional anti-replay. The server issues a `DPoP-Nonce:` response header; subsequent requests must include that `nonce` in the DPoP proof. Servers that issue nonces but don't rotate them, or that accept any nonce from the client without server-side binding, grant replay primitives.

**Preconditions.** (1) Server advertises nonce usage via `DPoP-Nonce` header. (2) Server-side state for nonce verification is missing or stale.

**Attack recipe.** Observe the `DPoP-Nonce` header across multiple requests. If static, the server is not rotating. Capture a victim's DPoP proof (with its nonce). Present the proof again (replay) at any later time — if nonce isn't rotated per-request, the proof still satisfies the server's nonce check.

**Confirmation.** The same proof+nonce pair accepted at time t and time t+N. Negative control: a proof with a stale nonce (from a prior epoch) rejected proves rotation is live.

**Impact.** Replay primitive on DPoP tokens, bounded by nonce-rotation frequency. Combined with the DPoP Proof Replay Within Time Window class, the exposure window extends to the time between rotations.

## Device Code and CIBA Flow Abuse

The device-code flow (RFC 8628) and CIBA (OIDC CIBA spec) decouple authorization approval from the device under attack. Both have standing issues when polling and binding are weak.

**Device-Code Phishing.** The attacker initiates a device-code flow against the target's authorization server, obtains a `user_code` and `verification_uri`, and tricks the victim into visiting the URI and entering the code. The victim thinks they're logging in to a service of their own; they're actually approving the attacker's device. Primitive: full account access, no credential theft. Mitigation: short code TTLs, prominent "device you're approving" context in the UI, rate-limiting on code issuance.

**Polling Race Against Session-Fixation.** The device-code flow polls for approval. If the authorization server issues a token at the first poll after approval without re-checking which session approved, an attacker who initiated the flow receives the token even though the victim's session approved it. Mitigation: the token endpoint checks the approval was from a session associated with the device.

**CIBA Notification Hijack.** CIBA sends an authentication notification to the user's registered device (push, SMS, call). Vulnerable implementations that let the client specify the notification channel (rather than the server deriving it from the user record) enable attacker-controlled notification delivery — the attacker is the one who approves. The primitive requires the authorization-server-side bug; confirm by submitting a CIBA request with a notification-channel attribute controlled by the client and watching whether the server honors it.

**Backchannel Response Injection.** CIBA notifies the authorization server when the user approves (backchannel). If the backchannel notification is not authenticated by the user's device identity, an attacker who can inject arbitrary requests to the authorization server simulates the approval. Fingerprint by probing the backchannel-notification endpoint for authentication.

## Refresh Token Reuse Detection Depth

Refresh-token rotation issues a new refresh token on each use and marks the old one as consumed; reuse of a consumed token should invalidate the entire token family (the current refresh token and every token derived from it). Weak enforcement grants durable primitives.

**No Rotation.** The server reissues the same refresh token on each use. The token is good forever; combined with any token-theft primitive (XSS, log leak, device theft), the attacker has permanent access.

**Rotation But No Reuse Detection.** The server rotates but doesn't invalidate on reuse. An attacker who steals a refresh token and uses it in parallel with the victim grants both parties new tokens on each refresh; the victim never notices, the attacker has indefinite access.

**Reuse Detection But No Family Invalidation.** The server invalidates the consumed token but leaves the subsequent-generation tokens valid. Attack: steal the current refresh token, use it once (invalidating it), use the new refresh token for your own refresh. The victim's parallel refresh fails (invalidated), the server issues new tokens to the attacker's branch, the attacker retains access while the victim is logged out.

**Grace Window on Reuse.** The server allows one grace use of a consumed token (to handle double-submit on flaky networks). The grace window is the attack window: use the stolen token during the grace, derive a new token family under the attacker.

**Confirmation.** Capture a refresh-token pair (yours), present the consumed one, and observe one of: (a) acceptance (no rotation), (b) acceptance plus a new token (rotation without invalidation), (c) rejection with the current token still valid (reuse detection without family invalidation), (d) rejection with the entire family invalidated (correct behavior).

## JWT Revocation and Blocklist Bypass Depth

JWTs are stateless by design; revocation requires a server-side blocklist or a short token lifetime. Both have operational gaps that extend the attacker's window past the intended revocation boundary.

**Blocklist Keyed on `jti` Only.** A blocklist indexed by the token's `jti` (JWT ID) claim rejects previously-seen tokens. If the attacker can forge tokens (via any key-control primitive), they mint new tokens with fresh `jti` values — the blocklist never contains them. The blocklist protects against replay of legitimately-issued tokens; it does not protect against forgery. Confirmation: forge a token with a `jti` never seen by the server; the blocklist accepts it.

**Blocklist Keyed on Token Hash.** A stronger blocklist hashes the full token and rejects known hashes. The attacker who can forge tokens generates semantically-identical tokens with different signatures (different `iat` by one second, different `jti`), producing distinct hashes. The blocklist misses them. Confirmation: forge two tokens with the same claims but different `jti`/`iat`; revoke one; present the other.

**Blocklist Race on Distributed Systems.** A blocklist maintained in a centralized store (Redis, database) has propagation delay to edge verifiers. A token revoked at `t=0` is still accepted at an edge verifier whose blocklist cache refreshes at `t=0+TTL`. The race window equals the cache TTL; for CDN-adjacent caches the window is often 60-300 seconds. Fingerprint by revoking a token (via logout or admin action) and immediately replaying at a different edge endpoint.

**Short-Lived Tokens with Long Grace Windows.** Tokens with `exp` set to 5 minutes are "short-lived" by design, but if the verifier applies a clock-skew tolerance of 5 minutes (common default), the effective lifetime is 10 minutes. Servers that add generous `nbf`-before-current-time tolerance further widen the window. Fingerprint by presenting an expired token and measuring the acceptance boundary — the exact tolerance reveals the clock-skew configuration.

**Logout Does Not Revoke.** Many implementations treat logout as a session-cookie deletion without adding the JWT to a blocklist. The token remains valid until `exp`. Confirmation: capture a token, trigger logout, replay the token; acceptance proves no server-side revocation.

**Revocation of Refresh but Not Access.** Revoking a refresh token (via `/revoke` endpoint) invalidates future token refreshes but leaves the current access token valid until its natural `exp`. An attacker who captured both the access and refresh tokens before revocation retains access for the access token's remaining lifetime. The gap is by design in OAuth 2.0; the finding is that the access token lifetime is the attacker's dwell time after a revocation event.

**Token Family Revocation Gaps.** When a refresh token rotation scheme invalidates the consumed refresh token but not the access tokens previously derived from it, all access tokens from the compromised family remain valid. The blast radius equals the number of un-expired access tokens derived from the compromised refresh token multiplied by their remaining lifetime.

**Blocklist Storage Exhaustion.** A blocklist that stores every revoked `jti` without TTL-based eviction grows unbounded. An attacker who can trigger mass logout (CSRF on logout, admin-level session-clear) inflates the blocklist until the storage backend degrades — a DoS on the revocation infrastructure that may cause the verifier to fail-open (accept all tokens when the blocklist is unreachable).

## Second-Order Token Confusion

A JWT written to persistent storage (database, cache, cookie) is later consumed by code that trusts it without re-verification. Second-order attacks turn storage into forgery.

**Admin-Impersonation via Stored Token.** An admin feature stores a JWT representing the admin's identity for later use in a background job. The storage path is write-reachable by lower-privilege users (SQL injection, prototype pollution on the storage layer, direct object reference to a storage record). Rewriting the stored token to an attacker-controlled forgery grants admin privilege when the background job runs.

**Long-Lived Service Account Tokens.** CI/CD and service accounts receive long-lived JWTs stored in secret managers, config files, or environment variables. Any read primitive (SSRF to a metadata service, directory traversal to a config file, log scrape) grants the token. Combined with the token's lax `aud`, the attacker reaches arbitrary services. Load `information_disclosure.md` for the read-primitive discovery.

**Audit-Log-Stored Tokens.** Services that log the Authorization header for debugging grant durable token leaks. A log pipeline with world-readable retention, a log-aggregator with weak access control, or a log-ingestion path reachable by lower-privilege users converts logging into a credential-leak primitive.

**Replay Across Logout Boundaries.** JWTs have no server-side revocation unless the server tracks a blocklist. Logging out invalidates the session cookie but not the JWT; the attacker who captured the JWT before logout retains access until `exp`. Fingerprint by capturing a token, calling the logout endpoint, and replaying the token after; retained acceptance proves no server-side revocation.

**Message-Queue Replay.** Workers that process bearer-tokenized messages from a queue may skip verification if they trust the queue. A replay attack: capture a legitimate message with a bearer token, re-inject into the queue (if the queue is write-reachable), the worker processes with the captured token. Load `rce.md` and `vulnerabilities/mass_assignment.md` for queue-write primitives.

## Session-JWT Hybrid Attack Patterns

Applications that maintain both a server-side session and a JWT create a dual-authority surface. The two identity sources can disagree, and the weaker one determines the effective security.

**Session Overrides JWT.** The server reads the JWT for identity but falls back to the session cookie when the JWT is absent or invalid. An attacker who compromises the session (via session fixation, cookie theft, or CSRF) bypasses JWT verification entirely — the session provides authentication without any signature check. Fingerprint by removing the `Authorization` header and observing whether the session cookie alone grants access.

**JWT Overrides Session.** The reciprocal: the server reads the session for state but uses the JWT for identity. An attacker who forges a JWT (via any key-control primitive) overrides the session's identity without invalidating the session. The server's session middleware sees a valid session; the authorization layer reads the JWT's claims. Confirmation: establish a legitimate session, then replace only the JWT with a forged one carrying a different identity; the server processes the forged identity.

**Dual-Write Inconsistency.** Login writes both a session record and issues a JWT. If the session write succeeds but the JWT issuance fails (or vice versa), the two authorities diverge. An attacker who triggers a partial-write (via a race condition on the login endpoint, a transient database failure, or a deliberate timeout) creates an inconsistent state exploitable on subsequent requests. Load `race_conditions.md` for the race-condition primitive.

**Logout Invalidates One but Not Both.** Logout clears the session but not the JWT (or vice versa). The surviving authority grants continued access. Confirmation: log out, then present only the JWT (no session cookie); acceptance proves the JWT was not revoked. Reciprocal: log out, clear the JWT, present only the session cookie; acceptance proves the session was not destroyed.

**Privilege Escalation via Authority Mismatch.** The session stores `role=user`; the JWT carries `role=admin` (via forgery). If the authorization layer reads role from the JWT while the session provides the authentication context, the attacker elevates privilege without the admin session. The inverse also applies: a legitimate admin JWT with a user-level session, where the server reads role from the session, demotes the admin — a denial-of-service on administrative actions.

**Token Refresh Updates JWT but Not Session.** A refresh cycle issues a new JWT with updated claims (rotated scopes, new `exp`) but does not update the session record. Subsequent requests that read from the session see stale claims; the JWT and session disagree on the user's current authority. An attacker who captures a pre-refresh JWT and a post-refresh session cookie constructs a request with elevated stale-JWT claims accepted against the fresh session context.

**Cookie-Stored JWT Without Signature Re-Verification.** Some frameworks store the JWT in a cookie and verify it only on the first request (writing a "verified" flag into the session). Subsequent requests read the "verified" flag from the session and skip JWT re-verification. An attacker who replaces the cookie-stored JWT after the first verification injects a forged token that is never re-checked. Confirmation: authenticate normally, replace the JWT cookie with a forged token, issue a subsequent request; if the server processes the forged claims, re-verification is absent.

## JWT Downgrade (JWS ↔ JWE) at Verification

A verifier configured for JWS might silently accept a JWE (five parts, different attack surface); vice versa. The downgrade is a configuration-shape attack, not a cryptographic break.

**JWS Accepted at JWE Endpoint.** The endpoint expects an encrypted token and verifies decryption; a presenter supplies a JWS. Vulnerable libraries that fall back on parse-failure to JWS verification (because the first attempt threw) grant acceptance under JWS semantics. Downgraded from encrypted to signed, the token is now readable by any middlebox that logs it.

**JWE Accepted at JWS Endpoint.** The reciprocal: the endpoint expects a signed token; a presenter supplies a JWE. Libraries that silently accept the JWE's inner claims without verifying the JWE's AEAD tag grant forgery when the attacker controls the content-encryption key — chaining with `alg:"dir"` and a guessable CEK gives the full forgery primitive.

**Nested Downgrade Confusion.** A JWS whose payload is itself a JWE (`cty:"JWE"`); the outer JWS verifies with the outer key, the inner JWE decrypts with a weak key, and the inner plaintext becomes trusted claims. Attack: forge a JWE whose decryption produces attacker-chosen claims; wrap in a JWS signed by any key the server trusts (even a leaked old key or a key reachable via `jku` abuse); present to a server that accepts the shape.

**Content-Type Hint Downgrade.** `cty` as a header hint can downshift the verifier's expectation. `cty:"JWT"` on a top-level JWS instructs the verifier the payload is itself a JWT; a nested-verification bug (see § JWS Edge-Case Verification) then exploits.

## HS-Family Secret Discovery Depth

HS256/HS384/HS512 tokens are HMAC-signed; the secret is a shared symmetric value. Discovery is in-reach for weak secrets.

**Offline Brute Force.** `jwt_tool -C -d <wordlist>` and `hashcat -m 16500` run offline HMAC brute force against a captured token. 2^30 attempts/second is standard on consumer GPUs for HS256; weak secrets (dictionary words, short random, defaults like `secret`, `your-256-bit-secret`, `jwt-secret`) crack in minutes to hours. For longer-than-dictionary secrets, mask-mode (`hashcat -a 3`) or hybrid-wordlist-plus-mask runs cover extended spaces efficiently.

**Default Secret Reuse.** Tutorial-defaulted secrets persist in production. Common values: library documentation examples (`your-256-bit-secret`, `my-super-secret-key`, `jwt_secret`), tutorial repositories, CI-pipeline test values that leak into production configs. A wordlist derived from framework documentation hits a surprising fraction of production targets. Standard tooling: `jwt_tool` by ticarpi (GitHub) for automated secret-brute, `hashcat -m 16500` for offline cracking, `jwt-cracker` for dictionary attacks.

**Secret-via-Environment-Variable Leakage.** Services that read `JWT_SECRET` from the environment leak the secret to any process that can read `/proc/<pid>/environ`, to any crash dump that captures the environment, to any logging pipeline that records startup banners. The leak is secondary to the service compromise but durable.

**Secret-via-Backup-File Leakage.** `.env.bak`, `config.json.old`, a deployment-artifact tarball served at `/releases/app-v1.2.3.tar.gz`: all common sources. Load `information_disclosure.md` for the discovery primitive.

**Secret-Reuse Across Environments.** Dev / staging / prod sharing the same `JWT_SECRET` is a frequent mistake. A compromise of the dev environment (weaker protections, world-readable configs, developer workstations) yields the production secret. Confirmation: capture tokens from each environment and attempt cross-environment forgery.

**Secret-Derivation via a Known KDF.** Some deployments derive JWT secrets from a tenant ID, hostname, or deployment timestamp via a known KDF (HKDF, PBKDF2, custom hash chain). If the KDF is deterministic and the input is known, the secret is recoverable. Audit configuration documentation and infrastructure-as-code for derivation patterns.

## JWT Storage and Transport Security Depth

Where and how the JWT is stored on the client determines which theft primitives reach it. Each storage location has a distinct attack surface; the choice trades one exposure for another.

**localStorage.** Accessible to any JavaScript executing in the page's origin. A single XSS vulnerability (reflected, stored, DOM-based) exfiltrates the token via `window.localStorage.getItem('token')`. No CSRF risk (the token is not automatically sent by the browser), but full exposure to script-based theft. The XSS-to-token-theft chain is the most common JWT compromise path in SPAs. Load `xss.md` for the exfiltration primitive.

**sessionStorage.** Same-origin JavaScript access, scoped to the tab. Lower persistence than localStorage (cleared on tab close), but identical XSS exposure during the tab's lifetime. A reflected XSS that executes in a new tab reads sessionStorage from the victim's session if the victim navigates to the attacker's crafted URL within the same tab context.

**HttpOnly Cookie.** Not accessible to JavaScript; immune to XSS-based exfiltration. Automatically sent on every same-site request, creating CSRF exposure. The token rides with every request to the origin, including attacker-triggered cross-origin requests unless `SameSite` is set to `Strict` or `Lax`. Load `csrf.md` for the CSRF primitive on cookie-stored JWTs. A `SameSite=None; Secure` cookie is sent cross-origin on HTTPS — the token is exposed to any authenticated cross-origin request the attacker can trigger.

**Non-HttpOnly Cookie.** JavaScript-accessible and automatically sent. Combines the XSS exposure of localStorage with the CSRF exposure of cookies. The weakest storage option; any XSS or CSRF primitive reaches the token.

**In-Memory (JavaScript Variable).** Not persisted; survives only as long as the JavaScript runtime. Immune to persistent storage scraping but vulnerable to XSS during execution. The token is lost on page refresh, requiring re-authentication or a refresh-token flow. The XSS exfiltration window is bounded by the page's lifetime.

**Authorization Header vs Cookie Transport.** Tokens sent in the `Authorization` header are not subject to CSRF (the browser does not add custom headers to cross-origin requests without CORS preflight). Tokens in cookies are subject to CSRF but benefit from `HttpOnly` and `SameSite` protections. The choice trades XSS risk (header, stored client-side for injection) against CSRF risk (cookie, sent automatically). Neither is universally safer; the finding depends on which other vulnerabilities the target has.

**Token in URL Query Parameter.** Tokens in `?token=<jwt>` are logged by proxies, stored in browser history, cached by CDNs, leaked in `Referer` headers, and visible in server access logs. Any log-reading primitive (`information_disclosure.md`) or cache-reading primitive yields the token. The transport is the leak — no additional vulnerability required.

**Token in `Sec-WebSocket-Protocol` Header.** A WebSocket-specific transport that embeds the JWT in the protocol negotiation header. The token appears in server logs of the WebSocket handshake, in proxy logs, and in browser developer tools. Load § JWT in Non-HTTP Protocols for the verification-side issues; the transport-side issue is log exposure.

**Token Binding (RFC 8471).** Token binding cryptographically ties the token to the TLS connection's key material, preventing replay on a different connection. Adoption is minimal; most deployments lack it. When absent, any token captured from any transport layer is replayable on any other connection to the same server. DPoP (§ DPoP / mTLS / Sender-Constrained Token Bypass) is the successor pattern; its enforcement gaps are covered there.

**Dual-Token Pattern Security.** A common SPA architecture stores a short-lived access token in memory and a long-lived refresh token in an HttpOnly cookie. The access token is XSS-exposed but short-lived; the refresh token is XSS-protected but CSRF-exposed. An attacker with a CSRF primitive triggers a refresh request (the HttpOnly cookie rides along), captures the new access token from the response (if the response is readable cross-origin via a CORS misconfiguration), and obtains a fresh access token without XSS. The chain requires CSRF plus CORS misconfiguration; load `csrf.md` and `browser_security.md` for the primitives.

## JWT in Non-HTTP Protocols

JWT verification across non-HTTP transports is often less-hardened than the HTTP-adjacent path.

**gRPC.** JWT authentication in gRPC flows via the `authorization` metadata entry. gRPC implementations vary: Go's `grpc-auth` typically verifies with the HTTP library's JWT handler; Python's `grpc_interceptor` may use a custom verifier. The verification path on gRPC may use a different library than the HTTP side, exposing primitives the HTTP side has patched (version-drift between protocols).

**WebSocket.** JWT in the `Sec-WebSocket-Protocol` header during the WebSocket handshake, or in the first message after connection. Verifiers that check the handshake JWT but trust subsequent messages grant primitives on long-lived connections: capture the JWT at handshake, inject messages that reference a different user identity, the server reads from a session that was established with the original JWT. Load `vulnerabilities/csrf_advanced_deep.md § CSWSH Against Hardened Targets` for the WebSocket-specific vector.

**SSE (Server-Sent Events).** JWT in a query parameter on the SSE endpoint. Verifiers that log the full URL leak the JWT to log pipelines; verifiers that cache responses by URL cache the authenticated response for an attacker who presents the same URL.

**GraphQL.** JWT in the `authorization` header or as a GraphQL variable. GraphQL schema introspection may reveal auth-adjacent fields and claim-related arguments; combine with field-level authorization checks that trust token claims directly (load `broken_function_level_authorization.md`).

**Message Queues.** JWTs as message authentication artifacts. The queue consumer may skip verification if it trusts the queue; the queue's write surface is the attack entry (see § Second-Order Token Confusion).

## JWT in Service Mesh and Zero-Trust Networks

Service meshes (Istio, Linkerd, Consul Connect) and zero-trust frameworks (SPIFFE/SPIRE, OPA) use JWTs for workload identity. The verification path differs from HTTP-middleware JWT handling.

**Istio Request Authentication.** `RequestAuthentication` CRDs configure JWT policy per workload. The common bug: `issuer` + `jwksUri` set but no `audiences` list — the mesh accepts any token signed by the issuer, regardless of audience. Combined with a shared issuer across environments (dev / staging / prod), a dev-issued token reaches production workloads. Fingerprint by inspecting the applied CRDs via `kubectl get requestauthentication -o yaml`.

**Linkerd Policy.** Linkerd uses `AuthorizationPolicy` referencing `MeshTLSAuthentication` or `NetworkAuthentication`. JWT verification is less-mature than Istio's but has an identity-federation path via SPIFFE SVIDs — a JWT-SVID is a JWT whose claims include the SPIFFE identity. Bypass: forge a JWT-SVID with any SPIFFE identity if the signing key is shared or if the issuer trust is loose.

**SPIFFE/SPIRE JWT-SVID.** SPIFFE JWT-SVIDs are JWTs with specific claim shape (`sub` as SPIFFE ID, `aud` as the audience). SPIRE's agent fetches and caches SVIDs; a cache poisoning or MitM at agent-to-server grants cross-workload impersonation. Compose with cluster-level attacks for the primitive.

**Kubernetes Service Account Tokens.** K8s service accounts generate JWTs that pods present to the API server. The projected volume feature (BoundServiceAccountToken) rotates these; vulnerable deployments use legacy long-lived tokens stored on-disk. Chain: pod compromise → read token from `/var/run/secrets/kubernetes.io/serviceaccount/token` → present to the API server with the pod's identity. The RFC 9700 shift toward short-lived tokens closes this gap but transition deployments remain exposed.

**EKS IRSA (IAM Roles for Service Accounts).** AWS EKS projects an OIDC-federated JWT into pods; the pod exchanges it for IAM credentials. A pod compromise reaches the JWT; the JWT is also presented to AWS STS, which validates the OIDC trust. If the pod's role has broad permissions, the chain is full AWS-side compromise. Load `aws` or `vulnerabilities/mass_assignment.md` for the IAM-adjacent primitives.

**GCP Workload Identity.** GCP's workload identity uses GCP-STS JWTs with specific audience values. Mis-scoped audience: a JWT issued for Workload-A is accepted by Workload-B if Workload-B's audience check is loose. Common misconfiguration: Workload-Identity-Federation with a shared audience across projects.

**Confirmation.** For each mesh / zero-trust framework, the confirmation is cross-workload presentation: capture a JWT from one workload, present at another, measure acceptance. The attack signal is any acceptance that policy should have blocked.

## JWT Token Relay and Propagation in Microservices

Microservice architectures propagate JWTs across service boundaries. The relay patterns create trust-boundary crossings that monolithic designs do not have.

**Passthrough Relay Without Re-Verification.** Service-A receives a user's JWT, then forwards it verbatim to Service-B in an internal request. Service-B trusts the token because Service-A "already verified it." If Service-A's verification is weaker (different algorithm acceptance, lax `aud` check, no `exp` enforcement), the token reaches Service-B with a trust level Service-B did not independently establish. Confirmation: compromise the verification path at Service-A (via any of the primitives in this file); the forged token propagates to Service-B without further challenge.

**Token Translation Without Scope Narrowing.** An API gateway verifies the user's JWT and issues an internal token for downstream services. If the internal token carries the same or broader scopes than the user's original token, the translation adds no security — it is a passthrough in disguise. The attack: forge or steal the internal token (which may have weaker signing, shorter key, or no `aud` restriction) and present it directly to downstream services, bypassing the gateway.

**Fan-Out Amplification.** A single user request triggers downstream calls to N services, each receiving the same JWT. If one of the N services is compromised, the attacker captures the JWT and replays it against the other N-1 services. The blast radius of a single service compromise equals the union of all services that accept the token. Fingerprint by tracing the JWT's propagation path through distributed tracing headers (`X-Request-Id`, `traceparent`) and mapping every service that receives it.

**Token Lifetime Mismatch Across Services.** The user-facing service issues a JWT with `exp` in 5 minutes. An internal service caches the token for 30 minutes to avoid re-verification overhead. The cached token is valid at the internal service for 25 minutes past its intended expiration. An attacker who captures the token in the caching window replays it against the internal service long after the user-facing service would reject it.

**Internal Service Tokens with No Audience Restriction.** Internal services that mint their own JWTs for inter-service calls often omit the `aud` claim (there is "only one audience — us"). Any service in the mesh that accepts unsigned-audience tokens accepts any other service's token. The attack: compromise Service-A, mint a token, present to Service-B through Service-N. Load § Cross-Service aud / typ Confusion for the claim-level depth; this section owns the relay-topology amplification.

**Sidecar Proxy Trust Assumptions.** Service-mesh sidecars (Envoy, Linkerd-proxy) terminate mTLS and may strip or add headers before the request reaches the application container. If the sidecar strips the `Authorization` header after verification and injects identity claims as plain headers (`X-Verified-User`, `X-JWT-Sub`), the application trusts those headers. An attacker who reaches the application container directly (container escape, misconfigured network policy, sidecar bypass via localhost) injects arbitrary identity headers. Load `header_injection.md` for the general class; the chain here is sidecar-bypass to identity-injection.

**Service-to-Service mTLS with JWT Double-Auth.** Some architectures require both mTLS (service identity) and a JWT (user identity) on every inter-service call. If only one is enforced, the other is bypassable: a service with valid mTLS credentials but no JWT reaches endpoints that check mTLS only; a request with a valid JWT but no mTLS reaches endpoints that check JWT only. The weakest enforcement path determines the actual security boundary.

**Confirmation.** Map the token relay topology by tracing a single request end-to-end. At each service boundary, observe: does the service re-verify the token signature, or does it trust upstream verification? Does it narrow `aud`/`scope` before forwarding, or pass through verbatim? Does it enforce `exp` independently, or inherit upstream's cached validity? Each "trust upstream" answer is a relay amplification point where a single upstream compromise propagates trust transitively.

## JWT in Serverless and Edge-Compute Environments

Serverless auth often uses JWT-based authorizers (Lambda authorizers, Cloudflare Workers JWT, Vercel middleware auth). The verification path is single-tenant and often reuses library-level patterns from the HTTP side.

**API Gateway JWT Authorizer.** AWS API Gateway's JWT authorizer validates issuer, audience, and signature; the configured issuer determines which JWKS is fetched. Misconfig: wildcard audience accepts any `aud`; shared issuer across stages accepts dev tokens in prod. The authorizer's cache (default 5 minutes) means a token revocation takes up to 5 minutes to propagate — a window for stale-token replay.

**Lambda Authorizer.** Custom-code authorizers run attacker-adjacent JavaScript / Python. The caller-side bugs apply: pinning the wrong algorithm, trusting header-sourced keys, caching too aggressively. Fingerprint by probing the authorizer error responses — a Lambda authorizer typically returns a specific response format.

**Cloudflare Workers JWT.** Cloudflare's Workers use `@tsndr/cloudflare-worker-jwt` or similar lightweight libraries. The libraries often lack the full defense-in-depth of mature server-side libraries — algorithm-pinning may be looser; alg:none may be accepted on caller opt-in. Audit the specific library the Worker imports.

**Vercel Middleware JWT.** Vercel's middleware runs at the edge; JWT verification may use `jose` (panva/jose) or a Vercel-provided helper. The common misconfig is reading JWT from a cookie and trusting it for authorization without re-verifying on each route — a middleware-sets-session shape that elides the token's own validation on subsequent requests.

**Deno Deploy / Bun / Edge-Runtimes.** Deno's std/jose and Bun's bundled JWT handling have their own defense budgets, generally close to Node's but with occasional lag on CVEs that have been patched upstream. Fingerprint the runtime by the error-string style and dependency manifest.

**Edge Cache Interactions.** Serverless / edge environments cache responses aggressively. A cache keyed on URL (not on Authorization) serves a cached authenticated response to any attacker who requests the same URL. Load `http_request_smuggling.md § Cache Poisoning` for the primitive.

## JWT in Container-Runtime and Platform-as-a-Service Environments

Container runtimes expose service-account-adjacent JWTs. Platform-as-a-service environments embed JWT-based auth in deployment pipelines.

**Docker Secrets.** Secrets mounted into containers via Docker Swarm or Compose are read from a tmpfs; a container breakout reads the secrets. Combined with a JWT secret stored this way, the chain is secret-leak → forgery.

**Kubernetes Secrets vs Projected Volumes.** Secrets stored as K8s `Secret` objects are mounted into pods as files or env vars. A pod with excessive privileges reads sibling pods' secrets via the Kubernetes API; the chain is pod-escape or elevated-privilege → secret-read → JWT forgery.

**OpenShift Service Account Tokens.** OpenShift adds additional CA validation and token binding; the exposure surface is narrower but still present for mis-scoped tokens.

**Cloud Run / App Runner / Fargate.** Each embeds JWT-based identity federation (GCP metadata token, AWS task role credentials). The metadata-service SSRF primitive (`169.254.169.254`) grants token-fetch; load `ssrf.md` for the primitive and `cloud/aws.md` or `cloud/gcp.md` for the specific endpoint.

## SAML-to-JWT and Bridge-Protocol Confusion

Federation deployments bridge SAML and JWT: a SAML assertion from an IdP is converted to a JWT for internal use. The bridge is itself an attack surface.

**SAML Signature-Wrapping (XSW) → JWT Trust Chain.** XSW attacks on the SAML assertion grant acceptance of an attacker-chosen `NameID`. The bridge converts to JWT; the JWT trusts the bridge's identity assertion. Chain: XSW on SAML (load `xxe.md` or SAML-specific coverage) → bridge accepts → JWT with elevated identity.

**Protocol-Downgrade via Bridge.** The bridge may support both SAML and JWT auth paths; a client that presents a JWT bypasses the SAML path's stricter checks. If the JWT-only path has lax validation (common when it's a "modern" add-on to a SAML-first deployment), the attack is: skip SAML, present forged JWT.

**Assertion-Lifetime Mismatch.** SAML assertions have `NotBefore` / `NotOnOrAfter` enforced strictly; the bridged JWT may have longer `exp`. The attacker captures a JWT derived from a legitimate SAML assertion, replays after the SAML would have expired.

**Attribute Mapping Confusion.** The bridge maps SAML attributes to JWT claims. A SAML attribute with multiple values maps to a JWT claim as an array; a JWT verifier that reads the first value only (not the whole array) can be bypassed by an attacker who includes a benign first value and a malicious second value.

**Trust Store Confusion.** SAML trust is per-IdP; JWT trust is per-signing-key. A bridge that doesn't re-check the IdP origin before issuing the JWT grants cross-IdP primitives — a less-trusted IdP's SAML assertion grants an equivalent JWT.

## JWT in GraphQL and WebSocket Hardened Paths

Non-REST APIs have JWT handling specific to their protocol.

**GraphQL Field-Level Auth Trusting JWT Claims.** A resolver reads `context.user.role` from the verified JWT and makes authorization decisions. If the JWT's `role` is attacker-controlled (via one of the primitives), each resolver that trusts it is a privilege-escalation vector. Fingerprint by introspection: look for `@auth(requires: ADMIN)` directives.

**GraphQL Subscriptions and JWT Refresh.** Subscriptions over WebSocket persist across token expiration. If the subscription establishes with a valid token but doesn't re-check on each message, the connection stays authenticated past `exp`. Load `csrf_advanced_deep.md § CSWSH Against Hardened Targets` for the connection-persistence vector.

**GraphQL Batching and Per-Operation Auth.** Batched queries may share one JWT verification across all operations in the batch; a per-operation permission check that trusts the batch-level JWT is bypassable by including a privileged operation in a batch intended for an unprivileged user.

**WebSocket Reconnect and Token Refresh.** Reconnects reuse the original JWT often; if the server doesn't require a fresh JWT on reconnect, the attacker captures the original JWT and reconnects with it indefinitely.

## WAF Bypass for JWT-Containing Requests

WAFs inspect requests for malicious patterns; JWT-containing requests are often inspected less-deeply.

**JWT in Authorization Header.** WAFs may skip inspection of `Authorization` header values beyond a prefix match on `Bearer`. Payloads smuggled inside the JWT (as a claim value) reach the application unfiltered.

**JWT in Cookie.** Cookies with JWT values pass through WAF filters that key on body content. The attack: encode SQL injection or XSS inside a JWT claim; the WAF inspects the raw bytes and sees base64url noise, not SQL keywords. The application decodes and processes.

**JWT Oversize to Bypass Rate Limiting.** Some rate limiters apply differently to large payloads. An oversized JWT (gigabyte-scale, with padding) may evade a size-aware rate limit; combined with a verifier that doesn't impose size caps, this is a DoS primitive.

**JWT in Non-Standard Locations.** JWTs in `X-Access-Token`, `X-Auth-Token`, custom header values, query-string parameters (`?jwt=`), POST body fields (`access_token=`). Each is a different WAF-handling path; the weakest-inspected path is the attack entry.

**JWT with Nested Encoding.** URL-encode or double-URL-encode the JWT inside a query parameter; the WAF decodes once and inspects, but the application decodes twice and gets the real token. Load `http_request_smuggling.md § Parser-Differential Smuggling` for the broader class.

## Framework-Specific JWT Middleware Depth

Each middleware has a configuration surface where a wrong default is the finding.

**Spring Security's `JwtAuthenticationProvider`.** The default `JwtDecoder` requires an explicit `algorithms` set in `NimbusJwtDecoder.withPublicKey(...).signatureAlgorithm(SignatureAlgorithm.RS256)`; configurations that use `.withJwkSetUri(...)` without pinning algorithms accept any signed token from the JWKS. The `kid` is resolved from the JWKS set; `jku`/`x5u` are not honored by default (good). Weakness: a custom `JwtDecoder` that reads header `jwk`/`jku` for key resolution reopens the base-file primitives.

**express-jwt (Node).** Pre-6.0.0 defaulted to `algorithms:['HS256','RS256',...]` — a token signed under any of the listed algorithms verified. Post-6.0.0 requires an explicit `algorithms` option; omitting it throws. Deployments that port 5.x configs to 6.x and silently accept the throw via a try/catch misconfigure.

**Flask-JWT-Extended (Python).** `JWT_ALGORITHM` config variable pins the algorithm; `JWT_ALGORITHMS` is a list of acceptable algorithms for decode. Deployments that leave `JWT_ALGORITHM='HS256'` and set `JWT_PUBLIC_KEY` for RS verification without updating `JWT_ALGORITHMS` accept both HS-signed-under-the-public-key tokens and RS-signed tokens — the RS→HS confusion primitive via config mistake.

**golang-jwt / jwt-go.** `jwt.Parse(tokenString, keyFunc)` passes the parsed token to `keyFunc` so the caller can return the right key for the token's `kid`/`alg`. Caller-side bugs: `keyFunc` returns the configured RSA public key regardless of `token.Header["alg"]` → RS→HS confusion on an attacker-signed HS token. The library's own `token.Method` field reports the method used for verification; checking it in `keyFunc` is the mitigation; omitting the check is the bug. Load `vulnerabilities/rce.md § Go` for the broader Go JWT ecosystem issues (Rails-adjacent variants in Hugo and gitea).

**ASP.NET Core `JwtBearerAuthentication`.** `TokenValidationParameters.ValidAlgorithms` is an opt-in — if unset, every algorithm the library supports is accepted. The historical bug (the .NET-port analogue of the classic jsonwebtoken RS→HS confusion class): `ValidateIssuerSigningKey=true` with `IssuerSigningKey` set to the server's RSA public key, and `ValidAlgorithms` unset, accepts HS-signed tokens signed with the public-key bytes. Current mitigation: `ValidAlgorithms = new[] {"RS256"}` explicitly.

**Nest.js Passport `JwtStrategy`.** `secretOrKey` provides a static key; `secretOrKeyProvider` is a per-token key resolver. The resolver pattern: parse the token header, fetch the right key by `kid`, pass to the strategy. Bugs in the resolver — fetching from an attacker-controlled JWKS, returning the configured server key for any `kid`, caching a stale JWKS — reopen the base-file primitives.

**Rails `Devise::JWT`.** Uses the `jwt` gem under the hood. `Devise::JWT.config.algorithm = 'HS256'` pins the algorithm; defaults are `HS256`. Weakness: deployments that rotate to RS256 without updating the algorithm config or re-verifying the key handling leave both paths open.

**FastAPI with python-jose.** FastAPI's dependency-injection auth flow typically uses python-jose. The caller passes `algorithms=["HS256"]` or similar; CVE-2024-33663 and CVE-2026-85394 (see novel sibling) apply directly. Fingerprint FastAPI by the `/openapi.json` endpoint and the error-string style; FastAPI projects documented with python-jose in the auth tutorial are near-ubiquitous.

**Framework-Pattern Fingerprint.** The common thread across every middleware: the key material and the algorithm set must be bound at configuration time, not derived from the token. Any middleware whose configuration permits "derive algorithm from token header" is one bug away from an RS→HS confusion.

## Introspection and Discovery Endpoint Abuse

RFC 7662's introspection endpoint and OIDC's discovery endpoint are themselves attack surfaces, though less-often-tested.

**Introspection-Response Trust.** `/introspect` returns `{active:true, scope:"...", sub:"..."}` for a valid token. A caller that trusts the response fields without re-verifying the token's own signature accepts a response from an attacker-impersonated introspection endpoint. If the caller is reachable via DNS rebinding or network-position bugs, the introspection URL can be spoofed.

**Introspection Response Caching.** Caches that key on token-prefix (not full token) grant collision primitives: two different tokens with the same prefix share a cached response; the longer token's response is served for a shorter attacker-chosen one.

**Discovery Metadata Poisoning.** `/.well-known/openid-configuration` is often cached by clients. If the client's cache is poisonable (via DNS rebinding, cache-poisoning upstream, or MitM at first-fetch), subsequent fetches use the poisoned metadata — pointing at an attacker's `authorization_endpoint`, `token_endpoint`, or `jwks_uri`. Load `http_request_smuggling.md § Cache Poisoning` for the primitive.

**Metadata URL Scheme Variants.** Clients that resolve metadata URLs via `urllib`/`requests` and permit `file://` schemes can be redirected to local files for discovery; the attack is adjacent to CVE-2026-48522 but on the metadata path.

## Automated JWT Audit Methodology

Systematic JWT testing follows a fingerprint-then-fuzz pattern that covers the full attack surface before committing to exploitation.

**Phase 1: Fingerprint.** Capture a legitimate token and decode the header and payload (no key needed — base64url decode). Record: `alg`, `kid`, `typ`, `jku`, `x5u`, `jwk`, `cty`, and any non-standard header parameters. Record payload claims: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, custom claims. The header determines which verification-bypass classes are in scope; the claims determine which confusion classes are in scope.

**Phase 2: JWKS Discovery.** Fetch `/.well-known/jwks.json`, `/.well-known/openid-configuration` (for `jwks_uri`), and any URL in the `jku`/`x5u` headers. Enumerate the key set: `kid` values, key types (`kty`), algorithms, key sizes. A mixed-key-type JWKS (RSA and HMAC, RSA and EC) is a strong signal for key-confusion primitives. A JWKS with retired keys (keys not matching any current token's `kid`) signals grace-period acceptance.

**Phase 3: Algorithm Manipulation.** Test each algorithm-bypass class in order of impact: `alg:none` (three-part token, empty signature), RS-to-HS confusion (sign with the RSA public key as HMAC secret), `jwk` inline injection (embed attacker's public key), `jku`/`x5u` injection (point to attacker-hosted JWKS). Use `jwt_tool` with `-X a` (alg:none), `-X k` (key confusion), `-X i` (inline jwk), `-X s` (jku spoof). Each test produces a forged token; present each to the target and record acceptance or rejection.

**Phase 4: Claim Manipulation.** With a working forgery primitive (or with a captured legitimate token if no forgery is available), test claim-level confusion: swap `aud` values between services, change `sub` to another user, elevate `role`/`scope` claims, alter `tenant_id` in multi-tenant deployments. Each manipulation targets a different authorization check; the acceptance pattern maps the enforcement surface.

**Phase 5: Key Discovery.** For HMAC-signed tokens, run offline brute force: `hashcat -m 16500 <token> <wordlist>` or `jwt_tool -C -d <wordlist>`. Start with framework-documentation default secrets, then common password lists, then mask-mode for short random secrets. For RSA/EC tokens, enumerate public-key availability: JWKS endpoints, TLS certificates, GitHub repositories, configuration files.

**Phase 6: Protocol-Level Testing.** If the target uses OIDC: test mix-up (multi-IdP), PKCE bypass (plain challenge, missing verifier), token exchange (scope widening, audience escalation), and response-mode abuse (web_message, form_post). If the target uses DPoP: test proof-not-validated, thumbprint-not-matched, nonce-not-rotated. If the target uses refresh tokens: test rotation detection, reuse detection, family invalidation.

**Phase 7: Composite Chain Assembly.** Combine discovered primitives from phases 3-6 with capabilities from sibling skills: SSRF for JWKS fetch, XSS for token theft, IDOR for impersonation-endpoint abuse, open redirect for OAuth code interception. The composite chain section (§ Composite Chain Depth) provides the routing map; the audit methodology here identifies which primitives are live before assembly.

## Confirmation Methodology — JWT-Specific

Confirmation discipline for JWT distinguishes "the server accepted the token" from "the server verified the signature." Four signals matter.

**Positive-Control Token.** A token issued by the server itself, captured by an authenticated session. The baseline for "the server accepts a correctly-formed token for this user."

**Negative-Control Token.** A token with a random signature (same length as expected). If the server accepts, signature verification is skipped entirely; the primitive is "no verification," which is the strongest finding and admits the simplest forgery.

**Alg-Confusion-Control Token.** The forged token under the specific primitive you're testing (RS→HS, alg:none, kid injection, etc.). Acceptance proves the specific class.

**Downstream-Behavior Control.** Does the authorization-dependent response reflect the forged claims? A token with `role:admin` must grant admin-only responses; acceptance of the token without the admin response proves the token was accepted but ignored (common in token-is-accepted-but-session-is-the-real-source designs). The finding is still real — "signature verification bypassable" — but the impact is bounded.

**Confirmation of Algorithm Enforcement.** Issue two tokens with the same payload: one correctly signed under the configured algorithm, one under `alg:"none"`. The server's acceptance pattern reveals the enforcement: both accepted → no enforcement; only correctly-signed accepted → enforcement is live. Repeat with HS/RS swaps for the complete matrix.

## Blind Signature-Oracle Confirmation

When the server returns a uniform "unauthorized" response regardless of the specific failure, blind confirmation is required.

**Timing Side-Channel.** Signature verification has algorithm-dependent timing. HMAC comparison in constant-time libraries is uniform; comparison in non-constant-time libraries leaks bytes. For RS verification, RSA signature verification has a timing floor; alg:none has none. The acceptance/rejection decision happens *after* signature verification; measurable response-time differentials by algorithm class reveal which path the server took.

**Error-Message Byte Count.** Even a "generic" error page may differ by a few bytes based on the specific failure. Capture responses to each failure class and compare byte-exact.

**Secondary-Effect Confirmation.** A rejected token should not advance any counter (rate limit, failed-login counter, audit log entry). An accepted-then-ignored token might advance a session-start counter. Observe secondary effects to discriminate.

**OOB Confirmation via Logging.** If the server logs rejected JWTs with the token prefix (common for audit), a known-prefix token with a unique marker lets the attacker check whether a corresponding log entry appeared via a log-reading primitive. The attack chains with `information_disclosure.md`.

**Oracle Confirmation via Rate-Limit Behavior.** A rate limiter that advances on verification-failure (not on parse-failure) is itself an oracle: present malformed tokens, measure which prefix lengths trigger the rate limit (parse succeeds, verification runs, fails) vs which don't (parse fails, verification never runs). The transition point locates the parse boundary.

## Composite Chain Depth

Composite JWT chains compose the primitives above with capabilities from sibling skills, framed as capability-transferred.

**Chain: SSRF → Private JWKS → Cross-Service Forgery.** Upstream capability: SSRF reaches internal network addresses — `ssrf.md` for the primitive, `ssrf_advanced_deep.md § Internal Service Enumeration` for the depth. Transition: a private JWKS endpoint on an internal address returns the keys the internal service uses to verify its own tokens. Downstream capability: sign tokens with the private keys; present at the internal service with any `aud` the service accepts. Routing: `ssrf.md` → this file § JWKS SSRF Chain Construction → this file § Cross-Service aud / typ Confusion.

**Chain: Host-Header Poisoning → OIDC redirect_uri → Code Capture.** Upstream: `header_injection.md § Host Header Primitive`. Transition: the OIDC authorization endpoint builds `redirect_uri` responses using the poisoned `Host`; the authorization-response URL points at the attacker's host. Downstream: capture the `code`; exchange at the token endpoint (if the attacker is also the client, or via a mix-up — `this file § OIDC Mix-Up`); forge the session.

**Chain: XSS → Token Theft → Cross-Service Replay.** Upstream: `xss.md § DOM Sink Catalog` for the client-side exfiltration primitive. Transition: steal the JWT from `localStorage` / cookie / in-flight fetch. Downstream: present at each service in the microservice fabric; the lax `aud` acceptance pattern (`this file § Cross-Service aud / typ Confusion`) determines the blast radius.

**Chain: IDOR on Impersonation Endpoint → Token Mint.** Upstream: `idor.md` for the primitive on an admin impersonation endpoint. Transition: the impersonation endpoint accepts an arbitrary `user_id` under the admin session's authority and mints a JWT for that user. Downstream: full account access for the targeted user without the user's credentials.

**Chain: Prototype Pollution → kid-Lookup Bypass → Forgery.** Upstream: `prototype_pollution.md` for the primitive against a Node service. Transition: pollute `Object.prototype.kid` or the key-lookup cache object so the resolver returns a known key regardless of the real `kid`. Downstream: sign under the known key; present with any `kid`; verifier returns the polluted key; verification succeeds. The chain crosses framework boundaries; the detection surface is the JWKS-lookup object graph.

**Chain: Request Smuggling → Session-Splice → JWT Swap.** Upstream: `http_request_smuggling.md § Session Splice`. Transition: the smuggled request lands on the back of a legitimate connection carrying the victim's Authorization header; the back-of-queue request's response goes to the victim. Downstream: inject an attacker-issued JWT into the victim's session via a `Set-Cookie` the victim's browser accepts. The chain requires the specific smuggling-plus-cookie-injection construction; load the smuggling skill for the primitive.

**Chain: Open Redirect → OAuth Code Interception → Token Issuance.** Upstream: `open_redirect.md § OAuth/OIDC` + `open_redirect_advanced_deep.md § OAuth redirect_uri Chain`. Transition: the open redirect on the registered `redirect_uri` host sends the authorization code to attacker.tld. Downstream: redeem the code at the token endpoint (if the attacker is or impersonates the client); access the account.

**Chain: Discovery Metadata Poisoning → Rotated Issuer → Full Forgery.** Upstream: discovery-endpoint cache poisoning (this file § Introspection and Discovery Endpoint Abuse). Transition: the client caches the poisoned metadata and resolves to an attacker-hosted authorization server. Downstream: the attacker's authorization server issues tokens for any user; the client trusts them. The chain is low-bandwidth but durable.

**Chain: GraphQL Field-Level Auth → JWT Claim Trust → Horizontal Escalation.** Upstream: `broken_function_level_authorization.md § GraphQL Function-Level Authz`. Transition: a GraphQL mutation modifies the caller's JWT-claim fields in a session store without re-verifying the JWT. Downstream: the modified session grants elevated claims that would not survive JWT re-verification.

## Post-Fix Adjacent-Bug Prediction

When a verifier patches one primitive, the adjacent bug is usually one of three shapes.

**Blocklist Patch Leaves Siblings.** A library that patches `alg:"none"` by blocklisting the literal string "none" might still accept `"None"`, `"nONE"`, `"none"` (unicode-equivalent), or a null byte-containing variant. The CVE-2026-85394 python-jose DER-public-key HMAC bypass is this pattern on the key-shape side — the CVE-2022-29217 fix blocklisted PEM-encoded public keys; the DER encoding bypassed the blocklist. The adjacent-bug prediction after any blocklist patch is a sibling encoding of the forbidden input.

**Fix on One Code Path, Not All Code Paths.** A library might fix the `PyJWK` path but leave a legacy `jwk.construct` path intact; a framework might fix one middleware entry but not the strategy variant another entry uses. The CVE-2026-48523 PyJWK-path algorithm-binding bug fits this shape: the fix added the algorithm-vs-header check on the PyJWK code path; whether other key-construction paths are checked is the hunt lead for the next advisory.

**Regression Reintroduction.** A refactor that drops a defensive measure (shallow-copy, immutability guard, explicit comparison) reintroduces a previously-fixed bug. CVE-2026-103001 is this pattern: a 2025 refactor dropped the 2022-era shallow-copy fix of `_merge_options`, reintroducing the dict-mutation primitive. The adjacent-bug prediction after any post-refactor advisory is "what else did the refactor drop?" — read the diff of the refactor, not just the diff of the fix.

**Type-System Fix Leaving Dynamic-Dispatch Path.** When a fix is implemented at the compile-time type-check layer (Rust `Validation`, Go typed parameter), dynamic-dispatch paths (reflection, duck-typing in Python, `interface{}` in Go) may bypass. Hunt lead: audit the code paths that take the type-untyped version of the fixed input.

## False Positives — Advanced

Four classes of acceptance that look like a bug but are not.

**Signature Verified, Claim Ignored.** The server accepts a token with an elevated claim, but the authorization decision reads from a session store rather than the claim. The forged token is accepted but ineffective; the finding is "signature verification was bypassable" (real, bounded impact) rather than "privilege escalation."

**Mock / Development Verifier.** A dev-mode verifier accepts any signature when `NODE_ENV !== 'production'`. The finding is "verifier is in dev mode in production" (configuration bug) rather than a library bug.

**Token Accepted, Response Censored.** The server verifies and processes the token but masks the actual user data in the response (e.g., all admin responses redacted at a middleware layer). The forged token worked but the data was not exposed; the finding is the acceptance, bounded by the response-mask.

**Error Shape Looks Like Acceptance.** A 200 OK with an error payload (`{"error":"invalid_token"}`) is a rejection in disguise; a 401 with an informative body (`{"user":"admin"}`) might be a legitimate authentication-challenge response, not a successful auth. Read the actual response, not the status code.

**Rate-Limit Rejection vs Signature Rejection.** A server that rate-limits before verification returns the same 401 as a signature-failure. Discriminate by varying only the signature (not the claims) and watching for differential response: a rate limiter returns the same error for both correctly-signed and incorrectly-signed; a signature-check returns differently.

## Validation Depth

Forged-token validation requires more than "server didn't reject." Four control pairs establish the finding beyond doubt.

**Owner vs Non-Owner.** Issue two tokens: one for the attacker's own account, one forged for a victim. Both must be verifiable in exactly the same way (same endpoint, same curl invocation, same response shape); the only difference is the token. If both succeed and the responses differ in a user-identifying way (attacker's data vs victim's data), the forgery is live.

**Pre-Fix vs Post-Fix.** On a target with a known deployed fix, verify the forged token is rejected; on a target lacking the fix, verify it is accepted. The pair establishes that the specific library version is the determinant.

**Signed-vs-Unsigned.** Issue the same payload under a correct signature and under `alg:"none"`. If both are accepted the server does not verify; if only correctly-signed is accepted, the signature path is live.

**Authorization-vs-Authentication.** A token that authenticates (identifies the user) but fails to authorize (doesn't grant the action) produces a different response than one that fails to authenticate. Distinguish the layers by observing which response you got.

**Replay-Protection Validation.** Issue the same token twice; if both succeed, no replay protection; if the second fails, replay protection is live (JTI tracking, nonce-binding, DPoP replay cache). The pair is informative for scoping impact — a replay-protected target has bounded forgery-reuse.

## JWT Temporal Claim Manipulation

Temporal claims (`exp`, `nbf`, `iat`) control the token's validity window. Each is an attack surface when enforcement is weak or absent.

**Missing `exp` Enforcement.** Libraries that do not reject tokens without an `exp` claim accept tokens that never expire. The attacker forges a token with no `exp`; the library verifies the signature but imposes no lifetime bound. The token is valid forever. Fingerprint by omitting `exp` from a forged token; acceptance proves the library does not require it.

**Clock-Skew Exploitation.** Verifiers apply a clock-skew tolerance (typically 30-300 seconds) to accommodate clock drift between the issuer and verifier. The tolerance extends the token's effective lifetime in both directions: a token is accepted `skew` seconds before `nbf` and `skew` seconds after `exp`. An attacker who knows the tolerance value (often a framework default) extends the exploitation window of any captured token by twice the skew. Fingerprint by presenting tokens at precise second-boundaries past `exp` and measuring the acceptance cutoff.

**`nbf` Bypass on Libraries Without `nbf` Support.** `nbf` (not before) prevents early use of a token. Libraries that parse `nbf` but do not enforce it accept tokens before their intended validity start — the attacker presents a pre-issued token before the issuer's expected activation time, bypassing time-gated authorization (scheduled access, embargoed resources). Confirm by issuing a token with `nbf` set one hour in the future; acceptance proves the library ignores `nbf`.

**`iat` Without `exp` as a Pseudo-Lifetime.** Some deployments enforce token lifetime by computing `iat + max_age` rather than reading `exp`. If the verifier's `max_age` configuration is missing, the `iat`-based check degrades to no lifetime check. Alternatively, an attacker who forges a token sets `iat` to the current time on each use, resetting the computed lifetime indefinitely — a perpetual token via `iat` manipulation.

**Negative Temporal Values.** Temporal claims are unsigned integers (seconds since epoch). A negative value (`"exp":-1`) or zero (`"exp":0`) may be parsed as epoch-origin or as a sentinel by weakly-typed libraries. A library that treats `exp:0` as "no expiration" (sentinel) rather than "expired at epoch" (literal) grants infinite lifetime. Confirm by setting `exp` to `0` and observing acceptance.

**Time-Zone Confusion.** Temporal claims are UTC. A verifier that compares against local time in a non-UTC zone introduces a systematic skew. A server in UTC+8 accepts tokens 8 hours past their UTC `exp` when it reads `exp` as local time. The attack is passive — any captured token has a wider window — but the finding is a systemic enforcement gap.

**Temporal Claim Removal Attack.** Some libraries default to "no enforcement" when a temporal claim is absent. Removing `exp`, `nbf`, and `iat` from the payload produces a token with no temporal bounds. Combined with any forgery primitive, the token is valid indefinitely and from any time. Confirm by forging a token with all temporal claims removed; acceptance proves the library defaults to open.

**Leap-Second and Epoch-Overflow Edge Cases.** Systems that use 32-bit signed integers for epoch seconds overflow at 2038-01-19T03:14:07Z (the Y2038 problem). A token with `exp` set beyond 2^31-1 wraps negative on vulnerable systems, potentially granting infinite lifetime or causing a parse error that the verifier treats as "no expiration." Test by setting `exp` to `2147483648` (one past the 32-bit signed maximum) and observing whether the verifier rejects, wraps, or ignores.

**Confirmation.** The temporal-claim confirmation matrix: (1) token with `exp` removed — accepted or rejected? (2) token with `exp` set one second in the past — accepted or rejected? (3) token with `exp` set one second in the future — accepted or rejected? (4) same three with `nbf` replacing `exp`. The acceptance pattern reveals which temporal claims are enforced, which are honored with tolerance, and which are ignored. The tolerance delta between cases 2 and 3 reveals the clock-skew configuration.

## Summary

Advanced JWT depth is the operational tier where the headline primitives (RS→HS, alg:none, ECDSA all-zeros) have been patched out and the attack moves to key-source control (jku/x5u/jwk/kid), nested verification order (JWS-in-JWE, JWE-in-JWS, b64:false, crit), rotation and cache races, cross-service aud/typ confusion, multi-tenant shared-key reuse, and composition with capabilities from sibling skills. The common thread across every section is the same: *where the verifier's trust is derived from a part of the token the attacker controls, the attacker controls verification.* Confirmation discipline rules out false positives — accepted-but-ignored, dev-mode, masked-response, rate-limit-vs-signature — before any claim of forgery.
