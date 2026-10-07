---
name: cryptographic-failures
description: Cryptographic failures — padding-oracle byte-at-a-time, ECB-mode pattern leakage, IV/nonce reuse, weak-randomness (MT19937 / time-seeded srand / predictable Math.random), hardcoded keys, hash length-extension (Merkle-Damgard MACs), and timing-attack classes
---

# Cryptographic Failures

OWASP A02 — cryptographic failures are the class where attacker-controlled input exploits a cryptographic primitive's structural weakness or implementation flaw to decrypt, forge, enumerate, or bypass a cryptographic boundary. The primitive is **a mathematical or protocol gap converted into an attacker-usable channel**: a decryption oracle returns distinguishable error signals, an ECB-mode cipher leaks block-level patterns, an IV/nonce reused across messages lets XOR arithmetic recover plaintext, a time-seeded PRNG makes session tokens predictable, a hardcoded key is reversible, a Merkle-Damgard hash lets an attacker extend a MAC without knowing the secret, and a non-constant-time comparison leaks a timing bit per character. The question is never "is crypto used?" — it is "which primitive-level or protocol-level gap does the implementation expose?"

This skill owns the crypto-primitive classes. Expressions of these classes in specific protocols route to:
- `authentication_jwt.md` — JWT algorithm confusion / `alg=none` / HS256-vs-RS256 confusion. Those are crypto failures in a JWT-shaped expression; the JWT skill owns them.
- `weak_password_detection.md` — bcrypt null-byte truncation, PBKDF2 iteration counts, Argon2 parameters. The password-storage expression lives there.
- `authentication_jwt_novel_deep.md` — per-library signature-verification bypass CVEs.

## Attack Surface

**Encryption Oracles**
- Server-side decryption endpoints (session cookies, API tokens, encrypted parameters) that return distinguishable error signals for valid-vs-invalid padding
- Message-authentication flows that reveal whether a MAC verified before timing-safe comparison completes
- Download URLs with encrypted file-ID parameters (`/file?id=<base64>`) where a wrong decrypt returns a different error page or status code
- Captcha / anti-CSRF token endpoints with CBC-encrypted state

**Mode-of-Operation Failures**
- ECB-mode encryption (any) — pattern leakage per block
- CBC-mode encryption with predictable or reused IV
- GCM/ChaCha20-Poly1305 with reused nonce — catastrophic key leak
- CTR-mode with reused counter — plaintext XOR via two-time pad

**Random-Number Failures**
- Session tokens generated from `rand()` / `srand(time())` / `Math.random()` / `random.random()` without CSPRNG
- Password reset tokens with Mersenne Twister (predictable after 624 outputs)
- UUIDv1 (time-based) treated as unpredictable
- Node `crypto.pseudoRandomBytes` vs `crypto.randomBytes` (first is predictable)

**Key Management Failures**
- Hardcoded keys in source code, configuration files, container images, binary artifacts
- Keys stored alongside ciphertext (same table, same file)
- Default keys shipped with product (Rails `secret_key_base` fallback, Django `SECRET_KEY` default)
- Keys derived from predictable inputs (hostname, serial number, MAC address)

**MAC Primitive Failures**
- Length-extension via Merkle-Damgard construction (SHA-1, SHA-256, SHA-512, MD5, MD4) — vulnerable when used as `SHA(secret || message)` instead of HMAC
- Timing-leakage in MAC comparison via early-exit strcmp
- MAC-then-encrypt instead of encrypt-then-MAC
- Short MAC output (truncated tags vulnerable to online birthday)

**Protocol-Level Failures**
- TLS downgrade attacks when server fallback is permissive
- Mixed cipher-suite support (export-grade / RC4 / DES / 3DES still enabled)
- SSL/TLS version negotiation reaching deprecated versions

**Input Vectors**
- Any ciphertext the application reads and decrypts
- Session cookies, OAuth state, SAML authnrequest/response payloads, encrypted URL parameters
- API tokens, encrypted bearer tokens
- MAC-protected integrity-check fields on request bodies
- CSV/XLSX/JSON exports encrypted with a static key

## Core Primitive — Padding Oracle (Measured)

Measured on Python v3.14 + pycryptodome v3.24.0 (`.zen-batch-artifacts/batch-15/measure/01-padding-oracle.output.txt`): an AES-128-CBC decryption endpoint that distinguishes "valid PKCS#7 padding" from "invalid padding" via error codes OR response-shape OR timing is a byte-at-a-time plaintext recovery oracle.

**Primitive.** The attacker modifies the IV (or the previous ciphertext block, for inner blocks), submits to the decrypt oracle, and observes the error-shape. A specific IV value produces valid padding iff the attacker's byte-position guess matches the plaintext intermediate state at that position.

**Attack cost (measured):** 256 oracle queries per byte × 16 bytes per block = ~4,096 queries per block. For a typical 32-byte secret in two blocks, ~8,192 total queries. A rate-limited oracle (1 req/sec) → ~2 hours; unthrottled → under a minute.

**Measurement recipe:**
```python
# .zen-batch-artifacts/batch-15/measure/01-padding-oracle.py
# Full attack recovers plaintext bytes one at a time
# Observed output: b'here\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
# (last plaintext bytes + PKCS#7 padding, confirming decryption succeeded)
```

**Primitive generalization — oracle distinguisher sources.** The oracle doesn't need to be an explicit error — ANY observable differential between "valid padding" and "invalid padding" works:
- HTTP status code (200 vs 500 vs 400)
- Response-body shape (full page vs error page)
- Response-time difference (padding-check short-circuits, HMAC-check is longer)
- Request-handling behavior (padding-pass triggers DB query, DB-query timing visible)

## ECB-Mode Pattern Leakage (Measured)

Measured (`03-ecb.output.txt`): AES-128-ECB with 4 identical 16-byte plaintext blocks produces 4 identical ciphertext blocks. The output confirms: `d86f17bd0ed118d6424402accb8d68dd` × 4.

**Primitive.** ECB encrypts each 16-byte block independently with no chaining. Identical plaintext blocks → identical ciphertext blocks. Any application that encrypts structured data (user records, images, token bundles with repeated structure) with ECB leaks structural information.

**Attack family:**
- **The ECB penguin** — image encrypted with ECB preserves spatial-correlation patterns.
- **Cookie-attribute leak** — session cookie encrypted ECB with structure `{user_id=X}{role=admin}{expiry=...}`; identical blocks across different users' cookies reveal shared attributes.
- **Pattern-based plaintext guess** — attacker builds a dictionary of known-plaintext blocks → known-ciphertext blocks, decrypts attacker-controlled messages by lookup.

**Detection:**
```python
# Fingerprint ECB by observing identical blocks in ciphertext
def is_ecb(ct, blocksize=16):
    blocks = [ct[i:i+blocksize] for i in range(0, len(ct), blocksize)]
    return len(blocks) != len(set(blocks))
```

## IV / Nonce Reuse

**Primitive — CBC IV reuse:** two messages encrypted with the same key AND same IV. Attacker recovers `P1 XOR P2 = C1 XOR C2` (XOR of plaintexts), reducing to a classical two-time-pad with heuristic natural-language analysis.

**Primitive — GCM nonce reuse (catastrophic):** two messages encrypted with the same key AND same 96-bit nonce. AES-GCM's authentication is a polynomial MAC in GF(2^128); nonce reuse lets an attacker recover the authentication subkey H, forging arbitrary ciphertexts under the same key. This is a one-shot compromise — single nonce-reuse pair breaks the key's integrity property forever.

**Primitive — CTR counter reuse:** stream cipher with reused keystream. Attacker XORs ciphertexts to recover plaintext XOR; crib-dragging reveals both.

## Weak Randomness (Measured)

Measured (`02-weak-rng.output.txt`): Python's `random.random()` uses Mersenne Twister (MT19937). Observable state: 624 consecutive int32 outputs recover the full internal state. Public tool `randcrack` performs this attack.

**Vulnerable primitives:**
- Python `random.*` without `random.SystemRandom`
- JavaScript `Math.random()` — V8 uses XorShift128+ (predictable from a handful of outputs via Z3-SAT solving)
- PHP `rand()` / `mt_rand()` — both MT19937
- Java `java.util.Random` — linear congruential, 48-bit state (trivially bruteforceable)
- C/C++ `rand()` with `srand(time(NULL))` — predictable within time-window
- Node pre-11.x `crypto.pseudoRandomBytes` (deprecated; use `crypto.randomBytes`)
- UUIDv1 — time + MAC-address based; attacker reconstructs via known creation time

**Safe primitives:**
- `/dev/urandom` on Unix; `BCryptGenRandom` on Windows
- Python `secrets.*` module (CSPRNG wrapper)
- Node `crypto.randomBytes`, `crypto.randomUUID` (v4)
- Java `java.security.SecureRandom`
- PHP `random_bytes()`, `random_int()`
- Rust `rand::rngs::OsRng`

**Fingerprint attack recipe (session token prediction):**
1. Observe a sequence of session tokens / password-reset tokens (publicly minted, e.g., via self-service password-reset or guest sessions).
2. Decode token structure — is it `random.randint`-shaped (int32), MT19937-generatable?
3. Feed 624 observed values to `randcrack`.
4. Predict next token value → predict victim's password-reset token.

## Hardcoded Keys

**Primitive.** Encryption/signing key committed to source, config, or binary. Reachable by any attacker who can read the artifact.

**Discovery recipe:**
```bash
# Classic grep targets
grep -rniE 'secret_key|api_key|AWS_SECRET|BEGIN RSA PRIVATE KEY|BEGIN DSA|BEGIN EC|BEGIN OPENSSH|aws_access_key_id' --include='*.py' --include='*.js' --include='*.java' --include='*.go'
# High-entropy string hunt (truffleHog, gitleaks)
truffleHog --regex --entropy=True /path/to/repo
gitleaks detect -r /path/to/repo
# Binary strings sweep
strings /path/to/binary | grep -E '^[A-Za-z0-9+/]{40,}=?$'  # base64 keys
```

**Common hardcoded-key patterns:**
- Rails `config/secrets.yml` with `secret_key_base: default_dev_key`
- Django `settings.py` `SECRET_KEY = 'django-insecure-...'` (project default)
- Spring `application.properties` `encryption.key=...`
- Docker image environment variables (`docker inspect` extraction)
- Mobile APK / IPA with keys in resources
- OTA firmware with keys in binary

## Hash Length-Extension (Measured)

Measured (`04-length-extension.output.txt`): any `SHA(secret || message)` MAC with a Merkle-Damgard-construction hash is extensible. Vulnerable primitives: SHA-1, SHA-256, SHA-512, SHA-224, SHA-384, MD4, MD5. Safe: HMAC (any), SHA-3 / Keccak (sponge construction), BLAKE2 with keyed mode.

**Attack recipe:**
```bash
# Install hashpumpy
pip install hashpumpy

python3 -c "
import hashpump
# Known MAC + known message + guessed secret length
new_hash, new_message = hashpump.hashpump(
    '2f9be5bad2af1e6d3b71fb5df7f9ba02de28f3485ccbdd98801771a22d00c705',
    b'user=alice&role=user',
    b';role=admin',
    len(b'MY_SECRET')  # bruteforce range 1-64 bytes
)
print(new_hash, new_message)
"
```

The attacker produces a valid-looking MAC without knowing the secret. The forged message appends `;role=admin` plus padding bytes; the server validates MAC successfully, parses the second `role=admin`, and (if the parser prefers the last value — typical) authorizes as admin.

## Timing Attacks

**Primitive.** A string comparison that short-circuits on first mismatched byte reveals, per request, how many bytes of a secret matched. Attacker enumerates one byte at a time.

**Vulnerable patterns:**
```python
# Vulnerable — Python
if provided_hmac == expected_hmac:   # early-exit strcmp
    return True

# Vulnerable — Java
if hmac1.equals(hmac2):               # String.equals is early-exit

# Safe
import hmac
if hmac.compare_digest(provided_hmac, expected_hmac):
    return True
```

**Measurement anchor:** Over the network, byte-granularity timing requires ~100-1000 samples per byte to overcome jitter (noise standard deviation ~1 ms, signal per byte ~10-100 ns). In-process timing is immediate; cross-process (unix socket) is intermediate.

**Confirmation ladder:**
1. **Local in-process** — microbenchmark `==` vs `hmac.compare_digest` reveals timing differential.
2. **Local cross-process** — ping-time-reasonable timing with ~1000 samples / byte.
3. **Network** — only usable on dedicated hardware with low-jitter paths; cloud is too noisy for byte-granularity timing against modern TLS.

## Detection Channels

### Padding Oracle Fingerprint

```bash
# Submit valid cookie → observe response
curl -b 'session=VALID_B64_COOKIE' https://target/
# Modify last byte of IV in cookie → observe response differential
# PADDING-INVALID: 500 Internal Server Error
# PADDING-VALID + MAC-INVALID: 403 Forbidden
# PADDING-VALID + MAC-VALID (lucky): 200 OK
# → Three-way distinguisher is the oracle; two-way is also sufficient
```

### ECB Fingerprint

```python
# Submit controlled plaintext with repeated 16-byte prefix
# ECB → repeated ciphertext blocks
# Submit with 2x the AES block size of identical bytes
# Observe ciphertext for identical 16-byte blocks
```

### Weak-RNG Fingerprint

Observe a sequence of session tokens, password-reset tokens, or any public RNG output. Attempt state recovery with `randcrack`:
```python
from randcrack import RandCrack
rc = RandCrack()
for v in observed_values:  # need 624 for Python MT19937
    rc.submit(v)
predicted = rc.predict_randint(0, 2**32)
```

### Hardcoded-Key Fingerprint

```bash
# Public GitHub search for leaked keys
# Decompile mobile apps + binaries for embedded keys
# Default-key hunt: match known-default keys against observed ciphertext/signatures
```

### Length-Extension Fingerprint

```bash
# Observe MAC format and length
# If MAC is 32 hex chars (128 bits) → MD5 — length-extensible if not HMAC
# If MAC is 40 hex chars → SHA-1 — length-extensible if not HMAC
# If MAC is 64 hex chars → SHA-256 — length-extensible if not HMAC
# HMAC-SHA-256 has same output length; distinguish by API docs or by testing extension
```

## Testing Methodology

1. **Identify crypto sinks.** Grep for `AES.new(.*MODE_(ECB|CBC)`, `DES`, `rand()`, `mt_rand()`, `Math.random`, `SecureRandom`, `MessageDigest.getInstance`, `hmac.*compare`, `secrets.*`.
2. **Fingerprint the primitive.** Which cipher, which mode, which hash, which RNG. Different primitives have different attack classes.
3. **Hunt oracles.** For every decrypt sink, test for padding-oracle distinguisher. For every MAC sink, test for timing differential.
4. **Enumerate hardcoded keys.** Dependency scan, container image scan, firmware extract.
5. **Match CVE to primitive-version.** The novel sibling catalogs 2024-2026 CVEs.
6. **Measure the attack cost.** Padding oracle: 4K queries per block. Weak RNG: 624 outputs for Python MT19937. Length extension: 1-64 secret-length bruteforce.

## Validation

- **Padding-oracle recovery produces plaintext bytes matching reality.** Dry-run against known plaintext before claiming an attack.
- **ECB fingerprint requires controlled plaintext.** A single-user observation of identical ciphertext blocks is suspicious; multiple users with identical blocks is confirmation.
- **Weak-RNG prediction matches the next observed value.** Build the predictor, verify against a next-observed, then target the victim's token.
- **Length-extension attack produces a working MAC.** Verify by submitting to the application and observing acceptance.
- **Timing attack requires enough samples.** 10 requests of timing data is noise; 1000 samples per byte is a reasonable signal threshold on a non-noisy network.

## False Positives

- **A "random-looking" session token that is actually CSPRNG-derived.** Confirm by checking the generator source.
- **An ECB-shaped cookie that is actually random padding.** Different users should still have different ciphertext blocks.
- **A padding-oracle differential that is actually a legitimate error path.** Normalize response-shape expectation before claiming oracle.
- **A hardcoded key that is actually a key-wrapping encryption key for a KMS-backed real key.** Review the key's role.
- **A length-extension claim on an HMAC MAC.** HMAC's double-hash construction prevents extension — verify the primitive is `SHA(secret || message)`, not `HMAC-SHA(secret, message)`.
- **A timing attack with 10 samples.** Not confirmed; noise dominates.

## Impact and Chaining

**Direct impact.**
- **Padding oracle → session hijack.** Decrypt a session cookie → impersonate any user whose cookie structure the attacker knows.
- **ECB → attribute leak.** Decrypt cross-user cookies by block substitution.
- **Nonce reuse → forgery.** AES-GCM reused nonce → forge any ciphertext under that key.
- **Weak RNG → token prediction.** Predict password-reset tokens; account takeover.
- **Hardcoded key → mass compromise.** Any attacker with source access decrypts/signs everything.
- **Length extension → MAC forgery.** Elevate privileges by appending authorized attribute to signed query.
- **Timing attack → secret extraction.** HMAC key or password byte-by-byte recovery.

**Upstream enablers.**
- An endpoint that decrypts attacker-controlled ciphertext.
- Static key material in source / binary / config.
- A MAC comparison that short-circuits.

**Downstream.**
- `authentication_jwt.md` — session impersonation via decrypted/forged tokens.
- `broken_function_level_authorization.md` — role-field forgery via length-extension.
- `information_disclosure.md` — cross-user data leak via ECB.
- `rce.md` — some crypto failures (serialized objects decrypted → deserialization) chain to RCE; route to `insecure_deserialization.md`.

**Composite chains.**
- *Padding oracle → cookie decrypt → session impersonation → admin BFLA.* Route: this file → `broken_function_level_authorization.md`.
- *Weak RNG → password-reset token prediction → account takeover.* Route: this file → `authentication_jwt.md`.
- *Length extension → MAC forgery → authorization bypass.* Route: this file → BFLA/authn.
- *Hardcoded key → source leak → mass session decrypt.* Route: this file → `information_disclosure.md`.

## Pro Tips

- **Oracle distinguishers are often subtler than HTTP status.** Response-time, response-body size, response-header presence, downstream side effects (DB query that only fires on padding-valid). Measure all channels.
- **Nonce reuse in AEAD is catastrophic in a way CBC IV reuse is not.** GCM reused nonce leaks the authentication subkey — one-shot key break. CBC reused IV leaks `P1 XOR P2` — plaintext recovery via two-time pad analysis.
- **Mersenne Twister needs 624 outputs; Node's XorShift128+ needs 5–8.** Different RNGs have different state-recovery bounds. Match the attack to the generator.
- **UUIDv1 is time-based — not unpredictable.** If the application uses UUIDv1 for session IDs, enumerate via known creation times.
- **Hash length extension is a Merkle-Damgard property.** SHA-3 / Keccak / BLAKE2 are immune by construction. HMAC's double-hash wrapper neutralizes extension on all Merkle-Damgard hashes.
- **Timing attacks over the internet are hard; timing attacks over a shared cloud instance are easy.** Co-residency attacks on cloud VMs produce microsecond-granularity timing against neighboring tenants.
- **Hardcoded keys live in container ENTRYPOINT scripts, Dockerfile ARG, k8s ConfigMaps, Terraform state files, CI/CD environment variables.** The attack is often not source-review, it's artifact-review.

## Tooling

- **Burp Suite PadBuster / padding-oracle probe extensions** — automated byte-at-a-time CBC padding-oracle attack.
- **padbuster, hashpumpy, hashpump** — padding oracle + length extension.
- **randcrack** — Python MT19937 state recovery.
- **CyberChef** — crypto primitive manipulation for payload crafting.
- **gitleaks, truffleHog, detect-secrets** — hardcoded-key discovery.
- **OpenSSL CLI** — crypto primitive manipulation (`openssl enc`, `openssl dgst`).
- **sagemath / pycryptodome** — Python crypto for custom attack scripts.

## Summary

Cryptographic failures are protocol-level or primitive-level gaps where a mathematical weakness becomes an attacker channel: padding-oracle byte-at-a-time (measured on AES-CBC, ~4K queries per block), ECB-mode pattern leakage (measured, identical blocks produce identical ciphertext), IV/nonce reuse (CBC two-time pad + GCM authentication-key leak), weak RNG (MT19937 state-recovery with 624 outputs, measured), hardcoded keys (source/binary/config review), hash length-extension (Merkle-Damgard family — SHA-1/256/512/MD4/5 — vs HMAC and SHA-3), and timing attacks. The 2024-2026 frontier is dense: Apache Tomcat EncryptInterceptor padding oracle (CVE-2026-29146), Apache Druid pac4j (CVE-2024-45384), wolfSSL PKCS7 (CVE-2026-5504/CVE-2026-6291), Authlib OAuth padding oracle (CVE-2026-28490), Envoy OAuth2 (CVE-2026-47775), phpseclib (CVE-2026-32935), Jervis Jenkins library (CVE-2025-68698/CVE-2025-68931), StreamPark AES-ECB + weak RNG (CVE-2025-54981). Expressions of these classes in JWT/password-storage route to `authentication_jwt.md` and `weak_password_detection.md` respectively; this file owns the crypto-primitive classes. The two deep siblings carry the full technique surface: `cryptographic_failures_advanced_deep.md` owns per-primitive full P/P/A/C/I treatment with measured per-mode and per-RNG matrices; `cryptographic_failures_novel_deep.md` owns the 2024-2026 CVE catalogue with Apache Tomcat/wolfSSL/phpseclib/Authlib/OpenSSL/Envoy mechanism decomposition.
