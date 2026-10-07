---
name: cryptographic-failures-novel-deep
description: Cryptographic failures 2024-2026 frontier — Apache Tomcat EncryptInterceptor padding oracle, wolfSSL PKCS7 Bleichenbacher cluster, OpenSSL CMS/PKCS7 Bleichenbacher, Envoy OAuth2 padding oracle, phpseclib padding oracle, Authlib OAuth padding oracle, Jervis Jenkins AES/CBC without authentication, Druid pac4j session cookie, StreamPark AES-ECB + weak RNG, Mercusys/OrangeHRM ECB clusters, Crypt::OpenSSL::X509 Perl, and the versioned mechanism catalog
sibling: cryptographic_failures
load_when: scan_mode == "deep"
---

# Cryptographic Failures — Novel + Frontier Depth

This is the novel+frontier deep sibling to `cryptographic_failures.md`. The base owns the primitive catalog + measurement anchors + routing to `authentication_jwt.md` + `weak_password_detection.md`. The advanced sibling owns the full per-primitive protocol depth across padding oracle (byte-at-a-time + CBC-R), ECB (attribute recovery + byte-at-a-time appended-secret), nonce-reuse (CBC + GCM/ChaCha20 + CTR per-AEAD attacks), weak RNG (per-generator state recovery), length extension (full protocol with secret-length bruteforce), and timing (local vs cross-process vs network). This file owns the 2024-2026 CVE mechanism catalogue with the canonical version/fix table, the Apache-ecosystem padding-oracle cluster (Tomcat EncryptInterceptor, Druid pac4j), the TLS/PKCS7 Bleichenbacher cluster (wolfSSL, OpenSSL), the OAuth2/OAuth padding-oracle anchor (Envoy, Authlib), and the embedded-crypto cluster (StreamPark, OrangeHRM, Mercusys, Jervis).

Load this file when the goal is matching a target application + version to a current crypto CVE, choosing between the Apache Tomcat EncryptInterceptor primitive and the OpenSSL CMS primitive, or writing up an embedded-stack hardcoded-key + ECB finding against industrial IoT.

The 2024-2026 cryptographic-failure frontier is dense: 24+ padding-oracle CVEs, 5+ ECB/weak-RNG CVEs, Bleichenbacher resurgence against OpenSSL + wolfSSL + Authlib + Envoy, and an industrial-IoT embedded-crypto thread. All version boundaries anchor to primary sources at `.zen-batch-artifacts/batch-15/nvd/`.

## 2024–2026 CVE Version/Fix Table — Canonical

| CVE | Package / Target | Vulnerable | Patched | CVSS | Primitive class |
|---|---|---|---|---|---|
| CVE-2024-45384 | Apache Druid druid-pac4j extension | per vendor | per vendor | 5.3 | pac4j session cookie padding oracle |
| CVE-2025-49824 | conda-smithy | per vendor | per vendor | n/a | Padding oracle in config decryption |
| CVE-2025-7071 | Oberon ocrypto library | ≥ 3.1.0 < 3.9.2 | 3.9.2 | n/a | PKCS7 padding oracle |
| CVE-2025-7383 | Oberon PSA Crypto library | ≥ 1.0.0 < 1.5.1 | 1.5.1 | n/a | Padding oracle in PSA Crypto |
| CVE-2025-68698 | Jervis Jenkins library | < 2.2 | 2.2 | 7.5 | PKCS1Encoding Bleichenbacher |
| CVE-2025-68931 | Jervis Jenkins library | < 2.2 | 2.2 | 7.5 | AES/CBC/PKCS5Padding lacks authentication |
| CVE-2025-41351 | Funambol v30.0.0.20 cloud server | 30.0.0.20 | per vendor | n/a | Thumbnail-URL padding oracle |
| CVE-2026-28490 | Authlib (Python OAuth) | < 1.6.9 | 1.6.9 | 6.5 | OAuth cryptographic padding oracle |
| CVE-2026-32935 | phpseclib (PHP) | 0.1.1–1.0.26 / 2.0.0–2.0.51 / 3.0.0–3.0.49 | per vendor | 5.9 | Padding oracle via decryption-error distinguisher |
| CVE-2026-29146 | Apache Tomcat EncryptInterceptor | 11.0.0-M1 through ... | per vendor | 7.5 | Padding oracle in EncryptInterceptor default config |
| CVE-2026-5504 | wolfSSL PKCS7 CBC decryption | per vendor | per vendor | 5.3 | Padding oracle via decryption-query differential |
| CVE-2026-42768 | OpenSSL CMS_decrypt / PKCS7_decrypt | per vendor | per vendor | 3.7 | Bleichenbacher via differential error on CMS/PKCS7 EnvelopedData |
| CVE-2026-6291 | wolfSSL PKCS7 KTRI decryption | per vendor | per vendor | 6.5 | Bleichenbacher padding oracle in PKCS#7 KTRI decryption |
| CVE-2026-47775 | Envoy OAuth2 HTTP filter | < 1.35.11 / < 1.36.7 / < 1.37.3 / < 1.38.1 | 1.35.11 / 1.36.7 / 1.37.3 / 1.38.1 | 6.8 | OAuth2 state cookie padding oracle |
| CVE-2026-41514 | OP-TEE TEE | per vendor | per vendor | 2.5 | TrustZone-side timing/padding differential |
| CVE-2025-54981 | Apache StreamPark | per vendor | per vendor | 7.5 | AES-ECB + weak RNG for sensitive data encryption |
| CVE-2026-39349 | OrangeHRM | 5.0–5.8 | per vendor | 2.7 | AES-ECB for sensitive fields |
| CVE-2026-36606 | Mercusys AC12G (EU) V1 | V1_200909 firmware | per vendor | 7.1 | Hardcoded DES key + ECB mode for config backups |
| CVE-2026-58102 | Crypt::OpenSSL::X509 (Perl) | < 2.1.3 | 2.1.3 | 9.1 | Heap OOB-read via long certificate extension OID (not length-extension in the classical sense — adjacency class) |

Notes on the table:
- **CVE-2026-29146 (Apache Tomcat EncryptInterceptor) at CVSS 7.5** is the standout — a default-configuration padding oracle in a cluster-communication primitive. Tomcat's EncryptInterceptor encrypts inter-node messages; the default config exposed a decryption-error differential. Patch adds authenticated encryption.
- **CVE-2026-42768 (OpenSSL CMS_decrypt + PKCS7_decrypt)** at CVSS 3.7 — low score because the attack is Bleichenbacher-style requiring many queries, but the attack IS cryptographic (recovers plaintext RSA-encrypted session keys). OpenSSL's long-running CMS/PKCS7 implementation returned different error signals for valid-PKCS#1-v1.5 padding vs invalid.
- **wolfSSL CVE-2026-5504 and CVE-2026-6291** are two separate Bleichenbacher classes in wolfSSL's PKCS7 implementation — PKCS7 CBC decryption and PKCS7 KTRI (Key Transport Recipient Info) decryption.
- **Authlib CVE-2026-28490** at CVSS 6.5 — a Python OAuth library padding oracle; Authlib is widely-used in Python OAuth providers.
- **Envoy CVE-2026-47775** at CVSS 6.8 affects OAuth2 state cookie encryption; attacker observes decryption error signal to decrypt state.
- **Jervis CVE-2025-68698/68931** at CVSS 7.5 — Jenkins pipeline library. Two separate issues: PKCS1 Bleichenbacher + AES-CBC-without-authentication (also padding oracle).
- **phpseclib CVE-2026-32935** at CVSS 5.9 — the Python-ecosystem analog in PHP; version range 0.1.1 → 3.0.49.
- **StreamPark CVE-2025-54981** at CVSS 7.5 — combined ECB + weak RNG for sensitive-data encryption; the primitive is "two cryptographic weaknesses in one deployment."
- **OrangeHRM CVE-2026-39349** at CVSS 2.7 — ECB for sensitive HR fields; low CVSS reflects attacker-reach constraints but ECB attribute-recovery is applicable.
- **Mercusys CVE-2026-36606** at CVSS 7.1 — IoT router hardcoded DES key + ECB mode. Classic IoT firmware primitive.
- **CVE-2026-58102 (Crypt::OpenSSL::X509)** at CVSS 9.1 — adjacent to length-extension in the "unbounded buffer" class but is actually a heap OOB read via long OID; included here as a crypto-library CVE but mechanism is memory-safety, not length-extension-cryptographic.

## Primitive-Class Index

The 24+ padding-oracle + 5+ ECB/weak-RNG CVEs cluster into four primitive classes:

| Class | 2024-2026 anchor CVEs | Attack shape | Confirmation signal |
|---|---|---|---|
| **A. CBC/PKCS#7 padding oracle via error-differential** | Apache Tomcat (CVE-2026-29146), Apache Druid (CVE-2024-45384), Authlib (CVE-2026-28490), phpseclib (CVE-2026-32935), Jervis AES/CBC (CVE-2025-68931), Oberon ocrypto (CVE-2025-7071), Oberon PSA (CVE-2025-7383), Funambol (CVE-2025-41351), Envoy OAuth2 (CVE-2026-47775), conda-smithy (CVE-2025-49824) | Flip IV byte, observe response differential; byte-at-a-time plaintext recovery | Response-time / status-code / body-shape differential; byte recovery against known plaintext |
| **B. Bleichenbacher / PKCS1-v1.5 RSA padding oracle** | OpenSSL CMS/PKCS7 (CVE-2026-42768), wolfSSL PKCS7 CBC (CVE-2026-5504), wolfSSL PKCS7 KTRI (CVE-2026-6291), Jervis PKCS1Encoding (CVE-2025-68698) | Submit crafted RSA ciphertext; observe PKCS#1 v1.5 validity signal; recover RSA plaintext | Million-queries scale; recover an actual RSA-encrypted session key |
| **C. ECB mode exposing pattern** | Apache StreamPark (CVE-2025-54981), OrangeHRM (CVE-2026-39349), Mercusys AC12G (CVE-2026-36606) | Submit identical plaintext blocks; observe identical ciphertext blocks; attribute-recovery via block substitution | Identical 16-byte blocks in ciphertext; cross-tenant block substitution reveals attributes |
| **D. Hardcoded key + static primitive** | Mercusys AC12G (CVE-2026-36606 — hardcoded DES key for config backup); embedded-firmware class | Extract key from firmware/source; decrypt all protected data | Key observed in extraction; decryption succeeds |

## CVE-2026-29146 — Apache Tomcat EncryptInterceptor Padding Oracle (The Standout)

**Primitive.** Apache Tomcat's `EncryptInterceptor` encrypts inter-node cluster communication. The default configuration used a CBC-mode cipher with a MAC-then-encrypt (or no MAC) scheme that returned different error responses for "padding-invalid" vs "padding-valid-but-malformed-message."

**All-of preconditions:**
1. Apache Tomcat in affected 11.0.0-M1+ range (per vendor advisory).
2. `EncryptInterceptor` enabled on cluster channel.
3. Attacker reaches cluster port (4000-4001 default) OR cluster port exposed via misconfigured firewall.
4. Attacker can submit modified ciphertext + observe response differential.

**Attack recipe:**
```python
import socket, struct

def oracle(iv, ciphertext):
    """Submit modified ciphertext to Tomcat cluster endpoint; observe response."""
    s = socket.create_connection(('tomcat-cluster-member.target.net', 4000))
    # Cluster frame format: length prefix + encrypted payload
    frame = struct.pack('>I', len(iv) + len(ciphertext)) + iv + ciphertext
    s.sendall(frame)
    response = s.recv(4096)
    # Differential:
    # PADDING-INVALID: specific error byte sequence
    # PADDING-VALID + MAC-INVALID: different byte sequence
    # PADDING-VALID + MAC-VALID: cluster accepts message
    return b'\x01\x02\x03MAC_INVALID' in response

# Standard PadBuster byte-at-a-time attack
# Target: inter-cluster session-replication message
target_block = capture_cluster_session_replication_message()
recovered = padbuster_attack(target_block, oracle)
# recovered = session-token / replication-payload / cluster-coordinator-message
```

**Confirmation signals.**
1. **Byte-recovery against known plaintext** (test replication message with known content).
2. **Response differential measurable** — three-state distinguisher (padding-invalid / MAC-invalid / accepted).
3. **Server-side `TLSException: BadPaddingException` in catalina.out** — padding-oracle byproduct.

**Preconditions:**
1. Apache Tomcat version in the affected range with `EncryptInterceptor` enabled on cluster communication.
2. Attacker reaches the cluster communication endpoint (lateral movement from within the network OR exposed cluster port).
3. Attacker can submit modified ciphertext and observe error differential.

**Attack recipe:**
```python
# Simplified attack shape — tool-level implementation uses PadBuster-style
import socket

def oracle(ciphertext_blob):
    # Submit to Tomcat cluster endpoint
    s = socket.create_connection(('tomcat.target.net', 4000))
    s.sendall(cluster_frame_wrapping(ciphertext_blob))
    response = s.recv(4096)
    # Differential: specific byte in response indicates padding validity
    return b'MAC_INVALID' in response  # vs b'PADDING_INVALID'

# Run PadBuster-style byte-at-a-time recovery against the ciphertext
```

**Confirmation.** Response differential between the two error categories observed; test byte recovery against a known-plaintext message (e.g., an application-level ping encrypted by a legitimate node).

**Impact.** Decrypt inter-cluster messages → recover session replication payloads, authentication tokens, cluster-coordinator messages. The cluster primitive is often the authority for session management; decrypting it is full session impersonation across the cluster.

## CVE-2026-42768 — OpenSSL CMS_decrypt / PKCS7_decrypt Bleichenbacher

**Primitive.** OpenSSL's `CMS_decrypt()` and `PKCS7_decrypt()` return distinguishable error signals when the CMS/PKCS7 EnvelopedData's RSA-encrypted session key fails PKCS#1 v1.5 unpadding vs when the unpadded session key fails later integrity checks. The Bleichenbacher attack uses this differential to recover the RSA-encrypted session key via ~10^6 oracle queries.

**Preconditions:**
1. Application uses OpenSSL `CMS_decrypt` or `PKCS7_decrypt` in a flow where the attacker can submit crafted CMS/PKCS7 EnvelopedData and observe success/failure.
2. The application exposes the error signal via response-shape differential.
3. OpenSSL version in the affected range.

**Attack recipe (classical Bleichenbacher):**
```python
# Public tool: Bleichenbacher-aware CMS payload crafter
# Submit RSA ciphertext C' = C * s^e mod n
# Oracle: 1 if PKCS#1 v1.5 unpadding succeeds (first two bytes 0x00 0x02)
#         0 if unpadding fails (any other first two bytes)
# Narrow interval around plaintext using the oracle's "yes" responses
# ~10^6 queries recover a 2048-bit RSA plaintext
```

**Confirmation.** Recovered RSA-encrypted plaintext matches the original EnvelopedData's session key.

**Impact.** Decrypt any CMS/PKCS7-protected message encrypted to the vulnerable OpenSSL instance. Chains to signed email decryption, document integrity bypass, PKI-based authentication compromise.

## CVE-2026-47775 — Envoy OAuth2 HTTP Filter Padding Oracle

**Primitive.** Envoy's OAuth2 HTTP filter encrypts OAuth state (session cookies, tokens) using a CBC mode without authenticated encryption. Decryption errors are distinguishable from downstream errors, exposing a padding oracle.

**Preconditions:**
1. Envoy versions in affected range (< 1.35.11 / < 1.36.7 / < 1.37.3 / < 1.38.1).
2. OAuth2 HTTP filter enabled.
3. Attacker reaches the filter endpoint with crafted state cookies.

**Attack recipe:** Standard CBC padding oracle — modify state cookie IV byte-by-byte, observe response-shape differential, recover state plaintext.

**Impact.** Decrypt OAuth state → session impersonation; forge state → authorization bypass. CVSS 6.8.

## CVE-2026-28490 — Authlib OAuth Padding Oracle

**Primitive.** Authlib (Python) < 1.6.9 had a cryptographic padding oracle in its OAuth token/state encryption path. Same mechanism family as Envoy / Druid pac4j: distinguishable error signal for padding validity.

**Impact.** Decrypt OAuth state → session impersonation. CVSS 6.5.

## Apache Druid CVE-2024-45384 — pac4j Session Cookie Padding Oracle

**Primitive.** Apache Druid's `druid-pac4j` extension uses pac4j for authentication. The pac4j session cookie encryption had a padding oracle. CVSS 5.3.

## StreamPark CVE-2025-54981 — ECB + Weak RNG

**Primitive.** Apache StreamPark used AES in ECB mode AND a weak RNG (not CSPRNG) for encrypting sensitive data including user credentials. The ECB mode exposes patterns; the weak RNG makes any derived material (IVs, salts, nonces) predictable.

**Preconditions:**
1. Apache StreamPark deployment with sensitive-data encryption enabled.
2. Attacker observes encrypted output (admin UI leak, log leak, API response).

**Attack recipe:**
```python
# 1. Observe encrypted sensitive-data output
# 2. ECB: identify identical blocks across records
# 3. Weak-RNG: predict upcoming IV/salt via state recovery
# 4. Combine: decrypt via block substitution + predicted IV
```

**Impact.** Decrypt stored credentials / sensitive config. CVSS 7.5.

## Mercusys AC12G CVE-2026-36606 — Hardcoded DES + ECB

**Primitive.** Mercusys AC12G (EU) V1 router with firmware V1_200909 encrypts configuration backups with a hardcoded DES key in single DES ECB mode. **Multiple cryptographic failures stacked:**
1. **Hardcoded key** — reversible via firmware extraction.
2. **DES** — 56-bit key, breakable in hours on commodity GPUs independent of the hardcoding.
3. **ECB mode** — pattern leakage.
4. **Single DES** — not triple-DES; the 56-bit key is the full crypto strength.

**Attack recipe:**
```bash
# 1. Extract firmware image
binwalk -e firmware.bin
# 2. Reverse-engineer backup-encryption function
# 3. Extract hardcoded DES key from binary via static analysis
strings extracted/filesystem/sbin/backup_tool | grep -E '^[0-9A-F]{16}$'
# 4. Decrypt any observed backup with the extracted key
openssl enc -d -des-ecb -K <extracted_key_hex> -in backup.enc -out backup.cfg
```

**Impact.** All config backups across all devices decryptable with the same key. Any attacker with firmware access decrypts any user's config file — WiFi passwords, admin credentials, PPPoE credentials. CVSS 7.1.

## wolfSSL PKCS7 Bleichenbacher Cluster (CVE-2026-5504 and CVE-2026-6291)

**CVE-2026-5504** — padding oracle in wolfSSL's PKCS7 CBC decryption. Attacker with ability to send PKCS7 messages observes error differential and recovers plaintext via repeated queries.

**CVE-2026-6291** — Bleichenbacher padding oracle in wolfSSL's PKCS#7 KTRI (Key Transport Recipient Info) decryption. When decrypting PKCS#7 EnvelopedData using RSA PKCS#1 v1.5 key transport, wolfSSL returned different error signals for valid vs invalid padding. Classical Bleichenbacher recovery with ~10^6 queries.

**Full attack recipe (Bleichenbacher against wolfSSL CMS/PKCS7):**
```python
# Simplified Bleichenbacher adaptive-chosen-ciphertext attack

def oracle(ciphertext_c_prime):
    """Server returns 1 if PKCS#1 v1.5 unpadding succeeds, 0 otherwise."""
    try:
        response = send_pkcs7_envelope(ciphertext_c_prime)
        # Different error path for padding-valid vs invalid
        if 'InternalCMSError' in response.text:
            return 1  # Padding valid
        return 0
    except Exception:
        return 0

def bleichenbacher(target_ciphertext, n, e):
    """Recover RSA plaintext using narrowing-interval attack."""
    # Interval [2B, 3B-1] where B = 2^(k-16) and k is RSA key size in bits
    B = 2 ** (n.bit_length() - 16)
    M = [(2 * B, 3 * B - 1)]
    s = ceil(n / (3 * B))

    while True:
        # Blind the target ciphertext with a multiplicative factor s^e
        c_prime = (target_ciphertext * pow(s, e, n)) % n
        if oracle(c_prime):
            # Narrow interval using the s that produced valid padding
            new_M = narrow_interval(M, s, B, n)
            if len(new_M) == 1 and new_M[0][0] == new_M[0][1]:
                return new_M[0][0]  # Recovered plaintext
            M = new_M
            s = next_s(M, B, n)
        else:
            s += 1
```

**Preconditions.** wolfSSL deployment with PKCS7 message handling + attacker-reachable decryption endpoint. Pre-fix version.

**Confirmation signals (Bleichenbacher).**
1. **Oracle returns differential signal.** Padding-valid vs invalid returns distinguishable response.
2. **~10^6 queries recover a 2048-bit RSA plaintext.** Standard Bleichenbacher complexity.
3. **Recovered plaintext matches the original PKCS7 session key format** — leading 00 02 || random-nonzero-bytes || 00 || keybytes.

**Impact.** Decrypt PKCS7-protected messages encrypted to the wolfSSL instance; typical use is embedded-crypto in IoT/firmware OTA. Chain: recovered session key → decrypt firmware image → extract credentials / signing keys → attack entire device fleet.

## Jervis Jenkins Library CVE-2025-68698 and CVE-2025-68931

**CVE-2025-68698** — Jervis < 2.2 uses `PKCS1Encoding` which is Bleichenbacher-vulnerable for RSA decryption in Jenkins pipeline script contexts.

**CVE-2025-68931** — Jervis < 2.2 uses `AES/CBC/PKCS5Padding` without authentication (no HMAC, no AEAD). The CBC mode is a padding oracle.

**Impact.** Decrypt Jenkins pipeline secrets stored encrypted; recover build-time credentials. CVSS 7.5 each.

## phpseclib CVE-2026-32935 Padding Oracle

**Primitive.** phpseclib (PHP crypto library) versions 0.1.1 through 1.0.26, 2.0.0 through 2.0.51, 3.0.0 through 3.0.49 are vulnerable to a padding oracle in the decryption error-handling path.

**Impact.** Any PHP application using phpseclib for symmetric encryption with the vulnerable versions. CVSS 5.9.

## Composite Chains at the Frontier

### Apache Tomcat EncryptInterceptor → Cluster Session Impersonation
1. **Primitive:** CVE-2026-29146 padding oracle on cluster communication.
2. **Reach:** attacker on cluster-adjacent network segment or exposed cluster port.
3. **Trigger:** byte-at-a-time plaintext recovery of session-replication messages.
4. **Impact:** session impersonation across the cluster; chained with `broken_function_level_authorization.md` for post-impersonation BFLA.

### OpenSSL CMS_decrypt → Email Decryption / PKI Compromise
1. **Primitive:** CVE-2026-42768 Bleichenbacher on CMS/PKCS7.
2. **Reach:** application accepts attacker-crafted CMS payloads.
3. **Trigger:** ~10^6 queries recover RSA-encrypted session key.
4. **Impact:** decrypt S/MIME email, signed document integrity bypass, PKI auth compromise.

### Mercusys IoT → Mass Decryption
1. **Primitive:** CVE-2026-36606 hardcoded DES + ECB.
2. **Reach:** firmware image publicly available OR extraction from one device.
3. **Trigger:** extract key via static analysis.
4. **Impact:** decrypt backups across the entire device fleet.

### StreamPark → Credential Database Decrypt
1. **Primitive:** CVE-2025-54981 ECB + weak RNG.
2. **Reach:** admin UI or log access.
3. **Trigger:** combine ECB block pattern analysis + RNG state prediction.
4. **Impact:** decrypt stored credentials.

### Envoy OAuth2 → OAuth Session Impersonation
1. **Primitive:** CVE-2026-47775 padding oracle on state cookie.
2. **Reach:** OAuth state cookie observable + modifiable.
3. **Trigger:** PadBuster-style byte-at-a-time recovery.
4. **Impact:** decrypt state → session impersonation; forge state → OAuth flow manipulation.

## Frontier Detection Methodology

1. **For every TLS/CBC/PKCS7 handling path, assume padding oracle until oracle-free is proven.** The Bleichenbacher resurgence confirms the pattern.
2. **For embedded IoT firmware, assume hardcoded key.** Extract and verify before assuming key rotation.
3. **For OAuth state / session cookies, test padding oracle.** CBC + no AEAD = probable oracle.
4. **For Java/Jenkins crypto, test PKCS1Encoding.** Bleichenbacher applies.
5. **For PHP applications using phpseclib, confirm version 3.0.49 or later.** Pre-fix is vulnerable.
6. **For GCM / ChaCha20 deployments, audit nonce generation.** Any reuse is catastrophic.

## Frontier Validation

- **Padding-oracle claim requires measurable byte recovery.** Not just an error-differential.
- **Bleichenbacher claim requires full RSA plaintext recovery.** The error-differential alone is "oracle present"; the extraction is the finding.
- **ECB claim against OrangeHRM / StreamPark / Mercusys requires reproducible identical-block observation across multi-tenant records.** Single-shot is suspicious.
- **Hardcoded-key claim against Mercusys requires actual extraction from firmware.** Confirm by decrypting a known backup.
- **Weak-RNG+ECB combined claim (StreamPark) requires both failures demonstrated.** Separate findings or combined chain.

## Pro Tips at the Frontier

- **CBC-mode WITHOUT HMAC is a padding oracle until proven otherwise.** The 2024-2026 wave confirms this isn't a 2010-era problem.
- **Bleichenbacher resurges against OpenSSL + wolfSSL + Authlib + Envoy + Jervis.** The attack is 25+ years old and still finding new victims. Any PKCS#1 v1.5 handling path is a candidate.
- **Embedded IoT crypto failures are structural.** Hardcoded keys + ECB + outdated primitives (DES, MD5) are the recurring pattern. Firmware extraction is the primary tooling.
- **"Our cookie is signed" ≠ "our cookie is secure."** CBC-sign-then-encrypt (Rails pre-5.2) is a padding oracle; CBC-encrypt-then-MAC is safe.
- **The Jervis class generalizes to any Jenkins library using PKCS1Encoding + AES-CBC-no-HMAC.** Grep Jenkins pipeline libraries.

## Summary

The crypto-failure 2024-2026 frontier is a resurgence of classical attacks: padding-oracle via CBC/PKCS7 across Apache Tomcat EncryptInterceptor (CVE-2026-29146 CVSS 7.5), Druid pac4j, Authlib OAuth, phpseclib, Envoy OAuth2, Jervis Jenkins library, Oberon crypto libraries, Funambol, conda-smithy. Bleichenbacher resurgence against OpenSSL CMS/PKCS7 (CVE-2026-42768), wolfSSL PKCS7 twice (CVE-2026-5504 + CVE-2026-6291), Jervis PKCS1Encoding. ECB-mode cluster across Apache StreamPark (CVE-2025-54981 — stacked with weak RNG), OrangeHRM, Mercusys IoT routers (CVE-2026-36606 — stacked with hardcoded DES key). Expressions in JWT and password storage are owned by `authentication_jwt.md` and `weak_password_detection.md`; this file owns the primitive-level cryptographic classes. Base and advanced siblings reference these CVEs by number only; the versioned mechanism catalog lives here.
