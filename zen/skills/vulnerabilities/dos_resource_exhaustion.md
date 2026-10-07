---
name: dos-resource-exhaustion
description: DoS and resource exhaustion — ReDoS (regex catastrophic backtracking), algorithmic complexity attacks (quadratic parsers, hash flooding, polynomial unification), decompression bombs (zip/gzip/brotli), GraphQL depth/batching/aliasing, XML XEE/billion-laughs, memory/CPU exhaustion in network protocols
---

# DoS and Resource Exhaustion

Denial-of-service via resource exhaustion is the class where attacker input triggers disproportionate CPU, memory, or network consumption on the server — collapsing availability for other requests. The primitive is **small attacker input → large server-side resource consumption**: an evil regex burns CPU for minutes on a 100-byte input, a 42-kilobyte zip-bomb expands to 4.5 petabytes, a GraphQL query with 10 nested field aliases forces 2^10 backend calls, an XML billion-laughs recursive-entity expands to gigabytes of memory. The question is never "can an attacker send requests?" — it is "which cheap input triggers expensive server-side work?"

This skill consolidates fragments that previously lived in `race_conditions.md`, `header_injection.md`, `xxe.md`, `semantic_confusion.md`, and `business_logic.md`. Those files now carry Option-A pointers to this canonical owner. Expressions remain in the owning skill where DoS is secondary (e.g., XML billion-laughs is cross-referenced from `xxe.md` which owns the broader XML-parser attack surface).

## Attack Surface

**Regex Engine Surfaces**
- Any user input processed by a regex with backtracking semantics: email validators, URL parsers, SPF/DKIM parsers, HTML/XML tokenizers, header-value validators, log-format parsers, firewall-rule compilers
- Framework-level regex application: route-matching regex, authentication regex, template-engine inline regex
- Shared middleware regex: Rails ActionDispatch Accept parsing, Express body-parser regex, Content-Security-Policy parsers

**Algorithmic Complexity Surfaces**
- Hash-table operations with attacker-controlled keys (hash flooding — CPython / PHP / Java pre-collision-resistant hashers)
- Sorting with attacker-controlled pathological input (quicksort O(n²) adversarial pivots)
- Parser quadratic/exponential behavior (XML `storeAtts`, HTTP header parsers, JSON parsers, CBOR decoders)
- Set/union operations on attacker-authored multisets
- Graph algorithms on attacker-authored graphs (dominator-tree, cycle-detection)

**Decompression Bomb Surfaces**
- HTTP request bodies with `Content-Encoding: gzip` / `br` / `deflate`
- WebSocket `permessage-deflate` extension
- File-upload paths accepting zip / rar / tar.gz / docx / xlsx
- Image decompression (PNG with large IDAT, JPEG with large dimensions, GIF with LZW, FITS)
- OCI/Docker image layer decompression
- Database import formats (Parquet, Arrow)

**GraphQL Surfaces**
- Deeply-nested query fields
- Query batching endpoint accepting arrays of queries
- Field aliasing enabling N-fold field duplication within a single query
- Introspection returning full schema
- Fragment unification with quadratic/exponential name resolution
- Subscription proliferation

**Streaming / Protocol Surfaces**
- HTTP/2 CONTINUATION flood, HEADERS flood, Rapid Reset (CVE-2023-44487), Priority flood
- WebSocket message flood, large single-frame, permessage-deflate bomb
- gRPC request flood, large request body
- SMTP recipient flood, header-count flood

**XML/JSON/CBOR Parser Surfaces**
- XML entity expansion (billion laughs, quadratic blowup)
- XML namespace attributes (quadratic parsing)
- JSON deep nesting (stack exhaustion, parser recursion)
- CBOR decoder algorithmic complexity

**Input Vectors**
- Query parameters, body fields, HTTP headers, cookies, URL path components
- GraphQL query body, variables, batched queries
- File uploads (zip, docx, xlsx, PNG, GIF, JPEG)
- WebSocket messages, SSE events, gRPC calls
- Second-order: stored attacker input processed later by a scheduled job

## Core Primitive — ReDoS (Catastrophic Backtracking)

**Primitive.** A regex with nested quantifiers or branching alternatives that match the same substring forces the engine to try exponentially many paths on a near-match input. CPU time explodes.

**Vulnerable regex patterns:**
```python
# Classic ReDoS patterns — all O(2^n) on adversarial input
r"(a+)+"           # Nested quantifier
r"(a|a)*"          # Branching alternatives matching same char
r"(a+)*$"          # Nested quantifier + anchor
r"^(([a-z])+.)+@" # Email-shaped
r"(.*a){10,}"     # Repetition on wildcard
```

**Trigger input:** `aaaaaaaaaaaaaaaaaaaaaaaaX` — 20 `a`s followed by a non-match character. Pure Python `re`, PCRE, Java `Pattern` all show the backtracking.

**Attack cost (measured elsewhere, cited):** input length n, time 2^n. On a modern CPU, n=25 is minutes; n=30 is hours; n=35 is days.

**Scope.** PCRE, Python `re`, Java `Pattern`, PHP `preg_match`, Ruby pre-3.2 `Regexp` are all backtracking-NFA engines. Rust `regex` and Go `regexp` use RE2 (automaton-based) — NOT vulnerable. Node v10+ switched to V8's irregexp which is a hybrid NFA/DFA with partial resistance; CVE-2024-26142 against ActionDispatch demonstrates the hybrid is still vulnerable.

## Algorithmic Complexity — Beyond Regex

**Primitive.** The runtime complexity of a server-side operation can be forced into its worst case by attacker-chosen input.

**Classes:**
- **Hash flooding (CPython pre-3.4, PHP pre-7.1, Java pre-15):** attacker crafts N input strings that all hash to the same bucket; hashtable operations degrade from O(1) to O(N²).
- **XML quadratic blowup (`storeAtts`, Expat CVE-2026-66046):** parser scans attribute list per attribute, O(N²) attribute processing.
- **Fragment unification (absinthe-graphql CVE-2026-43967, apollo-compiler CVE-2025-31496):** GraphQL fragment-name resolution over N fragments → O(N²) or O(N!).
- **CBOR polymorphic decode (CVE-2024-23684 upokecenter):** complex object recursion.
- **JSON number parsing:** some parsers allocate memory per digit → O(N) memory for an input number with N digits.
- **Pretty-print recursion (cJSON CVE-2026-67216):** comparing nested objects without memoization.
- **Hostname-matching regex (CVE-2024-6232 CPython tarfile):** quadratic match on header parse.

## Decompression Bombs — Measured Expansion Ratios

| Compression | Realistic max ratio | Attack recipe |
|---|---|---|
| gzip / deflate | ~1000:1 | 42KB → 42MB; nested gzip (CVE-2026-5438 Orthanc) multiplies |
| zip | ~1000:1 per entry; 42KB → ~5PB nested-zip (`42.zip`) | Nested archive with 16 levels of recursion |
| brotli | ~1000:1 (CVE-2025-6176 Scrapy) | HTTP response body with Content-Encoding: br |
| xz / lzma | ~400:1 | File upload |
| JPEG | n/a — but pixel dimensions can be huge (10000x10000 → 1GB bitmap) | SVG rasterization, PDF rendering |
| PNG IDAT | 1024:1 per IDAT chunk | Pillow CVE-2026-40192 (GZIP within FITS) |
| WebSocket permessage-deflate | 1000:1 per frame | undici CVE-2026-1526, Netty CVE-2026-42587 |

**Attack recipe (classic `42.zip`):**
```bash
# 42.zip — 42 kilobytes expanding to 4.5 petabytes
# Structure: 16 levels of nested zip archives
# Each level has 10 files
# Each innermost file is 4.3 GB of zeroes
# Total expansion: 10^16 × 4.3GB = 4.5PB
```

**Attack recipe (modern CVE-2026-42587 Netty permessage-deflate):**
```python
# WebSocket client with permessage-deflate
# Send one frame with maximum deflate compression ratio
# Netty HttpContentDecompressor accepts maxAllocation default too permissive
# Server allocates GB of memory per message
```

## GraphQL DoS

**Primitive — depth attack.** Deeply-nested queries force the resolver to walk the schema recursively.
```graphql
# Depth attack
{
  user {
    friends {
      friends {
        friends {
          # 20 levels deep
          friends { id name }
        }
      }
    }
  }
}
```

**Primitive — alias attack.** Field aliasing lets a single query duplicate expensive operations.
```graphql
{
  user1: user(id: 1) { field }
  user2: user(id: 1) { field }
  user3: user(id: 1) { field }
  # ... 10000 aliases
}
```

**Primitive — batching attack.** GraphQL batching endpoints accept arrays of queries.
```json
[
  {"query": "{ heavyField }"},
  {"query": "{ heavyField }"},
  // ... 10000 queries in one request
]
```

**Primitive — field duplication.** Within a single query, duplicate expensive fields.
```graphql
# Directus CVE-2024-39895 class
{
  heavyField
  heavyField
  heavyField
  // ... 10000 duplications
}
```

**Primitive — fragment unification.** Apollo Compiler CVE-2025-31496, absinthe-graphql CVE-2026-43967.
```graphql
# Each fragment references the next; resolution is O(N²) or exponential
fragment F1 on Query { ...F2 }
fragment F2 on Query { ...F3 }
# ...
fragment FN on Query { heavyField }
{ ...F1 }
```

**Primitive — introspection flood.** Even with introspection enabled only for dev, large schemas return megabytes of JSON per introspection query; repeated introspection is bandwidth DoS.

## Detection Channels

### Time-Based

Observe response time; a 10x-100x increase against a baseline for a given input is the ReDoS/complexity signal.
```bash
# Baseline
curl -w "@curl-format.txt" -o /dev/null -s https://target/search?q=hello
# ReDoS probe
curl -w "@curl-format.txt" -o /dev/null -s "https://target/search?q=$(python3 -c 'print("a"*30 + "X")')"
# >10 sec response = ReDoS confirmed
```

### Memory-Growth Observable

For decompression bombs, server returns 503/connection-reset after memory exhaustion.
```bash
# Decompression bomb probe
dd if=/dev/zero bs=1M count=100 | gzip > bomb.gz
curl -X POST -H "Content-Encoding: gzip" --data-binary @bomb.gz https://target/upload
# Memory-exhaustion signal: 503, connection reset, or process restart
```

### Concurrent-Request Signal

Issue N identical attack requests concurrently; observe if server becomes unresponsive for N+1-th request.

### GraphQL-Specific Signal

```bash
# Depth probe
curl -X POST -H "Content-Type: application/json" --data '{"query":"{ u { u { u { u { u { u { u { u { u { u { u { id }}}}}}}}}}}}"}' https://target/graphql
# Alias probe
# Fragment unification probe
```

## Testing Methodology

1. **Identify regex sinks.** Grep for `re.match`, `preg_match`, `Pattern.compile`, `Regex::new`. Match against known-vulnerable patterns (nested quantifiers, branching alternatives).
2. **Fuzz with pathological inputs.** `aaaa...X` style trigger payloads of increasing length; measure time per length.
3. **Identify decompression sinks.** `Content-Encoding: gzip` acceptance, zip-upload paths, image-upload paths, WebSocket permessage-deflate.
4. **Test for GraphQL endpoint.** `/graphql`, `/api/graphql`, Apollo-shaped introspection. Then probe depth/alias/batching/fragment.
5. **Identify XML/JSON parser sinks.** Billion-laughs, deep-nesting, large-attribute-list probes.
6. **Hash-flooding target identification.** Framework version + hashtable usage pattern (user-controlled keys reaching long-lived maps).

## Validation

- **ReDoS claim requires measurable time differential against baseline.** 2x is suspicious; 100x is confirmation.
- **Decompression-bomb claim requires observable server impact.** 503, timeout, memory-exhaustion log.
- **GraphQL claim requires reproducible resource consumption.** CPU spike, memory growth, slow response.
- **The attack must be externally reachable.** An admin-only sink is still a finding, but the privilege gate is explicit.

## False Positives

- A regex that LOOKS vulnerable but isn't reached by attacker input.
- A slow endpoint that is normal under baseline load (just slow, not amplified).
- A GraphQL depth response that is capped by server config (correctly limited).
- A decompression path that correctly enforces maxDecompressedSize.
- A hash-flooding claim on a framework that already migrated to SipHash (Python 3.4+, PHP 7.1+, Java 15+).

## Impact and Chaining

**Direct impact.**
- Service unavailable for other users; SLA breach.
- Rate-limiting bypass (DoS the rate-limiter itself).
- Database connection pool exhaustion.
- Backend cascade (one slow backend starves the pool for other requests).

**Upstream enablers.** User-reachable regex / decompression / GraphQL / XML / parser sinks.

**Downstream.**
- `business_logic.md` for state-exhaustion attacks (fill queues, lock resources).
- `cloud/*` for cost-amplification attacks (unlimited Lambda invocation, GPU-time exhaustion).
- `race_conditions.md` for pipeline-under-load bypasses.

**Composite chains.**
- *DoS the rate-limiter → bypass CAPTCHA → bulk-enumeration.* Route: this file → authn/BFLA.
- *Decompression bomb → memory exhaustion → process restart → session reset.* Route: this file → session-dependent downstream.
- *GraphQL batching DoS → distract SRE while another attack runs.* Route: this file → operational-cover-for-other-attacks.

## Pro Tips

- **ReDoS in a 1980s-era regex library is almost universal.** The regex itself is often fine for well-behaved input; the attacker explicitly targets backtracking.
- **A single zip file can be 42KB on-disk and 4.5PB uncompressed.** Any unbounded decompression is unsafe.
- **GraphQL batching is uncapped by default in many frameworks.** Apollo requires explicit `maxQueryDepth` and `maxBatchSize` configuration.
- **Hash flooding was mitigated in CPython 3.4+ via SipHash seed randomization.** Pre-3.4 Python apps are vulnerable; the SipHash seed is per-process-start (not per-request), so once observed via timing it can be weaponized.
- **HTTP/2 Rapid Reset (CVE-2023-44487) is DoS at the protocol layer.** Open stream + immediately RST_STREAM → trivial-cost on attacker, state-cost on server.
- **ReDoS in middleware regex (Rails Accept header CVE-2024-26142, Express body-parser) affects every endpoint.** The sink isn't per-route; it's per-request.

## Tooling

- **recheck, safe-regex, rxxr2** — static ReDoS detectors over regex patterns.
- **vacuum** — ReDoS fuzzer.
- **GraphQL Voyager, altair-graphql-client** — introspection + depth probe tooling.
- **InQL Scanner (Burp extension)** — GraphQL-specific vulnerability scanning.
- **slowloris, slowhttptest** — slow-HTTP DoS tools (legacy but still effective).
- **h2load (nghttp2)** — HTTP/2 load / Rapid-Reset testing.
- **42.zip, zipbomb.py** — classic + modern zip-bomb generators.

## Summary

Resource-exhaustion DoS is small-input-large-work asymmetry: ReDoS (nested-quantifier regex × adversarial input), algorithmic complexity (quadratic parsers, hash flooding, polynomial fragment unification), decompression bombs (gzip/brotli/zip/image/permessage-deflate), GraphQL depth/alias/batching/fragment, XML entity-expansion, protocol-level HTTP/2 Rapid Reset. The 2024-2026 frontier covers all classes: Rails ActionDispatch ReDoS (CVE-2024-26142), REXML (CVE-2024-49761), fast-xml-parser (CVE-2024-41818), Expat quadratic storeAtts (CVE-2026-66046), rsync hash_search (CVE-2026-70453), cJSON (CVE-2026-67216), Netty permessage-deflate (CVE-2026-42587), Pillow FITS GZIP (CVE-2026-40192), urllib3 streaming (CVE-2026-21441), Netty decompression (CVE-2026-42587), Apollo/Apollo-Router GraphQL (CVE-2025-31496/32030/32031/32032), apollo-compiler, absinthe-graphql fragment unification, Directus field duplication (CVE-2024-39895). The two deep siblings carry the full technique surface: `dos_resource_exhaustion_advanced_deep.md` owns per-primitive full P/P/A/C/I treatment; `dos_resource_exhaustion_novel_deep.md` owns the 2024-2026 CVE catalogue with ReDoS/compression/GraphQL/algorithmic-complexity clusters.
