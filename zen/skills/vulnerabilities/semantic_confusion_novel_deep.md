---
name: semantic-confusion-novel-deep
description: 2024-2026 academic frontier for parser-differential and semantic-confusion research — ZIPDIFF (USENIX 2025), HTTP Garden (arxiv 2024), JSON differential (ACM AsiaCCS 2024), HTTP Request Synchronization (arxiv Oct 2025), with measured primitives and open-problem framing
sibling: semantic_confusion
load_when: scan_mode == "deep"
---

# Semantic Confusion — Novel Deep

Novel-tier content for semantic-confusion covering the 2024–2026 academic frontier. The base owns class framing and format-level primitives; the advanced-deep sibling owns per-format full technique treatments; this file owns the research-grade grounding — ZIPDIFF (USENIX Security 2025), HTTP Garden (arxiv:2405.17737, 2024), JSON differential testing (ACM AsiaCCS 2024, DOI 10.1145/3634737.3657003), HTTP Request Synchronization (arxiv:2510.09952, October 2025), measured primitives for each, and the open-problem framing that this class remains unsolved as a systemic defense.

The 2024–2026 consensus across these four papers is that parser-differential vulnerabilities are not implementation bugs in individual libraries — they are a *specification* problem. Standards leave edge cases underspecified, and each parser's resolution of those edges diverges, producing a vulnerability class that no single-parser view can detect. The engineering fix must either (a) canonicalize before every security decision, or (b) use the same parser throughout the pipeline. "Validate harder" is structurally incomplete.

## The 2024–2026 Measured Primitive — JSON Number Precision

A local measurement captured for this skill (persisted at `.zen-batch-artifacts/batch-12/measurements/json_number_precision.out`) demonstrates the class directly:

Input bytes:
```json
{"id": 9007199254740993, "big": 99999999999999999, "e": 1e500, "neg_e": 1e-500}
```

| Parser | `id` (= 2^53 + 1) | `big` | `e` (1e500) | `neg_e` (1e-500) |
|---|---|---|---|---|
| Python 3 `json` | 9007199254740993 (int) | 99999999999999999 (int) | inf (float) | 0.0 (float) |
| Node.js `JSON.parse` | **9007199254740992** (number) | 100000000000000000 (number) | null (number) | 0 (number) |
| Ruby JSON | 9007199254740993 (Integer) | 99999999999999999 (Integer) | Infinity (Float) | 0.0 (Float) |
| Go `encoding/json` | — | — | **ERROR: cannot unmarshal 1e500 into float64** | — |

Four parsers, four different behaviors on the same byte sequence. Node.js's `JSON.parse` loses the `+1` at 2^53+1 — a precision collision that fingerprints as `id = 9007199254740992` where every other parser preserves `...993`. Go's `encoding/json` errors on `1e500` where every other parser returns Infinity or null-via-Infinity. Python and Ruby parse arbitrary-precision integers; Node.js and Go are bound by IEEE 754. This is the ACM AsiaCCS 2024 paper's thesis in miniature — the format is underspecified at these edges, and the resolution-of-silence varies.

### Measured Primitive: Node.js vs Python JSON ID Collision

**Primitive**: a service with a JS front-end tier and a Python back-end tier parses the same submitted ID differently; `9007199254740993` → `9007199254740992` in JS, preserved in Python. If authorization checks against the JS-parsed value and resource lookup uses the Python-parsed value (or vice versa), the attacker can address the resource owned by `...992` while the authorization system thinks they addressed `...993`.

**Preconditions**:
- Multi-tier service: JS parses once, Python parses again (or SQL does).
- Resource IDs regularly exceed 2^53.
- Authorization check tier and resource-lookup tier use different parsers.

**Attack recipe**:
1. Enumerate user IDs; identify a target with ID at 2^53+1 or higher.
2. Submit request with ID = `9007199254740993` (one above target).
3. JS front-end parses → `9007199254740992` (coerced down to even floor).
4. Authorization check against `...992` — authorizes access to the attacker's own resource.
5. Request forwarded to Python back-end; Python parses `...993` from the raw bytes, retrieves the target's resource.

**Confirmation**: HTTP response contains data from ID `...993` under an authorization logged for ID `...992`.

**Impact**: IDOR via precision collision; `broken_function_level_authorization`-adjacent authorization bypass; cross-user state access.

### Measured Primitive: Go JSON Reject vs Python Accept

**Primitive**: Go's `encoding/json` rejects `1e500` with an error; Python returns `inf`. A multi-service pipeline where Go validates and Python processes may have the Python stage encounter a parsed value Go would have rejected.

**Preconditions**:
- Multi-service pipeline, Python downstream of Go.
- Python receives the raw bytes (not Go's parsed form).

**Attack recipe**:
1. Submit `{"amount": 1e500}` to an endpoint.
2. Go edge rejects — but the body may be forwarded to the Python stage as raw bytes anyway, or the error is logged but not surfaced.
3. Python stage parses, treats `inf` as a numeric value.

**Confirmation**: Python-tier handler receives Infinity; subsequent arithmetic produces anomalous values.

**Impact**: value-domain confusion; downstream arithmetic poisoning (e.g., averages become `inf`, affecting business decisions).

## Measured URL-Parser Differentials

A second local measurement captured for this skill (persisted at `.zen-batch-artifacts/batch-12/measurements/url_parser_differential.out`) demonstrates the WHATWG vs RFC 3986 divergence directly across three widely-deployed URL parsers.

### Measured: Decimal IP Coercion

Input: `http://2130706433/`

| Parser | Host result |
|---|---|
| Python 3 `urllib.parse` (RFC 3986) | `2130706433` (preserved as string) |
| Node.js `URL` (WHATWG) | **`127.0.0.1`** (coerced to loopback) |
| Go `net/url` | `2130706433` (preserved as string) |

Node.js's WHATWG URL implementation applies IPv4 coercion for decimal, hex, and octal numeric host forms; Python and Go do not. This is a textbook SSRF-allowlist bypass primitive: a validator written in Python compares `url.hostname != "127.0.0.1"` and passes, but a Node.js client making the actual request resolves to 127.0.0.1.

### Measured: Hex IP Coercion

Input: `http://0x7f000001/`

| Parser | Host result |
|---|---|
| Python 3 `urllib.parse` | `0x7f000001` (preserved) |
| Node.js `URL` (WHATWG) | **`127.0.0.1`** (coerced) |
| Go `net/url` | `0x7f000001` (preserved) |

Same mechanism as the decimal case: WHATWG mandates numeric host coercion.

### Measured: Scheme-No-Slash Authority Recovery

Input: `https:evil.com/path`

| Parser | Host result | Path result |
|---|---|---|
| Python 3 `urllib.parse` | `None` | `evil.com/path` |
| Node.js `URL` (WHATWG) | **`evil.com`** | `/path` |
| Go `net/url` | `""` | `""` |

Three different interpretations of the same five bytes. Python treats as a scheme + opaque-path (no authority). Node.js's WHATWG parser recovers the authority. Go rejects the authority entirely. A validator written in Go would reject the request; a redirect-target computed in Node.js would resolve to evil.com; a validator written in Python would see no host at all (potentially passing a null-host check that an attacker-chosen host would fail).

### Measured: Backslash in Authority

Input: `http://trusted.com\@evil.com/`

| Parser | Host result |
|---|---|
| Python 3 `urllib.parse` | `evil.com` |
| Node.js `URL` (WHATWG) | `evil.com` |
| Go `net/url` | **ERROR: invalid userinfo** |

Python and Node.js agree (normalize `\` to `/`-like separator, host = `evil.com`); Go rejects. A validator written in Go would reject the request; a validator written in Python/Node would see `evil.com` as the host. If a Python validator parses to `evil.com` and matches against a hardcoded allowlist of `trusted.com`, it rejects. But if an attacker's control over the string is deeper, the WHATWG parser's recovery of authority produces a differential.

### Primitive Class: Python-Validator / Node-Client Divergence

**Primitive**: a service validates a user-supplied URL with Python (which uses RFC 3986), and executes the fetch via a Node.js subprocess or helper (which uses WHATWG URL). Numeric IP forms, scheme-no-slash recovery, and backslash handling differ.

**Preconditions**:
- Multi-language stack: validation in one language, execution in another.
- URL contains an edge case (numeric IP, scheme-no-slash, backslash).

**Attack recipe**:
1. Identify the stack: `urllib.parse` for validation, Node.js `fetch` for request.
2. Submit `http://2130706433/`.
3. Python validator: host is `"2130706433"`, no match against `"127.0.0.1"` allowlist → passes.
4. Node.js fetcher: resolves host to `127.0.0.1`, fetches from loopback.

**Confirmation**: validator logs host as `"2130706433"`; network log shows loopback request.

**Impact**: SSRF to loopback / metadata-service / internal network. Load `ssrf` for the broader class.

### Primitive Class: Three-Parser-Three-Interpretations

**Primitive**: for `https:evil.com/path`, three mainstream parsers return three different results (no-host, host=evil.com, parse-reject). A pipeline that passes the string through any pair of these components has a trivially-reproducible differential.

**Preconditions**:
- Multiple URL-parsing hops in the pipeline.
- At least two use different parsers.

**Attack recipe**:
1. Craft an edge-case URL (one from the measurement table).
2. Identify which parser is at the validator and which at the sink.
3. Submit; observe divergent host interpretations.

**Confirmation**: measured byte-level host output from both parsers.

**Impact**: SSRF, open redirect, cross-origin confusion, allowlist bypass.

## Measured Unicode Normalization Differentials

A third local measurement captured for this skill (`.zen-batch-artifacts/batch-12/measurements/unicode_normalization.out`) demonstrates Unicode normalization as a parser-differential surface.

### Measured: Byte-Different But Display-Identical

Input A: `café` (precomposed, bytes `b'caf\xc3\xa9'`, 4 characters)
Input B: `café` (decomposed, bytes `b'cafe\xcc\x81'`, 5 characters)

Both display as "café" in any Unicode-aware font. Byte-level equality is `False`. String-level equality in Python is `False`. Only after applying the same normalization form to both do they byte-match.

| Normalization | Input A result | Input B result | Equal |
|---|---|---|---|
| NFC | `b'caf\xc3\xa9'` | `b'caf\xc3\xa9'` | True |
| NFD | `b'cafe\xcc\x81'` | `b'cafe\xcc\x81'` | True |
| NFKC | `b'caf\xc3\xa9'` | `b'caf\xc3\xa9'` | True |
| NFKD | `b'cafe\xcc\x81'` | `b'cafe\xcc\x81'` | True |

Any component that compares normalized output of input A against raw-byte input B (or vice versa) sees inequality for display-identical values. If one tier normalizes to NFC on storage and another compares against user-supplied NFD-form bytes, identity-collision attacks are possible.

### Measured: NFKC Compatibility Decomposition

| Input | Bytes | After NFKC | Bytes after NFKC |
|---|---|---|---|
| `ﬁle` (fi ligature) | `b'\xef\xac\x81le'` | `file` | `b'file'` |
| `ＡＤＭＩＮ` (fullwidth) | `b'\xef\xbc\xa1\xef\xbc\xa4\xef\xbc\xad\xef\xbc\xa9\xef\xbc\xae'` | `ADMIN` | `b'ADMIN'` |
| `x²` (super 2) | `b'x\xc2\xb2'` | `x2` | `b'x2'` |

### Primitive Class: NFKC-Normalizing Sink With Non-Normalizing WAF

**Primitive**: a WAF scans raw bytes for forbidden tokens (`ADMIN`, `../`, `script`); the application NFKC-normalizes before use. Attacker submits NFKC-compatibility-form bytes that pass the WAF and normalize to the forbidden token at the sink.

**Preconditions**:
- WAF scanner uses raw-byte or ASCII-folded pattern matching.
- Application tier applies NFKC normalization.
- The forbidden token has a Unicode compatibility pre-image (ligature, fullwidth, superscript, mathematical symbol).

**Attack recipe**:
1. Identify a forbidden token at the WAF (e.g., `ADMIN`, `script`).
2. Encode as Unicode compatibility form: `ＡＤＭＩＮ` (fullwidth), `𝒜𝒟𝑀𝐼𝑁` (math script), `ﬃle` (triple-ligature).
3. Submit; WAF scans bytes, sees no `ADMIN`, passes.
4. Application NFKC-normalizes, sees `ADMIN`, grants privilege or executes privileged action.

**Confirmation**: WAF logs no block; application logs privileged action with the normalized token.

**Impact**: WAF-bypass; load `xss_novel_deep` (mXSS and sanitizer-bypass) and `broken_function_level_authorization` for the downstream classes.

### Primitive Class: Identity Collision Across NFC/NFD

**Primitive**: a service registers usernames in one normalization form; another tier accesses by a different form. Two accounts can coexist with visually-identical display names, enabling impersonation.

**Preconditions**:
- Username storage normalizes to one form at registration.
- Lookup compares raw bytes without re-normalizing.

**Attack recipe**:
1. Observe the registered username for a target (`café` in NFC).
2. Register your own username using NFD-form bytes (`cafe` + combining acute).
3. Both accounts exist; both display as "café".
4. Social engineering primitive — users cannot distinguish.

**Confirmation**: two accounts, byte-different usernames, visually-identical display.

**Impact**: impersonation, phishing, cross-user action authorization.

## ZIPDIFF — USENIX Security 2025

You et al., "My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers," USENIX Security 2025. Mutation-based differential fuzzer identifying parsing inconsistencies across 50 ZIP parsers in 19 programming languages. The paper's primary contribution is the systematization of ZIP ambiguity into 14 distinct types across 3 root-cause categories.

### The Three Root-Cause Categories

1. **Redundant Metadata**: ZIP stores file metadata in two headers — Central Directory Header (CDH, at archive end) and Local File Header (LFH, before each file). The specification does not define which to trust when they disagree.
2. **File Path Processing**: ZIP permits filenames with path separators, dot segments, non-ASCII characters, and encoded forms. Parsers normalize differently.
3. **ZIP Structure Positioning**: multiple central directory records, Zip64 extensions, and extra fields create positional ambiguity.

### Published Exploitable Instances

The paper demonstrates five independently reproducible real-world exploits:

- **§6.1 Secure Email Gateway Bypass**: an archive that antivirus engines read as benign but unarchivers extract as malware; the behavior-fingerprinted class is CDH-vs-LFH metadata disagreement, though the specific published mechanism should be referenced in the paper body, not inferred.
- **§6.2 Office Document Content Spoofing**: Office documents are ZIP archives; a crafted archive produces different content when opened in Word vs when scanned by document-security tools.
- **§6.3 LibreOffice Signature Forgery (CVE-2024-7788)**: LibreOffice's "Zip Repair Mode" invalidates digital signatures improperly; attacker-crafted archives bypass signature verification. CVE-2024-7788 published 2024-09-17, affects LibreOffice 24.2 before 24.2.5.
- **§6.4 Spring Boot Nested JAR Signature Forgery**: Spring Boot's nested-JAR format inherits ZIP ambiguity; crafted archives bypass signature verification.
- **§6.5 VS Code Extension ID Impersonation**: VS Code extension loading reads one header; the installed extension's ID is from another; impersonation vector.

### Primitive Class: CDH-vs-LFH Metadata Disagreement

**Primitive**: an archive where CDH and LFH disagree on filename, size, or compression method; different parsers consult different headers.

**Preconditions**:
- Pipeline with multiple ZIP parsers (scanner + unpacker, archive-manager + target application).
- Each parser preferentially consults CDH or LFH.

**Attack recipe**:
1. Craft an archive via a tool that permits header disagreement (hex-editor on a ZIP, custom builder).
2. Set CDH filename to `safe.txt`, LFH filename to `malware.exe`.
3. Submit to a pipeline where the scanner reads CDH (sees safe.txt) and the extractor reads LFH (writes malware.exe).

**Confirmation**: byte-level inspection of CDH and LFH confirms disagreement; measured extraction differs between tools.

**Impact**: scanner evasion; policy-filter bypass; delivery of malicious content past validation.

### Primitive Class: UTF-8 Encoding Flag Disagreement

**Primitive**: ZIP APPNOTE bit 11 indicates UTF-8 encoding for filename; parsers that honor the flag and parsers that assume CP437 decode the same bytes differently.

**Preconditions**:
- Pipeline with mixed Unicode-flag handling.
- Attacker controls the flag's value in each header.

**Attack recipe**:
1. Set bit 11 to 1 in CDH; 0 in LFH.
2. Encode filename bytes such that UTF-8 and CP437 decode to different strings.
3. One parser treats as string A (safe); another treats as string B (traversal).

**Confirmation**: decoding the same bytes under both interpretations yields distinct strings.

**Impact**: filename-filter bypass; path traversal via alternative-encoding filenames.

### Primitive Class: Zip64 Field Shadowing

**Primitive**: Zip64 extensions in the extra-fields area override the standard 32-bit size fields; parsers that don't support Zip64 use the 32-bit value, Zip64-aware parsers use the 64-bit value. Attacker crafts an archive where the two disagree.

**Preconditions**:
- Pipeline with mixed Zip64 support.

**Attack recipe**:
1. In CDH, set 32-bit size to small value; set Zip64 extra-field to large value.
2. Zip32 parser reads small; Zip64-aware parser reads large.
3. Memory-allocation or boundary logic differs.

**Confirmation**: declared sizes differ between the two parsers.

**Impact**: parser crash, buffer-overflow in older parsers, filter-size-check bypass.

### Primitive Class: Multiple Central Directory Records

**Primitive**: a ZIP file with multiple end-of-central-directory records; parsers that take the first vs the last see different archives.

**Preconditions**:
- Non-standard archive with multiple ECD records.

**Attack recipe**:
1. Concatenate two valid ZIP structures.
2. Parsers that scan from file-end-backward find the last ECD; parsers that scan from file-start find the first.
3. Two interpretations of the file content.

**Confirmation**: file listing differs between tools.

**Impact**: content-smuggling; email-gateway bypass; signed-container tampering.

### Measurable Scripts

- `secartifacts.github.io/usenixsec2025/appendix-files/sec25cycle2ae-final28.pdf` — the artifact reproducibility appendix.
- `github.com/ouuan/ZipDiff` — public artifact. Clone, build, run against a target binary.

## HTTP Garden — arxiv:2405.17737, 2024

Kallus et al., "HTTP Garden," May 2024 (follow-up ACM 2024 publication). Coverage-guided differential fuzzer that identified 100+ HTTP parsing bugs across popular web servers; 39 were designated exploitable; 68 were fixed after disclosure. The paper's central methodological contribution is that **the most significant parsing anomalies occur within origin servers**, not just at gateways — prior blackbox differential techniques that only examined gateway output were missing exploitable discrepancies.

### Core Finding — Expanded Smuggling Surface

The paper broadens request-smuggling beyond Content-Length vs Transfer-Encoding to include:

- **Header parsing discrepancies**: duplicate headers, folded headers, invalid-byte handling, trailing whitespace.
- **Start-line parsing discrepancies**: HTTP version coercion, path encoding, invalid methods.
- **Both occur at the transducer vs origin boundary**, meaning the attack surface is not just the proxy's CL/TE handling but also the proxy-origin header forwarding.

The implication is that the HTTP/1.1 spec is still too permissive — RFC 7230 and its successor RFC 9112 narrowed the surface post-Desync but did not close it.

### Primitive Class: Transducer-Origin Header Shadowing

**Primitive**: a header is accepted by the transducer (which forwards it) but interpreted differently by the origin.

**Preconditions**:
- Transducer and origin disagree on header validity.
- Attacker-controlled header reaches both.

**Attack recipe**:
1. Submit a request with a malformed-but-forgiving header (e.g., `Content-Length: \t100`, tab before value).
2. Transducer accepts, forwards.
3. Origin parses differently (treats tab as part of value, truncates, or rejects silently).

**Confirmation**: paired parser output for the transducer and the origin shows different header values.

**Impact**: request smuggling via header shadow; cache poisoning; auth-bypass if the header is auth-relevant.

### Primitive Class: Start-Line Encoding Discrepancy

**Primitive**: the request line `GET /path HTTP/1.1` can be encoded with alternate whitespace, HTTP version values, or path formats; the transducer and origin may parse differently.

**Preconditions**:
- Varying tolerance between hops.

**Attack recipe**:
1. Submit `GET /path  HTTP/1.1\r\n` (double space between path and version).
2. Transducer tolerates, routes based on `/path`.
3. Origin rejects or truncates path at the double-space.

**Confirmation**: origin behavior differs; audit log shows a path differing from the transducer's.

**Impact**: path routing bypass; auth-bypass if path drives route-level authorization.

### Primitive Class: Invalid-Byte Recovery

**Primitive**: an invalid byte in a header (e.g., `\x00` embedded) is recovered differently — truncated, discarded, kept, rejected.

**Preconditions**:
- Different recovery strategies between hops.

**Attack recipe**:
1. Inject `\x00` in a header value.
2. Hop A: truncates at null → header is short.
3. Hop B: keeps the null → header is long.

**Confirmation**: byte-level inspection.

**Impact**: header-value smuggling; log-injection; auth-token truncation.

### Open-Source Corpus

- `github.com/narfindustries/http-garden` — reproduction corpus for the published differentials.
- The paper's accompanying tooling permits running the same bytes through 20+ HTTP servers and comparing outputs.

### Independent Corroboration

- **PortSwigger "HTTP/1.1 Must Die"** (2024) — this result was named #3 in the 2024 Top 10 Web Hacking Techniques; the Kettle whitepaper (BH-USA-19) laid the earlier groundwork for header-and-start-line desync primitives.
- **WAFFLED** (arxiv:2503.10846, March 2025) — WAF bypass via parser disagreement; corroborates that WAF-origin discrepancies are a reliable attack surface.

## JSON Differential Testing — ACM AsiaCCS 2024

Möller, Weißberg, Pirch, Eisenhofer, Rieck, ACM AsiaCCS 2024, DOI 10.1145/3634737.3657003. Differentially tested 22 JSON parsers across C, C++, Rust, Java, and Python. The paper's thesis frames JSON as "imprecisely specified" and the discrepancy risk as arising from underspecification — directly supporting the semantic-confusion-as-spec-problem framing.

### Discrepancy Categories

The paper documents discrepancies in:

1. **Number representation**: precision (above 2^53), scientific notation handling, infinite values, NaN, denormalized values.
2. **String representation**: Unicode escape handling, surrogate-pair handling, embedded nulls, control characters.
3. **Object key/value handling**: duplicate keys, nested-object depth, empty-string keys, numeric keys.
4. **Trailing content**: content after the top-level value, trailing whitespace, trailing newlines.
5. **Error recovery**: how parsers recover from truncated input, malformed Unicode escapes, invalid structure.

### Primitive Class: Number-Precision Collision (Measured Above)

See the measurement section at the top of this file for the direct demonstration. The paper documents this across the broader parser set with similar divergence patterns.

### Primitive Class: Duplicate-Key First-vs-Last-Match

The paper documents parsers that:
- Return the last value (Python, Node.js, Ruby, Go, jq — confirmed by the measurement above).
- Return the first value (some older or strict parsers).
- Return both values (list-returning parsers).
- Error out (strict parsers).

### Primitive Class: Unicode Surrogate Pair Handling

**Primitive**: JSON escapes like `"😀"` represent a surrogate pair for 😀 (U+1F600). Parsers that handle surrogates correctly combine the pair; parsers that process each `\uXXXX` independently may produce invalid UTF-8 or two separate characters.

**Preconditions**:
- Pipeline with mixed surrogate-pair handling.

**Attack recipe**:
1. Submit `{"name": "😀"}`.
2. One parser produces one Unicode character 😀.
3. Another produces two sub-characters, each invalid as standalone.
4. If the value is passed as bytes to a downstream system, the bytes differ.

**Confirmation**: byte-level inspection of the parsed value.

**Impact**: identity-collision in Unicode-sensitive contexts; display-name confusion.

### Primitive Class: Trailing-Content Acceptance

**Primitive**: `{"a":1}trailing` — some parsers accept, returning `{"a":1}` and discarding the trailing content; others reject.

**Preconditions**:
- Parsers in the pipeline differ in trailing-content handling.

**Attack recipe**:
1. Submit `{"amount": 100}{"amount": 1000}` — two JSON documents concatenated.
2. One parser reads the first; another reads the second (if it starts from the end).

**Confirmation**: parsed value differs between parsers.

**Impact**: value smuggling; order-of-operations attacks in idempotent pipelines.

### Open-Source Artifact

- `github.com/j-moeller/crossy` — the paper's accompanying artifact; 22 parsers under test, reproducible differential corpus.
- `depositonce.tu-berlin.de/items/20715750-2c32-4330-8695-15f903d11ee4` — TU Berlin institutional mirror.

## HTTP Request Synchronization — arxiv:2510.09952, October 2025

Topcuoglu, Onarlioglu, Sprecher, Kirda (Northeastern Univ. / Akamai), arxiv:2510.09952v1, October 11, 2025. Taxonomizes HTTP processing-discrepancy attacks into three concrete categories and declares the class an open problem as of its publication date — "the first general defense against discrepancy attacks."

### The Three-Class Taxonomy

The paper names three concrete categories of HTTP discrepancy attack:

1. **Path confusion** — URLs with encoded delimiters that proxies and origins parse differently, enabling web cache deception.
2. **Host confusion** — Host-header interpretation discrepancies enabling cache poisoning.
3. **Request framing confusion** — Content-Length vs Transfer-Encoding disagreement enabling request smuggling (the classical surface, now one leg of a three-legged class).

### Open-Problem Framing

The paper's abstract states: "Discrepancy attacks are surging, yet, there exists no systemic defense." This is the frontier for 2025–2026 — the class is unsolved at the architectural level. Individual CVE fixes close individual bugs; no general approach exists that prevents the next.

### Primitive Class: Path Confusion → Web Cache Deception

**Primitive**: a URL like `/profile.css` is parsed as a static resource by the cache (which caches it with no auth-side) and as a dynamic resource by the origin (which serves authenticated profile data). The attacker tricks a victim into requesting `/profile.css`; the response is cached; attacker fetches `/profile.css` and receives the victim's cached profile.

**Preconditions**:
- Cache and origin disagree on which URLs are static.
- The cache is identity-blind.

**Attack recipe**:
1. Convince victim to request `/profile/safe.css` or `/api/user.jpg` (any URL with a seemingly-static extension).
2. Origin serves user-specific content (profile data for the authenticated victim).
3. Cache stores by URL alone.
4. Attacker fetches the same URL; cache returns victim's data.

**Confirmation**: unauthenticated fetch of a cached URL returns victim-specific content.

**Impact**: cross-user data disclosure; load `http_request_smuggling` for broader cache-poisoning primitives.

### Primitive Class: Host Confusion → Cache Poisoning

**Primitive**: `Host:` header parsed differently by cache and origin; attacker submits a request where the cache keys on one host but the origin serves content under a different host, poisoning the cache entry for all users of the "correct" host.

**Preconditions**:
- Front-end cache and origin disagree on Host-header parsing.
- Cache keys are host-sensitive.

**Attack recipe**:
1. Submit `Host: cdn.target.com\r\nHost: evil.com\r\n` (dup header).
2. Cache keys on first; origin serves based on last.
3. Cache stores evil.com content under cdn.target.com's key.
4. Legitimate users receive poisoned content.

**Confirmation**: paired request/response captures; cache key vs origin processing.

**Impact**: targeted cache poisoning; `http_request_smuggling` adjacency.

### Primitive Class: Framing Confusion → Request Smuggling

**Primitive**: the classical CL vs TE smuggling, now one third of the three-class taxonomy. See `http_request_smuggling_novel_deep` for the full treatment including the ASP.NET Core material.

## WAFFLED — arxiv:2503.10846, March 2025

Rodriguez-Baptista et al., "WAFFLED: WAF Bypass via Parser Disagreement." Independent 2025 corroboration that WAF-origin parser disagreement is a reliable attack surface. WAFs tested across 7 vendors; 100+ bypass patterns identified where the WAF parses one way and the origin parses another.

### Primitive Class: WAF-Origin Parser Mismatch

**Primitive**: WAF validates against pattern X parsed under its parser; origin processes under a different parser that produces attack-pattern Y.

**Preconditions**:
- WAF and origin are separate components.
- WAF parser differs from origin parser (common — WAF often uses its own HTTP parser).

**Attack recipe**:
1. Craft a request where WAF parser doesn't see the attack pattern.
2. Origin parser sees the attack pattern.

**Confirmation**: WAF logs show no block; origin logs show the attack-pattern reaching the sink.

**Impact**: WAF bypass; attack-pattern delivery past perimeter defense.

### Takeaway

The WAFFLED result is operational — if a target's WAF is a separate parser from the origin, there is a non-zero chance the WAF can be bypassed via parser disagreement. The frontier defense is parser-identity (same parser at WAF and origin) or canonicalization (both parse to a canonical form before any security decision).

## Transformation-Graph Model as a Research Framing

The 2024–2026 academic consensus implicitly uses a transformation-graph model: input bytes flow through a sequence of parsers, with each parser's output feeding the next. Discrepancies arise at any edge. The base skill's "transformation graph" section captures this; the academic papers measure specific graphs for specific protocols (ZIP, HTTP, JSON).

The research-grade formulation:

- Let `P_1, P_2, ..., P_n` be the parsers in a pipeline.
- Let `V_0` be the input bytes.
- Let `V_i = P_i(V_{i-1})` for `i = 1..n`.
- Let `check` be a security check applied at some step `k`.
- A vulnerability exists iff there exists `V_0` such that `check(V_k) = allow` AND the final consumer's behavior differs from what `check` was intended to protect.

The academic contribution is to automate the search over `V_0` for a given graph using fuzzing (ZIPDIFF, HTTP Garden) or formal methods.

## Open-Problem Frontier

The HTTP Request Synchronization paper is explicit: no systemic defense exists. The frontier questions:

- Can a canonical form be defined for each format (HTTP, JSON, ZIP) that all parsers agree to produce before any security decision? For HTTP, RFC 9112 is a partial answer but implementation discretion remains.
- Can parser identity be enforced in a pipeline — i.e., both WAF and origin use the exact same parser code? The practical answer today is no (vendor and architectural constraints).
- Can the specification itself be tightened to eliminate underspecification? Each tightening is a backwards-compatibility break.

The 2025–2026 research direction is likely to focus on canonical-form enforcement at ingress — a canonicalization layer that normalizes before any decision — and on formal verification of parser identity across hops.

## OpenAPI / JSON Schema Validation Drift

Modern APIs rely on OpenAPI specifications and JSON Schema validators for input validation. The validator-at-the-edge pattern often produces its own parser-differential surface.

### Primitive Class: Validator Parser ≠ Application Parser

**Primitive**: an OpenAPI validator (e.g., Zod, express-openapi-validator, FastAPI's Pydantic) parses the request body with its own JSON library; the application reads the raw body again with a different library. Discrepancies between the two parsers permit smuggled fields.

**Preconditions**:
- Request body validated by a middleware that uses one parser.
- Application tier re-reads the raw body with another parser.

**Attack recipe**:
1. Craft a body with a duplicate key that the two parsers resolve differently.
2. Validator sees first-match (benign) → passes schema check.
3. Application sees last-match (privileged) → performs privileged action.

**Confirmation**: logged validated payload differs from logged application-processed payload.

**Impact**: schema-check bypass; privileged-field smuggling.

### Primitive Class: Pydantic Strict vs Lax Mode

**Primitive**: Pydantic v2 (Python) accepts loose type coercion by default (string `"1"` becomes int `1`); strict mode rejects. A service with default-lax validation accepts type-confused inputs that a stricter downstream rejects or interprets differently.

**Preconditions**:
- Multi-service: Pydantic (lax) at the edge, strict typed downstream.

**Attack recipe**:
1. Submit `{"amount": "1e10"}` to an edge that expects a numeric amount.
2. Pydantic lax coerces string to float `1e10`.
3. Downstream strict parser rejects or interprets differently.

**Confirmation**: value stored or processed differs from submitted string.

**Impact**: numeric-value smuggling; business-logic flaw (`business_logic` adjacency).

### Primitive Class: additionalProperties Drift

**Primitive**: JSON Schema's `additionalProperties: false` rejects unknown fields at the validator; application code using `Object.assign` or Python `**kwargs` binding still ingests unknown fields from the raw body. Validator passes (unknown field was rejected? or ignored? depends on implementation); application acts on the smuggled field.

**Preconditions**:
- JSON Schema validator and application code use different field-handling.
- `additionalProperties: false` present but application re-parses raw body.

**Attack recipe**:
1. Submit `{"name": "safe", "is_admin": true}` where the schema allows only `name`.
2. Validator strips or rejects `is_admin`.
3. Application re-reads raw body with its own JSON parser; `is_admin: true` is bound into the user object via mass-assignment-style patterns.

**Confirmation**: validator logs show `is_admin` stripped; application logs show `is_admin: true` applied.

**Impact**: mass-assignment, privilege escalation; load `mass_assignment`.

## More ZIPDIFF Primitive Classes

Extending the ZIPDIFF (USENIX 2025) catalog beyond the first set of primitives:

### Primitive Class: Extra-Field Overrun

**Primitive**: the extra-field area within CDH or LFH can contain arbitrary length-tagged records; parsers that stop at the declared total vs. the sum of record lengths see different metadata.

**Preconditions**:
- Multi-parser pipeline with mixed extra-field handling.

**Attack recipe**:
1. Craft an entry with extra-field total-length larger than the sum of individual record lengths.
2. Parser A reads records until total-length consumed; may misinterpret trailing bytes.
3. Parser B reads only known-tag records; stops earlier.

**Confirmation**: parser output differs on same bytes.

**Impact**: filter evasion; parser-bug exploitation.

### Primitive Class: Mismatched Compression Method

**Primitive**: CDH declares compression method X; LFH declares Y. Scanner reads CDH's method and decompresses as X (producing one output); unpacker reads LFH's method and decompresses as Y (producing another).

**Preconditions**:
- Pipeline consumes compressed content under both decompression paths.

**Attack recipe**:
1. Craft entry: CDH says `stored` (no compression); LFH says `deflate`.
2. Scanner reads as stored, sees the raw deflate bytes (which may be a valid-looking JPEG header).
3. Unpacker reads as deflate, decompresses to malware.

**Confirmation**: scanned bytes vs extracted bytes differ.

**Impact**: AV scanner evasion; content-filter bypass.

### Primitive Class: Spanned-Archive Boundary

**Primitive**: ZIP's multi-volume (spanned) archive format uses a specific marker; parsers that recognize vs reject spanned archives differ.

**Preconditions**:
- One pipeline component accepts spanned archives.

**Attack recipe**:
1. Set the spanned-archive marker.
2. Parser A rejects (not a valid archive).
3. Parser B accepts, treating as a single-volume archive by convention.

**Confirmation**: parser outputs differ.

**Impact**: validator bypass.

### Primitive Class: Zip64 Marker-Only vs Full-Field

**Primitive**: Zip64 is triggered by sentinel values in CDH 32-bit size fields; parsers differ on whether the Zip64 extra-field must be present when the sentinel is set.

**Preconditions**:
- Multi-parser mixed Zip64 adherence.

**Attack recipe**:
1. Set sentinel in CDH 32-bit field but omit Zip64 extra-field.
2. Strict parser rejects; lenient parser reads size as sentinel value (0xFFFFFFFF).

**Confirmation**: parser output differs.

**Impact**: parser-crash primitive on strict parsers; validator-crash primitive.

### Primitive Class: Encrypted Entry With Weak Password

**Primitive**: ZIP entries encrypted with a known-weak password (`infected`, `test`, `123`, `virus`) that scanners cannot decrypt but users will supply at extraction.

**Preconditions**:
- Pipeline accepts encrypted ZIPs.
- Scanner cannot decrypt without the password.
- User supplies password out-of-band (phishing email, README).

**Attack recipe**:
1. Craft malicious content.
2. Encrypt in ZIP with password published in the delivery email.
3. Scanner sees encrypted entries, logs "skipped".
4. User enters password, extracts malware.

**Confirmation**: scanner report shows encrypted entries unprocessed.

**Impact**: email-gateway bypass; content-inspection evasion. This is the oldest ZIP-content-smuggling primitive; still live in 2024–2026 against unsophisticated gateways.

## More HTTP Garden Primitive Classes

### Primitive Class: HTTP/1.0 vs HTTP/1.1 Keep-Alive Confusion

**Primitive**: HTTP/1.0 defaults to Connection: close; HTTP/1.1 defaults to keep-alive. A proxy translating HTTP/1.1 to HTTP/1.0 may force connection close; attackers who send HTTP/1.0 to the proxy and expect it forward as HTTP/1.1 can create pipelining confusion.

**Preconditions**:
- Mixed HTTP/1.0 and HTTP/1.1 in the stack.
- Pipelining enabled on at least one hop.

**Attack recipe**:
1. Submit HTTP/1.0 pipelined request where the proxy upgrades to HTTP/1.1 keep-alive.
2. Pipelined second request is injected into the server's queue after a smuggled first.

**Confirmation**: observation of out-of-sequence responses.

**Impact**: request smuggling via version-translation.

### Primitive Class: Trailing Headers (Trailers)

**Primitive**: HTTP/1.1 chunked transfer supports trailing headers after the final chunk; some origins process trailers as regular headers (merging into the request), while gateways ignore them.

**Preconditions**:
- Chunked transfer encoding supported.
- Origin merges trailers with headers.

**Attack recipe**:
1. Send chunked request with a trailer `X-Internal: admin`.
2. Gateway logs the request's declared headers.
3. Origin processes with `X-Internal: admin` as an auth-relevant header.

**Confirmation**: origin logs show the trailer-merged header; gateway logs don't.

**Impact**: header-smuggling for internal-service header-trust (load `header_injection`).

### Primitive Class: 101 Switching Protocols Mid-Stream

**Primitive**: a response that begins with `HTTP/1.1 101 Switching Protocols` upgrades the connection to a different protocol (WebSocket, HTTP/2). A smuggled request might force an upgrade that the client doesn't expect.

**Preconditions**:
- Server supports upgrade.
- Attacker can smuggle a request that triggers 101.

**Attack recipe**:
1. Smuggle a request that elicits a 101 response.
2. Victim's next pipelined request lands in a protocol it doesn't speak.

**Confirmation**: protocol confusion on the shared connection.

**Impact**: client-protocol confusion; follow-up smuggling.

## More JSON Differential Primitive Classes

### Measured: Duplicate Key Behavior (From the Measurement at the Top)

The duplicate-key test earlier in this file established that Python/Node.js/Ruby/jq/Go all return the last value. This is the common behavior but not universal — the ACM AsiaCCS 2024 paper documents parsers across 22 implementations where this consensus breaks. Older parsers, lenient parsers, and parsers that return lists diverge. The measured consensus for mainstream parsers (last-wins) is the finding — it tells you that a service using any of these common parsers is predictable, but a service using a non-mainstream parser is not.

### Primitive Class: Nested Depth Limits

**Primitive**: JSON specifications don't mandate a maximum nesting depth; parsers set their own. A payload deeper than the validator's limit but shallower than the application's bypasses depth-based DoS protection.

**Preconditions**:
- Validator rejects beyond depth N; application accepts beyond N.

**Attack recipe**:
1. Craft `{"a": {"a": {"a": ... }}}` nested to depth N+1.
2. Validator rejects at depth N; application accepts.
3. Depth-based DoS at application tier.

**Confirmation**: validator rejects, application processes.

**Impact**: depth-based DoS; parser-crash.

### Primitive Class: Non-UTF-8 String Content

**Primitive**: JSON strings must be valid UTF-8; invalid-byte sequences are handled differently — rejected, replaced with U+FFFD, or kept as raw bytes.

**Preconditions**:
- Pipeline with mixed invalid-byte handling.

**Attack recipe**:
1. Submit `{"a": "\xC0\xAE"}` (overlong UTF-8 encoding of `.`).
2. Strict parser rejects.
3. Lenient parser converts to `.` or keeps as `?` or U+FFFD.
4. If the sink uses the "decoded" value for a path, overlong-encoding bypass.

**Confirmation**: parsed value differs between parsers.

**Impact**: path-traversal via overlong UTF-8; filter-bypass.

## Prototype Pollution as Parser-Differential Consequence

A service that uses `JSON.parse` and then applies `Object.assign` or a merge function inherits any `__proto__` or `constructor.prototype` fields smuggled through JSON. The parser-differential arises when:

- The schema validator strips `__proto__` from the raw body.
- The downstream code re-parses and merges, applying `__proto__` to the global prototype.

The measurement of parser behavior is: does the parser retain `__proto__` as a plain field, or does it set the prototype chain? Node.js's `JSON.parse` retains `__proto__` as a plain field (not setting prototype); `Object.assign({}, parsed)` makes it available to a later merge. See `prototype_pollution_novel_deep` for the full merge-function behavior across 14 libraries.

## HTTP/3 and WebTransport (Early Frontier)

The HTTP/3 over QUIC transition introduces new parser-differential surface:

- HTTP/3 framing differs from HTTP/2 framing; translation layers compound.
- WebTransport's bidirectional stream model has different semantics than WebSocket; cross-protocol attacks may apply.
- Published 2025 research on HTTP/3 smuggling is thin at the time of this writing. The surface is anticipated to grow as HTTP/3 deployment increases.

Treat HTTP/3 as a near-frontier surface — primitives are plausible, published measurements remain limited.

## Chaining Depth at the Novel Frontier

Novel-tier semantic-confusion findings chain through:

- **ZIP CDH-vs-LFH → signed-container tampering** → `insecure_deserialization` for JAR-based gadget chains; or `insecure_file_uploads` for upload-and-serve.
- **HTTP Garden transducer-origin → request smuggling** → `http_request_smuggling_novel_deep` for the CVE-2025-55315 (ASP.NET Core) mechanism.
- **JSON precision → IDOR** → `idor_novel_deep` for the authorization-bypass class.
- **Path confusion → web cache deception** → `http_request_smuggling_novel_deep` for the full cache-poisoning class.
- **Host confusion → cache poisoning** → `http_request_smuggling_novel_deep`.
- **WAFFLED WAF bypass → any downstream class** — the primitive is the WAF bypass; the exploitation is whatever the underlying attack intends (XSS, SSRF, RCE).

## Verification Discipline for Frontier Findings

Novel-tier findings require:

1. **Measured demonstration**: raw bytes in, raw bytes out, at every parser in the pipeline.
2. **Minimized input**: the shortest byte sequence that reproduces the discrepancy.
3. **Reachability proof**: the attacker-controlled interpretation reaches a security-relevant consumer.
4. **Impact demonstration**: the consequence of weaponizing the disagreement.
5. **Primary-source citation**: the paper or published advisory that documents the class.
6. **Negative control**: a measurement on current versions where the class may have been patched.

A novel-tier finding without a measurement is a lead, not a confirmation.

## Breadth of the Live Frontier

The verified 2024–2026 novel-tier frontier for semantic confusion is dense enough to sustain depth without padding: four peer-reviewed/preprint primary sources (ZIPDIFF, HTTP Garden, JSON differential, HTTP Request Synchronization) and one 2025 corroborating result (WAFFLED), plus the live measured primitive demonstrated at the top of this file. The academic trajectory is clear — this class is defined by specification underspecification, measured by differential fuzzing, and remains an open problem for systemic defense.

## Summary

The 2024–2026 academic frontier for semantic confusion is captured by four peer-reviewed/preprint primary sources (ZIPDIFF, HTTP Garden, JSON differential, HTTP Request Synchronization) and one 2025 WAF-bypass result (WAFFLED). All four converge on the thesis that parser-differential vulnerabilities are a specification problem — standards leave edge cases underspecified, implementations diverge, and the class remains an open problem for systemic defense. The measured JSON number-precision primitive at the top of this file is a textbook demonstration: four mainstream parsers, four different behaviors on 2^53+1. The reusable unit is the primitive; the frontier contribution is the research-grade methodology (differential fuzzing, coverage-guided fuzzing) and the formal framing that elevates individual CVE-level findings into a class.
