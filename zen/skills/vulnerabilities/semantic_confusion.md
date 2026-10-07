---
name: semantic-confusion
description: Cross-component semantic confusion testing for parser differentials, canonicalization and normalization drift, overloaded fields, lifecycle state drift, internal redirects, protocol translation, and validator-to-sink inconsistencies across HTTP/URL/JSON/XML/YAML/MIME/multipart/ZIP/cookie surfaces
---

# Semantic Confusion

Use this skill when two or more components consume the same attacker-influenced value. The central question is not merely whether input is validated, but whether every consumer assigns the same meaning to the value at the moment it makes a security decision.

Typical chains cross a validator, router, proxy, framework, parser, filesystem, interpreter, cache, or browser. A value can be safe in one representation and dangerous after a later decode, normalization, fallback, or field mutation. The 2024–2026 academic literature establishes that parser disagreement is not an implementation defect in individual libraries but a *specification* problem — standards leave edge cases underspecified and each parser's resolution of those edges diverges, giving rise to a vulnerability class the single-parser view cannot see.

## Authorization and Safety Boundary

- Run active differentials only against explicit authorized targets. Preserve destination allowlists and set request, rate, body, response, timeout, and retry ceilings.
- Perform malformed framing, delayed-body, oversized-input, crash, or resource-exhaustion cases only in a restartable isolated lab with health monitoring.
- Use synthetic canaries, reversible actions, non-secret protected resources, or a constant per-test callback identifier. Never place target-derived secrets in an OAST label/body.
- Change one representation axis at a time so the security-relevant disagreement remains attributable to a specific boundary.
- Pair `browser_security` when the final consumer is a browser context, worker, cache, or navigation state machine.
- Do not load this skill for pure ownership drift where every component resolves and interprets the name consistently; use `infrastructure_lifecycle` unless a representation, alias, identity, or resolution-result mismatch is present.

## Core Model

Build a transformation graph before spraying payloads:

```text
raw bytes
  -> transport parser
  -> proxy / middleware representation
  -> authorization or validation decision
  -> rewrite / decode / normalization
  -> internal redirect or dispatch
  -> final sink interpretation
```

For every edge, record:

- exact input representation: bytes, string, URL, path, header list, object, or structured field
- owning component and implementation/version
- transformation performed, including error and fallback behavior
- security decision made before or after the transformation
- whether the original and transformed values remain available simultaneously
- whether a field changes semantic type, such as filename to URL or MIME type to handler

The highest-signal condition is `security_check(value_A)` followed by `sink(transform(value_A))` where the checked and consumed representations are not equivalent.

### Formal Framing

The class has a standard shape across its instances. Let `V` be the value as it enters the system, `check(V) = allow/deny` be the security decision, and `use(V')` be the consumer where `V' = T(V)` for some transformation `T`. Semantic confusion is the condition:

```text
    exists V, T such that:
        check(V) returns allow
        AND use(T(V)) performs an operation that would have been denied if the check had evaluated T(V) directly.
```

Every exploit is a witness `(V, T)` to this formula. The engineering fix must either (a) normalize to a canonical form before the check and reject non-canonical input, or (b) move the check to the sink after `T` is applied. "Validate harder before `T`" without canonicalization is structurally incomplete — the attacker's job is to find any `T` that moves `V` past the check.

## High-Value Confusion Classes

### Parser Differentials

- Compare browser, framework, proxy, library, and backend parsing of the exact same bytes.
- Test duplicate and comma-joined fields, first-match vs last-match behavior, invalid-token recovery, comments, quoting, and empty members.
- Include structured formats and metadata: URL, MIME, JSON, multipart, XML, cookies, forwarded headers, serialized objects, ZIP archives.
- Treat leniency as a security feature only when every downstream consumer is equally lenient in the same way.
- The 2024–2026 academic record establishes that major deployed parsers disagree systematically — not as individual bugs. For ZIP archives, 50 parsers across 19 languages were systematized into 14 ambiguity types with 10 novel (ZIPDIFF, USENIX Security 2025). For HTTP/1.1, over 100 parsing bugs were discovered across popular servers with 39 designated exploitable, extending request-smuggling beyond Content-Length-vs-Transfer-Encoding into header and start-line discrepancies (HTTP Garden, 2024). For JSON, 22 parsers across C/C++/Rust/Java/Python exhibit discrepancies from number/string representation to object key/value handling (ACM AsiaCCS 2024). For HTTP processing more broadly, the class was declared an open problem with no systemic defense as of October 2025 (arxiv 2510.09952). Deep-sibling material: see `semantic_confusion_advanced_deep` for the full class treatments and `semantic_confusion_novel_deep` for the 2024–2026 research grounding.

### Normalization and Canonicalization Drift

- Map percent-decoding count, Unicode conversion, slash/backslash handling, dot-segment removal, case folding, IDNA, numeric IP conversion, and filesystem cleanup.
- Compare string-prefix checks with segment-aware or origin-aware comparisons.
- Test malformed Unicode and replacement behavior; a rejected code point may become an allowed delimiter or wildcard later.
- Test path, query, and fragment separately. Browsers and routers commonly transform each source differently.
- Unicode canonicalization forms (NFC/NFD/NFKC/NFKD) each produce different byte sequences; services that normalize to one form at the edge and compare against another in the backend admit a canonicalization gap.
- IDN (Internationalized Domain Names) with Punycode encoding introduce visual-confusable domain primitives — characters that render identical in common fonts but are distinct code points (classic `а` Cyrillic vs `a` Latin). Validators that compare on Unicode strings may accept names that render deceptively.

### Field and Type Overloading

- Identify shared fields reused for different concepts: path vs URL, content type vs handler, display name vs executable name, route vs filesystem location.
- Trace every writer and reader of the field across the complete lifecycle.
- Look for implicit fallback: when the intended field is empty, another field becomes authoritative.
- Exercise fields after errors, rewrites, subrequests, retries, internal redirects, and protocol upgrades/downgrades.
- Type-juggling in loosely-typed runtimes: in PHP `"0e123" == "0"` compares as equal under `==`; in JS `[] == false`, `null == undefined`. Numerical-string coercion rules differ between PHP, JS, and strongly-typed languages — a validator written in one and a sink written in another may disagree.

### Lifecycle and State Drift

- Trigger error paths that should terminate processing and verify that later phases actually stop.
- Look for stale metadata copied into a new request, subrequest, background job, cache entry, or retry.
- Compare direct external access with internal dispatch. Edge controls may inspect the public URL while an internal resolver opens a different path or invokes a different handler.
- Test order-dependent behavior: validation before rewrite, auth before route normalization, or content classification before processing.

### Boundary Translation

- Map HTTP/2 to HTTP/1 translation, proxy to application rewriting, URL to filesystem resolution, upload detector to content consumer, and client router to API request construction.
- In a restartable lab and only when supported by evidence, vary framing, bounded delays/body sizes, content type, pseudo-headers, and method conversion. Check target health after resource-sensitive cases.
- Do not assume a WAF or authorization sidecar sees the full body or final normalized request.

### Namespace and Resolution Fallback

- Identify names resolved across multiple scopes: local path, environment `PATH`, cache, private registry, public registry, plugin directory, template search path, or autoloader.
- Record lookup order and what happens when the intended entry is missing.
- Compare protected package/module names with exposed command, binary, handler, or alias names. For npm, a scoped package can expose an unscoped `bin` name, so the protected package name and invoked executable may differ.
- Treat automatic remote fallback or search-path fallback as an execution boundary.
- Load `npx_confusion` when `npx` or `npm exec` may reinterpret a missing executable as a public package spec.

## Common Confusion Classes by Format

Each format has a short list of recurring confusion primitives — the deep sibling owns full treatments.

### URL

- Scheme coercion: `javascript:` vs `data:` vs `http:`; a URL parser rejects, string matcher accepts.
- Userinfo bypass: `http://trusted.com@attacker.com` — host-prefix check matches `trusted.com` as a substring.
- Numeric IP radix: `http://2130706433/` (decimal), `http://0x7f.0.0.1/` (hex per-octet), `http://017700000001/` (octal) — all 127.0.0.1 to some parsers, invalid to others.
- Trailing dot: `example.com.` matches `example.com` host-equality in some stacks and not others.
- Percent-encoding: `%2E%2E%2F` is `..` after one decode; some stacks decode twice.
- Fragment vs query delimiter precedence: `https://example.com?a=b#c=d&e=f` — where does the query end?
- IDN and Punycode: `http://аpple.com/` with Cyrillic `а` renders identical in common fonts but is `xn--pple-43d.com` after IDNA toASCII; validators comparing on Unicode may accept, DNS resolves differently.
- Scheme-less authority: `//example.com/` is treated as a scheme-relative URL by WHATWG but as a path by RFC 3986; a server-side URL parser may see a path, a browser-side may see a new origin.
- Backslash as path separator: Windows filesystem accepts `\\` as path separator; URL parsers nominally do not; some stacks normalize `\` to `/` before parsing (opens path-traversal — load `path_traversal_lfi_rfi`).

### JSON

- Duplicate keys: `{"role": "user", "role": "admin"}` — first-match vs last-match varies by parser; some return both.
- Number representation: `1e308` (very large), `1e-500` (effectively zero at some precision), `9999999999999999` (precision loss in IEEE 754).
- Unicode in keys: `{"a": 1, "a": 1}` where one `a` is `U+00E1` with combining — looks identical, parses as distinct keys.
- Trailing commas: some lenient parsers accept, strict parsers reject.
- `BigInt` vs `Number`: PostgreSQL `BIGINT` fields serialized as JS `Number` lose precision above 2^53.
- Unicode escapes: `"\u0000"` — null-in-string, accepted by RFC 8259 but rejected or mangled by some stacks.
- Scientific-notation integer: `"5e2"` parses as 500 in some JS consumers but as the string `"5e2"` in a stricter one.
- Empty-object vs null-object: `{"items": {}}` vs `{"items": null}` — the application may treat both as "no items" but a schema validator may require one specifically.

### XML and HTML

- External entity reference (XXE): `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` — some parsers resolve, some reject by default (parser-defaults table in `xxe`).
- Namespace confusion: HTML parsing vs XML parsing of the same byte stream in different contexts (SVG inline in HTML, MathML).
- Comment and CDATA sections: `<![CDATA[ ... ]]>` masks content from one parser but not another.
- HTML5-tree-construction state machine: `<svg><style>` and `<math><mtext>` change the parsing context, so a sanitizer that treated the content as HTML may miss SVG-parsed script execution (classic mXSS — load `xss`).
- Processing instructions: `<?xml ... ?>` and `<?php ... ?>` behave differently per parser; a stored XML document may be interpreted as PHP by a legacy processor.
- XML signature wrapping: the signed element is in one position, the processed element in another — the signature validates against moved content.

### Multipart and MIME

- Boundary confusion: multiple `Content-Type: multipart/form-data; boundary=X` — which boundary binds?
- File-type disagreement: `Content-Type` vs sniffed-type vs extension; attacker renames `malware.exe` to `safe.jpg.exe` or sets a benign `Content-Type` for a malicious payload (load `insecure_file_uploads`).
- Header-value folding: continuation lines in multipart headers (deprecated by RFC 7230 but still parsed by some stacks).
- Boundary-prefix match: a looser parser matches `--boundary` as a prefix (treating `--boundary-fake` as a boundary); a stricter one requires exact match.
- Part-count disagreement: nested multipart or malformed boundary produces different part counts between parsers.
- Content-Disposition filename encoding: `filename*=UTF-8''%E2%98%A0` (RFC 5987 encoded) vs `filename="☠"` (raw UTF-8) — some parsers prefer one, some the other.

### DNS and Hostname

- Trailing dot: `example.com.` is an absolute DNS name; `example.com` is relative. Many stacks treat them equivalently as hostnames but a strict resolver can disagree.
- IDN toASCII vs toUnicode: Punycode `xn--pple-43d` → `аpple` (Cyrillic a) via IDNA. Validators comparing on toUnicode strings may accept visually-indistinct names.
- Underscore in hostname: RFC-illegal in A-record names but accepted by many parsers; some resolvers reject.
- Case-folding: DNS is case-insensitive but SOA records and some records are case-preserving; a cache that keys on exact case may miss hits.
- Fully-qualified vs unqualified: `example` vs `example.local.` vs `example.corp.internal.` — resolver search-domain behavior differs; a service accepting unqualified names can resolve to attacker-chosen domains in environments with search-domain injection.
- Punycode-double-encoding: `xn--xn--pple-43d-abc` is an attempted double-encoding — accepted by lenient toASCII, rejected by strict.

### Date and Time Formats

- ISO 8601 timezone handling: `2026-01-01T00:00:00` (no timezone) is parsed as UTC in one stack and as local in another; a service that compares timestamps across these interpretations misorders events.
- `2026-02-29` (invalid leap-year date) is rejected by strict parsers, coerced to March 1 by lenient ones.
- Unix epoch vs ISO: a field accepting either (`1735689600` vs `"2025-01-01"`) is a differential surface — the sign of the number matters, negative epochs predate 1970.
- Format with-and-without milliseconds: `2026-01-01T00:00:00.000Z` vs `2026-01-01T00:00:00Z` — a serializer-reader pair that disagrees on precision drops a millisecond that affects deduplication.
- Non-Gregorian calendars (Islamic, Hebrew, Thai Buddhist): services operating across locales may parse the same calendar date into different absolute times.
- Daylight-saving ambiguity: `2026-11-01T01:30:00 America/New_York` is ambiguous (falls twice during fall-back); some parsers return the first occurrence, some the second, some reject.

### Query String

- Array encoding: `?a=1&a=2` vs `?a[]=1&a[]=2` vs `?a=1,2` — Rails, Django, Express, PHP, Go parse each differently.
- Dot/brace notation: `?user.name=X` vs `?user[name]=X` — PHP's `$_GET['user']['name']`, Rails's `params[:user][:name]`.
- Last-wins vs first-wins: `?a=1&a=2` — Rails takes last, PHP takes last, Node.js `querystring` keeps both as array.
- Nested empty keys: `?a[]=1&a[][]=2` — nested arrays are permitted in some stacks and rejected in others.
- URL-encoded ampersand: `?a=1%26b=2` — one key `a` with value `1&b=2`, or two keys depending on decode timing.

### Protobuf and gRPC

- Field-number encoding: protobuf fields are addressed by number; unknown fields are skipped by some stacks and surfaced to the application by others. An attacker can inject known-privileged field numbers into messages that are documented as not supporting them.
- Required vs optional: proto2 "required" removed in proto3; a service that expects "required" on a field may accept its absence under proto3.
- Oneof semantics: setting multiple fields in a oneof — later-set-wins in canonical implementations, but a non-canonical parser may accept both.
- JSON-mapping: gRPC-JSON transcoding and canonical JSON format for protobuf differ on how numeric types, enums, and oneof fields render; a service exposing both may disagree on identical semantic payloads.

### Cookie

- `__Host-` and `__Secure-` prefix: strict parsers reject, lenient parsers coerce.
- Duplicate cookies with the same name across different `Domain`/`Path`: which wins at the application layer?
- Trailing-equals in cookie values; the `=` in `name=value=extra` is value content, but some parsers truncate.

### HTTP Headers

- Comma-joined vs duplicated: `X-Forwarded-For: a, b` vs two `X-Forwarded-For:` headers.
- Header-value trimming: leading/trailing whitespace normalized by one proxy and preserved by another.
- Header folding (obsolete): `Content-Length:\n 100` — accepted by some stacks, rejected by RFC 7230.
- Chunked-encoding with Content-Length both present (request smuggling — load `http_request_smuggling`).

### YAML

- Version 1.1 vs 1.2: unquoted `yes`, `no`, `on`, `off`, `y`, `n` are booleans in 1.1 and strings in 1.2 — a serializer emitting the string "yes" produces different downstream state depending on parser version.
- Octal literals: `0777` parses as octal in some YAML libraries and decimal in others.
- Anchor and alias (`&a`, `*a`) resolution — the YAML Billion Laughs variant inflates to a resource-exhaustion primitive and some parsers resolve recursively without depth limits.
- Loose coercion: unquoted numeric strings become numbers; `"version: 1.10"` parses as a string in some libraries and as `1.1` (losing the trailing zero) in others.
- Tags: `!!python/object` triggers deserialization gadgets in PyYAML (load `insecure_deserialization`).

### ZIP Archives

- Central Directory Header (CDH) vs Local File Header (LFH): size, filename, and metadata disagreement between the two records.
- UTF-8-flag honored by some parsers and ignored by others; results in different filename interpretation.
- Nested archives: ZIP-in-ZIP, where the outer scanner reads the outer archive and the inner tool reads a different structure.
- Encrypted entries that bypass content inspection but are accepted by downstream unpackers with the password supplied out-of-band.

### CSV and Spreadsheet

- Delimiter and quoting rules differ: Excel defaults to the locale's list-separator (comma in US, semicolon in EU); import tools may assume one.
- Formula injection: a cell beginning with `=`, `+`, `-`, `@` is interpreted as a formula by Excel/LibreOffice when opened, allowing RCE via `=cmd|' /C calc'!A1` (classic) — the exported CSV is data to the server, code to the user's spreadsheet application.
- UTF-8 BOM: `﻿` at the start of a CSV may be stripped by one parser and kept as the first byte of the first field by another.
- Multi-byte quote handling: `"he said ""hi"""` → `he said "hi"` by RFC 4180; some parsers treat the embedded `""` differently.

## Specification Interpretation Gaps

The 2024–2026 academic consensus is that parser-differential vulnerabilities are rarely caused by individual implementation bugs. They are caused by specifications leaving edge cases underspecified, each parser filling the gap differently.

Mode of failure:

1. The spec defines behavior for a well-formed input.
2. The spec is silent on a specific malformed or edge-case input.
3. Each parser's author resolves the silence differently — reject, accept, canonicalize, truncate, warn, repair.
4. Two parsers in a pipeline produce different values on the same bytes.

Instances in standards:

- **RFC 7230** (HTTP/1.1) was tightened post-Desync, but still permits implementation discretion on malformed Transfer-Encoding and Content-Length combinations.
- **RFC 8259** (JSON) explicitly accepts that duplicate keys, number precision beyond 2^53, and malformed Unicode escapes are implementation-defined — the "interchange profile" is intentionally narrow.
- **RFC 3986** (URI) permits reserved characters in different positions with different meanings; percent-encoding depth and parse of userinfo+host differ between stacks.
- **WHATWG URL** diverges from RFC 3986 on dozens of edges; browser and server consequently disagree.
- **ZIP APPNOTE** supports multiple compression methods, encryption modes, and metadata-storage locations (CDH, LFH, Zip64, extra fields) without a canonicalization rule — "if CDH disagrees with LFH, use ..." is unspecified.

The engineering fix is to canonicalize before the check: parse the input to a canonical representation, reject any non-canonical bytes, pass only the canonical form forward. "Validate the input more strictly" without canonicalization is a lost game — the attacker enumerates the specification's gaps.

## Reconnaissance

### Black-Box Mapping

1. Capture a clean baseline with raw request and response bytes.
2. Change one representation axis at a time: encoding depth, delimiter, duplicate, separator, method, protocol, body framing, or Unicode form.
3. Diff status, headers, body digest/length, timing, redirects, cache state, and out-of-band callbacks.
4. Replay through different paths: direct origin vs CDN, HTTP/1.1 vs HTTP/2, public route vs alternate host, synchronous vs background processing.
5. Cluster responses by behavior before escalating. Small differentials reveal component boundaries.

### Source-Aware Mapping

- Find every read and write of shared request/context fields, not just the obvious sink.
- Trace route matching, auth middleware, rewrites, internal redirects, handler selection, and response generation in execution order.
- Inventory decode/parse/normalize calls and note whether return values or errors are ignored.
- Search for compatibility fallbacks, legacy aliases, permissive recovery, default handlers, and search-path iteration.
- Inspect packaging and deployment defaults; distro configuration, enabled modules, plugins, and symlinks often determine reachability.

## Differential Test Matrix

Build a bounded matrix from relevant axes instead of blindly combining everything:

| Axis | Representative variants |
|---|---|
| Encoding | raw, once encoded, twice encoded, mixed case, malformed Unicode |
| Structure | duplicate, comma-joined, empty member, quoted, comment-like suffix |
| Path | `/`, `\\`, `//`, dot segments, absolute, sibling-prefix collision |
| URL | userinfo, numeric IP, alternate IP radix, trailing dot, fragment/query split |
| Transport | HTTP/1.1, HTTP/2, chunked/fixed body, delayed DATA, oversized body |
| Lifecycle | normal, error, retry, internal redirect, cache hit, background worker |
| Consumer | edge, application, library, filesystem, interpreter, browser |

Select axes supported by evidence from the target. Record which component saw which representation. A full product of axes yields thousands of inputs; a focused matrix of ten carefully-chosen cases wins over a thousand random ones.

### Repeatable Harnesses

- For two local parsers, canonicalizers, or validator/consumer functions, load `hypothesis` and express the expected relationship as a property. Bound sizes/examples and keep the minimized disagreement as a regression test.
- For an ordered HTTP flow with cookies, redirects, captured values, and assertions, load `hurl` and encode vulnerable, fixed, and negative-control environments using the same request chain.
- Use raw-byte or protocol-specific harnesses when a high-level HTTP client would normalize the ambiguity away.
- Separate input generation from transport. Generators that are safe against pure local functions become active fuzzers when connected to a live target.
- For broader coverage, consult the published differential-fuzzer corpora: `narfindustries/http-garden`, `ouuan/ZipDiff`, `j-moeller/crossy` are open and reproducible.

## Testing Scope — What to Test First

Semantic-confusion surfaces are large. Prioritize:

1. **Edges with authorization checks**: any request that passes through a WAF, auth middleware, or route-matcher before reaching the application. Each layer is a candidate parser.
2. **Edges that cross protocols**: HTTP/2 to HTTP/1 downgrade in a proxy; browser URL to backend fetch; app layer to filesystem; app layer to shell.
3. **Edges with retries, async, or background processing**: the handler-at-request-time and the handler-at-worker-time are often different code paths with different parsers.
4. **Edges that fall back on error**: a specific parser rejects, triggering a generic default handler.
5. **Edges that cross tenant/user boundaries**: internal routers that trust forwarded headers from an "already-authenticated" edge.
6. **Edges in file-upload pipelines**: content-type detection (`detector`), content-type storage, content-type honored at serve (load `insecure_file_uploads`).
7. **Edges across language runtimes**: polyglot services that parse the same bytes in Python and Node and Rust often disagree on numeric types, Unicode, and date formats.

## Known Confusion Signatures

A short checklist of signatures that commonly indicate a semantic-confusion surface during initial recon:

- Response-length differs between two seemingly-equivalent inputs.
- Status code differs between HTTP/1.1 and HTTP/2 on the same URL.
- A trailing `\n`, `\r`, `.`, or space changes behavior.
- A URL with `%2F` vs `/` returns different content.
- A header with duplicate values vs comma-joined values behaves differently.
- An uploaded file is served with a Content-Type that does not match its stored metadata.
- A cookie prefixed `__Host-` is accepted on an HTTP response (should be strict).
- A JSON key appears twice in a stored object (visible on later read).
- A URL with `userinfo` is parsed as expected by the server but as a different host by the browser.
- A WAF rejects `../` but accepts `.%2E/`.
- An IP in decimal (`2130706433`) succeeds against an allowlist expecting `127.0.0.1`.

Each signature is a lead for a focused matrix.

## Observable vs Latent Confusion

Not every parser disagreement is a vulnerability. The disagreement must reach a security decision point:

- **Observable confusion**: the two interpretations differ, and the difference affects a security check or sink output. This is the vulnerability.
- **Latent confusion**: the two interpretations differ, but the second interpretation never reaches a security-relevant consumer. This is a bug but not a vulnerability.
- **Harmless-leniency**: the parser accepts non-standard input, but the downstream consumer rejects or canonicalizes before use. This is defense-in-depth and not a finding.

The test is always: does the attacker-controlled interpretation reach a sink that would have been protected by the pre-decode check?

## Measurement — The Load-Bearing Deliverable

A measured parser differential is stronger evidence than any CVE citation:

- **Observed, not asserted**: run the input through both components and record the actual output byte-for-byte.
- **Pair with the version**: parser behavior changes between versions; a 2024-recorded differential may not reproduce on a 2026 release.
- **Minimize the input**: the final finding is the smallest input that produces the discrepancy. A one-byte difference is more credible than a 2 KB payload.
- **Document the environment**: OS, locale, Unicode-ICU version, compiler flags — all can shift parser behavior.
- **Keep the negative result**: if the differential does not reproduce on a current version, that is a measured finding (version boundary identified).

For the deep sibling's full technique treatments and the 2024–2026 academic measurements, see `semantic_confusion_advanced_deep` and `semantic_confusion_novel_deep`.

## Chaining Strategy

Treat the first differential as a primitive, then ask what authority the later consumer has:

- auth or ACL bypass -> protected route or file
- path/URL confusion -> source disclosure, SSRF, local socket, or unintended handler
- detector/consumer mismatch -> active upload processing or inline browser execution
- internal redirect state carryover -> handler selection or policy bypass
- search-path or namespace fallback -> attacker-controlled code resolution
- browser/router decode -> client-side path traversal, CSRF-like action, SSRF, or XSS sink

Enumerate existing local gadgets only after the primitive is proven. Prefer generic classes such as interpreters, template engines, debug tools, package scripts, local sockets, and autoload paths over a vendor-specific file list. Load the sibling skill that owns the chained class — `ssrf`, `path_traversal_lfi_rfi`, `http_request_smuggling`, `insecure_file_uploads`, `xxe`, `rce`, `browser_security`.

## Testing Methodology

1. **Define the invariant** - State what all components are expected to agree on: origin, path, type, handler, identity, length, or package name. "All consumers of this URL agree on its host" is a testable invariant; "the URL is valid" is not.
2. **Draw the graph** - List consumers and transformations in real execution order.
3. **Locate early decisions** - Mark validation, auth, WAF, cache, and routing checks.
4. **Locate late meaning changes** - Mark decodes, rewrites, fallback, internal dispatch, and sink parsing.
5. **Build a focused matrix** - Exercise only transformations supported by the stack.
6. **Isolate the disagreement** - Produce paired inputs that differ at one boundary and explain both interpretations.
7. **Prove the primitive safely** - Use a synthetic protected canary, reversible marker, constant callback identifier, or no-op handler whose behavior and side effects are understood.
8. **Escalate by capability** - Track Read -> influence -> write -> dispatch -> execute transitions with evidence and prerequisites for every edge.
9. **Cross-check versions/configurations** - Reproduce on a fixed version or hardened configuration when possible.

## Validation

A valid confusion finding should include:

1. the exact bytes or structured input supplied
2. the representation observed by the security control
3. the different representation observed by the final consumer
4. the transformation or lifecycle event that created the difference
5. paired control and exploit results across repeat runs
6. version, protocol, configuration, and interaction prerequisites
7. a minimal impact proof that does not depend on unrelated undefined behavior
8. a measured demonstration — raw bytes in, raw bytes out, at every component boundary

## False Positives

- Different error messages with identical final authorization and sink behavior
- A parser accepts odd syntax but downstream consumers preserve the same safe meaning
- A normalization difference visible only in logs, with no security decision between representations
- WAF bypass where the application itself rejects the request identically
- Version-specific behavior claimed as universal without testing the relevant deployment
- A search-path candidate that is attacker-named but cannot be created, claimed, loaded, or executed
- A parser-differential finding where the "second interpretation" never reaches a sink — the component that disagrees is not a security decision point

## Framework-Specific Expression

Semantic-confusion primitives surface in frameworks under framework-specific shapes. Keep this skill's class framing and route framework-specific details to:

- `django_python` for Django URL dispatcher and Django's cookie / Content-Type coercions.
- `rails_ruby` for Rails `request.params` type-juggling and nested-parameter coercion.
- `express_node` for Express body-parser quirks and `req.query` behavior.
- `spring_java` for Spring's content negotiation, path-variable extraction, and matrix-parameter parsing.
- `aspnet_dotnet` for the model-binder's cultural coercions and routing precedence.
- `nextjs` for the Next.js router's path-decoding, server-component vs client-component split.

Confusion in a framework typically arises where the framework normalizes before the application sees the value and the application later re-processes the raw request. Load the framework file for the specific decode-and-re-decode pattern.

## Standards and Prior-Art Mapping

- **CWE-436 Interpretation Conflict** names the class generically; sub-weaknesses CWE-179/180/181/182 cover specific normalization issues.
- **RFC 3986 (URIs)** leaves several edge cases underspecified; parser disagreement on these edges is a recurring surface.
- **WHATWG URL Living Standard** diverges from RFC 3986 in several places; a browser's URL parser (WHATWG) and a server's URL parser (RFC 3986) therefore disagree systematically on inputs like `//`, trailing dots, and percent-decoding depth.
- **RFC 7230/9112 (HTTP/1.1)** was explicitly tightened to narrow parser-differential surface after HTTP Desync research but still leaves implementation latitude on malformed input.
- **RFC 8259 (JSON)** acknowledges in §4 that implementations differ on duplicate keys, number precision, and parsing of structures beyond the "interchange" subset.
- **Unicode TR#15 Normalization** and **TR#36 Unicode Security Considerations** are the authoritative references for canonicalization and confusable-script issues.

## Measurement Script Patterns

Semantic-confusion findings earn their rigor from measurement. Core patterns:

- **Two-parser oracle in one process**: install both parsers as libraries, feed the same bytes to each, assert equivalence; a Hypothesis property-test reduces to a minimal disagreement.
- **Request-pair against a live target**: send the same request body with each of two framings (HTTP/1 and HTTP/2, two different content-types) and record every byte of each response.
- **Reflect-and-echo**: a service that echoes a field value in its response is a free oracle — see which representation lands in the echo.
- **Cache-side-channel**: a stored value that is read on a later request lets you observe the final interpretation after storage normalization.
- **File-upload-and-serve**: upload a file through the controlled endpoint; download it and inspect the served Content-Type, filename, and content.

Persist every measurement script under the batch artifact directory alongside the raw byte captures. Later audits need the exact input bytes, not the explanation.

## Pro Tips

1. Begin with relationships and shared state, not endpoint payload lists.
2. Preserve raw traffic; high-level clients often normalize away the exploit before sending it.
3. Error paths are alternate lifecycles. Verify which fields survive and which phases still execute.
4. Compare direct and internal access separately; ingress policy rarely governs framework file IO or handler dispatch.
5. When a prefix allowlist is used, test a sibling sharing the prefix and verify with a segment-aware comparison.
6. Distinguish presence, reachability, and impact. Each needs separate evidence.
7. Generalize a finding by naming the disagreement class, not by copying its final payload.
8. Measure before asserting. The strongest evidence is raw bytes in, raw bytes out, with both parsers under version control.
9. The specification is sometimes the bug — document when the standard itself is underspecified.

## Summary

Semantic confusion exists when a security decision and a privileged consumer disagree about the meaning of the same attacker-influenced data. Model the entire transformation lifecycle, isolate one disagreement at a time, and prove both interpretations with measured byte-for-byte evidence. The reusable unit is the boundary and its invariant — not a CVE-specific string. For full technique treatments across URL, JSON, XML, YAML, MIME/multipart, cookie, HTTP, and ZIP, load `semantic_confusion_advanced_deep`; for the 2024–2026 academic grounding (ZIPDIFF, HTTP Garden, JSON differential, HTTP Request Synchronization) and the open-problem frontier, load `semantic_confusion_novel_deep`.
