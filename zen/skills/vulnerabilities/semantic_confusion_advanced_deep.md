---
name: semantic-confusion-advanced-deep
description: Advanced parser-differential and canonicalization exploitation — full technique treatments for URL, Unicode/IDN, path, JSON, XML/HTML, YAML, MIME/multipart, cookie, HTTP header, ZIP, and date-time surfaces with measured differentials
sibling: semantic_confusion
load_when: scan_mode == "deep"
---

# Semantic Confusion — Advanced Deep

Full technique treatments for the parser-differential and canonicalization-drift primitives named by the base skill. The base owns the class framing (transformation graph, 7-axis matrix, format classes, standards mapping); this file owns per-format Primitive / Preconditions / Attack recipe / Confirmation / Impact at depth. Load `semantic_confusion_novel_deep` for the 2024–2026 academic grounding (ZIPDIFF, HTTP Garden, JSON differential, HTTP Request Synchronization) and the research-grade open-problem framing.

Each primitive below is reusable — the vulnerability is the parser-disagreement class, not the specific payload. Measurement is load-bearing: raw bytes in, raw bytes out, with both parsers under version control.

## URL Parser Differentials

### Primitive: WHATWG vs RFC 3986 Host-Parsing Divergence

**Primitive**: a URL that two components parse with different hosts. The security check sees host A; the request lands at host B.

**Preconditions**:
- One component uses WHATWG URL semantics (browsers, Node.js `URL`, Go `net/url` with WHATWG mode).
- Another uses RFC 3986 (Python `urllib.parse`, Java `java.net.URL`, Go `net/url` without WHATWG).
- The check-component and the use-component are different.

**Attack recipe**:
1. Craft a URL with ambiguous host: `http://evil.com\\@trusted.com/`, `http://trusted.com#@evil.com/`, `https://evil.com\\.trusted.com/`.
2. Submit through the security-check component.
3. Observe which host it parses.
4. The use-component may parse the other host.

**Confirmation**: measurement script with both parsers; one returns `host=evil.com`, the other `host=trusted.com`.

**Impact**: SSRF bypass of allowlist checks (`ssrf`); open-redirect bypass of host validators (`open_redirect`); cookie-sending to attacker-controlled host (session hijack).

### Primitive: Userinfo-as-Hostname

**Primitive**: `http://trusted.com@attacker.com/path` — the userinfo is `trusted.com`, the host is `attacker.com`. String-prefix validators match on `trusted.com` while URL parsers correctly identify `attacker.com`.

**Preconditions**:
- Validator uses `url.startswith("http://trusted.com")` or `trusted.com in url` without parsing.
- Downstream uses a real URL parser.

**Attack recipe**:
1. Submit `http://trusted.com@attacker.com/`.
2. The naive validator passes.
3. The fetcher resolves to `attacker.com`.

**Confirmation**: fetcher's DNS query is for `attacker.com`; HTTP request lands at attacker.

**Impact**: SSRF, open redirect, data exfiltration via the "trusted" URL.

### Primitive: Numeric IP Radix Differentials

**Primitive**: `127.0.0.1` can be written as `2130706433` (decimal), `0x7f000001` (hex), `017700000001` (octal), `127.1` (truncated), `0x7f.1` (mixed), `127.0.1` (3-octet). Different parsers accept different subsets.

**Preconditions**:
- Validator checks a specific textual form (`127.0.0.1`, `localhost`, `0.0.0.0`).
- Downstream resolver accepts a broader form.

**Attack recipe**:
1. Enumerate the broader-accepting resolver's valid forms (measure with a local probe).
2. Pick a form the validator does not match.
3. Submit; the downstream resolves to the loopback.

**Confirmation**: validator returns "safe"; downstream connects to 127.0.0.1 (observed via local socket or metadata response).

**Impact**: SSRF to loopback despite a textual loopback allowlist; metadata-service reachability (load `ssrf` for IMDS specifics).

### Primitive: Percent-Encoding Depth Mismatch

**Primitive**: `/api/..%2Fadmin` is `/api/../admin` after one decode, or `/api/..%2Fadmin` kept as-is. A proxy that decodes once and an application that decodes once more see different paths.

**Preconditions**:
- Two components in the path handle percent-decoding independently.
- Decode steps vary (proxy decodes before routing; application decodes before serving).

**Attack recipe**:
1. Submit `/public/..%2Fadmin`.
2. Proxy decodes once → `/public/../admin` → routes based on `/public/`, allowed.
3. Application decodes once more or canonicalizes → `/admin` → serves admin.

**Confirmation**: paired response: an "allowed" status on the proxy's log and an admin resource served.

**Impact**: authorization bypass, path traversal, access to internal routes. Load `path_traversal_lfi_rfi`.

### Primitive: Trailing-Dot and Case-Fold Host Equality

**Primitive**: `example.com.` (with trailing dot) matches `example.com` for DNS and most URL parsers but may not match `host == "example.com"` in a string allowlist. Similarly `Example.Com` may match or not depending on case-folding.

**Preconditions**:
- String-equality host check without case-fold or trailing-dot normalization.
- Downstream resolver accepts the un-normalized form.

**Attack recipe**:
1. Submit URL with `example.com.` or `Example.Com`.
2. Validator string-compares to `example.com` and may reject (bypass through mixed-case) or accept (bypass through trailing-dot).

**Confirmation**: paired string-compare vs URL-parse-and-compare.

**Impact**: allowlist bypass; cross-origin confusion in cookie-domain-matching.

### Primitive: Scheme Masquerade

**Primitive**: a scheme-matching regex that accepts `http` or `https` also accepts `httpa` or `https:x` depending on anchoring. A URL parser rejects or coerces; a string matcher accepts.

**Preconditions**:
- Scheme check via `startswith("https:")` or regex like `^http[s]?://`.
- Attacker can supply a URL that passes the regex but is a different scheme downstream.

**Attack recipe**:
1. `https:evil.com/` — scheme is `https`, no `//`; some parsers accept this with authority = `evil.com`, some don't.
2. `httpa://evil.com/` — regex with `http[a]?://` accepts, URL parser treats as unknown scheme.
3. `javascript://ok/%0aalert(1)` — the `//` makes it look like a URL for a line-based validator; browser executes as `javascript:` scheme.

**Confirmation**: parser output varies between validator and sink.

**Impact**: open redirect, XSS via `javascript:`, SSRF to a scheme the validator didn't anticipate (gopher, dict, file).

### Primitive: Backslash Normalization

**Primitive**: `http://example.com\@evil.com/` — a backslash where WHATWG expects a forward slash; some parsers normalize `\` to `/` before further parsing, others treat the backslash as part of the userinfo.

**Preconditions**:
- WHATWG parser normalizes `\` to `/`.
- Non-WHATWG parser does not.

**Attack recipe**:
1. Submit `http://trusted.com\@evil.com/`.
2. One parser: userinfo = `trusted.com\`, host = `evil.com`.
3. Other parser: host = `trusted.com`, path = `\@evil.com/`.

**Confirmation**: measurement; two different host values.

**Impact**: open redirect, SSRF, allowlist bypass.

## Unicode and IDN Normalization

### Primitive: NFC/NFD/NFKC/NFKD Form Differential

**Primitive**: Unicode text can be stored in four canonical forms; two components normalize to different forms and compare on different byte sequences.

**Preconditions**:
- Validator normalizes to one form (e.g., NFC); storage normalizes to another (e.g., NFD).
- Comparison is byte-level.

**Attack recipe**:
1. Register username `café` as NFC (precomposed `é`).
2. Login via a path that normalizes to NFD (`cafe` + combining acute); comparison fails.
3. Attacker registers `cafe` + combining acute separately; both resolve to same display name.
4. Impersonation primitive.

**Confirmation**: two accounts with visually-identical names; measurement shows different stored byte sequences.

**Impact**: account impersonation; display-name hijack; CSRF-like consent on visually-identical accounts.

### Primitive: NFKC Compatibility Decomposition

**Primitive**: NFKC decomposes compatibility characters: ligatures `ﬁ → fi`, superscripts `²→2`, Hangul composition. A validator that compares post-NFKC and a sink that doesn't see different values.

**Preconditions**:
- Validator applies NFKC; sink does not.
- The resource name space treats the decomposed and compatibility characters distinctly.

**Attack recipe**:
1. Submit a URL with a compatibility character: `/admin/ﬁle` (ligature `ﬁ`).
2. The validator NFKC-decomposes to `/admin/file` and may reject.
3. If the sink uses the raw bytes, it looks up `/admin/ﬁle` which may be unregistered.
4. Alternatively, the inverse: the sink NFKC-normalizes but the validator does not.

**Confirmation**: raw bytes in request vs resource looked up.

**Impact**: resource hiding, authorization bypass through name-space confusion.

### Primitive: IDN Homograph Attack

**Primitive**: internationalized domain names use Punycode (`xn--...`) via IDNA; characters that render identically in common fonts can produce visually-identical domains with different Punycode encodings.

**Preconditions**:
- UI displays the Unicode form of a domain to the user.
- Browser/resolver resolves the Punycode form.
- Attacker can register the homograph domain.

**Attack recipe**:
1. Register `xn--pple-43d.com` (Cyrillic а apple.com) with a legitimate CA.
2. Serve a phishing site.
3. User sees `apple.com` in the address bar; actual resolution is Cyrillic.

**Confirmation**: browser displays visually-identical hostname; `host` header is the Punycode form or the Cyrillic form (depending on browser).

**Impact**: phishing, trust abuse. Modern browsers warn when a mixed-script label is used in a TLD where the script is not expected, but validators that don't apply the browser's heuristic can still be fooled.

### Primitive: Right-to-Left Override

**Primitive**: `U+202E` (RLO) reverses display order. A filename `exe.cod` becomes `doc.exe` visually when RLO is embedded.

**Preconditions**:
- UI preserves bidirectional control characters.
- The user interprets the displayed name as the actual name.

**Attack recipe**:
1. Craft a filename: `benign‮gpj.exe` → displays as `benignexe.jpg` to the user.
2. Deliver through a channel that preserves the raw bytes.
3. User double-clicks thinking it's a jpg; OS launches as exe.

**Confirmation**: raw bytes of filename differ from displayed name.

**Impact**: user-deception, malicious-file execution.

### Primitive: Case-Fold Dot-All

**Primitive**: Turkish-locale case-folding of `I` → `ı` (dotless) and `i` → `İ` (dotted). A locale-aware comparison in one component and a locale-naive one in another produce different equality.

**Preconditions**:
- One component uses `toLowerCase()` with locale-aware folding; another uses invariant folding.
- Attacker can control locale (e.g., `Accept-Language: tr`).

**Attack recipe**:
1. Submit `ADMIN` in a Turkish-locale request.
2. Locale-aware fold → `admın` (dotless i); comparison to `admin` fails.
3. If one checkpoint is locale-aware and the other is not, authorization bypasses.

**Confirmation**: paired case-fold output.

**Impact**: authorization bypass; privilege-boundary confusion.

## Path Canonicalization

### Primitive: Dot-Segment Removal Order

**Primitive**: `/public/../private` is `/private` after dot-segment removal. One component removes before authorization check; another removes after.

**Preconditions**:
- Path arrives at validator with dot-segments present.
- Validator checks prefix (`/public/`) before removal.
- Downstream canonicalizes before resource lookup.

**Attack recipe**:
1. Submit `/public/../private`.
2. Validator sees `/public/`, allows.
3. Downstream canonicalizes to `/private`, returns private content.

**Confirmation**: validator path vs served path.

**Impact**: path traversal (load `path_traversal_lfi_rfi`); authorization bypass.

### Primitive: Backslash-As-Separator on Non-Windows

**Primitive**: a path `/public\../private` is one segment on Linux, but a cross-platform tool normalizes `\` to `/` before processing, yielding dot-segment traversal.

**Preconditions**:
- Service runs on Linux (uses `/` as separator).
- A library in the stack is cross-platform-aware and normalizes `\`.

**Attack recipe**:
1. Submit `/public\../private`.
2. First handler: one segment `/public\../private`; validator may pass if it only checks `/public/` prefix segment-aware.
3. Cross-platform library: normalizes to `/public/../private`; dot-segment removes to `/private`.

**Confirmation**: paired path handling.

**Impact**: path traversal.

### Primitive: Null Byte Truncation

**Primitive**: `/safe.txt\0.jpg` — a path with embedded null. C-style string handlers truncate at the null; language-aware handlers do not. If a validator sees `.jpg` extension and the filesystem call sees `.txt`, extension-based authorization bypasses.

**Preconditions**:
- Mixed C-and-managed stack (C filesystem call, managed-language validator).
- Null byte permitted in the path.

**Attack recipe**:
1. Submit `/safe.txt\x00.jpg`.
2. Managed validator sees `.jpg` extension, allows.
3. C-level `open()` truncates at null, opens `.txt`.

**Confirmation**: path opened differs from path validated. Modern Python and Node reject nulls in paths; this primitive now mostly applies to legacy stacks and specific framework configurations.

**Impact**: file-type validator bypass, path escape, upload-filter bypass (load `insecure_file_uploads`).

### Primitive: Multi-Slash and Empty-Segment Normalization

**Primitive**: `//public///file` — multiple slashes. Normalization behavior differs: Apache collapses to `/public/file`, Nginx preserves, Django treats `//` as path-start of a different URL in some version. A per-component path-identity differential arises.

**Preconditions**:
- Multiple normalization-aware components in the stack.
- Multi-slash permitted in input.

**Attack recipe**:
1. Submit `//admin///something`.
2. Edge normalizes; application sees different path.
3. Allowlist on `/admin/` may fail to match `//admin/` string-wise.

**Confirmation**: edge-log path vs app-log path differ.

**Impact**: authorization bypass; cache poisoning if cache key normalizes differently from backend.

## JSON Differentials

### Primitive: Duplicate Key First-vs-Last-Match

**Primitive**: `{"role": "user", "role": "admin"}` — RFC 8259 says parsers "SHOULD" return an error or the last value, but implementations differ: some return the first, some the last, some both, some neither (error).

**Preconditions**:
- Service's JSON parser and schema validator differ in duplicate-key handling.
- Attacker can submit duplicate-key JSON (not blocked by WAF).

**Attack recipe**:
1. Submit `{"role": "user", "role": "admin"}`.
2. Schema validator sees first-match (`role: user`), passes.
3. Application processes last-match (`role: admin`), privileged action.

**Confirmation**: measurement of both parsers' output. The 2024 ACM AsiaCCS 2024 JSON-differential-testing paper documented 22 parsers across C/C++/Rust/Java/Python with discrepancies at this edge.

**Impact**: role escalation, authorization bypass, privileged-field smuggling.

### Primitive: Number-Precision Collision

**Primitive**: `9999999999999999` (16 nines) exceeds IEEE 754 double precision; parsing to a double yields `10000000000000000`. If one parser preserves string, another coerces to double, equality tests disagree.

**Preconditions**:
- Service compares a user-supplied numeric field to a stored value.
- Comparison path uses one coercion rule; storage path uses another.

**Attack recipe**:
1. Submit `{"account_id": 9999999999999999}`.
2. API deserializes to double → `10000000000000000`.
3. Database stores `10000000000000000`.
4. Later retrieve by `account_id = 9999999999999999` → matches due to float coercion in query.

**Confirmation**: value stored differs from value submitted; later retrieval by the submitted value matches the stored (different) value.

**Impact**: cross-user resource lookup (`idor`-adjacent); state corruption; precision-loss financial impact.

### Primitive: Unicode-Escape Normalization

**Primitive**: `"Admin"` = `"Admin"` after decode. A WAF scans for `admin` as literal; the parser produces `Admin` which matches a role check.

**Preconditions**:
- WAF or validator scans raw JSON for keyword strings without decoding.
- Downstream parser applies Unicode escape resolution.

**Attack recipe**:
1. Submit `{"role": "Admin"}`.
2. WAF sees `A...` and does not match `admin`.
3. Parser returns `Admin`.

**Confirmation**: raw bytes vs parsed string.

**Impact**: WAF bypass; role-string smuggling.

### Primitive: BigInt vs Number Collision

**Primitive**: PostgreSQL `BIGINT` IDs exceed 2^53; JavaScript's default `Number.parseInt` loses precision above 2^53. A service that uses JS at one tier and SQL at another may return different IDs for the same input.

**Preconditions**:
- Multi-tier service (JS frontend/backend, SQL database).
- IDs regularly exceed 2^53.

**Attack recipe**:
1. Request resource ID `9007199254740993` (2^53 + 1).
2. JS coerces to `9007199254740992`.
3. SQL stores or retrieves the coerced value.
4. The user who owns ID `...993` has their resource returned to attacker who requested `...993`.

**Confirmation**: ID submitted differs from ID returned by one tier.

**Impact**: cross-user resource access; IDOR-adjacent.

## XML and HTML Differentials

### Primitive: XML Namespace Context Confusion

**Primitive**: `<svg><style>...</style></svg>` embedded in HTML parses as foreign-content; the `<style>` inside SVG does not restart HTML parser's style-escape rules.

**Preconditions**:
- Sanitizer processes HTML.
- Content includes SVG embedded with payload inside `<svg>`.
- Browser's HTML5 parser follows the state-machine spec correctly.

**Attack recipe**:
1. Inject `<svg><style>&lt;/style&gt;&lt;script&gt;alert(1)&lt;/script&gt;</style></svg>` with sanitizer-active rules on `<script>`.
2. Sanitizer-processed; `<script>` not re-detected in SVG foreign-content.
3. Browser processes: SVG foreign-content → `<style>` → closes early → `<script>` executes.

**Confirmation**: HTML sanitized output includes `<svg>...<script>...</script></svg>`; browser renders with script execution.

**Impact**: mXSS (mutation XSS); load `xss` for the broader HTML sanitization-differential class.

### Primitive: XML External Entity Within Allowlisted Doctype

**Primitive**: XXE through doctype that passes a shallow allowlist check.

**Preconditions**:
- XML parser accepts DTD processing.
- Allowlist validates document element but not DTD content.

**Attack recipe**:
1. Submit XML with `<!DOCTYPE allowed-root [<!ENTITY x SYSTEM "file:///etc/passwd">]><allowed-root>&x;</allowed-root>`.
2. Allowlist sees `allowed-root` as the root element.
3. Parser resolves `&x;` entity.

**Confirmation**: served response contains file contents; or XXE out-of-band request lands at attacker.

**Impact**: SSRF, file read, DoS; load `xxe` for the full class.

### Primitive: XML Signature Wrapping

**Primitive**: a signed element is in position A; the processor evaluates position B. The signature validates (because position A still exists); the processed content is attacker-controlled (position B).

**Preconditions**:
- XML signature with a reference by element position or ID.
- Processor uses XPath to locate the element to process.
- Attacker can insert additional elements between signature and sink.

**Attack recipe**:
1. Capture a signed XML message.
2. Duplicate the signed element and modify the second copy.
3. The processor's XPath selects the modified copy (via wrapping tricks: new ID, parent-axis).
4. Signature validates on the original; processing acts on the modified.

**Confirmation**: processor's execution content differs from signed content.

**Impact**: SAML authentication bypass; XML-sig-based access control defeat.

## MIME, Multipart, and Content-Type Differentials

### Primitive: Multipart Boundary Shadowing

**Primitive**: a request with two `Content-Type: multipart/form-data; boundary=X` headers — which boundary applies?

**Preconditions**:
- WAF reads the first header; server reads the last (or vice versa).
- Attacker can submit duplicate Content-Type.

**Attack recipe**:
1. Send request with headers:
   ```
   Content-Type: multipart/form-data; boundary=A
   Content-Type: multipart/form-data; boundary=B
   ```
2. WAF parses using A, scans body as multipart A.
3. Server parses using B, body is a different multipart structure.
4. Smuggle unseen parts.

**Confirmation**: WAF-visible fields differ from server-visible fields.

**Impact**: upload-filter bypass; smuggled authentication data; WAF evasion.

### Primitive: Content-Type vs Sniffed-Type

**Primitive**: a service accepts a file with declared `Content-Type: image/jpeg` but the content is actually HTML; a serving-time MIME sniff identifies it as HTML, the browser executes.

**Preconditions**:
- Upload path trusts declared Content-Type.
- Serving path either preserves declared type or sniffs.
- Browser renders HTML.

**Attack recipe**:
1. Upload a file with content `<html><script>alert(1)</script></html>` and `Content-Type: image/jpeg`.
2. Service stores as "image."
3. On download, service returns `Content-Type: image/jpeg` but the browser sniffs (`X-Content-Type-Options: nosniff` is absent) and renders as HTML.

**Confirmation**: HTML executes in a browser rendering the uploaded "image."

**Impact**: stored XSS via upload; load `insecure_file_uploads`.

### Primitive: Content-Disposition Filename Encoding Divergence

**Primitive**: filename supports two encodings: RFC 5987 (`filename*=UTF-8''`) and raw (`filename=""`). A parser preferring one and a parser preferring the other store different names.

**Preconditions**:
- Upload path parses `Content-Disposition`.
- Storage path uses a different encoding.

**Attack recipe**:
1. Upload with both encodings:
   ```
   Content-Disposition: form-data; name="file"; filename="normal.jpg"; filename*=UTF-8''../../../etc/passwd
   ```
2. One parser stores `normal.jpg`; another stores `../../../etc/passwd`.

**Confirmation**: served or stored filename.

**Impact**: path traversal via filename; load `path_traversal_lfi_rfi`.

## Cookie Differentials

### Primitive: Cookie-Prefix Non-Enforcement

**Primitive**: `__Host-` prefix is defined to require `Secure`, no `Domain`, `Path=/`. A server that sets a `__Host-` cookie on HTTP (without Secure) violates the spec; a strict browser rejects, a lenient browser accepts.

**Preconditions**:
- Browser's prefix enforcement differs (older browsers may be lenient).
- Attacker controls a parallel cookie value.

**Attack recipe**:
1. Service sets a `__Host-sessionid=XYZ` cookie but on HTTP.
2. Strict browser rejects; attacker (on same browser) sets `__Host-sessionid=ATTACKER_XYZ` from a different origin (via a subdomain they control, exploiting Domain=null-is-this-host behavior).
3. The attacker's cookie "sticks" where the service's didn't.

**Confirmation**: cookie received at the service bears attacker's value.

**Impact**: session fixation; cookie-tossing attack.

### Primitive: Duplicate-Cookie Same Name

**Primitive**: two cookies with the same name, different Domain/Path. The browser sends both; the server reads one.

**Preconditions**:
- Attacker can set a cookie at a parent domain or sibling path.
- Server's cookie parser picks first or last without validation.

**Attack recipe**:
1. Attacker (controlling `attacker.target.com`) sets `Cookie: sess=ATTACKER` for `Domain=.target.com`.
2. Legitimate server (`app.target.com`) sets `Cookie: sess=LEGITIMATE` for `Domain=app.target.com`.
3. Browser sends both.
4. Server's parser picks the first (ATTACKER) by Cookie-header order.

**Confirmation**: server uses the attacker's cookie.

**Impact**: session fixation; cookie-tossing.

### Primitive: Cookie-Jar vs Server-Parse Order

**Primitive**: the browser's cookie-jar sorts cookies by (path-length, creation-time); the server parses in header order. An attacker who times cookie-setting controls the header order.

**Preconditions**:
- Service relies on specific cookie value when multiple exist.
- Browser cookie-sorting is spec-defined.

**Attack recipe**:
1. Set an attacker-cookie late, with a longer path, before the legitimate.
2. Browser sorts by path-length-desc; attacker-cookie first.
3. Server picks first (attacker).

**Confirmation**: server receives attacker-first ordering.

**Impact**: session fixation; privilege elevation via cookie precedence.

## HTTP Header Differentials

### Primitive: Duplicate vs Comma-Joined Header Semantics

**Primitive**: `X-Forwarded-For: a, b` vs two headers `X-Forwarded-For: a`, `X-Forwarded-For: b`. Different stacks interpret: pick first, pick last, join, pick leftmost-trusted.

**Preconditions**:
- Two components read the same header with different precedence (edge vs application).
- Attacker can submit duplicate or comma-joined.

**Attack recipe**:
1. Submit `X-Forwarded-For: trusted-ip, attacker-ip`.
2. Edge logs `trusted-ip` (first).
3. Application reads `attacker-ip` (last) as the client IP.
4. Access control based on client IP applies attacker's IP.

**Confirmation**: audit log client-IP differs between components.

**Impact**: IP-based authorization confusion; rate-limit evasion; abuse-attribution laundering. Load `header_injection`.

### Primitive: Header-Folding (Obsolete but Still Live)

**Primitive**: RFC 7230 deprecated line-folded headers; `Content-Length:\n 100` is forbidden. Some stacks still parse it; stricter stacks reject.

**Preconditions**:
- At least one component accepts obsolete folding.

**Attack recipe**:
1. Submit folded header; the folded-value is accepted differently.
2. Request-smuggling conditions arise when CL/TE disagreement feeds this.

**Confirmation**: paired parser output.

**Impact**: request smuggling via header-value shadowing; load `http_request_smuggling`.

### Primitive: Content-Length vs Transfer-Encoding Disagreement

**Primitive**: a request with both `Content-Length` and `Transfer-Encoding: chunked`. RFC 9112 requires TE wins; some stacks pick CL (CL.TE smuggling) or TE (TE.CL smuggling, when CL misleads downstream).

**Preconditions**:
- Front-end and back-end disagree on which header wins.

**Attack recipe**:
1. Craft a request with both headers framing conflicting bodies.
2. Front-end routes one way; back-end interprets the other.
3. Body boundary mismatches; next request smuggled into back-end's queue.

**Confirmation**: subsequent legitimate request appears to carry attacker-chosen body or returns attacker-chosen status.

**Impact**: request smuggling; load `http_request_smuggling` for full treatment.

## YAML Differentials

### Primitive: YAML 1.1 Boolean Coercion

**Primitive**: YAML 1.1 treats unquoted `yes`, `no`, `on`, `off`, `y`, `n`, `true`, `false` (and more) as booleans. YAML 1.2 only `true`/`false`. A service parsing user config with 1.1 coerces `country: no` to `country: false`.

**Preconditions**:
- Service parses YAML 1.1 (PyYAML without explicit `safe_load`/1.2 mode).
- A field accepts strings that happen to be in the boolean set.

**Attack recipe**:
1. Submit config with `country: no`.
2. Parser returns `country: False`.
3. Downstream treats boolean falsy as "unset" or "default", applying permissive defaults.

**Confirmation**: parsed value vs expected string.

**Impact**: feature-gate bypass, security-flag disable, authorization-field coercion.

### Primitive: Octal Literal Divergence

**Primitive**: `0777` is octal in some YAML libraries, decimal in others. A permission field `mode: 0777` gives 777 (decimal) or 511 (octal) depending.

**Preconditions**:
- Service uses the numeric mode field.
- Parsing varies.

**Attack recipe**:
1. Submit `mode: 0777` where the service expects octal.
2. Decimal-interpreting library stores 777.
3. Later use as mode treats 777 as unusual permission.

**Confirmation**: file permission post-create reflects the alternate interpretation.

**Impact**: filesystem permission misconfiguration; `insecure_file_uploads` adjacency.

### Primitive: YAML Tag Deserialization

**Primitive**: `!!python/object:os.system [...]` or `!!python/object/apply:subprocess.call` tags in PyYAML trigger code execution if `yaml.load` is used instead of `yaml.safe_load`.

**Preconditions**:
- Service uses `yaml.load` (not safe variant).
- Attacker-controlled YAML input reaches the loader.

**Attack recipe**:
1. Submit YAML with `!!python/object/apply:os.system ["id"]`.
2. Parser deserializes, invokes `os.system`.

**Confirmation**: command execution observable (OAST, side-channel).

**Impact**: RCE; load `insecure_deserialization` for the broader class.

## Date and Time Differentials

### Primitive: Timezone Omission Default

**Primitive**: ISO 8601 without timezone is parsed as UTC by one stack, local by another.

**Preconditions**:
- Service compares timestamps across stacks.

**Attack recipe**:
1. Submit `expires: "2026-01-01T00:00:00"` (no TZ).
2. Component A treats as UTC → expires 1 Jan 00:00 UTC.
3. Component B treats as local (e.g., UTC+8) → expires 1 Jan 00:00 +08:00 = 31 Dec 16:00 UTC.
4. Up to 24h discrepancy.

**Confirmation**: component-level comparison of parsed timestamps.

**Impact**: token-expiry edge, grace-period boundary, idempotency-window drift.

### Primitive: Leap Year Normalization

**Primitive**: `2026-02-29` is invalid (2026 is not leap). Strict parsers reject; lenient parsers coerce to March 1.

**Preconditions**:
- Two components parse the date differently (one strict, one lenient).

**Attack recipe**:
1. Submit `2026-02-29` as a scheduled event or token.
2. Strict parser: rejects; service goes to default (immediate).
3. Lenient parser: coerces to March 1; service schedules.

**Confirmation**: event scheduled at March 1 vs immediate vs rejected.

**Impact**: scheduling-logic confusion; token-validity-boundary gap.

## ZIP and Archive Differentials

### Primitive: CDH vs LFH Metadata Mismatch

**Primitive**: a ZIP archive has two metadata records for each entry — Central Directory Header (CDH, at archive end) and Local File Header (LFH, before each file). Different parsers consult different headers; attacker crafts an archive where they disagree.

**Preconditions**:
- At least two tools in the pipeline parse the ZIP (scanner + unpacker, archive manager + target).
- Each tool chooses CDH or LFH preferentially.

**Attack recipe**:
1. Craft an archive where CDH filename says `safe.txt` and LFH filename says `malicious.exe`.
2. One tool reads CDH (sees safe.txt); the other reads LFH (extracts malicious.exe).
3. The scanner-and-serve mismatch delivers malware past the filter.

**Confirmation**: raw bytes of both headers differ; extracted content differs between tools.

**Impact**: scanner bypass; policy-filter evasion. ZIPDIFF (USENIX 2025) systematized 14 ambiguity types including this class; 10 of them were newly discovered. See `semantic_confusion_novel_deep` for the academic grounding.

### Primitive: UTF-8 Flag Disagreement

**Primitive**: ZIP APPNOTE bit 11 is the UTF-8 encoding flag; filename interpretation depends on it. Parsers that honor the flag and those that assume CP437 interpret the same bytes as different filenames.

**Preconditions**:
- Multi-parser pipeline with mixed Unicode-flag handling.

**Attack recipe**:
1. Set bit 11 to 1 in CDH, 0 in LFH; craft filename bytes that render differently in UTF-8 vs CP437.
2. Parsers disagree on the stored filename.

**Confirmation**: bytewise filename decoded under both interpretations yields different strings.

**Impact**: filename-based filter bypass; path-traversal via alternative encoding.

### Primitive: Zip64 Format Trigger

**Primitive**: entries larger than 2^32 use Zip64 extensions; parsers that only support Zip32 misinterpret the size field.

**Preconditions**:
- A Zip64 archive processed by a Zip32-only tool.

**Attack recipe**:
1. Craft a Zip64 archive with large declared sizes but small actual content.
2. Zip32 parser reads a truncated size field; may underflow or misread.

**Confirmation**: declared size vs read size differ.

**Impact**: memory corruption in older parsers; filter evasion.

### Primitive: Encrypted-Entry Opacity

**Primitive**: ZIP encryption modes conceal file content from scanners that lack the password; downstream unpacker receives the password out of band and extracts.

**Preconditions**:
- Pipeline accepts encrypted ZIPs.
- Scanner cannot decrypt.
- User or application supplies password at extraction.

**Attack recipe**:
1. Encrypt malicious content in a ZIP with a known password (`infected`, `test`).
2. Scanner sees encrypted entries, cannot inspect, lets through.
3. User extracts with the published password; malware runs.

**Confirmation**: scanner report shows "encrypted - skipped"; extraction yields unknown content.

**Impact**: evasion of content scanning; email-gateway bypass; stored-malware delivery.

## HTTP/2 and Protocol-Specific Differentials

### Primitive: HTTP/2 Header Case Rewriting

**Primitive**: HTTP/2 mandates lowercase header names on the wire; a server that normalizes to lowercase for routing but preserves the case for logging produces audit-log confusion.

**Preconditions**:
- Front-end HTTP/2, back-end HTTP/1.1.
- Translation preserves case for forwarded headers.

**Attack recipe**:
1. Submit HTTP/2 request with `host` lowercase (as required).
2. Translator forwards to back-end with `Host:` (titlecase) or whatever it preserves.
3. Back-end's duplicate-detection on case-sensitive header name doesn't collapse.

**Confirmation**: audit log shows one case; the back-end sees another.

**Impact**: logging confusion; header-smuggling for request-smuggling (load `http_request_smuggling`).

### Primitive: HTTP/2-to-HTTP/1 Pseudo-Header Translation

**Primitive**: HTTP/2 uses `:path`, `:method`, `:scheme`, `:authority` pseudo-headers; translation to HTTP/1 constructs the request line. Mismatches in `:authority` vs `host` header or in `:path` encoding create smuggling.

**Preconditions**:
- HTTP/2 front-end translating to HTTP/1 back-end.

**Attack recipe**:
1. Submit HTTP/2 with `:authority: evil.com` and `host: trusted.com`.
2. Translation picks one or combines; back-end may see one host while the front-end logged another.

**Confirmation**: back-end logs host differ from front-end logs.

**Impact**: Host-header-trust confusion; cache-poisoning (`http_request_smuggling`).

### Primitive: HTTP/3 QUIC Framing Divergence

**Primitive**: HTTP/3 over QUIC has distinct framing from HTTP/2; proxies translating HTTP/3 → HTTP/2 → HTTP/1 compound opportunities for parser disagreement.

**Preconditions**:
- Multi-protocol-tier infrastructure.
- Translation layers in each hop.

**Attack recipe**:
1. Craft HTTP/3 request with maximally-ambiguous framing.
2. Each translation step accumulates small differences.
3. End-to-end round-trip reveals which hop decided which boundary.

**Confirmation**: hop-by-hop logs show successively-different interpretations.

**Impact**: smuggling, cache-poisoning at the newest-protocol tier. The HTTP Request Synchronization paper (arxiv 2510.09952) declares this class an open problem as of October 2025.

## Field Overloading and Lifecycle Carryover

### Primitive: Shared-Field Semantics Across Lifecycle

**Primitive**: a field named `path` is used for both filesystem path and URL path at different code paths; the value's semantic flips mid-request.

**Preconditions**:
- Shared schema or model object across request handling and background processing.
- The semantic depends on where the field is read.

**Attack recipe**:
1. Submit an upload with `path: ../../../etc/passwd` where the handler validates it as a URL path (dot-segments are not "traversal" in a URL).
2. The background worker later interprets the same field as a filesystem path.
3. Dot-segments canonicalize to parent-directory escape at the worker.

**Confirmation**: audit log shows the request handler saw `path = /uploads/../..` as a URL; worker opened `/etc/passwd`.

**Impact**: late-binding path traversal; load `path_traversal_lfi_rfi`.

### Primitive: Field Mutation Across Internal Redirect

**Primitive**: a request is validated with path A; the handler internally redirects to a different path B that trusts a now-mutated version of path A.

**Preconditions**:
- Framework supports internal redirects (Nginx `X-Accel-Redirect`, Apache `mod_rewrite` passthrough).
- Mutation happens between validation and internal dispatch.

**Attack recipe**:
1. Submit request to validated endpoint; path contains `?file=public.txt`.
2. Handler issues `X-Accel-Redirect: /internal?file=public.txt`.
3. The internal endpoint re-parses, applies different canonicalization.
4. The attacker-authored query is honored at the internal endpoint even though the outer path validator didn't consider the query.

**Confirmation**: internal endpoint log shows the final processed query.

**Impact**: SSRF via internal redirect, path escape, authorization bypass.

### Primitive: Request-Context Carryover to Background Jobs

**Primitive**: the request handler enqueues a background job carrying the request's auth-context (user ID, tenant); the job runs with the context without re-validating. If the request was from a tenant that has since been downgraded or deleted, the job still runs with the old authority.

**Preconditions**:
- Jobs persist request context.
- No re-validation at job execution.

**Attack recipe**:
1. Enqueue a job with a privileged context (e.g., admin role).
2. Change the context (lose admin via role change).
3. Job runs with the still-cached old context.

**Confirmation**: job executes action the current identity could not.

**Impact**: privilege retention in async flows; load `broken_function_level_authorization` and `business_logic_advanced_deep` for the async-privilege-retention chain.

## Measurement Discipline

The advanced-tier content requires measured demonstrations. For each primitive above:

1. **Local measurement script**: install the two parsers, feed them the same bytes, record both outputs.
2. **Minimized input**: iteratively shrink the input until the smallest-byte-sequence that reproduces the discrepancy.
3. **Version pinning**: note parser versions, OS, locale, Unicode-ICU version.
4. **Negative control**: test an input the two parsers agree on, to confirm the measurement is picking up a real difference.
5. **Persist raw bytes**: save input bytes and both parser outputs as artifact-directory JSON for later audit.

A measured discrepancy with a minimized input is the gold standard. An asserted discrepancy without measurement is a lead.

## Chaining Depth

Advanced parser-differential primitives chain into:

- **URL-differential → SSRF**: `ssrf_advanced_deep` for IMDS-reachability and cloud metadata chains.
- **Path-canonicalization → traversal**: `path_traversal_lfi_rfi_advanced_deep` for the sink-reachability analysis.
- **Multipart → upload**: `insecure_file_uploads_advanced_deep` for server-specific execution semantics.
- **HTTP header → smuggling**: `http_request_smuggling_novel_deep` for the ASP.NET Core and transducer-vs-backend material.
- **JSON duplicate-key → role smuggling**: `broken_function_level_authorization` and `mass_assignment` for the authorization-flow consequence.
- **XML XXE → SSRF/file read**: `xxe_advanced_deep` for parser-defaults and lab setup.
- **XML signature wrapping → SAML bypass**: `authentication_jwt` for the broader token-signature-vs-content class.
- **IDN homograph → phishing**: `subdomain_takeover` for the DNS-resolution class.
- **mXSS from HTML sanitizer drift**: `xss_advanced_deep` for the full DOMPurify / Trusted Types primitives.

Each chain names the sibling that owns the downstream primitive. The semantic-confusion skill produces the capability transfer; the receiving skill owns the exploitation.

## Verification Discipline

Report format for an advanced-tier semantic-confusion finding:

1. **Named invariant**: what the two components should agree on (host, path, type, numeric value, boolean, timestamp).
2. **Named components**: validator / sink by filename, library, version.
3. **Minimized input**: the smallest byte sequence that reproduces the disagreement.
4. **Measured outputs**: raw bytes in, raw bytes out from each parser.
5. **Reachability proof**: that the second interpretation reaches a security-relevant consumer.
6. **Impact proof**: what the attacker gains when the disagreement is weaponized.
7. **Preconditions**: version, locale, configuration, co-dependent primitives.

If any of these is missing, the finding is a lead, not a confirmation.

## Summary

Advanced-tier semantic confusion is a per-format catalog of parser-differentials, canonicalization gaps, and encoding-divergences that an exploit chain can bridge. For each format, name the invariant, the components, and the minimized input; measure both parsers; prove reachability; prove impact. The content unit is the primitive — the reusable primitive, not the specific payload. For the 2024–2026 academic grounding (ZIPDIFF, HTTP Garden, JSON differential, HTTP Request Synchronization) and the research-grade open-problem framing, load `semantic_confusion_novel_deep`.
