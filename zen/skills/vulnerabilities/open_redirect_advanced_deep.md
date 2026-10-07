---
name: open-redirect-advanced-deep
description: Open redirect at advanced+expert depth — the Claroty/Snyk 16-library URL-parser-confusion framework, scheme/slash/backslash/userinfo/encoding/scheme-mixup bypass classes with measured differentials, framework-specific redirect sinks, OAuth redirect_uri chain depth, SPA/service-worker/WebSocket sinks, and composite-chain construction with SSRF/host-header/cache primitives.
sibling: open_redirect
load_when: scan_mode == "deep"
---

# Open Redirect — Advanced Depth

This is the advanced+expert deep sibling to `open_redirect.md`. The base owns the class framing, the measured 5-payload × 6-parser matrix, the 3-line reproduction harness, the OAuth chain primer, the client-side sink catalog, and the primary chains. The novel+frontier sibling `open_redirect_novel_deep.md` owns the 2024–2026 CVE mechanism decompositions (authentik CVE-2024-52289, urllib3 CVE-2025-50181 and CVE-2025-50182), the Claroty/Snyk 16-library framework's current frontier status, measured 2026 parser differentials against urllib3 2.8.0 and CPython 3.12/3.13, the URL-parser-disagreement SSRF class with the vLLM CVE-2026-25960 case study, and the OAuth 2.1 / RFC 9700 strict-redirect-URI shift. This file owns the technique-class spine — the five inconsistency classes (scheme, slash, backslash, URL-encoded-data, scheme-mixup), the five vulnerability classes (SSRF, XSS, open redirect, filter bypass, DoS), framework-specific redirect sink depth, OAuth redirect_uri chain depth, SPA/service-worker/WebSocket sinks, and composite-chain construction.

Load this file when the target has moved past a trivial PoC — the single-slash and single-backslash tests already got rejected, the allowlist has some canonicalization, the OAuth flow has partial `redirect_uri` matching, or the chain requires composing an open redirect with cache poisoning, SSRF, host-header injection, or a client-side sink.

Every parser-behavior claim in this file is anchored to primary sources (Claroty/Snyk research, WHATWG URL spec, framework documentation) or measured. Every CVE referenced by number lives version-metadata-wise in the novel sibling per §2 CVE single-ownership; this file references by CVE number + route.

## The Claroty/Snyk 16-Library URL-Parser-Confusion Framework

Claroty Team82 and Snyk Research published the canonical taxonomy of URL-parsing inconsistencies at Black Hat USA 2022 (Moshe/Brizinov, "Exploiting URL Parsing Confusion"). The research examined sixteen URL-parsing libraries across Python, cURL, Wget, Chrome, .NET, Java, PHP, Node.js, Go, Ruby, and Perl, categorizing their disagreements into five inconsistency classes that produce five vulnerability classes.

**The sixteen libraries examined:**

Python: `urllib`, `urllib3`, `rfc3986`, `httptools`. cURL. Wget. Chrome (WHATWG URL). .NET `Uri`. Java `URL` and `URI`. PHP `parse_url`. Node.js `url` (legacy) and `url-parse`. Go `net/url`. Ruby `URI`. Perl `URI`.

**The five inconsistency classes:**

1. **Scheme confusion** — parsers disagree on what counts as a scheme.
2. **Slash confusion** — parsers disagree on how many slashes separate scheme from host, and whether `/` can appear in positions it isn't formally allowed.
3. **Backslash confusion** — parsers disagree on whether `\` is a valid authority-delimiter and whether `\` normalizes to `/` for special schemes.
4. **URL-encoded data confusion** — parsers disagree on when percent-encoded sequences are decoded (at parse time vs at component-extraction time vs never).
5. **Scheme mixup** — parsers disagree on scheme comparison (case-insensitive vs case-sensitive) and on scheme-specific normalization.

**The five vulnerability classes produced:**

1. **SSRF** — a validator that extracts one host and a fetcher that extracts another sends requests to the fetcher's host while the validator's allowlist passed on a different host.
2. **XSS** — a `javascript:` scheme that the validator rejects but a browser-side sink executes.
3. **Open redirect** — the headline class: validator extracts a trusted host, browser navigates to an attacker host.
4. **Filter bypass** — a security filter (regex, prefix check, list check) that passes on one parser's view while another parser's view is attacker-friendly.
5. **DoS** — malformed URLs that crash the parser or burn CPU in pathological parsing paths.

This file organizes its sections around the five inconsistency classes, with each inconsistency class covering the primitive, the measured differential, the exploitation, and the specific library-pair that produces the bypass. For the current frontier status of each library (patched / still-vulnerable / newly-affected), load `open_redirect_novel_deep.md § 2026 Parser-Differential Status`.

## Scheme Confusion Class

Parsers disagree on when a scheme is required, when it is inferred, and when a scheme-less input is treated as relative-vs-absolute. The primitive is "attacker's URL navigates one way for the validator and another way for the browser/fetcher."

### Scheme-less input, attacker-specified host

**Primitive.** The validator's parser treats `google.com/path` as a relative path (no host extracted); the fetcher's parser treats it as absolute (host=`google.com`). The disagreement is at the fundamental "is there a scheme" question.

**Preconditions.** (1) Validator parses with `urllib.parse.urlsplit()` or sibling parser that returns empty netloc on scheme-less input. (2) Validator logic treats empty host as "relative, same-origin, allowed." (3) Fetcher uses urllib3 or sibling parser that infers host from scheme-less input.

**Attack recipe.** Submit `google.com/secret` or `localhost/internal` as the redirect/fetch target. `urllib.parse.urlsplit('google.com/secret').netloc` returns empty — validator check `if hostname not in ALLOWLIST: reject` with the implicit `if hostname is None: allow` passes. `urllib3.util.parse_url('google.com/secret').host` returns `google.com` — fetcher dispatches there. The measured output is in the base file's `localhost/secret.txt` reproduction (`.zen-batch-artifacts/batch9-20261003/measurement/output/06_url_parser_differentials__urllib3.out`).

**Confirmation.** For SSRF reach, dispatch to a loopback target and observe the measured response (status 200 with the local server's body). For open-redirect reach, submit to the redirect endpoint and observe the browser navigates away from the trusted host.

**Impact.** The validator was supposed to prevent cross-origin navigation / internal SSRF; it passed on empty-host-equals-safe. Combined with urllib3-based fetchers (webhooks, link unfurlers, SSR fetchers), the chain is immediate SSRF.

### Explicit scheme with single slash

**Primitive.** Payload: `https:/evil.com`. WHATWG URL (`new URL('https:/evil.com')`) treats this as `https://evil.com/` — a browser navigates to `evil.com`. Python's `urlparse('https:/evil.com')` returns `scheme='https', netloc='', path='/evil.com'` — no host extracted. The validator reads `.hostname` as `None` and passes if the logic treats missing hostname as "relative URL, safe."

**Preconditions.** (1) Validator uses Python/legacy-Node parser. (2) Validator's logic for empty-host is "same-origin, allow." (3) The redirect sink emits the raw input into a `Location:` header or `location.href`.

**Attack recipe.** Submit `https:/evil.com` through any redirect/next-URL parameter whose validator uses urlparse-and-check-hostname. The validator passes (hostname is None); the server emits `Location: https:/evil.com`; the browser normalizes to `https://evil.com/` and navigates.

**Confirmation.** Browser-level observation of the final navigation destination (not the server's status code). Headless browser (Puppeteer, Playwright) automates this; curl-only confirmation is insufficient because the server returns 302 either way.

**Impact.** Open redirect to attacker-chosen host, bypassing the hostname-allowlist control. The chain extends to OAuth code interception when the redirect sink is a registered `redirect_uri`.

### Explicit scheme with no slashes

**Primitive.** Payload: `https:evil.com`. WHATWG URL extracts `evil.com` as the host via implicit slash-insertion normalization. Python's `urlparse` returns `scheme='https', netloc='', path='evil.com'`. Same validator-vs-browser disagreement as single-slash.

**Preconditions.** Same as single-slash case: Python-based validator reading empty hostname as safe.

**Attack recipe.** Submit `https:evil.com` through the redirect parameter; the browser's implicit normalization fills in the missing `//` and navigates to `evil.com`.

**Confirmation.** Same browser-level navigation observation as single-slash.

**Impact.** Equivalent to single-slash. The payload is shorter but functionally identical. Hunt method: try both forms when fingerprinting an unfamiliar validator — the shorter form may evade a regex that matches on `://`.

### Scheme-less with implicit protocol (protocol-relative URL)

**Primitive.** Payload: `//evil.com`. The `//` prefix is a protocol-relative URL that the browser resolves against the current page's scheme. WHATWG URL requires a base to resolve (`new URL('//evil.com')` throws without base); with a base of `https://trusted.com/`, it resolves to `https://evil.com/`. Python's `urlparse('//evil.com')` returns `scheme='', netloc='evil.com', path=''` — host extracted but scheme empty.

**Preconditions.** (1) Validator extracts hostname and compares against allowlist, but the comparison is `if urlparse(x).scheme == '': allow` (treating empty scheme as same-origin). (2) The redirect sink is server-side `Location:` or client-side `location =`. (3) Context has a base URL (always the case for browser navigation).

**Attack recipe.** Submit `//evil.com` through the redirect parameter. Validator sees scheme empty, allows. Server emits `Location: //evil.com`; browser resolves against current scheme and navigates to `https://evil.com/`. Alternatively, client-side `location = params.get('next')` with `next=//evil.com` navigates directly.

**Confirmation.** Browser-level navigation observation. The attack is distinct from single-slash because the parser DOES extract a hostname — the bypass depends on scheme-empty logic, not hostname-empty logic.

**Impact.** Full open-redirect. Mitigation: reject empty-scheme values at the validator; require explicit `https://` scheme on all redirect targets.

### Scheme-mixed-case

**Primitive.** Payload: `hTtPs://evil.com`. WHATWG canonicalizes scheme to lowercase before processing; Python canonicalizes via `.scheme.lower()`; some older urllib3 versions preserve original case. A validator that string-compares the scheme without explicit case-folding (`url.scheme == 'https'`) fails against mixed-case, while the browser canonicalizes and navigates.

**Preconditions.** (1) Validator uses `==` or exact string comparison on scheme. (2) Validator falls through on scheme-mismatch to a lax policy (allow, treat as same-origin) rather than a strict reject.

**Attack recipe.** Submit `hTtPs://evil.com/`. Validator's `url.scheme == 'https'` returns False; validator's fall-through logic allows. Browser canonicalizes scheme to `https` and navigates.

**Confirmation.** Fingerprint by submitting a known-safe URL with mixed-case scheme (`hTtPs://trusted.com/`) and observing whether it's accepted (lax validator) or rejected (strict validator). The pair discriminates lax from strict.

**Impact.** Bypasses scheme-pinning validators that use case-sensitive comparison. Mitigation: `.lower()` the scheme before comparison.

### Scheme with embedded whitespace or control characters

**Primitive.** Payload: `http%09://evil.com` (percent-encoded horizontal tab in the scheme) or `http\n://evil.com` (newline), or `http\t://evil.com` (literal tab). WHATWG URL strips leading ASCII whitespace and tabs/newlines before parsing; `urlparse` does not. The validator sees scheme `http\t` and fails scheme-equality; the browser normalizes to `http` and navigates.

**Preconditions.** (1) The input traverses an URL-decoding boundary where percent-encoded whitespace becomes real whitespace. (2) Validator does not strip whitespace before scheme comparison. (3) Browser performs the whitespace-strip normalization (all current major browsers do).

**Attack recipe.** Submit `http%09://evil.com/` through a redirect parameter that URL-decodes the input before passing to the validator. The decoded form has `http\t://evil.com/`. The validator's scheme comparison `url.scheme == 'http'` fails (scheme contains tab). The validator falls through to permissive handling.

**Confirmation.** Test both the pre-decoded and post-decoded payloads. If the post-decoded form is accepted but the pre-decoded form is rejected, the primitive is the whitespace-handling differential.

**Impact.** Scheme bypass; combined with the fall-through-to-allow pattern this reaches the full open-redirect primitive.

### Dangerous schemes (javascript:, data:, file:, gopher:)

**Primitive.** Payload: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`, `file:///etc/passwd`, `gopher://internal.svc:6379/_PING`. Validators that check for `http`/`https` as a prefix (`url.startswith('http')`) can be bypassed with `http+javascript:alert(1)` on parsers that extract `http+javascript` as the scheme (the `+` is permitted in RFC-3986 scheme characters). The attack moves beyond open-redirect into DOM-XSS (javascript:/data:) or SSRF (gopher:/file:).

**Preconditions.** (1) Validator checks scheme by prefix match rather than exact equality. (2) The sink executes the URL rather than displays it: for XSS, `location.href = userInput` or `<a href=userInput>` + click; for SSRF, a server-side fetcher that respects alternative schemes.

**Attack recipe for `javascript:` XSS via scheme-prefix bypass.** Submit `http+javascript:alert(document.cookie)`. The validator's `url.startswith('http')` returns True; the browser's URL-parser extracts scheme `http+javascript`, which maps to `javascript:` behavior on execution. The alert fires. Load `xss.md § JavaScript URI Sinks` for the full XSS chain.

**Attack recipe for `gopher://` SSRF.** Submit `gopher://internal.redis:6379/_SET%20evilkey%20pwned%0D%0A`. A fetcher that honors gopher: scheme sends raw bytes to the target port, reaching Redis / Memcached / MongoDB protocols. Load `ssrf.md § Protocol Smuggling via Gopher` for the primitive construction.

**Confirmation.** For XSS, observe the alert or payload execution in the browser. For SSRF, observe the side-effect at the target protocol service.

**Impact.** XSS or SSRF depending on scheme; both widen the open-redirect primitive significantly. Mitigation: allowlist specific schemes (`http:`, `https:` only) with exact equality, not prefix match.

### Scheme-smuggling via newline injection

**Primitive.** Payload: `javascript:alert(1)%0Ahttps://trusted.com/`. The URL contains two "logical lines" — one with `javascript:` scheme, one with `https:`. Parsers that process the first line and parsers that process the last line reach different conclusions. If the application reads one line for scheme extraction (sees `javascript:`) and the browser follows the other (navigates to the trusted URL first then re-navigates), or vice versa, the attacker chains the behaviors.

**Preconditions.** (1) The input traverses a line-oriented processing step (log entry, header value, CSP policy) that treats newlines as record separators. (2) The validator and the sink disagree on which line is authoritative.

**Attack recipe.** Craft payload with a newline between a benign scheme and a malicious scheme; submit through a sink that processes line-by-line. The validator reads line one (benign); the sink executes line two (malicious). Common in CRLF-injection chains; load `header_injection.md` for the primitive.

**Confirmation.** Observe differential processing by submitting both single-line forms and the newline-separated multi-line form; the behavior-shift between them reveals the line-processing boundary.

**Impact.** Scheme bypass combined with any line-based processing differential; chains with header injection and CRLF injection.

### Confirmation methodology for scheme-class primitives

For each scheme-confusion payload, run the 3-line reproduction harness from the base file against the exact validator and fetcher the target uses. The differential between parsers is the attack surface; the specific exploit is the parser pair that mismatches. Payloads reaching WHATWG as `evil.com` and server-side parsers as empty/relative are the headline open-redirect bypasses. For the measured 2026 state of the pair stdlib-urllib + urllib3, load `open_redirect_novel_deep.md § Measured 2026 URL-Parser Differentials`.

## Slash Confusion Class

Parsers disagree on how many slashes separate scheme from host and how `/` behaves in authority positions. The historical anchor is CVE-2021-23435 (Ruby Clearance) where `////evil.com` passed through a four-slash validator and a three-slash URI parse to produce a browser navigation to `evil.com`.

### Multi-slash prefix (five or more slashes)

**Primitive.** Payload: `/////evil.com`. Ruby's `URI.parse` strips exactly two leading slashes, leaving `///evil.com`. Rails' routing ignores leading-slash multiplicity, passing the whole string through to the application. The browser's URL parser treats three leading slashes as protocol-relative-plus-one and navigates to `evil.com`. The combination is the exact chain in CVE-2021-23435.

**Preconditions.** (1) Application uses Ruby's `URI.parse` for return-to or redirect-URL validation. (2) The validator reads `URI.parse(input).host` and compares against an allowlist (expecting the host to be the trusted domain). (3) The browser receives the raw input (or minimally-normalized input) in the response's `Location:` header.

**Attack recipe.** Submit `/////evil.com` through the return-to parameter. Rails routing passes it through unchanged. `URI.parse('/////evil.com').host` returns `nil` or empty (depending on Ruby version); the validator sees no host and allows. The server emits `Location: /////evil.com`. The browser normalizes: strip the first two slashes (per RFC 3986 scheme-relative), leaving `///evil.com`, then strip one more as part of the authority parse, leaving `//evil.com` which it treats as protocol-relative. Browser navigates to `evil.com` under the current scheme.

**Confirmation.** The browser's final navigation destination (observed via browser or Puppeteer) is `evil.com`. Negative control: the single-slash `/evil.com` form stays within the trusted origin (same-origin relative path).

**Impact.** Open redirect to attacker host, pre-fix behavior of Clearance ≤ 2.4.x. The mechanism-and-version metadata lives in `open_redirect_novel_deep.md § Historical Anchor — CVE-2021-23435 Clearance Multi-Leading-Slash`. Hunt lead: any Rails-adjacent framework that uses `URI.parse` for return-to validation inherits the same vulnerability shape.

### Four-slash prefix

**Primitive.** Payload: `////evil.com`. WHATWG URL rejects (too many slashes for special schemes); Python's `urlparse('////evil.com')` returns `scheme='', netloc='', path='////evil.com'` — all slashes in the path; a browser navigating directly to the raw string treats it as same-origin (no cross-origin navigation). But when the server reflects the raw string into a `Location:` header, the response's `Location: ////evil.com` triggers a browser normalization distinct from direct-URL-bar navigation: the browser's HTTP-response-redirect handler normalizes `////evil.com` to `//evil.com` (two slashes = protocol-relative) and navigates to `evil.com`.

**Preconditions.** (1) Validator reads the input and sees no host (urlparse returns empty netloc). (2) Server reflects the input into `Location:` without normalization. (3) Browser's redirect-handling path (distinct from the direct-navigation path) applies protocol-relative normalization.

**Attack recipe.** Submit `////evil.com` through a server-side redirect sink. Server validates (empty host, allow); server emits `Location: ////evil.com`; browser treats as `//evil.com` and navigates. The attack is specific to the server-side-reflection path; a client-side `location.href = '////evil.com'` typically stays same-origin.

**Confirmation.** Browser navigates to `evil.com` on redirect-handling. Compare to client-side `location.href` assignment: the latter stays same-origin, revealing the distinct code path.

**Impact.** Open redirect via the server-reflection path. Mitigation: canonicalize the redirect target before emitting Location.

### Three-slash prefix

**Primitive.** Payload: `///evil.com`. Treated as protocol-relative with an extra slash: WHATWG normalizes to `//evil.com/`; Python returns `netloc='', path='///evil.com'`. The browser navigation is to `evil.com`; the validator sees empty netloc. This is the direct bypass pattern — simpler than the four-slash variant because it doesn't require the server-reflection step.

**Preconditions.** (1) Validator uses urlparse-like parser returning empty netloc on 3+ slash prefix. (2) Validator's logic for empty netloc is "same-origin, allow." (3) Browser normalizes to protocol-relative.

**Attack recipe.** Submit `///evil.com` through the redirect parameter. Validator sees empty netloc, allows. Server emits raw or `Location: ///evil.com`. Browser normalizes to `//evil.com` and navigates cross-origin.

**Confirmation.** Browser navigates to `evil.com`. Negative control: `/evil.com` (single slash) stays same-origin.

**Impact.** Direct open-redirect bypass. One of the most reliable payloads against Python/Node-legacy validators.

### Slash in authority before @

**Primitive.** Payload: `https://evil.com/@google.com`. The `@` typically signals userinfo-vs-host, but a `/` before it ends the authority. WHATWG parses `host='evil.com'`, `path='/@google.com'`. Python's `urlparse` parses `host='evil.com'`, `path='/@google.com'` — same. But a regex-based validator that looks for `@` in the input to extract host-as-after-@ sees `google.com` and allows.

**Preconditions.** (1) Validator uses regex-based host extraction (common in hand-rolled validators or legacy codebases) that finds the first `@` and takes everything after as host. (2) The parser and the browser agree that the authority ends at the first `/`. (3) The validator trusts its own regex over the parser's extraction.

**Attack recipe.** Submit `https://evil.com/@google.com`. The regex-based validator sees `google.com` as host (last-@-wins or any-after-@) and allows. The browser's standards-conformant parser sees `evil.com` as host and navigates there.

**Confirmation.** Browser navigates to `evil.com`. Fingerprint the validator: a parser-based validator would see `evil.com` and reject; a regex-based validator sees `google.com` and allows — the pair discriminates.

**Impact.** Open redirect to attacker host, specifically against regex-based validators. Mitigation: use a proper URL parser instead of regex; canonicalize before comparing.

### Slash-backslash mix (`/\evil.com`)

**Primitive.** Payload: `/\evil.com`. Python's `urlparse('/\\evil.com')` returns `scheme='', netloc='', path='/\\evil.com'` — all in path. WHATWG normalizes `\` to `/` for special schemes but requires a base; with base `https://trusted.com/`, resolves to `https://trusted.com//evil.com` which the browser then navigates as protocol-relative to `evil.com`. A validator seeing path-only passes; a browser navigating normalizes and goes external.

**Preconditions.** (1) Validator uses Python/Node-legacy parser not normalizing backslash. (2) Browser's normalization is WHATWG-conformant (all current browsers). (3) Context has a base URL (always the case for browser navigation).

**Attack recipe.** Submit `/\evil.com` through the redirect parameter. Validator sees path-only, allows. Browser normalizes `/\` to `//`, resolves to protocol-relative, navigates to `evil.com`.

**Confirmation.** Browser navigates to `evil.com`. Observe the final URL in the address bar — intermediate processing (server-side) may show the `/\` form, but the final navigation is `evil.com`.

**Impact.** Open redirect through combined slash-backslash normalization. Specifically bypasses validators that handle `/` and `\` differently (most Python/Node validators).

### Combinatorial slash variants

**Primitive.** Payloads like `/\/evil.com`, `/\\/evil.com`, `\/\evil.com`, `/./evil.com`, `/./.evil.com/`, and other mixed-separator forms. Each is handled differently by different parsers; the matrix in the base file covers the core five payloads, but combinatorial variants add dozens more.

**Hunt method.** Generate payloads of up to ten characters mixing `/`, `\`, `.`, and alphanumeric. Run each through the target's parser (using the 3-line reproduction harness from the base file) and the equivalent through WHATWG `new URL()`. Any payload where parser and browser disagree is a candidate. Automate with a fuzzer that produces the combinatorial grid and compares outputs; the differential output is the lead for a bypass.

**Confirmation per payload.** For each candidate payload, submit through the redirect sink and observe the browser's final navigation. A payload where (a) validator extracts a trusted host and (b) browser navigates to an attacker host confirms the bypass. Document the payload in the per-target playbook.

**Impact.** The grid-generation method surfaces new bypass payloads over time as validators patch specific payloads but miss combinatorial variants. Any validator that doesn't canonicalize to WHATWG form before comparison is a candidate.

## Backslash Confusion Class

The WHATWG URL spec converts `\` to `/` for special schemes (http, https, ws, wss, ftp); programmatic parsers in Python, PHP, and Node (legacy `url.parse`) typically do not. This disagreement is the single most reliable allowlist-bypass against Python/PHP/Node-legacy validators. The measured urllib3 2.8.0 vs CPython 3.12 differential is in the base file's matrix.

**Backslash as authority delimiter in urllib3.** Payload: `http://evil.com\@google.com/`. The measured urllib3 differential (reproduced at `.zen-batch-artifacts/batch9-20261003/measurement/output/06_url_parser_differentials__urllib3.out`):

```
--- payload='http://evil.com\\@google.com/' ---
urllib.parse.urlsplit : scheme='http'  netloc='evil.com\\@google.com'  path='/'  hostname='google.com'
urllib3.util.parse_url: scheme='http'  host='evil.com'  port=None  path='/%5C@google.com/'
```

urllib treats the full `evil.com\@google.com` as userinfo-and-host and extracts `google.com` as hostname (the `@` splits it). urllib3 treats `\` as an authority-ending character and extracts `evil.com` as the host, with the rest becoming a URL-encoded path. A validator using `urlparse(input).hostname` sees `google.com` (passes an allowlist of `google.com`); urllib3-based fetcher dispatches to `evil.com`. The measured loopback-dispatch confirmation from `.../06_url_parser_differentials__urllib3.out`:

```
--- PoolManager.request('GET', 'http://127.0.0.1:8913\\@evil.com/x') ---
  stdlib: hostname='evil.com' netloc='127.0.0.1:8913\\@evil.com'
  urllib3: host='127.0.0.1' port=8913 path='/%5C@evil.com/x'
  dispatch status=200 body=b'loopback-fetched: /%5C@evil.com/x'
```

A stdlib-based allowlist denying `127.0.0.1` sees `hostname='evil.com'` and allows the request; urllib3 then dispatches to `127.0.0.1`. The chain is validator-vs-fetcher disagreement producing SSRF.

### Backslash normalization in browsers (post-scheme)

**Primitive.** Payload: `http:\\google.com` (two backslashes immediately after the scheme colon). Chrome, Firefox, and WebKit normalize `\` to `/` for `http:` / `https:` / `ws:` / `wss:` / `ftp:` (the WHATWG "special scheme" set) and treat `http:\\google.com` as `http://google.com/`. Python's `urlparse('http:\\\\google.com')` returns `scheme='http', netloc='', path='\\\\google.com'` — all backslashes in the path.

**Preconditions.** (1) Validator uses Python/Node-legacy parser that does not normalize backslash. (2) Validator's logic for empty netloc is "allow" (same-origin, relative). (3) Browser performs WHATWG backslash-to-slash normalization. (4) The redirect sink is server-side `Location:` or client-side navigation that triggers WHATWG parsing.

**Attack recipe.** Submit `http:\\evil.com/` through the redirect parameter. Validator sees empty netloc, allows. Server emits `Location: http:\\evil.com/`; browser canonicalizes to `http://evil.com/` and navigates.

**Confirmation.** Browser's final navigation is `evil.com`. Negative control: a `\` in a non-special-scheme input (`unknown:\\evil.com`) is NOT normalized by the browser — stays in the path — confirming the special-scheme-only normalization behavior.

**Impact.** Open redirect to attacker host. The payload is distinct from `//evil.com` because it includes an explicit scheme, bypassing scheme-required validators.

### Backslash in userinfo (password component)

**Primitive.** Payload: `https://user:\pass@google.com/` or `https://ad\min@evil.com/`. The `\` in the userinfo portion is typically preserved by programmatic parsers and may percent-encode or pass through unchanged in browsers. The attack surface is twofold: (a) validators that split on `\` to extract host see different host than the parser's split-on-@; (b) authentication layers that read the credential may mishandle the escape, granting a secondary primitive (credential injection).

**Preconditions.** (1) Input traverses a validator that treats userinfo specially. (2) Downstream processing (auth layer, logging, trace system) reads the credential and does not escape backslash properly. (3) Browser's percent-encoding of `\` in userinfo differs from the server's unescape step.

**Attack recipe.** For the open-redirect primitive: submit `https://safe\.com@evil.com/` to a validator that extracts the pre-`@` host (seeing `safe\.com` which contains `safe.com` substring, passes a substring check). Browser extracts host as `evil.com` and navigates. For the credential-injection primitive: submit `https://user:\pass@target/` to a client that reads the password component; a backslash-aware authentication layer may process the escaped password differently.

**Confirmation.** Open-redirect confirmation: observe browser navigation to `evil.com`. Credential-injection: measure differential response from the authentication endpoint — successful auth with the backslashed credential proves the backslash was handled.

**Impact.** Open redirect via userinfo-aware validators that trust the substring match; secondary impact in credential-injection if the downstream auth layer is permissive.

### Backslash before scheme

**Primitive.** Payload: `\https://evil.com/`. Unusual but observed in crafted inputs. Most parsers reject at parse time (the leading backslash is invalid); some lenient parsers pass through with `\https` as the scheme (which fails scheme-equality checks against `https`). Combined with a browser's leading-whitespace-strip (if any) or a validator fall-through-to-allow on scheme-mismatch, the attacker reaches navigation.

**Preconditions.** (1) Validator's scheme comparison falls through to allow on mismatch. (2) The input traverses a context that may strip leading whitespace or sanitize the `\`. (3) The browser's final navigation uses the sanitized form.

**Attack recipe.** Submit `\https://evil.com/`. Validator sees scheme as `\https` (not `https`), fails strict equality, falls through to allow. Server emits raw or minimally-normalized output. Browser applies leading-whitespace-strip (treats `\` as whitespace-like in some permissive handlers) and navigates to `https://evil.com/`.

**Confirmation.** Observed browser navigation. The pattern is rare in production but surfaces in deliberately-crafted fuzz inputs.

**Impact.** Open redirect bypass via scheme-mismatch-plus-permissive-fallthrough. Mitigation: strict scheme matching with no fall-through-to-allow.

### Backslash after host, before path

**Primitive.** Payload: `https://trusted.com\evil.com/path`. Treated as `host='trusted.com\evil.com'` by programmatic parsers (the `\` is part of the host string); `host='trusted.com'` with `path='\evil.com/path'` by WHATWG (which normalizes `\` to `/` for special schemes, so the host ends at the first `\` which it treats as `/`). A validator that uses `trusted.com\evil.com in ALLOWLIST` (substring check against `trusted.com`) succeeds; a browser normalizes and navigates to `trusted.com/evil.com/path` (safe within trusted.com) — but if the server reflects the raw string into a `Location:` header, the browser's redirect-handling path may apply the normalization differently.

**Preconditions.** (1) Validator uses substring-contains or startswith check for allowlist. (2) The redirect sink is server-side with raw string reflection. (3) Browser's redirect-handling normalization produces different host than direct-URL-bar navigation. (The exact behavior depends on browser version and the direct-vs-redirect path.)

**Attack recipe.** Submit `https://trusted.com\evil.com/path`. Validator passes (contains `trusted.com`). Server emits raw `Location:`. Browser's redirect handling applies special-scheme backslash normalization and navigates to `trusted.com/evil.com/path` — which is same-origin to trusted.com. This specific payload does NOT typically produce cross-origin navigation on modern browsers; it DOES open a secondary attack where the subsequent path on `trusted.com` is attacker-controlled. If `trusted.com` has a server-side URL-reflection endpoint on `/evil.com/path`, the chain extends.

**Confirmation.** The attack is bounded by what `trusted.com/evil.com/path` returns. If `trusted.com` has `/evil.com/*` reflected into a Location, iterative use of the primitive escalates. Fingerprint by submitting a sequence of nested forms and observing where normalization lands.

**Impact.** Secondary primitive — not a direct cross-origin navigation but a within-origin path-smuggling that composes with reflected URL sinks on the trusted host.

### Hunt method for backslash primitives

**Methodology.** Generate payloads with `\` in each position within a URL: before scheme, in scheme, after scheme-colon, before host, in host, after host, in userinfo, in path, in query, in fragment. Run each through the target's validator parser and compare to WHATWG `new URL()` output and (where available) direct `curl -L` observation. Any payload where parser-and-browser disagree on host extraction is a candidate for a bypass.

**Automated tool.** The measurement script at `.zen-batch-artifacts/batch9-20261003/measurement/scripts/06_url_parser_differentials.py` can be extended to accept a payload grid (positional backslash variants) and emit the per-pair host/path extraction. Run against the target's inferred parser pair; any row with a disagreement is a candidate.

**Confirmation per candidate.** For each candidate, construct the full URL (adding the needed path, query, context) and submit through the target's redirect sink. Browser-level observation of the final navigation closes the finding.

**Impact grid.** The hunt method surfaces 10-30 payload variants on most URL-parsing libraries; of those, 2-5 typically produce exploitable open-redirect primitives per target. The grid is reusable across targets with similar parser pairs.

## URL-Encoded Data Confusion Class

Parsers disagree on when percent-encoded sequences are decoded (at parse time vs at component-extraction time vs never). The disagreement produces primitives where the validator sees one URL and the fetcher sees another.

**Note on refuted URL-encoded loopback.** The deep-research pass refuted the claim that URL-encoded loopback addresses (`http://%67oogle.com`, percent-encoded forms of `127.0.0.1`) cause urllib/requests to dispatch to `127.0.0.1`. Three-vote adversarial verification failed on the primitive; current CPython 3.12 and urllib3 2.8.0 do not reproduce the behavior as described. This file does not claim that primitive. The URL-encoded primitives below are the ones that do reproduce.

**Encoded slash in path.** Payload: `https://trusted.com%2F@evil.com`. The `%2F` is percent-encoded `/`. Parsers that decode-before-split treat the input as `https://trusted.com/@evil.com` → host `evil.com` (the `@` is now after a slash, so it's not authority-separator). Parsers that split-before-decode see `trusted.com%2F@evil.com` as userinfo+host → host `evil.com` without needing decode. A validator that decodes-then-splits (less common) sees `evil.com`; a validator that splits-then-decodes (more common) also sees `evil.com`. The exploit requires a parser that treats `%2F` as a non-separator character in splitting but a slash in the final URL — rare, but observed.

**Encoded userinfo @.** Payload: `https://trusted.com%40evil.com/`. `%40` is percent-encoded `@`. The parser's decoding of `%40` to `@` before authority-split would produce userinfo `trusted.com` and host `evil.com`; the parser's not-decoding would produce host `trusted.com%40evil.com`. Browsers typically decode-at-parse (per WHATWG); programmatic parsers (urllib, PHP's `parse_url`) do not. The attack: a validator using `urlparse` sees host `trusted.com%40evil.com` (passes if the allowlist is substring-containing-`trusted.com`); the browser navigates to the decoded form `trusted.com@evil.com`, which treats `trusted.com` as userinfo and `evil.com` as host.

**Double-encoded sequences.** Payload: `https://trusted.com%252F@evil.com/`. `%25` is `%`; the double-encoded `%252F` decodes-once to `%2F`, decodes-twice to `/`. Parsers that decode once produce `trusted.com%2F@evil.com`; parsers that decode twice (or that the application decodes once then passes to another parser that decodes again) produce `trusted.com/@evil.com`. The combined validator-and-fetcher may disagree on the decoding depth. Attack vector: filter decodes once, fetcher decodes once more.

**Encoded dot in host.** Payload: `https://evil%2Ecom/` (`.` encoded as `%2E`). WHATWG decodes percent-encoded ASCII dots back to `.` for the host; programmatic parsers may not. A validator that extracts host `evil%2Ecom` and checks against `evil.com` fails; the browser decodes and navigates to `evil.com`.

**Encoded colon in scheme-host separator.** Payload: `https%3A%2F%2Fevil.com/`. Fully encoded `https://`. Most parsers fail to recognize this as a URL; some parsers that decode-before-reject do recognize it. Observed in URL-field validators that attempt lenient parsing.

**Non-ASCII percent-encoded sequences.** Payload: `https://%E4%B8%AD.evil.com/` (percent-encoded UTF-8). Parsers that interpret percent-encoded sequences as UTF-8 may extract a Unicode-domain-name host; parsers that treat each byte independently extract a different string. Load § Unicode / IDNA Normalization Class below for the IDN-adjacent class.

**Confirmation.** For each payload, measure what the parser produces (host, path) and what the browser navigates to. The pair that disagrees is the attack surface. The measured urllib3 differential script extended to percent-encoded payloads reproduces each of the above.

## Scheme Mixup Class

Parsers compare schemes with varying case-sensitivity and normalize differently.

**Uppercase scheme.** Payload: `HTTPS://evil.com/`. WHATWG canonicalizes to lowercase; Python's `urlparse().scheme` returns the original case; a validator comparing `url.scheme == 'https'` fails on `HTTPS`. If the validator passes on scheme-mismatch (allowing it through as "unknown scheme, treat as same-origin"), the attack succeeds.

**Scheme with trailing whitespace.** Payload: `https :/evil.com/` (whitespace between scheme and `:`). Rejected by most parsers; some lenient parsers trim whitespace and succeed. If the validator uses the trimmed form but the fetcher uses the untrimmed, confusion.

**Scheme with embedded control character.** Payload: `ht\x00tps://evil.com/`. Null byte in scheme. Some parsers truncate at null; others preserve the null and fail scheme-equality. Browsers often strip the null and navigate.

**Scheme name case-fold confusion.** Payload with Unicode-equivalent `S` (`Ѕ`, Cyrillic): `httpѕ://evil.com/`. Validators that normalize ASCII-case but not Unicode case-fold see `httpѕ` as a different scheme; browsers that case-fold Unicode may accept.

**Scheme smuggling via newline.** Payload: `javascript%0Ahttps://evil.com/`. The newline splits the input into two "logical lines"; parsers that process one line extract `javascript` as the scheme; parsers that process the other extract `https`. If the application reads the first line (for scheme extraction) but the browser follows the second (for navigation), the attack lands.

**Non-standard scheme.** Payload: `wss://evil.com/`, `data:text/html,...`, `blob:https://trusted.com/UUID`, `android-app://package/`. Validators that only check for `http`/`https` miss these; some are safe (data: in a navigation context is usually blocked by CSP) and some are not (wss: redirects can carry WebSocket authentication to the attacker).

## Userinfo Injection Class

The `userinfo@host` syntax of a URL carries authentication credentials. Attackers abuse the `@` to make the real host appear as the credential and the attacker host as the authority.

**Basic userinfo injection.** Payload: `https://trusted.com@evil.com/`. Programmatic parsers extract userinfo `trusted.com` and host `evil.com`; naive validators that check `url.contains('trusted.com')` pass; browsers navigate to `evil.com`. The base file's matrix covers this; the depth here is the variants.

**Multi-@ with escape.** Payload: `https://trusted.com%40trusted.com@evil.com/`. The first `%40` is encoded `@`; the parser's decoding behavior determines what counts as userinfo. If the parser decodes-at-parse, the full `trusted.com@trusted.com@evil.com` has two unencoded `@`s, and the parser picks the last `@` as authority-separator → userinfo `trusted.com%40trusted.com` → host `evil.com`. If the parser does not decode, userinfo `trusted.com%40trusted.com` → host `evil.com` still. Either way, `evil.com` is the host. The validator confusion arises when the validator decodes but checks the pre-decoded form.

**Userinfo with path-like characters.** Payload: `https://trusted.com/path@evil.com/`. The `/` before `@` ends the authority; the `@` is in the path. Parsers that split-on-first-@ incorrectly extract userinfo `trusted.com/path` and host `evil.com`; parsers that respect `/` end the authority at the first `/`. The browser respects `/`; a validator that doesn't fails. The attack: validator extracts `evil.com`, browser navigates to `trusted.com`. This is the reverse — a false-positive from the attacker's perspective, but a validator-bypass if the attacker's goal is to appear-legitimate.

**Userinfo with authentication credentials.** Payload: `https://admin:password@trusted.com/`. If the application logs the full URL, credentials leak. Not an open-redirect primitive directly, but a credential-stuffing adjacency.

**Fragment-with-@.** Payload: `https://trusted.com#@evil.com/`. The `#` starts the fragment; the `@evil.com/` is in the fragment, which browsers strip before navigation. No open redirect, but validators that treat the whole input as "authority" (not stopping at `#`) may incorrectly parse `evil.com` as the host — and reject the input as "evil.com not allowed." If the validator's rejection stops the request before the browser's fragment-strip, the request itself might be rejected but the actual navigation (if the attacker controls the full URL) would be safe. Confusion goes both ways.

**Query-with-@.** Payload: `https://trusted.com/path?x=@evil.com`. The `?` starts the query; the `@evil.com` is in the query. Similar to fragment handling.

**Userinfo in protocol-relative.** Payload: `//trusted.com@evil.com/`. Protocol-relative with userinfo. Parsers that recognize the `//` as scheme-relative extract host `evil.com`; parsers that don't recognize `//` without base throw. The attack: present at a context that resolves `//` as scheme-relative (common in `<a href>` and `location =` where the base is the current page URL).

## Fragment and Query Injection Class

The `#` and `?` separators disambiguate URL components. Attackers abuse them to split the URL across validator-visible and browser-visible pieces.

**Query injection.** Payload: `https://trusted.com/path?next=https://evil.com/`. The server-side validator reads the top-level URL (`trusted.com/path`) and passes; the application reads `next=https://evil.com/` and uses it as a redirect target. The common `?next=`/`?redirect=`/`?url=` parameters are the entry; validation must happen on the parameter's value, not just the top-level URL.

**Nested-URL-in-query.** Payload: `?url=%68ttps%3A%2F%2Fevil.com/`. Percent-encoded `https://evil.com/` as the query value. The validator reading the decoded parameter value sees `https://evil.com/`; the attack is whether the validator checks the decoded or raw form.

**Fragment-with-URL.** Payload: `https://trusted.com/path#url=https://evil.com/`. The fragment is browser-side only; server-side logs may not record it. If a client-side script reads `window.location.hash` and uses it as a redirect target, the fragment is the attack vector; load § Client-Side Sinks.

**Fragment survives OAuth response.** OAuth implicit flow puts the `access_token` in the fragment. An open redirect that preserves the fragment leaks the token to the attacker's redirect target. Load § OAuth redirect_uri Chain — Advanced Depth.

**Query-and-fragment combined.** Payload: `?a=1#@evil.com`. The `?` separates query from path; the `#` separates fragment from query. The combined input is `?a=1#@evil.com` with the fragment being `@evil.com`. Parsers that extract the "host-after-@" from the full input (not respecting fragment boundary) see `evil.com`. Attack: the validator misparses, the browser correctly navigates to the base URL (safe).

## Unicode / IDNA Normalization Class

Internationalized Domain Names (IDN) use Punycode for the ASCII representation of Unicode domain names. The IDN-vs-ASCII differential is a common bypass surface.

**Punycode homograph.** Payload: `https://truѕted.com/` (Cyrillic `ѕ` instead of Latin `s`). The Unicode form is `truѕted.com`; the Punycode form is `xn--trusted-7jc.com`. A validator that normalizes to Punycode and compares against the ASCII allowlist sees a different domain than the Unicode form; a validator that compares the Unicode form directly also sees different. The browser displays the Unicode form (which looks identical to `trusted.com`) and navigates to the Punycode form.

**IDN with trailing dot.** Payload: `https://trusted.com./`. The trailing dot is a canonical hostname terminator. Validators that strip-and-compare (or that compare with/without the trailing dot inconsistently) accept differently. The browser treats both as the same domain.

**Full-width characters.** Payload: `https://trusted.com。evil.com/` (`。` is a full-width period, U+3002). Parsers that treat `。` as separate from `.` extract host `trusted.com。evil.com` as a single label; others normalize `。` to `.` and extract `trusted.com.evil.com` with a subdomain `trusted.com` under `evil.com`. The attack: validator sees `trusted.com` substring (passes); browser navigates to `evil.com`.

**IDN with mixed-script characters.** Payload: `https://аpple.com/` (Cyrillic `а` + Latin `pple`). Mixed-script forms are visually similar but produce different Punycode. Modern browsers detect mixed-script and display Punycode as a warning; older browsers do not.

**IDN URL display vs navigation.** The displayed URL in the address bar may be the Unicode form; the actual navigation and TLS cert validation use the Punycode form. A domain the attacker registers under Punycode (`xn--trusted-...`) displays as the Unicode form; combined with a weak CA that issues a cert for the Punycode form, the attack is a visual-phishing-with-valid-TLS primitive.

**IDNA 2003 vs IDNA 2008.** The two IDNA specs disagree on some characters. Validators using one spec and browsers using another can produce bypasses on specific character choices. The frontier is thin here but observed in enterprise-security tools that pin to IDNA 2003.

## Server-Side Fetcher Redirect-Following SSRF Chain Depth

Server-side fetchers (link unfurlers, image fetchers, PDF-from-URL converters, OpenGraph scrapers, webhook delivery) typically follow redirects. An open redirect on an allowlisted host chains to SSRF against internal targets.

**Classic chain: allowlisted redirector → internal target.** The fetcher validates the target URL against `*.trusted.com`. The attacker finds an open redirect at `trusted.com/out?url=`. The fetcher starts at `trusted.com/out?url=http://169.254.169.254/latest/meta-data/`; the first-hop allowlist passes; the fetcher follows the 302 to the metadata service. Load `ssrf.md` for the primitive discovery and `cloud/aws.md` for the metadata-service specifics.

**Multi-hop redirector chaining.** Fetcher validates only the first hop. Chain: `trusted.com/out?url=https://attacker.tld/r1` → `attacker.tld/r1` 302s to `https://trusted.com/out?url=https://attacker.tld/r2` → and so on, each hop re-validating against the allowlist. Eventually the chain lands at the internal target. The hunt is for fetchers with a hop-count-greater-than-1 but allowlist-only-first-hop semantics.

**Redirect to private-IP ranges.** Payload: `trusted.com/out?url=http://10.0.0.1/`, `http://192.168.1.1/`, `http://172.16.0.1/`. Load `ssrf.md § Private IP Range Discovery` for the enumeration.

**Redirect to DNS-rebind host.** Payload: `trusted.com/out?url=http://attacker.rebind.tld/`. The attacker-controlled DNS returns `127.0.0.1` for the first fetch and the real external IP for subsequent fetches, or vice versa. The redirect chain uses the first response for the allowlist check (external IP) and the second for the fetch (internal IP).

**Redirect to the fetcher's own metadata service.** Chain: `trusted.com/out?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` reaches AWS credentials from an EC2-hosted fetcher. The combination with role-based access produces full AWS account access. Load `cloud/aws.md § EC2 Metadata Service` for the role-specific discovery.

**Redirect to IPv6 forms.** Payload: `trusted.com/out?url=http://[::ffff:127.0.0.1]/`. IPv4-mapped IPv6 bypass of IPv4-only allowlists; the fetcher resolves to IPv4-loopback.

**Redirect to Gopher / FTP / file:.** Payload: `trusted.com/out?url=gopher://internal.svc:6379/_PING`. Gopher scheme allows sending arbitrary bytes to a port, reaching Redis / Memcached / MongoDB protocols. `file:///etc/passwd` reaches local file read. Chain depth: the fetcher's scheme allowlist is the gate.

**Confirmation.** For each chain, present the payload and measure (a) the fetcher reaches the final target (via timing or error leak), (b) the response content is reflected to the attacker (if the fetcher returns the fetched content), or (c) a side-effect at the internal target is observable.

## Multi-Hop Validation Depth

Validators that validate only the first hop in a redirect chain are the common bug class.

**First-hop-only.** The validator reads the input URL, confirms it's on the allowlist, and the fetcher follows redirects without re-validating. Any open redirect at the first hop extends the chain to any attacker target. The headline example is the classic `trusted.com/out?url=` → `attacker.tld` chain in § Server-Side Fetcher.

**Full-chain validation.** The validator (or fetcher config) validates every hop. The attack surface here is parser-differential-across-hops: the chain begins at a URL the validator parses one way and the fetcher parses another; later hops exploit the fetcher's parser.

**No-hop validation.** The validator skips redirect-following entirely and relies on the first-response's `Location:` header. The attack: the attacker's first-hop response includes a redirect to the internal target; the fetcher follows without any validation.

**Validated-but-not-dispatched.** Some fetchers validate URLs for compliance (block private IPs) but dispatch via a separate HTTP library that doesn't enforce. The chain: validator passes (external IP), fetcher's library (urllib3 vs requests) dispatches to a different host than the validator extracted.

**Confirmation.** For each shape, present a payload that reveals the handling: first-hop-only reveals via a chain of redirect-to-internal; full-chain reveals via parser-differential at the final hop.

## Framework-Specific Redirect Sinks

Each framework has its own redirect helper. The helper's safety depends on how it handles the destination URL.

**Rails `redirect_to`.** `redirect_to params[:url]` is the dangerous shape; Rails prior to 7.0 passed any URL to the response. Rails 7.0+ requires `allow_other_host: true` to redirect to a different host; the default rejects cross-origin. Weakness: `redirect_to url_for(params)` with `only_path: false` (deprecated but common in legacy code) permits cross-origin. The URI.parse path for Clearance (CVE-2021-23435) is in `open_redirect_novel_deep.md`.

**Django `HttpResponseRedirect` / `redirect`.** Django's `redirect()` helper accepts a URL, a view name, or a model instance. For URL inputs, Django does not canonicalize or validate the destination; the application must call `is_safe_url()` (deprecated in Django 4.0) or `url_has_allowed_host_and_scheme()` (post-4.0). Weakness: deployments that migrated from `is_safe_url()` to the newer function without updating the allowed-hosts list.

**Flask `redirect()`.** `redirect(url)` passes any URL. The common extension `Flask-Login`'s `next` parameter uses `url_for('login', next=request.args.get('next'))` and `redirect(next)` on login; absent `url_has_allowed_host_and_scheme()`-equivalent, the `next` parameter is a redirect target.

**Express `res.redirect()`.** Node Express `res.redirect(301, url)` passes any URL. No built-in validation; the application must call a validator. Weakness: deployments that use `req.query.redirect` or `req.body.redirect` directly as the destination.

**Spring MVC `redirect:`.** Spring's `return "redirect:" + target;` passes any URL. Spring Security's `SavedRequestAwareAuthenticationSuccessHandler` restores the pre-login URL; the `savedRequest` is validated against the application's own URLs by default, but custom handlers may bypass.

**ASP.NET Core `LocalRedirect` vs `Redirect`.** `LocalRedirect(url)` validates `Url.IsLocalUrl(url)` and throws if the URL is external; `Redirect(url)` accepts any URL. The developer must choose correctly. Weakness: deployments that use `Redirect(returnUrl)` without the local-URL check.

**FastAPI `RedirectResponse`.** Python FastAPI's `RedirectResponse(url=target)` passes any URL. No built-in validation; same bug class as Flask.

**Go Gin `c.Redirect`.** Gin's `c.Redirect(code, location)` passes any URL. The caller must validate.

**Framework-pattern fingerprint.** The common thread across every framework: the redirect helper takes a URL and emits a `Location:` header without validation; the application must validate before calling. Any framework that provides a "safe" redirect alongside an "unsafe" redirect (ASP.NET Core's `LocalRedirect` vs `Redirect`) exposes the choice as the attack surface. For the Rails URI.parse-stripping behavior that produces the slash-confusion CVE-2021-23435 class, load `open_redirect_novel_deep.md § Clearance Historical Anchor`.

## OAuth redirect_uri Chain — Advanced Depth

The base file covers the OAuth code-interception pattern. This section covers depth beyond the primary chain — each sub-primitive is a redirect_uri validation weakness that enables code interception on its own or chains with another primitive to extend the exposure.

### Prefix-match vs exact-match redirect_uri

**Primitive.** OAuth 2.0 permitted prefix-matching on `redirect_uri`; RFC 9700 and OAuth 2.1 require exact string match. Pre-2024 deployments with prefix-match: a registered pattern `https://app.example/*` matches any URL under that prefix, including `https://app.example/attacker-controlled-path`.

**Preconditions.** (1) Authorization server configured with prefix-match semantics. (2) The registered prefix includes a path or wildcard that extends to attacker-controllable paths. (3) Any attacker-controlled endpoint exists at the matched path — reflected-user content, path-traversal-reach, user-generated content hosted on the registered path, or any URL-reflecting feature on the trusted host.

**Attack recipe.** Register the attacker's path on the trusted host (post an issue if the host hosts a public-content feature, upload a file to a user-content path that then reflects, use a path-traversal primitive to reach a reflecting endpoint). Craft the authorization request with `redirect_uri=https://app.example/<attacker-controlled-path>`. The authorization server's prefix-match passes; the code is delivered to the attacker's path. The attacker's path reflects the full URL (including the `code` parameter) in a way the attacker can read (via post content, a stored log, a client-side script).

**Confirmation.** Observe the `code` reaches the attacker-controlled path. Negative control: an authorization request with a non-prefix-matching URI (`https://evil.tld/cb`) is rejected — the pair shows prefix-match-vs-exact-match.

**Impact.** Full code interception without needing an open-redirect primitive. Chain into the token endpoint for full account access.

### Regex-match redirect_uri

**Primitive.** Some authorization servers permit regex as the matching semantic. Weak regex: `https://app\.example/callback.*` matches `https://app.example/callback.evil.tld/`. The authentik CVE-2024-52289 is in this class on the admin-config side where unescaped `.` metacharacters in registered URIs match any single character.

**Preconditions.** (1) Authorization server supports regex matching. (2) The registered URI contains regex metacharacters (`.`, `*`, `?`, `+`, `|`, `(`, `)`, `[`, `]`) that are not escaped by the server before compilation. (3) Attacker can register (or already holds) a domain that matches the metacharacter-pattern.

**Attack recipe.** For an `.`-based bypass: given registered `https://app.example.com/callback`, acquire `appxexample.com` (single-char substitution for the TLD-adjacent `.`); submit authorization with `redirect_uri=https://appxexample.com/callback`. The server's compiled pattern `app.example.com/callback` matches (`.` matches `x`), allows. Code delivered to attacker domain. For a `*`-based bypass: given `https://*.app.example.com/callback`, submit `redirect_uri=https://app.example.com.evil.com/callback` — some regex compilations treat the `*` as greedy and match arbitrary suffixes.

**Confirmation.** Observe the `code` parameter arrive at the attacker-chosen host. The mechanism and version metadata lives in `open_redirect_novel_deep.md § authentik Redirect-URI Regex-Metacharacter Bypass`.

**Impact.** Full code interception; chain to token issuance. The authentik class recurs across any OAuth implementation with regex-based matching and no `re.escape`-equivalent in the config loader.

### Scheme-mismatched redirect_uri

**Primitive.** The server allows both `https://app.example/cb` and `http://app.example/cb` as the same registered URI (either explicitly configured or by not pinning the scheme). An attacker on the same network downgrades the response to HTTP and intercepts.

**Preconditions.** (1) Server treats `http:` and `https:` as scheme-equivalent for redirect matching. (2) Attacker has a network position permitting HTTP interception (same WiFi, compromised router, MitM-adjacent position, downgrade attack on TLS). (3) The target client does not enforce HTTPS at the browser level (missing HSTS or pre-HSTS-era user agent).

**Attack recipe.** Craft authorization request with `redirect_uri=http://app.example/cb`. Server allows (scheme-equivalent). Server's redirect response goes to HTTP. Attacker's network position intercepts the HTTP request carrying `code`. Attacker exchanges the code at the token endpoint.

**Confirmation.** Observe the HTTP request to `app.example/cb` carrying the `code` parameter. Negative control: an HSTS-enforcing user agent upgrades the request to HTTPS, defeating the interception.

**Impact.** Full code interception on the same-network attack path. Load `vulnerabilities/network/mitm.md` for the broader MitM positioning. Mitigation: pin scheme on `redirect_uri`.

### Port-mismatched redirect_uri

**Primitive.** Server validates the host but not the port. `https://app.example:1234/cb` is allowed if `https://app.example/cb` is registered (port 443 default). The attacker uses a high-port service on the same host to receive the code.

**Preconditions.** (1) Authorization server's URI comparison omits the port component. (2) The attacker can run a service on an arbitrary port on the registered host (via SSRF-adjacent write, container-breakout to a neighboring service, cloud-adjacent port-reach).

**Attack recipe.** Set up an attacker-controlled service at `https://app.example:1234/cb`. Craft authorization request with `redirect_uri=https://app.example:1234/cb`. Server validates host-only (`app.example`), allows. Code delivered to port 1234, which the attacker controls.

**Confirmation.** The attacker's port-1234 service receives the `code`.

**Impact.** Code interception with a host-local attacker port. Chain requires port-reach, which is non-trivial but exists in multi-tenant hosting, cloud-provider misconfigurations, and container-escape scenarios.

### redirect_uri with URL fragment preservation

**Primitive.** OAuth implicit flow puts the token in the fragment (`#access_token=...`). A `redirect_uri` with a fragment preserved through the browser's redirect may be read by attacker-controlled JavaScript on the redirect page. The attack specifically targets the implicit flow (being deprecated per OAuth 2.1 but still deployed on legacy clients).

**Preconditions.** (1) Deployment supports implicit flow (`response_type=token` or `response_type=id_token`). (2) The `redirect_uri` host executes attacker-controllable JavaScript on the callback path (reflected XSS, same-origin iframe, SPA router). (3) The browser preserves the fragment on redirect (standard behavior).

**Attack recipe.** Register (or compromise) a URL on the client's host that executes attacker JavaScript on page load. Craft authorization request with `response_type=token&redirect_uri=https://client.example/compromised-path#attacker_read=1`. The token lands in the fragment at the compromised path. Attacker's JavaScript reads `window.location.hash` and exfiltrates.

**Confirmation.** Attacker's exfil endpoint receives the token.

**Impact.** Full token theft without needing an open-redirect; the primitive is a client-side XSS or reflection on the registered host. OAuth 2.1 deprecates implicit flow specifically because of this attack surface class.

### post_logout_redirect_uri

**Primitive.** OIDC's `post_logout_redirect_uri` is the URL the authorization server redirects to after logout. It is typically validated more weakly than `redirect_uri` because logout is perceived as low-impact — but a redirect from the authorization server to attacker.tld is still a phishing-grade primitive.

**Preconditions.** (1) OIDC authorization server supports `post_logout_redirect_uri`. (2) Validation for logout-URI is lax: no explicit allowlist, substring match on the client's domain, or any-URL-accepted. (3) User-facing logout flow allows attacker-crafted logout URLs.

**Attack recipe.** Craft a logout URL: `https://authsrv.example/logout?post_logout_redirect_uri=https://attacker.tld/`. Share the URL with the victim. On click, the authorization server completes logout and redirects to attacker.tld. The attacker's page presents a lookalike login screen; the victim re-enters credentials.

**Confirmation.** User browser navigates to attacker.tld after logout.

**Impact.** Phishing-grade primitive via a trusted-brand URL. Fingerprint deployment weakness by probing the logout endpoint with various URIs and observing which pass.

### redirect_uri with reserved query parameters

**Primitive.** The server validates the URL's host+path but not the full URL (ignoring the query component). An attacker appends `?code=<attacker-controlled>` to the registered URI; the authorization server appends its own `code=<real>` on redirect; a client that reads the last-matching `code=` parameter sees the attacker's.

**Preconditions.** (1) Authorization server's URI comparison ignores query component. (2) Client parses the URL and takes the "last" `code=` match (or "first" — the direction determines which attack works). (3) Attacker can craft the full `redirect_uri` including query parameters.

**Attack recipe.** Craft authorization request with `redirect_uri=https://app.example/cb?code=attacker-chosen-value`. Server allows (query ignored). Server appends `code=real-code&state=...` on redirect, resulting in `https://app.example/cb?code=attacker-chosen-value&code=real-code&state=...`. Client reads the first `code` parameter — sees attacker's value. Client sends attacker's value to the token endpoint — fails. BUT: a client that uses the request's `code` claim for display or for a secondary request may leak the real code via a response or log entry.

**Confirmation.** The specific exploitability depends on how the client processes duplicated `code` parameters. Fingerprint the client's parsing (first-wins vs last-wins vs error-on-duplicate).

**Impact.** Partial — the direct attack is bounded by client parsing semantics, but secondary leaks are common.

### Hybrid-flow response capture

**Primitive.** Hybrid OIDC flows (`response_type=code id_token` or `code id_token token`) return both the code and an id_token in the redirect. If the redirect_uri target leaks either, the chain is immediate forgery.

**Preconditions.** (1) OIDC deployment supports hybrid flow. (2) The redirect_uri target has a leak surface — client-side script that logs the URL, Referer leak when loading a subresource, server-side logging of the Location.

**Attack recipe.** Craft hybrid-flow authorization request. The response URL carries both artifacts. Any leak (Referer header to attacker-hosted subresource, logged Location header reachable via log-scrape, screen capture via UI phishing) extracts one or both. The id_token alone grants claim-level authentication; combined with the code, grants full token exchange.

**Confirmation.** Observe id_token or code in the leaked surface (log file, Referer tracking, UI capture).

**Impact.** Multiplied impact over code-only flow — the id_token alone identifies the user to the attacker; code enables token exchange.

### Pushed Authorization Requests (PAR) endpoint abuse

**Primitive.** PAR (RFC 9126) stores the authorization-request parameters server-side and returns a `request_uri` the client passes to the authorization endpoint. The attack surface is on the PAR endpoint itself: if PAR accepts an arbitrary `redirect_uri` from an unauthenticated or weakly-authenticated caller, the attacker queues their malicious request and triggers the victim to visit the authorization endpoint with the attacker's `request_uri`.

**Preconditions.** (1) OAuth server exposes a PAR endpoint. (2) PAR endpoint does not enforce client authentication or accepts weak client authentication. (3) The victim can be induced to visit a crafted URL containing the attacker's `request_uri`.

**Attack recipe.** Submit a PAR request with `redirect_uri=https://attacker.tld/cb` under weak-or-no authentication. Server returns `request_uri=urn:ietf:params:oauth:request_uri:<token>`. Craft the authorization URL: `https://authsrv.example/authorize?request_uri=<attacker-token>`. Trick the victim into visiting. Victim authenticates; server reads the stored `redirect_uri` from the attacker's PAR submission; code delivered to attacker.tld.

**Confirmation.** The `code` arrives at the attacker's `redirect_uri`.

**Impact.** Full code interception via the PAR back-channel, bypassing any `redirect_uri` validation that occurs at authorization-request time (because the attacker's URI was already stored). Mitigation: require strong authentication on PAR; validate `redirect_uri` on both PAR submission and authorization.

### redirect_uri on wildcarded subdomains

**Primitive.** `*.app.example/cb` matches `attacker.app.example/cb`. If the attacker can register `attacker.app.example` (via dynamic DNS, subdomain takeover, dangling-DNS acquisition), the chain is full code capture under the trusted apex.

**Preconditions.** (1) Authorization server configured with wildcard-subdomain matching. (2) Attacker can register or acquire a subdomain under the trusted apex. (3) Wildcard-matching does not additionally require the subdomain to be in an admin-controlled allowlist.

**Attack recipe.** Enumerate dangling DNS records under the trusted apex — common on cloud providers (Azure, Heroku, GitHub Pages, CloudFront) where a subdomain CNAME points to a resource the attacker can claim. Load `vulnerabilities/subdomain_takeover.md` for the primitive and `reconnaissance/subdomain_enumeration` for the hunt. Claim the subdomain. Craft authorization request with `redirect_uri=https://<claimed-subdomain>.app.example/cb`. Code delivered.

**Confirmation.** Attacker's claimed subdomain receives the code.

**Impact.** Full code interception without needing a prior client compromise; the attack is a composition with subdomain takeover. The 2024-2026 subdomain-takeover frontier remains active on specific CDN providers; the subdomain_takeover skill (Batch 10 scope) covers the current provider status.

## SAML RelayState Chain Depth

SAML's `RelayState` parameter carries session-state across the authentication redirect — a client-defined opaque string that the IdP relays back verbatim with the SAML Response. Weak validation of `RelayState` by the Service Provider (SP) enables open-redirect-equivalent attacks even when the SAML assertion itself is sound.

### RelayState as unvalidated redirect target

**Primitive.** The Service Provider commonly uses `RelayState` as "the URL to go to after login" — storing it before authentication, consuming it after. Attackers inject `RelayState=https://attacker.tld/`; the SP redirects there after login. The SP's trust in `RelayState` is misplaced because the IdP relays it verbatim without validation (per spec).

**Preconditions.** (1) SP accepts `RelayState` from an unauthenticated SP-initiated flow. (2) SP uses `RelayState` directly as a redirect target without allowlist. (3) The user is persuaded to initiate SAML login via an attacker-crafted URL.

**Attack recipe.** Craft the SP-initiated SSO URL: `https://sp.example/sso/initiate?RelayState=https://attacker.tld/phish`. Send to victim. Victim clicks, authenticates at IdP, IdP responds with SAML assertion to SP's AssertionConsumerService. SP processes the assertion successfully, then consumes `RelayState` and redirects the victim to `attacker.tld/phish` — presenting an authenticated-session cookie plus a phishing landing page.

**Confirmation.** Victim's browser navigates to `attacker.tld/phish` immediately after SAML authentication. The address bar shows the trusted SP's domain briefly, then shifts to attacker.tld — the phishing effectiveness is high because the user just authenticated.

**Impact.** Open-redirect-equivalent primitive on a federated authentication flow. The attack extends to credential-phishing (lookalike re-login prompt) or token-replay (if the SP sets session cookies on the browser before redirect, the attacker-page can exploit the authenticated state via cross-origin postMessage or embedded iframe tricks).

### RelayState signed but not verified

**Primitive.** The SAML spec permits signing `RelayState` as an optional integrity measure (common in IdP-initiated flows for binding RelayState to a specific issuance). Many SPs skip the signature verification entirely — treating RelayState as opaque text — so an attacker-crafted RelayState passes without the signature.

**Preconditions.** (1) IdP signs RelayState as part of its signature over the SAML Response. (2) SP's code does not include RelayState in the signature-verification scope. (3) Attacker can mutate RelayState in flight (MitM on the response, SP's return endpoint not HTTPS-enforced, or SP accepts arbitrary RelayState in SP-initiated flows).

**Attack recipe.** Intercept the SAML Response (or craft one in an SP-initiated flow). Modify the RelayState to attacker-controlled URL. Submit to the SP's AssertionConsumerService. SP verifies the SAML assertion signature (passes — attacker didn't touch the assertion); reads RelayState without re-verifying signature; redirects to attacker.

**Confirmation.** Compare the SAML Response's signature scope (reads the XML elements covered by the `<ds:Reference>` entries in the signature) against the elements the SP actually enforces. If RelayState is signed but not enforced, the primitive is live.

**Impact.** Open redirect bypassing the IdP's integrity measure — the SP's gap is the enforcement, not the signing.

### RelayState length-limit bypass

**Primitive.** SAML spec limits `RelayState` to 80 bytes. SPs that encode a full URL exceed the limit; attackers abuse the encoding format (base64, JWT-in-RelayState, hash-of-full-state with lookup) to pack malicious targets. The attack surface is the SP's workaround for the 80-byte limit.

**Preconditions.** (1) SP uses an encoding or indirection for RelayState (base64, URL-encoded, hash-with-storage lookup, JWT). (2) The encoding or lookup is attacker-manipulable.

**Attack recipe (base64 variant).** SP uses `base64(json)` to pack redirect-URL plus other state into RelayState. Attacker crafts `base64({"redirect":"https://attacker.tld/"})`, submits as RelayState. SP decodes, extracts redirect, follows. The attack is identical to the first class but through an encoding step.

**Attack recipe (hash-with-storage variant).** SP generates a hash and stores the full state server-side; RelayState is the hash. Attacker races a legitimate submission to seed storage with their redirect value, then captures the hash and uses it. Alternatively, if the hash is predictable (hash of user-visible fields), compute it offline.

**Confirmation.** Observe the decoded state (base64) or the mapped state (lookup) in the SP's handling. The exploitability depends on the exact encoding/lookup.

**Impact.** Open redirect through the encoding workaround. Mitigation: validate the decoded redirect URL against an allowlist after decoding.

### RelayState as JWT

**Primitive.** Some SPs use `RelayState` as a JWT with a `redirect` claim and a server-signed signature. The attack chain: compromise the JWT (via any of the `authentication_jwt` primitives — alg:none, RS→HS, weak HS secret, JWKS spoofing), inject attacker redirect in the compromised JWT, use.

**Preconditions.** (1) SP's RelayState format is a JWT with `redirect` claim. (2) SP's JWT verification has one of the common weaknesses enumerated in `authentication_jwt.md` / `authentication_jwt_advanced_deep.md`. (3) The attacker can obtain the signing key or forge the JWT via one of those primitives.

**Attack recipe.** Fingerprint the JWT library used for RelayState (same fingerprint approach as regular JWT — error strings, response-time differentials). Match to the `authentication_jwt_novel_deep.md § Measured Per-Library Matrix` for the exposed primitive. Forge a JWT with `redirect=https://attacker.tld/`. Submit as RelayState. SP verifies (vulnerable path), extracts redirect, follows.

**Confirmation.** The forged JWT is accepted and the redirect lands on attacker.tld.

**Impact.** Open redirect inherited from the JWT compromise. Chain requires upstream work in the JWT skill; this file is the sink.

## Reverse-Proxy and Host-Header Interaction Depth

Reverse proxies and CDNs between the browser and the application change the Host, X-Forwarded-*, and other headers. Validation that depends on these headers is exposed.

**Host-header-based URL construction.** `Location: https://${Host}/path` reflects the Host header into the redirect. Attackers manipulate `Host:` (or `X-Forwarded-Host:` if trusted) and point the redirect to an attacker host.

**X-Forwarded-Proto confusion.** The application decides HTTPS-vs-HTTP based on `X-Forwarded-Proto`. An attacker who can inject this header downgrades or upgrades the redirect scheme.

**Trusted-proxy-list bypasses.** The application trusts proxy headers from a configured proxy IP. If the IP check is weak (trusts any 10.x address, trusts XFF forwarded-by-chain), the attacker from a cloud environment with 10.x IP (or via a chain through a trusted hop) injects headers.

**X-Original-URL and X-Rewrite-URL.** IIS and some other servers honor these headers for URL rewriting. An attacker setting `X-Original-URL: https://evil.com/` can redirect the application's internal routing.

**Multi-tier proxy header stripping.** A proxy that doesn't strip incoming X-Forwarded-* headers lets attacker-injected values flow through. The hunt: check whether the proxy adds-to or replaces-the-list.

## Blind and Second-Order Open Redirect

Not every open redirect produces a visible navigation. Blind variants require measurement.

**Logging-sink open redirect.** The application stores the destination URL in an audit log; a later report generation (admin dashboard) renders it as a clickable link. The admin clicks, navigates to the attacker. Chain: log-write → log-read-and-render-as-link → admin-click.

**Email-link open redirect.** Password-reset or notification emails include a redirect URL. If the URL is attacker-chosen (via a reset-request with a crafted URL field), the email arrives at a legitimate user with an attacker-controlled link. Chain: form submission → email delivery → user-click.

**Push-notification open redirect.** Mobile apps that render push-notification URLs. The attacker sends a notification URL via a push-service; the mobile app opens it. Combined with mobile-deep-link primitives, the chain reaches app-level sinks.

**Server-side-generated-links in APIs.** An API that returns links derived from an input URL (`"next_page": "/path?url=..."`) propagates the input. Validators focus on the primary input; the derived links also need validation.

**Second-order via caching.** The attacker's URL is cached by a CDN. The cached response's `Location:` header serves to subsequent users. The chain is cache-poisoning + redirect; load `http_request_smuggling.md § Cache Poisoning`.

**OAuth code-interception as blind variant.** The attacker never sees the browser navigation; the chain works through the OAuth code being delivered to the attacker-controlled URL. The confirmation is "a token was issued" rather than "a navigation happened."

## Client-Side Sinks

Client-side redirect sinks execute in the browser; the attack surface is distinct from server-side.

**`location`, `location.href`, `location.assign`, `location.replace`, `window.open`.** All navigate to the input URL. For each, source=`params.get('next')` or `hash.substr(1)` or `postMessage(data)` is the attack-entry.

**Meta-refresh.** `<meta http-equiv="refresh" content="0;url=USER_INPUT">` injected into the DOM via `innerHTML` or SSR navigates. The injection is XSS-adjacent (load `xss.md`); the navigation is the open-redirect primitive.

**SPA router navigation.** React Router `navigate()`, Vue Router `router.push()`, Angular `Router.navigateByUrl()`, Next.js `router.push()` or `router.replace()`. Each accepts a URL and navigates; same-origin paths are relative, cross-origin paths are external. The common bug: `router.push(searchParams.get('next'))` without validation.

**`<a href>` and `<form action>` set from input.** `document.querySelector('a').href = userInput` is a passive sink until the user clicks; the attack is UI-driven.

**`<base href>` set from input.** A `<base href>` reflects into every subsequent relative-URL resolution on the page; attacker-controlled `<base>` redirects all relative links.

**Server-issued `Location:` echoed from client-controlled input.** The server receives a URL via a POST body, uses it in the subsequent response's `Location:` header. The attack: craft the POST, the response navigates the user.

**Service Worker fetch handlers.** A Service Worker that intercepts fetch and routes based on URL may route attacker-controlled URLs. The chain: compromise the service-worker registration (same-origin requirement, so chain with XSS or Service Worker takeover); route legitimate requests to the attacker's handler.

**postMessage-driven navigation.** A page that listens to `postMessage` for navigation commands and calls `location = event.data` without origin check accepts navigation from any opener/iframe. Load `vulnerabilities/browser_security.md` for postMessage depth; this file covers the open-redirect-via-postMessage shape.

## WebSocket Handshake and Redirect

WebSocket connections start with an HTTP handshake. Redirects during handshake have specific semantics.

**Handshake redirect-follow.** Browsers follow 3xx responses during WebSocket handshake. An attacker-controlled 302 at the WebSocket URL redirects to an attacker-controlled WebSocket server, which proxies the connection. The chain: WebSocket connection → redirect to attacker → attacker-mediated communication.

**Subprotocol / Origin confusion.** WebSocket handshake can specify subprotocols and origins. Redirects that cross-origin can confuse the browser's security model. Load `csrf_advanced_deep.md § CSWSH Against Hardened Targets` for the broader WebSocket-security surface.

**WebSocket URL in `Sec-WebSocket-Location`.** Some servers include URL fields in headers that reflect the attacker's host; downstream processing may trust these.

## Proxy and Gateway Redirect Policy Confusion

Proxies and gateways have their own redirect-following policies that interact with the application's.

**Proxy follows but application doesn't.** The proxy fetches `https://trusted.com/out?url=https://attacker.tld/` and follows the 302; the application code never sees the intermediate URL and processes the attacker's response as if from the trusted host. If the application trusts the proxy's URL as the actual origin, impact is high.

**Application follows but proxy doesn't.** The reverse: the proxy caches the first-hop response (the 302); subsequent users receive the cached 302 and follow to the attacker. Combined with cache-poisoning on the proxy, impact is multi-user.

**Redirect in Cache-Control.** A 302 response with aggressive `Cache-Control: public, max-age=86400` is cached by proxies. Subsequent users see the cached 302 and navigate to the attacker. Compose with cache-key-manipulation to make the cached response reach specific user populations.

**Proxy-stripped Location.** Some proxies strip or modify `Location:` headers (e.g., AWS CloudFront). The attacker's redirect may be dropped at the proxy; defender-side mitigation.

## Email Link, Password-Reset, and Invite Link Redirect

Links embedded in emails are a frequent open-redirect vector.

**Password-reset return URL.** The reset link carries a return URL; the user clicks, resets password, and is redirected. Attacker-controlled return URL redirects the user post-reset.

**Email verification return URL.** Similar shape. The user clicks a verification link, verifies, and is redirected.

**Invite link acceptance return URL.** Multi-tenant deployments invite users; the invite URL carries a return parameter. Attacker who controls the invite (first-tenant admin) sets the return to attacker.tld.

**Unsubscribe link return URL.** Unsubscribe links are typically GET-only and don't require authentication; attacker can craft an unsubscribe link that unsubscribes any user and returns to attacker.tld.

**Newsletter / notification tracking URL.** Email tracking URLs (`https://email.sender.com/track?url=`) are open redirectors by design. If the sender's URL is on a trusted-sender list, phishing emails abuse the tracking URL to deliver attacker links from a legitimate-looking source.

**Chain: email → user-click → open redirect → phishing.** The composite is the standard phishing pattern. Open redirect is one hop; the whole chain is the attack.

## Mobile Deep-Link Redirect

Mobile apps register URL schemes; attackers craft URLs that invoke the app with attacker-controlled parameters.

**App-link redirect handling.** The app receives a URL via its intent filter / URL scheme handler; renders the URL in a WebView or passes to an internal navigation. Attacker-controlled URLs navigate to attacker destinations.

**Deep-link to in-app browser.** Deep links that open an in-app browser (WKWebView, SFSafariViewController) accept any URL. Combined with the in-app browser's ability to share cookies/tokens, the chain leaks session state.

**Cross-app redirect.** App A's URL scheme handler takes a URL and calls `UIApplication.open(url)` to launch another app. An attacker-controlled URL launches an attacker-chosen app (if installed) or opens a web URL that leads to attacker.tld.

## Confirmation Methodology — Open-Redirect-Specific

Open redirect confirmation requires more than "server returned 302."

**Observe the browser's actual navigation.** The attack is a navigation, not a status code. Use a browser (not just curl) to confirm the destination is attacker.tld. Headless browsers (Puppeteer, Playwright) automate this.

**Status-code-independent navigation.** 301, 302, 303, 307, 308 all redirect; some change method, some don't. 307/308 preserve the request method (POST stays POST), which matters for state-change redirects.

**Confirm the fragment preservation (OAuth-adjacent).** For OAuth implicit flow, the token is in the fragment. Confirm that the attacker's redirector preserves the fragment (not all redirects do — some strip, some URL-encode).

**Confirm scheme preservation.** `javascript:` as a redirect target in some sinks executes JavaScript; in others, it's rejected. The browser's handling depends on the sink (location.href executes javascript:, Location-header navigation does not).

**Confirm user-visible address bar.** The browser shows the final URL in the address bar. If the chain preserves the trusted URL in the bar (via a redirect that returns to the original before navigating), the phishing effectiveness is high.

**Confirm cross-origin dispatch (SSRF-adjacent).** For SSRF-adjacent chains, the fetcher must dispatch to the internal target. Confirm via a timing differential, a known-side-effect at the target, or a response reflection.

**Negative control: non-attacker URL.** Submit a non-attacker, non-allowed URL (like `https://google.com/`) and verify it's rejected or redirected. The pair with the attacker URL reveals the actual filter logic.

## Blind Open-Redirect Confirmation

Not every open redirect produces an observable client-side navigation.

**Collaborator URL in redirect.** Submit `https://<unique>.collaborator.net/` and watch for a DNS query or HTTP request from the target to the collaborator. Burp Collaborator, interactsh, or self-hosted equivalents provide the OOB channel. The absence of a hit does not prove the redirect doesn't happen (the server might not follow); the hit proves it does.

**Second-channel confirmation.** The redirect leaks into logs, metrics, analytics. If the attacker has read access to any of these (via a secondary vulnerability), the redirect's existence is confirmed.

**Timing-based confirmation.** A redirect that reaches an internal target with a known response-time (slow DB query, large file download) produces a measurable delay. Compare response times for allowed-URL vs crafted-URL.

**Response-header leakage.** Some fetchers leak upstream response headers (`X-Served-By`, cache-related, timing). If the headers differ by target, the redirect's destination is inferable.

## False Positives — Advanced

Open-redirect findings get rejected when the "redirect" is scope-bounded.

**Redirect to a sanitized URL.** The server redirects to the user-input URL but the browser's URL bar shows a canonical form that strips the attacker component. The finding is "redirect happened" but the user-visible outcome is safe.

**Redirect inside an iframe.** The target navigates in an iframe context; same-origin policies limit impact to the frame. Not a top-level navigation.

**Redirect with user confirmation.** Some redirects show "You are leaving trusted.com; are you sure?" page. The user-confirmation step narrows phishing effectiveness; impact is bounded.

**Redirect to only-same-host.** The validator produces a canonical form that forces same-host navigation; the attack appeared to redirect but actually stayed within the trusted host.

**Redirect to a known-safe third-party.** Some redirects to known-safe destinations (Google login, documentation sites) are intentional and non-exploitable.

**Redirect by UI, not by link.** A redirect that requires UI interaction (click confirmation) is bounded by the user's choice.

## Post-Fix Adjacent-Bug Prediction

When a redirect validator is patched, the adjacent bug follows the parser-differential pattern.

**Patched one parser.** Only one of the parsers in the chain was updated; the validator-vs-fetcher differential persists. Hunt lead: audit which parsers the application uses and verify each is patched to the same canonicalization.

**Patched one allowlist.** The server now checks one allowlist strictly but another allowlist elsewhere (e.g., post_logout_redirect_uri) remains loose. Hunt lead: enumerate all redirect-accepting endpoints.

**Patched regex to add escapes.** The authentik CVE-2024-52289 pattern: the fix wraps `.` in `\.`; a sibling regex may not have been updated. Hunt lead: search for all `re.escape`-less regex patterns in the codebase.

**Patched decoding depth.** The fix decodes once; the attacker finds a double-encoded payload. Audit the full decode chain.

**Patched scheme list.** The fix adds `javascript:` to the blocklist; the attacker finds `vbscript:` or `data:text/html,`. Hunt lead: the full dangerous-scheme list is long and OS/browser-dependent.

## Summary

Advanced open-redirect depth is the operational tier where single-payload tests already got rejected and the attack moves to the parser-differential class, framework-specific sink patterns, OAuth and SAML chain construction, and client-side sinks that bypass server-side allowlists. The common thread across every section is the same: *the attack is a disagreement between the parser that validates and the parser (or browser) that acts.* Confirmation discipline — browser-level verification, status-code-independent navigation, fragment preservation, scheme preservation — rules out false positives before any claim of exploitable redirect. For the 2024–2026 CVE mechanisms (authentik regex-metachar, urllib3 redirect-policy mismatches, URL-parser-disagreement SSRF class) load `open_redirect_novel_deep.md`.
