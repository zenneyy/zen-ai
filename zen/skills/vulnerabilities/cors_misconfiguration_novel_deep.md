---
name: cors-misconfiguration-novel-deep
description: 2024–2026 CORS misconfiguration frontier — verified middleware-default CVE catalog (Flask-CORS cluster, Fiber v2, Hono, elysia-cors), Chrome Private Network Access header mechanics with unverified-current enforcement state, framework audit anchors (Spring @CrossOrigin, AWS API Gateway HTTP APIs), and the bounded-live-frontier reasoning.
sibling: cors_misconfiguration
load_when: scan_mode == "deep"
---

# CORS Misconfiguration — Novel Deep

Load `cors_misconfiguration` for the base-tier framing (attack-surface, three-condition confirmation rule, key-vulnerability classes). Load `cors_misconfiguration_advanced_deep` for allowlist-bypass depth, preflight expansion, PNA mechanics in detail, framework-middleware audit discipline, and chained exploitation. This file owns the 2024–2026 verified middleware-default CVE catalog with version/fix metadata as the single-ownership canonical source — the base and advanced siblings reference these CVEs by number with filename+section pointers only — plus the bounded live-frontier reasoning for the mature CORS class.

The CORS novel-tier frontier is comparatively narrow: no new browser-level technique classes have landed since Jan 2024, and the 2024–2026 live frontier is dominated by middleware-default CVEs in widely-deployed libraries (Flask-CORS, Fiber, Hono, elysia-cors). The browser-side primitives have been stable since the Fetch standard's wildcard-vs-credentials prohibition took effect; the live frontier is where configuration defaults are legitimately `fail-open`. This file's structure reflects that bounded shape — the CVE catalog is the depth; the bounded-live-frontier reasoning explains why the surface is middleware-default-dominant rather than new attack primitives.

## 2024–2026 Live Frontier — Scope

The 24 primary-source-verified claims from the Batch 13 CORS research pass yielded ten CVE-anchored or audit-anchored findings. Of these:

- **Six middleware CVEs** that globally resolve on GitHub Security Advisory REST and NVD (Flask-CORS × 3, Fiber, Hono, elysia-cors)
- **Two framework audit anchors** without CVE assignment (Spring @CrossOrigin defaults, AWS API Gateway HTTP APIs AllowOrigins behavior)
- **One browser-mechanic update** with unverified-current enforcement state (Chrome Private Network Access)
- **One baseline technique class** that remains the dominant vulnerability shape and anchors the base file (naive origin reflection + ACAC:true)

No new browser-level CORS technique classes (not covered by the pre-2024 PortSwigger/OWASP WSTG baseline) emerged. The DoubleClickjacking / defense-irrelevant UI-redress frontier (per `clickjacking_novel_deep`) has no CORS-adjacent primary-source material; the two classes are architecturally orthogonal.

## Flask-CORS Middleware Cluster — Verified CVE Catalog

Three independent primary-source-resolving CVEs land on the Python Flask-CORS middleware across the Batch 13 research pass. Shared affected-package: `flask-cors` on PyPI.

### CVE-2024-6844 — unquote_plus Path-Normalization Desync

- **GHSA**: `GHSA-8vgw-p6qm-5gr7`
- **Severity**: Medium (CVSS 5.3), CWE-346 (Origin Validation Error)
- **Affected**: `flask-cors` on PyPI, versions `<= 5.0.1`
- **Fix**: `6.0.0`; fix commit `35d875319621bd129a38b2b823abf4a2f6cda536`
- **Published**: 2025-03-20

**Mechanism**: Flask-CORS passes `request.path` through `urllib.parse.unquote_plus` for CORS allowlist/path matching. The `unquote_plus` function decodes `+` characters into space (` `) in addition to the standard percent-decoding. The Flask routing layer does not apply the same transform. The CORS matching path is therefore desynchronized from the actually-routed path: either (a) the CORS check passes for a path different from the handled path (allowlist bypass), or (b) the CORS check fails for a path that is in fact being routed (legitimate blockage producing CORS errors on correct requests).

**NVD-vs-GHSA version-metadata inconsistency**: NVD CPE narrowly lists only `4.0.1` while GHSA lists the broader `<=5.0.1` range fixed in `6.0.0`. Cite GHSA for the range; this file's canonical statement follows GHSA.

**Attack vector**: attacker crafts a URL path containing `+` that the Flask-CORS allowlist matches against (e.g., allowlist uses regex over paths; path contains `+` that `unquote_plus` converts to space, matching an allowlist pattern that the real path does not). Impact is bidirectional:
- Allowlist bypass → attacker Origin for a path matching the desync-allowed pattern
- Legitimate-endpoint block → DoS on real requests whose CORS check fails

**Confirmation**: deployed Flask-CORS version is `<=5.0.1`; endpoint uses per-path CORS configuration; probe with path variants containing `+` that match the allowlist pattern.

### CVE-2024-6866 — try_match Case-Insensitive Path Matching

- **GHSA**: `GHSA-43qf-4rqw-9q2g`
- **Severity**: Medium (CVSS 5.3), CWE-178 (Improper Handling of Case Sensitivity)
- **Affected**: `flask-cors` on PyPI, versions `<= 5.0.1`
- **Fix**: `6.0.0`; fix commit `eb39516a3c96b90d0ae5f51293972395ec3ef358`
- **Published**: 2025-03-20

**Mechanism**: Flask-CORS reuses the `try_match` function — originally designed for host-name matching — to validate request paths. Host matching is case-insensitive (per DNS semantics); path matching should be case-sensitive (per URI semantics). The result is a path-allowlist check that treats cases as equivalent, enabling allowlist bypass via case-variation of the attacker-supplied path against an allowlist regex that pattern-matches a different path.

**Attack vector**: allowlist regex restricts paths like `/admin/*`; attacker requests `/ADMIN/sensitive` or `/Admin/sensitive`; the case-insensitive match admits the request as `admin/sensitive` for CORS purposes while the Flask router correctly routes to the different case-sensitive-matched handler (or the handler is unaware the case mismatches).

**Confirmation**: deployed Flask-CORS version `<=5.0.1`; endpoint uses per-path CORS; probe case-shuffled path variants against the allowlist pattern.

**Co-affected version range**: shares `<=5.0.1` → `6.0.0` with CVE-2024-6844. Governance implication: both Flask-CORS path-side CVEs share a single version-metadata anchor; this file is the single owner.

### CVE-2024-6221 — Access-Control-Allow-Private-Network Default-True

- **GHSA**: `GHSA-hxwh-jpp2-84pm`
- **Severity**: High (CVSS 7.5)
- **Affected**: `flask-cors` on PyPI, versions `<4.0.2`
- **Fix**: `4.0.2`; fix commit `7ae310c` (PR #363)
- **Published**: 2024 (before the two above)

**Mechanism**: Flask-CORS versions prior to 4.0.2 set `Access-Control-Allow-Private-Network: true` on every response where the request's `Access-Control-Request-Private-Network: true` header was present. There was no configuration option to disable this; the behavior was hard-coded. The 4.0.2 fix introduces both the `CORS_ALLOW_PRIVATE_NETWORK` config entry and the `allow_private_network` kwarg — proving neither existed previously.

**Critical downstream caveat**: the 4.0.2 fix **keeps `allow_private_network=True` as the default** for backwards compatibility. Downstream guidance in files reading this skill must not oversell 4.0.2 as secure-by-default. The refuted framing "upgrading to 4.0.2+ removes the default-true PNA behavior" (voted 1-2 refute) is explicitly out of scope and must not appear anywhere.

**Attack vector**: an internal service deployed with Flask-CORS <4.0.2 (or 4.0.2+ with default config) at a private IP automatically approves PNA preflights from any external page in a Chrome browser that enforces PNA. The result is cross-origin external-to-private credentialed reads of the internal API.

**Confirmation**: deployed Flask-CORS version <4.0.2 OR version 4.0.2+ with `allow_private_network` not explicitly set to `False`; private-network endpoint; Chrome PNA enforcement active; external page issues credentialed fetch.

## Fiber v2 (Go) — CVE-2024-25124

- **GHSA**: `GHSA-fmg4-x8pw-hjhg`
- **Severity**: Critical (CVSS 9.4)
- **Affected**: `github.com/gofiber/fiber/v2` (Go), versions `< 2.52.1`
- **Fix**: `2.52.1`; fix commit `f0cd3b44b086544a37886232d0530601f2406c23`
- **Published**: 2024-02-22

**Mechanism**: The CORS middleware allowed configuration with `Access-Control-Allow-Origin: *` AND `Access-Control-Allow-Credentials: true` simultaneously — the exact browser-rejected combination the Fetch standard forbids. The middleware did not validate the combination; the developer could ship the configuration without any runtime warning. The fix in commit `f0cd3b4...` adds middleware-side validation that panics on wildcard-origin + `AllowCredentials=true`, normalizes origins, and gates the ACAC emission.

**Advisory verbatim**: "The CORS middleware allows for insecure configurations... it allows setting the Access-Control-Allow-Origin header to a wildcard (*) while also having the Access-Control-Allow-Credentials set to true."

**Exploitability caveat**: the wildcard + credentials combination is browser-rejected (base file's § Wildcard Origin + Credentials — Browser-Rejected Dead Class), so the CVE's exploitability depends on a non-cookie credential-echo path. The CVE is still a Critical configuration vulnerability because (a) it indicates allowlist mis-design broader than the specific combination, and (b) chained with another middleware feature that echoes credentials (session in response body, bearer token in response header), it enables credential leak via wildcard.

**Confirmation**: deployed Fiber v2 version `<2.52.1`; CORS middleware configured with both wildcard origin and AllowCredentials=true; verify the response contains the combination (not just the configuration — Fiber may silently drop one in some code paths).

## Hono (JS) — CVE-2026-54290

- **GHSA**: `GHSA-88fw-hqm2-52qc`
- **Severity**: High (CVSS 7.1), CWE-942 (Permissive Cross-domain Policy)
- **Affected**: `hono` on npm, versions `<4.12.25`
- **Fix**: `4.12.25`
- **Published**: 2026-06-16

**Mechanism**: Hono's CORS middleware, when configured with `credentials: true` and no explicit `origin` (relying on the default wildcard), reflects the request's `Origin` header into `Access-Control-Allow-Origin` and emits `Access-Control-Allow-Credentials: true` for every origin — including `null`. The preflight also echoes requested headers back, approving non-simple credentialed requests. The middleware **laundered the Fetch-spec wildcard+credentials prohibition** by substituting reflection for rejection; the deployed config `credentials:true + default origin` used to fail closed (wildcard + credentials browser-rejected), now succeeds for every origin (reflected origin + credentials, browser-permitted).

**Advisory verbatim**: "The spec forbids Access-Control-Allow-Origin: * with credentials and browsers reject it, so this configuration used to fail closed. In affected versions the middleware reflects the request Origin instead, so it now succeeds for every origin, including null. The preflight also echoes the requested headers back, approving non-simple credentialed requests too."

**Attack vector**: Hono application configured with `cors({ credentials: true })` and no `origin` option. Any attacker page makes a credentialed cross-origin fetch; the response carries reflected Origin + ACAC:true; the browser permits the response body to reach attacker JS.

**Confirmation**: deployed Hono version `<4.12.25`; `cors` middleware configured with `credentials:true` and no explicit `origin`; probe with cross-origin fetch and observe the ACAO reflection + ACAC emission.

**Significance**: this is the 2026 instance of the pattern — a middleware deliberately changed to be more permissive than the spec. The deployed-regression shape is distinct from "developer misconfigured the middleware"; the middleware's default behavior was the vulnerability.

## elysia-cors (Bun/JS) — CVE-2025-50864

- **GHSA**: `GHSA-f9qj-4c5x-cpcw`
- **Severity**: Medium (CVSS v3.1 6.5 / v4.0 6.9), CWE-346 (Origin Validation Error)
- **Affected**: `@elysiajs/cors` on npm, versions `< 1.3.1`
- **Fix**: `1.3.1`; fix commit `9b9eb92e32a7a4b43b6d5108668941701c33e221` (commit message: "fix: strictly check origin not using sub includes.")
- **Published**: 2025-08-20

**Mechanism**: The library validated origins by substring match rather than exact match. An allowlist entry of `example.com` matched attacker-controlled origins like `notexample.com` or `example.common.net` — any origin containing the allowlist string as a substring was admitted.

**Advisory verbatim**: "The library incorrectly validates the supplied origin by checking if it is a substring of any domain in the site's CORS policy, rather than performing an exact match. For example, a malicious origin like notexample.com, example.common.net is whitelisted when the site's CORS policy specifies example.com."

**Attack vector**: deployed Elysia application with `@elysiajs/cors < 1.3.1`; allowlist entry contains a substring `example.com`; attacker registers `notexample.com` or `example.common.net`; attacker page issues cross-origin fetch; the substring-match admits the attacker Origin.

**Confirmation**: deployed elysia-cors version `<1.3.1`; probe with origins containing the allowlist substring; observe reflection.

**Class template**: this is the textbook instance of the prefix/suffix/substring match mistake class documented in the advanced sibling (`cors_misconfiguration_advanced_deep.md § Regex Escape and Pattern-Match Bypass Classes`).

## Netty CorsHandler — CVE-2026-56746

- **GHSA**: `GHSA-6cqp-g7gg-8hr5`
- **Severity**: Medium (CVSS 6.5)
- **Affected**: `io.netty:netty-codec-http` (Maven), versions `4.2.0` through `4.2.15` and `4.1.0` through `4.1.135`
- **Fix**: `4.2.16` / `4.1.136`

**Mechanism**: Netty's `CorsHandler` supports a `shortCircuit` option that, when enabled, is meant to reject CORS requests from non-allowlisted origins by closing the connection before the request reaches the application handler. In affected versions, the `shortCircuit` logic had a bypass path: a crafted request could reach the application handler despite the `shortCircuit` guard rejecting the CORS preflight. The result is that the application processes a cross-origin request that the CORS policy was configured to block.

**Attack vector**: attacker issues a cross-origin request to a Netty-based service configured with `CorsHandler` + `shortCircuit(true)` and a restrictive origin allowlist. The request bypasses the `shortCircuit` guard and reaches the application handler with the attacker's credentials.

**Confirmation**: deployed Netty version in the affected range; `CorsHandler` configured with `shortCircuit(true)` and a restrictive allowlist; probe with a non-allowlisted origin and observe whether the application handler processes the request (response body contains application data, not a CORS rejection).

**Class template**: *"CORS enforcement bypass at the framework handler level"* — distinct from the middleware-default-permissive class (Flask-CORS, Hono, Fiber) where the configuration itself is the problem. Here, the configuration is correct (restrictive allowlist + shortCircuit), but the enforcement implementation has a gap. This is a **defense-bypass** shape, not a **misconfiguration** shape.

## Chrome Private Network Access — Header Mechanics and Enforcement State

**Header mechanism** (per developer.chrome.com, primary-source verified):
- Request-side: Chrome sets `Access-Control-Request-Private-Network: true` on all PNA preflight requests to private-network destinations
- Response-side: the private-network server must return `Access-Control-Allow-Private-Network: true` for the preflight to succeed

**Enforcement state (as of 2026-10-04, unverified-current)**: Chrome's PNA rollout is in flux. The earlier Chrome 123+ warning → full enforcement timeline was altered by a pivot to a permission-prompt model (`developer.chrome.com/blog/pna-on-hold`, `developer.chrome.com/blog/pna-permission-prompt-ot-end`). The current browser-side enforcement is version-dependent and partially gated by permission-prompt origin trials. Treat PNA enforcement as **unverified-current rather than a fixed 2026 state**; do not assert 2026 enforcement from 2023 blog posts.

**Interaction with Flask-CORS CVE-2024-6221**: Flask-CORS <4.0.2 (and 4.0.2+ with default config) emits `Access-Control-Allow-Private-Network: true` by default — so an internal service deployed with vulnerable Flask-CORS, hit by a Chrome browser enforcing PNA, admits the external-to-private credentialed fetch. The chain depends on both halves (vulnerable middleware + enforcing browser version). Where the browser does not enforce PNA (older Chrome, non-Chromium browsers, origin-trial opt-out), the middleware's permissive behavior is latent — the browser does not emit the PNA preflight and the server's permissive response does not activate.

**Audit discipline**: for an internal service with PNA concerns, verify both halves: deployed middleware's PNA behavior AND the browser version(s) in the user base that enforce PNA.

## Spring @CrossOrigin — Default Behavior Audit Reference

Not a CVE; the Spring default behavior is a documented, intentional design choice that produces audit findings when combined with developer misuse.

**Primary-source anchors**:
- Spring 4.3.x docs verbatim: "By default @CrossOrigin allows all origins and the HTTP methods specified in the @RequestMapping annotation" and "By default all origins and GET, HEAD, and POST methods are allowed."
- Spring 6.x/7.0 current docs verbatim: "By default, @CrossOrigin allows: All origins, All headers, All HTTP methods ... with maxAge=30 min" and "allowCredentials is not enabled by default, since that establishes a trust level that exposes sensitive user-specific information (such as cookies and CSRF tokens) and should only be used where appropriate."

**Audit implication**: a developer who writes `@CrossOrigin` without arguments on an admin endpoint grants all-origins + GET/HEAD/POST access. The `allowCredentials` default-off limits the exposure to non-credentialed cross-origin reads. **Where the endpoint uses non-cookie, non-Authorization-header auth** (e.g., client-cert, custom auth-via-URL-parameter, IP-based trust), the credentials-off default is irrelevant — the authenticated response is still readable cross-origin because the auth travels with the request without being treated as a "credential" by the browser's CORS layer.

**Spring 5.3+ hard-reject**: when `allowCredentials=true` is explicitly set alongside wildcard origins, Spring 5.3+ hard-rejects at startup, forcing the developer to use `allowOriginPatterns` instead. Pre-5.3 versions do not reject at startup; the misconfiguration ships.

**Property-name drift**: `allowedCredentials` in Spring 4.3.x → `allowCredentials` in current. Cosmetic rename; audit text referencing older property names is stale but functionally equivalent.

## AWS API Gateway HTTP APIs — AllowOrigins Wildcard Behavior

Not a CVE; AWS API Gateway's documented behavior admits scheme-prefix wildcards in the `AllowOrigins` field, which is a legitimately-named configuration option producing a very broad allowlist.

**Primary-source anchor** (AWS docs verbatim example): `AllowOrigins` accepts
- `*` (allow all origins)
- `https://*` (allow any origin that begins with https://)
- `http://*` (allow any origin that begins with http://)

**Audit implication**: a developer who configures `AllowOrigins: ["https://*"]` has created a scheme-wildcard allowlist admitting every HTTPS origin — the attacker's `evil.tld` on HTTPS is a legitimate match. Combined with `AllowCredentials: true`, this is naive-origin-reflection equivalent via a legitimately-named gateway option.

Separately, AWS docs state verbatim: "API Gateway ignores CORS headers returned from your backend integration" for HTTP APIs — the gateway-level CORS is authoritative; backend-returned headers do not override. This changes the audit discipline: the gateway's configuration IS the CORS policy; backend-set headers are irrelevant to the live behavior.

**Audit discipline**: for AWS API Gateway HTTP API deployments, inspect the API's CORS configuration (not the backend's headers); verify `AllowOrigins` is either exact strings or `*` with `AllowCredentials: false`; never scheme-prefix wildcards with `AllowCredentials: true`.

## Bounded Live-Frontier Class Reasoning

The CORS novel-tier frontier is bounded: no new browser-level technique classes have emerged since Jan 2024, and the 2024–2026 live frontier is middleware-default CVEs rather than new attack primitives. The reasoning:

1. **The browser-side enforcement is settled**. The Fetch standard's wildcard-vs-credentials prohibition, the Origin header's RFC 6454 semantics, and the preflight model have been stable since 2020+; new technique classes would require a browser-vendor change, not a configuration misread
2. **The server-side allowlist pattern-mistake surface is exhaustively enumerated** (regex, prefix, suffix, substring, case-sensitivity, trailing-slash, scheme/port, subdomain-takeover-fed) — all documented in the advanced sibling. A sibling class is unlikely to emerge because the pattern-mistake surface is a product of comparison-function design, and the design space has been explored
3. **The live middleware-default CVEs are the frontier precisely because they are implementation regressions of settled architectural knowledge** — Hono CVE-2026-54290 is "the middleware now reflects when it used to fail closed," which is a regression, not a new class. Flask-CORS × 3 are implementation-detail path-matching desyncs
4. **The DoubleClickjacking / defense-irrelevant UI-redress frontier** (per `clickjacking_novel_deep`) has no CORS-adjacent material; it is a different trust-boundary class entirely

The bounded reasoning does not predict zero new CORS findings in 2026–2027; it predicts that new findings will continue to be middleware-default or allowlist-mistake instances, not browser-level technique classes. The pentester's time investment is in enumerating the deployed middleware against this catalog, not in exploring hypothetical new browser-mediated primitives.

## Chaining Depth at the Novel Frontier

**Chain F1 — Flask-CORS unquote_plus desync (CVE-2024-6844) → Per-path allowlist bypass → Credentialed read**:
- Flask app with Flask-CORS <=5.0.1; per-path CORS config (one allowlist for `/public/*`, different for `/admin/*`)
- Attacker crafts request path with `+` such that `unquote_plus` conversion lines up `+`→` ` to match `/public/*` while the real route is `/admin/*`
- CORS passes allowlist for `public`; Flask routes to `admin` endpoint; response includes admin content with ACAO reflecting attacker origin + ACAC:true

**Chain F2 — Flask-CORS try_match (CVE-2024-6866) → Case-shuffled path → Admin reach**:
- Flask-CORS <=5.0.1; allowlist regex `^/public/.*$`
- Attacker requests `/PUBLIC/.../admin/` (case variation); `try_match` matches due to case-insensitivity
- Response from the admin endpoint with CORS admitted

**Chain F3 — Hono (CVE-2026-54290) → Default-config → Full cross-origin credentialed read**:
- Hono app with `cors({ credentials: true })` and no explicit `origin`
- Attacker page: `fetch(api.target.tld/account, {credentials:'include'})`
- Hono reflects attacker Origin + ACAC:true; browser admits; attacker reads response

**Chain F4 — Fiber (CVE-2024-25124) → Wildcard+credentials → Specific-echo-path exfil**:
- Fiber v2 <2.52.1 with wildcard origin + credentials configured
- Browser rejects wildcard+credentials but target app also echoes the session cookie in the response body (anti-pattern)
- Attacker page issues non-credentialed cross-origin fetch; response body includes session cookie via echo
- Session hijack via echoed-credential, not via credentialed-fetch

**Chain F5 — elysia-cors (CVE-2025-50864) → Substring match → Legitimately-looking origin**:
- Target allowlist specifies `example.com`
- Attacker registers `notexample.com`; attacker page fetches target with `Origin: https://notexample.com`
- Substring match passes; attacker Origin is reflected; ACAC:true; credentialed cross-origin read

**Chain F6 — Flask-CORS PNA (CVE-2024-6221) → Internal admin service → External page compromise**:
- Internal admin service at `192.168.1.100` running Flask-CORS <4.0.2 (OR 4.0.2+ with default config)
- Victim visits attacker page on public internet while connected to the private network
- Attacker page issues `fetch('http://192.168.1.100:8080/admin', {credentials:'include'})`
- Chrome enforces PNA preflight; Flask-CORS returns `Access-Control-Allow-Private-Network: true` by default; browser admits
- External page reads internal admin API

## Verification Discipline

- Every CVE claim in this file links to a globally-resolving GHSA REST advisory (persisted in `.zen-batch-artifacts/batch-13/`); the manifest demonstrates 1:1 resolution
- CVE version metadata is single-owned here; base/advanced sibling files reference by CVE number + filename+section pointer only
- The "upgrading Flask-CORS to 4.0.2+ removes default-true PNA" framing (voted 1-2 refuted) is explicitly out of scope and must not appear anywhere in deliverable files
- The "PortSwigger four-step practical methodology" framing (voted 3-0 refuted in Batch 13 cross-check) is out of scope; the Fetch-standard three-condition confirmation rule in the base file is the authoritative framing
- Chrome PNA enforcement state is flagged as unverified-current; do not assert 2026 enforcement from older sources
- For audit anchors without CVEs (Spring, AWS API Gateway), the audit discipline is documented at `cors_misconfiguration_advanced_deep.md § Framework Middleware Default Catalog`
- CVE single-ownership: Flask-CORS × 3 CVEs share this file; Fiber, Hono, elysia-cors each have their own version-metadata block here; no version string or GHSA ID repeats in the base or advanced siblings
- Spring property-name drift (`allowedCredentials` → `allowCredentials`) is cosmetic; audit text citing one or the other is correct for its era

## Summary

The 2024–2026 CORS misconfiguration frontier is bounded to middleware-default CVEs (Flask-CORS × 3 for path-matching desyncs and PNA default-true; Fiber v2 for wildcard+credentials; Hono for naive reflection-via-default; elysia-cors for substring match) plus two audit anchors (Spring @CrossOrigin defaults, AWS API Gateway HTTP APIs scheme-prefix wildcards) and one unverified-current browser-mechanic (Chrome PNA enforcement). No new browser-level technique classes have emerged since 2024; the live frontier is implementation-regression of settled architectural knowledge. Load `cors_misconfiguration` for base framing and the three-condition confirmation rule; load `cors_misconfiguration_advanced_deep` for allowlist-bypass depth and framework audit discipline; this file is the version-metadata anchor the siblings reference by CVE number.
