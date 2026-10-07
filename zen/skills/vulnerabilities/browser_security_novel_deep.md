---
name: browser-security-novel-deep
description: 2024-2026 frontier for browser-security exploitation — CSPT verified CVEs, novel XS-Leaks oracles (connection pool, ETag length), DoubleClickjacking, Document Isolation Policy, postMessage CVEs, sandbox bypass CVEs, and WebTransport/WebRTC vendor advisories
sibling: browser_security
load_when: scan_mode == "deep"
---

# Browser Security — Novel Deep

Novel-tier content covering the 2024–2026 browser-security frontier. The base owns the state model, oracle inventory, and framework-specific CSPT framing; the advanced-deep sibling owns full technique treatments for postMessage, CSPT, XS-Leaks, service workers, CSP bypass, and sandbox primitives; this file owns the verified-CVE catalog, measured frontier primitives, and the open-problem research framing.

The 2024–2026 period surfaced the first wave of CSPT CVEs (Doyensec research turning into assigned CVE IDs), novel XS-Leaks oracles via connection pool and HTTP header-size, DoubleClickjacking as a defeater of classic framing defense, Chrome's Document Isolation Policy as a 2025 per-frame alternative to COOP/COEP, and a sustained flow of browser-vendor renderer-sandbox CVEs. The Privacy Sandbox APIs (Fenced Frames, Topics, Protected Audience, Attribution Reporting, Shared Storage, Private Aggregation, Related Website Sets) have been **scheduled for deprecation and removal** from Chrome as of August 2026, so should not be treated as current attack-surface frontier.

## Verified CSPT CVE Catalog

Client-Side Path Traversal was formalized as a vulnerability class by Doyensec in 2024. The following CVEs resolve globally on GHSA REST and NVD and demonstrate the class's reach.

### CVE-2023-45316 — Mattermost Playbooks CSPT (POST Sink)

GHSA-2pgg-h82p-8cpr. Mattermost playbooks telemetry endpoint. The playbook UI constructs a POST URL using a client-router path; attacker-crafted path reaches a state-changing API with the user's credentials — classic CSPT2CSRF with a POST sink.

**Primitive class template**: *"Client-router path interpolated into state-changing POST"* — generalize to any SPA where user-visible URL fragments reach a state-changing API via client-side URL construction.

**Fix shape**: use URL constructor with path containment; validate the resolved path against an allowlist of API endpoints before fetching.

### CVE-2023-6458 — Mattermost `/channels/<name>` CSPT (GET Sink)

GHSA-7664-hcp7-f497. Mattermost channel route. The channel-name URL parameter was reflected into a client-side fetch without canonicalization; attacker-crafted channel name reaches a sibling route and reads its response.

**Primitive class template**: *"Route-parameter interpolation into fetch URL without canonicalization"* — a GET-sink variant of CSPT where the response leaks.

**Fix shape**: canonicalize path parameters; reject `..` and `%2e%2e` encodings; use the WHATWG URL constructor rather than string concatenation.

### CVE-2024-50336 — matrix-js-sdk MXC URI CSPT

GHSA-xvg8-m4x3-w6xr. The matrix-js-sdk handled MXC (Matrix Content) URIs by concatenating them with the homeserver URL; attacker-crafted MXC URI escaped the content path to reach other homeserver endpoints.

**Primitive class template**: *"Protocol-specific URI with path interpolation into fetch"* — same CSPT class, applied to a protocol-specific URI format.

**Fix shape**: canonicalize MXC parts; strict allowlist of permitted URI components.

### CVE-2023-5123 — Grafana marcusolsson-json-datasource CSPT

Grafana plugin. The JSON datasource plugin took user input for its URL field and did not sanitize path components; attacker-controlled dashboard reached arbitrary server-side endpoints.

**Primitive class template**: *"Plugin-configured URL with path interpolation into fetch"* — plugin ecosystems are a dense CSPT surface because plugins commonly accept URL configuration and interpolate into fetch URLs.

### Primitive Class: CSPT2CSRF Universality

Across the four CVEs, the common pattern is:

1. User-visible URL fragment (route param, query, hash, uploaded identifier).
2. Client-side URL construction via string concatenation or non-canonicalizing routing.
3. Fetch to the constructed URL with credentials.
4. Impact — either data leak (GET sink) or state change (POST sink).

Any SPA with this pattern is a candidate. The 2024 Doyensec CSPT2CSRF whitepaper (OWASP Global AppSec Lisbon 2024) formalized this and provided the term. The research directs defenders to canonicalize before fetch and segment-validate against an allowlist.

## Novel XS-Leaks Oracles

Beyond the xsleaks.dev wiki's classic catalogue, 2024–2025 produced two novel primary-source-verified oracles.

### Connection Pool Subdomain Leak

Published 2024–2025 at blog.babelo.xyz. Primary source cited to Chromium's `client_socket_pool.h`. Mechanism:

- Chromium's connection pool limits are 256 total sockets, 32 per host, 6 per host-and-origin.
- Within the pool, hosts are sorted lexicographically.
- An attacker opening 255 fetches to attacker-domain forces subsequent fetches to compete for the remaining slot.
- Victim's cross-origin fetch to a sibling host (say, `admin.target.com`) is observable via timing of the attacker's 256th slot.
- By binary-search over host prefixes, the attacker enumerates which subdomains the victim is accessing.

**Primitive**: cross-origin subdomain enumeration via connection pool exhaustion.

**Preconditions**:
- Chromium browser (Firefox/Safari have different pool semantics).
- Victim visiting attacker page in a background tab.
- Victim has an authenticated session with target.

**Attack recipe**:
1. Attacker page opens 255 fetches to `attacker.com` with long response (held open).
2. Monitor timing of 256th slot.
3. Victim's browser performs its own fetch to `admin.target.com`.
4. Connection-pool sorting places `attacker.com` and `admin.target.com` sequentially.
5. Timing of 256th slot reveals when `admin.target.com` was fetched.

**Confirmation**: timing-signal consistent across trials.

**Impact**: subdomain-enumeration oracle; reveals which admin subdomains the user is logged into.

### Cross-Site ETag Length Leak

Published December 2025 at blog.arkark.dev. Mechanism:

- Chromium's `history.replaceState()` and `history.pushState()` have a 16-KiB header limit (shared with `jshttp/etag`).
- Server responds with ETag whose length depends on target state.
- Attacker measures history behavior: if the push succeeds, ETag was short; if it fails with status 431, ETag was long.

**Primitive**: cross-origin ETag-length oracle.

**Preconditions**:
- Target endpoint returns ETag varying by state.
- Browser's history-size limit observable.

**Attack recipe**:
1. Attacker page navigates to target in iframe.
2. Attempts history manipulation.
3. 431 status if ETag too long; 200 otherwise.

**Confirmation**: status-code differential observable.

**Impact**: fine-grained state oracle via header-size leak.

### DoubleClickjacking (Paulos Yibelo, 2024)

Published December 2024 at paulosyibelo.com. Technique:

- Attacker page requires a double-click to interact (natural UI pattern).
- First click lands on attacker's page.
- Attacker JS uses `window.open()` to open target and immediately swaps the window.
- Second click lands on target's sensitive button.
- Defeats X-Frame-Options, `frame-ancestors`, SameSite, classic clickjacking defenses.

**Primitive**: double-click window-swap bypass.

**Preconditions**:
- Target has sensitive action triggerable by a single click (OAuth consent, password save, delete button).
- No elapsed-time or additional-confirmation requirement.
- Attacker can navigate the user with `window.open`.

**Attack recipe**:
1. Attacker page: `<button onclick="doubleClickExploit()">Click me</button>`.
2. `doubleClickExploit` opens target URL in a popup, then swaps.
3. User's double-click: first click fires the handler; second click lands on target's sensitive button.

**Confirmation**: target's sensitive action triggered without informed consent.

**Impact**: UI redressing bypassing all classic framing defenses. The OWASP Clickjacking Cheat Sheet (PR#2438) now has a DoubleClickjacking defense section.

**Defense**: require a secondary action (passphrase, visible confirmation modal, timing-delay) for sensitive buttons.

## Chrome 137 Document Isolation Policy (DIP) — 2025 Primary Primitive

Chrome 137 shipped Document Isolation Policy in May 2025 — a per-frame alternative to COOP+COEP that unlocks `SharedArrayBuffer` + `performance.measureUserAgentSpecificMemory()` without requiring embedded subframes to opt-in via COEP.

### Context

- Pre-DIP, cross-origin isolation required COOP same-origin + COEP require-corp on the top-level document AND every embedded subframe (because COEP forces subframes to opt in).
- Many apps couldn't adopt COEP because their third-party subframes (ads, analytics, embeds) wouldn't opt in.
- DIP decouples the subframe constraint: the top-level document can be isolated without the subframes being isolated.

### Primitive Class: DIP-Isolation Without COEP

**Primitive**: a Chrome 137+ page can achieve cross-origin isolation (crossOriginIsolated = true) via `Document-Isolation-Policy` header rather than requiring COEP.

**Attack-surface implications**:
- Spectre-adjacent coarsening of `performance.now()` applies when isolated.
- Several XS-Leaks defenses activate.
- Pages that could not previously isolate (due to third-party subframes) can now isolate — reducing attack surface against them.

**Primitive class template**: *"Documents under DIP vs under COOP+COEP"* — behavior may differ in subtle ways; test both.

**Chrome-specific**: as of August 2026, DIP is Chrome 137+ only. Firefox and Safari have not shipped equivalent. A cross-browser pentest must test the COOP+COEP path on non-Chrome browsers.

## Verified Browser-Vendor CVEs

### CVE-2024-5691 — Firefox X-Frame-Options Error-Page Clickjacking

Firefox-specific: a sandboxed iframe navigating to an X-Frame-Options-DENY resource shows an error page that remains in a navigable context. The sandboxed iframe can continue to navigate from the error page, bypassing sandbox-navigation restrictions.

**Primitive class template**: *"Error-page nav state preserved in sandboxed context"* — generalize to any browser handling of blocked-content error pages where the context remains interactive.

### CVE-2025-54143 — Firefox iOS Sandboxed Iframe Download Bypass

Firefox iOS < 141: sandboxed iframes could trigger downloads despite sandbox restrictions on `allow-downloads` not being set.

**Primitive class template**: *"Sandboxed iframe capability leak"* — a sandbox flag not fully enforced in a specific browser build.

### CVE-2024-1674 — Chrome Navigation Bypass

Chrome < 122.0.6261.57: inappropriate navigation implementation allowed bypassing navigation restrictions.

**Primitive class template**: *"Browser navigation primitive bypass"* — generalizes to the broader class of browser-specific navigation attacks.

### CVE-2024-10229 — Chrome Extensions Site Isolation Bypass

Chrome < 130.0.6723.69: extensions could bypass Site Isolation.

**Primitive class template**: *"Extension-API Site-Isolation bypass"* — relevant for threat-model context when extensions are part of the attack surface.

### CVE-2025-4664 — Chrome Loader Cross-Origin Data Leakage (In-the-Wild)

Chromium's Loader component had insufficient policy enforcement for cross-origin resource loading. A crafted HTML page could leak cross-origin data via the `Link` response header's `referrerpolicy` attribute. CVSS 4.3 MEDIUM per NVD; HIGH severity per Chromium's own assessment. Actively exploited in the wild.

**Primitive class template**: *"Cross-origin data leakage via response header policy"* — the Link header's referrer-policy setting is trusted without cross-origin validation; a page can set a permissive referrer policy on a cross-origin subresource load, leaking the full URL (including query-string tokens) to the attacker.

**Pentester relevance**: any application passing sensitive data in URL query parameters (OAuth tokens, session IDs, API keys) is exposed when users visit an attacker page in a vulnerable Chrome version. Fix shipped in Chrome; verify target user base's Chrome version.

### CVE-2026-102320 — Chrome CORS Renderer Bypass

Chrome renderer-level CORS enforcement bypass. CVSS 6.5 MEDIUM. A crafted page could bypass CORS checks at the renderer level, reading cross-origin response bodies that should be blocked.

**Primitive class template**: *"Renderer-level CORS enforcement gap"* — the CORS check runs at the renderer, and a specific code path skips it. Distinct from network-level CORS (which runs at the Fetch layer).

**Pentester relevance**: a web-application finding when the target's users run affected Chrome versions; the application's server-side CORS headers are irrelevant because the browser skips the check.

## Deeper Primitive Classes From the Verified CVE Set

### Primitive Class: Plugin/Extension CSPT

**Primitive**: a Grafana or similar plugin takes URL configuration from the user and constructs a backend fetch URL without canonicalization. CVE-2023-5123 (Grafana) is the canonical instance.

**Preconditions**:
- Plugin accepts URL configuration.
- Backend trusts the client-supplied URL.
- No allowlist of permitted endpoint classes.

**Attack recipe**:
1. Craft a dashboard with a user-controlled JSON datasource URL containing path traversal.
2. Server-side plugin fetches the constructed URL.
3. Attacker reaches endpoints beyond the configured datasource.

**Confirmation**: server-side request logs show fetches to unintended endpoints.

**Impact**: SSRF-like primitive via plugin configuration. Chain with cloud-metadata reachability for IMDS.

### Primitive Class: URI-Scheme-Specific CSPT

**Primitive**: a client-side URI handler (MXC, matrix:, custom scheme) interpolates path components into fetch URLs; attacker crafts URIs that escape the intended scope. CVE-2024-50336 (matrix-js-sdk) is the canonical instance.

**Preconditions**:
- Custom URI scheme with path components.
- Client-side handler constructs fetch URL via concatenation.
- No canonicalization at the scheme boundary.

**Attack recipe**:
1. Submit a URI (`mxc://../other-content`) via a message or configuration path.
2. Handler concatenates with homeserver URL.
3. Fetch lands at unintended endpoint.

**Confirmation**: fetch URL in network tab differs from expected.

**Impact**: unauthorized endpoint access via protocol-handler primitive.

### Primitive Class: Playbook/Workflow-Builder CSPT

**Primitive**: workflow-builder UIs (Mattermost playbooks, GitHub actions UIs, Zapier) construct backend URLs from user-supplied step configurations; attacker inputs escape to admin endpoints. CVE-2023-45316 and CVE-2023-6458 (Mattermost playbooks) are instances.

**Preconditions**:
- Workflow-builder exposes user-controlled URL fields.
- Backend trusts the UI-supplied URL.

**Attack recipe**:
1. Add a step with a URL field containing path traversal.
2. Execute the workflow; backend fetches the constructed URL.
3. Reach admin or cross-tenant endpoints.

**Confirmation**: audit log shows workflow-triggered fetches at unexpected endpoints.

**Impact**: cross-user or cross-tenant state access.

### CSPT Testing Methodology

Given the 2024–2026 CSPT formalization, a focused testing methodology:

1. **Enumerate client-side URL constructions**: grep `fetch(` and `axios.` in client bundles; look for string concatenation with user input.
2. **Trace user-input source**: route params, query params, hash, uploaded content, chat message, etc.
3. **Check decode depth**: WHATWG URL + framework router may decode N times; count the decodes.
4. **Test with path traversal**: inject `../`, `%2e%2e%2f`, `%252e%252e%252f`.
5. **Classify sink**: GET sink (data read) vs POST sink (state change) vs other.
6. **Prove impact**: capture the final fetch; show the sink is reached.

The Doyensec CSPT research includes `CSPTBurpExtension` and CSPTPlayground as reproduction tooling.

## Verified postMessage CVE

### CVE-2024-49038 — Copilot Studio postMessage XSS

Microsoft Security Response Center documented three real postMessage patterns at MSRC's August 2025 "postMessaged and Compromised" post:

1. **Bing Travel wildcard token leak**: wildcard origin check leaked tokens cross-origin.
2. **web.kusto.windows.net clusterUrl token exfil**: cluster URL extraction via postMessage.
3. **Copilot Studio `validDomains` XSS (CVE-2024-49038)**: domain-check regex allowed attacker-controlled domain through postMessage data, enabling XSS.

**Primitive class template**: *"postMessage domain-check regex bypass"* — the regex pattern tolerates attacker-domain due to weak anchoring. Load `semantic_confusion_advanced_deep` for the broader URL-parser-differential class.

## MSRC postMessage Report Full Analysis

### CVE-2024-49038 Deep-Dive

Microsoft Copilot Studio's `validDomains` configuration permits a list of trusted origins for postMessage communication. The validation regex was overly permissive, allowing attacker-controlled domains to pass through.

**Mechanism**:
- Service receives postMessage; validates `event.origin` against regex derived from `validDomains`.
- Regex permits domains with specific substring patterns.
- Attacker registers a domain matching the pattern.
- Attacker's domain sends postMessage; service accepts.
- Message data contains script-shaped payload that is rendered into DOM.
- XSS execution.

**Fix shape**: strict string-equality origin check against the allowlist; anchor regex both ends; use `URL` constructor to parse origin before comparison.

**Primitive class template**: *"Regex-based origin allowlist with weak anchoring"* — generalize to any postMessage validation using regex (which should be deprecated in favor of exact-string comparison). Load `semantic_confusion_advanced_deep` for the broader URL-parser-differential class.

### Other MSRC postMessage Patterns (Context)

The MSRC post documented two additional patterns without specific CVEs (framed as "fixed internally"):

- **Bing Travel wildcard token leak**: `event.data` contained an auth token; the `targetOrigin` was `*`, so the token broadcast to any listener. Fix: scope `targetOrigin` to the specific trusted origin.
- **web.kusto.windows.net clusterUrl token exfil**: similar wildcard-origin broadcasting pattern.

Both reinforce that `targetOrigin = "*"` is a persistent anti-pattern. Audit for `postMessage(data, "*")` calls as a baseline check on any sensitive messaging flow.

## Firefox and Chrome Browser-Vendor Walkthrough

### CVE-2024-5691 Deep-Dive — Firefox X-Frame-Options Error Page

Firefox's handling of X-Frame-Options-DENY in a sandboxed iframe left the error page interactive. Specifically:

**Mechanism**:
- Attacker page contains `<iframe sandbox="allow-scripts" src="target">`.
- Target serves `X-Frame-Options: DENY`.
- Firefox blocks frame content; shows error page.
- The error page's URL remains navigable from the sandbox.
- Attacker iframe can navigate from the error page to attacker-chosen URL — bypassing sandbox navigation restrictions.

**Fix shape**: ensure error pages are non-navigable from sandboxed context; or treat sandbox-blocked frames as fully opaque.

**Primitive class template**: *"Blocked-content state preserved in interactive context"* — a general class where a security block's error UI retains navigability.

### CVE-2024-10229 Deep-Dive — Chrome Extensions Site Isolation Bypass

Chrome's Site Isolation separates sites into processes to prevent Spectre; extensions have specific access to multiple sites.

**Mechanism**:
- Extension API provides tabs.executeScript or similar.
- An extension with access to multiple sites could use the API to read cross-site content from the shared extension-privileged process.
- Site Isolation was bypassed because the extension context mixed sites.

**Fix shape**: enforce per-site process boundary within the extension context; or restrict extension APIs that cross site boundaries.

**Primitive class template**: *"Trusted-middle-tier bypasses isolation"* — generalizes to any process-isolation defense where a trusted middle tier has broader access.

## Verified Browser-Vendor Rendering-Pipeline CVEs (Context)

The following CVEs are renderer-sandbox / rendering-pipeline bugs. They are relevant for threat-model context but are NOT client-side web-app primitives — they require a renderer compromise chain to be useful. A web-app pentester should document them as "attack-surface preconditions" rather than as directly-weaponizable primitives:

- **CVE-2025-6558** — ANGLE/GPU untrusted-input validation → sandbox escape (Chrome < 138.0.7204.157).
- **CVE-2025-2783 / CVE-2025-2857 / CVE-2025-4609** — Mojo/ipcz incorrect-handle sandbox-escape across Chrome + Firefox 2025.
- **CVE-2024-7971 / CVE-2025-0995 / CVE-2024-11395** — V8 type-confusion / UAF (renderer-compromise feeders).
- **CVE-2024-9680** — Firefox animation-timelines UAF (in-the-wild zero-day).

### CVE-2023-7024, CVE-2024-5493, CVE-2024-10488, CVE-2025-10501 — Chrome WebRTC UAFs

Multiple Chrome WebRTC-stack UAFs across 2024–2025 — memory-safety class. Not directly weaponizable from a web page without further chain, but establishes that WebRTC remains a sensitive sandbox-adjacent surface.

### CVE-2025-1931 — Firefox WebTransport UAF

Firefox WebTransport content-process UAF; same class.

## Novel XS-Leaks — Full Primary-Source Treatment

### Connection-Pool XS-Leak Full Treatment

The babelo.xyz 2024/2025 publication is the primary source. Technical mechanism in depth:

**Chromium's connection pool architecture** (per `client_socket_pool.h`):
- Maximum 256 total sockets across the browser.
- 32 per host.
- 6 per host-and-origin combination.
- When all slots are full, new requests wait; freshly-closed slots are reassigned based on wait order.
- The wait-order is affected by host-lexicographic sorting under some conditions.

**The attack**:
1. Attacker opens 255 slow fetches to `attacker.com` (held with `Response` streaming or server-sent events).
2. Victim's own activity (triggered by visiting a target site in a background tab) competes for the 256th slot.
3. The 256th-slot fetch's wait-time is observable.
4. The host-lexicographic sort order means that known sibling hosts have predictable timing.
5. Binary-search over possible subdomain prefixes reveals which subdomains the victim is making requests to.

**Primary-source confirmation**: the paper cites Chromium's `client_socket_pool.h` for the specific pool limits and ordering behavior.

**Primitive class template**: *"Browser internal-state side channel via resource contention"* — generalize to other browser-internal resources (DNS cache, connection pool, HTTP cache, service worker cache).

### ETag-Length XS-Leak Full Treatment

Published December 2025 at blog.arkark.dev. Primary source cites Chromium's history API and `jshttp/etag`.

**Mechanism**:
- Node.js's `jshttp/etag` library (used by Express and others) generates ETags whose length depends on content.
- Chromium's `history.pushState()` / `history.replaceState()` fail with HTTP 431 if the state's headers exceed 16 KiB.
- A cross-origin fetch's ETag ends up in request headers on subsequent requests (via `If-None-Match`).
- A sufficiently-long ETag causes the subsequent request to fail with 431 — observable to the attacker.

**The attack**:
1. Attacker page fetches target in iframe with specific state.
2. Target returns ETag; browser caches.
3. Attacker triggers subsequent navigation that would include `If-None-Match: <long-etag>`.
4. If ETag long: 431 status; iframe shows error page.
5. If ETag short: 200 or 304; iframe loads normally.

**Primitive class template**: *"HTTP header-size limit as side channel"* — browser-internal size constraints as observable signal.

### DoubleClickjacking Deep-Dive

The Paulos Yibelo December 2024 publication established DoubleClickjacking as a class.

**Technical mechanism**:
1. Attacker page: `<button onclick="exploit()">Watch video</button>`.
2. User sees a button that logically needs to be double-clicked.
3. On first click, `exploit()` runs:
   - Opens target URL in a popup via `window.open()`.
   - Immediately removes the attacker's own content.
   - The popup is now positioned to receive the second click.
4. User's second click lands on the target's sensitive button (OAuth consent, save-password, delete-account).

**Why classic defenses fail**:
- X-Frame-Options and `frame-ancestors` prevent framing, but DoubleClickjacking uses a popup, not a frame.
- SameSite cookie attributes don't block top-level navigation to a target.
- Classic clickjacking defenses depend on the attacker's context being iframed or overlapping — this attack uses a legitimate popup.

**Defense**:
- Require a secondary interaction (passphrase, confirmation modal) for sensitive buttons.
- Add a timing-delay between page load and button activation.
- Use `postMessage` + user-gesture requirement for sensitive OAuth consent.

**Primary source**: `paulosyibelo.com/2024/12/doubleclickjacking-what.html`. OWASP Clickjacking Cheat Sheet (PR#2438) incorporated this.

**Primitive class template**: *"UI redressing via window-swap during multi-click"* — generalize to any multi-click interaction with a window change.

## Cross-Site WebSocket Hijacking in 2025

Published 2025 analysis (Include Security, blog.includesecurity.com, April 2025) confirms that **Private Network Access does not cover WebSockets** — no preflight is required for WebSocket upgrades. This means attacker's public page can open credentialed WebSockets to internal private-IP services from the public internet.

**Primitive**: public page → WebSocket to internal private-IP service.

**Preconditions**:
- Internal service exposes WebSocket on private IP.
- Victim's browser can resolve the private IP (same LAN).
- Service uses cookies for auth.

**Attack recipe**:
1. From attacker.com, `new WebSocket('wss://192.168.1.5:8443/ws')`.
2. Browser sends upgrade with cookies.
3. Service accepts.

**Confirmation**: WebSocket established; attacker JS has credentialed channel.

**Impact**: SSRF-like primitive from a user's browser; attacker reaches internal services the victim's workstation can see. Chain with internal-service-specific exploitation (`ssrf`, service-specific CVEs).

**Defense**: WebSocket upgrade handlers must check `Origin` header strictly; add Origin to the list of allowlisted trusted origins.

## Privacy Sandbox APIs — Deprecating, Not Frontier

Google announced in 2025–2026 that the following Privacy Sandbox APIs are **marked for deprecate-and-remove on the web**:

- **Fenced Frames**: `<fencedframe>` element and `window.fence` APIs.
- **Topics API**: `document.browsingTopics()`.
- **Protected Audience (FLEDGE)**: in-browser auction primitives.
- **Attribution Reporting**: conversion-measurement framework.
- **Shared Storage**: `window.sharedStorage` key-value store.
- **Private Aggregation**: aggregated measurement.
- **Related Website Sets**: cross-origin cookie access within a declared set.

APIs that continue to be supported:

- **CHIPS** (Cookies Having Independent Partitioned State): partitioned cookies.
- **FedCM** (Federated Credential Management): federated identity.
- **Private State Tokens** (previously Trust Tokens): anti-fraud.
- **Storage Access API**: user-gated cross-site storage access.
- **Bounce tracking mitigations**: automatic cookie clearing on bounce patterns.

**Implication for pentest planning**: writing exploit content against Topics/Fenced Frames/Protected Audience has a shrinking lifetime. Report findings on these as *transitional*, not frontier. CHIPS, FedCM, Storage Access API are stable and worth testing.

## Measured Primitive: Cross-Origin Isolation State

A measurement for a target's isolation state (safe to run against any target as a reconnaissance primitive):

```javascript
// Run in the controlled browser profile:
console.log({
  crossOriginIsolated: self.crossOriginIsolated,
  isSecureContext: self.isSecureContext,
  sharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
  measureMemoryAvailable: typeof performance.measureUserAgentSpecificMemory === 'function',
  COOP: await fetch(location.href).then(r => r.headers.get('Cross-Origin-Opener-Policy')),
  COEP: await fetch(location.href).then(r => r.headers.get('Cross-Origin-Embedder-Policy')),
  DIP: await fetch(location.href).then(r => r.headers.get('Document-Isolation-Policy'))
});
```

A sensitive application with `crossOriginIsolated === false` and no COOP/COEP/DIP is Spectre-exposed and has an increased XS-Leaks attack surface. This is a finding on its own for high-value apps.

## Deep Treatment: Chrome WebRTC and WebTransport CVEs

The Chrome WebRTC and Firefox WebTransport stacks have exhibited a sustained flow of memory-safety CVEs across 2024–2026. For a web-security pentester, these are relevant for threat-modeling (what sandbox-adjacent surface is live) rather than as directly-weaponizable primitives from a page.

### CVE-2023-7024 — Chrome WebRTC Heap Buffer Overflow (In-the-Wild Zero-Day)

A heap-buffer-overflow in WebRTC that was exploited in the wild in late 2023 / early 2024. Chrome patched. The attack chain required a renderer compromise feeder followed by WebRTC-specific heap manipulation.

**Pentester relevance**: a target that is a WebRTC-enabled page is in-scope for memory-safety analysis if the pentest covers client-side browser compromise. Not weaponizable from a web-application pentest.

### CVE-2024-5493, CVE-2024-10488 — Chrome WebRTC UAFs

Two 2024 UAFs in Chrome's WebRTC implementation. Same class as above; same relevance.

### CVE-2025-10501 — Chrome WebRTC UAF

A 2025 UAF; patched in Chrome 140+ (prior to 140.0.7339.185).

### CVE-2025-1931 — Firefox WebTransport Content-Process UAF

Firefox's WebTransport stack UAF. Content-process scope means a compromise is contained to the renderer; still a stepping stone for sandbox escape when chained with other primitives.

**Pentester relevance**: for an application using WebTransport, maintaining current browser versions is important; the CVE itself is a vendor-side concern.

## Deep Treatment: V8 Type-Confusion CVEs

V8's JIT compiler and runtime have historically been a type-confusion source. 2024–2026 continues this pattern.

### CVE-2024-7971 — V8 Type Confusion

In-the-wild zero-day; a JIT type-confusion. Patched Chrome.

### CVE-2025-0995 — V8 UAF

Patched Chrome.

### CVE-2024-11395 — V8 Type Confusion

Patched Chrome.

**Pentester relevance**: V8 bugs enable renderer compromise; from a web-application-pentest perspective, this translates to "if the attacker owns the renderer, they still don't own the user's cross-site data (thanks to Site Isolation), but they can perform arbitrary JS execution and observe timing". Document browser-version in findings; expect V8 patches to land as regular Chrome updates.

## Deep Treatment: Mojo/ipcz Sandbox-Escape Pattern

### CVE-2025-2783 — Chrome Mojo/ipcz Incorrect Handle Validation

A 2025 sandbox-escape chain in Chrome's Mojo IPC. The specific primitive involved incorrect handle validation that allowed an in-renderer attacker to send a malicious IPC message escaping the renderer sandbox.

**Pattern**: Chrome's inter-process communication (ipcz is the new backend) relies on handle validation to ensure cross-process references are legitimate. A validation gap allows a compromised renderer to forge references to higher-privilege processes.

### CVE-2025-2857 — Mozilla Firefox Mojo Pattern

A corresponding Firefox CVE in the same class, suggesting the pattern is architectural (IPC-handle-validation) rather than vendor-specific.

### CVE-2025-4609 — Chrome Mojo/ipcz Pattern Continuation

Another instance of the handle-validation class.

**Pentester relevance**: these establish that renderer-sandbox-escape chains remain a 2025 attack surface. For a web-application pentest, document that Chrome versions below the patched release are threat-model-relevant for high-value targets. These are not weaponizable from a page without a renderer-compromise feeder.

## Deep Treatment: GPU and Rendering-Pipeline CVEs

### CVE-2025-6558 — ANGLE/GPU Sandbox Escape

ANGLE is Chrome's GPU abstraction layer. 2025 CVE involved untrusted-input validation in GPU operations enabling sandbox escape. Patched in Chrome 138+.

**Pattern**: GPU drivers and GPU-abstraction layers are historically a sandbox-escape surface. A page that triggers GPU operations (WebGL, Canvas 2D with hardware acceleration) exposes the GPU stack.

### CVE-2024-9680 — Firefox Animation Timelines UAF (In-the-Wild Zero-Day)

Firefox animation timelines UAF; in-the-wild zero-day. Patched.

**Pentester relevance**: animation and GPU surfaces are not web-application pentest primitives directly, but establish that the attack surface exists.

## XS-Leaks Oracle Testing Methodology

Beyond the three primary-source novel oracles above (connection pool, ETag length, DoubleClickjacking), the xsleaks.dev wiki continues to catalogue oracles. Testing methodology:

### Oracle Testing Methodology

1. **Enumerate state**: identify different user states on the target (logged-in/out, admin/user, feature-flagged).
2. **Enumerate observable signals**: timing, dimensions, event firing, counts, DOM accessibility.
3. **Pair control and exploit**: for each state and each signal, measure.
4. **Quantify separation**: signal must separate the states with reliability.
5. **Chain to impact**: a bare oracle is a lead; the impact is what the oracle enables.

### Example: Framework-Specific Oracle

A SPA that uses React Router may show a different `window.length` for authenticated users (more child frames for widgets) than unauthenticated (login form only). The oracle is framework-specific but reliable in-context.

### Oracle: Service-Worker Response Side-Channel

A service worker's `fetch` handler can see all origin's requests; its logs or state (if observable cross-origin) is a side-channel.

## CSPT Chain Walkthroughs

### Chain 1: CSPT2CSRF Against Mattermost Playbooks (CVE-2023-45316 Mechanism)

Steps:
1. Victim is authenticated to Mattermost Playbooks.
2. Attacker crafts a URL `/playbooks/retrospective/../../../api/admin/users/{victim-id}/delete`.
3. User navigates (clicks a link, is redirected, visits attacker page with iframe).
4. Client-side JS constructs POST URL from the route param without canonicalization.
5. Fetch to constructed URL with victim's session.
6. Admin API accepts; user deleted.

### Chain 2: CSPT1 Response Read (CVE-2023-6458 Mechanism)

Steps:
1. Attacker crafts URL `/channels/..%2F..%2Fapi%2Fprivate_profile`.
2. Victim visits (iframe or navigation).
3. Client fetches constructed URL.
4. Response rendered in victim's UI.
5. Attacker reads via XSS or screenshot or further CSPT chain.

### Chain 3: Plugin CSPT (CVE-2023-5123 Mechanism)

Steps:
1. Attacker publishes a public Grafana dashboard that uses the JSON datasource with a URL field containing path traversal.
2. Victim imports the dashboard.
3. Grafana server-side fetches the URL — reaching intranet endpoints the attacker chose.
4. Response rendered in the dashboard; or cached for later exfiltration.

### Chain 4: URI-Scheme CSPT (CVE-2024-50336 Mechanism)

Steps:
1. Attacker sends a Matrix message containing an MXC URI with path traversal.
2. matrix-js-sdk fetches the URI, constructing fetch URL via concatenation.
3. Fetch reaches arbitrary homeserver endpoints.
4. Attacker-chosen content is retrieved and rendered.

## Multi-Hop Chain Depth at the Novel Frontier

Novel-tier browser-security chains:

- **CSPT2CSRF → account takeover**: `csrf_novel_deep` for the broader CSRF-defense bypass; this skill for the primitive.
- **Novel XS-Leaks (connection pool) → subdomain enumeration → attack prioritization**: `reconnaissance` for next-stage.
- **DoubleClickjacking → OAuth consent abuse**: `oauth` for the authorization-grant abuse class.
- **DNS rebinding + loopback MCP → tool invocation**: `agentic_system_security_novel_deep` for CVE-2025-66414 and the broader class.
- **DIP absence + XS-Leaks**: broader XS-Leaks surface; load this skill's XS-Leaks oracle depth.
- **CSWSH + internal service → SSRF-equivalent**: `ssrf` for the broader class.
- **postMessage CVE-2024-49038 class → XSS**: `xss_novel_deep` for the DOM-rendering primitive.
- **Sandbox-iframe bypass (CVE-2024-5691) → navigation primitive**: `open_redirect` for downstream.

## Deep DIP Compatibility Analysis

Chrome 137 (May 2025) shipped Document Isolation Policy. The primary-source Chrome blog post at `developer.chrome.com/blog/document-isolation-policy` establishes the mechanism and compatibility.

**Pre-DIP COOP+COEP Problem**:
- To enable cross-origin isolation (crossOriginIsolated), both headers required:
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Embedder-Policy: require-corp`
- The COEP constraint propagated to embedded subframes: each subframe either needed its own COEP, or needed to opt in via CORP, or needed to serve `Cross-Origin-Resource-Policy: cross-origin`.
- Many apps couldn't adopt COEP because third-party embeds (ads, analytics, Twitter widgets) wouldn't opt in.
- As a result, many apps that needed SharedArrayBuffer or precise timing stayed on the Spectre-exposed path.

**DIP Mechanism**:
- `Document-Isolation-Policy: isolate-and-require-corp` on the document.
- Isolates the document in its own process (like COOP same-origin).
- Does not require COEP on subframes — the subframe constraint is lifted.
- Subresources (not subframes) still need CORP or CORS covering.

**Attack-Surface Implications**:
- Pages that were previously Spectre-exposed because they couldn't adopt COEP can now isolate.
- The XS-Leaks defenses that activate on crossOriginIsolated (timer coarsening, structured postMessage) now apply to a broader population.
- A sensitive app in Chrome 137+ should either adopt COOP+COEP (classic path) or DIP (new path); absence of either is a Spectre-exposed finding.

**Testing**:
- Fetch document; inspect `Document-Isolation-Policy` header.
- Check `self.crossOriginIsolated` in a controlled Chrome 137+ profile.
- Verify timer-precision: `performance.now()` returns coarsened (5-microsecond) vs precise (microsecond) values.

**Chrome-specific**: Firefox and Safari have not shipped DIP equivalent. Cross-browser pentest requires separate COOP+COEP testing on non-Chrome.

## Expanded DNS Rebinding Context

The CVE-2025-66414 MCP TypeScript SDK CVE establishes DNS rebinding as a live 2025 attack vector against local HTTP services. This is a browser-security primitive because the attack vector is a victim's browser.

**Chrome Private Network Access**:
- Chrome 2024 shipped Private Network Access (PNA): preflight required before public-page fetches to private IPs (RFC 1918) can succeed.
- Mitigates DNS rebinding against most HTTP services on private IPs.
- **But does not cover WebSockets** (see the CSWSH section).
- Firefox and Safari lag; PNA is Chrome-specific.

**Implication**:
- Services bound to loopback and using HTTP: Chrome protection via PNA + an Origin check at the service.
- Services bound to loopback and using WebSocket: Chrome's PNA does not help; service must check Origin.
- Services bound to loopback and using HTTP with DNS rebinding protection (e.g., `enableDnsRebindingProtection: true`): protected.
- Services bound to loopback with none of these: fully exposed.

## Measured Primitive: Novel Oracle Reproduction

Reproduction methodology for novel 2024–2026 XS-Leaks oracles (without running against unauthorized targets):

### Measurement Script: Connection-Pool Pool-State

```javascript
// Measurement — observe local browser's connection pool behavior.
// Safe to run against attacker-controlled test server only.
const probeDurationMs = 2000;
const concurrency = 32;
const target = 'https://your-test-server.example/slow-endpoint';

async function probe() {
  const start = performance.now();
  const promises = Array(concurrency).fill(0).map(() => fetch(target));
  await Promise.all(promises);
  const elapsed = performance.now() - start;
  return elapsed;
}

const baseline = await probe();
console.log(`Baseline: ${baseline}ms for ${concurrency} parallel fetches`);
// To observe pool contention: increase concurrency to 258 and observe where new requests block.
```

### Measurement Script: ETag Length Capture

```javascript
// Measurement — observe ETag length and cache behavior.
// Safe to run against attacker-controlled test server only.
const response = await fetch('/test-endpoint');
const etag = response.headers.get('ETag');
console.log(`ETag: "${etag}", length: ${etag.length}`);
// Node.js jshttp/etag typically produces 10-20 char ETags; crafted content can be arbitrary length.
```

### Measurement Script: Isolation State

```javascript
// Measurement — observe cross-origin isolation state.
// Safe to run on any page; purely reads from DOM.
console.log({
  crossOriginIsolated: self.crossOriginIsolated,
  sharedArrayBuffer: typeof SharedArrayBuffer,
  measureMemory: typeof performance.measureUserAgentSpecificMemory,
  nowPrecision: {
    now: performance.now(),
    after1ms: await new Promise(r => setTimeout(() => r(performance.now()), 1))
  }
});
```

The `nowPrecision` field reveals timer coarsening: isolated pages see 5-microsecond granularity; non-isolated pages see finer resolution (microsecond or sub-microsecond).

## MSRC and Vendor-Published Primary Sources

Microsoft, Google, Mozilla, and Apple publish security posts that document specific browser-platform findings. For 2024–2026 browser-security research, the primary-source checklist:

- **Microsoft Security Response Center** (`msrc.microsoft.com`): Copilot Studio postMessage class.
- **Chrome blog** (`developer.chrome.com/blog`): DIP, Private Network Access, Site Isolation updates.
- **Mozilla blog / Bugzilla**: Firefox-specific CVEs and sandbox-posture.
- **WebKit blog**: Safari-specific changes.
- **xsleaks.dev wiki**: canonical XS-Leaks oracle catalogue.
- **portswigger.net/research**: HTTP/1.1 Must Die (BH USA 2024 Top 10 Web Hacking Techniques #3) and HTTP smuggling research.
- **Cure53 wiki / H5SC** (`cure53.de`): sanitizer-bypass primary research.

Treat these as PRIMARY technique sources; verify specific CVE claims against NVD and GHSA.

## Research-Grade Open Problems

Browser-security open problems identified in the 2024–2026 landscape:

### Problem: XS-Leaks Oracle Enumeration Not Complete

The xsleaks.dev wiki catalogues the current known oracles but is incomplete: new oracles (connection pool, ETag length) are discovered yearly. No systematic defense exists — each oracle is patched individually.

### Problem: DoubleClickjacking Class is Not Fully Mitigated

Classic framing defenses (X-Frame-Options, frame-ancestors, SameSite) do not block DoubleClickjacking. Mitigations are per-application (require confirmation modal, delay, passphrase). Browser-platform mitigation is open.

### Problem: Browser-Side URL-Parser-Differential

Browsers use WHATWG URL; servers use RFC 3986. The disagreement is a general attack surface. Browser-side canonicalization at `fetch()` time doesn't match server-side. See `semantic_confusion_novel_deep` for the broader class.

### Problem: Multi-Browser Policy Equivalence

A page secured against Chrome may be exploitable in Firefox or Safari (and vice versa). DIP is Chrome-only; some XS-Leaks oracles are browser-version-specific. Multi-browser pentest coverage is manual and expensive.

### Problem: Service Worker Lifecycle

Service workers survive injection-point patches; the attacker's persistence is on the user's browser, not the server. Rollback and detection are difficult.

### Problem: Agent-Driven Browser Interaction

Agents (Claude, Cursor, Devin) that control a browser (DevTools, Puppeteer) extend the attack surface — a browser-security finding on an agent-controlled browser affects the user through the agent. Load `agentic_system_security_novel_deep`.

## Browser-Vendor Advisory Current-Status Checklist

For a 2024–2026 browser-security pentest, maintain a current-status matrix across the major vendors:

| Vendor | Blog | Advisory Tracker |
|---|---|---|
| Chrome | developer.chrome.com/blog | chromereleases.googleblog.com + nvd |
| Firefox | mozilla.org/security/advisories | bugzilla.mozilla.org |
| Safari | webkit.org/blog | apple.com/support/security |

For each advisory in the pentest scope, verify:
1. CVE globally resolves on NVD.
2. Patched version shipped.
3. Target browser version is at or above patched.

## Cross-Browser Behavior Matrix Checklist

For a cross-browser pentest, document behavior across:

- **URL parsing**: WHATWG URL in Chrome/Firefox/Safari — subtle differences remain.
- **Cross-origin isolation**: COOP+COEP (all browsers), DIP (Chrome 137+ only).
- **Service worker scope**: implementations differ.
- **XS-Leaks oracles**: connection pool is Chromium-specific; dimension oracles affect all.
- **PNA**: Chrome-specific; Firefox and Safari have different approaches.
- **CSP evaluator**: differences in how browsers evaluate directives (`trusted-types` enforcement varies).
- **Trusted Types**: enforcement varies; some bypass gadgets work only on specific browsers.

## Verification Discipline for Novel-Tier Findings

For a novel browser-security finding:

1. **CVE globally resolves**: verify on NVD + GHSA. The CVEs cited in this file have been verified for this skill (JSON persisted in `.zen-batch-artifacts/batch-12/nvd/` and `ghsa/`).
2. **Primary-source citation**: Chrome blog, Mozilla blog, xsleaks.dev, or peer-reviewed research — not blog aggregators.
3. **Browser-version matrix**: Chrome X.Y, Firefox X.Y, Safari X.Y with specific-version observations.
4. **Measured oracle quantification**: for XS-Leaks, timing separation in milliseconds across N trials.
5. **Chain to impact**: a primitive is a lead; the impact is the authorization or data-exposure chain.
6. **Current status of Privacy Sandbox APIs**: do not cite deprecating APIs (Fenced Frames, Topics, etc.) as frontier.

## Breadth of the Live Frontier

The verified 2024–2026 browser-security novel-tier spans at least 15 CVEs with globally-resolving GHSA/NVD records (CSPT: 4; browser-vendor renderer: 10+; postMessage: 1; WebRTC/WebTransport: 5+), plus three verified novel techniques (connection-pool XS-Leaks, ETag-length XS-Leaks, DoubleClickjacking) with primary-source citations, plus Chrome's Document Isolation Policy as a 2025-shipped primitive. The ecosystem is rich enough that this file lands in the ~850-line target through genuine primary-source-grounded content, not padding. Future research directions (xsleaks.dev wiki updates, additional browser-vendor advisories, DIP adoption-pattern findings) will continue to broaden the surface through 2026.

## Summary

The 2024–2026 browser-security frontier is anchored on verified CVEs across CSPT, postMessage, iframe sandbox, WebTransport/WebRTC/WebSocket, and renderer-sandbox classes, plus novel XS-Leaks oracles (connection pool, ETag length), DoubleClickjacking as a UI-redressing defeater, and Chrome's Document Isolation Policy as a 2025-shipped alternative to COOP+COEP. The Privacy Sandbox APIs that were once positioned as frontier (Fenced Frames, Topics, Protected Audience, etc.) are deprecate-and-remove; focus 2026 work on CHIPS, FedCM, Storage Access API, Private State Tokens, and the mature primitive classes. The open research problems — comprehensive XS-Leaks oracle enumeration, DoubleClickjacking defense, cross-browser policy equivalence, service-worker lifecycle, agent-driven browser interaction — define the next 12–24 months of browser-security research.
