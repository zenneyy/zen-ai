---
name: browser-security
description: Browser-internals security testing — browsing-context relationships, postMessage, client-side path traversal (CSPT), XS-Leaks oracles, service workers, Web Workers, navigation behavior, CSP interactions, cross-origin isolation (COOP/COEP/CORP), caches, and cross-origin state machines
---

# Browser Security

Use this skill when exploitability depends on browser behavior beyond a basic HTML injection. Model origins, browsing contexts, navigation history, workers, caches, router decoding, request metadata, and user activation as explicit state.

Pair this skill with `xss`, `oauth`, `open_redirect`, `csrf`, or `semantic_confusion` when one of those is the primary vulnerability class. For an Electron renderer with a preload or IPC bridge, load `electron_desktop_apps` to analyze whether navigation and origin transitions reach native capability.

## Safety Boundary

- Use a controlled browser profile, synthetic account/data, explicit target allowlist, and a fresh assessment-specific proxy/CA when interception is required.
- Redact tokens, cookies, message contents, storage values, and personal data from console logs, captures, recordings, and reports.
- Treat oversized URLs/headers, cookie inflation, redirect loops, cache exhaustion, and high-rate timing trials as resource/denial-of-service tests; run them only with strict ceilings in a restartable lab.
- Do not attempt to set or spoof browser-generated `event.origin`. Vary the sender URL and record the serialized origin supplied by the browser.
- Restore monkey-patched browser APIs and unregister test workers/caches after validation.

## Browser State Model

For each relevant page or worker, record:

- origin and site, including transitions after navigation
- top-level window, opener, parent, child frames, named contexts, and retained references
- sandbox flags, CSP `frame-ancestors`, COOP, COEP, CORP, and X-Frame-Options
- service-worker controller and scope
- storage access: cookies, local/session storage, IndexedDB, Cache API
- navigation/history entries and redirect type: HTTP, JavaScript, form, meta refresh
- user-activation and interaction requirements
- browser family/version and enabled experimental features
- cross-origin isolation state: `self.crossOriginIsolated` — true requires COOP same-origin + COEP require-corp (or Document Isolation Policy, Chrome 137+)

Draw the context graph. Security checks on `event.origin`, `event.source`, or a popup reference are meaningful only when the lifetime and ownership of that context are understood.

## High-Value Surfaces

### postMessage and Window Relationships

- Enumerate listeners and senders; record message schema, origin check, source check, and reachable sinks/actions.
- Validate origins after URL parsing and canonicalization, not with raw-string regexes.
- Test numeric/alternate IP forms, userinfo, path masquerading as a host suffix, and redirects.
- Treat predictable `window.open()` target names and iframe names as potentially shared namespace entries. Confirm reuse within the same browsing-context group, opener chain, COOP state, and relevant navigation/message timing.
- Check whether a blocked intermediate frame leaves a useful browsing-context relationship intact.
- Use random per-flow names or `_blank` with `noopener` where an opener relationship is unnecessary.
- Verify `event.isTrusted` on messages when the handler is sensitive — synthetic `MessageEvent` can lie about origin via `dispatchEvent`.

### Client-Side Path Traversal (CSPT)

Trace the complete source-to-request pipeline:

```text
browser URL -> router parser -> route/query/hash accessor -> app interpolation -> fetch/XHR -> final normalized URL
```

- Test path parameters, query parameters, and hashes independently.
- Determine exactly where `%2F`, `%5C`, `%2E`, and double-encoded forms decode or re-encode.
- Instrument `fetch`, XHR, Axios, router navigation, and server-side fetch wrappers to capture the final URL.
- Escalate only after identifying the sink: state-changing API for CSRF-like impact (CSPT2CSRF), HTML/attachment response rendered in an unsafe sink for XSS, or server-side fetch for SSRF.
- Do not assume the same framework API behaves identically in client components, server components, and route handlers.

The CSPT class was formalized by Doyensec in 2024 (CSPT1 — leaking server responses; CSPT2CSRF — turning CSPT into a CSRF primitive against state-changing endpoints). The frontier is well-documented across SPAs built on React Router, Next.js router, Vue Router, Angular router, and framework-independent routing libraries.

### XS-Leaks and Cross-Origin Oracles

Inventory observable signals that do not require reading the cross-origin response:

- load/error events for script, image, stylesheet, frame, media, and module elements
- timing, connection reuse, cache state, redirect count, and navigation success
- window/frame count, focus, history length, and resource dimensions
- browser-generated error pages and status-dependent behavior
- request headers such as `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, and `Origin`

The xsleaks.dev wiki catalogues the current oracle set:

- **Frame counting**: `window.frames.length` and `window.length` differentiate pages that load N vs M child frames.
- **Element ID attribute**: an element with `id="foo"` fired `focus/blur` events when `location.hash = "#foo"` navigates.
- **Error events**: `onload` vs `onerror` on `<script>`, `<img>`, `<iframe>` differ by target state (authenticated vs unauthenticated).
- **PostMessage broadcasts**: cross-origin iframes that `postMessage("*", ...)` leak the message to any listener.
- **Cache probing**: cache-hit vs cache-miss timing differential reveals prior-fetch state.
- **CSS injection**: `@import` with error vs success leaks state.
- **Window references**: a window reference's property-access behavior reveals origin changes.
- **Connection pool**: the browser's 256-connection-per-host limit is a side-channel for subdomain-lexical-sort-order attacks.
- **Performance API**: `PerformanceObserver` on resource-load entries can reveal timing and origin details.
- **CORB/CORP enforcement side-effects**: a resource that gets blocked by CORB returns different Observable state than one that loads normally.

Test controls such as ORB (Opaque Response Blocking), CORP (Cross-Origin-Resource-Policy), COEP (Cross-Origin-Embedder-Policy), and MIME enforcement. A service worker or alternate fetch path can change request destination metadata and therefore change whether a blocked response becomes a network error or an empty response. Validate the oracle across authenticated and unauthenticated control cases.

### Service Workers and Caches

- Map service-worker registration scope, update lifecycle, controller acquisition, and fetch handlers.
- Inspect Cache API keys and responses; determine whether HTML or JavaScript is served directly from a writable cache.
- Test whether a constrained script context can poison app-managed cache entries later consumed by a normal page or service worker.
- Treat service-worker persistence as high impact, but prove registration/control scope and update survivability.
- Compare a direct subresource request with the same request proxied through `fetch(event.request)`; request destination and mode can differ.

### Web Workers and Constrained Script Execution

When script runs inside a worker, inventory capabilities instead of dismissing it as low impact:

- credentialed same-origin `fetch` for data access and state changes
- `postMessage` gadgets into the main page
- IndexedDB and Cache API shared with other same-origin contexts
- Blob construction and object URLs
- import mechanisms, WebSocket, and available browser-specific APIs

Prove the strongest reliable capability first. If escalation requires a user gesture, document the exact gesture, timing, browser, and visibility rather than calling it zero-click XSS.

### Navigation and Redirect Control

- Distinguish HTTP 30x, script navigation, form submission, meta refresh, and popup navigation.
- Test invalid or blocked URL schemes and WAF-generated error pages only when they support a real flow. Oversized URLs/headers, cookie-path-specific header inflation, redirect limits, and navigation throttling are restartable-lab-only tests with strict size/iteration limits and health checks.
- A sandbox inherited by a new top-level context can selectively block forms, scripts, popups, or navigation; enumerate the exact flag set.
- Preserve and inspect history when a built-in error page replaces the active document; do not assume the errored URL is lost.

### CSP and Browser Parsing

- Evaluate the delivered policy on the exact response, including redirects and error/API/static paths.
- Map nonces, hashes, `strict-dynamic`, allowed schemes, trusted script gadgets, `base-uri`, `frame-ancestors`, and Trusted Types.
- Test parser namespaces and repairs in HTML, SVG, and MathML. A protected attribute or sanitizer rule in the HTML namespace may behave differently after namespace transitions.
- Treat scriptless disclosure of a nonce or trusted URL as a primitive; prove a second controllable sink before claiming bypass.
- For response splitting, consider whether a same-origin endpoint can be turned into a script resource with a controlled body length or framing.

### Cross-Origin Isolation (COOP, COEP, CORP, DIP)

A page is **cross-origin isolated** when it meets COOP + COEP (or Chrome 137+ Document Isolation Policy). Isolation gates:

- `SharedArrayBuffer` creation and `postMessage` transfer.
- `performance.measureUserAgentSpecificMemory()`.
- Precise `performance.now()` timers (otherwise coarsened to prevent Spectre).

Testing cross-origin isolation:

- Check `self.crossOriginIsolated` in the controlled profile.
- COOP `same-origin` + COEP `require-corp` is the classic path; DIP (Chrome 137+) is a per-frame alternative not requiring subframe opt-in.
- When isolated, subresources without CORP/CORS are blocked; `window.opener` across cross-origin popups is severed; `document.domain` writes are rejected.
- Isolation state is a prerequisite for several XS-Leaks defenses — missing isolation keeps the Spectre-era attack surface live.

Chrome 137 (May 2025) shipped Document Isolation Policy. Firefox and Safari lag; DIP is Chrome-specific as of this writing — a cross-browser pentest must test COOP/COEP in Firefox/Safari independently.

### JavaScript Gadget Discovery

- When direct calls are blocked, inspect implicit coercions (`toString`, `valueOf`, iterators, getters, proxies) and callbacks invoked by accessible library functions.
- Search for functions whose `this` object and arguments can be attacker-shaped.
- Build a bounded harness to enumerate reachable globals and observe property reads/calls; avoid assuming one library gadget is universal.
- Validate the complete call chain to a dangerous sink such as navigation, HTML insertion, `eval`, `Function`, or a privileged API.

## Framework-Specific CSPT

Each frontend framework has distinct URL-parameter decoding behavior; CSPT primitives are framework-sensitive:

### React Router

- `useParams()` returns decoded path params; a URL `/user/%2Fetc%2Fpasswd` passes to the fetch as `/user//etc/passwd` after double-decode.
- `useSearchParams()` returns decoded query params; same decoding.
- `generatePath()` can be an injection point if the pattern includes attacker-controlled parts.
- React Router v6+ handles encoding differently from v5 — test both.

### Next.js Router

- App-router `params` and `searchParams` are available server-side (Server Components) and client-side; the decoding differs.
- Dynamic routes (`[id]/page.tsx`) decode once.
- Catch-all routes (`[...slug]/page.tsx`) preserve slashes within slug — `..` segments are possible.
- Server Actions can be CSPT-reachable from a client-side link.

### Vue Router

- `route.params.id` is decoded; the composition API `useRoute()` carries the decoded value.
- Vue 3 Composition API routes may differ from Vue 2 options API.

### Angular Router

- `ActivatedRoute.snapshot.params` carries decoded path parameters.
- `queryParams` decoded via Angular's `UrlTree` parser.

### Framework-Independent Pattern

For any SPA router: the user-visible URL is decoded N times (by browser, by router, by app) before reaching `fetch`. The validator at step N-1 may see the pre-decode form while the fetcher at step N sees the fully-decoded form. Instrument every decode step to catch the invariant break.

## Specific XS-Leaks Oracle Treatments

### Oracle: Frame Count

**Primitive**: `window.length` reveals how many child frames a page contains; different states of a page may have different frame counts (admin UI with more panels, logged-in state with more widgets).

**Precondition**: can embed target cross-origin; target does not forbid framing (no `X-Frame-Options: DENY` or `frame-ancestors` restriction).

**Confirmation**: `window.frames.length` differs between authenticated and unauthenticated states.

### Oracle: ID Attribute Focus Event

**Primitive**: `location.hash = "#elem_id"` on a cross-origin iframe causes focus/blur events on the parent; events reveal the ID's presence.

**Precondition**: target page framable; target has ID-indexed elements per state.

**Confirmation**: focus event fires on hash navigation.

### Oracle: Load/Error Event

**Primitive**: an `<img>` or `<script>` tag targeting a cross-origin URL fires `onload` on success, `onerror` on 404 or error. Target state determines which fires.

**Precondition**: resource must be requestable; target returns different status by state.

**Confirmation**: onload vs onerror differs between control cases.

### Oracle: Connection Pool

**Primitive**: Chromium's 256-connection-per-host limit; attacker exhausts and times connection re-use.

**Precondition**: target supports many concurrent requests; attacker can time connection availability.

**Confirmation**: timing-separated connection availability reveals target state.

### Oracle: Cache Probing

**Primitive**: a fetch to a URL that may or may not be cached differs in timing; attacker measures.

**Precondition**: resource may be cacheable; cache state varies by target state.

**Confirmation**: fetch-timing distribution bimodal (cache-hit vs cache-miss).

Each oracle requires paired controls (success-case, failure-case) and multiple trials to separate noise. Report quantified separation (e.g., success at 50ms ± 10ms, failure at 200ms ± 30ms, separation = 150ms).

## Service Worker Attack Depth

### Attack: Service-Worker Scope Abuse

Service workers control a scope defined at registration. A service worker registered at `/subpath/` intercepts fetches for all `/subpath/*` pages. If an attacker can inject the registration (through XSS to a page served at `/subpath/malicious.html`), the worker intercepts legitimate `/subpath/*` traffic.

### Attack: Cache API Poisoning

If attacker-controlled script can write to the Cache API, subsequent fetches that read from cache will see attacker content. The cache is same-origin; cross-origin writes require a service worker in the attacker-controlled context.

### Attack: Service Worker Persistence

A service worker survives patches to the vulnerable page — the worker continues to control until explicitly unregistered or an updated worker takes over. For an XSS primitive that registers a worker, the attacker's control outlives the fix.

### Attack: Service-Worker-Controlled-Fetch Destination Change

A service worker's `fetch` handler may re-issue the request with different metadata (`destination: 'empty'` instead of `'script'`). Downstream security checks keyed on `Sec-Fetch-Dest` see the modified metadata.

## Named Window Reuse Attack

### Attack: Browsing-Context-Group Collision

A predictable `window.open(url, "sidebar")` creates or reuses a named context "sidebar". Attacker predicts the name, pre-registers the context from an attacker-controlled page, and future opens by the victim land in the attacker's context.

- **Precondition**: name is predictable or guessable; attacker-page is open in the same browser.
- **Confirmation**: open-call lands in attacker-context rather than fresh.
- **Impact**: cross-origin content injection into what the user believes is a trusted window.

Mitigation: use `_blank` with `noopener`, or randomize names per flow.

## Protocol Handler and Scheme Abuse

### Scheme: `javascript:` Navigation

Modern browsers block `javascript:` in `<a href>` top-navigation but allow in some sub-contexts. Framework-level navigation calls (`router.push("javascript:...")`) sometimes slip through.

### Scheme: `data:` Top-Frame Navigation

Chrome deprecated top-frame `data:` navigation; subframe navigation to `data:` still works. A sandboxed iframe navigating to `data:text/html,...` with `allow-scripts` executes attacker-content.

### Scheme: `mailto:` Parameter Injection

A `mailto:` URL with user-controlled `to`, `subject`, `body` can abuse mail-client features (BCC injection, encoding tricks).

### Scheme: `blob:` and `filesystem:` URLs

Both are same-origin schemes; a page with XSS can create blob URLs with executable content.

### OS-Level Protocol Handlers

`ms-settings:`, `vscode:`, `cursor:`, `claude:`, `anthropic:` register OS-level handlers that launch applications with URL-passed arguments. Browser-page JS triggers them via `window.location`. Load `agentic_system_security` when the handler launches an agent application.

## Reconnaissance

### Runtime Instrumentation

Instrument in a controlled browser session:

```javascript
const realFetch = window.fetch;
window.fetch = (...args) => {
  const input = args[0];
  const rawUrl = typeof input === 'string' ? input : input.url;
  const url = new URL(rawUrl, location.href);
  const method = args[1]?.method || input?.method || 'GET';
  console.log('fetch', {method, origin: url.origin, path: url.pathname});
  return realFetch(...args);
};

window.addEventListener('message', e => {
  const keys = e.data && typeof e.data === 'object' ? Object.keys(e.data) : [];
  console.log('message', {origin: e.origin, sourceMatches: e.source === window.opener, keys, isTrusted: e.isTrusted});
}, true);
```

Use the wrapper only in the controlled profile and restore `window.fetch = realFetch` afterward. Do not log bodies, message values, credentials, or query strings.

Also inspect DevTools network initiators, service workers, storage, CSP violations, frame tree, and navigation history. Use raw browser behavior for validation; command-line HTTP clients cannot reproduce origin/window/worker semantics.

### Source Review

- Search for `postMessage`, message listeners, `window.open`, named targets, opener/parent access, frame creation, and sandbox attributes.
- Search for router parameter APIs flowing into `fetch`, Axios, navigation, or HTML rendering.
- Search for service-worker registration, Cache API writes, worker constructors, Blob URLs, and dynamic imports.
- Search for raw HTML sinks and trust escape hatches in every supported frontend framework.
- Compare CSP and framing headers across document, API, static, callback, redirect, and error routes.
- Check for `event.isTrusted` enforcement on message listeners.

## WebTransport, WebRTC, and WebSocket Cross-Origin

Modern transports have different cross-origin behavior than classic HTTP:

### WebSocket Cross-Origin

- Cross-Site WebSocket Hijacking (CSWSH): same-origin policy does not block cross-site WebSocket upgrade requests when the target doesn't check `Origin`. If the WebSocket uses cookies for auth, attacker's page can establish a credentialed connection to the target.
- Private Network Access (PNA) **does not cover WebSockets** — the no-preflight requirement means attacker's public page can open WebSocket to internal `192.168.x.x` services.
- Testing: open `ws://target/path` from attacker.com with credentials; check if target accepts.

### WebRTC Signaling

- WebRTC signaling may expose internal IPs (STUN candidates), creating a reconnaissance primitive.
- WebRTC data channels can bypass CORS for peer-to-peer data transfer; a victim-side JS can be instructed to send data to attacker via WebRTC.

### WebTransport

- WebTransport over HTTP/3 (QUIC) introduces new framing; cross-origin behavior is still evolving.
- No equivalent of PNA preflight at this transport layer.

## Site Isolation and Spectre-Adjacent Primitives

Chrome's Site Isolation project runs each site in its own renderer process. This is a defense against Spectre-class side-channels — a compromised renderer cannot read cross-site data because it doesn't have it mapped.

Site Isolation is desktop-Chrome 67+ default and Android-Chrome 77+ selective. Firefox has Project Fission (shipped). Safari has per-origin processes on iOS.

Attacks that undermine Site Isolation:

- **Renderer compromise then cross-site read**: if the renderer is compromised (type-confusion in V8, UAF in rendering), the attacker still cannot read cross-site content because that content isn't in the compromised process. The chain requires an additional sandbox-escape or Mojo/IPC primitive.
- **Spectre-era timing side-channels**: with cross-origin isolation absent, high-precision timers remain accessible, enabling Spectre-adjacent gadgets. The defense is COOP+COEP (or DIP) which coarsens timers to defeat Spectre.

The 2024–2026 CVEs in this space (Mojo/ipcz handle validation bugs, V8 type-confusion, animation-timeline UAFs) are renderer-exploit chain tail-ends — useful for threat-model context but not client-side web-application attack primitives directly.

## Standards and Spec Mapping

- **W3C/WHATWG URL Living Standard**: diverges from RFC 3986 in several places; browser URL parsing is WHATWG, server URL parsing is often RFC 3986 — classic semantic-confusion surface. Load `semantic_confusion`.
- **Fetch Standard**: defines request destination (`Sec-Fetch-Dest`), mode, credentials; the destination metadata is the XS-Leaks signal surface.
- **HTML Standard**: HTML5 parser state machine; CSP; CORS; postMessage; MessageEvent.isTrusted.
- **Service Worker Spec**: registration lifecycle, controller selection, fetch event.
- **Trust Tokens / Private State Tokens** (continued support): anti-fraud primitive.
- **FedCM** (continued support): federated identity model.
- **Private Network Access** (continued support, not covering WebSockets): preflight for private-IP fetch.
- **Fenced Frames, Topics API, Protected Audience, Attribution Reporting, Shared Storage, Related Website Sets**: these Privacy Sandbox APIs have been scheduled for deprecation and removal from Chrome; do not treat as current frontier attack surfaces for new work (verify current status against the Privacy Sandbox project page at the time of testing).

## Testing Methodology

1. **Define the browser state** — Origin/site, context graph, policies, workers, storage, and activation.
2. **Identify a source and observable sink** — Message, URL component, cache entry, navigation, load/error event, or implicit call.
3. **Trace transformations** — URL parsing, framework decode, browser normalization, request destination, and document replacement.
4. **Build paired controls** — Same-origin/cross-origin, status success/error, worker/direct, unique/predictable window name, encoded/raw path.
5. **Prove the primitive** — Data transfer, path change, state oracle, cache modification, or context capture.
6. **Escalate deliberately** — Chain to a privileged action, sensitive disclosure, SSRF, or executable DOM sink.
7. **Cross-browser check** — At minimum record Chromium/Firefox/Safari applicability when the primitive is browser-specific. DIP is Chrome-specific; some XS-Leaks oracles are browser-version-specific.
8. **State interaction requirements** — Click, drag, popup permission, timing window, login state, and visual deception.

## Validation

1. Capture the context graph and relevant policies at exploit time.
2. Show the exact browser-parsed origin or final request URL, not just the attacker-supplied string.
3. For postMessage, prove both message origin and source/context ownership; include `event.isTrusted`.
4. For XS-Leaks, repeat randomized success/failure trials and quantify separation and noise.
5. For workers/caches, show which later context consumes the modified data.
6. For client-side traversal, capture the final network request and the security-relevant response/action.
7. For interaction-dependent chains, provide a screen recording or deterministic event trace.

## False Positives

- A message reaches a listener but fails schema, origin, source, or state validation before any action
- A router decodes traversal characters but the value never reaches a URL/path sink
- Different load/error behavior caused by unstable network rather than protected state
- Worker script execution with no sensitive API, shared state, main-thread gadget, or meaningful action
- CSP nonce disclosure without a controllable way to reuse it in an executable sink
- Named-window collision blocked by origin scoping, randomized names, COOP, or `noopener`
- Browser-specific behavior reported without the required version, flag, or user interaction
- Oracle based on timing with no measured separation beyond noise

## Clickjacking and Interaction-Hijack

### DoubleClickjacking

A 2024 technique by Paulos Yibelo: a window-swap during a user's double-click defeats X-Frame-Options, `frame-ancestors`, SameSite, and classic clickjacking defenses. First click lands on attacker's page; the attacker JS swaps the window; the second click lands on the target's authenticated action button.

The defense is to require more than a simple click for sensitive actions (passphrase, confirmation modal, elapsed-time delay). Standard framing defenses do not block this.

### Classic Clickjacking

- `<iframe>` of target with transparent overlay; victim's click lands on target's hidden action.
- Mitigation: `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.
- Check both headers; a missing header on one route (API, error page) is sufficient for the attacker.

### UI Redressing with Opacity Tricks

CSS `opacity: 0.01` with `pointer-events: auto` makes an iframe invisible but click-able; `transform: scale()` can position it over a user-visible button.

### Overlay via Cross-Window Positioning

A popup positioned over the main window (requires explicit permission from the user in modern browsers) can mimic the main window's chrome.

## Chaining Attacks

Browser primitives chain into:

- **CSPT → CSRF (CSPT2CSRF)**: client-side path traversal that reaches a state-changing API — load `csrf` for the broader attack class.
- **postMessage weakness → XSS**: a listener that trusts message content and renders → load `xss`.
- **XS-Leaks → login/state oracle**: a cross-origin timing or counting signal that reveals user state → chain with `csrf` or `open_redirect` for impact.
- **Service worker persistence → long-lived XSS**: an initial `xss` primitive registers a service worker that outlives the vulnerability patch.
- **Cross-origin isolation gap → Spectre-adjacent primitives**: missing COOP/COEP leaves the renderer-process attack surface; load `rce` adjacency.
- **Named-window reuse → cross-origin credentialed action**: a browser-wide named-window attack reaches an authenticated flow.
- **DNS rebinding → local MCP**: load `agentic_system_security_advanced_deep` for the MCP class.
- **Sandbox-iframe bypass → navigation primitive**: load `open_redirect` for the downstream.

## Pro Tips

1. Treat browsing-context names as attacker-contestable identifiers unless randomized.
2. Query parameters are usually decoded automatically; path parameters vary by router and execution context.
3. Compare request metadata, not just URLs. Service workers can alter destination/mode semantics.
4. A strict origin check does not compensate for attacker control of the supposedly trusted window reference.
5. Error pages, redirects, and blocked frames still mutate history and context relationships.
6. Keep browser-version claims narrow and retest; these behaviors change faster than server-side primitives.
7. Prefer a small state-machine explanation over a large payload catalog.
8. Check `event.isTrusted` on message listeners; synthetic events can lie about origin.
9. Cross-origin isolation is a prerequisite for several defenses; its absence is itself a finding on sensitive apps.

## Summary

Browser exploitation is state-machine exploitation. Map origins, context references, policies, workers, storage, navigation, and decoding as one system. Prove each state transition with browser evidence, then chain only the primitives that survive the target's browser and interaction constraints. For advanced technique treatments (CSPT2CSRF, XS-Leaks oracles at depth, postMessage patterns), load `browser_security_advanced_deep`; for the 2024–2026 verified-CVE catalog and emerging frontier (DIP, DoubleClickjacking, novel XS-Leaks oracles), load `browser_security_novel_deep`.
