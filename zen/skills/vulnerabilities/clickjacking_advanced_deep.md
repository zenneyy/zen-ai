---
name: clickjacking-advanced-deep
description: Advanced clickjacking / UI-redress technique depth — browser-enforcement differentials for X-Frame-Options and CSP frame-ancestors, SameSite cookie interactions, nested-frame and shadow-DOM primitives, drag-and-drop and keyboard-focus depth, CSS-only variants, framework-specific exposure, and chained exploitation.
sibling: clickjacking
load_when: scan_mode == "deep"
---

# Clickjacking — Advanced Deep

Load `clickjacking` for the base-tier framing (attack-surface, key-vulnerability classes, defense headers, confirmation discipline). Load `clickjacking_novel_deep` for the 2024–2026 published frontier (DoubleClickjacking's "defense-irrelevant UI redress" class). This file owns the advanced-tier differential depth: per-browser enforcement of X-Frame-Options vs CSP frame-ancestors, SameSite cookie interactions at depth, nested-frame and shadow-DOM primitives, drag-and-drop and keyboard-focus mechanics, CSS-only variants, framework-specific exposure patterns, and the chained exploitation surface.

The classic defenses are architecturally correct for the iframe-overlay primitive when configured without the gaps this file enumerates; the novel-tier primitives are a separate class entirely and route to the novel sibling. Overlapping class surfaces route by filename: cross-origin credential-echo configuration to `cors_misconfiguration`; the state-change invariant for CSRF-shaped mutations to `csrf`; the rendered-script sink to `xss`; broader site-isolation and frame-containment primitives to `browser_security_advanced_deep`.

## X-Frame-Options Enforcement Differentials

**Chrome 94+**: honors `DENY` and `SAMEORIGIN`. `ALLOW-FROM uri` was never implemented and is ignored. Multiple `X-Frame-Options` headers: Chrome rejects (treats as invalid, defaults to allowing framing — a security surface) in some versions and takes the first-value in others. Verify behavior per deployment.

**Firefox 110+**: honors `DENY`, `SAMEORIGIN`, and (uniquely) `ALLOW-FROM uri` with single-origin value — ALLOW-FROM support was retained in Firefox through recent versions. Compound values are not supported.

**Safari (WebKit) 15.4+**: honors `DENY` and `SAMEORIGIN`. `ALLOW-FROM` never supported.

**Legacy IE / Edge Legacy** (deprecated): supported `ALLOW-FROM uri`. Modern Edge (Chromium-based) follows Chrome's behavior.

**Primitive**: a deployment relying on `X-Frame-Options: ALLOW-FROM trusted.tld` for cross-origin framing control is enforcing only in Firefox-at-the-time-of-this-writing; Chrome and Safari users receive no `X-Frame-Options` protection against that specific trusted origin's intent, and absent a CSP `frame-ancestors` directive the page is framable from everywhere in Chrome/Safari.

**Header-stripping-by-proxy**. Reverse proxies (Nginx, Cloudflare, AWS CloudFront) may add, strip, or override `X-Frame-Options` based on configuration. Verify the browser-received header, not the application-set header. A deployment that sets `X-Frame-Options: DENY` at the application but has a CDN that strips security headers (misconfigured `response_headers_policy` on CloudFront, missing `proxy_pass_header` on Nginx) is framable in practice.

**Error / exception-page gap**. Many deployments set `X-Frame-Options` on the main 200-response but miss 404, 500, or exception pages. If an attacker-reachable path produces a framable error page that reveals state (CSRF token echo, session info, user-specific error content), the clickjacking surface extends.

**Confirmation**: the primitive is the browser-rendered state, not the application claim. Use `curl -I` + a browser frame-test, not just header inspection.

## CSP frame-ancestors Enforcement Depth

**Precedence** over `X-Frame-Options`: normative in modern Chrome/Firefox/Safari. A deployment with `X-Frame-Options: DENY` + `Content-Security-Policy: frame-ancestors *` is framable from anywhere in modern browsers because `frame-ancestors` is honored and `X-Frame-Options` is ignored when `frame-ancestors` is present.

**Value syntax at depth**:
- `'none'` — never framable
- `'self'` — same-origin framable; schemes and ports count
- `http://trusted.tld` and `https://trusted.tld` — distinct sources; a mismatch leaves the HTTP side framable from only HTTP origins
- `https://*.trusted.tld` — wildcard subdomain; `evil.trusted.tld` under subdomain-takeover becomes a legitimate frame source
- `https://trusted.tld:443` — explicit port; omit the port and the default is implied, inconsistent across browsers
- Space-separated list with multiple sources
- No `'none'`-equivalent allowed value with `'unsafe-inline'` or other legacy source expressions

**Subdomain-takeover feeding frame-ancestors**: a `frame-ancestors https://*.trusted.tld` directive with an unused subdomain claimable via `subdomain_takeover` becomes an attacker-controlled framing origin. Route to `subdomain_takeover` for the recon side; the clickjacking consequence lives here.

**Report-only mode**: `Content-Security-Policy-Report-Only: frame-ancestors 'none'` reports but does not enforce. A deployment that sets only report-only mode is framable; the reports arrive at the configured endpoint but the attack succeeds.

**Multiple CSP headers**: multiple `Content-Security-Policy` response headers are intersected (the strictest applies). Multiple `frame-ancestors` directives across those headers all apply simultaneously. A deployment with two CSPs — one `frame-ancestors 'self'` and one `frame-ancestors https://evil.tld` — produces an effective policy of `'self' AND https://evil.tld`; both must grant framing. Not a bypass but a configuration surface worth verifying.

**Meta-tag CSP vs header CSP**: `frame-ancestors` is **not** valid in `<meta http-equiv="Content-Security-Policy">` and is ignored there. A deployment using meta-tag CSP for `frame-ancestors` is unenforced.

**Content-Security-Policy with 'self' and scheme considerations**:
- `frame-ancestors 'self'` matches same-origin (scheme + host + port exact match)
- Framing from HTTPS when the top page is HTTPS is in-origin
- A deployment serving the same content on both HTTP and HTTPS with `frame-ancestors 'self'` is framable from HTTP by HTTP and HTTPS by HTTPS; cross-scheme framing is blocked

**Confirmation**: inspect `Content-Security-Policy` response header (not meta tag); verify framing attempt from the expected-blocked origin returns a browser frame-blocked error, not a rendered iframe.

## SameSite Cookie Interactions at Depth

**Current browser defaults (2024–2026)**:
- Chrome / Edge (Chromium): `SameSite=Lax` default when the cookie has no `SameSite` attribute (since Feb 2020)
- Firefox 69+: `SameSite=Lax` default (introduced progressively; honoring default since full rollout)
- Safari 13+: ITP (Intelligent Tracking Prevention) adds additional cookie restrictions beyond SameSite

**Interaction with clickjacking**:
- `Strict`: cookie never sent on cross-origin iframe load. Clickjacking-with-auth is defeated.
- `Lax`: cookie not sent on cross-origin POST (iframe form POST does not carry auth); cookie IS sent on cross-origin GET-shape iframe load (iframe `src` loads a GET request). State-change POST clickjacking defeated; information-disclosure GET clickjacking still viable where there's a GET-based state change (anti-pattern but exists).
- `None; Secure`: cookie sent on all cross-origin iframe loads. Full clickjacking surface open.

**Lax-POST exception window** (Chrome, 2020): cookies without an explicit `SameSite` attribute default to Lax but ARE sent on cross-origin POST within a 2-minute window of creation. Only applies to session cookies with recent creation and no explicit SameSite attribute. The exception window narrows the "cookies always travel" assumption but admits specific attack windows.

**Chrome third-party cookie phaseout (2024–2026)**: Chrome's progressive removal of third-party cookies affects clickjacking-with-auth in cross-origin iframes. The current state (as of 2026) is partial deprecation with origin-trial opt-outs; the eventual full removal will close the `SameSite=None; Secure` default clickjacking case. Verify browser version and the deployment's user base.

**Safari ITP / Firefox Total Cookie Protection**: cookies are partitioned per top-level site; a cross-origin iframe sees a different cookie jar than the main window of its origin would. Many classic clickjacking attacks fail silently on these browsers because the iframe has no auth cookies. The pentester must verify on the user's actual browser, not the attacker's reference.

**Confirmation**: test the specific browser(s) the deployment supports. A clickjacking attack reproducing in Chrome but failing in Safari is still a Chrome-user finding; state the browser-scope.

## Nested-Frame and Shadow-DOM Primitives

**Same-origin chain**. A target with `frame-ancestors 'self'` is framable from same-origin pages. If any same-origin page is attacker-controllable (XSS, open-redirect, user-content hosting, markdown-rendering flaw), the attacker's same-origin page can frame the target. The attacker's same-origin page is itself framable from the attacker's cross-origin page (if the attacker's page is on an origin without framing restrictions).

**Attack recipe**:
```html
<!-- attacker.evil.tld -->
<iframe src="https://target.tld/attacker-controlled-same-origin-page?html=<iframe src=/account/delete></iframe>"></iframe>
```
Two frame layers; the inner frame carries SAMEORIGIN authority; the outer is unrestricted (attacker's origin). The user's click delivers through both layers to the target's state-change action.

**Primitive class**: any same-origin content hosting is a potential frame-ancestors escape. Verify by considering every path at which an attacker's content lands at the target origin: XSS, user-uploaded HTML, markdown that renders iframe tags, open-redirect to a framable location.

**Shadow DOM variants**. Where the target UI mounts framable content inside a Shadow DOM slot (Web Components with `<slot>` elements that render user-authored content), the attacker's slot-content can overlay the component's internal UI. Not a cross-origin attack but a trust-crossing within a page: component A's `<slot>` renders content from source B; B's content overlays A's buttons.

**iframe sandbox interactions**. `<iframe sandbox>` attribute controls iframe capabilities:
- `sandbox` with no values: maximum restriction; the frame cannot form-submit, run script, navigate top
- `sandbox="allow-forms"`: form submission allowed; clickjacking still viable
- `sandbox="allow-scripts"`: scripts allowed; frame-busting scripts can run but cannot top-navigate without `allow-top-navigation`
- `sandbox="allow-top-navigation"`: the frame can navigate the top window — used by malicious framed content to redirect the parent

**Iframe csp attribute** (`<iframe csp="...">`): proposed in CSP3, deprecated in favor of `sandbox` + Permissions Policy. Browser support uneven; treat as unenforced.

**Fenced frames** (Chrome 2023+ experimental, generally-available-ish by 2026): `<fencedframe>` provides stricter isolation than `<iframe>`; the fenced frame cannot communicate with the embedder via postMessage, cannot access localStorage of its origin, and operates in a partitioned storage context. For clickjacking-against-fenced-frame, the attack surface is narrowed; the user's click still lands on the fenced-frame content, but the attacker's reward (reading state, extracting tokens) is limited.

## Drag-and-Drop Clickjacking at Depth

**Browser cross-origin DnD matrix**:
- `text/plain` drag payload: cross-origin DnD allowed in Chrome, Firefox, Safari
- `text/html` drag payload: cross-origin DnD restricted; the dragged HTML is sanitized or dropped
- `application/x-*` custom MIME types: cross-origin blocked in Chrome and Firefox; Safari varies
- `Files` DnD across origins: blocked in all modern browsers

**Attack recipe** (API-key capture via drag):
```html
<!-- attacker.evil.tld -->
<div draggable="true" ondragstart="event.dataTransfer.setData('text/plain', 'ATTACKER_API_KEY_HERE')">
  Drag me to the hoop!
</div>
<iframe src="https://target.tld/settings/api-keys" style="position:absolute; top:200px; left:200px; opacity:0.001"></iframe>
<!-- target's "paste API key" field is at (250, 240) absolute; the hoop sits over it -->
```
User drags the "ball"; the drop payload is attacker's text; the target's field receives the drop; if the field auto-saves or the form auto-submits, the attacker's API key is stored.

**Confirmation**: the target field's persisted value equals the attacker's drag payload; verify via a second principal reading the target's audit log or the field value in the UI.

**Reverse DnD — extraction**. The attacker's page drops ONTO the target iframe; if the target has a draggable element with user-specific data (session token, OAuth code, API key displayed in a copy-able text field), the attacker's drop handler can read the dragged content via `event.dataTransfer.getData()`. Cross-origin restrictions apply; the attacker gets what the browser allows.

**Clipboard interactions**. Modern DnD + clipboard interact via `document.execCommand('copy')` and the Clipboard API. A clickjacking variant: the user "clicks" a decoy that calls `navigator.clipboard.writeText(attackerText)`; the clipboard content changes without user intent; a subsequent paste delivers the attacker's text.

**Modern constraints**:
- Clipboard writes require transient user activation (click, keypress) in modern Chrome; a clickjacked click supplies that activation
- Clipboard reads require explicit permission; clickjacking cannot acquire the permission directly but can direct the user through a prompt

## Keyboard-Focus Redress

Primitive: the attacker's visible UI suggests typing into one place; keyboard focus is redirected to a hidden iframe field.

**Mechanisms**:
- `iframe.focus()` from the attacker's script places focus in the iframe; subsequent keystrokes target the iframe's focused element
- Layered elements with CSS: an element positioned over a visible field with `pointer-events: none` captures no focus; the hidden iframe field below receives focus
- Programmatic focus-steal via `requestFocus()` in some browsers (deprecated), `showPicker()` for date/color inputs

**Attack recipe**:
```javascript
// attacker page shows "Type the captcha into the box below"
const iframe = document.querySelector('iframe'); // hidden iframe with target password-change form
iframe.focus();
// user types; keystrokes reach iframe's focused password field
// the field is autofocused on a password-reset confirmation screen
// user "completes the captcha" by typing their new password
```

**Browser constraints**: cross-origin iframe focus is permitted; the focused element inside the iframe does not notify the top window of the focused element's identity (same-origin boundary preserved). The attack relies on predictable autofocus in the target.

**Confirmation**: the target field receives the attacker-chosen keystrokes; the state change (password set) fires with the victim's auth.

## CSS-Only Variants

**Pointer-events trickery**. CSS `pointer-events: none` on an overlay allows clicks to pass through to layers below. The pattern:
```css
.visible-decoy { pointer-events: none; z-index: 2; }
.hidden-action { pointer-events: auto; z-index: 1; }
```
User sees the decoy, clicks it; the click passes through to the hidden action layer. Within a single page (same origin), this is UI redress at the page level, not cross-origin — relevant when one tenant's content overlays another's in multi-tenant layouts.

**Hover-based reveal**. A hover event reveals an element (`:hover` CSS pseudoclass displays a hidden sibling); the user's mouse movement, intended to hover over a decoy, reveals an action element at the same pixel; the subsequent click lands on the revealed action.

**Transform-based position shift**. CSS `transform: translate()` can shift an element's rendered position without changing its layout flow; the attacker can position a target button where it is clicked by the user who intends to click a different, laid-out element.

**Opacity gradients**. Elements with `opacity: 0.001` are visually imperceptible but still interactable; a user clicking on what appears to be whitespace clicks the invisible element.

## Framework-Specific Exposure Patterns at Depth

### React / Vue / Angular / Svelte SPAs

- Single `index.html` shell + per-route components: headers must be on the shell response for every entry
- SSR frameworks (Next.js, Nuxt, Astro): per-route headers possible; verify configuration via `next.config.js` headers, Nuxt `routeRules`, Astro `response.headers`
- Component-level mutation state: a state-change action may be gated by a one-time setup step; clickjacking the setup step then the mutation step is a two-click composite
- Route-change pattern: SPAs navigate without full page reload; a single frame may host multiple route states; the pixel position of the state-change button may vary across route states

### Angular Universal (SSR)

- `TransferState` carries server state to the hydration layer; a clickjack during pre-hydration vs post-hydration may behave differently
- Angular's built-in CSRF (`HttpClientXsrfModule`) relies on a cookie-token read; iframe-contexted auth may not have the cookie; state-change POSTs may fail silently

### OAuth / OIDC Providers

- Keycloak default `frame-ancestors` behavior: realms set via admin UI; verify explicitly per realm — the `X-Frame-Options: SAMEORIGIN` default is overridable
- Auth0: `X-Frame-Options: DENY` by default on hosted login pages; the universal-login screen is non-framable
- Okta: `X-Frame-Options: DENY` by default on sign-in and consent screens
- Google / Microsoft / Apple: `frame-ancestors 'self'` or stricter on consent screens

### Payment Processors

- Stripe hosted checkout: `frame-ancestors` configurable per account; default disallows framing from non-registered merchant domains
- PayPal: hosted checkout non-framable; Smart Payment Buttons intentionally embeddable
- Adyen hosted checkout: frameable from registered merchant domains only

### Admin Consoles (Grafana, Prometheus, Jenkins, GitLab, GitHub, cloud consoles)

- Grafana `security_options` controls `frame_ancestors`; default varies by deployment
- Jenkins: `X-Frame-Options` configurable via `Jenkins.getFrameOptionsPolicy()`
- GitLab: `frame-ancestors` default varies by self-hosted vs hosted
- GitHub: strict framing restrictions on sensitive pages (settings, OAuth); public repository pages may be framable
- AWS / Azure / GCP consoles: `frame-ancestors 'self'` or stricter

### Embedded Analytics / Chat / Social Widgets

- Framable by design; the clickjacking concern is the widget's state changes (not the host page's)
- Widget-side defenses: user-interaction gates ("double-click to confirm"), transient-activation requirements

## Chained Exploitation at Depth

**Chain 1 — Open-redirect → Clickjacking delivery → OAuth consent capture**:
- Attacker uses `open_redirect` on a trusted site to deliver victim to attacker's framing page
- Attacker's page frames the OAuth consent screen for `attacker-app`
- User clicks the decoy; "Authorize" fires in iframe
- Attacker's OAuth app receives the code; token exchange yields victim's authority

**Chain 2 — Clickjacking → Email change → Password reset → Full ATO**:
- Victim's account settings page is framable (classic clickjacking)
- Decoy captures the "Change Email" submission with attacker email
- Attacker initiates password reset to the new email
- Password reset code arrives at attacker; account takeover

**Chain 3 — Drag-and-drop clickjacking → API key creation → Persistent access**:
- Target page has an "Add API key with scope X" form that accepts the scope as a form field
- Attacker's DnD payload delivers an attacker-chosen scope value
- The form auto-submits (or the user clicks the submit decoy)
- API key created with attacker's chosen scope; attacker reads the key from the response page via a follow-on primitive

**Chain 4 — Same-origin chain via XSS → Nested frame → SAMEORIGIN clickjacking**:
- Target permits `frame-ancestors 'self'`
- XSS in a target same-origin page (`xss`) provides an attacker-controllable same-origin frame source
- Attacker's cross-origin page frames the XSSable same-origin page which frames the target
- Three-layer composite with same-origin authority preserved

**Chain 5 — Keyboard-focus redress → Password change → Session fixation**:
- Target has a password-change form with autofocus on new-password field
- Attacker's page captures keyboard focus into the hidden target iframe
- User types their new "captcha" code which is actually set as their new password
- Attacker knows the password; session takeover

**Chain 6 — Subdomain-takeover feeding frame-ancestors → Legitimized framing**:
- Target CSP: `frame-ancestors https://*.trusted.tld`
- Attacker takes over `unused-service.trusted.tld` via `subdomain_takeover`
- Attacker's content on the subdomain frames the target; frame-ancestors matches
- Full clickjacking surface restored despite the deployment having "configured" frame-ancestors

## Fenced Frames and Permissions-Policy

**Fenced frames** (Chrome 2023+, moving to generally-available status through 2024–2026) provide a stricter containment than iframes:
- Cannot access storage of their origin (partitioned)
- Cannot postMessage to the embedder (no cross-origin channel)
- Cannot read URL parameters at embed time (opaque)
- Cannot access cookies of their origin (for FLEDGE/Protected Audience ads use case)

**Clickjacking surface against fenced frames**:
- The user's click still lands on the fenced-frame content; the primitive persists
- The attacker's reward is limited: no access to the fenced-frame's storage or cookies means less exfiltratable state
- Fenced frames remain cross-origin to the embedder; the user's cookies at the fenced-frame's origin still travel on load (subject to SameSite)
- Primary use case is ad-rendering; the state-change surface in fenced frames is deliberately minimized

**Permissions-Policy / Feature-Policy** (modern name: `Permissions-Policy`):
- Controls which capabilities (geolocation, camera, microphone, fullscreen, autoplay, payment) iframes can use
- Does NOT control framing per se; `frame-ancestors` remains the framing control
- Interaction with clickjacking: a page that permits `payment` in `Permissions-Policy` and is framable from attacker origin exposes the Payment Request API through clickjacking (`clickjacking → payment request → charge`)

**Clipboard-write permission policy**: in modern Chrome, `navigator.clipboard.writeText()` requires transient user activation; a clickjacked click supplies that activation. A deployment that reads clipboard content on load (previously allowed, now restricted) can be clickjacked into writing attacker-chosen content to the user's clipboard.

**Credential Management API** (`navigator.credentials.get()`): framable; a clickjacked user interaction can trigger a credential request that discloses stored credentials to the iframe.

**Confirmation**: for each capability enabled by Permissions-Policy and reachable via clickjacking, verify the specific primitive the user's click enables.

## Browser Enforcement Measurement

A deployment claim of "we set `X-Frame-Options` and `frame-ancestors`" is unverifiable without a browser-level test. Reproducible probes:

**Probe 1 — Simple framability test** (reproducible against any public target):
```html
<!doctype html>
<html>
<body>
<p>If the frame below renders, the target is framable from this origin.</p>
<iframe src="https://target.tld/" width="800" height="600"></iframe>
<script>
  // Browser reports frame load errors in console
  window.addEventListener('error', e => console.error('frame-load error:', e));
</script>
</body>
</html>
```
Open in Chrome, Firefox, Safari separately. The browsers' developer-console will log a specific error for frame-ancestors-blocked (`Refused to display 'https://target.tld/' in a frame because an ancestor violates the following Content Security Policy directive: "frame-ancestors …"`). Note the per-browser error wording.

**Probe 2 — Header-vs-browser audit**:
```bash
curl -sIL "https://target.tld/sensitive-action" | grep -iE 'x-frame-options|content-security-policy|strict-transport'
```
Compare the headers returned by curl to the frame-load behavior in the browser; a mismatch (headers claim DENY, frame loads) suggests reverse-proxy stripping between application and browser.

**Probe 3 — SameSite cookie behavior under framing**:
```bash
# 1. Log into target normally; capture Cookie
curl -c /tmp/jar "https://target.tld/login" -d 'u=…&p=…'
# 2. Inspect SameSite attribute
grep -i samesite /tmp/jar
# 3. In a fresh browser, log in; frame the state-change page from an attacker origin
# 4. Check DevTools Network panel: does the framed request include the auth cookie?
```
The pentester's confirmation is "DevTools shows the request fired WITH the auth cookie" (full clickjacking surface) vs "request fired WITHOUT the cookie" (SameSite=Strict/Lax defeats auth).

**Probe 4 — Modern browser frame-containment stacking**:
```javascript
// Inspect the top-level embedding context from inside the frame (where same-origin permits)
console.log('frameElement:', window.frameElement);  // null if cross-origin
console.log('top === self:', window.top === window.self);  // false if framed
try { console.log('top.location:', window.top.location); } catch(e) { console.log('top.location blocked:', e.message); }
```
This measures the actual browser-enforced isolation, which is the ground truth beyond the headers.

**Measured observation**: a deployment reporting `X-Frame-Options: SAMEORIGIN` + `Content-Security-Policy: frame-ancestors 'self' https://trusted.tld` renders framable from `https://trusted.tld` in Chrome, Firefox, and Safari — the compound `'self'` + explicit origin is honored. If `https://trusted.tld` is attacker-controllable (subdomain-takeover, user-content hosting, open-redirect to a framable path), the deployment is framable in practice.

## Tooling

- **Burp Suite Clickbandit** (built into Burp Suite Pro) — point-and-click clickjacking PoC generator. Captures the target page, lets you position decoy elements, generates the attacker HTML. Useful for rapid PoC assembly; the generated attack is a reference, not a comprehensive engagement
- **OWASP Burp Extension — Clickjacker** (community): grep-level reporting of pages missing `X-Frame-Options` and `frame-ancestors`
- **Nikto / Nuclei** (`-t http/misconfiguration/missing-frame-options`): grep-level discovery of missing-header surface at scale
- **BeEF** (Browser Exploitation Framework): module for clickjacking + hooked-browser post-exploitation; useful when you have a victim-reachable channel to deliver the frame
- **framebuster.py / anti-framebuster harnesses**: historical; relevant only when a legacy deployment uses JS frame-busting as a primary control
- **Chrome DevTools Security panel**: direct per-page frame-load status, CSP violation reporting, and security-origin inspection
- **Google Clickjacking Reporter** (`chrome://safe-browsing/`): built-in Chrome tooling for the specific user-reported class

Sandbox-trap note: `Clickbandit` and similar tools do not themselves fire the state change; they generate the PoC. Running the PoC against production without a dedicated test tenancy is the sandbox-trap concern. Confirm the test environment's authority before clicking a decoy that would delete an admin's record.

## Verification Discipline

- Reproduce the attack from a browser matching the deployment's user base; a Chrome-only attack must state "Chrome ≥N" explicitly, not generalize to "all browsers"
- The confirmation is the target's state change observable in the audit log under the victim's identity; a UI render of the overlay is not sufficient
- For OAuth clickjacking, confirm the attacker's app actually receives a code/token, not just the "Authorize" button click
- For drag-and-drop, verify the target field's persisted value equals the attacker payload; verify in a second session (post-close) that the state persisted
- For keyboard-focus, verify the final auth state is attacker-known, not just the keystrokes being redirected
- For same-origin-chain primitives, verify the chain holds across the full browser lifecycle (page reload, back-navigation, mid-session)
- Record the exact browser version, zoom level, window size, and OS where the attack reproduces; responsive layouts shift target positions and the finding is not universal

## Summary

Advanced clickjacking is about where the trust boundary breaks under modern defenses — the gaps in X-Frame-Options enforcement across browsers, the frame-ancestors edge cases (meta vs header, report-only, same-origin chain, subdomain takeover feeding allowlists), SameSite cookie partitioning quirks, nested-frame mechanics, drag-and-drop and keyboard-focus payload delivery, and the per-framework defaults that leave shells framable where application state is not. The classic class is well-defended on correctly configured deployments; the gap is in configuration completeness and the modern-browser-specific behaviors that legacy write-ups do not cover. For the structural "defense-irrelevant UI redress" frontier (DoubleClickjacking), load `clickjacking_novel_deep` — a separate class with distinct mechanics.
