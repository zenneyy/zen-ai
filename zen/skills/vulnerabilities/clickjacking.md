---
name: clickjacking
description: "UI-redress / clickjacking testing — classic iframe overlay, likejacking, cursorjacking, drag-and-drop, nested frames, keyboard UI redress, with X-Frame-Options, CSP frame-ancestors, and SameSite-cookie defense-enforcement discipline."
---

# Clickjacking (UI Redress)

Clickjacking is a trust-boundary failure between the user and the target origin: the target UI renders in a context where the user's click, drag, or keypress is captured by attacker UI chrome and delivered to the target as a legitimate interaction. The target application cannot distinguish "the user clicked Pay" from "the user clicked a decoy that was overlaid on Pay." Confirmation is the state-change the attack produces, not the overlay rendering.

The class covers iframe-based overlay, cursor repositioning (cursorjacking), drag-and-drop capture, keyboard-input redirection, and the "defense-irrelevant UI redress" variants (DoubleClickjacking) that bypass the classic defenses by not using an iframe at all. The modern defense stack — `X-Frame-Options`, CSP `frame-ancestors`, `SameSite` cookies — defeats the classic iframe-overlay class when correctly configured; the frontier (routed to `clickjacking_novel_deep`) is the primitives that bypass this stack structurally.

Load `clickjacking_advanced_deep` for differential/bypass depth, per-browser enforcement differences, nested-frame and shadow-DOM primitives, CSS-only variants, drag-and-drop depth, chained exploitation, and framework-specific exposure. Load `clickjacking_novel_deep` for the 2024–2026 primary-source frontier (DoubleClickjacking and the "defense-irrelevant UI redress" class). Overlapping surfaces route by filename: `cors_misconfiguration` owns cross-origin trust configuration generally; `csrf` owns the state-change invariant; `xss` owns the rendered-script sink; `browser_security` owns the broader site-isolation and frame-containment primitives.

## Attack Surface

**Iframe-embedded targets**
- Any URL that returns `200 OK` with no `X-Frame-Options` header AND no CSP `frame-ancestors` directive and that performs a state change on click, drag, keypress, or form submission

**OAuth consent screens**
- Authorization endpoints whose consent dialog can be framed, with the Authorize button at a predictable position

**Payment flows**
- One-click "Pay" / "Confirm Transaction" buttons on frameable pages

**Admin consoles**
- Role-change / permission-grant / delete-record / rotate-key buttons on frameable admin UIs

**Social actions**
- "Like," "Follow," "Share," "Add to Cart" — classic likejacking targets

**Settings mutations**
- Email change, 2FA disable, API key rotation, password change, session-active list clearing

**Download / install**
- Framed download links or auto-execute install buttons

## High-Value Targets

- Account-settings pages: email change, password change, 2FA disable, session management
- OAuth authorization: granting an attacker-registered client access to the victim's account
- Payment and transfer flows: one-click confirm with pre-filled attacker-chosen amount
- Role-grant / permission-change in admin UIs
- API key creation / rotation (if a key is generated and displayed in the frame, the attacker captures via overlay-reveal)
- Multi-user action flows that are irreversible (deletes, publishes, mass messages)

## Reconnaissance

### Frame-Containment Fingerprinting

- `curl -I <target>` — observe `X-Frame-Options`, CSP `frame-ancestors`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`
- `X-Frame-Options: DENY` → not framable at all
- `X-Frame-Options: SAMEORIGIN` → framable from same origin only
- `X-Frame-Options: ALLOW-FROM uri` → deprecated, inconsistent browser support; treat as unframable from arbitrary origins
- CSP `frame-ancestors 'none'` → not framable
- CSP `frame-ancestors 'self'` → same-origin framable
- CSP `frame-ancestors https://trusted.tld` → specific-origin framable
- Neither header present → structurally framable from any origin

**X-Frame-Options vs CSP frame-ancestors precedence**. Where both headers exist and disagree, `frame-ancestors` is normative in modern browsers (Chrome 40+, Firefox 33+, Safari 15.4+). `X-Frame-Options` remains honored as a fallback for older clients. A deployment that sends `X-Frame-Options: SAMEORIGIN` + `frame-ancestors https://evil.tld` is framable from `evil.tld` in modern browsers.

### Cookie Context Fingerprinting

- `SameSite=Strict` cookies are not sent on cross-origin iframe loads; a state-change requiring auth will not fire
- `SameSite=Lax` cookies are not sent on cross-origin iframe POSTs (and most state-changing requests); narrows the attack surface
- `SameSite=None; Secure` cookies ARE sent on cross-origin iframe loads; the classic clickjacking surface

### Target-Position Mapping

- Load the target in a frame; capture pixel coordinates of the state-change element
- Verify the target is reproducible pixel-position across browser window sizes (responsive layouts shift elements; a clickjacking attack must target a stable position)
- Confirm the target action is single-click (not multi-step wizard); multi-step raises reproducibility cost significantly

## Key Vulnerabilities

### Classic Clickjacking (Iframe Overlay)

Primitive: an iframe loads the target page; the attacker renders decoy UI (button, image, "play" overlay) at the same pixel position as the target's state-change element; the iframe is made invisible (`opacity: 0.001`) or layered behind the decoy with CSS `z-index`; the user clicks the decoy; the click lands on the target button.

**Preconditions**: (a) no `X-Frame-Options` / no CSP `frame-ancestors` restricting the attacker's origin; (b) the target endpoint accepts the state change on a single click; (c) the user's auth context is active (session cookie present, `SameSite` permissive); (d) the target button's pixel position is stable.

**Attack recipe**:
```html
<style>
  iframe { opacity: 0.001; position: absolute; top: 0; left: 0;
           width: 1000px; height: 800px; z-index: 2; }
  .decoy { position: absolute; top: 420px; left: 320px;
           width: 100px; height: 40px; z-index: 1; }
</style>
<div class="decoy">Click to win</div>
<iframe src="https://target.tld/account/delete"></iframe>
```
The iframe loads over the decoy; the target's "Delete Account" button sits at pixel (320, 420); the user sees "Click to win" and clicks; the click lands on the target.

**Confirmation**: the target state change fires (account deleted, email changed, OAuth authorized). The overlay rendering alone is not a finding; the invariant violation is.

**Impact**: full state change in the target's authority; depends on the specific button clicked.

### Likejacking

Primitive: classic clickjacking against a social-action button (`Like`, `Follow`, `Share`). Specific-target variant of the general class.

Confirmation: the target's social action fires visible on the victim's social-media feed, which is a secondary channel confirming the primitive.

### Cursorjacking

Primitive: CSS `cursor:` property or JS re-rendering displaces the visible cursor from its real position; the user sees the cursor on a decoy and clicks there, but the real click lands at a different position.

**Attack recipe** (CSS-based cursor spoof):
```html
<style>
  .fake-cursor-area {
    cursor: url('data:image/svg+xml;utf8,<svg...fake arrow at 50,100 offset.../>'), auto;
  }
</style>
<div class="fake-cursor-area">
  Click to continue... [visible target]
  <!-- real iframe target button sits 50px/100px offset -->
</div>
```

Modern browsers constrain custom-cursor positioning (max 128×128 image with hotspot inside the bounding box), narrowing but not eliminating cursorjacking. Current effective shape: subtle offsets within the allowed cursor region, not large relocations.

### Drag-and-Drop Clickjacking (DnD-jacking)

Primitive: the attacker page captures a drag from a visible decoy and routes the drop into a target iframe. The target UI accepts drag-and-drop input (file upload, text drop into a message, token drag into a config field) and treats the drop as user action.

**Attack recipe**:
1. Target page accepts drag-and-drop of text into a field (e.g., API key field)
2. Attacker page shows a "drag the ball to the hoop" game; the "ball" is a textContent-set element the drag starts from
3. The iframe target overlay places its drop target under the "hoop"
4. User drags from the attacker's game; the browser's drag payload carries the attacker-chosen text; the drop lands in the target field; the target form auto-submits or the field is persisted

**Confirmation**: the target field's value reflects the attacker's drag payload. Modern browser constraints (same-origin DnD restrictions) narrow but do not eliminate the class; cross-origin drag-and-drop remains partially permitted for text/plain content.

### Nested iframe / Shadow DOM Variants

Primitive: a target page's frame-ancestors policy permits same-origin framing but a vulnerability allows an attacker-controlled same-origin page to embed the frame. The attacker embeds via the vulnerable same-origin page, inheriting the SAMEORIGIN framability.

**Preconditions**: (a) target permits same-origin framing; (b) an attacker-controlled page exists on the same origin — via XSS, open-redirect, user-content hosting, or any mechanism that gives the attacker a same-origin page.

**Attack recipe**: the attacker's same-origin page frames the target; the attacker's page is itself framable from the attacker's cross-origin page; two-level framing delivers the clickjacking with same-origin credentials intact.

Shadow DOM variant: an attacker component inserted into a Shadow DOM slot can render over same-component content; where the target UI mounts framable content in Shadow DOM, the attacker's slot-content capture is a UI-redress primitive without a cross-origin iframe.

### Keyboard-Based UI Redress (Keyjacking)

Primitive: the attacker page captures keyboard focus; the target iframe receives the keystrokes as if the user typed into the target directly. The attacker's visible UI suggests typing into one field; the real keystrokes reach the target.

**Preconditions**: iframe not blocked; the target has a focusable element at the attack time; the browser's keyboard-focus delivery goes to the iframe based on explicit focus() or layered focus-stealing.

**Attack recipe**: attacker page shows a "type the captcha" prompt; the hidden iframe has focus on a password-change field; the user types their password-reset confirmation code or new password, which the target's form accepts.

### CSS-Only Clickjacking (Pointer-Events, Hover)

Primitive: no iframe; the attacker uses CSS `pointer-events` and layered elements on their own page to redirect clicks between the user's visible target and a hidden action element. Narrower surface — this does not reach a different origin — but applicable to attacker-controlled multi-tenant pages where one tenant's UI overlays another's content.

### Tab-Nabbing and Window-Focus Redress

Primitive: a user clicks a link that opens a new tab; the attacker's page in the opener uses `window.opener.location` to navigate the opener to a phishing page while the victim is focused on the new tab.

**Mitigation**: `rel="noopener"` on links; the modern default in major browsers for `target="_blank"` links treats them as implicitly `noopener`, closing this class. Confirm the target does not override the default back to legacy behavior.

## Defenses — Enforcement Discipline

### X-Frame-Options

Values and semantics:
- `DENY` — never framable; preferred for pages that have no legitimate framing use
- `SAMEORIGIN` — framable only from same origin
- `ALLOW-FROM uri` — framable from one specified origin; **deprecated**, inconsistent browser support (Chrome never implemented); treat as unframable in modern deployment

Common failure: `X-Frame-Options` set at the application layer but stripped by a reverse proxy; or set only on the main page but not on error/API/exception pages that may still be framable.

### CSP frame-ancestors

Normative framing control in modern browsers. Values:
- `'none'` — never framable
- `'self'` — same-origin framable
- `https://trusted.tld` (space-separated multi-origin list)
- `*` — framable from anywhere (reporting mode; never use in enforcement)

**Precedence**: `frame-ancestors` overrides `X-Frame-Options` where both are present. A target with `X-Frame-Options: DENY` and `frame-ancestors *` is framable from anywhere in modern browsers.

### SameSite Cookies

- `Strict` — not sent on any cross-site request including iframe loads; strongest defense but breaks legitimate cross-origin embedding
- `Lax` — not sent on cross-site POST/subresource (iframe load with POST does not carry the cookie); default for modern browsers absent an explicit attribute
- `None; Secure` — sent on cross-origin iframe loads; required for cross-origin embedding of authenticated features

**Chrome's default change (2020+)**: cookies default to `Lax` if no `SameSite` attribute is set, which closed many legacy classes. The pentester verifies the explicit attribute; default behavior may change again across browser versions.

### JavaScript Frame-Busting

Historical defense (page JS detects `top !== self` and attempts to break out). Bypassable: `sandbox="allow-scripts"` without `allow-top-navigation` prevents the busting script from navigating; HTML5 `<iframe sandbox>` neutralizes classic busting. Treat JS frame-busting as a defense-in-depth comment, not a primary control.

### User-Interaction Gates (Confirm Dialogs)

Confirm dialogs ("Are you sure you want to delete your account?") are UI-redress-attackable themselves. The attacker overlays a second decoy at the dialog's confirm position. Confirm dialogs are not clickjacking defenses; they are UX friction that occasionally reduces attack success but do not change the primitive.

## Framework-Specific

### Single-Page Applications (React / Vue / Angular / Svelte)

- SPAs often lack per-route headers because they ship a single HTML file for all routes; frame-ancestors must be set at the shell-HTML level
- Server-side-rendering (Next.js, Nuxt, Astro) can set per-route headers; verify the configuration includes `X-Frame-Options`/`frame-ancestors` on the shell response
- Hydration state restoration — the SPA's state-change action often fires after hydration; a frame-busting script that runs pre-hydration may be too early

### OAuth / OIDC Consent Screens

- Consent screens are high-value clickjacking targets (grant attacker-registered client access to victim's account)
- RFC 6749 does not mandate framing restrictions; current major providers (Google, Microsoft, Okta, Auth0) set `frame-ancestors 'self'` or `DENY` by default
- Self-hosted OAuth servers (Keycloak, Dex, Hydra, Zitadel) require explicit configuration; default varies by product
- Confirm the specific authorization endpoint, not just the login endpoint, has framing restrictions

### Payment Processors / Embedded Checkout

- Hosted payment pages (Stripe Checkout, PayPal, Adyen hosted) require specific framing configuration; the processor's hosted form is explicitly framable from the merchant's registered domain
- Embedded iframes for payment (Stripe Elements) are a different class — the processor's iframe is designed to be embedded; the clickjacking concern is on the merchant's page framing the processor

### Admin Consoles

- High-privilege actions (role grant, user delete, settings mutation) on admin UIs that lack framing restrictions
- SPA admin UIs commonly miss shell-level `frame-ancestors`

### Embedded Widgets (Chat, Analytics, Social)

- Framing-enabled by design; verify the widget's state changes are either (a) idempotent, (b) require a secondary action, or (c) authenticated via a token the clickjacker cannot reach

## Exploitation Scenarios

### Account-Takeover via OAuth Consent Clickjacking

1. Attacker registers an OAuth application `attacker-app` with scope `read:all write:all`
2. Attacker's page frames the authorization endpoint `https://provider.tld/oauth/authorize?client_id=attacker-app&...`
3. User clicks a decoy; the "Authorize" button is clicked under the hood
4. Attacker's app receives the OAuth code / access token with the victim's authority
5. Full account access

### State-Change Clickjacking → Email Change → Password Reset

1. Attacker frames the account-settings page; the "Change Email" form sits at a known position
2. Decoy captures the user's click submitting an attacker email
3. Attacker initiates a password reset to the new email
4. Account takeover

### Multi-Click Composite via Drag-and-Drop

1. Target page has a two-step mutation: field edit + confirm button
2. Attacker's game captures a drag (fills the field with attacker-chosen text) and a click (presses confirm)
3. The composite requires two independent user actions; the game design is more elaborate but the attack is still feasible

## Confirmation and Validation Discipline

- The target's state change is the finding, not the overlay. "The page framed" is the primitive; "the state changed in the victim's account" is the finding.
- Verify from a non-attacker principal: the attack page served from `evil.tld`, the victim logged in to `target.tld`, the state change observable in the target's audit log under the victim's identity.
- Pixel positioning is reproducible only in a specific browser version / zoom level / responsive layout; the finding reproduces across the deployment's typical user environment, not just the attacker's reference.
- For OAuth consent clickjacking, confirm the resulting token/code reaches attacker control; the UI showing "Authorize" alone is not the finding.

## Chaining and Routing

Upstream:
- Open-redirect primitive used to deliver the victim to the attacker's framing page → `open_redirect`
- XSS on the target's own origin enabling same-origin framing → `xss`

Downstream:
- CSRF-shape state changes clickjacked without needing to break CORS → `csrf.md § Reconnaissance` for the two-skill boundary
- Credential capture via drag-and-drop payloads → general UI exfil
- OAuth client-registration → full account access with persistent token

Composite chains:
- Clickjacking → OAuth consent → token issuance → `authentication_jwt_novel_deep.md § Token-Exchange Primitives` for the token-side exploitation
- Clickjacking → email change → password reset → `authentication_jwt` for the auth-recovery primitive
- Clickjacking → settings mutation → persistent back-door

Note: CORS misconfiguration enables a different cross-origin read class (`cors_misconfiguration`); clickjacking is cross-origin write. Both are state-change / cross-origin primitives but with distinct mechanics and defenses.

## Testing Methodology

1. **Header fingerprint** — `curl -I <target>`; parse `X-Frame-Options`, CSP `frame-ancestors`, Cookie `SameSite` for every state-change endpoint
2. **Framability probe** — load the target in `<iframe src="target.tld">` from an attacker origin; observe whether it renders
3. **Pixel-position map** — identify state-change elements and their reproducibility
4. **Build the overlay** — invisible iframe + decoy UI; verify the click lands on the target
5. **State-change confirmation** — reproduce from a victim account; verify the audit log attribution
6. **SameSite cookie behavior** — verify the auth context survives the cross-origin iframe load
7. **Drag-and-drop probe** — if the target accepts drops, test cross-origin drag payload delivery
8. **Keyboard-focus probe** — if the target has focusable fields, test keystroke redirection
9. **Modern-defense bypass check** — test for same-origin-chain primitives, Shadow-DOM variants, and (for the novel tier) the DoubleClickjacking class routed to `clickjacking_novel_deep`

## Validation

1. State the state-change invariant the clickjacking violates ("admin UI should only mutate role on explicit admin click")
2. Reproduce the attack from a victim's authenticated session, with the attacker page served from a cross-origin host
3. Capture the target's audit log entry attributing the action to the victim
4. For OAuth clickjacking, capture the issued token at the attacker's endpoint
5. Record browser version(s) that reproduce the attack; modern browser defaults may deviate from legacy behavior

## False Positives

- Target returns `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`: not clickjackable
- Target's state change requires a confirmation token in a URL the attacker does not control: the one-click primitive does not fire
- `SameSite=Strict` cookies on the auth session: cross-origin iframe does not carry auth; the state change does not fire with the victim's authority
- Target rendering as a frame but the pixel-position of the state-change element is not reproducible: the attack is not operational
- Overlay rendering alone with no invariant violation: safety finding, not security finding

## Impact

- Account takeover via OAuth consent capture, email change, password reset
- Settings mutation (2FA disable, API key creation, session invalidation)
- Role / permission escalation on admin UIs
- Payment / transfer confirmation under the victim's authority
- Reputational / policy-violating social actions attributed to the victim

## Pro Tips

1. The pixel-position-stability check is often the attack's hardest step; responsive layouts shift elements and a working overlay in one window size may not reproduce in another
2. `frame-ancestors` takes precedence over `X-Frame-Options`; test the composite enforcement in modern browsers, not just the headers
3. `SameSite` behavior changed in 2020+ (Chrome default to `Lax`); older write-ups assume cookies always travel cross-origin which is no longer the case
4. OAuth consent screens remain high-value even on modern deployments where other UI is well-defended; test these explicitly
5. The novel-tier frontier is DoubleClickjacking (window-swap during double-click, bypasses the three primary defenses structurally) — load `clickjacking_novel_deep` when the deployment's classic defenses look complete
6. Drag-and-drop and keyboard-focus variants are under-tested; include them in a thorough review
7. The confirmation is the state change in the target's authority, not the overlay — a clickjacking write-up without an audit-log entry under the victim's identity is not a finding

## Summary

Clickjacking is the user-click trust-boundary failure: the target cannot distinguish an attacker-overlaid interaction from a legitimate one. The classic defenses (`X-Frame-Options`, CSP `frame-ancestors`, `SameSite` cookies) defeat the iframe-overlay class when correctly configured; the frontier is primitives like DoubleClickjacking that bypass the stack structurally by not using an iframe at all. For differential/bypass depth, load `clickjacking_advanced_deep`; for the 2024–2026 published frontier, load `clickjacking_novel_deep`. State-change clickjacking downstream routes to the specific class of state change — payment, OAuth, settings — by filename pointer.
