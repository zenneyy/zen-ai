---
name: application-enumeration-client-deep
description: Advanced client-side and modern JavaScript ecosystem enumeration. Loaded automatically by deep scan mode as a companion to application_enumeration.md. Covers Web Workers, Service Workers, WebAssembly module enumeration, PostMessage handler discovery, module federation (host and remote), monorepo runtime patterns (Turborepo, Nx, PNPM workspaces), micro-frontend orchestrators, feature-flag-driven route discovery, source map reconstruction, bundle obfuscation reversal, and 2024-2026 bundler ecosystem patterns (Vite, esbuild, Turbopack, Bun bundler).
sibling: application_enumeration
load_when: scan_mode == "deep"
---

# Application Enumeration — Client-Side & JS Ecosystem (Deep)

This is the deep sibling to `application_enumeration` for the client-side attack surface — the code that ships to the browser and the modern JavaScript ecosystem it runs in. The base file mines JS bundles for endpoint strings; this file goes to the layer under that: the Service Worker that caches and rewrites requests, the Web Worker that holds business logic, the WebAssembly module that hides key derivation, the `postMessage` handler that trusts any origin, the module-federation remote loaded from another host, the feature flag that gates a whole route, and the source map that reconstructs the original TypeScript.

It loads only in deep scan mode. Its sibling `application_enumeration_api_deep` owns the *server-side* API surface (REST/GraphQL/gRPC/WebSocket/WebRTC signaling) — this file does not re-enumerate protocols; it discovers the *client* that speaks them. `application_enumeration_auth_multiservice_deep` owns OAuth/OIDC/SAML/WebAuthn and multi-service/AI-endpoint depth — feature-flag/cohort work here stops at flag-name and route discovery and points there for the auth of independently-deployed micro-frontends.

The method: fingerprint the bundler and framework first (they dictate where routes, workers, and federation config live), then extract the client's full runtime — workers, WASM, federation remotes, feature flags — and reconstruct source where maps or unpackers allow. Bundler/framework patterns and tool syntax verified 2026-09-13; where a framework moved recently (Turbopack default, React Server Actions, Module Federation 2.0), the current form is given. Never replay a token, session, or key recovered from a bundle, worker, or WASM module — record its presence, location, and scope only.

## Web Workers and Service Workers

Workers run code off the main thread with their own script, message API, and (for Service Workers) network interception — a surface the base bundle scan walks right past.

### Service Worker registration discovery

**Pattern**: `navigator.serviceWorker.register('<url>'[,{scope}])` in a bundle; the SW script is commonly `/sw.js`, `/service-worker.js`, `/ngsw-worker.js` (Angular), `/firebase-messaging-sw.js`, `/workbox-*.js`, or a hashed `/sw-<hash>.js`.

```bash
grep -rhoE "serviceWorker\.register\(['\"][^'\"]+|/(sw|service-worker|ngsw-worker|firebase-messaging-sw)\.js" bundles/ | sort -u
for p in /sw.js /service-worker.js /ngsw-worker.js /firebase-messaging-sw.js /serviceworker.js; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
```

**Confirm**: a `200` on the SW path returns readable JS (SWs are not usually minified as hard as app bundles). At runtime, Chrome DevTools → Application → Service Workers lists the registered SW, scope, and status.

**Gotcha**: the SW `scope` determines which requests it controls — a SW registered at `/` intercepts the whole origin; a `Service-Worker-Allowed` response header can widen scope above the script's own path. Read the SW source (below) as a route and cache map the app never links.

### Service Worker lifecycle and update surface

The SW lifecycle (`install` → `waiting` → `activate`) is scriptable and leaks intent: `self.skipWaiting()` forces immediate takeover, `clients.claim()` grabs open tabs, `self.registration.update()` re-fetches the script.

```bash
curl -s https://<target>/sw.js | grep -oE "(skipWaiting|clients\.claim|addEventListener\('(install|activate|message)'|registration\.update)\(" | sort -u
```

**Gotcha**: a SW that calls `skipWaiting()`+`clients.claim()` updates aggressively — a poisoned SW script (served once through any cache/CDN weakness) persists and controls the origin until manually unregistered; note SWs whose update path is cache-controllable as a persistence lead.

### Workbox routing strategies

Workbox (Google's SW toolkit) declares routes with explicit caching strategies — each `registerRoute` names a URL pattern and how it is cached.

```bash
curl -s https://<target>/sw.js | grep -oE "registerRoute\([^)]*|(NetworkFirst|CacheFirst|StaleWhileRevalidate|NetworkOnly|CacheOnly)|__WB_MANIFEST" | sort -u
```

**Gotcha**: `registerRoute` patterns enumerate the API and asset URL shapes the app fetches; a `StaleWhileRevalidate`/`CacheFirst` route on an authenticated endpoint means responses sit in Cache Storage (data-at-rest), and the embedded `self.__WB_MANIFEST` precache array (`{url,revision}` per asset) is a complete static-asset inventory with content revisions — extract it verbatim.

### Service Worker fetch-handler enumeration

The SW's `fetch` handler (`self.addEventListener('fetch', ...)`) names the routes it special-cases — API paths, cache-first assets, offline fallbacks, request rewrites.

```bash
curl -s https://<target>/sw.js | grep -oE "(fetch|match|caches\.open|new Request|respondWith)\([^)]*|/[a-z0-9/_-]+" | sort -u
```

**Gotcha**: a `fetch` handler that rewrites request URLs or injects headers is an in-browser proxy — read exactly what it rewrites; navigation preload (`self.registration.navigationPreload.enable()`) and offline fallback routes reveal endpoints the app hits only on cold start or offline.

### Service Worker cache enumeration

`caches.keys()` names the Cache Storage buckets; their contents often include API responses cached for offline mode.

```javascript
// browser console (or Playwright): enumerate caches and their cached request URLs
for (const k of await caches.keys()) { console.log(k, (await (await caches.open(k)).keys()).map(r=>r.url)); }
```

**Gotcha**: cached API responses persist in Cache Storage across sessions — a cache that holds authenticated `/api/*` responses is a client-side data-at-rest exposure, and its keys enumerate endpoints the SW has fetched; diff the cached bodies across roles.

### Angular Service Worker (ngsw)

Angular's SW is configured by `ngsw-config.json` (build input) and served as `ngsw.json` (runtime manifest) alongside `ngsw-worker.js`.

```bash
curl -s https://<target>/ngsw.json | jq '{index,assetGroups:[.assetGroups[].name],dataGroups:[.dataGroups[]?.name],hashTable:(.hashTable|keys|length)}' 2>/dev/null
```

**Gotcha**: `ngsw.json` `dataGroups` enumerate the API URL patterns Angular caches (with freshness/performance strategies), and its `hashTable` lists every hashed asset URL with its content hash — a full asset manifest and API-shape list in one authenticated-cache-aware file.

### Push and Background Sync surface

**Signals**: `pushManager.subscribe({applicationServerKey})` (VAPID public key), `registration.sync.register('<tag>')` (Background Sync), `registration.periodicSync.register('<tag>', {...})` (Periodic Background Sync).

```bash
grep -rhoE "(pushManager\.subscribe|applicationServerKey|sync\.register|periodicSync\.register)\(['\"]?[^)]*" bundles/ sw.js 2>/dev/null | sort -u
```

**Gotcha**: Background-Sync/Periodic-Sync tags name endpoints the app calls on connectivity restore / on schedule — endpoints that never fire during a normal crawl; the VAPID `applicationServerKey` identifies the push backend.

### Firebase Cloud Messaging integration

`firebase-messaging-sw.js` embeds `firebase.initializeApp({...})` with `messagingSenderId`, `projectId`, `apiKey`, `appId`.

```bash
curl -s https://<target>/firebase-messaging-sw.js | grep -oE '"(messagingSenderId|projectId|apiKey|appId|storageBucket)":\s*"[^"]+"'
```

**Gotcha**: the FCM config leaks the Firebase project — cross to `firebase` for auth/rules abuse and to `asset_discovery_saas_deep`/`_cloud_deep` for the project footprint; the `apiKey` here is public by design, the finding is what the project's rules allow.

### Web Workers and Shared Workers

**Signals**: `new Worker('<url>'[,{type:'module'}])`, `new SharedWorker('<url>')`; worker scripts at `/worker.js`, `/*.worker.js`, `/assets/*-worker-*.js`. A blob worker (`new Worker(URL.createObjectURL(blob))`) hides the script inline.

```bash
grep -rhoE "new (Shared)?Worker\(['\"][^'\"]+|[a-zA-Z0-9_-]+\.worker(\.[a-z0-9]+)?\.js" bundles/ | sort -u
# once a worker URL is known, read it and enumerate its message API
curl -s https://<target>/main.worker.js | grep -oE "(onmessage|addEventListener\('message'|case ['\"][a-z_]+['\"]|type ===? ['\"][a-z_]+['\"])" | sort -u
```

**Gotcha**: workers frequently hold business logic and API keys the main bundle delegates to them, and a worker whose `onmessage` dispatches on a `{type,...}` field is a **direct message-injection surface** — `worker.postMessage({type:"fetch",url:"..."})` may drive it to fetch/compute on your behalf; a SharedWorker also leaks cross-tab state and survives after the spawning tab closes.

### Worker script dependencies (importScripts)

Classic workers pull extra code via `importScripts('<url>', ...)`; module workers use `import` inside the worker.

```bash
grep -rhoE "importScripts\(['\"][^)]*|import\s+[^;]+from\s*['\"][^'\"]+" main.worker.js sw.js 2>/dev/null | sort -u
```

**Gotcha**: `importScripts` fetches and runs remote code inside the worker with no SRI — a same-origin or CDN script pulled here is a supply-chain and a further-endpoint lead; follow each imported URL as its own script to mine.

### Worklets (Paint, Audio, Layout, CSS Houdini)

Worklets are lightweight isolated JS contexts: `CSS.paintWorklet.addModule('<url>')`, `audioContext.audioWorklet.addModule('<url>')`, `CSS.layoutWorklet.addModule('<url>')`.

```bash
grep -rhoE "(paintWorklet|audioWorklet|layoutWorklet|animationWorklet)\.addModule\(['\"][^'\"]+" bundles/ | sort -u
```

**Gotcha**: worklet module URLs are additional scripts that run in a distinct context and are commonly overlooked; an audio worklet in particular can process media buffers off-thread — pull each module URL and mine it like any other worker script.

### Comlink and worker RPC

Many apps front workers with an RPC layer (Google's `Comlink`) so the main thread calls worker methods like local functions: `Comlink.wrap(worker)` on the main side, `Comlink.expose(api)` inside the worker.

```bash
grep -rhoE "Comlink\.(wrap|expose|proxy|transfer)\(|__comlink|@?workerize" bundles/ *.worker.js 2>/dev/null | sort -u
```

**Gotcha**: `Comlink.expose(api)` publishes the worker's entire `api` object as a callable surface — read the exposed object to enumerate every remotely-invokable method and its arguments; those methods (file access, network, compute) are drivable from the page and, via a message-injection bug, from an attacker.

## WebAssembly Modules

WASM ships compiled logic the JS-focused scan cannot read — reverse it to recover algorithms, imports/exports, and embedded strings.

### WASM discovery

**Signals**: `.wasm` files served (`/wasm/`, `/assets/*.wasm`, `/_framework/*.wasm`), `WebAssembly.instantiateStreaming(fetch('<url>'))` / `WebAssembly.instantiate` / `WebAssembly.compileStreaming` in JS.

```bash
grep -rhoE "WebAssembly\.(instantiate|compile)(Streaming)?\(|['\"][^'\"]+\.wasm['\"]" bundles/ | sort -u
curl -s https://<target>/assets/app.wasm -o app.wasm && file app.wasm   # "WebAssembly (wasm) binary module"
```

**Gotcha**: a `.wasm` is compiled from Rust/C/Go/AssemblyScript/.NET — always pull it; JS-only recon skips the exact logic (crypto, license checks, parsers) the developers moved into WASM to hide.

### WASM disassembly and decompilation

```bash
wasm2wat app.wasm -o app.wat            # WAT text: imports, exports, functions (wabt)
wasm-objdump -x app.wasm | grep -A50 -E '^(Import|Export)'   # imports/exports section
wasm-decompile app.wasm -o app.dcmp     # C-like reconstruction (wabt)
wasm-tools print app.wasm | head -50    # bytecodealliance wasm-tools (newer suite)
```

**Gotcha**: the **import** section names what the module depends on (DOM bindings, `crypto`, custom JS glue), and the **export** section is the module's callable API — you can invoke exported functions directly from the JS console against the instantiated module.

### Runtime memory and toolchain fingerprint

At runtime, `new Uint8Array(wasmInstance.exports.memory.buffer)` exposes the linear memory (strings, structs, key material). Toolchain tells: `wasm-bindgen` glue + `__wbindgen_*` imports → **Rust**; `_gojs`/`runtime.` symbols and a large binary → **Go**; `~lib/` imports → **AssemblyScript**; `env.emscripten_*`/`env.__cxa_*` → **Emscripten/C/C++**.

```bash
wasm-objdump -x app.wasm | grep -oE '__wbindgen_[a-z_]+|_gojs|~lib/|emscripten_[a-z_]+|__cxa_' | sort -u
```

**Gotcha**: the toolchain narrows the source language and thus the decompilation approach — and the memory buffer at runtime frequently holds decrypted strings the static `.wasm` obfuscates; snapshot memory after key operations.

### Rust / wasm-bindgen modules

**Pattern**: a `*_bg.wasm` binary paired with a `*.js` glue file full of `__wbindgen_*` and `__wbg_*` functions; `wasm-pack`/`wasm-bindgen` output.

```bash
grep -oE "__wbg_[a-z0-9_]+|__wbindgen_[a-z_]+|wasm_bindgen" app.js | sort -u | head
```

**Gotcha**: the JS glue maps Rust structs and methods to JS — read the glue to recover the exported Rust API (function names, argument shapes) without disassembling; the glue is far more readable than the `.wasm` and names every callable entry point.

### Go WebAssembly modules

**Pattern**: a large `.wasm` plus `wasm_exec.js` (the Go runtime shim) and a `Go` global; `new Go(); WebAssembly.instantiate(..., go.importObject)`.

```bash
grep -rhoE "wasm_exec\.js|new Go\(\)|go\.importObject" bundles/ *.html 2>/dev/null | sort -u
strings app.wasm | grep -E 'main\.|/go/src/|\.go:' | sort -u | head   # un-stripped Go symbols/paths
```

**Gotcha**: Go WASM embeds the full Go runtime and, frequently, un-stripped symbol names — the `strings` pull recovers package/function names and source paths that map the internal package layout; the binary is large because the whole runtime ships.

### Emscripten (C/C++) modules

**Pattern**: a `.wasm` plus a generated `.js` glue exposing a `Module` object, `ccall`/`cwrap`, `_malloc`/`_free`, and `HEAP8`/`HEAPU8` typed-array views over memory.

```bash
grep -oE "\b(ccall|cwrap|_malloc|HEAPU?8|Module\.[a-zA-Z_]+)\b" app.js | sort -u | head
```

**Gotcha**: `cwrap`/`ccall` in the glue name the exported C functions and their signatures — call them directly from the console; `Module.FS` (Emscripten's virtual filesystem) can hold embedded files the app ships inside the module.

### WASI and the component model

Newer modules target WASI (`wasi_snapshot_preview1` imports) or the component model (`*.component.wasm`); component tooling is still stabilizing (2024-2026).

```bash
wasm-objdump -x app.wasm | grep -iE 'wasi_snapshot|component' | sort -u
wasm-tools component wit app.wasm 2>/dev/null   # extract WIT interface if it's a component
```

**Gotcha**: a WASI module expects host-provided syscalls (fs/clock/random) — its imports reveal what host capabilities it assumes; component-model modules carry a WIT interface describing their typed API — extract it for a clean surface map.

### WASM in workers and threaded modules

WASM is frequently instantiated *inside* a worker (off-thread compute) or built with threads — Emscripten `-pthread`/Rust `wasm-bindgen-rayon` use `SharedArrayBuffer` + a worker pool, which requires COOP/COEP cross-origin isolation.

```bash
grep -rhoE "PTHREAD_POOL_SIZE|wasm-bindgen-rayon|SharedArrayBuffer|new Worker\([^)]*wasm|instantiateStreaming" bundles/ *.worker.js 2>/dev/null | sort -u
curl -sI https://<target>/ | grep -iE '^cross-origin-(opener|embedder)-policy:'   # isolation required for threaded WASM
```

**Gotcha**: a `.wasm` loaded inside a worker is invisible to a main-thread-only crawl — enumerate worker scripts first (above), then look for the WASM instantiate inside them; the presence of `SharedArrayBuffer`+COOP/COEP confirms threaded WASM and a shared-memory surface to inspect at runtime.

### Blazor WebAssembly (.NET)

**Pattern** (verified): `_framework/blazor.webassembly.js` bootstraps; `_framework/blazor.boot.json` is the manifest listing every assembly; `_framework/dotnet.wasm` is the runtime; the app's `.dll`/`.wasm`-packed assemblies sit under `_framework/`.

```bash
curl -s https://<target>/_framework/blazor.boot.json | jq -r '.resources.assembly? // .resources.coreAssembly? | keys[]' 2>/dev/null
```

**Gotcha**: `blazor.boot.json` enumerates the entire .NET assembly set — download the `.dll`s and decompile with ILSpy/dnSpy/`ilspycmd` to recover the full C# app (controllers, models, embedded config, connection strings), the closest thing to source you'll get client-side.

## PostMessage Handlers

`postMessage` is cross-context IPC; a handler that skips origin validation is one of the most-underestimated client bugs.

### Handler discovery and origin validation

```bash
grep -rhnE "addEventListener\(\s*['\"]message['\"]|onmessage\s*=" bundles/ | sort -u
# for each handler, check for an origin guard nearby
grep -rhnE "e(vent)?\.origin\s*(===?|!==?|\.(indexOf|includes|match|startsWith|endsWith))" bundles/ | sort -u
```

**Gotcha**: a `message` handler with **no** `event.origin` check accepts messages from any embedding origin; trace what the handler does with `event.data` (navigation, `eval`, DOM write, token relay) — this is the DOM-XSS/token-theft surface (route to `xss`).

### Origin-validation bypass patterns

When a guard exists, it is frequently defeatable. Common weak forms and why they fail:

- `origin.indexOf('trusted.com') !== -1` → matches `trusted.com.evil.com` and `evil.com/?x=trusted.com`.
- `origin.endsWith('trusted.com')` → matches `nottrusted.com`.
- `origin.startsWith('https://trusted')` → matches `https://trusted.evil.com`.
- regex without `^`/`$` anchors, or with an unescaped `.` → over-matches.
- allow-list built from `document.referrer` or a `postMessage`-supplied value → attacker-controlled.

```bash
grep -rhnE "\.(indexOf|includes|search)\(['\"][^'\"]*\.[a-z]{2,}['\"]|new RegExp\(|origin\.match\(" bundles/ | sort -u
```

**Gotcha**: report the exact comparison — a substring/suffix/prefix check or an unanchored regex is a bypassable origin guard, functionally equivalent to no guard for the data-flow that follows.

### Adjacent cross-context sinks

`postMessage` is not the only cross-context channel — the same trust bugs appear on:

- `window.name` (survives cross-origin navigation, attacker-writable before redirect)
- `hashchange`/`location.hash` handlers (fragment is not sent to the server; classic DOM-XSS source)
- `storage` events (`addEventListener('storage')`) driven by another same-origin tab
- `document.referrer`-driven logic

```bash
grep -rhnE "addEventListener\(['\"](hashchange|storage|popstate)['\"]|window\.name|location\.hash|document\.referrer" bundles/ | sort -u
```

**Gotcha**: fragment (`location.hash`) and `window.name` are attacker-controllable client-side inputs the server never sees — a sink that writes either to the DOM or into `eval`/`Function` is DOM-XSS regardless of server-side controls.

### Framing, opener, and cross-origin isolation

- **iframes**: `<iframe src>` in the app — parent↔iframe `postMessage` often lacks origin validation both ways.
- **`window.opener`**: `target="_blank"` without `rel="noopener"` lets the opened page navigate the opener (reverse tabnabbing).
- **Cross-origin isolation**: `SharedArrayBuffer` requires `Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy: require-corp`.

```bash
grep -rhoE "target=['\"]_blank['\"]|rel=['\"][^'\"]*noopener|SharedArrayBuffer|<iframe[^>]+src=" bundles/ *.html 2>/dev/null | sort -u
curl -sI https://<target>/ | grep -iE '^cross-origin-(opener|embedder|resource)-policy:'
```

**Gotcha**: missing `noopener` on external `_blank` links is reverse-tabnabbing; absent COOP/COEP means no cross-origin isolation — but the higher-frequency finding is the unvalidated iframe `postMessage` bridge.

### Broadcast, MessageChannel, and custom-element bridges

**Signals**: `new BroadcastChannel('<name>')` (cross-tab), `new MessageChannel()` (port-based), custom-element events bridged to `postMessage`.

```bash
grep -rhoE "new BroadcastChannel\(['\"][^'\"]+|new MessageChannel\(|customElements\.define\(['\"][^'\"]+" bundles/ | sort -u
```

**Gotcha**: a `BroadcastChannel` name is a cross-tab bus — messages posted to it reach every same-origin tab; if a handler on that channel performs privileged actions, another tab (or an injected script) can drive it.

## Module Federation and Micro-Frontends

Module Federation loads code from *other* hosts at runtime; the remotes are separate deployments with their own (often weaker) auth and their own surface.

### Host detection and remoteEntry discovery

**Signals**: `remoteEntry.js` (Webpack MF 1.x) or `mf-manifest.json` (MF 2.0) URLs; `__webpack_require__.federation`, `webpackChunk`, `__webpack_share_scopes__` globals.

```bash
grep -rhoE "[a-z0-9._/-]*remoteEntry\.js|mf-manifest\.json|__webpack_require__\.federation|__webpack_share_scopes__|federationContainerName" bundles/ | sort -u
```

**Gotcha**: each unique `remoteEntry.js`/`mf-manifest.json` host is a **separate remote deployment** — its own origin, CDN, and frequently its own (or missing) auth; enumerate every remote host, not just the shell app's origin.

### Remote enumeration (MF 1.x vs 2.0)

MF 1.x: a `remoteEntry.js` defines a container exposing `init(shareScope)` and `get('./Module')`. MF 2.0: `mf-manifest.json` lists `exposes`, `remotes`, `shared`, and chunks directly, and `@module-federation/runtime`'s `loadRemote('<remote>/<module>')` loads them without a build plugin.

```bash
# MF 2.0 manifest lists exposed modules outright
curl -s https://<remote-host>/mf-manifest.json | jq '{name,exposes:[.exposes[].path],remotes:[.remotes[].federationContainerName],shared:[.shared[].name]}' 2>/dev/null
# MF 1.x: load the container in a browser/Playwright and read its module map
#   const c = await import('https://<remote>/remoteEntry.js'); await c.init({}); c.get('./exposedModule')
```

**Gotcha**: `mf-manifest.json` (MF 2.0) enumerates every exposed module, every downstream remote, and the shared-dependency versions in one file — a complete federation graph. For 1.x, the container's `get()` returns the actual module code for any exposed name (enumerate names from the shell's `remotes` config).

### Vite plugin federation

**Pattern**: `@originjs/vite-plugin-federation` ships an ESM `remoteEntry.js` with `__federation_*` helpers (`__federation_method_getRemote`, `__federation_shared`).

```bash
curl -s https://<remote-host>/assets/remoteEntry.js | grep -oE "__federation_[a-zA-Z_]+|\./[A-Za-z0-9_]+" | sort -u
```

**Gotcha**: Vite federation exposes are ESM dynamic imports — the `remoteEntry.js` names each exposed module path; the shared-scope logic differs from Webpack's but the exposed-module enumeration is the same goal.

### Angular Native Federation

**Pattern**: `@angular-architects/native-federation` uses browser-native import maps + ESM rather than Webpack; the manifest is `remoteEntry.json` and a `federation.manifest.json` maps remote names → URLs.

```bash
curl -s https://<target>/federation.manifest.json 2>/dev/null | jq .
curl -s https://<remote-host>/remoteEntry.json | jq '{name,exposes,shared:[.shared[]?.packageName]}' 2>/dev/null
```

**Gotcha**: Native Federation publishes its remotes through an import map in the shell's HTML — read `<script type="importmap">` to get every remote URL; the `remoteEntry.json` then lists each remote's exposed modules.

### Dynamic and runtime-registered remotes

Remotes are often registered at runtime from config, not baked into the build — a remotes list fetched from an API, an env-injected URL, or `registerRemotes([...])`/`loadRemote(url)` calls.

```bash
grep -rhoE "registerRemotes\(|loadRemote\(['\"][^'\"]+|remotes\s*:\s*\{|__FEDERATION__|window\.__mf" bundles/ | sort -u
for p in /config/remotes.json /assets/config.json /federation.config.json /api/mfe/config; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
```

**Gotcha**: a runtime remotes config fetched from an endpoint is the authoritative live federation map (dev/staging remotes sometimes leak in here) — and if that config URL is writable or the remote URL is derived from user/tenant input, it is a remote-code-injection path (attacker-hosted `remoteEntry` loaded and executed by the shell).

### Rspack and Webpack federation runtime

Rspack (the Rust webpack-compatible bundler) ships Module Federation 2.0 natively; both it and Webpack emit a federation *runtime* chunk that lists share scopes and remote wiring even when the manifest is absent.

```bash
grep -rhoE "rspack|__rspack_require__|__webpack_require__\.federation|initSharing|shareScopeMap|__webpack_require__\.S" bundles/ | sort -u
```

**Gotcha**: the federation runtime chunk (`__webpack_require__.federation`/`initSharing`/`__webpack_require__.S`) enumerates the share-scope keys and remote container names in code — recover the federation graph from the runtime even when `mf-manifest.json` is not served; Rspack output is webpack-compatible, so the same greps apply.

### Shared dependencies and import maps

MF's `shared` config lists shared libraries and versions across the host/remote boundary; native ESM federation uses `<script type="importmap">`.

```bash
grep -rhoE '<script[^>]*type=["'"'"']importmap' bundles/ *.html 2>/dev/null
curl -s https://<target>/ | grep -A80 'type="importmap"' | grep -oE '"[^"]+":\s*"[^"]+"'
```

**Gotcha**: a shared dependency pinned to a **vulnerable version** across the whole federation is one finding that hits every micro-frontend; the import map reveals the exact module-resolution targets (a bare specifier remapped to an attacker-influenceable URL is a supply-chain lead).

### Micro-frontend orchestrators and registries

**Signals**: `single-spa` (`registerApplication`, `single-spa-config`), `qiankun` (`registerMicroApps`, `start()`), Luigi (`luigi-config`), native MF composition. Some setups expose a registry endpoint listing all micro-apps.

```bash
grep -rhoE "single-spa|registerApplication|registerMicroApps|qiankun|luigi|import-map-overrides" bundles/ | sort -u
for p in /api/microfrontends /apps/registry /mfe/registry /api/apps /importmap.json; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
```

**Gotcha**: micro-frontend routes are **composed at runtime** by the orchestrator — sitemap/static enumeration misses them entirely; the orchestrator config (or a registry endpoint) is the only place the full app list exists. `single-spa`'s `import-map-overrides` dev tool, if left enabled, lets you repoint any micro-app to an arbitrary URL. Each micro-app often has independent auth — enumerate and test each separately (auth depth → `application_enumeration_auth_multiservice_deep`).

## Modern JavaScript Ecosystem

Bundler and framework fingerprints tell you where routes, server-callable code, and config live — enumerate accordingly.

### Bundler fingerprinting

- **Webpack**: `__webpack_require__`, `webpackChunk<name>` global, `webpackJsonp` (older).
- **Vite**: `__vite__mapDeps`, `/@vite/`, `?import`/`?url` query suffixes, `/@id/` in dev.
- **esbuild**: terse function-wrapped modules, `__toESM`/`__commonJS`/`__require` helpers.
- **Rollup**: `.mjs` chunks, `import`-based chunk graph.
- **Turbopack**: **default bundler in Next.js 16** (dev-stable in 15) — chunks under `/_next/static/chunks/` with a `turbopack`-tagged runtime.
- **Bun bundler** (`bun build`): default chunk naming `[name]-[hash].[ext]` (e.g. `entry-a-t268ez5g.js`).
- **Parcel**: `parcelRequire`, numeric module ids.

```bash
grep -rhoE "__webpack_require__|webpackChunk[a-zA-Z0-9_]*|__vite__mapDeps|__toESM|__commonJS|parcelRequire|turbopack" bundles/ | sort -u | head
```

**Gotcha**: the bundler dictates the chunk/manifest layout — Webpack/Turbopack ship a chunk manifest (`_next/static/.../_buildManifest.js` for Next.js) that lists every route's chunks; the fingerprint tells you which manifest to pull for the complete route list.

### Chunk manifest and lazy-route extraction

Whatever the bundler, the async-chunk map names every lazily-loaded route/component.

```bash
# Next.js build manifest (lists every route → chunk)
curl -s https://<target>/_next/static/<buildId>/_buildManifest.js | grep -oE '/[a-zA-Z0-9/_\[\]-]+' | sort -u
grep -rhoE "__webpack_require__\.(e|u)\(|import\(\s*/\*[^*]*\*/\s*['\"]?[0-9]+" bundles/ | sort -u
```

**Gotcha**: lazy routes (`import()`, `loadChildren`, `React.lazy`) only load on navigation, so their paths never appear in a crawl until you read the chunk manifest or the dynamic-import map — force each chunk to load (or read its module list) to reveal hidden routes and admin panels.

### Monorepo and cache endpoints

**Signals**: Turborepo (`turbo` config, build-hash headers), Nx (`nx.json`, `@nx/*` in bundles), PNPM workspace (`.pnpm/` in module paths). Remote-cache endpoints: Turborepo `/api/artifacts/<hash>` (self-hosted or Vercel), Nx Cloud `nx.app` / `/nx-cloud/` task cache.

```bash
grep -rhoE "\.pnpm/|@nx/|nx-cloud|turbo(repo)?|/api/artifacts/" bundles/ | sort -u
curl -s -o /dev/null -w '%{http_code}\n' https://<target>/api/artifacts/status   # Turborepo remote cache probe
```

**Gotcha**: a self-hosted Turborepo remote cache (`/api/artifacts/*`) authenticated with a **predictable or leaked token** lets you read (and poison) shared build artifacts — a supply-chain lead; the PNPM/Nx signatures also reveal the internal package graph in module paths.

### React Server Components and Server Actions (Next.js / React 19)

**Signals** (verified): App-Router RSC navigation uses `?_rsc=<hash>` + the `RSC: 1` request header, returning a flight payload; the older Pages Router uses `_next/data/<buildId>/<route>.json`. **Server Actions** POST a body with the **`Next-Action: <actionId>`** header, where `<actionId>` is a hash of the server function.

```bash
curl -s "https://<target>/some/route?_rsc=1" -H 'RSC: 1' | head -c 300      # flight payload
curl -s https://<target>/_next/data/<buildId>/index.json | jq 'keys' 2>/dev/null   # Pages Router server state
grep -rhoE '"\$ACTION_ID_[0-9a-f]+"|Next-Action|createServerReference' bundles/ | sort -u   # server-action ids in the client
```

**Gotcha**: the flight/`_next/data` payload contains server-computed state (props, sometimes data the UI never renders) keyed to the request context — diff it across roles/tenants. Server Actions are **server-callable endpoints reachable by replaying the `Next-Action` id** with a crafted body — enumerate the action ids from the bundle and test authorization on each. Version-fingerprint note: RSC deserialization had a pre-auth RCE, **CVE-2025-55182** (react-server-dom-{webpack,parcel,turbopack}, React 19.0.0–19.2.0) — check the React version before assuming the flight endpoint is safe (route to `rce`).

### Remix and React Router 7 (loaders/actions)

**Pattern**: Remix routes expose `loader` (GET) and `action` (POST) functions; loader data is fetched with `?_data=routes/<routeId>` (Remix v1/v2). React Router 7 framework mode uses single-fetch `.data` requests (`<route>.data`).

```bash
grep -rhoE "\?_data=routes/[a-zA-Z0-9._/$-]+|createBrowserRouter|__remixManifest|__reactRouterManifest" bundles/ | sort -u
curl -s "https://<target>/dashboard?_data=routes/dashboard" | head -c 300   # Remix loader data
```

**Gotcha**: each `?_data=`/`.data` request is a direct call to that route's server loader — enumerate route ids from the bundle's route manifest (`window.__remixManifest` / `window.__reactRouterManifest`) and hit each loader/action directly to test authorization outside the UI.

### SvelteKit data and server endpoints

**Pattern**: `+page.server.ts` (server load), `+server.ts` (standalone API endpoints), universal `+page.ts`; SvelteKit serves route data at `<route>/__data.json` and marks links with `data-sveltekit-*` attributes.

```bash
grep -rhoE "__data\.json|data-sveltekit-[a-z]+|__sveltekit_[a-z0-9]+" bundles/ *.html 2>/dev/null | sort -u
curl -s "https://<target>/account/__data.json" | head -c 300
```

**Gotcha**: `<route>/__data.json` returns the server `load` output for that route — a JSON data endpoint per page; `+server.ts` endpoints are full REST handlers (all methods) that never appear as page routes — enumerate them from the client route table.

### Nuxt payload and server routes

**Pattern**: Nuxt 3 ships assets under `/_nuxt/`, hydration state in `window.__NUXT__` or a separate `/_payload.json` (and `_payload.js`), and Nitro server routes under `/api/*` and `/_nuxt/builds/meta/<hash>.json`.

```bash
curl -s https://<target>/ | grep -oE "window\.__NUXT__|/_payload\.(json|js)|/_nuxt/[a-zA-Z0-9._/-]+"
curl -s "https://<target>/_payload.json" 2>/dev/null | head -c 300
```

**Gotcha**: the Nuxt payload embeds server-fetched state (including data the page conditionally renders) — parse it for API URLs and pre-loaded records; the Nitro build meta and `/api/` prefix name the server route surface (`server/api/**` maps 1:1 to `/api/**`).

### Astro islands and server endpoints

**Pattern**: Astro renders static HTML with hydrated "islands" — `<astro-island>` custom elements carrying `component-url`/`renderer-url`/`props` attributes and `client:load`/`client:visible`/`client:only` directives; server endpoints live at `src/pages/**/*.{js,ts}`.

```bash
curl -s https://<target>/ | grep -oE "<astro-island[^>]*(component-url|renderer-url)=['\"][^'\"]+|client:(load|idle|visible|only|media)"
grep -rhoE "/_astro/[a-zA-Z0-9._/-]+" bundles/ *.html 2>/dev/null | sort -u
```

**Gotcha**: `<astro-island>` `props` attributes carry the exact server-serialized props passed to each interactive component (a data leak of what the server sent); `component-url` points at the hydration chunk to mine, and any `.js`/`.ts` under `src/pages` is a server (SSR/API) endpoint, not a static page.

### Qwik resumability

**Pattern**: Qwik serializes app state into the HTML (`<script type="qwik/json">`) and lazy-loads QRL segments on interaction; look for `q:` attributes (`q:container`, `q:base`), `q-*.js` chunks, and `q-manifest.json`.

```bash
curl -s https://<target>/ | grep -oE "q:(container|base|render|version)=['\"][^'\"]+|type=['\"]qwik/json['\"]"
curl -s https://<target>/build/q-manifest.json 2>/dev/null | jq '{symbols:(.symbols|keys|length),bundles:(.bundles|keys|length)}'
```

**Gotcha**: `q-manifest.json` maps every event-handler symbol to its lazy chunk — a complete list of interaction-triggered code paths (including ones the current UI never surfaces); the serialized `qwik/json` state is the server-provided data snapshot to inspect.

### GraphQL client cache and persisted queries

SSR GraphQL apps embed the normalized client cache in the initial HTML (`window.__APOLLO_STATE__`, urql SSR data, Relay store), and use Automatic Persisted Queries (APQ) — the client sends a `sha256Hash` instead of the query text.

```bash
curl -s https://<target>/ | grep -oE "window\.__APOLLO_STATE__|__RELAY_STORE__|__URQL_DATA__"
grep -rhoE "persistedQuery|sha256Hash|APQ|createPersistedQueryLink" bundles/ | sort -u
```

**Gotcha**: `__APOLLO_STATE__` is a normalized dump of every entity the server returned for the page — including fields the UI never renders and object types that hint at the full schema; the APQ `sha256Hash` values map to server-registered queries (a `PersistedQueryNotFound` response confirms APQ) — this is client-side cache recon, distinct from the GraphQL *protocol* work in `application_enumeration_api_deep`.

### Server-driven UI (HTMX, Turbo, Alpine)

Server-driven-UI frameworks put endpoint URLs directly in HTML attributes rather than in a JS router: HTMX (`hx-get`/`hx-post`/`hx-target`/`hx-trigger`/`hx-vals`), Hotwire Turbo (`<turbo-frame src>`, `<turbo-stream>`, `data-turbo-*`), Alpine (`x-data`, `@click`).

```bash
curl -s https://<target>/ | grep -oE "hx-(get|post|put|delete|patch|target|trigger|vals)=['\"][^'\"]+|<turbo-frame[^>]+src=['\"][^'\"]+|<turbo-stream[^>]+action="
```

**Gotcha**: `hx-*` and `turbo-frame src` attributes name server endpoints and their HTTP methods **inline in the HTML** — a complete endpoint list without touching a bundle; `hx-vals`/`hx-include` reveal the parameters each endpoint expects, and Turbo Streams name the server actions that push DOM updates.

### Angular hydration and deferrable views

Angular 16+ SSR marks hydrated DOM with `ngh` attributes and `provideClientHydration()`; Angular 17+ `@defer` blocks lazy-load a chunk on a trigger (viewport, interaction, timer).

```bash
curl -s https://<target>/ | grep -oE "ngh=|_nghData|ng-server-context"
grep -rhoE "ɵɵdefer|@defer|loadChildren|import\(['\"][^'\"]+" bundles/ | sort -u
```

**Gotcha**: `@defer`/`loadChildren` chunks are routes and components that never load until their trigger fires — read the dynamic-import targets to reach deferred admin/feature components; the `ng-server-context` attribute reveals whether SSR/prerender/hydration is in use (and thus whether a server render exists to diff across roles).

### SPA route composition (client routers)

Routes live in config, not in links: React Router (`createBrowserRouter`, `<Route>`), TanStack Router (file-based `routeTree.gen.ts`), Vue Router (`routes:[...]`), Angular (`RouterModule.forRoot([...])`, `loadChildren`).

```bash
grep -rhoE "(createBrowserRouter|createRouter|RouterModule\.forRoot|path:\s*['\"][^'\"]+['\"]|loadChildren)" bundles/ src/ 2>/dev/null | sort -u
```

**Gotcha**: the router config is the authoritative client route list — lazy routes (`loadChildren`, dynamic `import()`) point at chunks that only load on navigation, so their paths never appear until you read the config or force the import; guard clauses (`canActivate`, route loaders returning `redirect`) name the auth model to test.

## Feature Flags and A/B Testing

Feature flags gate whole routes and features per cohort; enumerating flag names and cohort keys reveals surface that is invisible to a default session.

### Flag-provider SDK detection

Grep the bundle for the SDK init and evaluation calls (method names verified):
- **LaunchDarkly**: `LDClient.initialize('<client-side-id>', ...)`, `.variation('<flag>', default)`; endpoints `clientstream.launchdarkly.com` (stream), `clientsdk.launchdarkly.com` (poll/eval), `events.launchdarkly.com`; goals at `/sdk/goals/<clientId>`.
- **Statsig**: `statsig.checkGate('<gate>')`, `getConfig`/`getExperiment`.
- **Split.io**: `SplitFactory(...)`, `client.getTreatment('<split>')`.
- **Optimizely**: `optimizely.isFeatureEnabled('<flag>')` / `decide('<flag>')`; CDN datafile.
- **Flagsmith**: `flagsmith.init(...)`, `hasFeature('<flag>')`/`getValue('<flag>')`.
- **GrowthBook**: `gb.isFeatureOn('<flag>')` / `isOn`.

```bash
grep -rhoE "(LDClient\.initialize|\.variation|checkGate|getTreatment|isFeatureEnabled|hasFeature|isFeatureOn)\(['\"][^'\"]+['\"]|clientstream\.launchdarkly\.com|[a-z0-9-]+\.split\.io" bundles/ | sort -u
```

**Gotcha**: flag **names** frequently ship in the client even when evaluation is server-side — and a name like `enable-new-admin-panel` or `beta-payments-v2` maps directly to a route/feature to force on. The LaunchDarkly client-side ID (in `LDClient.initialize`) is public and lets you pull the flag set from the eval/goals endpoint.

### Edge and analytics-driven flag platforms

Newer flag delivery rides analytics or edge platforms:
- **Vercel Flags SDK** (`flags`, formerly `@vercel/flags`; `flags/next`): flags resolved at the edge, often backed by Edge Config; precomputed flag state can appear in a `x-vercel-flag-*` header or an encoded URL segment.
- **PostHog**: `posthog.isFeatureEnabled('<flag>')`/`getFeatureFlag('<flag>')`; evaluation POSTs to `/decide` (older) or `/flags` (recent SDKs).
- **Amplitude Experiment**: `experiment.variant('<flag>')`.

```bash
grep -rhoE "(getFeatureFlag|isFeatureEnabled|experiment\.variant)\(['\"][^'\"]+|/(decide|flags)/?\?|x-vercel-flag" bundles/ | sort -u
```

**Gotcha**: PostHog's `/decide`(`/flags`) response returns **all** flags evaluated for the current identity in one JSON blob — capture it to enumerate the entire flag set and their on/off state for your session; Vercel precomputed flags encode enabled features into the request context, diff-able across cookies.

### Remote config and self-hosted flag systems

- **Firebase Remote Config**: fetched from `firebaseremoteconfig.googleapis.com`; `getValue`/`getString('<key>')` in the bundle.
- **Unleash**: `isEnabled('<flag>')`; frontend/proxy endpoint `/api/frontend` or `/proxy`.
- **GitLab feature flags** (Unleash-compatible), **ConfigCat** (`getValue`), **AWS AppConfig**.

```bash
grep -rhoE "firebaseremoteconfig|remoteConfig|isEnabled\(['\"][^'\"]+|/api/frontend|unleash|configcat" bundles/ | sort -u
```

**Gotcha**: a Remote Config / Unleash frontend endpoint returns the full flag payload for the client key — pull it to enumerate every flag and value; Firebase Remote Config values sometimes contain URLs, thresholds, and kill-switch keys that describe backend behavior.

### Server-bootstrapped flags in the initial payload

SSR apps often inline the evaluated flag set into the first HTML/RSC response (`window.__FLAGS__`, a Redux/Zustand preloaded state, or an RSC flight chunk) rather than calling an SDK client-side.

```bash
curl -s https://<target>/ | grep -oE "__(FLAGS|BOOTSTRAP|INITIAL_STATE|LD)__|\"(featureFlags|flags|experiments|toggles)\":" | sort -u
```

**Gotcha**: the bootstrapped flag object in the initial HTML is the ground-truth flag set for your session — it lists flags that never trigger an SDK network call; flags shown `false` here are exactly the features to try to force on.

### Cohort and region-gated route discovery

Cohort assignment rides a cookie/localStorage key or a bootstrapped flag set; regional variants ride geo headers.

```bash
grep -rhoE "(cohort|variant|bucket|treatment|experiment)[\"'_:=]" bundles/ | sort -u
# same URL, different backend by region
for h in 'CloudFront-Viewer-Country: US' 'CloudFront-Viewer-Country: DE' 'X-Forwarded-For: 1.1.1.1'; do
  echo "== $h =="; curl -s https://<target>/ -H "$h" -o /dev/null -w '%{size_download}\n'; done
```

**Gotcha**: flipping a cohort cookie/localStorage value or forcing a flag on surfaces routes and features that exist only for a cohort (beta admin tools, new-checkout flows); region headers (`CloudFront-Viewer-Country`, `Accept-Language`, `X-Forwarded-For`) reveal geo-gated content and routes a single-region crawl never sees. Flag-gated *auth* differences (a role only some cohorts get) → `application_enumeration_auth_multiservice_deep`.

## Source Maps and Bundle Reconstruction

Source maps turn minified bundles back into original TypeScript with comments and module structure — the single highest-yield client artifact when present.

### Source-map discovery

**Signals**: `.js.map` at the same path as the `.js`; a `//# sourceMappingURL=<url>` trailer (same-path, CDN-hosted, or inline `data:` base64); `.css.map` for stylesheets.

```bash
for u in $(cat jsfiles.txt); do echo "$(curl -s -o /dev/null -w '%{http_code}' "$u.map") $u.map"; done
# trailing sourceMappingURL (incl. inline data: maps deployed by accident)
for u in $(cat jsfiles.txt); do curl -s "$u" | grep -oE '//# sourceMappingURL=[^ ]+' | tail -1; done
```

**Gotcha**: production source maps are far more common than teams believe — always probe `.js.map`; an inline `//# sourceMappingURL=data:application/json;base64,...` embeds the entire original source in the bundle itself (no separate fetch needed).

### Hidden maps and Sentry release artifacts

`devtool: 'hidden-source-map'` generates maps **without** the `sourceMappingURL` comment — the `.map` still exists at the predictable path and is uploaded to error trackers.

```bash
# guess the map path even with no comment
for u in $(cat jsfiles.txt); do echo "$(curl -s -o /dev/null -w '%{http_code}' "$u.map") $u.map"; done
grep -rhoE "//# debugId=[0-9a-f-]+|sentry-trace|_sentryDebugIds" bundles/ | sort -u   # Sentry debug-id linked maps
```

**Gotcha**: `hidden-source-map` hides the *comment*, not the *file* — probe the `.map` path directly. Sentry-linked bundles carry a `//# debugId=` / `_sentryDebugIds`; if the Sentry org/project (or a leaked auth token — see `asset_discovery_historical_deep` for secret history) is reachable, the uploaded source maps are downloadable release artifacts, i.e. full original source.

### Reconstruction and deobfuscation

```bash
webcrack app.min.js -o out/            # deobfuscate + unpack webpack; with a .map, unpacks to original tree
npx unwebpack-sourcemap -o src/ app.js.map    # reconstruct the original file tree from a .map
jsluice urls app.js ; jsluice secrets app.js  # URLs/secrets from the bundle
```

**Gotcha**: `webcrack` (j4k0xb, actively maintained — v2.16.x) reverses obfuscator.io, unminifies, and unpacks webpack/browserify back to readable modules even without a map; **with** a `.map`, `unwebpack-sourcemap` reconstructs the original `src/` tree (TypeScript, folder names, comments) — read it as if you had the repo.

### String, comment, and coverage analysis

```bash
strings -n 8 app.min.js | grep -iE 'api|token|secret|key|internal|/v[0-9]|https?://' | sort -u
grep -oE '/\*.*?\*/' app.min.js | sort -u        # surviving comments
source-map-explorer app.min.js app.js.map        # which modules/deps are actually in the bundle
```

**Gotcha**: `strings` on a minified bundle surfaces endpoint URLs, feature-flag names, and keys that aren't obvious in the code flow; DevTools **Coverage** tab shows which code actually executed (live vs dead code) to prioritize reversing; `source-map-explorer` reveals the real dependency set (and internal package names) without needing `package.json`.

### CSS source maps and CSS-in-JS names

Stylesheets carry maps too (`.css.map`), and CSS-in-JS (styled-components, Emotion) leaks component names into generated class names when `displayName`/`babel-plugin-styled-components` is on.

```bash
for u in $(cat cssfiles.txt); do echo "$(curl -s -o /dev/null -w '%{http_code}' "$u.map") $u.map"; done
grep -rhoE "class=['\"][^'\"]*(sc-[A-Za-z0-9]+|css-[a-z0-9]+)|styled\.[a-z]+|makeStyles|emotion" bundles/ *.html 2>/dev/null | sort -u
```

**Gotcha**: a `.css.map` reconstructs the original SCSS/Less (including commented-out and internal styles); CSS-in-JS class names like `LoginForm-sc-1x2y3z` embed the source component name — a free component inventory (admin, internal, feature-gated components) even when the JS is minified.

### Secret scanning inside bundles

Bundles routinely embed keys that were "meant" for a backend-only build.

```bash
trufflehog filesystem out/ --results=verified,unknown 2>/dev/null
noseyparker scan out/ && noseyparker report
grep -rhoE "(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36})" out/ | sort -u
```

**Gotcha**: distinguish *public* client keys (Firebase/Stripe publishable/LaunchDarkly client-id — designed to ship) from *private* ones (server API keys, cloud credentials, private Stripe `sk_live`) accidentally bundled — only the latter is a finding. Record location and scope; never use a live credential.

### Integrity and build-timeline signals

**Signal**: `<script integrity="sha384-...">` (SRI). A changing SRI hash over time (via `asset_discovery_historical_deep` archives) dates bundle changes.

**Gotcha**: SRI on a `<script src>` pins the exact bytes — diffing the archived SRI hash tells you when the bundle last changed (a deploy timeline); a *missing* SRI on a third-party script is a supply-chain lead. The Next.js `buildId`, Vite manifest hash, or a `/version.json`/`/build-info.json` endpoint also fingerprints the exact build for CVE mapping.

## Modern Client-Side Patterns

Newer browser capabilities the app opts into are attack surface a classic crawl never considers.

### Client-side crypto

Apps move key derivation/signing into JS or WASM to obfuscate — recover the algorithm and any embedded keys.

```bash
grep -rhoE "crypto\.subtle\.(encrypt|decrypt|sign|deriveKey|importKey)|(CryptoJS|forge|tweetnacl|jsencrypt)|new Uint8Array\(\[" bundles/ | sort -u
```

**Gotcha**: a client-side crypto routine (especially a hardcoded key passed to `importKey`, or key derivation in WASM) means the "secret" is in reach of anyone who reads the bundle; note the algorithm, key handling, and whether the key is static — client-side encryption with a bundled key is not a control.

### Client-side ML models

**Signals**: TensorFlow.js (`model.json` + `*.bin` shards, `tf.loadLayersModel`/`loadGraphModel`), ONNX Runtime Web (`*.onnx`, `onnxruntime-web`), `transformers.js` (models under `/models/` or pulled from Hugging Face), MediaPipe (`.tflite`/`.task`).

```bash
grep -rhoE "['\"][^'\"]+\.(onnx|tflite|task)['\"]|model\.json|tf\.load(Layers|Graph)Model|transformers|onnxruntime" bundles/ | sort -u
curl -s https://<target>/models/model.json | jq '.modelTopology?.model_config? // .format' 2>/dev/null
```

**Gotcha**: a client ML model (`model.json`/`.onnx`) leaks the architecture and weights — which can reveal training-data structure, business logic (fraud/scoring/moderation models), and organizational intent; download the weights and note the model's purpose.

### Client-side storage enumeration

The app's `localStorage`, `sessionStorage`, and IndexedDB frequently hold tokens, PII, cached API data, and feature state.

```javascript
// browser console / Playwright
console.log({...localStorage}); console.log({...sessionStorage});
for (const db of await indexedDB.databases()) console.log(db.name, db.version);
```

**Gotcha**: JWTs/refresh tokens in `localStorage` are readable by any XSS (a stored-token finding to pair with `xss`); IndexedDB object stores often cache full authenticated API responses and offline records — enumerate the DBs and object-store keys as both a data exposure and an endpoint map.

### Analytics, tag managers, and event taxonomy

Analytics wiring leaks internal event names, third-party destinations, and PII flows: Google Tag Manager (`/gtm.js?id=GTM-XXXX`, `dataLayer.push({event:...})`), Segment (`analytics.track/identify/page`, a `writeKey`), plus Amplitude/Mixpanel/RudderStack/PostHog capture calls.

```bash
grep -rhoE "GTM-[A-Z0-9]+|dataLayer\.push\(|analytics\.(track|identify|page|group)\(['\"][^'\"]+|writeKey|mixpanel\.track|amplitude" bundles/ *.html 2>/dev/null | sort -u
curl -s "https://www.googletagmanager.com/gtm.js?id=GTM-XXXX" | grep -oE '"[a-z_]+\.(com|io|net)/[^"]+"' | sort -u   # tags/pixels in the container
```

**Gotcha**: the GTM container script lists every tag, trigger, and third-party pixel the site loads (a full third-party/data-sharing map), and `analytics.track('<event>')`/`dataLayer.push({event:'<name>'})` calls name internal business events (`checkout_completed`, `admin_impersonate`) that describe backend actions and workflows a crawl never sees; a client-side `writeKey` identifies the analytics backend.

### Trusted Types, CSP, and DOM-sink signals

The response CSP and Trusted Types policy both describe the app's own risk model and gate DOM-XSS.

```bash
curl -sI https://<target>/ | grep -iE '^content-security-policy(-report-only)?:|^x-frame-options:'
grep -rhoE "trustedTypes\.createPolicy\(['\"][^'\"]+|innerHTML|dangerouslySetInnerHTML|insertAdjacentHTML|eval\(|new Function\(" bundles/ | sort -u
```

**Gotcha**: `require-trusted-types-for 'script'` in the CSP means DOM sinks are gated (harder DOM-XSS); its **absence** plus `innerHTML`/`dangerouslySetInnerHTML`/`eval` in the bundle marks the sinks to attack. A CSP with `unsafe-inline`/`unsafe-eval` or a wildcard/JSONP-able allow-listed host is itself a finding and a bypass map (route to `xss`).

### PWA manifest, protocol handlers, and share targets

The web app manifest declares routes and OS-integration surface.

```bash
curl -s https://<target>/manifest.json | jq '{scope,start_url,protocol_handlers,share_target,shortcuts:[.shortcuts[]?.url],file_handlers}' 2>/dev/null
grep -rhoE "registerProtocolHandler\(['\"][^'\"]+|launchQueue|setConsumer" bundles/ | sort -u
```

**Gotcha**: a `share_target` is a route that accepts POSTed shared content (an unusual input surface); `protocol_handlers`/`registerProtocolHandler('web+<scheme>', ...)` route external `web+foo://` URLs into the app (deep-link injection); `file_handlers` + `launchQueue` mean the app is invoked with user files — all inputs a normal crawl never exercises.

### Device and hardware capability APIs

Apps that opt into hardware access carry unusual reach worth cataloguing.

```bash
grep -rhoE "navigator\.(usb|serial|hid|bluetooth|gpu|xr)|showOpenFilePicker|showDirectoryPicker|navigator\.locks|IdleDetector|WebTransport\(" bundles/ | sort -u
```

**Gotcha**: File System Access (`showDirectoryPicker`), WebUSB/WebSerial/WebHID, WebBluetooth, WebGPU, and WebXR mark an app with local-device or GPU reach — flag the capability and where it is triggered; `WebTransport` (like WebRTC data channels) is a transport a TLS-terminating proxy won't fully see.

### WebRTC data channels (client side)

The app may use `RTCDataChannel` for P2P data beyond media. Signaling and STUN/TURN enumeration are in `application_enumeration_api_deep`; here, note the capability and that data channels bypass TLS-terminating proxies.

```bash
grep -rhoE "createDataChannel\(['\"][^'\"]*|new RTCPeerConnection\(|iceServers" bundles/ | sort -u
```

**Gotcha**: `createDataChannel` in the bundle means peer-to-peer data transfer that a MITM proxy won't see — capture the ICE candidates (via the signaling channel, per `api_deep`) to unmask peer IPs; a hardcoded TURN credential in `iceServers` is a recordable secret.

## Tooling and Command Reference

- **Bundle reconstruction**: `webcrack` (deobfuscate/unpack, maintained), `unwebpack-sourcemap` (reconstruct src tree from `.map`), `source-map-explorer` (module/size map), `unminify`, `de4js` (obfuscator.io reversal).
- **Static mining**: `jsluice` (URLs/secrets), `LinkFinder`/`xnLinkFinder` (endpoints), `subjs`/`getJS`/`katana -jc` (collect JS URLs), `trufflehog`/`noseyparker` (secrets, incl. history — see `asset_discovery_historical_deep`).
- **WASM**: `wabt` (`wasm2wat`, `wasm-objdump`, `wasm-decompile`), `binaryen` (`wasm-dis`), `wasm-tools` (bytecodealliance, incl. component `wit`); ILSpy/`ilspycmd`/dnSpy for Blazor `.dll`s.
- **Runtime/headless**: Playwright or Puppeteer to execute the app and enumerate runtime routes, registered SWs, caches, storage, and federation remotes; Chrome DevTools Application panel (SW/cache/storage) and Coverage tab (live vs dead code).
- **Interception**: `mitmproxy` (scriptable), Burp, Caido — capture every request the client actually makes, including worker/SW/federation/WebTransport fetches.

Install any tool not present at runtime. Never replay a token or key recovered from a bundle/worker/WASM — record its presence, location, and scope only.

## What Deep Client-Side Recon Completeness Looks Like

Client recon is done only when:

- The Service Worker is found, its lifecycle/fetch handler/Workbox routes and precache manifest read, and its Cache Storage enumerated
- Every Web/Shared Worker, importScripts dependency, and worklet is enumerated and its message API analyzed
- WebAssembly modules are disassembled if present (imports/exports, toolchain, Rust/Go/Emscripten/Blazor specifics)
- PostMessage handlers are catalogued with origin-validation (and bypass-pattern) analysis, plus opener/COOP/COEP/BroadcastChannel and adjacent sinks (hash/window.name/storage)
- The module-federation host/remote graph is mapped (`mf-manifest.json`/`remoteEntry.js`, Vite/Angular/dynamic remotes, exposed modules, shared deps) when applicable
- The bundler and framework are fingerprinted, the chunk/route manifest extracted, and framework data layers enumerated (RSC/Server Actions, Remix/RR7 loaders, SvelteKit `__data.json`, Nuxt payload, Astro islands, Qwik manifest)
- Feature-flag providers are identified and flag/cohort names enumerated (→ cohort-gated routes), including server-bootstrapped flag sets
- Source maps are probed (including hidden/Sentry maps) and, where present, the original source reconstructed and secret-scanned
- Client-side crypto/ML, storage, CSP/Trusted-Types sinks, and capability APIs (PWA manifest, protocol/share/file handlers, device APIs) are catalogued

Only then scope hunters to client-side classes: `postMessage`/origin-validation abuse and DOM XSS (`xss`), client-side prototype pollution (`prototype_pollution`), Server-Action authorization and the RSC-deserialization CVE class (`rce`), service-worker MITM/cache-poisoning, and module-federation remote takeover.

## Pro Tips

1. Read the Service Worker source — its fetch handler, Workbox `registerRoute` list, and precache manifest reveal internal endpoint URLs and a full asset inventory the app never links.
2. Always check for `.wasm` — JS-focused recon skips the exact logic (crypto, license checks) developers moved into WebAssembly to hide; `wasm-objdump -x` gives imports/exports fast, and the JS glue (wasm-bindgen/Emscripten) names the callable API.
3. Module-federation remotes are separate deployments with separate (often weaker) auth — enumerate every `remoteEntry.js`/`mf-manifest.json` host, and treat a runtime-configurable remote URL as a code-injection path.
4. Production source maps are common — probe `.js.map` on every bundle (including hidden maps with no comment); `unwebpack-sourcemap` then hands you the original `src/` tree, and inline `data:` maps embed the source in the bundle itself.
5. Feature-flag SDKs ship flag names in the client even when evaluation is server-side, and SSR apps inline the whole evaluated flag set in the first HTML — a flag name maps straight to a route/feature to force on.
6. PostMessage handlers with weak/absent origin validation are among the most-underestimated client bugs — grep every `addEventListener('message')`, and treat substring/suffix/prefix/unanchored-regex origin checks as no guard.
7. React 19 Server Actions are server-callable endpoints reachable by replaying the `Next-Action` id, and every framework has an equivalent direct data endpoint (Remix `?_data=`, SvelteKit `__data.json`, Nuxt `_payload.json`) — enumerate and test authorization on each outside the UI.
8. Turborepo/Nx remote-cache endpoints (`/api/artifacts/*`) are sometimes exposed with predictable tokens — a read/poison supply-chain lead.
9. Client-side ML models (`model.json`/`.onnx`) leak architecture and weights — a window into fraud/scoring/moderation logic and training-data structure.

## Summary

This deep sibling to `application_enumeration` maps the client-side surface: Service/Web Workers and worklets, WebAssembly (Rust/Go/Emscripten/Blazor), `postMessage` bridges and adjacent cross-context sinks, module federation and micro-frontends (Webpack/Vite/Angular/dynamic), the modern bundler/framework ecosystem (RSC/Server Actions, Remix/SvelteKit/Nuxt/Astro/Qwik data layers, monorepo caches, SPA route config), feature-flag/cohort-gated routes, source-map reconstruction (including hidden/Sentry maps), and modern capability/storage/crypto/ML surface. It loads only in deep mode. Completeness means the workers, WASM, federation graph, route/chunk manifests, flags, storage, and source maps are all extracted before client-side hunters are scoped. Companion deep siblings `application_enumeration_api_deep` (server-side API protocols) and `application_enumeration_auth_multiservice_deep` (auth, multi-service, AI/ML) cover the adjacent surface.
