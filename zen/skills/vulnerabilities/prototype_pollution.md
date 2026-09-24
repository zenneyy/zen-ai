---
name: prototype-pollution
description: Client and server prototype pollution testing covering JavaScript object merge bugs, Node.js RCE chains, and filter bypasses
---

# Prototype Pollution

Prototype pollution corrupts shared object prototypes (`Object.prototype`, `Array.prototype`, etc.), leading to application logic bypass, denial of service, and — on Node.js — remote code execution via gadget chains. Test anywhere user input merges into objects without safe key filtering.

## Attack Surface

**Languages & Runtimes**
- JavaScript/TypeScript (browser and Node.js)
- JSON parsers that preserve `__proto__`, `constructor`, `prototype` keys
- Server-side template engines and config merge utilities

**Input Vectors**
- JSON request bodies, query strings, multipart form fields
- URL-encoded nested objects (`__proto__[key]=value`)
- WebSocket messages, GraphQL variables, file import formats (JSON, YAML)

**Vulnerable Patterns**
- Deep merge/extend: `lodash.merge`, `jQuery.extend`, custom `Object.assign` loops
- Query parsers: `qs`, `body-parser` with nested object support
- Client-side routing, state hydration, analytics SDK config merges

## Key Vulnerabilities

### Pollution Mechanics

Measured on Node 24, these decide whether a candidate is real:

- **`JSON.parse` alone does not pollute.** `JSON.parse('{"__proto__":{"x":1}}')`
  creates an **own property named `__proto__`** on the result (`Object.hasOwn`
  is `true`); it does *not* set the prototype, so `({}).x` stays `undefined`.
  Pollution happens only when that parsed object is then walked by a **recursive
  merge/clone/defaults** that copies `__proto__`. The finding is the merge, not
  the parse — a raw echo of a `__proto__` key proves nothing.
- **Both `__proto__` and `constructor.prototype` work.** A naive merge of
  `{"constructor":{"prototype":{"z":"Z"}}}` pollutes just as
  `{"__proto__":{...}}` does, so a filter blocking only `__proto__` is bypassed
  (measured: `({}).z === 'Z'`).
- **The guard differential is the whole game.** With
  `Object.prototype.isAdmin` polluted: `user.isAdmin` → `true` and
  `'isAdmin' in user` → `true` (both **exploitable**), but
  `Object.hasOwn(user,'isAdmin')` → `false` and an `Object.create(null)` object
  is `undefined` (both **safe**). So the exploitable sinks are property reads
  and `in` checks; an app that gates on `Object.hasOwn` / null-proto objects is
  not. Look for `if (user.isAdmin)`, `opts.x || default`, and `key in obj`
  patterns downstream of the merge.
- Mitigations that actually stop it: `Object.create(null)` option objects,
  key blocklists on `__proto__`/`constructor`/`prototype`, `Map` instead of
  plain objects, and running Node with `--disable-proto=throw` (measured:
  accessing `obj.__proto__` then throws).

### Client-Side Prototype Pollution

**Gadget Effects**
- Bypass auth checks reading `user.isAdmin` when polluted on prototype
- DOM XSS via polluted properties consumed by `innerHTML`, `document.write`, script loaders
- Cookie/session manipulation if app reads config from polluted defaults

**Payload Shapes**
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

### Server-Side Prototype Pollution (Node.js)

**Common Sinks**
- `lodash.merge`, `lodash.defaultsDeep`, `deep-extend`, `merge-options`
- Express/query parsers accepting nested objects
- YAML `load()` (not `safeLoad`) with prototype keys
- JSON.parse → merge into existing object without null prototype

**RCE Gadget Chains (Node.js)**
Pollute properties consumed by child_process, template engines, or require paths:
```json
{"__proto__": {"shell": "/proc/self/exe", "argv0": "node", "NODE_OPTIONS": "--require /tmp/evil.js"}}
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id')//"}}
```

Gadget availability depends on package versions — enumerate `node_modules` in white-box scans.

**Entry-point libraries (the merge/set that pollutes).** These recursively
copy attacker keys into a target object; a vulnerable version is the pollution
primitive. Match the installed version to its advisory (load
`dependency_cve_scanning` for the version→CVE mapping — this catalog is the
sink map, not a CVE list):

| Library | Polluting functions |
|---|---|
| `lodash` | `merge`, `mergeWith`, `defaultsDeep`, `set`, `setWith`, `zipObjectDeep` |
| `set-value` / `dset` / `unset-value` | `set` / `dset` with a dotted/`__proto__` path |
| `deepmerge`, `merge-deep`, `deep-extend`, `merge-options`, `mixin-deep`, `assign-deep` | the deep-merge entry point |
| `flat` | `unflatten()` on `{"__proto__.x":1}` |
| `js-yaml` (legacy `load`), `config`, `nconf` | config/YAML merge preserving proto keys |
| `qs` / `body-parser` / Express | the *transport* that turns `__proto__[x]=1` / nested JSON into the object handed to a merge |

**Polluted property → RCE sink gadget.** Once `Object.prototype` is polluted,
a later operation reads your key as if it were legitimate config:

| Polluted key(s) | Sink that executes | Mechanism |
|---|---|---|
| `shell`, `argv0`, `NODE_OPTIONS`, `env`, `execArgv`, `cwd`, `stdio` | `child_process.spawn/exec/fork` (any later call with an options object) | polluted defaults enter the spawn options; `NODE_OPTIONS=--require /path` or `--eval` runs code on the next Node spawn |
| `outputFunctionName`, `escapeFunction`, `compileDebug` + `client` | `ejs.render` | injected JS is compiled into the template function |
| `main`, `exports`, block/compile options | `pug`, `handlebars` compile | compile-time code path takes attacker input |
| `require`/module resolution fields | dynamic `require`/import | redirect module resolution |

Concrete: pollute for the `child_process` gadget, then let any dependency that
spawns fire it:
```json
{"__proto__": {"argv0": "node", "shell": "node", "NODE_OPTIONS": "--require /proc/self/fd/0"}}
```
Confirm the sink is actually reached (a real `spawn`/`render` on the request
path), not just that pollution succeeded — the gadget is version- and
call-site-specific.

### Filter Bypasses

**Key Sanitization Bypasses**
- Unicode normalization: `__proto__` variants, fullwidth underscores
- Nested forms: `constructor.prototype` instead of `__proto__`
- Array pollution: `__proto__[0]`, `[].__proto__`
- JSON `$` or `.` keys in some parsers (MongoDB-style operators overlap — see nosql_injection skill)

**Freeze/Seal Gaps**
- Pollution before `Object.freeze` on instance but not prototype
- Pollution affecting newly created objects after merge

## Testing Methodology

1. **Identify merge points** — Search for extend/merge/defaults/deep copy on user-controlled objects
2. **Baseline probe** — Inject benign pollution marker:
   ```json
   {"__proto__": {"pollutionCanary": "yes"}}
   ```
   Verify via response behavior, error messages, or follow-up request reading shared state
3. **Shape variants** — Test `__proto__`, `constructor.prototype`, nested bracket notation
4. **Channel matrix** — JSON body, query string, multipart, WebSocket for same endpoint
5. **Gadget hunting (Node.js)** — Map polluted keys to sinks in dependency tree (ejs, pug, handlebars, child_process wrappers)
6. **Client-side** — Check if polluted properties affect routing, auth UI, or DOM sinks

## Validation

1. Demonstrate a property on `Object.prototype` (or relevant prototype) affecting behavior on unrelated objects
2. Show security impact: auth bypass, XSS execution, or server-side command execution with minimal PoC
3. Prove pollution persists across requests (server) or page lifetime (client) as applicable
4. Document exact merge function and input path (parameter name, content-type)
5. Confirm fix: null-prototype objects, `Object.create(null)`, or key blocklists on `__proto__`/`constructor`/`prototype`

## False Positives

- Parser strips `__proto__` before merge — marker property never appears on prototype
- Framework uses `Object.create(null)` for options objects throughout
- Polluted key visible in JSON echo but never merged into object graph
- Client-side pollution blocked by frozen prototypes in modern hardened libraries (verify no behavioral change)
- WAF blocks payload but alternate encoding also blocked consistently

## Bypass Methods

- Switch from `__proto__` to `constructor[prototype]` when only one is filtered
- Use array notation: `__proto__[key]`, `[].__proto__.key`
- Content-type switching: JSON vs `application/x-www-form-urlencoded` vs multipart
- Split pollution across multiple parameters merged sequentially
- Second-order pollution: store payload, trigger merge in background job or export pipeline

## Impact

- Authentication/authorization bypass via polluted flag checks
- DOM XSS and session compromise in browsers
- Remote code execution on Node.js through known gadget chains
- Denial of service via polluting widely read prototype properties

## Pro Tips

1. Always verify pollution with a unique canary key (`pollutionCanary_<random>`) before attempting RCE gadgets
2. In white-box scans, grep for `merge`, `extend`, `defaultsDeep`, `assign` with user input
3. Check both request parsing and response template config merges (second-order)
4. Node gadget chains are version-specific — confirm package version before claiming RCE
5. Combine with client-side template injection if polluted keys flow into rendering config

## Tooling

Detection is mostly about payload shapes (above) plus a couple of light helpers. The sandbox has `go` and `nuclei`; `ppfuzz` is a single static binary.

- **ppfuzz** (dwisiswant0) — fast client-side prototype-pollution fuzzer (Rust, single binary); good for spraying the URL/param shapes across many endpoints: `ppfuzz -l urls.txt`
- **nuclei** (preinstalled) — has prototype-pollution templates for quick triage: `nuclei -u https://target -tags prototype-pollution`
- **BlackFan `client-side-prototype-pollution`** — not a tool but the canonical **gadget reference**: maps polluted keys to concrete DOM-XSS sinks per library (jQuery, Popper, Wistia, etc.). Use it to turn a confirmed pollution into real impact.

For server-side gadget hunting there is no reliable one-click tool — enumerate `node_modules` in white-box scope and match polluted keys to sinks (`ejs`/`pug` `outputFunctionName`, `child_process` `shell`/`NODE_OPTIONS`) as covered above.

## Summary

Any unsafe recursive merge of user-controlled keys is a prototype pollution candidate. Block `__proto__`, `constructor`, and `prototype` keys, use null-prototype objects, and validate impact with behavioral proof — not just reflected keys.
