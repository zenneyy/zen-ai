---
name: hurl
description: Reproducible, reviewable HTTP request chains and response assertions with Hurl for authorized multi-step security validation, vulnerable-versus-fixed regression cases, captured values, and low-rate semantic oracles
---

# Hurl Security Regression Playbook

Use [Hurl](https://hurl.dev/) when a security proof requires an ordered HTTP session whose requests, captured values, and assertions should be code-reviewed and replayed. It is well suited to authentication flows, redirects, cookies, CSRF tokens, upload lifecycles, patch regression, and paired semantic-differential cases.

Hurl sends exactly what the file describes. It does not make state-changing requests safe. Review scope, methods, targets, and captured secrets before every run.

## Install

Not preinstalled in the sandbox. Install from the official release binary:

```bash
VER=8.0.1
curl -sSL -o /tmp/hurl.tar.gz \
  "https://github.com/Orange-OpenSource/hurl/releases/download/${VER}/hurl-${VER}-x86_64-unknown-linux-gnu.tar.gz"
cd /tmp && tar xzf hurl.tar.gz
sudo ln -sf /usr/lib/x86_64-linux-gnu/libxml2.so.16 /usr/lib/x86_64-linux-gnu/libxml2.so.2
export PATH="/tmp/hurl-${VER}-x86_64-unknown-linux-gnu/bin:$PATH"
hurl --version
```

The sandbox ships `libxml2.so.16`; hurl 8.0.1 links against `libxml2.so.2` — the symlink resolves the loader error. The binary runs with ABI-warning noise but functions correctly for all HTTP operations.

## Minimal Chain

```hurl
# lab-regression.hurl
GET {{base_url}}/session
HTTP 200
[Captures]
csrf: xpath "string(//input[@name='csrf']/@value)"
[Asserts]
header "Content-Type" startsWith "text/html"

POST {{base_url}}/action
Content-Type: application/x-www-form-urlencoded
[FormParams]
csrf: {{csrf}}
operation: noop
HTTP 204
```

Hurl keeps cookies across requests in the same file, so an explicit `Cookie` header is unnecessary here.

Run one reviewed case against one authorized target first:

```bash
hurl --test --jobs 1 --connect-timeout 5 --max-time 15 \
  --variable base_url=https://lab.example lab-regression.hurl
```

When credentials are required, pass them with `--secrets-file local-secrets.env`, keep that file outside version control, and avoid verbose/debug output that could expose headers or bodies. Use `--variables-file` only for non-secret environment values.

## High-Signal Flags

HTTP options:
- `--cacert <file>` trusted CA for server verification (self-signed lab certs)
- `-E, --cert <cert[:pass]>` client certificate (mTLS)
- `--key <file>` client private key for mTLS
- `--compressed` request compressed response (deflate/gzip)
- `--connect-timeout <sec>` connection timeout (default 300 — always lower for pentest)
- `--connect-to <host1:port1:host2:port2>` route requests to a different backend (host-header manipulation, SNI testing)
- `-H, --header <name:value>` custom header (repeatable)
- `--http1.0` / `--http1.1` / `--http2` / `--http3` force HTTP version
- `-k, --insecure` skip TLS server cert verification (self-signed targets)
- `-L, --location` follow redirects
- `--location-trusted` follow redirects and send credentials to all redirect targets
- `--max-redirs <n>` redirect limit (default 50)
- `-m, --max-time <sec>` total operation timeout (default 300)
- `--no-cookie-store` disable cookie persistence between requests
- `--ntlm` / `--negotiate` / `--digest` HTTP authentication schemes
- `--path-as-is` preserve literal `/../` and `/./` path segments (path-traversal testing)
- `-x, --proxy <url>` send through proxy (route through Caido: `-x http://127.0.0.1:48080`)
- `--resolve <host:port:addr>` DNS override (pin resolution without /etc/hosts)
- `--unix-socket <path>` connect via Unix domain socket
- `-u, --user <user:pass>` basic auth header
- `-A, --user-agent <ua>` custom User-Agent

Run options:
- `--continue-on-error` keep running subsequent entries on failure
- `--delay <ms>` pause before each request (rate control; default 0)
- `--from-entry <n>` / `--to-entry <n>` execute a slice of the chain (1-indexed)
- `--jobs <n>` parallel file execution limit (1 = serial; default in `--test` mode: CPU count)
- `--no-assert` skip all assertions (exploration only — never for regression)
- `--parallel` run files in parallel (default in `--test`)
- `--repeat <n>` repeat the file sequence (`-1` = infinite loop)
- `--retry <n>` retries per entry on failure (0 = none, -1 = unlimited)
- `--retry-interval <ms>` wait between retries (default 1000)
- `--secret <name=value>` define a secret variable (masked in verbose/debug output; repeatable)
- `--secrets-file <file>` load secrets from file
- `--test` test mode: parallel by default, summary output
- `--variable <name=value>` define a variable (repeatable)
- `--variables-file <file>` load variables from properties file

Output options:
- `--curl <file>` export each request as a curl command (reproducer for others)
- `--error-format <short|long>` error detail level (default `short`)
- `-i, --include` show HTTP response headers in output
- `--json` structured JSON output per file
- `-o, --output <file>` write last response body to file
- `-v, --verbose` / `--very-verbose` verbose / debug-level logging
- `--verbosity <brief|verbose|debug>` granular log level

Report options:
- `--report-html <dir>` HTML report
- `--report-json <dir>` JSON report
- `--report-junit <file>` JUnit XML report
- `--report-tap <file>` TAP report

Other options:
- `-b, --cookie <file>` read cookies from file (Netscape format)
- `-c, --cookie-jar <file>` write cookies to file after the session
- `--file-root <dir>` root directory for file imports (default: input file dir)
- `--glob <pattern>` match input files by glob (repeatable)

## Captures

Captures extract values from responses and bind them to variables for subsequent requests.

Query types:
- `status` — HTTP status code
- `url` — effective URL after redirects
- `header <name>` — response header value
- `cookie <name>[<attr>]` — cookie value or attribute (`Value`, `Expires`, `Max-Age`, `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`)
- `body` — raw response body as string
- `bytes` — raw response body as bytes
- `jsonpath <expr>` — JSONPath query (RFC 9535 in 8.0.x)
- `xpath <expr>` — XPath query on HTML/XML
- `regex <pattern>` — first capture group of a regex match
- `duration` — response time in milliseconds
- `sha256` / `md5` — body hash
- `certificate <attr>` — TLS certificate field (`Subject`, `Issuer`, `Start-Date`, `Expire-Date`, `Serial-Number`)
- `variable <name>` — re-capture an existing variable (for filter chaining)

```hurl
GET {{base_url}}/api/user/1
HTTP 200
[Captures]
user_id: jsonpath "$.id"
user_role: jsonpath "$.role"
resp_time: duration
server_cert_expiry: certificate "Expire-Date"
csrf_token: xpath "string(//meta[@name='csrf-token']/@content)"
session_id: cookie "session"
api_version: header "X-API-Version"
secret_key: regex "api_key=([a-f0-9]{32})"
```

## Assertions

Implicit assertion: the status code on the response line (`HTTP 200`, `HTTP 403`).

Explicit assertions in `[Asserts]`:

```hurl
GET {{base_url}}/api/resource
HTTP 200
[Asserts]
# Status
status == 200

# Headers
header "Content-Type" contains "application/json"
header "X-Frame-Options" == "DENY"
header "Strict-Transport-Security" exists

# Body
body contains "success"
body not contains "stack trace"

# JSONPath
jsonpath "$.items" count == 10
jsonpath "$.user.role" != "admin"
jsonpath "$.id" isInteger
jsonpath "$.created_at" isIsoDate

# XPath
xpath "count(//form[@action])" == 1

# Regex
regex "version: ([0-9.]+)" matches "^[0-9]+\\.[0-9]+$"

# Timing
duration < 2000

# Certificate
certificate "Expire-Date" daysAfterNow > 30

# SHA-256 body integrity
sha256 == hex,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;

# Byte size
bytes count < 1048576
```

Predicates: `==`, `!=`, `>`, `>=`, `<`, `<=`, `startsWith`, `endsWith`, `contains`, `includes`, `matches` (regex), `exists`, `not exists`, `isBoolean`, `isCollection`, `isDate`, `isEmpty`, `isFloat`, `isInteger`, `isIsoDate`, `isNumber`, `isString`.

## Filters

Filters transform captured values or assertion queries:

- `count` — collection length
- `daysAfterNow` / `daysBeforeNow` — date math against current time
- `charsetDecode <encoding>` — decode bytes to string (`decode` is deprecated)
- `dateFormat <fmt>` — format a date value (`format` is deprecated)
- `htmlEscape` / `htmlUnescape` — HTML entity encoding
- `jsonpath <expr>` — chain a JSONPath on a captured value
- `nth <n>` — select element from a collection
- `regex <pattern>` — extract via capture group
- `replace <old> <new>` — string replacement (literal)
- `replaceRegex <pattern> <replacement>` — regex replacement
- `split <delimiter>` — split string to list
- `toDate <fmt>` — parse string to date
- `toFloat` / `toInt` — type conversion
- `urlDecode` / `urlEncode` — URL encoding
- `xpath <expr>` — chain XPath on a captured value
- `utf8Decode` / `utf8Encode` — byte/string conversion

Functions: `newDate` (current timestamp), `newUuid` (unique canary generation).

```hurl
GET {{base_url}}/api/tokens
HTTP 200
[Captures]
first_token: jsonpath "$.tokens" nth 0
token_count: jsonpath "$.tokens" count
[Asserts]
jsonpath "$.expires" toDate "%Y-%m-%dT%H:%M:%S" daysAfterNow > 1
jsonpath "$.name" urlDecode contains "test"
```

## Security Regression Patterns

Assert the security invariant, not only a status code. Each pattern captures the condition that must hold, then asserts it structurally.

IDOR regression — access control across identity boundaries:
```hurl
# Authenticate as user A
POST {{base_url}}/login
[FormParams]
username: {{user_a}}
password: {{pass_a}}
HTTP 200
[Captures]
resource_id: jsonpath "$.resources[0].id"

# Attempt to access user A's resource as user B
POST {{base_url}}/login
[FormParams]
username: {{user_b}}
password: {{pass_b}}
HTTP 200

GET {{base_url}}/api/resources/{{resource_id}}
HTTP 403
```

CSRF regression — token enforcement:
```hurl
GET {{base_url}}/form
HTTP 200
[Captures]
csrf: xpath "string(//input[@name='csrf']/@value)"

# Submit without CSRF token — must be rejected
POST {{base_url}}/action
Content-Type: application/x-www-form-urlencoded
[FormParams]
operation: test
HTTP 403
```

Auth bypass — unauthenticated access to protected resource:
```hurl
# No session cookie, no auth header
GET {{base_url}}/admin/dashboard
[Options]
location: false
HTTP 302
[Asserts]
header "Location" contains "/login"
```

Open redirect:
```hurl
GET {{base_url}}/redirect?url=https://evil.tld
[Options]
location: false
HTTP 302
[Asserts]
header "Location" not contains "evil.tld"
```

Path traversal (requires `--path-as-is`):
```hurl
GET {{base_url}}/files/../../../etc/passwd
[Options]
path-as-is: true
HTTP 400
[Asserts]
body not contains "root:"
```

Header injection:
```hurl
GET {{base_url}}/api/data
X-Custom: value%0d%0aInjected-Header: pwned
HTTP 200
[Asserts]
header "Injected-Header" not exists
```

Paired vulnerable-vs-fixed: run the same `.hurl` file against two targets:
```bash
hurl --test --variable base_url=https://vuln-staging.lab regression.hurl
hurl --test --variable base_url=https://fixed-staging.lab regression.hurl
```

## Request Chaining Methodology

Captures flow forward: a value captured in request N is available in request N+1 and all subsequent entries in the same file.

Cookie persistence is automatic within a file (same session). For cross-file cookie state, use `--cookie <file>` (read) and `--cookie-jar <file>` (write).

Variable scoping:
- `--variable name=value` — CLI-defined, non-secret, visible in verbose output
- `--variables-file <file>` — bulk variables from a properties file
- `--secret name=value` — CLI-defined, masked in verbose/debug output
- `--secrets-file <file>` — bulk secrets from file (keep outside version control)
- `[Options]` block per request can set `variable` locally

Chain structure for multi-step security proofs:
```text
fingerprint → establish session → reach boundary → prove primitive → verify state → cleanup
```

At each response, assert the condition required by the next request. A final success assertion cannot explain which earlier assumption failed.

Selective replay: `--from-entry 4 --to-entry 6` re-executes only entries 4–6 of the chain (1-indexed). Useful for re-testing a single boundary after a fix without replaying the full authentication setup — but only when earlier entries' captures are not needed.

## Output, Reports, and Automation

Test mode (`--test`) runs files in parallel and produces a summary:
```bash
hurl --test --jobs 4 --report-junit results.xml --report-html report/ \
  --variable base_url=https://lab.example regression/*.hurl
```

Export to curl (`--curl <file>`) writes each request as a curl command — useful for handing a reproducer to someone who does not have hurl.

JSON output (`--json`) produces structured results per file — parse with `jq` for CI integration:
```bash
hurl --json --no-output --variable base_url=https://lab.example regression.hurl | jq '.success'
```

Report formats:
- `--report-html <dir>` — browsable HTML report with request/response detail
- `--report-json <dir>` — machine-readable JSON
- `--report-junit <file>` — JUnit XML for CI (Jenkins, GitLab)
- `--report-tap <file>` — TAP for tap-consuming test harnesses

Redaction: `--secret` values are masked in verbose/debug output, but reports (HTML, JSON, JUnit) may contain request URLs, headers, captured variables, and response snippets. Redact reports before sharing.

## Safety Rules

- Use an explicit `base_url`; never derive the destination from untrusted response data without validating scheme, host, and port.
- Review POST/PUT/PATCH/DELETE requests and server-side side effects before replay.
- Set bounded timeouts: `--connect-timeout 5 --max-time 15` — the defaults (300s each) are far too permissive for pentest runs.
- `--path-as-is` is required when literal `/../` or `/./` path segments are the behavior under test; otherwise hurl normalizes them away.
- `--location` follows redirects automatically. `--location-trusted` also sends credentials (auth headers, cookies) to all redirect targets — use only when testing same-origin redirect chains.
- `--no-assert` skips all assertions — use for initial exploration only, never for regression runs.
- Do not use hurl for raw HTTP parser/smuggling cases when its HTTP stack normalizes the bytes being tested; use an appropriate raw harness in an isolated lab.
- Redact reports. HTML/JSON/JUnit/TAP artifacts may contain request URLs, headers, captured variables, and response snippets.
- Keep authentication material in local secret storage (`--secrets-file`) and use dedicated test accounts with minimum privilege.
- `--repeat -1` runs an infinite loop — always pair with `--max-time` or an external timeout.

## Failure Recovery

- "error: Could not resolve host": check `--resolve` or `--connect-to` if targeting by IP with hostname-based routing.
- TLS errors on self-signed certs: add `-k` or `--cacert <ca.pem>`.
- "variable not found": verify captures in earlier entries succeeded — a failed capture silently leaves the variable unset; add an assertion on the capture source.
- Timeout on slow targets: raise `--max-time` or `--connect-timeout` but keep them bounded.
- Assertion failures after a fix: use `--from-entry` / `--to-entry` to isolate and re-test the specific entry.
- Cookie not persisted across requests: verify `--no-cookie-store` is not set; cookies are automatic within a single file.

If uncertain, consult the [Hurl manual](https://hurl.dev/docs/manual.html) for version-specific syntax.

## Validation Deliverable

1. Reviewed `.hurl` file with variablized target and no embedded secrets
2. Vulnerable, fixed, and negative-control environment descriptions
3. Assertion at every capability transition
4. Deterministic results with tool version and timestamps
5. Side effects, cleanup, and residual-state check
6. Redacted report appropriate for sharing

Routed consumers:
- Validation/regression workflows across vulnerability skills (IDOR, CSRF, auth bypass, open redirect, path traversal, header injection)
- `tooling/caido.md` (proxy hurl traffic through Caido with `-x http://127.0.0.1:48080`)
- `vulnerabilities/csrf.md` (CSRF token assertion chains)
- `vulnerabilities/idor.md` (cross-identity access control regression)
- `vulnerabilities/open_redirect.md` (redirect-target validation)
- `vulnerabilities/path_traversal_lfi_rfi.md` (`--path-as-is` traversal assertions)
- `vulnerabilities/authentication_jwt.md` (JWT-in-header regression chains)
