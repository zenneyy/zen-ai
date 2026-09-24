---
name: application-enumeration-api-deep
description: Advanced API surface enumeration. Loaded automatically by deep scan mode as a companion to application_enumeration.md. Covers REST API depth, GraphQL federation and entity resolution, gRPC-web and protobuf discovery, tRPC (Next.js/Nuxt patterns), WebSocket endpoint discovery and subprotocol enumeration, Server-Sent Events, RPC schema discovery, WebRTC signaling, and API contract analysis (OpenAPI 3.1 schema mining, GraphQL introspection, HAR file analysis).
sibling: application_enumeration
load_when: scan_mode == "deep"
---

# Application Enumeration — API Surface (Deep)

This is the deep sibling to `application_enumeration` for API surface. The base file answers "is there an API at `/api`, and what routes and parameters does it expose?" — enough for standard mode. This file answers the next question: given an API surface exists, what is its full, technology-specific enumeration methodology? A REST API, a GraphQL federation graph, a gRPC service behind Envoy, a tRPC router, and a WebSocket subscription channel are enumerated by completely different means — and a hunter that treats all of them as "endpoints in Burp" misses the schema, the reflection interface, the federation helpers, and the real-time surface entirely.

It loads only in deep scan mode. Two companion deep siblings cover adjacent scope: `application_enumeration_client_deep` (client-side and JS-ecosystem depth — Web/Service Workers, WebAssembly, module federation, source-map reconstruction) and `application_enumeration_auth_multiservice_deep` (authenticated-surface depth — OAuth/OIDC/SAML/WebAuthn — multi-tenant and multi-service architecture, and AI/ML endpoints). Do not duplicate their content: this file stops at "what API technology is here and how do I map its full surface"; how a token is minted or how a bundle is reconstructed belongs to the siblings.

The method is: fingerprint the API technology first (content-type, error shape, reflection/introspection response), then run that technology's schema-recovery interface, then enumerate the full operation set from the recovered contract — not by guessing routes. URL patterns, protocol content-types, and tool syntax below verified against provider documentation 2026-09-13; where a protocol has a legacy and a current form (gRPC reflection, graphql-ws), both are given.

## REST API Depth

REST is the most-enumerated surface and the most under-enumerated: hunters find `/api/v1/users` and stop, missing the other versions, the methods the endpoint also accepts, the content-types it parses differently, and the batch endpoint that skips validation.

### Version and prefix enumeration

**Pattern**: `/api/v1`, `/api/v2`, `/api/v3`, `/v1`, `/v2`, `/api/latest`, date-versioned (`/api/2024-01-01`), header-versioned (`Accept: application/vnd.example.v2+json`).

```bash
ffuf -u https://<target>/apiFUZZ/users -w <(printf '/v1\n/v2\n/v3\n/v0\n/latest\n/beta\n') -mc all -fc 404
# header-based version negotiation
for v in 1 2 3; do curl -s -o /dev/null -w "v$v %{http_code}\n" https://<target>/api/users -H "Accept: application/vnd.example.v$v+json"; done
```

**Gotcha**: an older version left running rarely gets the newer version's authorization fixes — enumerate every version, and diff a resource's response across versions (`v1` often returns fields `v2` learned to hide).

### Method enumeration

`OPTIONS` pre-flight reveals allowed methods per endpoint; test methods the docs don't mention.

```bash
curl -s -X OPTIONS https://<target>/api/users -D - -o /dev/null | grep -i '^allow:'
for m in GET POST PUT PATCH DELETE; do echo "$m $(curl -s -o /dev/null -w '%{http_code}' -X $m https://<target>/api/users/1)"; done
```

**Gotcha**: an endpoint documented POST-only frequently also handles `PATCH`/`PUT` through the same framework router with weaker validation, and a `DELETE` handler may exist un-advertised — the `Allow` header and a method sweep reveal both.

### Content-type enumeration

The same endpoint may parse `application/json`, `application/xml`, `application/x-www-form-urlencoded`, `multipart/form-data`, `application/vnd.api+json`, `application/graphql`, or `application/protobuf` — each through a different parser and validation path.

```bash
for ct in application/json application/xml application/x-www-form-urlencoded 'application/vnd.api+json'; do
  echo "== $ct =="; curl -s -X POST https://<target>/api/x -H "content-type: $ct" --data '{"a":1}' -o /dev/null -w '%{http_code}\n'; done
```

**Gotcha**: switching JSON→XML on an endpoint that accepts both can reach an XML parser (XXE surface, `xxe` skill) the JSON path never touches; form-encoding can trigger mass-assignment binders JSON doesn't.

### Response-format negotiation

**Pattern**: `Accept` header variations, `?format=json|xml|csv`, `.json`/`.xml`/`.csv` path suffixes.

```bash
for s in '' .json .xml .csv; do echo "$s $(curl -s -o /dev/null -w '%{http_code}' https://<target>/api/users$s)"; done
curl -s https://<target>/api/users -H 'Accept: text/csv' -o /dev/null -w '%{content_type}\n'
```

**Gotcha**: a `.csv`/`.xml` variant sometimes serializes fields the JSON view filters, and a format param that reaches a templating serializer is an injection surface.

### Pagination pattern discovery

**Patterns**: cursor (`?cursor=<token>`), offset (`?offset=<n>&limit=<n>`), keyset (`?after=<id>`), page (`?page=<n>&per_page=<n>`, `?page_size=`), and RFC 8288 `Link` header (`rel="next"`).

```bash
curl -s -D - "https://<target>/api/users?limit=1" -o /dev/null | grep -i '^link:'
curl -s "https://<target>/api/users?page=1&per_page=1" | jq 'keys'   # look for next/cursor/total keys
```

**Gotcha**: a cursor token is often a base64/hex-encoded record id or offset — decode it; a predictable cursor is an enumeration primitive (walk every record), and `per_page`/`limit` with no cap is a resource-exhaustion lead.

### Filter and query enumeration

**Patterns**: OData (`$filter=`, `$select=`, `$expand=`, `$orderby=`), JSON:API (`filter[<field>]=`), custom DSLs, RSQL/FIQL (`filter=name==foo`).

```bash
curl -s "https://<target>/api/users?\$select=id,email&\$filter=id gt 0" -o /dev/null -w '%{http_code}\n'
curl -s "https://<target>/api/users?filter%5Brole%5D=admin" | jq '.data | length'
```

**Gotcha**: `$expand`/`$select` reach related objects and fields the default view omits (an authorization-bypass and hidden-field lead); a filter that reaches the ORM is a NoSQL/SQL-injection surface (route to `sql_injection`/`nosql_injection`).

### Batch endpoint discovery

**Patterns**: `/api/batch`, `/api/bulk`, `/$batch` (OData), `/api/graphql` (batched array). Batch endpoints frequently apply middleware (rate-limit, per-item authorization) once for the batch, not per operation.

```bash
curl -s -X POST https://<target>/api/batch -H 'content-type: application/json' \
  -d '[{"method":"GET","path":"/users/1"},{"method":"GET","path":"/users/2"}]' -o /dev/null -w '%{http_code}\n'
```

**Gotcha**: a batch wrapper is the classic rate-limit and per-request-validation bypass — 1000 operations in one authenticated request; test whether per-item authorization is enforced inside the batch.

### CORS preflight enumeration

An `OPTIONS` with an `Origin` header returns the CORS policy — allowed origins, methods, headers, and the credentials flag.

```bash
curl -s -X OPTIONS https://<target>/api/users -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: DELETE' -H 'Access-Control-Request-Headers: x-api-key' \
  -D - -o /dev/null | grep -i '^access-control-'
```

**Gotcha**: `Access-Control-Allow-Origin` reflecting an arbitrary `Origin` plus `Allow-Credentials: true` is a CORS-misconfiguration finding; `Allow-Methods`/`Allow-Headers` also enumerate the methods and custom headers (`X-Api-Key`, `X-Tenant`, `X-CSRF`) the endpoint reads — headers the base parameter scan misses.

### Rate-limit and throttling discovery

Response headers and `429`s reveal the limit model and its key.

```bash
curl -s -D - https://<target>/api/users -o /dev/null | grep -iE '^(x-ratelimit|ratelimit|retry-after|x-rate)'
```

**Gotcha**: `X-RateLimit-Limit`/`-Remaining`/`-Reset` (or the draft `RateLimit-*`) expose the budget, window, and whether the limit is per-key, per-IP, or per-route — a per-route limit is exactly why the batch/alias endpoints above bypass it.

### Admin and internal API surface

**Patterns**: `/api/admin`, `/api/internal`, `/api/v0`, `/api/experimental`, `/api/private`, `/internal/`. Often IP-restricted or gateway-gated — but frequently just unlinked and reachable.

```bash
ffuf -u https://<target>/apiFUZZ -w <(printf '/admin\n/internal\n/v0\n/experimental\n/private\n/debug\n') -mc all -fc 404
# gateway may key internal routes off a header
curl -s -o /dev/null -w '%{http_code}\n' https://<target>/api/internal/users -H 'X-Internal: true'
```

**Gotcha**: an internal API gated only by a header or a source-IP check the frontend proxy sets is reachable when you can influence that header (SSRF, header injection) or hit the origin directly.

### Deprecation and sunset signals

`Deprecation` and `Sunset` (RFC 8594) response headers, and `Warning` headers, mark endpoints scheduled for removal but still live.

```bash
curl -s -D - https://<target>/api/v1/users -o /dev/null | grep -iE '^(deprecation|sunset|warning):'
```

**Gotcha**: a `Deprecation: true` / `Sunset: <date>` endpoint runs on borrowed time with frozen, often un-patched code — a prime target and a map to the version the org is migrating off.

### Legacy API surface

**Patterns**: `/rpc`, `/xmlrpc.php`, `/soap`, `/api/legacy`, `/services/`, `/cgi-bin/`. Legacy endpoints predate modern hardening.

**Gotcha**: XML-RPC/SOAP endpoints (below) often lack rate-limiting, CSRF protection, and modern auth — and a legacy `/api/legacy/v0` frequently trusts inputs the current API validates.

### API gateway fingerprinting

Response headers name the gateway fronting the API — which tells you where auth, rate-limit, and routing are enforced, and thus what a direct-to-origin request bypasses.

```bash
curl -s -D - https://<target>/api/ -o /dev/null | grep -iE '^(via|server|x-kong|x-amzn|x-amz-apigw|x-tyk|x-envoy|x-apigee|x-google-|x-glb):'
```

Signals: `x-amzn-*` + `x-amz-apigw-id` → AWS API Gateway; `Via: kong/…` / `X-Kong-*` → Kong; `X-Tyk-*` → Tyk; `X-Envoy-*` → Envoy; `X-Apigee-*` → Apigee.

**Gotcha**: the gateway is where auth/WAF/rate-limit usually live — reaching the origin directly (found via `asset_discovery_cloud_deep`) bypasses them; the gateway header also dates its version for known-CVE checks.

### Health, metrics, and diagnostic endpoints

**Patterns**: `/health`, `/healthz`, `/ready`, `/livez`, `/metrics` (Prometheus), `/debug`, `/debug/pprof/` (Go), `/actuator` and `/actuator/{env,heapdump,mappings,configprops}` (Spring Boot), `/vars` / `/expvar` (Go), `/api/version`, `/api/info`, `/status`.

```bash
for p in /health /healthz /metrics /debug/pprof/ /actuator /actuator/env /actuator/mappings /api/version; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
```

**Gotcha**: `/actuator/mappings` dumps every route (a free endpoint inventory); `/actuator/env` and `/actuator/heapdump` leak secrets; `/metrics` leaks internal hostnames and route names; `/debug/pprof/` is both a leak and a DoS lever. Load `information_disclosure` for exploitation — this section is discovery.

## GraphQL Depth

GraphQL is a single endpoint hiding an entire schema. The whole methodology is: find the endpoint, recover the schema (introspection, or reconstruction when it is off), then enumerate every query/mutation/subscription and the federation helpers.

### Endpoint discovery beyond /graphql

**Patterns**: `/graphql`, `/api/graphql`, `/query`, `/api/query`, `/v1/graphql`, `/gql`, `/graphql/v1`. Framework-specific: Hasura `/v1/graphql` + `/v1/relay` + `/v2/query`; Apollo `/graphql`; Prisma/Postgraphile `/graphql`; WPGraphQL `/graphql` on WordPress.

```bash
for p in /graphql /api/graphql /query /v1/graphql /gql /graphql/v1; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' -X POST https://<target>$p -H 'content-type: application/json' -d '{"query":"{__typename}"}')"; done
```

**Confirm**: a `200` with `{"data":{"__typename":"Query"}}` (or a GraphQL-shaped error) confirms a GraphQL endpoint. `{__typename}` is the minimal probe — it is valid on every schema.

### Introspection detection and bypass

Full introspection: `{__schema{types{name fields{name}}}}`. If disabled (`"GraphQL introspection is not allowed"` / `"introspection is disabled"`), try the bypasses:

```bash
curl -s https://<target>/graphql -H 'content-type: application/json' -d '{"query":"{__schema{queryType{name}}}"}'
# bypasses when disabled:
#  - __type probe (sometimes allowed when __schema isn't): {"query":"{__type(name:\"User\"){name fields{name}}}"}
#  - field-suggestion oracle: query a wrong field, read the "Did you mean ...?" hint
curl -s https://<target>/graphql -H 'content-type: application/json' -d '{"query":"{userr}"}' | jq -r '.errors[].message'
```

**Gotcha**: introspection-off does not make the schema secret — the "Did you mean" suggestion engine leaks field names one query at a time (the basis for `clairvoyance` reconstruction), and some servers disable `__schema` but not `__type`. Also try newline/whitespace and aliased introspection (`a:__schema`) against naive regex-based blockers.

### Introspection tooling

- **`graphw00f`** (dolevf, maintained) — fingerprints the engine: `graphw00f -d -f -t https://<target>/graphql`.
- **`clairvoyance`** — reconstructs the schema from field suggestions when introspection is off: `clairvoyance https://<target>/graphql -o schema.json -w wordlist.txt`.
- **GQLSpection** (Doyensec, successor to InQL) / the InQL Burp extension — schema parsing and query generation; **Assetnote BatchQL** — batch/alias auditing; **graphql-cop** — automated audit; **graphql-voyager** — schema visualizer.

**Gotcha**: run `graphw00f` first — the engine (below) determines which bypasses and DoS vectors apply, so fingerprint before you probe.

### Engine fingerprinting

`graphw00f` distinguishes Apollo, Sangria (Scala), GraphQL-Yoga, graphql-ruby, Graphene (Python), Absinthe (Elixir), Hasura, Postgraphile, HyperGraphQL, Ariadne, Strawberry, and others by their error strings and behavior.

**Gotcha**: the engine dictates defaults — e.g. Hasura exposes `/v1/graphql` with permissive default roles and `x-hasura-*` header auth; Apollo exposes federation helpers (below); graphql-ruby's error format differs from Graphene's. A version-fingerprinted engine also gates known CVEs — verify the version before assuming a specific bug.

### Federation and entity resolution

Apollo Federation adds two helper fields to `Query` that are **not governed by introspection controls**:

```bash
# _service.sdl returns the full subgraph schema even when introspection is disabled
curl -s https://<subgraph>/graphql -H 'content-type: application/json' -d '{"query":"{_service{sdl}}"}' | jq -r '.data._service.sdl'
# _entities drives entity resolution as if you were the router
curl -s https://<subgraph>/graphql -H 'content-type: application/json' \
  -d '{"query":"query($r:[_Any!]!){_entities(representations:$r){__typename ...on User{id email}}}","variables":{"r":[{"__typename":"User","id":"1"}]}}'
```

**Gotcha** (primary-source, Apollo docs + 2024 research): `_service{sdl}` recovers the schema when standard introspection is off — always try it. Hitting a **subgraph directly** (rather than the gateway/router) frequently bypasses the router's auth layer, and `_entities` then lets you fetch arbitrary entities by key across the graph as the router would. Enumerate subgraphs (distinct hosts/ports serving `_service`) and test each directly.

### Subscriptions

Subscriptions run over WebSocket, usually at the same path (`wss://<target>/graphql`) but sometimes a separate one. The subprotocol matters (verified): modern **`graphql-ws`** library speaks subprotocol **`graphql-transport-ws`**; the deprecated **`subscriptions-transport-ws`** library speaks subprotocol **`graphql-ws`** (the naming is swapped — offer both to see which the server accepts).

```bash
wscat -c wss://<target>/graphql -s graphql-transport-ws     # modern
wscat -c wss://<target>/graphql -s graphql-ws               # legacy
```

**Gotcha**: the subscription endpoint often has *different* (or no) auth versus the query endpoint — a subscription that streams data the query API gates is the finding; enumerate subscription operations from the recovered schema.

### Batching and aliases

```bash
# array batching (if the server accepts it)
curl -s https://<target>/graphql -H 'content-type: application/json' -d '[{"query":"{a:__typename}"},{"query":"{b:__typename}"}]'
# aliasing: many operations in one document (bypasses per-operation rate limits)
curl -s https://<target>/graphql -H 'content-type: application/json' -d '{"query":"{a:user(id:1){email} b:user(id:2){email} c:user(id:3){email}}"}'
```

**Gotcha**: aliasing runs N operations in one request — the classic rate-limit and brute-force bypass (N password checks, N object fetches per request); array batching multiplies it further. Test both against any rate-limited mutation.

### Query depth and complexity

Recursive/nested queries probe depth and complexity limits; their absence is a DoS surface.

```bash
# nested cycle to probe depth limiting (adjust to a real relation from the schema)
curl -s https://<target>/graphql -H 'content-type: application/json' -d '{"query":"{user(id:1){posts{author{posts{author{id}}}}}}"}' -o /dev/null -w '%{http_code} %{time_total}s\n'
```

**Gotcha**: no depth/complexity limit is a DoS lead (fragment cycles, deep nesting); persisted queries (`/graphql?extensions={"persistedQuery":{"sha256Hash":"..."}}`, Apollo APQ) restrict to pre-registered hashes — enumerate whether arbitrary queries are still accepted alongside persisted ones.

### Automatic Persisted Queries (APQ)

Apollo APQ lets a client send a query hash instead of the full text: `?extensions={"persistedQuery":{"version":1,"sha256Hash":"<hash>"}}`. An unknown hash returns `PersistedQueryNotFound`, after which the client registers the full query.

```bash
curl -s "https://<target>/graphql?extensions=%7B%22persistedQuery%22%3A%7B%22version%22%3A1%2C%22sha256Hash%22%3A%22deadbeef%22%7D%7D"
```

**Gotcha**: `PersistedQueryNotFound` confirms APQ is in use and that registration is open (you can still send arbitrary queries). Only a *persisted-queries-only* / allowlisted deployment blocks ad-hoc queries — test whether a full query still runs; if it does, APQ is a caching feature, not a control.

### GraphQL error-message leakage

Malformed queries surface backend detail in `errors[].message`/`extensions`.

```bash
curl -s https://<target>/graphql -H 'content-type: application/json' -d '{"query":"{__typename @bogus}"}' | jq '.errors'
```

**Gotcha**: stack traces, ORM/DB errors, and internal type names in the error `extensions` (esp. Apollo's `exception.stacktrace` in non-production mode) leak framework, versions, and internal structure — a debug-mode-in-production signal.

### Mutation enumeration

Introspection (or `_service{sdl}`) lists every mutation; naming reveals privileged actions.

```bash
curl -s https://<target>/graphql -H 'content-type: application/json' -d '{"query":"{__schema{mutationType{fields{name args{name type{name}}}}}}"}' | jq -r '.data.__schema.mutationType.fields[].name'
```

**Gotcha**: mutations like `createUser`, `setRole`, `adminUpdate*`, `impersonate*`, `deleteAccount` are the privileged surface — enumerate them all and test authorization on each (route to `broken_function_level_authorization`); a mutation present in the schema but absent from the UI is the highest-value target.

### Playground / GraphiQL exposure

**Patterns**: `/graphql` with `Accept: text/html` (renders GraphiQL), `/graphiql`, `/graphql-playground`, `/altair`, `/voyager`, `/apollo-server-landing-page`.

```bash
curl -s https://<target>/graphql -H 'Accept: text/html' | grep -ioE 'graphiql|playground|altair|apollo'
```

**Gotcha**: a GraphQL IDE in production hands the tester the full schema and a query runner — check for it before attempting introspection bypasses.

## gRPC and Protobuf

gRPC hides behind HTTP/2 and binary protobuf, so it is invisible to URL-oriented recon. Fingerprint by content-type, then use reflection to recover the entire service catalog.

### gRPC endpoint discovery

**Signals**: HTTP/2-only endpoints on `:443`, `:50051`, `:9090`, `:8080`; `content-type: application/grpc` (and `application/grpc+proto`/`+json`). Trailers carry `grpc-status`.

```bash
# a gRPC server rejects a plain HTTP/1.1 GET but speaks HTTP/2 with application/grpc
curl -sI --http2-prior-knowledge https://<target>:443/ 2>&1 | head
grpcurl -plaintext <target>:50051 list 2>&1 | head    # errors reveal whether it's gRPC even if reflection is off
```

**Gotcha**: a service answering only over HTTP/2 with `application/grpc` and no REST semantics is gRPC — do not fuzz it with REST tooling; switch to `grpcurl`/`evans`.

### gRPC server reflection

Reflection exposes the entire service/message catalog. Current service is **`grpc.reflection.v1.ServerReflection`** (v1); **`grpc.reflection.v1alpha.ServerReflection`** is the legacy fallback many servers still expose — grpcurl tries both.

```bash
grpcurl -plaintext <target>:50051 list                          # all services
grpcurl -plaintext <target>:50051 describe <package.Service>    # methods
grpcurl -plaintext <target>:50051 describe <package.Message>    # message fields
grpcurl -plaintext <target>:50051 <package.Service/Method>      # invoke (with -d '{...}')
```

**Gotcha**: reflection is frequently left enabled in production — a `list` that returns the service catalog is a complete API map for free. If reflection is off, recover the schema from `.proto` files (below).

### gRPC-web

**Signals**: `content-type: application/grpc-web`, `application/grpc-web+proto`, or `application/grpc-web-text` (base64). Usually fronted by Envoy/Kong/AWS API Gateway to bridge browser↔gRPC.

```bash
grep -rhoE 'application/grpc-web(-text)?|grpc-web' bundles/ | sort -u   # bundle signals the app uses gRPC-web
```

**Gotcha**: gRPC-web calls look like ordinary POSTs in a proxy until you notice the `application/grpc-web*` content-type and decode the base64/length-prefixed protobuf body — a proxy view of "opaque binary POSTs to `/pkg.Service/Method`" is gRPC-web; the path segment names the service and method directly.

### Decoding gRPC-web frames

A gRPC-web body is length-prefixed protobuf: 1 flag byte, a 4-byte big-endian length, then the message; `-text` variants base64 the whole thing. Decode to read the request/response.

```bash
# grpc-web-text: base64-decode, then the first 5 bytes are the frame header, rest is protobuf
echo "<base64-body>" | base64 -d | xxd | head
protoc --decode_raw < message.bin    # field-number dump without the .proto
```

**Gotcha**: the trailing frame (flag byte `0x80`) is the gRPC trailer carrying `grpc-status`/`grpc-message` — the *real* status lives there, not in the HTTP 200; read it to distinguish auth-denied (`PERMISSION_DENIED`) from not-found. `protoc --decode_raw` recovers field numbers and values even without the schema.

### Protobuf schema discovery via .proto

When reflection is off, recover message/service definitions from `.proto` files.

```bash
grep -rl 'syntax = "proto3"' . 2>/dev/null           # .proto in source
# Buf Schema Registry hosts public modules at buf.build/<org>/<module>
# buf export buf.build/<org>/<module> -o ./proto   (with buf CLI)
```

**Gotcha**: many orgs publish their protobuf contracts to the public Buf Schema Registry (`buf.build/<org>`) — check there for the target's `.proto` before assuming the schema is private; the path segment from a gRPC-web call (`/pkg.Service/Method`) tells you which module to look for.

### gRPC health checking

The standard health service reveals service names even without full reflection.

```bash
grpcurl -plaintext <target>:50051 grpc.health.v1.Health/Check
grpcurl -plaintext -d '{"service":"<package.Service>"}' <target>:50051 grpc.health.v1.Health/Check
```

**Gotcha**: `Check` with a service name returns `SERVING`/`NOT_SERVING`, confirming a service exists by name — a probe that works even when reflection is disabled.

### gRPC-Gateway / HTTP transcoding

grpc-gateway and Envoy's gRPC-JSON transcoder expose a REST/JSON facade in front of gRPC services, mapped in the `.proto` via `google.api.http` annotations; the REST paths map 1:1 to gRPC methods.

```bash
grep -rhoE 'google\.api\.http|option \(google\.api\.http\)' . 2>/dev/null   # .proto transcoding annotations
```

**Gotcha**: a REST API that is really a transcoder usually has *both* facades live on the same backend — the JSON REST path and raw `application/grpc` — and the gRPC side frequently skips the gateway's auth/validation; find the `google.api.http` mappings (or the OpenAPI grpc-gateway emits) to see both, then test the gRPC side directly.

### Connect protocol (Buf)

Connect (connectrpc.com) is a modern gRPC alternative, POST-only over HTTP/1.1 or HTTP/2. Content-types (verified): **unary** uses `application/json` and `application/proto`; **streaming** uses `application/connect+json` and `application/connect+proto`.

```bash
# Connect unary is a normal JSON POST to /package.Service/Method — testable with curl
curl -s -X POST https://<target>/pkg.v1.Service/Method -H 'content-type: application/json' -d '{}' -o /dev/null -w '%{http_code}\n'
```

**Gotcha**: a Connect unary endpoint looks like a plain JSON REST POST (`/pkg.Service/Method` with `application/json`) and is fully testable with curl — but the same server usually also speaks gRPC and gRPC-web on the same routes; enumerate all three protocols against a discovered `Service/Method`.

### gRPC channelz

The channelz service (`grpc.channelz.v1.Channelz`) exposes live server/channel/socket state — peer addresses, call counts, sockets — when enabled.

```bash
grpcurl -plaintext <target>:50051 grpc.channelz.v1.Channelz/GetServers
grpcurl -plaintext <target>:50051 grpc.channelz.v1.Channelz/GetTopChannels
```

**Gotcha**: channelz left enabled leaks the service's live connection topology (upstream/downstream peer addresses) — an internal-map disclosure akin to Envoy's `config_dump`, and it responds even when full reflection is restricted.

### Envoy proxy interception

gRPC/gRPC-web is commonly fronted by Envoy; its admin interface leaks the full route table when exposed.

```bash
curl -s http://<target>:15000/config_dump | jq '.configs[].dynamic_route_configs' 2>/dev/null
curl -s http://<target>:15000/clusters 2>/dev/null | head
```

**Gotcha**: Envoy admin on `:15000` (`/config_dump`, `/clusters`, `/stats`) exposes every upstream gRPC service and route — cross to `kubernetes`/`asset_discovery_cloud_deep` for the mesh angle; here it is a free service catalog.

### gRPC tooling

`grpcurl` (list/describe/invoke), `evans` (interactive REPL: `evans -r repl -p 50051`), `ghz` (load test, useful to confirm a method accepts traffic), `bloomrpc`/`grpcui` (GUI). Prefer `grpcurl` + `evans` in-sandbox.

## tRPC and Modern RPC

tRPC and JSON-RPC/SOAP look like REST in a proxy but follow a rigid structure that, once known, enumerates cleanly.

### tRPC endpoint pattern

**Pattern** (verified): query `GET /api/trpc/<router>.<procedure>?input=<url-encoded-json>`; mutation `POST /api/trpc/<router>.<procedure>` with JSON body. The `input` is the procedure's argument (often SuperJSON-wrapped: `{"json":{...}}`).

```bash
curl -s "https://<target>/api/trpc/user.getById?input=%7B%22json%22%3A%7B%22id%22%3A1%7D%7D" | jq
```

**Gotcha**: the router.procedure structure comes from the JS bundle or source (`.query(`/`.mutation(` calls) — mine those (light bundle read; deep bundle mining is `client_deep`). A `200` with `{"result":{"data":...}}` confirms the procedure; a `TRPCError` shape confirms tRPC even on a wrong procedure.

### tRPC batch endpoint

**Pattern** (verified): `GET /api/trpc/<p1>,<p2>?batch=1&input=<indexed-json>` where `input` is `{"0":{...},"1":{...}}` keyed by position; procedures are comma-joined in the path.

```bash
curl -s "https://<target>/api/trpc/user.me,post.list?batch=1&input=%7B%220%22%3A%7B%7D%2C%221%22%3A%7B%7D%7D" | jq
```

**Gotcha**: batching combines procedures into one request and frequently applies middleware once for the batch — test each procedure individually *and* batched; a procedure that enforces auth alone may not inside a batch.

### tRPC in Next.js / Nuxt

**Next.js**: handler at `pages/api/trpc/[trpc].ts` or `app/api/trpc/[trpc]/route.ts`; routers under `server/routers/*` / `server/api/root.ts`. **Nuxt**: `server/api/trpc/[...trpc].ts` and `server/trpc/routers/*`.

**Gotcha**: the App-Router path (`app/api/trpc/[trpc]`) vs Pages-Router path (`pages/api/trpc`) tells you the Next.js architecture (relevant for `nextjs` middleware/route-handler bugs); the router file names enumerate the top-level routers.

### tRPC procedure enumeration

```bash
# from source: procedures and their Zod input schemas
grep -rhnE '\.(query|mutation|subscription)\(' server/ src/server/ 2>/dev/null
# from runtime: probe guessed procedures, read the error to confirm existence vs input-validation
curl -s "https://<target>/api/trpc/<guess>?input=%7B%22json%22%3Anull%7D" | jq -r '.error.message? // .result'
```

**Gotcha**: Zod schemas in the router source reveal exact input shapes and constraints — the parameter map for each procedure; at runtime, a "No procedure found" error vs an input-parse error distinguishes a wrong name from a wrong argument.

### JSON-RPC (1.0 / 2.0)

**Pattern**: `POST` `{"jsonrpc":"2.0","method":"<method>","params":{...},"id":1}`. Discovery: OpenRPC's `rpc.discover` method returns the service document (this is the **OpenRPC** discovery method, not an RFC — the base JSON grammar is RFC 8259); XML-RPC-style servers use `system.listMethods`.

```bash
curl -s -X POST https://<target>/rpc -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"rpc.discover","id":1}' | jq
curl -s -X POST https://<target>/rpc -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"system.listMethods","id":1}' | jq
```

**Gotcha**: `rpc.discover` returns a full OpenRPC schema (every method + params) when supported — the JSON-RPC equivalent of introspection; JSON-RPC also supports array batching, the same rate-limit-bypass lever as GraphQL aliasing.

### XML-RPC

**Pattern**: `POST` `<methodCall><methodName>system.listMethods</methodName><params/></methodCall>`; common at `/xmlrpc.php` (WordPress), `/RPC2`, `/xmlrpc`.

```bash
curl -s https://<target>/xmlrpc.php -H 'content-type: text/xml' \
  --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
```

**Gotcha**: `system.listMethods` enumerates every method; the historical WordPress `pingback.ping` (SSRF/port-scan) and `system.multicall` (amplified brute-force) live here — XML-RPC is a parser (XXE surface) and an amplification lever at once.

### SOAP

**Pattern**: WSDL at `?wsdl`, `<endpoint>?wsdl`, `/services/<Service>?wsdl`, `/soap/`. The WSDL enumerates every operation, its SOAP action, and message schemas.

```bash
curl -s "https://<target>/service?wsdl" | grep -oiE '<(operation|wsdl:operation)[^>]*name="[^"]+"'
```

**Gotcha**: the WSDL is a complete operation contract — parse it for every method and its parameters; SOAP bodies are XML (XXE surface), and `soapAction` header routing sometimes reaches operations the WSDL marks internal.

## WebSocket and Real-Time

Real-time surface is routinely omitted from threat models. Find the endpoint, identify the protocol, then enumerate the messages/channels/topics it accepts.

### WebSocket endpoint discovery

**Patterns** in bundles: `ws://`/`wss://` URLs; common paths `/ws`, `/websocket`, `/socket.io/`, `/api/ws`, `/realtime`, `/cable` (Rails ActionCable), `/live` (Phoenix LiveView), `/hub` (SignalR).

```bash
grep -rhoE 'wss?://[^"'"'"' ]+|["'"'"'](/(ws|websocket|socket\.io|realtime|cable|live|hub)[^"'"'"' ]*)' bundles/ | sort -u
websocat -v wss://<target>/ws     # connect and observe
```

**Gotcha**: bundle-mine the WS URL and any first-message auth/subscribe shape alongside it — the connect URL alone is not enough; the app's client code shows the handshake the server expects.

### Socket.IO

**Fingerprint** (verified): `GET /socket.io/?EIO=4&transport=polling` returns the Engine.IO handshake `{"sid":"...","upgrades":["websocket"],"pingInterval":...}`. `EIO=4` = Engine.IO v4 = Socket.IO v3+; `EIO=3` = Socket.IO v2 (different framing).

```bash
curl -s "https://<target>/socket.io/?EIO=4&transport=polling" ; echo
```

**Gotcha**: the `EIO` version determines the framing and exploitation approach; Socket.IO **namespaces** (`/<namespace>`) and rooms are separate surfaces — enumerate namespaces from the client code, each may have distinct auth.

### SockJS

**Pattern**: `GET /<prefix>/info` returns `{"websocket":true,"origins":["*:*"],...}`; SockJS wraps WS with HTTP fallbacks.

```bash
curl -s https://<target>/sockjs/info ; echo
```

**Gotcha**: `origins:["*:*"]` in the SockJS info is a cross-origin-WebSocket (CSWSH) lead; SockJS's HTTP-fallback transports (xhr-streaming) are reachable even where raw WS is blocked.

### STOMP over WebSocket

STOMP frames (`CONNECT`, `SUBSCRIBE`, `SEND`) over WS, common with Spring/RabbitMQ. Topic/queue destinations (`/topic/*`, `/queue/*`, `/app/*`, `/user/*`) are the surface.

**Gotcha**: a STOMP broker that lets a client `SUBSCRIBE` to `/topic/#` or another user's `/user/<id>/*` destination leaks cross-user messages — enumerate destinations from the client code.

### GraphQL subscriptions over WebSocket

Covered above (graphql-ws `graphql-transport-ws` vs legacy `graphql-ws` subprotocol). Enumerate subscription operations from the recovered schema; the WS auth is frequently weaker than the HTTP query endpoint.

### Server-Sent Events (SSE)

**Signal**: `Content-Type: text/event-stream`. **Paths**: `/events`, `/stream`, `/api/stream`, `/updates`, `/sse`, `/notifications`.

```bash
curl -sN https://<target>/events -H 'Accept: text/event-stream' | head -5
```

**Gotcha**: SSE is one-directional server→client and often forgotten in auth review — an SSE stream that pushes events for resources the caller shouldn't see is an authorization finding; `curl -N` reads the stream.

### Framework channels — ActionCable / Phoenix / SignalR

Framework real-time layers have fixed handshakes and authorize at join/subscribe time:
- **Rails ActionCable**: `wss://<target>/cable`; subscribe with `{"command":"subscribe","identifier":"{\"channel\":\"<Channel>\"}"}`. Channel names come from `consumer.subscriptions.create` in the JS.
- **Phoenix Channels**: `wss://<target>/socket/websocket?vsn=2.0.0`; join with `["<ref>","<ref>","<topic>","phx_join",{}]`. Topics (`room:*`, `user:<id>`) come from the JS.
- **SignalR**: `POST /<hub>/negotiate?negotiateVersion=1` returns a `connectionToken`, then `wss://<target>/<hub>?id=<token>`. Hub/method names come from `connection.invoke("<Method>")`.

```bash
curl -s -X POST "https://<target>/hub/negotiate?negotiateVersion=1" | jq   # SignalR: transports + auth requirement
curl -s -o /dev/null -w '%{http_code}\n' "https://<target>/socket/websocket?vsn=2.0.0"   # Phoenix liveness
```

**Gotcha**: authorization is enforced per channel/topic/hub at join time — enumerate the names from the client and test joining ones you should not (another user's `user:<id>` topic, an admin channel). SignalR `negotiate` leaks the available transports and often whether auth is required.

### WebSocket subprotocol enumeration

The `Sec-WebSocket-Protocol` offer reveals accepted subprotocols; the server echoes the one it selects.

```bash
websocat -H='Sec-WebSocket-Protocol: graphql-transport-ws, wamp, mqtt, stomp' wss://<target>/ws -v 2>&1 | grep -i protocol
```

**Gotcha**: the echoed subprotocol names the real protocol (WAMP, MQTT-over-WS, STOMP, graphql-transport-ws) — fingerprint it before sending messages, since each has a distinct enumeration approach.

### WAMP

WAMP (Web Application Messaging Protocol) runs RPC + pub/sub over WebSocket (subprotocol `wamp.2.json`). After HELLO/WELCOME, `CALL` invokes procedures and `SUBSCRIBE` joins topics, both by URI.

**Gotcha**: a WAMP router that lets a client `CALL` arbitrary procedure URIs or `SUBSCRIBE` to wildcard topics leaks cross-component RPC and events — enumerate procedure/topic URIs from the client code; the `wamp.2.json` subprotocol echoed in the handshake identifies it.

### WebSocket authentication patterns

Query-string token (`wss://<t>/ws?token=<jwt>`), cookie-based (session cookie sent on the Upgrade), header-based, or first-message auth (`{"type":"auth","token":"..."}`). Each has a different surface.

**Gotcha**: WS auth usually happens **once, at connection**; after the Upgrade, messages are frequently trusted with no per-message authorization — the core WebSocket testing insight. A token in the query string also leaks to logs/referrers.

### WebSocket message enumeration

Once connected, probe accepted message types.

```bash
# wsrepl (Doyensec) is an interactive REPL for this; wscat/websocat for one-offs
echo '{"type":"subscribe","channel":"*"}' | websocat wss://<target>/ws
echo '{"type":"list"}' | websocat wss://<target>/ws
```

**Gotcha**: send `{"type":"subscribe","channel":"*"}` / `{"action":"list"}` / an empty/`ping` frame and read the error or response — servers routinely reflect the accepted message schema in validation errors, enumerating the message API.

### WebSocket tooling

`wscat` (`wscat -c wss://…`), `websocat` (scriptable, subprotocol/header control), `wsrepl` (Doyensec — interactive REPL with auto-reconnect and fuzzing), Burp's WebSocket history/repeater. Prefer `websocat` for scripted enumeration.

## WebRTC Signaling

WebRTC's ICE configuration and signaling live in the client, and its peer connections bypass TLS-terminating proxies.

### ICE configuration discovery

The `new RTCPeerConnection({iceServers:[...]})` config in the bundle lists every STUN/TURN server and, often, TURN credentials.

```bash
grep -rhoE '"?iceServers"?\s*:|(stun|turns?):[^"'"'"' ,]+|"(credential|username)"\s*:' bundles/ | sort -u
```

**Gotcha**: the `iceServers` array is the WebRTC infrastructure inventory in one place — an org-hosted `turn.<target>.com` is target infrastructure, and any `credential` next to it is a leaked TURN account (below).

### STUN / TURN enumeration

**Pattern**: `iceServers` config in JS bundles — `stun:` and `turn:`/`turns:` URIs, often with `username`/`credential`.

```bash
grep -rhoE '(stun|turns?):[a-z0-9._:-]+|"(urls|username|credential)"\s*:' bundles/ | sort -u
```

**Gotcha**: TURN credentials (`username`/`credential`) frequently leak in the bundle — a working TURN account is a relay you can abuse (bandwidth, and sometimes internal-network relaying via TURN's allocation to internal IPs). An org-hosted STUN/TURN (`turn.<target>.com`) is target infrastructure, not a public server.

### Signaling protocol enumeration

Signaling rides a separate channel — usually a WebSocket (custom JSON), or Matrix/XMPP/SIP-over-WebSocket.

**Gotcha**: identify the signaling channel (it is a WebSocket surface, enumerate per above) — it carries the offer/answer/ICE-candidate messages and often the room/call authorization logic; a signaling server that lets you join arbitrary rooms is the finding.

### Direct peer-connection detection

WebRTC establishes peer-to-peer media/data channels that bypass the CDN and TLS proxy.

**Gotcha**: the ICE candidates exchanged during signaling reveal actual peer IPs (server-reflexive and host candidates) — a way to unmask origin/peer IPs behind a CDN; capture the candidates from the signaling channel.

## API Contract Analysis

The fastest route to the full surface is the contract the developers already wrote — recover it before brute-forcing.

### OpenAPI schema discovery

**Patterns**: `/openapi.json`, `/openapi.yaml`, `/swagger.json`, `/v3/api-docs` (springdoc), `/v2/api-docs` (older Springfox), `/api/openapi.json`, `/api-docs`, `/swagger/v1/swagger.json` (.NET). Version indicator: `openapi: 3.0.x` vs `3.1.x` (3.1 aligns with JSON Schema).

```bash
for p in /openapi.json /swagger.json /v3/api-docs /api-docs /swagger/v1/swagger.json /openapi.yaml; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
```

**Confirm**: a `200` with a top-level `"openapi"` or `"swagger"` key is the full contract. Load it into any client generator to enumerate every operation.

### OpenAPI schema mining

```bash
curl -s https://<target>/openapi.json | jq -r '.paths | to_entries[] | .key as $p | .value | keys[] | "\(.|ascii_upcase) \($p)"'   # every method+path
curl -s https://<target>/openapi.json | jq -r '.components.schemas | to_entries[] | .key + ": " + ([.value.properties?|keys[]?]|join(","))'   # every field
curl -s https://<target>/openapi.json | jq '.components.securitySchemes'   # auth model
```

**Gotcha**: `components.schemas` lists request/response fields the UI never shows — the fastest hidden-parameter and hidden-field discovery there is; `securitySchemes` reveals the auth model (API-key header name, OAuth scopes) to route to `auth_multiservice_deep`.

### Swagger UI / Redoc / Stoplight exposure

**Patterns**: `/swagger`, `/swagger-ui.html` (springdoc), `/swagger-ui/`, `/redoc`, `/docs` (FastAPI), `/api/docs`, `/scalar` (Scalar). Each renders the same schema; the UI's JS reveals the schema URL if the well-known paths 404.

```bash
curl -s https://<target>/docs | grep -oiE 'swagger|redoc|openapi\.json|api-docs|scalar'
```

**Gotcha**: FastAPI's `/docs` (Swagger) and `/redoc` are on by default and frequently left in production — they hand you the schema and a request runner; the page source names the exact `/openapi.json` URL when the guessed paths miss.

### Postman / Insomnia / client exports

**Patterns**: `*.postman_collection.json`, `*.postman_environment.json`, `.insomnia.{yaml,json}`, `*.bru` (Bruno) — in source repos, gists, or exposed on the target.

```bash
grep -rhoE '[A-Za-z0-9_.-]*\.postman_collection\.json|\.insomnia\.(yaml|json)' . 2>/dev/null | sort -u
# public repos:  gh search code "org:<org> extension:postman_collection.json"
```

**Gotcha**: a committed Postman collection is a documented request set *including example auth headers and tokens* — grep source and public repos for it before enumerating manually.

### OData `$metadata`

OData services expose a full entity model at `<service>/$metadata` (XML/CSDL) — every entity set, property, navigation, and function — the OData equivalent of an OpenAPI schema.

```bash
curl -s "https://<target>/odata/\$metadata" | grep -oiE '<(EntitySet|FunctionImport|ActionImport)[^>]*Name="[^"]+"'
curl -s "https://<target>/odata/" | jq '.value[].name' 2>/dev/null   # service document lists entity sets
```

**Gotcha**: `$metadata` enumerates the entire data model including entity sets not linked in the UI, and OData's `$expand`/`$filter`/`$select` (above) then reach them — a complete backend object map for free.

### AsyncAPI contracts

**Patterns**: `asyncapi.{json,yaml}` in source or served — the OpenAPI equivalent for event-driven APIs (WebSocket, SSE, Kafka, MQTT, AMQP).

**Gotcha**: an AsyncAPI doc enumerates every channel, message schema, and operation for the real-time surface above — the contract that maps the WebSocket/SSE/broker API a proxy view can't.

### Schema files in source

**Patterns**: `*.graphql` / `schema.graphql` (GraphQL SDL), `*.apib` (API Blueprint), `*.raml`, `*.proto` (gRPC), `openapi.{yaml,json}` committed to the repo.

**Gotcha**: the checked-in schema is the authoritative contract — often ahead of what's deployed (new operations not yet live) and behind what's removed (deprecated ones still in git history; cross to `asset_discovery_historical_deep`).

### HAR file analysis

`.har` (HTTP Archive) files capture full browser sessions — every request, response, header, and token.

```bash
grep -rhoE '[A-Za-z0-9_.-]+\.har' . 2>/dev/null
# gh search code "org:<org> extension:har"
jq -r '.log.entries[].request | "\(.method) \(.url)"' session.har | sort -u   # every request in a captured session
```

**Gotcha**: a committed or exposed `.har` is a complete request/response history including live `Authorization` headers, cookies, and API keys — treat any public `.har` as both an endpoint inventory and a credential exposure.

### Chrome DevTools protocol

**Pattern**: a dev-mode process with `--remote-debugging-port` exposes `http://localhost:9222/json` (and `/json/version`) — the CDP target list.

```bash
curl -s http://localhost:9222/json | jq -r '.[].url'   # only reachable from the host / via SSRF
```

**Gotcha**: reachable only locally or via SSRF, but a headless-Chrome/Electron backend with the debug port bound to `0.0.0.0` (misconfiguration) is remote code execution via CDP — note it as an SSRF-chain target (route to `ssrf`).

### API changelog and versioning docs

**Patterns**: `/changelog`, `/api/changes`, `/api-changelog`, `CHANGELOG.md` in source, `/docs/changelog`.

**Gotcha**: an API changelog names deprecated-but-still-live endpoints and parameters and dates when auth/behavior changed — a map to the un-migrated surface (cross to `asset_discovery_historical_deep` for the historical angle).

## Advanced Detection Techniques

When the contract is hidden and reflection is off, differential and structural techniques recover surface.

### Timing-based endpoint enumeration

Some frameworks dispatch existing routes faster than 404s (route-table lookup + handler vs error path). Statistical timing separates real routes from a uniform 404.

```bash
ffuf -u https://<target>/api/FUZZ -w wordlist.txt -p 0.1 -o timing.json   # -p adds delay; compare time_total across hits
```

**Gotcha**: a consistent time delta between a known-good and known-404 path is a timing oracle — useful where status codes are uniform (everything returns 200 or a generic 404); confirm with repeated samples to beat jitter.

### Response-differential parameter discovery

Send with a parameter, without it, and with a junk value; diff responses. This is how `x8`/`arjun` find unlinked parameters.

```bash
x8 -u https://<target>/api/users -w params.txt    # response-differential parameter mining
```

**Gotcha**: a parameter that changes the response length/shape but isn't in any form or doc is a hidden input — often the highest-value one (a `debug`, `admin`, `include`, `fields` toggle).

### Header-based endpoint variants

The same URL routes differently on `User-Agent`, `Accept-Language`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-API-Version`, `X-Tenant` — feature flags, canary backends, tenant routing.

```bash
for h in 'X-API-Version: 2' 'X-Forwarded-Host: internal' 'X-Tenant: admin'; do
  echo "== $h =="; curl -s https://<target>/api/config -H "$h" -o /dev/null -w '%{size_download}\n'; done
```

**Gotcha**: a differing response on `X-Forwarded-Host`/`X-Forwarded-For` indicates the frontend proxy routes or trusts those headers — a routing-bypass and SSRF/host-injection lead (route to `ssrf`/`header_injection`).

### Method-override header abuse

`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, or `_method=DELETE` (form field) make a POST reach a DELETE/PUT handler — reaching methods a WAF or gateway blocks on the real verb.

```bash
curl -s -X POST https://<target>/api/users/1 -H 'X-HTTP-Method-Override: DELETE' -o /dev/null -w '%{http_code}\n'
```

**Gotcha**: an override header that reaches the DELETE handler when a direct `DELETE` is blocked is both a hidden-method discovery and a WAF/gateway bypass.

### Path-normalization variants

`/api//users`, `/api/./users`, `/api/users/`, `/api/users;.json` (matrix param), `/api/users%2e`, `/api/users%20`, `/api/users%00`, `/api/users#` may hit different code paths or bypass path-based access controls.

```bash
for p in '/api/users' '/api//users' '/api/./users' '/api/users/' '/api/users%2f' '/api/users;a=1'; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' "https://<target>$p")"; done
```

**Gotcha**: a normalization difference between the proxy/gateway and the app (`//`, `/./`, `%2e`, trailing slash, matrix params) is the basis for path-based auth bypass — load `path_traversal_lfi_rfi` for the normalization table and route access-control differentials there.

### Content-encoding handling

The same endpoint with `Content-Encoding: gzip`/`deflate`/`br` on the *request* body — some backends decompress and parse differently, and a decompression bomb is a DoS lead.

**Gotcha**: a backend that accepts and decompresses a request `Content-Encoding` is a zip-bomb DoS surface and occasionally parses the decompressed body through a different validator than the plain one.

## Tooling and Command Reference

- **REST**: `arjun`, `paramspider`, `x8` (parameter mining); `kiterunner` (`kr scan` — API-route bruteforce with Kitebuilder wordlists built from OpenAPI/Swagger corpora; established, low recent maintenance — pair with `ffuf` + the actively-maintained `assetnote/wordlists` API lists).
- **GraphQL**: `graphw00f` (engine fingerprint), `clairvoyance` (schema reconstruction), `graphql-cop` (audit), GQLSpection / InQL (Burp), Assetnote BatchQL, graphql-voyager (visualize).
- **gRPC**: `grpcurl` (list/describe/invoke), `evans` (REPL), `ghz` (traffic), `grpcui`/`bloomrpc` (GUI); `buf` (export schemas from the Buf Schema Registry).
- **WebSocket**: `websocat` (scriptable), `wscat`, `wsrepl` (Doyensec REPL), Burp WebSocket tools.
- **Contract analysis**: `spectral` (OpenAPI lint — surfaces undocumented/loose schema), `openapi-diff` (version drift), `swagger-codegen`/`openapi-generator` (generate a client to enumerate operations), `postman-to-openapi` / `Newman` (run a discovered Postman collection).

Install any tool not present at runtime. Never replay a live token recovered from a HAR/Postman export — record its presence, location, and scope only.

## What Deep API Recon Completeness Looks Like

API recon is done only when:

- Every API technology in use is identified (REST / GraphQL / gRPC(-web) / Connect / tRPC / JSON-RPC / SOAP / WebSocket / SSE / WebRTC)
- Each technology's schema-recovery interface has been run: OpenAPI schema fetched, GraphQL introspected or reconstructed, gRPC reflection listed, tRPC router mapped, WSDL/`rpc.discover` pulled
- The full operation set is enumerated from the recovered contract — every REST method×path×version, every query/mutation/subscription, every gRPC service/method, every tRPC procedure
- Endpoint variants are tested (methods, content-types, versions, path-normalization, header-routed backends)
- The real-time surface is enumerated (WebSocket message/channel API, SSE streams, GraphQL subscriptions, WebRTC signaling)
- Federation/batch surfaces are checked (`_service`/`_entities`, GraphQL/JSON-RPC batching, tRPC batch, subgraph-direct access)

Only then scope hunters to API-specific classes: field/operation authorization (GraphQL, gRPC, tRPC), IDOR on REST/tRPC object references, batch/alias rate-limit bypass, subscription and depth-based DoS, and the parser-differential surface (content-type/XXE, path normalization).

## Pro Tips

1. Fingerprint the API technology before enumerating — GraphQL, gRPC, and tRPC each have a schema-recovery interface that beats any amount of route brute-forcing.
2. GraphQL introspection being disabled does not make the schema secret — `clairvoyance` reconstructs it from "Did you mean" suggestions, and Apollo's `_service{sdl}` returns it outright.
3. Hit GraphQL subgraphs directly, not just the federation gateway — the subgraph often skips the router's auth and `_entities` resolves arbitrary objects across the graph.
4. gRPC-web looks like ordinary binary POSTs in a proxy until you check `content-type: application/grpc-web*` — the path segment names the service and method directly.
5. tRPC batch endpoints frequently bypass per-procedure middleware — test procedures individually *and* batched.
6. WebSocket auth usually happens once at connection — after the Upgrade, messages are commonly trusted with no per-message authorization.
7. OpenAPI schemas (`/v3/api-docs`, `/openapi.json`) and FastAPI `/docs` reveal fields and endpoints the UI never shows — the fastest hidden-parameter discovery.
8. Server-Sent Events and WebRTC signaling are routinely absent from threat models — an SSE stream leaking unauthorized events, and TURN creds leaking in the bundle, are common misses.
9. HAR and Postman files committed to source or exposed on the target are complete request histories with live tokens — grep for `.har` and `.postman_collection.json` first.

## Summary

This deep sibling to `application_enumeration` maps API surface by technology: REST depth (versions/methods/content-types/batch/diagnostics), GraphQL (introspection, reconstruction, federation, subscriptions), gRPC/protobuf (reflection, gRPC-web, Connect), tRPC and JSON-RPC/SOAP, WebSocket/SSE real-time, WebRTC signaling, and the API contract (OpenAPI/GraphQL-schema/protobuf/HAR). It loads only in deep mode. Completeness means every API technology is fingerprinted, its schema recovered, and its full operation set enumerated before API hunters are scoped. Companion deep siblings `application_enumeration_client_deep` (client/JS ecosystem) and `application_enumeration_auth_multiservice_deep` (auth, multi-service, AI/ML) cover the adjacent surface.
