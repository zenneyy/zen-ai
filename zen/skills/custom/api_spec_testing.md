---
name: api_spec_testing
description: Spec-driven API pentesting — systematically exercise every endpoint from an ingested OpenAPI/Swagger/Postman inventory for authz, injection, and business-logic flaws
---

# API Spec Testing

When a target is an API specification (OpenAPI 3.x, Swagger 2.0, or a Postman
collection), the root task lists it under **API Specifications** with the path
to the spec file in the workspace and the authorized base URL(s). Read the spec
file first and build your own endpoint inventory from it — every operation with
its method, path, parameters, request-body schema (resolve `$ref`/`allOf`), and
auth scheme. Do not rediscover the surface by crawling. Walk the inventory
operation-by-operation and prove findings against the live base URL(s), which
are authorized in scope.

## Methodology

**1. Baseline the contract.** For each endpoint, send a well-formed request that
matches the declared schema and record the normal response (status, shape,
auth requirement). This baseline is what every abuse case is compared against.

**2. Enumerate coverage.** Track every `METHOD path` in the inventory and mark it
tested. Undocumented-but-implied siblings are worth probing too (e.g. if
`GET /users/{id}` exists, try `PUT`/`DELETE`/`PATCH` on the same path even when
the spec omits them — specs routinely under-document write operations).

**3. Prioritize by risk.** Object-scoped reads/writes, exports, admin/staff
operations, and anything touching billing, auth, or PII first.

## Resolving the Spec

A half-resolved spec hides the exploitable surface. Fully dereference it
before testing — `$ref`, composition keywords, and the auth block each carry
attack signal.

- **`$ref`** — local (`#/components/schemas/User`), remote-file, and recursive.
  Follow every one; a body schema that is just `{"$ref": "..."}` is opaque
  until resolved. Flatten with a resolver:
  ```bash
  # dereference OpenAPI to a single self-contained doc
  npx @redocly/cli bundle --dereferenced spec.yaml -o spec.deref.json
  # or list every operation with method, path, and security
  jq -r '.paths | to_entries[] as $p | $p.value | to_entries[] |
    "\(.key|ascii_upcase) \($p.key)  sec=\(.value.security // "inherit")"' spec.deref.json
  ```
- **`allOf` / `oneOf` / `anyOf` / `discriminator`** — `allOf` *merges* schemas,
  so the real accepted body is the union of all members (extra writable fields
  hide here). `oneOf`/`anyOf` + `discriminator` mean multiple body shapes are
  accepted for one endpoint — test each variant; a variant may skip a
  validation the "primary" shape enforces.
- **`additionalProperties`** — `false` means extra fields are rejected;
  **absent or `true` is a mass-assignment green light** (send `isAdmin`,
  `role`, `ownerId`). This one keyword decides whether mass assignment is even
  possible — check it per body schema.
- **`readOnly` / `writeOnly`** — `readOnly` fields (server-set: `id`, `role`,
  `balance`) appearing in a *response* schema are the excessive-data-exposure
  candidates; the same field, if the server does not actually enforce
  `readOnly` on input, is a mass-assignment target. `writeOnly` (passwords)
  should never appear in responses — check that it doesn't.
- **Parameter `in`** — path/query/header/cookie; header and cookie params are
  under-tested. `nullable`, `default`, and `enum` values are input hints and
  boundary seeds.

## What to test per endpoint

Test the full range of API weaknesses against each operation, driven by what the
contract reveals — do not treat the following as an exhaustive checklist. The
highest-yield classes on APIs are **authorization** flaws, since the spec hands
you the object identifiers and privilege boundaries to abuse: examples include
BOLA/IDOR (swap `{id}`/`accountId`/`tenantId` across two accounts), BFLA
(privileged operations with a lower-privilege token), and missing/broken auth
(replay with the token stripped or expired against endpoints whose declared auth
says one is required). Beyond authorization, use the declared parameters and
body schema as a launch point for mass assignment and excessive data exposure,
injection and type-confusion on every parameter, and multi-step business-logic
and rate-limit abuse — and follow the contract wherever it suggests something
else worth probing.

## Per-Method Abuse Matrix

The method tells you the highest-yield class to try first:

| Method | Try first |
|---|---|
| `GET` | BOLA/IDOR on `{id}`/`accountId`/`tenantId`; excessive data exposure (fields in the response schema beyond what the UI shows); query-param injection |
| `POST` | Mass assignment (extra fields from the merged `allOf` schema); injection in every body field; duplicate/array-shaped keys; content-type switch |
| `PUT` / `PATCH` | Mass assignment on write; IDOR-on-write (update another owner's object); JSON Merge Patch / JSON Patch `op` abuse; partial-update skipping validation |
| `DELETE` | BFLA (destructive op with a low-priv token); IDOR (delete another user's object); idempotency/replay |
| any | Method override (`X-HTTP-Method-Override`, `_method`) to reach a handler the declared method hides; **undocumented siblings** — the spec omits write ops far more than read ops |

## Auth-Scheme Extraction

`components.securitySchemes` (OpenAPI 3) / `securityDefinitions` (Swagger 2)
plus the global and per-operation `security` blocks define exactly how to
authenticate and, more usefully, where auth is *missing*:

- **Resolve each scheme**: `apiKey` (`in`: header/query/cookie + `name`),
  `http` (`bearer`/`basic`), `oauth2` (flows + `scopes`), `openIdConnect`
  (`openIdConnectUrl` → its discovery doc). Build one authenticated request per
  scheme from the baseline.
- **Per-operation overrides are the gold.** An operation with `security: []`
  **overrides global auth to public** — a declared, intentional no-auth
  endpoint that is often forgotten and privileged. Diff every operation's
  `security` against the global default and flag any that drop or downgrade it.
- **Scope gaps**: an `oauth2` operation requiring scope `admin` that the server
  accepts with a `user`-scoped token is a BFLA. Extract the declared scope per
  operation and test with a lesser token.
- Missing/broken auth: replay each secured operation with the token stripped,
  expired, or belonging to another principal (the core two-account diff).

## Schema-Driven Fuzzing

Turn each parameter/body schema into abuse inputs rather than random noise:

- **Type confusion** — send a string where `integer`/`boolean` is declared, an
  array where a scalar is, an object where a string is, and `null` on a
  non-nullable field. Type coercion downstream causes auth/logic bugs (load
  `mass_assignment` for the framework-specific coercion).
- **Boundary** — `minimum`/`maximum`, `minLength`/`maxLength`,
  `minItems`/`maxItems`: send one past each edge, plus `0`, `-1`, `MAX_INT`,
  and empty.
- **Format abuse** — `format: email/uuid/uri/date-time`: submit values that
  pass the format regex but are semantically hostile (SSRF URL, homoglyph
  email, a UUID belonging to another tenant).
- **Enum** — submit a value outside the declared `enum`; servers often trust
  the client stayed in range.
- **Structure** — omit `required` fields; add fields not in the schema (mass
  assignment); duplicate keys; send `readOnly` fields as input.

`schemathesis` automates exactly this from the OpenAPI schema (below) — but
confirm each generated hit by hand against the two-account/authz oracle.

## Non-REST Specs (GraphQL / gRPC / Postman)

- **GraphQL** — if the "spec" is an SDL or introspection result, load `graphql`
  (the canonical owner): build the type graph, then run aliased owner-vs-foreign
  queries, batching, and `_entities`/persisted-query probes. Ingest the schema,
  do not crawl.
- **gRPC** — a `.proto` / protoset or server reflection is the inventory.
  Enumerate and call methods with different tokens:
  ```bash
  grpcurl -plaintext target:443 list                         # services (reflection)
  grpcurl -plaintext target:443 list pkg.AdminService        # methods
  grpcurl -H "authorization: Bearer <low-priv>" -d '{"id":"<foreign>"}' \
    target:443 pkg.AdminService/GetUser                       # BFLA/IDOR via protobuf field
  ```
  Direct protobuf fields (`owner_id`, `tenant_id`) frequently bypass HTTP-layer
  middleware — load `broken_function_level_authorization` / `idor`.
- **Postman** — the `collection.json` is the inventory; `environment.json`
  variables and saved request examples give valid tokens/IDs to clear
  validation fast. **Pre-request scripts** often mint the auth token — read them
  to learn the auth flow, then replicate it per principal.

## Tooling

- **schemathesis** — property-based tester driven directly by the OpenAPI
  schema; finds 500s, schema-conformance breaks, and auth issues:
  ```bash
  schemathesis run spec.yaml --base-url https://target/api \
    -H "Authorization: Bearer <t>" --checks all
  ```
- **RESTler** (Microsoft) — stateful REST fuzzer: compiles the spec into a
  request grammar, then fuzzes *sequences* (create→use→delete), catching
  ordering and use-after-delete bugs a per-endpoint tool misses.
- **Kiterunner** (Assetnote) — brute-forces API routes/methods from a spec or
  its route wordlists, surfacing undocumented siblings:
  ```bash
  kr scan https://target -w routes-large.kite -A=apiroutes
  ```
- Convert the spec to raw requests for manual work: `npx openapi-to-postman`,
  or the flatten `jq` above to drive `curl`/`hurl` per operation.

## Validation

A finding is only real once reproduced against the live base URL with a
concrete request/response pair. Capture the exact HTTP request (method, path,
headers, body) and the response proving impact (another account's data, a
privileged action succeeding, an injected payload executing). Prefer two-account
diffs for authorization findings: same request, different token, unauthorized
success.

## Tips

- The base URL(s) from the spec are authorized targets — send real traffic.
- Path templates use `{param}`; substitute real values from your baseline.
- For Postman collections, saved example values and environment variables are
  strong hints for valid inputs — use them to get past validation quickly.
- Keep a running coverage table so no operation in the inventory is skipped.
