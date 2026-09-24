---
name: supabase
description: Supabase security testing covering Row Level Security and RLS bypass via views (security_invoker), PostgREST, SECURITY DEFINER RPCs, pg_net/http extension SSRF, pg_graphql, Edge Functions, pgsodium and Vault, and service_role key exposure
---

# Supabase

Security testing for Supabase applications. Focus on mis-scoped Row Level Security (RLS), unsafe RPCs, leaked `service_role` keys, lax Storage policies, and Edge Functions trusting headers without binding to issuer/audience/tenant.

## Attack Surface

**Data Access**
- PostgREST: table CRUD, filters, embeddings, RPC (remote functions)
- GraphQL: pg_graphql over Postgres schema with RLS interaction
- Realtime: replication subscriptions, broadcast/presence channels

**Storage**
- Buckets, objects, signed URLs, public/private policies

**Authentication**
- Auth (GoTrue): JWTs, cookie/session, magic links, OAuth flows

**Server-Side**
- Edge Functions (Deno): server-side code calling Supabase with secrets

## Architecture

**Endpoints**
- REST: `https://<ref>.supabase.co/rest/v1/<table>`
- RPC: `https://<ref>.supabase.co/rest/v1/rpc/<fn>`
- Storage: `https://<ref>.supabase.co/storage/v1`
- GraphQL: `https://<ref>.supabase.co/graphql/v1`
- Realtime: `wss://<ref>.supabase.co/realtime/v1`
- Auth: `https://<ref>.supabase.co/auth/v1`
- Functions: `https://<ref>.functions.supabase.co/`

**Headers**
- `apikey: <anon-or-service>` — identifies project
- `Authorization: Bearer <JWT>` — binds user context

**Roles**
- `anon`, `authenticated` — standard roles
- `service_role` — bypasses RLS, must never be client-exposed

**Key Principle**
`auth.uid()` returns current user UUID from JWT. Policies must never trust client-supplied IDs over server context.

## High-Value Targets

- Tables with sensitive data (users, orders, payments, PII)
- RPC functions (especially `SECURITY DEFINER`)
- Storage buckets with private files
- Edge Functions with `service_role` access
- Export/report endpoints generating signed outputs
- Admin/staff routes and privilege-granting endpoints

## Reconnaissance

**Enumerate Surfaces**
```
/rest/v1/<table>
/rest/v1/rpc/<fn>
/storage/v1/object/public/<bucket>/
/storage/v1/object/list/<bucket>?prefix=
/graphql/v1
/auth/v1
```

**Obtain Principals**
- Unauthenticated (anon key only)
- Basic user A, user B
- Admin/staff (if available)
- Check if `service_role` key leaked in client bundle or Edge Function responses

## Key Vulnerabilities

### Row Level Security (RLS)

Enable RLS on every non-public table; absence or "permit-all" policies → bulk exposure.

**Common Gaps**
- Policies check `auth.uid()` for SELECT but forget UPDATE/DELETE/INSERT
- Missing tenant constraints (`org_id`/`tenant_id`) allow cross-tenant access
- Policies rely on client-provided columns (`user_id` in payload) instead of JWT
- Complex joins where policy is applied after filters, enabling inference via counts

**Tests**
```bash
# Compare row counts for two users
GET /rest/v1/<table>?select=*&Prefer=count=exact

# Cross-tenant probe
GET /rest/v1/<table>?org_id=eq.<other_org>
GET /rest/v1/<table>?or=(org_id.eq.other,org_id.is.null)

# Write-path
PATCH /rest/v1/<table>?id=eq.<foreign_id>
DELETE /rest/v1/<table>?id=eq.<foreign_id>
POST /rest/v1/<table> with foreign owner_id
```

**RLS bypass via views (`security_invoker`).** A Postgres **view runs with the
view owner's privileges by default** — and Supabase tables/views are owned by
the `postgres` superuser, who **bypasses RLS**. So a view over an RLS-protected
table returns *every* row to any role that can query the view, unless it was
created `WITH (security_invoker=true)` (PG15+). Measured locally (PG18):
```
alice on the table directly (RLS)         -> alice            (RLS applies)
alice on a default view over the table    -> alice,bob        (RLS BYPASSED)
alice on a WITH(security_invoker=true) view-> alice            (RLS applies)
```
This is a top Supabase footgun: a dev creates a "convenience" view (or a
reporting/join view) exposed to `anon`/`authenticated` via PostgREST
(`/rest/v1/<view>`), and it silently leaks the whole underlying table. Enumerate
views (`/rest/v1/` reflects them like tables; or read `information_schema.views`
via an RPC) and query each as a low-priv principal — a view returning rows the
base table's RLS would deny is the finding. The fix is `security_invoker=true`
on every view over an RLS table.

### PostgREST & REST

**Filters**
- `eq`, `neq`, `lt`, `gt`, `ilike`, `or`, `is`, `in`
- Embed relations: `select=*,profile(*)`—exploits overfetch if resolvers skip per-row checks
- Search leaks: generous `LIKE`/`ILIKE` filters combined with missing RLS → mass disclosure via wildcard queries

**Headers**
- `Prefer: return=representation` — echo writes
- `Prefer: count=exact` — exposure via counts
- `Accept-Profile`/`Content-Profile` — select schema

**IDOR Patterns**
```
/rest/v1/<table>?select=*&id=eq.<other_id>
/rest/v1/<table>?select=*&slug=eq.<other_slug>
/rest/v1/<table>?select=*&email=eq.<other_email>
```

**Mass Assignment**
- If RPC not used, PATCH can update unintended columns
- Verify restricted columns via database permissions/policies

### RPC Functions

RPC endpoints map to SQL functions. `SECURITY DEFINER` bypasses RLS unless carefully coded; `SECURITY INVOKER` respects caller.

**Anti-Patterns**
- `SECURITY DEFINER` + missing owner checks → vertical/horizontal bypass
- `set search_path` left to public; function resolves unsafe objects
- Trusting client-supplied `user_id`/`tenant_id` rather than `auth.uid()`

**Tests**
```bash
# Call as different users with foreign IDs
POST /rest/v1/rpc/<fn> {"user_id": "<foreign_id>"}

# Remove JWT entirely
Authorization: Bearer <anon_token>
```
Verify functions perform explicit ownership/tenant checks inside SQL.

### pg_net / http Extension SSRF

Supabase ships `pg_net` (async HTTP from Postgres) and sometimes `http`
(pgsql-http). Any RPC/function/trigger that fetches a **user-controlled URL** is
SSRF **from the database host**, which sits inside Supabase's infrastructure and
can reach cloud metadata and internal services:
```bash
# an RPC that calls net.http_get(url)/net.http_post(...) or http_get(url)
POST /rest/v1/rpc/<fn>  {"url":"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"}
POST /rest/v1/rpc/<fn>  {"url":"http://localhost:5432/"}   # internal reach
```
- `pg_net` is **async** — responses land in `net._http_response`. If that table
  is readable (or the RPC returns the request id and another RPC reads the
  response), the SSRF is not blind; otherwise use OAST.
- **Database webhooks / triggers** built on `pg_net` fetch a URL derived from a
  row column; insert a row with an attacker URL to trigger the outbound request.
- Load `ssrf` for the metadata/bypass catalog; the novelty here is that the
  request originates from Postgres, not an app server.

### Storage

**Buckets**
- Public vs private; objects in `storage.objects` with RLS-like policies

**Misconfigurations**
```bash
# Public bucket with sensitive data
GET /storage/v1/object/public/<bucket>/<path>

# List prefixes without auth
GET /storage/v1/object/list/<bucket>?prefix=

# Signed URL reuse across tenants/paths
```

**Content-Type Abuse**
- Upload HTML/SVG served as `text/html` or `image/svg+xml`
- Verify `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`

**Path Confusion**
- Mixed case, URL-encoding, `..` segments may be rejected at UI but accepted by API
- Test path normalization differences between client validation and server handling

### Realtime

**Endpoint**: `wss://<ref>.supabase.co/realtime/v1`

**Risks**
- Channel names derived from table/schema/filters leaking other users' updates when RLS or channel guards are weak
- Broadcast/presence channels allowing cross-room join/publish without auth

**Tests**
- Subscribe to `public:realtime` changes on protected tables; confirm visibility aligns with RLS
- Attempt joining other users' channels: `room:<user_id>`, `org:<org_id>`

### GraphQL

**Endpoint**: `/graphql/v1` using pg_graphql with RLS

**Risks**
- Introspection reveals schema relations
- Overfetch via nested relations where resolvers skip per-row ownership checks
- Global node IDs leaked and reusable via different viewers

pg_graphql runs **inside Postgres** and reflects the schema of whatever role
queries it, so it *inherits* RLS — it is not usually a separate authorization
engine. The gaps are where the SQL layer already leaks:
- **`nodeId`** is a base64-encoded array `[schema, table, ...pk]`; decode and
  swap the pk to reference other rows (RLS still gates it — but a table with
  weak/absent RLS is now enumerable by node id too).
- **Views and functions exposed to GraphQL** — a `security_invoker=false` view
  (above) surfaced as a GraphQL type bypasses RLS through GraphQL exactly as it
  does through REST; and `SECURITY DEFINER` functions exposed as GraphQL fields
  run with elevated rights.
- **REST vs GraphQL parity** — a policy fix applied to the REST path may not be
  reflected if a computed field/relationship takes a different SQL route; diff
  the two for the same principal.
- pg_graphql is reached via the `graphql.resolve(query, variables)` RPC too —
  callable at `/rest/v1/rpc/graphql` on some setups.

**Tests**
- Compare REST vs GraphQL responses for same principal and query shape
- Query deep nested fields; verify RLS holds at each edge
- Decode `nodeId`, swap pk/schema/table, and query as a low-priv principal

### Vault / pgsodium

Supabase **Vault** stores secrets encrypted with **pgsodium**; the plaintext is
exposed through the **`vault.decrypted_secrets` view**. Because that is a *view*
(see the `security_invoker` bypass above) and secrets are high-value, verify who
can read it:
- A role granted `SELECT` on `vault.decrypted_secrets` (or a
  `SECURITY DEFINER` RPC that reads it) gets **plaintext secrets** — API keys,
  webhook signing secrets, service credentials. Test `anon`/`authenticated`
  against it and any RPC that returns a secret.
- pgsodium key ids / server key access: a role that can call the pgsodium
  decrypt functions or read the key table can decrypt column-encrypted data.
- Confirm Vault secrets are not surfaced through a convenience view/RPC exposed
  to client roles — the classic mistake.

### Auth & Tokens

GoTrue issues JWTs with claims (`sub=uid`, `role`, `aud=authenticated`).

**Verification Requirements**
- Issuer, audience, expiration, signature, tenant context

**Pitfalls**
- Storing tokens in localStorage → XSS exfiltration
- Treating `apikey` as identity (it's project-scoped, not user identity)
- Exposing `service_role` key in client bundle or Edge Function responses
- Refresh token mismanagement leading to long-lived sessions beyond intended TTL

**Tests**
- Replay tokens across services; check audience/issuer pinning
- Try downgraded tokens (expired/other audience) against custom endpoints

### Edge Functions

Deno-based functions often initialize Supabase client with `service_role`.

**Risks**
- Trusting Authorization/apikey headers without verifying JWT against issuer/audience
- CORS: wildcard origins with credentials; reflected Authorization in responses
- SSRF via fetch; secrets exposed via error traces or logs

**Tests**
- Call functions with and without Authorization; compare behavior
- Try foreign resource IDs in payloads; verify server re-derives user/tenant from JWT
- Attempt to reach internal endpoints (metadata services) via function fetch

### Tenant Isolation

Ensure every query joins or filters by `tenant_id`/`org_id` derived from JWT context, not client input.

**Tests**
- Change subdomain/header/path tenant selectors while keeping JWT tenant constant
- Export/report endpoints: confirm queries execute under caller scope

## Bypass Techniques

- Content-type switching: `application/json` ↔ `application/x-www-form-urlencoded` ↔ `multipart/form-data`
- Parameter pollution: duplicate keys in JSON/query (PostgREST chooses last/first depending on parser)
- GraphQL+REST parity probing: protections often drift; fetch via the weaker path
- Race windows: parallel writes to bypass post-insert ownership updates

## Blind Enumeration

- Use `Prefer: count=exact` and ETag/length diffs to infer unauthorized rows
- Conditional requests (`If-None-Match`) to detect object existence
- Storage signed URLs: timing/length deltas to map valid vs invalid tokens

## Testing Methodology

1. **Inventory surfaces** - Map REST, Storage, GraphQL, Realtime, Auth, Functions endpoints
2. **Obtain principals** - Collect tokens for anon, user A/B, admin; check for `service_role` leaks
3. **Build matrix** - Resource × Action × Principal
4. **REST vs GraphQL** - Test both to find parity gaps
5. **Seed IDs** - Start with list/search endpoints to gather IDs
6. **Cross-principal** - Swap IDs, tenants, and transports across principals

## Tooling

- PostgREST: httpie/curl + jq; enumerate tables; fuzz filters (`or=`, `ilike`, `neq`, `is.null`)
- GraphQL: graphql-inspector, voyager; deep queries for field-level enforcement
- Realtime: custom ws client; subscribe to suspicious channels; diff payloads per principal
- Storage: enumerate bucket listing APIs; script signed URL patterns
- Auth/JWT: jwt-cli/jose to validate audience/issuer; replay against Edge Functions
- Policy diffing: maintain request sets per role; compare results across releases

## Validation Requirements

- Owner vs non-owner requests for REST/GraphQL showing unauthorized access (content or metadata)
- Mis-scoped RPC or Storage signed URL usable by another user/tenant
- Realtime or GraphQL exposure matching missing policy checks
- Minimal reproducible requests with role contexts documented
