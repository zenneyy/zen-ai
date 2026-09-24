---
name: mass-assignment
description: Mass assignment testing for unauthorized field binding and privilege escalation via API parameters
---

# Mass Assignment

Mass assignment binds client-supplied fields directly into models/DTOs without field-level allowlists. It commonly leads to privilege escalation, ownership changes, and unauthorized state transitions in modern APIs and GraphQL.

## Attack Surface

- REST/JSON, GraphQL inputs, form-encoded and multipart bodies
- Model binding in controllers/resolvers; ORM create/update helpers
- Writable nested relations, sparse/patch updates, bulk endpoints

## Reconnaissance

### Surface Map

- Controllers with automatic binding (e.g., request.json → model)
- GraphQL input types mirroring models; admin/staff tools exposed via API
- OpenAPI/GraphQL schemas: uncover hidden fields or enums
- Client bundles and mobile apps: inspect forms and mutation payloads for field names

### Parameter Strategies

- Flat fields: `isAdmin`, `role`, `roles[]`, `permissions[]`, `status`, `plan`, `tier`, `premium`, `verified`, `emailVerified`
- Ownership/tenancy: `userId`, `ownerId`, `accountId`, `organizationId`, `tenantId`, `workspaceId`
- Limits/quotas: `usageLimit`, `seatCount`, `maxProjects`, `creditBalance`
- Feature flags/gates: `features`, `flags`, `betaAccess`, `allowImpersonation`
- Billing: `price`, `amount`, `currency`, `prorate`, `nextInvoice`, `trialEnd`

### Shape Variants

- Alternate shapes: arrays vs scalars; nested JSON; objects under unexpected keys
- Dot/bracket paths: `profile.role`, `profile[role]`, `settings[roles][]`
- Duplicate keys and precedence: `{"role":"user","role":"admin"}`
- Sparse/patch formats: JSON Patch/JSON Merge Patch; try adding forbidden paths

### Encodings and Channels

- Content-types: `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- GraphQL: add suspicious fields to input objects; overfetch response to detect changes
- Batch/bulk: arrays of objects; verify per-item allowlists not skipped

## Key Vulnerabilities

### Privilege Escalation

- Set role/isAdmin/permissions during signup/profile update
- Toggle admin/staff flags where exposed

### Ownership Takeover

- Change ownerId/accountId/tenantId to seize resources
- Move objects across users/tenants

### Feature Gate Bypass

- Enable premium/beta/feature flags via flags/features fields
- Raise limits/seatCount/quotas

### Billing and Entitlements

- Modify plan/price/prorate/trialEnd or creditBalance
- Bypass server recomputation

### Nested and Relation Writes

- Writable nested serializers or ORM relations allow creating or linking related objects beyond caller's scope

## Advanced Techniques

### GraphQL Specific

- Field-level authz missing on input types: attempt forbidden fields in mutation inputs
- Combine with aliasing/batching to compare effects
- Use fragments to overfetch changed fields immediately after mutation

Input-coercion depth — GraphQL coerces variables *by type* but does not
*authorize* them, so the input type is the allowlist and a loose one is the bug:
- **Model-mirroring input types** — introspect the input object
  (`__type(name:"UpdateUserInput"){inputFields{name type{name}}}`); any field
  the schema accepts (`role`, `isAdmin`, `ownerId`, `tenantId`) is bindable if
  the resolver spreads the input into the model. The schema *is* the sensitive-
  field dictionary here.
- **Nested input objects** — writable nested inputs (`user:{profile:{role:ADMIN}}`)
  reach relations the top-level type seemed to gate.
- **Default-value / `null` injection** — omit a field to take a server default,
  or send explicit `null` to blank a server-set field the resolver then
  "updates."
- **`@oneOf` inputs and enums** — coercion picks a branch; test each variant and
  out-of-range enum values the resolver may trust.
- Diff the object immediately after the mutation (a follow-up query) — effects
  persist even when the mutation's return type hides the changed field.

### ORM Framework Edges

- **Rails**: strong parameters misconfig or deep nesting via `accepts_nested_attributes_for`
- **Laravel**: $fillable/$guarded misuses; `guarded=[]` opens all; casts mutating hidden fields
- **Django REST Framework**: writable nested serializer, read_only/extra_kwargs gaps, partial updates
- **Mongoose/Prisma**: schema paths not filtered; `select:false` doesn't prevent writes; upsert defaults

### Model-Binder Edges (Spring / ASP.NET / Go)

The typed/compiled stacks have their own overposting shapes — the pattern is
"an input binder populates a persistence object by field name":

- **Spring MVC** — `@ModelAttribute` binds request params to a command object's
  setters by name, and `@RequestBody` (Jackson) binds any settable field. When
  the command object *is* the JPA entity (the common shortcut), `role=ADMIN` /
  `{"enabled":true,"id":1}` binds directly. Guards to check for: an
  `@InitBinder` calling `setAllowedFields(...)`/`setDisallowedFields(...)`, or a
  dedicated DTO; their absence is the finding.
- **ASP.NET (MVC / Web API)** — model binding populates every public settable
  property from the form/JSON ("overposting"). `[Bind(Include=...)]`,
  `[BindNever]`, `[BindRequired]`, or a view-model restrict it; without them,
  posting `IsAdmin=true` to an action taking the entity binds it. `TryUpdateModel`
  with an explicit include-list is the fix — flag actions that bind the entity
  directly.
- **Go** — `json.Unmarshal`/`c.Bind` populate any **exported** field the JSON
  names (by field name or `json:` tag). Measured: unmarshalling
  `{"isAdmin":true,"role":"admin"}` into a `User{... IsAdmin bool}` sets
  `IsAdmin=true`. Note `Decoder.DisallowUnknownFields()` rejects *unknown* keys
  but **not** a known exported field like `IsAdmin` — so a struct reused for
  input and persistence is vulnerable even with that guard; the real fix is a
  separate input struct omitting the privileged fields.

### Parser and Validator Gaps

- Validators run post-bind and do not cover extra fields
- Unknown fields silently dropped in response but persisted underneath
- Inconsistent allowlists between mobile/web/gateway; alt encodings bypass validation pipeline

## Bypass Techniques

### Content-Type Switching

- Switch JSON ↔ form-encoded ↔ multipart ↔ text/plain; some code paths only validate one

### Key Path Variants

- Dot/bracket/object re-shaping to reach nested fields through different binders

### Batch Paths

- Per-item checks skipped in bulk operations
- Insert a single malicious object within a large batch

### Race and Reorder

- Race two updates: first sets forbidden field, second normalizes
- Final state may retain forbidden change

## Testing Methodology

1. **Identify endpoints** - Create/update endpoints and GraphQL mutations
2. **Capture responses** - Observe returned fields to build candidate list
3. **Build sensitive-field dictionary** - Per resource: role, isAdmin, ownerId, status, plan, limits, flags
4. **Inject candidates** - Alongside legitimate updates across transports and encodings
5. **Compare state** - Before/after diffs across roles
6. **Test variations** - Nested objects, arrays, alternative shapes, duplicate keys, batch operations

## Validation

1. Show a minimal request where adding a sensitive field changes persisted state for a non-privileged caller
2. Provide before/after evidence (response body, subsequent GET, or GraphQL query) proving the forbidden attribute value
3. Demonstrate consistency across at least two encodings or channels
4. For nested/bulk, show that protected fields are written within child objects or array elements
5. Quantify impact (e.g., role flip, cross-tenant move, quota increase) and reproducibility

## False Positives

- Server recomputes derived fields (plan/price/role) ignoring client input
- Fields marked read-only and enforced consistently across encodings
- Only UI-side changes with no persisted effect

## Impact

- Privilege escalation and admin feature access
- Cross-tenant or cross-account resource takeover
- Financial/billing manipulation and quota abuse
- Policy/approval bypass by toggling verification or status flags

## Pro Tips

1. Build a sensitive-field dictionary per resource and fuzz systematically
2. Always try alternate shapes and encodings; many validators are shape/CT-specific
3. For GraphQL, diff the resource immediately after mutation; effects are often visible even if the mutation returns filtered fields
4. Inspect SDKs/mobile apps for hidden field names and nested write examples
5. Prefer minimal PoCs that prove durable state changes; avoid UI-only effects

## Summary

Mass assignment is eliminated by explicit mapping and per-field authorization. Treat every client-supplied attribute—especially nested or batch inputs—as untrusted until validated against an allowlist and caller scope.
