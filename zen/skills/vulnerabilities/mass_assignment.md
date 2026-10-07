---
name: mass-assignment
description: Mass-assignment testing — unauthorized field binding via framework binders (Spring/ASP.NET/Go/Rails/Laravel/DRF/Mongoose/Pydantic), nested and bulk shapes, GraphQL input-type coercion, content-type and encoding bypasses, and the measured known-field vs unknown-field binder trap.
---

# Mass Assignment

Mass assignment binds client-supplied fields directly into models/DTOs without field-level allowlists. It is a privilege-escalation, ownership-takeover, and unauthorized-state-transition primitive in modern APIs and GraphQL. The structural question in every test is "which fields are bindable because the binder treats this type as both input and persistence model?"

## Attack Surface

- REST/JSON, GraphQL inputs, form-encoded and multipart bodies.
- Model binding in controllers/resolvers; ORM create/update helpers.
- Writable nested relations, sparse/patch updates, bulk endpoints.
- Admin / staff endpoints and mobile-SDK-only fields the UI never exposes.

## Reconnaissance

### Surface Map

- Controllers with automatic binding (`request.json → model`); grep for direct `User.create(**request.json)`, `model = JSON.parse(req.body)`, `@RequestBody User user`.
- GraphQL input types mirroring models; admin/staff tools exposed via API.
- OpenAPI/GraphQL schemas: uncover hidden fields or enums; introspect `__type(name:"UpdateUserInput")`.
- Client bundles and mobile apps: inspect forms and mutation payloads for field names.

### Parameter Strategies

- Flat fields: `isAdmin`, `role`, `roles[]`, `permissions[]`, `status`, `plan`, `tier`, `premium`, `verified`, `emailVerified`.
- Ownership/tenancy: `userId`, `ownerId`, `accountId`, `organizationId`, `tenantId`, `workspaceId`.
- Limits/quotas: `usageLimit`, `seatCount`, `maxProjects`, `creditBalance`.
- Feature flags/gates: `features`, `flags`, `betaAccess`, `allowImpersonation`.
- Billing: `price`, `amount`, `currency`, `prorate`, `nextInvoice`, `trialEnd`.
- Timestamps: `createdAt`, `verifiedAt`, `trialStartsAt` — set to past dates to backdate state.

### Shape Variants

- Alternate shapes: arrays vs scalars; nested JSON; objects under unexpected keys.
- Dot/bracket paths: `profile.role`, `profile[role]`, `settings[roles][]`.
- Duplicate keys and precedence: `{"role":"user","role":"admin"}`.
- Sparse/patch formats: JSON Patch (RFC 6902) / JSON Merge Patch (RFC 7396); try adding forbidden paths.
- Array indices as nested-model binding: `roles[0].name=admin`.

### Encodings and Channels

- Content-types: `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`.
- GraphQL: add suspicious fields to input objects; overfetch response to detect changes.
- Batch/bulk: arrays of objects; verify per-item allowlists not skipped.

## Measured Binder Behaviour

The core trap is "the input type is reused as the persistence model, and the binder strips *unknown* keys but accepts *known* privileged keys". Measured locally (persisted at `.zen-batch-artifacts/batch-11/measurements/mass_assignment_binders.py`+`.out` and `mass_assignment_go.go`+`.out`):

| Binder | Body `{"name":"a","isAdmin":true}` | Body `{"name":"a","role":"admin"}` (unknown) | Dedicated DTO body `{"name":"a","isAdmin":true}` |
|---|---|---|---|
| Python `obj.__dict__.update(body)` | `IsAdmin=True` (bind) | `role` added to `__dict__` | — |
| Python `dict.update(body)` | `is_admin=True` (bind) | `role` added | — |
| Python Pydantic v2 (default `extra='ignore'`) | `is_admin=True` (bind) | `role` silently dropped | — |
| Go `json.Unmarshal(body, &User{})` | `IsAdmin=true` (bind) | `role` silently dropped | — |
| Go `Decoder.DisallowUnknownFields()` on `&User{}` | `IsAdmin=true` (bind) | `err=json: unknown field "role"` | `err=json: unknown field "isAdmin"` |
| Allowlist (`{k: body[k] for k in ALLOWED & body}`) | `IsAdmin=False` (not bound) | `role` ignored | — |

What this proves:

1. **`DisallowUnknownFields()` is not a mass-assignment defence.** It catches unknown-key typos; it does not prevent binding of a known-but-privileged field. The Go result shows `IsAdmin=true` under both `DisallowUnknownFields` and lax parsing when the struct is the reused entity.
2. **Pydantic v2 default `extra='ignore'` has the identical trap.** The unknown `is_superuser` is silently dropped, but the known `is_admin` is bound. Pydantic's defence model is defined-fields-are-bindable, which coincides with the vulnerability.
3. **The fix is a separate input DTO omitting the privileged fields.** The `UserDTO` row shows the correct defence: `isAdmin` is rejected as an unknown field, independent of binder strictness.
4. **An explicit allowlist (`setattr` only for known-safe fields) is correct across all stacks**, but requires per-endpoint discipline the framework cannot enforce.

## Key Vulnerabilities

### Privilege Escalation

- Set `role`/`isAdmin`/`permissions` during signup/profile update.
- Toggle admin/staff flags where exposed.
- Add roles via array-shape fields the UI treats as read-only.

### Ownership Takeover

- Change `ownerId`/`accountId`/`tenantId` to seize resources.
- Move objects across users/tenants.
- Replace a referenced sub-object's ID so a mutation on self-resource writes to another user's resource.

### Feature Gate Bypass

- Enable premium/beta/feature flags via `flags`/`features` fields.
- Raise limits/`seatCount`/quotas.

### Billing and Entitlements

- Modify `plan`/`price`/`prorate`/`trialEnd` or `creditBalance`.
- Bypass server recomputation of derived billing fields.

### Nested and Relation Writes

- Writable nested serializers or ORM relations allow creating or linking related objects beyond caller's scope.
- Rails `accepts_nested_attributes_for` is a long-standing footgun — nested fields pass through strong_parameters' top-level `permit` list without secondary filtering.

## Advanced Techniques

### GraphQL Specific

- Field-level authz missing on input types: attempt forbidden fields in mutation inputs.
- Combine with aliasing/batching to compare effects.
- Use fragments to overfetch changed fields immediately after mutation.

Input-coercion depth — GraphQL coerces variables *by type* but does not *authorize* them, so the input type is the allowlist and a loose one is the bug:

- **Model-mirroring input types** — introspect the input object (`__type(name:"UpdateUserInput"){inputFields{name type{name}}}`); any field the schema accepts (`role`, `isAdmin`, `ownerId`, `tenantId`) is bindable if the resolver spreads the input into the model. The schema *is* the sensitive-field dictionary here.
- **Nested input objects** — writable nested inputs (`user:{profile:{role:ADMIN}}`) reach relations the top-level type seemed to gate.
- **Default-value / `null` injection** — omit a field to take a server default, or send explicit `null` to blank a server-set field the resolver then "updates."
- **`@oneOf` inputs and enums** — coercion picks a branch; test each variant and out-of-range enum values the resolver may trust.
- Diff the object immediately after the mutation (a follow-up query) — effects persist even when the mutation's return type hides the changed field.

### ORM Framework Edges

- **Rails**: strong parameters misconfig or deep nesting via `accepts_nested_attributes_for`; the dangerous `permit!` sinks every parameter unfiltered (see `mass_assignment_novel_deep.md § Camaleon CMS CVE-2025-2304`).
- **Laravel**: `$fillable`/`$guarded` misuses; `guarded=[]` opens all; casts mutating hidden fields.
- **Django REST Framework**: writable nested serializer, `read_only`/`extra_kwargs` gaps, partial updates. `ModelSerializer` without an explicit `fields` or `exclude` writes every column by default.
- **Mongoose/Prisma**: schema paths not filtered; `select:false` doesn't prevent writes; upsert defaults bind unexpected fields.

### Model-Binder Edges (Spring / ASP.NET / Go)

The typed/compiled stacks have their own overposting shapes — the pattern is "an input binder populates a persistence object by field name":

- **Spring MVC** — `@ModelAttribute` binds request params to a command object's setters by name, and `@RequestBody` (Jackson) binds any settable field. When the command object *is* the JPA entity (the common shortcut), `role=ADMIN` / `{"enabled":true,"id":1}` binds directly. Guards to check for: an `@InitBinder` calling `setAllowedFields(...)`/`setDisallowedFields(...)`, or a dedicated DTO; their absence is the finding. Grep for `@RequestBody <Entity>` across controllers.
- **ASP.NET (MVC / Web API)** — model binding populates every public settable property from the form/JSON ("overposting"). `[Bind(Include=...)]`, `[BindNever]`, `[BindRequired]`, or a view-model restrict it; without them, posting `IsAdmin=true` to an action taking the entity binds it. `TryUpdateModel` with an explicit include-list is the fix — flag actions that bind the entity directly.
- **Go** — `json.Unmarshal`/`c.Bind` populate any **exported** field the JSON names (by field name or `json:` tag). Measured (see table above): unmarshalling `{"isAdmin":true,"role":"admin"}` into a `User{... IsAdmin bool}` sets `IsAdmin=true`. Note `Decoder.DisallowUnknownFields()` rejects *unknown* keys but **not** a known exported field like `IsAdmin` — so a struct reused for input and persistence is vulnerable even with that guard; the real fix is a separate input struct omitting the privileged fields.

### Parser and Validator Gaps

- Validators run post-bind and do not cover extra fields.
- Unknown fields silently dropped in response but persisted underneath.
- Inconsistent allowlists between mobile/web/gateway; alt encodings bypass validation pipeline.

## 2024-2026 CVE Routing

Instance-level CVEs for the current mass-assignment frontier. The version/GHSA metadata lives in `mass_assignment_novel_deep.md`; the base cites by number and route only.

- **CVE-2024-7297** — Langflow `/api/v1/users` POST accepts `is_superuser` from the request body; any low-privileged authenticated user flips themselves to super admin. Classic unmodified-DTO overpost. Route: `mass_assignment_novel_deep.md § Langflow is_superuser Overpost`.
- **CVE-2025-34291** — Langflow follow-up: overly-permissive CORS (`allow_origins='*'` with `allow_credentials=True`) combined with a `SameSite=None` refresh-token cookie enables cross-origin credentialed requests that hit the mass-assignment endpoint from an attacker's page. Chained class with CSRF. Route: `mass_assignment_novel_deep.md § Langflow CORS + Mass-Assignment Chain`.
- **CVE-2025-2304** — Camaleon CMS `UsersController#updated_ajax` calls `params.permit!` which bypasses strong_parameters entirely; a password-change request also binds `role=admin` and other privileged attributes. Rails strong_params anti-pattern. Route: `mass_assignment_novel_deep.md § Camaleon CMS permit! Abuse`.
- **CVE-2025-41249** — Spring Framework annotation detection does not correctly resolve annotations on methods in type hierarchies with parameterized super types with unbounded generics. Authorization-adjacent class, not strictly mass-assignment, but affects `@EnableMethodSecurity`-protected methods that bind a DTO. Route: `mass_assignment_novel_deep.md § Spring Generic Hierarchy Annotation Gap`.

The advanced sibling (`mass_assignment_advanced_deep.md`) owns binder-ecosystem depth (Rails, DRF, Laravel, Mongoose, Spring, ASP.NET, Go, Node binders with worked attack recipes), content-type and encoding bypass taxonomy, GraphQL input-type depth with introspection recipes, nested and bulk shape depth, parser/validator gap classes, and composite-chain construction.

## Bypass Techniques

### Content-Type Switching

- Switch JSON ↔ form-encoded ↔ multipart ↔ text/plain; some code paths only validate one.
- A JSON-only CSRF defence may be defeated by `text/plain` with a JSON-shaped body on a stack that still JSON-parses.

### Key Path Variants

- Dot/bracket/object re-shaping to reach nested fields through different binders.
- Query-string parameters leaking into model binding on ASP.NET MVC: `?IsAdmin=true` on a mutating endpoint binds the field.

### Batch Paths

- Per-item checks skipped in bulk operations.
- Insert a single malicious object within a large batch.
- GraphQL batch mutations where the mutation count exceeds the allowlist check's iteration bound.

### Race and Reorder

- Race two updates: first sets forbidden field, second normalizes.
- Final state may retain forbidden change — see `race_conditions.md`.

### Partial-Update vs Replace

- `PATCH` (partial) may bypass validators that `PUT` (replace) runs; the validator assumed every field was present.
- JSON Merge Patch's `null` field removes a server-set field entirely.

## Testing Methodology

1. **Identify endpoints** — Create/update endpoints and GraphQL mutations.
2. **Capture responses** — Observe returned fields to build candidate list.
3. **Build sensitive-field dictionary** — Per resource: `role`, `isAdmin`, `ownerId`, `status`, `plan`, limits, flags.
4. **Inject candidates** — Alongside legitimate updates across transports and encodings.
5. **Compare state** — Before/after diffs across roles.
6. **Test variations** — Nested objects, arrays, alternative shapes, duplicate keys, batch operations.
7. **Measure the binder** — Run the local binder script against the detected framework to confirm the "known-privileged-but-still-bindable" trap applies.

## Validation

1. Show a minimal request where adding a sensitive field changes persisted state for a non-privileged caller.
2. Provide before/after evidence (response body, subsequent GET, or GraphQL query) proving the forbidden attribute value.
3. Demonstrate consistency across at least two encodings or channels.
4. For nested/bulk, show that protected fields are written within child objects or array elements.
5. Quantify impact (e.g., role flip, cross-tenant move, quota increase) and reproducibility.

## False Positives

- Server recomputes derived fields (plan/price/role) ignoring client input.
- Fields marked `read_only` and enforced consistently across encodings.
- Only UI-side changes with no persisted effect.
- The returned object includes the field but a database-level trigger or an application-layer post-save hook resets it to the authoritative value.

## Impact

- Privilege escalation and admin feature access.
- Cross-tenant or cross-account resource takeover.
- Financial/billing manipulation and quota abuse.
- Policy/approval bypass by toggling verification or status flags.

## Chaining

Mass assignment is a *gateway* primitive — it rarely stands alone. The capability granted (set a flag, change an ID, inject a nested object) chains into:

- **Mass-assignment → BFLA/IDOR**: setting `ownerId` grants control of a resource; see `broken_function_level_authorization.md`.
- **Mass-assignment → Privilege escalation**: `role=admin` turns an authenticated-user primitive into an admin primitive; see `broken_function_level_authorization.md`.
- **Mass-assignment → RCE**: nested-attribute binding can set configuration fields that control code paths (template, serializer, interpreter), setting up a second-stage RCE; see `insecure_deserialization.md`.
- **Mass-assignment → CSRF**: a mass-assignment endpoint reachable without a CSRF token is a direct privilege-flip CSRF; see `csrf.md`.
- **Mass-assignment → Race**: race the attribute-write against a validator that runs post-bind; see `race_conditions.md`.

## Pro Tips

1. Build a sensitive-field dictionary per resource and fuzz systematically.
2. Always try alternate shapes and encodings; many validators are shape/CT-specific.
3. For GraphQL, diff the resource immediately after mutation; effects are often visible even if the mutation returns filtered fields.
4. Inspect SDKs/mobile apps for hidden field names and nested write examples.
5. Prefer minimal PoCs that prove durable state changes; avoid UI-only effects.
6. Measure the binder's behaviour in a one-liner script against the detected framework — "does `DisallowUnknownFields` catch my payload?" is a 10-second answer.
7. Audit for `permit!` (Rails), `guarded=[]` (Laravel), `ModelSerializer` without `fields` (DRF), `@RequestBody <Entity>` (Spring), `[Bind(Prefix="")]` without `Include` (ASP.NET).

## Breadth Note

This base is a reference overview of the mass-assignment technique surface — class framing, the measured binder-trap table, sensitive-field dictionary, shape/encoding/channel variants, every primary primitive family (privilege/ownership/feature/billing/nested), GraphQL input-coercion basics, ORM and model-binder edges, parser/validator gap class, and the full 2024-2026 CVE routing map. It is deliberately scoped to be a complete overview of every technique class rather than full-treatment of each; the advanced sibling owns per-framework binder depth with full-treatment sub-primitives, and the novel sibling owns current CVE mechanism depth.

## Summary

Mass assignment is eliminated by explicit mapping and per-field authorization. Treat every client-supplied attribute — especially nested or batch inputs — as untrusted until validated against an allowlist and caller scope. The structural fix is a dedicated input DTO omitting privileged fields; strictness toggles (`DisallowUnknownFields`, Pydantic's `extra='forbid'`) help with typos but do not defend against known-privileged fields in a reused entity. The 2024-2026 CVE frontier (Langflow, Camaleon, Spring annotations) shows the class remains high-impact in modern stacks whenever the API-first mindset reuses the persistence model as the input DTO.
