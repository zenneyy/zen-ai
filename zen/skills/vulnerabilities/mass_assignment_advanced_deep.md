---
name: mass-assignment-advanced-deep
description: Advanced mass-assignment exploitation — per-framework binder depth (Spring @RequestBody / Jackson, ASP.NET Core model binder, Go encoding/json + gin + echo, Rails strong_parameters + accepts_nested_attributes_for, Laravel fillable/guarded, Django REST Framework ModelSerializer, Node/Express/Fastify body parsers, Mongoose/Prisma ORMs), GraphQL input-type coercion depth, nested and bulk shape exploitation, content-type and patch-semantics bypasses, and composite chaining into IDOR, BFLA, CSRF, race, and RCE.
sibling: mass_assignment
load_when: scan_mode == "deep"
---

# Mass Assignment — Advanced + Expert Depth

This is the advanced+expert deep sibling to `mass_assignment.md`. The base owns class framing, the measured binder-trap table, sensitive-field dictionary and shape variants, GraphQL input-coercion basics, model-binder edges across major stacks, the parser/validator gap class, bypass primitives, methodology, and the 2024-2026 CVE routing map. The novel+frontier sibling `mass_assignment_novel_deep.md` owns the current CVE instances (Langflow is_superuser overpost, Langflow CORS chain, Camaleon CMS permit! abuse, Spring generic-hierarchy annotation gap) with canonical version/GHSA tables and the research-grade techniques.

This file owns the expert-tier binder exploitation — per-framework binder internals with worked attack recipes and full-treatment sub-primitives (Primitive / Preconditions / Attack recipe / Confirmation / Impact for each), GraphQL input-type introspection depth, nested and bulk shape exploitation, content-type and patch-semantics bypass classes, and composite-chain construction routed to sibling skills.

Load this file when the goal is to construct a reliable mass-assignment exploit against a hardened target — simple field injection has failed, there is at least one layer of defence (DTO, serializer allowlist, binder restriction) to be worked around, and the question is whether a specific framework path still binds a privileged field.

## Spring MVC Binder Depth

### Primitive: `@RequestBody` into Reused Entity

Primitive: a Spring MVC controller receives a request body with Jackson and binds every settable field on the target type. When the target type is the JPA entity itself, every entity field is bindable from the request.

**Preconditions:**

1. Controller method signature uses `@RequestBody <Entity>` where `<Entity>` is a JPA `@Entity`-annotated class.
2. No `@InitBinder` restricts the fields via `setAllowedFields`/`setDisallowedFields`.
3. The entity has publicly settable (`public` or `@JsonProperty` with setter) privileged fields.

**Attack recipe:**

```http
POST /api/users/42 HTTP/1.1
Content-Type: application/json

{"email": "attacker@x", "role": "ADMIN", "enabled": true, "isAdmin": true}
```

If the entity has a `role: String` field and a `User.role` column, Jackson binds it; the subsequent `userRepository.save(user)` persists the change.

**Confirmation signal:** follow-up `GET /api/users/42` returns the elevated role; database audit log shows the single update event.

**Impact:** Privilege escalation; downstream resources accessible under the new role.

**Class generalization:** grep `@RequestBody` in the codebase; for each, check whether the parameter type is annotated with `@Entity` (JPA) or `@Document` (Spring Data MongoDB) or is a dedicated DTO.

### Primitive: `@ModelAttribute` with Query String Pollution

Primitive: Spring's `@ModelAttribute` populates a command object from both the request body and the query string. An action taking an entity through `@ModelAttribute` can be overposted via `?role=ADMIN` in the URL.

**Preconditions:** Controller method uses `@ModelAttribute <Entity>` or default parameter binding. The method is reachable with query-string parameters (GET or query-param-friendly POST).

**Attack recipe:**

```http
POST /settings/update?role=ADMIN HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=attacker@x
```

The query string's `role` is bound by the model-attribute binder even though it was not in the body.

**Confirmation signal:** persisted role is `ADMIN` after a POST with no body-level `role` field.

**Impact:** Overposting via GET-shape in a POST handler; often bypasses body-focused validators.

### Primitive: `@InitBinder` Scope Confusion

Primitive: `@InitBinder` restricts fields but is scoped to the controller class; a shared command object used across controllers may have different allowed-field lists per path, and an admin controller may allow fields that leak into a user-facing controller via the same command object.

**Preconditions:** `@InitBinder` is defined per controller; the command object type is shared.

**Attack recipe:** identify a user-facing controller that reuses an admin's command object; the `@InitBinder` on the user controller may not cover all privileged fields the admin controller allows.

**Confirmation signal:** field write via user-facing endpoint on a field only allowlisted on the admin endpoint.

**Impact:** Trust-boundary confusion; the user endpoint inherits the admin's binder exposure.

### Primitive: Jackson Polymorphic Binding

Primitive: Jackson's polymorphic type handling (`@JsonTypeInfo`) permits a `type` field to switch the target class. If the target class resolution is not restricted, an attacker can bind a different (potentially privileged) subtype.

**Preconditions:** The target type uses `@JsonTypeInfo` without `@JsonSubTypes` constraints; or uses a `DefaultTyping` policy that includes attacker-reachable subtypes.

**Attack recipe:**

```json
{"type": "com.app.AdminUser", "name": "a", "isAdmin": true}
```

Jackson instantiates `AdminUser` instead of `User`; the privileged flag is bound.

**Confirmation signal:** persisted object is of the privileged subtype.

**Impact:** Type-confusion escalates to privileged persistence. Note: this overlaps with insecure-deserialization — see `insecure_deserialization.md` for the gadget-chain depth. In the mass-assignment framing, the primitive is "the input type was supposed to be restricted and was not."

## ASP.NET Core Model Binder Depth

### Primitive: `[FromBody]` on Entity Type

Primitive: ASP.NET Core MVC's model binder populates every public settable property from the request body (JSON, form, or XML). If the action parameter is the entity type, every property is bindable.

**Preconditions:**

1. Action parameter is `[FromBody] <Entity> entity`.
2. The entity has public settable privileged properties.
3. No `[BindNever]` on privileged properties; no `[Bind(Include=...)]` on the action.

**Attack recipe:**

```http
POST /api/users HTTP/1.1
Content-Type: application/json

{"email": "a@x", "IsAdmin": true, "Role": "Admin"}
```

**Confirmation signal:** persisted entity has the elevated property; EF-Core migration audit shows the single update.

**Impact:** Privilege escalation.

### Primitive: `TryUpdateModel` Without Explicit Include

Primitive: `TryUpdateModel(entity)` without an explicit include-list populates every property.

**Preconditions:** Legacy ASP.NET MVC pattern using `TryUpdateModel` or `UpdateModel`.

**Attack recipe:** post the full entity shape with privileged fields; `TryUpdateModel` binds them.

**Confirmation signal:** same as above.

**Impact:** Same as above.

### Primitive: Model-Prefix Confusion

Primitive: `[Bind(Prefix="user")]` restricts the binder to fields prefixed with `user.`, but a nested-model binder may still pick up query-string `role=` as a sibling field if the model allows top-level fields.

**Preconditions:** `[Bind(Prefix="...")]` used; the model has top-level privileged fields.

**Attack recipe:** send both `user.email=...` and `role=admin`; the model binds `email` via the prefix and `role` via the default binding path.

**Confirmation signal:** `role` persisted despite the prefix restriction.

**Impact:** Prefix-based restriction defeated.

### Primitive: Query-String Overposting

Primitive: ASP.NET Core default model binding considers query string, form, and body; a POST handler can be overposted via query string even when the body shape is restricted.

**Preconditions:** No `[FromBody]`-only restriction; default binding is active.

**Attack recipe:** `POST /api/users?IsAdmin=true` with a benign body; query string's `IsAdmin` is bound.

**Confirmation signal:** persisted entity shows the query-string-sourced privileged field.

**Impact:** Overposting via unexpected binding source.

## Go Binders — gin, echo, chi, encoding/json

### Primitive: `gin.Context.ShouldBindJSON` Into Entity

Primitive: Gin's `ShouldBindJSON` is a thin wrapper over `encoding/json`; it binds any exported field named in the JSON. When the target struct is the persistence model, every exported field is bindable.

**Preconditions:**

1. Handler calls `c.ShouldBindJSON(&user)` where `user` is `*User` (the persistence model).
2. `User` struct has exported privileged fields with `json:` tags matching user-supplied keys.
3. Validator (via `binding:"required"` tags or custom hook) does not reject the privileged fields.

**Attack recipe:**

```go
// Vulnerable handler
func UpdateUser(c *gin.Context) {
    user := User{ID: c.Param("id")}
    c.ShouldBindJSON(&user)   // binds every exported field in body
    db.Save(&user)
}

// Attacker body:
// {"email":"a@x","isAdmin":true,"role":"admin"}
```

**Confirmation signal:** `/users/<id>` subsequent GET shows the elevated role.

**Impact:** Privilege escalation.

### Primitive: `DisallowUnknownFields` False Confidence

Primitive: `json.Decoder.DisallowUnknownFields()` rejects unknown fields but does not prevent binding of known exported privileged fields. The measured result (`.zen-batch-artifacts/batch-11/measurements/mass_assignment_go.go`+`.out`):

```
== body: {"name":"attacker","email":"a@x","isAdmin":true} ==
   [User + strict]     err=<nil>  IsAdmin=true  IsSuperuser=false  Name="attacker"
```

**Preconditions:** Handler uses `DisallowUnknownFields()` and binds into the entity type.

**Attack recipe:** post a body with a known privileged field (not an unknown one). The decoder accepts it.

**Confirmation signal:** privileged field persisted.

**Impact:** Defence-pattern misunderstanding: `DisallowUnknownFields` is a typo-defence, not a mass-assignment defence.

**Class generalization:** the correct defence is a separate input struct that omits the privileged fields; the measured `UserDTO + strict` row rejects `isAdmin` as an unknown field precisely because `isAdmin` is not declared on `UserDTO`.

### Primitive: Echo Binder with Struct Tag Permissiveness

Primitive: Echo's binder uses struct tags to decide which fields are bindable; `form:`, `json:`, `query:` tags each enable binding from a different source. A single struct with all three tags allows binding from any source.

**Preconditions:** Entity struct has `form:"..."`, `json:"..."`, `query:"..."` tags on privileged fields.

**Attack recipe:** post a form body with the privileged field; alternatively, add it as a query parameter.

**Confirmation signal:** privileged field persisted via a source the handler author did not anticipate.

**Impact:** Multi-source overposting; a validator keyed on one source does not cover others.

## Rails Strong Parameters Depth

### Primitive: `params.permit!` — The Nuclear Button

Primitive: `permit!` on an `ActionController::Parameters` instance marks every parameter as permitted; subsequent `.to_h` or model assignment binds everything.

**Preconditions:** Controller calls `params.permit!` or `params.require(:resource).permit!`.

**Attack recipe:** any shape — the entire params hash passes through.

**Confirmation signal:** every supplied field is persisted, including the ones never permitted by any explicit allowlist.

**Impact:** Mass-assignment class-wide; this is the Camaleon CMS CVE-2025-2304 pattern. See the novel sibling for the full CVE treatment.

### Primitive: `accepts_nested_attributes_for` Nested Overpost

Primitive: Rails's `accepts_nested_attributes_for :profile` adds a `profile_attributes` setter to the parent model that cascades every attribute into the nested record. If the parent's strong-parameters allowlist includes `profile_attributes: [:name, :bio]`, those nested fields are safe — but if the allowlist is `profile_attributes: {}` (empty hash, meaning "any key"), every nested attribute is bindable.

**Preconditions:** Parent model has `accepts_nested_attributes_for`; strong-parameters allowlist for the nested attributes is `{}` or missing entirely.

**Attack recipe:**

```json
{"user": {"email": "a@x", "profile_attributes": {"role": "admin"}}}
```

**Confirmation signal:** nested profile row has elevated role.

**Impact:** Mass assignment reaches a nested resource via the parent's binder.

### Primitive: Strong-Params Deep-Nested Hash Shape

Primitive: `params.permit(:x, y: [:z])` permits `y` as an array of hashes with `z` key; attacker sends an array of hashes with extra keys.

**Preconditions:** The allowlist uses `[:z]`-style but the model's bind step passes the whole hash.

**Attack recipe:** `{"y":[{"z":"a","role":"admin"}]}`; depending on how the controller consumes `y`, extra keys may pass through.

**Confirmation signal:** persisted array element contains the extra key.

**Impact:** Nested-array overpost.

### Primitive: Rails `has_many :through` Join-Table Overpost

Primitive: Join tables used with `has_many :through` can have their foreign-key columns written via mass assignment; setting `user_id` on a shared-with-current-user join record changes ownership.

**Preconditions:** `UserRole` join model with `accepts_nested_attributes_for` or direct writable attrs.

**Attack recipe:** nested shape with `user_role_attributes: [{ id: X, user_id: Y }]`.

**Confirmation signal:** join row's `user_id` changes from current user to victim's user ID.

**Impact:** Role transfer or role replication; chains to IDOR/BFLA.

## Laravel Fillable/Guarded Depth

### Primitive: `$guarded = []` — Equivalent to Nuclear Button

Primitive: `protected $guarded = [];` on an Eloquent model disables guarded-mode entirely, so every attribute is mass-assignable.

**Preconditions:** Model has `$guarded = []` (common anti-pattern copied from tutorials).

**Attack recipe:** post the full attribute set; everything binds.

**Confirmation signal:** every attribute persisted.

**Impact:** Full mass assignment on the model.

### Primitive: `$fillable` Omission + `fill($request->all())`

Primitive: `$fillable` not set and `fill($request->all())` called. Laravel 7+ requires `$fillable` for mass assignment to work; absent `$fillable`, the attempt throws `MassAssignmentException`. But a developer who hits that exception may add `$guarded = []` to silence it — reintroducing the vulnerability.

**Preconditions:** Model and controller both evolved to the "unguarded" pattern.

**Attack recipe:** overpost.

**Confirmation signal:** persisted change.

**Impact:** Same as above.

### Primitive: `::create` vs `::make` Inconsistency

Primitive: `Model::create($data)` respects `$fillable`; `new Model($data)` + `save()` may bypass it depending on Laravel version and the `->forceCreate` path.

**Preconditions:** Controller mixes `create` and `forceCreate` or raw `new` for different endpoints.

**Attack recipe:** target the endpoint that uses the raw constructor path.

**Confirmation signal:** persisted change on a model with `$fillable` that otherwise rejects it.

**Impact:** Fillable-restriction bypass via alternative creation path.

### Primitive: Casts-Mediated Field Mutation

Primitive: Laravel's `$casts` can transform attribute types on set/get; a `casts = ['role' => RoleCast::class]` with a custom cast class that spreads nested data into the model.

**Preconditions:** Custom cast class with a wide-set `set()` method.

**Attack recipe:** post a nested object into a cast-handled attribute; the cast's `set` method distributes fields across the model.

**Confirmation signal:** attributes outside the cast target are also set.

**Impact:** Cast-mediated mass assignment; bypasses `$fillable` since the cast is a transformation layer.

## Django REST Framework Serializer Depth

### Primitive: `ModelSerializer` Default-Exposes Every Column

Primitive: `ModelSerializer` with `fields = '__all__'` (or no `fields` declaration, which errors on newer DRF but was permissive in older versions) exposes every column for write.

**Preconditions:** `ModelSerializer` with `fields='__all__'` and no `read_only_fields` for sensitive columns.

**Attack recipe:** post a body with privileged fields corresponding to User model columns (`is_staff`, `is_superuser`, `groups`).

**Confirmation signal:** persisted user has elevated flags.

**Impact:** Privilege escalation.

### Primitive: Writable Nested Serializer

Primitive: A `ProfileSerializer` nested under `UserSerializer` with no explicit `read_only=True` on sensitive fields.

**Preconditions:** Writable nested serializer.

**Attack recipe:**

```json
{"name":"a","profile":{"role":"admin"}}
```

**Confirmation signal:** nested profile row has elevated role.

**Impact:** Nested overpost.

### Primitive: `extra_kwargs` Partial-Mask Bypass

Primitive: `extra_kwargs = {'password': {'write_only': True}}` only hides the field from reads; it does not restrict writes. A `read_only=True` or exclusion from `fields` is needed.

**Preconditions:** Developer confuses `write_only` with write restriction.

**Attack recipe:** post the sensitive field; it binds despite `write_only`.

**Confirmation signal:** persisted field change.

**Impact:** The "write_only is read_only" misconception.

### Primitive: `partial=True` + Validator Scope

Primitive: `serializer.save(partial=True)` allows updates without requiring every field; validators that assumed every field was present skip their checks.

**Preconditions:** PATCH endpoint using `partial=True`; validators written against a full-replace model.

**Attack recipe:** PATCH with a privileged field only, no other fields; validator does not fire.

**Confirmation signal:** PATCH succeeds with field combinations the full-PUT would reject.

**Impact:** Partial-update validator-bypass.

## Node.js Body-Parser Depth

### Primitive: Express body-parser + Direct Spread

Primitive: Express applications using `body-parser.json()` (or Express ≥4.16's built-in `express.json()`) populate `req.body` with the parsed JSON. Handlers that then do `Object.assign(user, req.body)` or `User.update(req.body)` bind every field in the body.

**Preconditions:** Handler spreads `req.body` into a Mongoose/Sequelize/Prisma model or an existing object.

**Attack recipe:**

```javascript
// Vulnerable
app.patch('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);  // binds every field
  await user.save();
});
```

Attacker body: `{"email":"a@x","isAdmin":true}`.

**Confirmation signal:** persisted user has elevated flag.

**Impact:** Privilege escalation.

### Primitive: Fastify Schema-less Binding

Primitive: Fastify handlers without a declared `schema.body` schema accept arbitrary JSON into `request.body`. If the handler spreads it, the mass-assignment class is open.

**Preconditions:** Fastify route has no body schema (or schema is `type: 'object'` with no `additionalProperties: false` and no `properties` limit).

**Attack recipe:**

```javascript
fastify.patch('/users/:id', async (request, reply) => {
  // No schema; request.body is attacker-shaped
  await User.update({ where: { id: request.params.id }, data: request.body });
});
```

**Confirmation signal:** persisted change on privileged fields.

**Impact:** Mass assignment. **The Fastify defence idiom is `schema.body` with `additionalProperties: false`** — Fastify's AJV-based validator then rejects extra keys and only binds the declared property set.

### Primitive: NestJS DTO Transform Pipe Bypass

Primitive: NestJS controllers use `@Body()` with a DTO class; `class-transformer`'s `plainToClass` converts the body into the DTO instance. By default, extra fields in the body *are kept on the instance* unless `excludeExtraneousValues: true` is set globally or `@Exclude()` is on every non-DTO property.

**Preconditions:** `app.useGlobalPipes(new ValidationPipe())` without `whitelist: true` and `forbidNonWhitelisted: true`.

**Attack recipe:** add extra fields to the body; `plainToClass` keeps them on the instance; subsequent `.save()` persists them.

**Confirmation signal:** persisted change on fields not in the DTO.

**Impact:** DTO-based defence defeated unless `whitelist` is enabled.

**Class generalization — the "schema defence must forbid extras" lesson.** AJV, class-validator, Zod, Joi, and Yup all have a configuration where extra keys are allowed by default; the defence pattern is explicit `strict: true` / `additionalProperties: false` / `whitelist: true` / `.strict()`.

## Java JPA Entity Manager Depth

### Primitive: Entity Manager Merge Overwrites

Primitive: `EntityManager.merge(entity)` copies every field from the detached `entity` onto the managed entity in the persistence context. If the controller binds a request body into a detached entity and merges, every column is updated.

**Preconditions:** Controller receives `@RequestBody <Entity>` and calls `entityManager.merge(entity)` or `repository.save(entity)` (Spring Data).

**Attack recipe:** post the full entity shape with privileged fields; `merge` writes them.

**Confirmation signal:** persisted change on privileged fields; `UPDATE` SQL includes all columns.

**Impact:** Mass assignment via JPA; `merge` is a common Spring-Data pattern.

### Primitive: Jackson `@JsonAnySetter` Fallback

Primitive: A class with `@JsonAnySetter` method accepts *any* field name during deserialization; attacker can inject arbitrary field-name-to-value mappings that reach an inner Map or dispatcher.

**Preconditions:** DTO class has `@JsonAnySetter` method; the method writes to a Map used in business logic.

**Attack recipe:**

```java
public class UserDTO {
    public String name;
    private Map<String, Object> extra = new HashMap<>();

    @JsonAnySetter
    public void set(String key, Object value) {
        extra.put(key, value);  // attacker chooses the key
    }
}
```

If `extra` is later iterated for setter dispatch (`for (k,v) : entity.setField(k, v)`), the attacker reaches arbitrary setters.

**Confirmation signal:** persisted change on fields the DTO did not declare.

**Impact:** JsonAnySetter-mediated mass assignment.

### Primitive: Jackson `@JsonTypeInfo` Polymorphic Mass Assignment

Primitive: Jackson's `@JsonTypeInfo(use=Id.CLASS)` lets the request body specify the concrete class to deserialize. An attacker-chosen class may expose more fields (or privileged fields) than the base type.

**Preconditions:** Target type uses `Id.CLASS` or `Id.MINIMAL_CLASS` without a restrictive `@JsonSubTypes` allowlist.

**Attack recipe:**

```json
{"@class":"com.app.AdminUser","name":"a","isAdmin":true,"adminLevel":99}
```

Jackson instantiates `AdminUser` and sets `isAdmin` / `adminLevel`.

**Confirmation signal:** persisted entity is of the privileged subtype.

**Impact:** Type-confusion mass assignment; related to insecure deserialization — see `insecure_deserialization.md § Jackson Polymorphism`. In the mass-assignment framing, the primitive is the privileged-field reach via the attacker-chosen type.

## Serverless Binder Depth

### Primitive: AWS Lambda Event Shape Overbinding

Primitive: Lambda handlers receive an `event` object (API Gateway event, S3 event, SQS message). Code that spreads `event.body` into a persistence call binds every field.

**Preconditions:** Lambda handler does `JSON.parse(event.body)` and spreads into a model.

**Attack recipe:** post via API Gateway with privileged fields; Lambda spreads.

**Confirmation signal:** DynamoDB / RDS persistence shows privileged fields.

**Impact:** Mass assignment at the function-URL / API Gateway layer.

### Primitive: Vercel Serverless Function `req.body` Spread

Primitive: Vercel's Next.js API routes expose `req.body` as the parsed body; same shape as Express.

**Preconditions:** API route handler spreads `req.body`.

**Attack recipe:** standard mass assignment.

**Confirmation signal:** persisted change.

**Impact:** Mass assignment at the serverless function layer.

### Primitive: Netlify / Cloudflare Workers Binding

Primitive: Cloudflare Workers' `request.json()` returns the parsed body; handler-spread pattern applies.

**Preconditions:** Worker handler spreads parsed JSON.

**Attack recipe:** same pattern.

**Confirmation signal:** persisted change in whatever KV / D1 / durable-object storage the Worker writes to.

**Impact:** Mass assignment in Workers-based APIs.

## Mongoose / Prisma ORM Depth

### Primitive: Mongoose `strict` Mode and Dot-Path

Primitive: Mongoose's `strict: true` (default) rejects unknown schema paths, but `strict: false` or `strict: 'throw'` disabled allows arbitrary paths. Nested dot-path binding (`'profile.role'=admin`) can also bypass top-level checks.

**Preconditions:** Schema with `strict: false`, or ORM operation that resolves dot-paths.

**Attack recipe:** post `{"profile.role": "admin"}` with dot-path.

**Confirmation signal:** nested path persisted.

**Impact:** Nested overpost via dot-notation.

### Primitive: Prisma `data: req.body` Direct Spread

Primitive: Prisma's `create({ data: req.body })` spreads the request body into the create input; every column named in the body is bindable.

**Preconditions:** Direct spread without an allowlist transform.

**Attack recipe:** post the privileged column.

**Confirmation signal:** persisted field change.

**Impact:** Privilege escalation.

### Primitive: Prisma `upsert` Create-Side Overpost

Primitive: Prisma `upsert` has a `create` and an `update` branch; the `create` branch may have different field restrictions. An attacker-chosen non-existent ID forces the `create` path with the privileged body.

**Preconditions:** Upsert with asymmetric field restrictions.

**Attack recipe:** POST with a non-existent ID so the create branch fires; include privileged fields.

**Confirmation signal:** new row with privileged state.

**Impact:** Create-branch overpost.

## GraphQL Input Type Depth

### Primitive: Input-Type Introspection → Field Dictionary

Primitive: GraphQL introspection reveals the sensitive-field dictionary for every input type on the schema.

**Preconditions:** Introspection enabled (default in many deployments despite advisories).

**Attack recipe:**

```graphql
{
  __type(name: "UpdateUserInput") {
    inputFields { name type { name } }
  }
}
```

Enumerate every bindable field; attempt each privileged-looking one in a subsequent mutation.

**Confirmation signal:** input-type field list includes `role`, `isAdmin`, `ownerId`, etc.; mutation accepts the field.

**Impact:** Direct enumeration of the attack surface.

### Primitive: Nested Input Overpost

Primitive: Nested input types in a mutation input accept their own set of fields; an attacker can reach them without the top-level input exposing them.

**Preconditions:** Mutation input has a nested input type with privileged fields.

**Attack recipe:**

```graphql
mutation {
  updateUser(input: {
    id: "me",
    profile: { role: ADMIN, bio: "..." }
  }) { id }
}
```

**Confirmation signal:** nested profile has elevated role.

**Impact:** Nested overpost.

### Primitive: Default-Value and Null Injection

Primitive: Omitting a field takes a server default; sending explicit `null` blanks a server-set field the resolver then "updates" from the input.

**Preconditions:** Resolver reads from the input and writes to the DB without explicit null-handling.

**Attack recipe:** omit `is_locked` to let it default to the input's `false`; or send `null` to blank the server's `locked_at` timestamp.

**Confirmation signal:** server-set field reset or default-applied.

**Impact:** Server-side field reset via omission or null-injection.

### Primitive: `@oneOf` Enum Branch Confusion

Primitive: GraphQL `@oneOf` input types permit exactly one of a set of fields; a resolver that reads multiple fields may fire for more than one branch.

**Preconditions:** `@oneOf` directive without matching resolver-side enforcement.

**Attack recipe:** send multiple branches; the resolver evaluates all.

**Confirmation signal:** state change for a branch that should not have been active.

**Impact:** Branch-condition bypass.

### Primitive: Enum Out-of-Range Coercion

Primitive: GraphQL enums coerce to their declared values; a resolver that trusts the coerced value may accept out-of-range names if the enum is `String`-backed.

**Preconditions:** Enum defined on the schema but the resolver accepts an unvalidated string value for the field.

**Attack recipe:** send an enum value not in the declared set; resolver may process it.

**Confirmation signal:** state change with an enum-outside-range value.

**Impact:** Enum-coercion escape; opens the field to arbitrary string state.

## Nested and Bulk Shape Exploitation

### Primitive: Array-Index Model Binding

Primitive: ASP.NET MVC and Spring MVC bind array elements by index (`roles[0].name=admin`); nested overpost through arrays.

**Preconditions:** Form-encoded binding with array index support.

**Attack recipe:**

```
POST /settings HTTP/1.1
Content-Type: application/x-www-form-urlencoded

roles[0].name=admin&roles[0].level=99
```

**Confirmation signal:** persisted array element has elevated state.

**Impact:** Nested-array overpost.

### Primitive: Bulk Operation Allowlist Skip

Primitive: Bulk endpoints iterate over items but validate at the array level, not per-item; one malicious item in a benign batch binds privileged fields.

**Preconditions:** Bulk endpoint with per-item processing but array-level validation.

**Attack recipe:** `[{normal},{normal},{normal},{isAdmin:true}]`; the per-item check only runs if the array passes validation.

**Confirmation signal:** persisted malicious item has elevated state.

**Impact:** Bulk-path overpost.

### Primitive: JSON Patch (RFC 6902) Operation Shape

Primitive: `PATCH` with JSON Patch (`[{"op":"replace","path":"/role","value":"admin"}]`) can reach paths the body-shape validator did not expect.

**Preconditions:** Endpoint accepts JSON Patch; path validator missing or regex-based.

**Attack recipe:** craft operations targeting privileged paths.

**Confirmation signal:** persisted path change.

**Impact:** Patch-path overpost.

### Primitive: JSON Merge Patch (RFC 7396) Null Removal

Primitive: Merge Patch's `null` value removes the field; a server-set `locked_at` can be cleared via `{"locked_at":null}`.

**Preconditions:** Endpoint accepts Merge Patch semantics.

**Attack recipe:** post `{"locked_at":null}` to clear the lock.

**Confirmation signal:** field cleared.

**Impact:** Server-state reset via merge-patch null.

## Content-Type and Encoding Bypass Classes

### Primitive: text/plain + JSON Body (CSRF-Adjacent)

Primitive: `Content-Type: text/plain` with a JSON-shaped body; some stacks still JSON-parse (Express `body-parser` with `type: '*/*'`), making the request a CORS-simple one that bypasses preflight.

**Preconditions:** Server parses JSON regardless of content-type; CSRF defence is preflight-dependent.

**Attack recipe:**

```http
POST /api/users HTTP/1.1
Content-Type: text/plain

{"isAdmin":true}
```

**Confirmation signal:** JSON body processed; no CORS preflight triggered.

**Impact:** CSRF + mass-assignment chain; see `csrf.md`.

### Primitive: multipart/form-data Field Injection

Primitive: `multipart/form-data` body with privileged fields intermixed with file uploads; some binders process the form fields independently of the file-part validation.

**Preconditions:** Mixed multipart body on an endpoint that normally only expects files.

**Attack recipe:** add a `role=admin` form part alongside the file upload.

**Confirmation signal:** persisted role change despite the endpoint being nominally a file-upload.

**Impact:** Mass assignment via file-upload endpoint.

### Primitive: application/xml Overpost

Primitive: XML content with namespace confusion or type coercion binds privileged fields in Spring/ASP.NET XML binders.

**Preconditions:** XML content type supported.

**Attack recipe:**

```xml
<User><email>a@x</email><isAdmin>true</isAdmin></User>
```

**Confirmation signal:** persisted change.

**Impact:** Overpost via XML; separate validator pipeline often weaker than JSON's.

## Validator-Scope Failure Classes

### Primitive: Validator Runs Post-Bind

Primitive: Validator fires after the binder has already written privileged fields; the validator rejects the final state but the write already happened in-memory.

**Preconditions:** `@Valid`/`@Validated` on the controller parameter; binder populates the entity, validator runs, response is 400 — but the entity reference was passed by reference to a logging or event hook that persisted state.

**Attack recipe:** post a body that passes basic validation but has an extra privileged field; observe side-effect telemetry.

**Confirmation signal:** persisted change despite 400 response.

**Impact:** Side-effect-mediated mass assignment.

### Primitive: Validator Scope Mismatch

Primitive: Validator checks a subset of fields; the subset does not include the privileged ones.

**Preconditions:** Field-granularity validator with incomplete coverage.

**Attack recipe:** post the uncovered field.

**Confirmation signal:** persisted change despite validator passing.

**Impact:** Scope-gap overpost.

## Composite Chain Construction

Mass assignment is a gateway primitive. Chain by capability transferred:

### Chain 1: Mass-Assignment → BFLA → Admin Operation

- Preconditions: endpoint reachable by low-privilege user; model has `role` field.
- Mass-assignment: `role=admin` on self-update.
- BFLA: new admin role lets attacker reach admin-only endpoints.

Route: `broken_function_level_authorization.md § Role-Flip Chains`.

### Chain 2: Mass-Assignment → IDOR → Cross-Tenant Takeover

- Preconditions: `ownerId` or `tenantId` is bindable.
- Mass-assignment: `ownerId=victim-id` on self-resource.
- IDOR: resource now belongs to victim; subsequent operations grant attacker access.

Route: `idor.md § Ownership-Flip Chains`.

### Chain 3: Mass-Assignment → Race → Partial-Construction Exploit

- Preconditions: user-creation flow with asynchronous role-binding.
- Mass-assignment: set role in the initial create.
- Race: beat the server's role-reset step.

Route: `race_conditions.md § Partial-Construction Races`.

### Chain 4: Mass-Assignment → RCE via Configuration Field

- Preconditions: Model has `template`/`serializer`/`handler` string fields the application uses to pick a code path.
- Mass-assignment: set a privileged value (e.g., `template="erb"` to switch to the ERB engine, or `serializer="Marshal"` to switch Marshal deserialization).
- RCE: the configured code path's deserializer executes attacker-controlled downstream input.

Route: `insecure_deserialization.md` and `ssti.md § Configuration-Driven Template Selection`.

### Chain 5: Mass-Assignment → CSRF → Victim-Side Impact

- Preconditions: no CSRF token on mass-assignment endpoint; attacker-hosted page.
- CSRF: victim's browser posts the mass-assignment body (text/plain content-type).
- Impact: victim's own role/attributes mutated.

Route: `csrf.md § JSON-Endpoint Primitives`.

## Verification Discipline

Every mass-assignment claim must survive:

1. **Field-is-written confirmation**: a GET-back or DB query shows the privileged field at the attacker-chosen value — not just a 2xx response.
2. **Minimal-shape reproducibility**: a request with the privileged field alone (plus auth) demonstrates the binding, independent of other body content.
3. **Encoding variance**: the same change works across JSON and form-encoded, or the finding is scoped to one encoding.
4. **Downstream effect**: the privileged field actually changes behaviour — a `role=admin` write that doesn't grant admin access is a cosmetic finding.
5. **Isolation of cause**: a control request without the privileged field does not produce the elevated state.

## Summary

Advanced mass-assignment exploitation spans every modern binder (Spring, ASP.NET, Go, Rails, Laravel, DRF, Mongoose, Prisma), every input shape (nested, array, dot-path, bulk, JSON Patch, Merge Patch, XML, form), and every encoding (JSON, form-encoded, multipart, text/plain). The defensive pattern that scales is a dedicated input DTO per endpoint omitting privileged fields; strictness toggles like `DisallowUnknownFields` or Pydantic's `extra='forbid'` catch typos but not known-privileged fields in reused entities. Chaining into IDOR, BFLA, race, RCE, and CSRF turns a single-field write into a lateral or vertical privilege gain.
