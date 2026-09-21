---
name: django
description: Security testing playbook for Django applications covering ORM injection, middleware gaps, auth/session flaws, and template issues
---

# Django

Security testing for Django web applications and Django REST Framework (DRF) APIs. Focus on ORM/raw query misuse, middleware ordering, permission class gaps, and session/auth configuration across views, admin, and channels.

## Attack Surface

**Core Components**
- URL routing (`urls.py`), class-based and function views, middleware stack
- ORM (QuerySet filters), raw SQL, `extra()`, `RawSQL`, annotations
- Templates (Django template language, Jinja2 if configured)
- Forms, ModelForms, serializers (DRF)

**Authentication**
- Session framework, `AuthenticationMiddleware`, `@login_required`, DRF `permission_classes`
- Token auth, JWT (djangorestframework-simplejwt), OAuth integrations
- Django admin (`/admin/`), staff/superuser flags

**Deployment**
- `DEBUG=True` exposure, `ALLOWED_HOSTS`, `SECRET_KEY` leakage
- Static/media serving, reverse proxies, ASGI (Channels, Daphne, Uvicorn)

## High-Value Targets

- `/admin/` — brute force, credential stuffing, IDOR on admin objects
- API endpoints with mixed permission classes across ViewSets
- File upload (`FileField`, `ImageField`), import/export (django-import-export)
- Search/filter endpoints using `filter()`, `Q` objects, or raw SQL
- Password reset, email verification, invitation tokens
- WebSocket consumers (Django Channels) with weaker auth than HTTP equivalents
- Celery task triggers accepting user IDs without ownership checks

## Reconnaissance

**Fingerprinting**
```
curl -I https://target/ -H "Cookie: sessionid=test"
# X-Frame-Options, Set-Cookie (sessionid, csrftoken), Server header
GET /admin/login/
GET /api/  /api/v1/  /swagger/  /api/schema/
```

**Settings Leakage (when DEBUG=True or misconfigured)**
- Yellow debug page exposes `SECRET_KEY`, database credentials, installed apps
- `/static/`, error pages with stack traces revealing paths and ORM queries

**OpenAPI / DRF**
```
GET /api/schema/
GET /swagger.json
```
Map endpoints, authentication classes, and permission classes per route.

## Key Vulnerabilities

### Authentication & Authorization

**Permission Class Gaps**
- ViewSet with `list` protected but `retrieve`/`update` missing `permission_classes`
- Custom permissions checking authentication but not object ownership (IDOR)
- `@api_view` without explicit permissions inheriting permissive defaults
- Admin actions or custom management commands without staff checks

**Session Issues**
- `SESSION_COOKIE_SECURE=False` on HTTPS sites; missing `HttpOnly`
- Session fixation if session key not rotated on login
- Weak or leaked `SECRET_KEY` → forge session cookies (`django.contrib.sessions.backends.signed_cookies`)

**JWT (simplejwt)**
- RS256→HS256 confusion if algorithm pinning is misconfigured
- Missing `user_id`/`token` blacklist on logout
- Refresh token rotation not enforced

### Injection

**ORM SQL Injection**
Vulnerable patterns (more common in legacy code):
```python
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{user_input}'")
User.objects.extra(where=[f"username = '{user_input}'"])
```
Test: `' OR 1=1 --`, time-based payloads, database-specific syntax.

**Column-alias SQLi via `.values()` / `.values_list()` — CVE-2024-42005.**
`QuerySet.values()`/`values_list()` on a model with a **JSONField** does not
validate the `*args` (column names / JSON key paths), so a user-controlled arg
breaks out of the column **alias** into arbitrary SQL. Affected **Django 5.0
< 5.0.8 and 4.2 < 4.2.15** (fixed 5.0.8 / 4.2.15 / 5.1; CVSS 9.8). Measured
locally — the same crafted arg on 5.0.7 vs 5.0.8:
```python
crafted = 'data__a") AS "x", (SELECT secret FROM auth_user) AS "y'
Model.objects.values(crafted)     # a JSONField model
# Django 5.0.7 (vuln): the crafted key is embedded in the generated SQL
# Django 5.0.8 (fixed): raises ValueError "Column aliases cannot contain
#   whitespace characters, quotation marks, semicolons, or SQL comments" (check_alias)
```
The hunter's check: is the target on an affected Django, and does any endpoint
pass user input into `.values(*fields)`/`.values_list()` args (a `?fields=` /
`?group_by=` / GraphQL projection mapped straight to `.values()`)? This is the
same class as the older crafted-key SQLi in `.annotate()`/`.aggregate()`/
`.alias()` dict expansion — any place a user-controlled string becomes a column
name/alias. `RawSQL`, `.extra()`, `.raw()`, and `.order_by()` on unvalidated
fields remain the classic sinks.

**DRF Filter Backends**
- `django-filter` with unsafe field exposure: `?username__icontains=` on unintended columns
- Ordering injection via `?ordering=` if field whitelist missing

**Template Injection**
Django templates auto-escape by default; risk rises with:
```python
mark_safe(user_input)
|safe filter in templates
Template(user_input).render(...)  # SSTI if user controls template source
```
Jinja2 backend without autoescape: `{{7*7}}`, RCE gadgets if sandbox misconfigured.

### CSRF

- `@csrf_exempt` on state-changing views
- DRF session authentication without CSRF enforcement on unsafe methods
- CSRF cookie not set (`CSRF_USE_SESSIONS`, trusted origins misconfiguration)
- `CSRF_TRUSTED_ORIGINS` too broad

**Test:** Cross-origin POST with victim session cookie; JSON endpoints with session auth.

### IDOR and Mass Assignment

**DRF Serializers**
- `fields = '__all__'` exposing `is_staff`, `is_superuser`, `role`, `balance`
- `read_only_fields` missing on sensitive ModelSerializer fields
- Nested writes updating foreign keys across tenants

**Object-Level Permissions**
- `get_object()` without filtering queryset by request.user
- Generic views with `queryset = Model.objects.all()` and weak permissions

### File Handling

- `MEDIA_ROOT` served directly in DEBUG or via misconfigured nginx
- Path traversal in custom file download views using user-supplied paths
- SVG/HTML uploads served with `Content-Type` that enables XSS
- Missing file size/type validation on uploads

### SSRF

- `requests.get(user_url)` in webhooks, preview, import features
- Celery tasks fetching user URLs server-side
- Test loopback, metadata IPs, redirect chains

### Host Header / Password Reset

- `ALLOWED_HOSTS = ['*']` or permissive subdomain patterns
- Password reset emails built from `Host` header → poisoned reset links
- Cache poisoning via unkeyed Host header on cached pages
- **User-email enumeration via password reset — CVE-2024-45231** (fixed 4.2.16 /
  5.0.9 / 5.1.1): `PasswordResetForm` raised a server error when email delivery
  failed *only for addresses that exist*, so a `500` vs a normal response
  distinguishes registered emails when the mail backend is failing. Test the
  reset flow for outcome differences (status, timing, error) between a known and
  an unknown address.

### Django Admin

- Default `/admin/` path with weak credentials
- `has_add_permission` / `has_change_permission` overrides with logic bugs
- ModelAdmin exposing sensitive fields in list_display or export

### Channels / WebSocket

- Consumer accepts connection without session/auth parity to HTTP
- Group name derived from user input → subscribe to other users' channels
- Missing origin validation on WebSocket handshake

### Version-Specific DoS & Async Gaps

Fingerprint the Django version, then match:
- **IPv6-validation DoS — CVE-2024-56374** (fixed 4.2.18 / 5.0.11 / 5.1.5):
  `clean_ipv6_address` / `GenericIPAddressField` lacked an input length bound, so
  a very long IPv6-shaped string causes CPU-DoS. Send an oversized value to any
  IP-address form field. (This CVE is an **IPv6 DoS, not a SQL injection** —
  don't mislabel it.)
- **Truncator ReDoS — CVE-2024-27351** (fixed 3.2.25 / 4.2.11 / 5.0.3):
  `Truncator.words(html=True)` and the `truncatewords_html` template filter are
  ReDoS-prone on a crafted string; if a template truncates user-supplied HTML,
  a pathological input hangs the worker.
- **Async-view middleware ordering**: Django adapts sync↔async middleware
  (`sync_to_async`/`async_to_sync` per `async_capable`/`sync_capable`). Mixed
  stacks can create adaptation gaps — verify CSRF/auth middleware actually runs
  on the async view path, not just the sync one; test the same route as an async
  view for weaker enforcement.
- **Auth timing / enumeration**: Django's default login runs the password hasher
  even for nonexistent users to blunt timing, but custom auth backends and
  bespoke login views often skip that — measure response-time deltas between a
  known and unknown username, and combine with CVE-2024-45231's reset-flow
  outcome differential.

## Bypass Techniques

- Content negotiation: JSON vs form data hitting different parser/permission paths
- HTTP method override or trailing slash routing to alternate view
- Parameter pollution: duplicate `id` fields in query and body
- Race on state transitions (coupon redemption, inventory) via parallel requests
- Versioned API (`/api/v1/` vs `/api/v2/`) with weaker auth on older version

## Testing Methodology

1. **Map surface** — URLs, DRF schema, admin, static/media paths
2. **Auth matrix** — Unauthenticated/user/staff for each endpoint and method
3. **Object ownership** — Swap IDs across two user accounts on every CRUD route
4. **Serializer audit** — Identify writable sensitive fields and nested relations
5. **Middleware order** — Confirm auth runs before business logic; check CSRF on session APIs
6. **Channel parity** — Same authorization on WebSocket actions as REST equivalents
7. **Settings review (white-box)** — DEBUG, ALLOWED_HOSTS, SECRET_KEY, session/cookie flags

## Validation

1. Side-by-side requests proving unauthorized access (IDOR, privilege escalation)
2. CSRF PoC executing state change with victim session (for session-authenticated endpoints)
3. SQLi/template injection with deterministic oracle (error, timing, or `7*7` equivalent)
4. Document view/serializer/permission class where enforcement failed
5. Show admin or staff capability gained from regular user context if applicable

## False Positives

- `queryset.filter(user=request.user)` consistently applied including nested routes
- Object-level permission class correctly validates ownership on all actions
- DEBUG=False and generic error pages with no settings leakage confirmed
- Mark_safe used only on server-generated trusted content
- CSRF correctly enforced on all session-authenticated unsafe methods

## Impact

- Account takeover via session forgery or password reset poisoning
- Horizontal/vertical privilege escalation through IDOR and mass assignment
- Data breach via ORM/SQL injection or excessive serializer fields
- Server compromise via SSTI, pickle in cache (if used), or SSRF to internal services

## Pro Tips

1. DRF ViewSets often protect `list` but forget `destroy` or custom `@action` routes
2. Check `APIView` subclasses for missing `permission_classes` — common oversight
3. Test `?format=` and browsable API HTML responses for CSRF on session auth
4. `django.contrib.admin` uses separate auth — don't assume API auth covers admin
5. Compare ASGI WebSocket consumers against REST permissions for the same resource

## Tooling

Static analysis is the fastest way to reach the sinks above in white-box scope. The sandbox ships `python`/`pipx`, `semgrep`, `bandit`, `ast-grep`, and `ripgrep`.

- **bandit** (preinstalled) — Python security linter; flags `mark_safe`, `extra()`, `RawSQL`, `subprocess`, weak crypto, hardcoded secrets: `bandit -r . -ll`
- **semgrep** (preinstalled) with the Django ruleset — higher-signal than bandit for framework-specific bugs (`.extra()`, `RawSQL`, `|safe`, `csrf_exempt`, `ALLOWED_HOSTS=['*']`): `semgrep --config p/django .`
- **pip-audit** (PyPA) — dependency CVE scanner for known-vuln Django/DRF/simplejwt versions: `pipx install pip-audit && pip-audit -r requirements.txt`
- **ast-grep** (preinstalled) — quick structural grep for risky calls without a full SAST run: `ast-grep run -p 'mark_safe($X)' -l python`

For the `SECRET_KEY` → signed-cookie/reset-token forgery path noted under Session Issues, Django's own `django.core.signing` is the "tool": with a leaked key you can mint valid `signing.dumps()` values (session cookies, password-reset tokens, and `PickleSerializer`-backed session RCE).

## Summary

Django's defaults help (CSRF middleware, template auto-escape) but DRF, raw SQL, custom permissions, and deployment settings introduce frequent gaps. Test every endpoint with role-separated principals and verify object-level enforcement on querysets, not just authentication presence.
