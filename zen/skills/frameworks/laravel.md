---
name: laravel
description: Security testing playbook for Laravel applications covering APP_KEY exploitation, Ignition RCE, mass assignment, Blade SSTI, and debug/config exposure
---

# Laravel

Security testing for Laravel (PHP) applications. Focus on `APP_KEY`-based session forgery and deserialization RCE, Ignition debug mode exploitation, mass assignment via Eloquent, Blade template injection, and exposure of debug/admin tooling (Telescope, Horizon).

## Attack Surface

**Core Components**
- Routing: `routes/web.php`, `routes/api.php`, route model binding, middleware groups
- Controllers: resource controllers, form requests, `$request->input()`/`$request->all()`
- Views: Blade templates (`{{ }}` escaped, `{!! !!}` raw), component attributes
- ORM: Eloquent models, `$fillable`/`$guarded`, query builder, raw queries

**Authentication & Session**
- `laravel_session` cookie: encrypted with `APP_KEY` (AES-256-CBC or AES-256-GCM)
- `XSRF-TOKEN` cookie: encrypted CSRF token for JavaScript frameworks
- Laravel Sanctum (SPA/API tokens), Passport (OAuth2), Fortify, Breeze, Jetstream
- Guards and providers, multi-auth

**Debug & Admin**
- Laravel Telescope (request/job/query inspector)
- Laravel Horizon (Redis queue dashboard)
- Ignition error page (debug mode)
- Artisan console, `tinker`

**Deployment**
- Apache/nginx with PHP-FPM, Laravel Forge, Vapor (serverless)
- `.env` file with `APP_KEY`, database credentials, API keys, mail credentials
- `APP_DEBUG=true` in production

## High-Value Targets

- `.env` file accessible via web (misconfigured web root or path traversal)
- Ignition error page when `APP_DEBUG=true` (CVE-2021-3129 RCE)
- Telescope (`/telescope`) and Horizon (`/horizon`) dashboards without auth
- Eloquent models with permissive `$guarded = []` or missing `$fillable`
- Endpoints using `DB::raw()`, `whereRaw()`, `selectRaw()` with user input
- File upload endpoints (`Storage::put`, `$request->file()->store()`)
- Password reset, email verification, and signed URL endpoints
- API routes using Sanctum with relaxed domain/SPA configuration

## Reconnaissance

**Fingerprinting**
```
curl -sI https://target/
# Set-Cookie: laravel_session=eyJ...  (encrypted, base64)
# Set-Cookie: XSRF-TOKEN=eyJ...  (encrypted CSRF token)
# X-Powered-By: PHP/8.x  (if not hidden)

curl -s https://target/nonexistent
# Laravel 404: "404 | Not Found" (default view)
# Debug mode: Ignition error page with full stack trace, request details, environment
```

**Debug/Admin Discovery**
```
GET /.env                     # direct .env exposure (misconfigured document root)
GET /telescope                # Telescope dashboard
GET /horizon                  # Horizon dashboard
GET /log-viewer               # laravel-log-viewer if installed
GET /_ignition/health-check   # Ignition health check (debug mode)
GET /api/documentation        # L5-Swagger if installed
```

**Ignition Detection**
The Ignition error page (when `APP_DEBUG=true`) displays: full stack trace, request parameters, headers, session data, environment variables, executed queries, and application configuration. This alone is a critical finding — it leaks `APP_KEY` and database credentials.

## Key Vulnerabilities

### APP_KEY Exploitation

`APP_KEY` is the master encryption key for the application — it encrypts session cookies, CSRF tokens, signed URLs, and any data encrypted via `Crypt::encrypt()`. Laravel uses AES-256-CBC (or AES-256-GCM in newer versions) with this key.

**If APP_KEY is leaked:**
- **Session forgery**: decrypt the `laravel_session` cookie, modify its contents (user ID, role), re-encrypt, and replay. Laravel sessions are server-side (file/database/Redis) by default, but the session ID is encrypted in the cookie.
- **Deserialization RCE**: Laravel's cookie serialization used PHP `unserialize()` on the decrypted cookie value in older versions. With a known `APP_KEY`, craft a malicious serialized PHP object (using gadget chains from `phpggc`) in the cookie → server decrypts and deserializes → RCE.
- **Signed URL forgery**: forge password reset links, email verification URLs, and any route using `URL::signedRoute()`.

**APP_KEY discovery vectors**: `.env` file exposure, Ignition debug page, git history, environment variable leaks, `/actuator/env` if Spring-style management exists, error messages.

```bash
# phpggc for Laravel gadget chains
phpggc Laravel/RCE1 system 'id' | base64
# Forge encrypted cookie with known APP_KEY
```

Cross-ref: `insecure_deserialization` for PHP gadget chains and phpggc usage; `cryptographic_failures` for key management weaknesses.

### Debug Mode — Ignition RCE (CVE-2021-3129)

When `APP_DEBUG=true`, Laravel uses Ignition as the error handler. **CVE-2021-3129** (Ignition ≤ 2.5.1, Facade Ignition ≤ 2.5.1) allows RCE via the `_ignition/execute-solution` endpoint by chaining a file write (via the `MakeViewVariableOptionalSolution`) with a `phar://` deserialization trigger.

**Exploitation steps**
```
POST /_ignition/execute-solution HTTP/1.1
Content-Type: application/json

{
  "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
  "parameters": {
    "variableName": "x",
    "viewFile": "php://filter/write=convert.base64-decode/resource=<path>/exploit.phar"
  }
}
```

**Detection**: `GET /_ignition/health-check` returning `{"can_execute_commands":true}` confirms vulnerability. The Ignition error page alone confirms debug mode.

Even without CVE-2021-3129, debug mode leaks `APP_KEY`, database credentials, API keys, and full application state — always a critical finding.

Cross-ref: `rce` for PHP exploitation and phar deserialization; `information_disclosure` for debug page data extraction.

### .env Exposure

Laravel's `.env` file contains all sensitive configuration: `APP_KEY`, `DB_PASSWORD`, `MAIL_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, API tokens. If the web server document root is set to the project root instead of `/public`, `.env` is directly accessible:

```
GET /.env HTTP/1.1
# Returns: APP_KEY=base64:...
#          DB_PASSWORD=...
#          MAIL_PASSWORD=...
```

Also test: `/.env.backup`, `/.env.old`, `/.env.production`, `/.env.local`, and path traversal to reach `.env` from the public directory.

### Mass Assignment (Eloquent)

```php
// Vulnerable: no $fillable or $guarded = []
$user = User::create($request->all());
$user->update($request->all());

// Bypass: $fillable exists but misses sensitive fields
// POST: name=test&email=test@test.com&is_admin=1&role=superadmin
```

**`$guarded = []`** (empty guard) permits all fields — equivalent to no protection. **Missing `$fillable`** on a model used with `create()`/`update()` is mass-assignable by default in older Laravel versions.

Test every create/update endpoint with: `is_admin`, `role`, `email_verified_at`, `balance`, `plan`, `permissions`, `password` (direct hash injection).

Cross-ref: `mass_assignment` for automated parameter discovery.

### Blade Template Injection

Blade's `{{ }}` syntax escapes output by default (htmlspecialchars). The risk is:

**Raw output**
```php
{!! $userInput !!}         // unescaped — XSS if user-controlled
{!! request('name') !!}   // direct XSS
```

**SSTI (if Blade source is user-controlled)**
```php
// Vulnerable: compiling user input as Blade template
Blade::render($userInput, $data);  // arbitrary PHP execution
// Blade compiles to PHP: <?php echo ... ?> — full code execution
@php system('id') @endphp
```

Standard use of `{{ $variable }}` in `.blade.php` files with server-side variables is safe against XSS. The risk is `{!! !!}` with user input or user-controlled template source.

Cross-ref: `ssti` for template injection detection; `xss` for output encoding bypass techniques.

### SQL Injection

```php
// Vulnerable: raw queries with user input
DB::select("SELECT * FROM users WHERE name = '" . $request->name . "'");
User::whereRaw("email = '" . $request->email . "'");
User::select(DB::raw("*, " . $request->input('field')));
DB::statement("DROP TABLE " . $request->table);

// Eloquent query builder is parameterized and safe:
User::where('name', $request->name);  // safe
```

`DB::raw()`, `whereRaw()`, `selectRaw()`, `orderByRaw()`, `groupByRaw()`, and `havingRaw()` with string concatenation are the sinks. The Eloquent query builder with `where('col', $value)` parameterizes correctly.

Cross-ref: `sql_injection` for injection payloads and PHP/MySQL-specific techniques.

### Telescope & Horizon Exposure

**Telescope** (`/telescope`) records all requests, queries, exceptions, jobs, mail, and cache operations. In production, it exposes:
- Full request/response data including auth tokens
- Database queries with bound parameters
- Exception traces with file paths and config
- Queued job payloads

**Horizon** (`/horizon`) is a Redis queue dashboard exposing:
- Job payloads and arguments
- Queue names, worker status
- Failed job details with full exception traces

Both should require auth middleware in production. Default installations may leave them open — check `TelescopeServiceProvider` and `HorizonServiceProvider` for `gate()` definitions.

### Path Traversal & File Operations

```php
// Vulnerable: user-controlled storage path
Storage::get($request->input('path'));
Storage::download($request->input('file'));
response()->download(storage_path($request->path));
```

Test with `../../../etc/passwd`, URL-encoded variants, and null byte injection (PHP < 5.3.4).

Cross-ref: `path_traversal_lfi_rfi` for traversal payloads.

## Bypass Techniques

- Middleware group gaps: `web` vs `api` middleware groups have different protections (CSRF, session, cookies) — test same endpoint via both route groups
- Route model binding: `/users/1` (integer) vs `/users/1%00` vs `/users/1%20` — binding resolution edge cases
- Content-type: `application/json` on web routes may bypass CSRF middleware (`VerifyCsrfToken` checks `_token` only for form submissions)
- HTTP method spoofing: `_method=DELETE` in POST body or `X-HTTP-Method-Override` header (Laravel supports both)
- Query string injection in Eloquent: `?sort=id;DROP TABLE users--` reaching `orderByRaw()`

## Testing Methodology

1. **Fingerprint** — Identify Laravel via `laravel_session`/`XSRF-TOKEN` cookies, error page style, `X-Powered-By: PHP`
2. **Debug check** — Request non-existent paths; check for Ignition error page; probe `/_ignition/health-check`
3. **.env exposure** — Test `/.env`, `/.env.backup`, path traversal to `.env`
4. **Admin tooling** — Check `/telescope`, `/horizon`, `/log-viewer` accessibility
5. **Mass assignment** — Test every create/update endpoint with unexpected privilege fields
6. **Auth matrix** — Test each route across unauthenticated, user, and admin with middleware group switching
7. **SQLi audit** — Focus on `DB::raw`, `whereRaw`, `orderByRaw` with user input
8. **APP_KEY exploitation** — If key is leaked, attempt session forgery and deserialization RCE

## Validation Requirements

- APP_KEY exploitation: session forgery with modified user/role, or deserialization RCE via phpggc
- Ignition RCE: command execution via `_ignition/execute-solution` (CVE-2021-3129)
- .env exposure: leaked credentials confirmed accessible and valid
- Mass assignment: privilege field modified via parameter injection (show before/after state)
- SQLi: error-based, blind, or data extraction via raw query methods
- Debug leakage: APP_KEY, database credentials, or API keys visible on error page
- Telescope/Horizon: sensitive request data or job payloads accessible without authentication
- Blade SSTI: template evaluation or PHP code execution via user-controlled template source
