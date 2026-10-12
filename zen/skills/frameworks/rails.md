---
name: rails
description: Security testing playbook for Ruby on Rails applications covering mass assignment, ActiveRecord injection, unsafe deserialization, and session/routing vulnerabilities
---

# Ruby on Rails

Security testing for Ruby on Rails applications. Focus on mass assignment bypass, ActiveRecord SQL injection, unsafe deserialization (Marshal/YAML), ERB template injection, and the signed-cookie session model sharing Flask's key-leakage risk class.

## Attack Surface

**Core Components**
- Routing: RESTful resources, globbing (`*path`), constraints, namespaces, engines
- Controllers: ActionController, `params`, strong parameters (`permit`), filters (`before_action`)
- Views: ERB, Slim, Haml templates, `render` with dynamic targets
- Models: ActiveRecord ORM, callbacks, validations, scopes, raw SQL

**Authentication & Session**
- `_rails_session` cookie: signed and encrypted with `secret_key_base` (Rails 4+)
- Devise, OmniAuth, bcrypt-ruby, `has_secure_password`
- CSRF protection via `protect_from_forgery` and authenticity tokens

**Deployment**
- Puma/Unicorn behind nginx, Heroku, Docker
- `RAILS_ENV=development` in production (verbose errors, console)
- Credentials file (`config/credentials.yml.enc`), `config/master.key`

## High-Value Targets

- Controllers with permissive strong parameters or `params.permit!`
- Endpoints using `find_by_sql`, `.where(string)`, `.order(string)` with user input
- File upload/download endpoints (`Active Storage`, `send_file`, `send_data`)
- Admin namespaces (ActiveAdmin, RailsAdmin, custom `/admin`)
- API endpoints (Rails API mode) with relaxed CSRF or different auth
- `render` calls with user-controlled template paths
- Background jobs (Sidekiq, DelayedJob) processing user-supplied data
- WebSocket channels (Action Cable) with weaker auth than HTTP

## Reconnaissance

**Fingerprinting**
```
curl -sI https://target/
# X-Powered-By: Phusion Passenger  (sometimes present)
# Set-Cookie: _rails_session=...  (or _<app_name>_session)
# X-Request-Id: uuid format
# X-Runtime: 0.123456  (Rails timing header)

curl -s https://target/nonexistent
# Rails default 404: "The page you were looking for doesn't exist"
# Development mode: full routing error page listing all routes
```

**Route Discovery (development mode)**
```
GET /rails/info/routes    # lists all routes if development mode
GET /rails/info           # Rails info page with version, environment
GET /rails/mailers        # lists mailer previews
```

**Error Page Leakage**
Development mode error pages expose: full stack trace, request parameters, session contents, `ENV` variables, loaded gems with versions, complete route table.

## Key Vulnerabilities

### Mass Assignment

Even with strong parameters, mass assignment vulnerabilities persist:

**Permissive permit**
```ruby
params.require(:user).permit!              # permits everything — worst case
params.require(:user).permit(:name, :role) # role should not be user-settable
```

**Nested attributes bypass**
```ruby
# accepts_nested_attributes_for can expose associated model fields
params.require(:order).permit(:total, line_items_attributes: [:id, :price])
# user sets :price on line_items → total manipulation
```

**JSON API parameter wrapping**: Rails wraps JSON bodies into params — test setting `is_admin`, `role`, `balance`, `verified` on every create/update endpoint.

Cross-ref: `mass_assignment` for parameter injection techniques and automated testing.

### SQL Injection (ActiveRecord)

**Vulnerable patterns**
```ruby
# String interpolation in where
User.where("name = '#{params[:name]}'")
User.where("role = '#{role}' AND active = true")

# find_by_sql
User.find_by_sql("SELECT * FROM users WHERE token = '#{params[:token]}'")

# order with user input
User.order(params[:sort])  # ORDER BY injection — can extract data via conditional errors

# pluck/select with user input
User.pluck(params[:field])
```

Safe alternatives (`where(name: value)`, `where("name = ?", value)`) parameterize correctly. The risk is string interpolation or concatenation reaching any query method.

**`Arel.sql()` wrapping**: `User.order(Arel.sql(params[:sort]))` explicitly marks input as raw SQL — it's an intentional escape hatch, but if `params[:sort]` is user-controlled, it's a direct injection sink.

Cross-ref: `sql_injection` for injection payloads, blind extraction, and database-specific syntax.

### Unsafe Deserialization

Rails has a history of critical deserialization vulnerabilities:

**CVE-2013-0156** — XML parameter parsing accepted YAML type markers, allowing arbitrary Ruby object instantiation via crafted XML requests. Affected Rails 2.x–3.x. This introduced the class of Rails deserialization attacks.

**Marshal.load / YAML.load**
```ruby
Marshal.load(user_input)  # arbitrary object instantiation → RCE
YAML.load(user_input)     # same — YAML supports arbitrary Ruby objects
# Safe alternatives: YAML.safe_load, JSON.parse
```

**Cookie store + secret_key_base**: Rails 4+ encrypts and signs the session cookie with `secret_key_base`. If this key is leaked (from `credentials.yml.enc` compromise, env exposure, or git history), an attacker can forge session cookies. In Rails 4.x with the cookie store, the session was serialized with Marshal — a leaked key → forged Marshal payload → RCE.

**Rails 7+ defaults**: `config.active_support.message_serializer = :json` (safe). Earlier versions default to Marshal — fingerprint the Rails version and check the serializer configuration.

Cross-ref: `insecure_deserialization` for Ruby gadget chains and Marshal exploitation.

### Template Injection (ERB)

```ruby
# Vulnerable: user input as template source
render inline: params[:template]    # ERB evaluation of user input → RCE
render plain: params[:msg]          # safe — plain text, no evaluation

# ERB RCE
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
```

Standard `render :show` with file-based templates is safe. The risk is `render inline:` with user input, or `render file:` with a user-controlled path (local file disclosure).

**`render file:` disclosure**
```ruby
render file: params[:page]  # reads and returns arbitrary file contents
# Test: render file: '/etc/passwd'
```
Rails 6+ restricts `render file:` to the app directory by default, but earlier versions allow absolute paths.

Cross-ref: `ssti` for template injection detection; `path_traversal_lfi_rfi` for file disclosure via `render file:`.

### CSRF

Rails includes CSRF protection by default (`protect_from_forgery with: :exception`), but gaps exist:

- `skip_before_action :verify_authenticity_token` on state-changing endpoints
- API mode (`config.api_only = true`) disables CSRF middleware entirely
- CSRF token in `<meta>` tag reusable across tabs — no per-request token by default
- JSON-only endpoints: Rails skips CSRF verification for non-form content types by default, but cross-origin `fetch()` with credentials can send JSON if CORS allows it

### Command Injection

```ruby
system("convert #{params[:file]} output.pdf")
`ping #{params[:host]}`
exec("nslookup #{params[:domain]}")
IO.popen("dig #{params[:name]}")
%x(curl #{params[:url]})
```
Ruby offers multiple shell execution methods — all are sinks if user input reaches them unsanitized.

Cross-ref: `rce` for shell metacharacter payloads and Ruby-specific injection.

### Session & Authentication

- **Devise token fixation**: password reset tokens, confirmation tokens, and unlock tokens — check for token reuse after consumption, timing leaks on token comparison, and brute-forceable token spaces.
- **`secret_key_base` leakage**: enables session forgery, message verifier forgery (password reset tokens, signed URLs), and potentially RCE via Marshal deserialization in older Rails versions.
- **Timing attacks**: `Devise.secure_compare` mitigates, but custom token comparisons using `==` are vulnerable.

### Routing Exploits

- **Glob routes**: `get '*path', to: 'pages#show'` matches everything — may bypass auth middleware or expose unintended controller actions.
- **Constraint bypass**: route constraints using regex without anchors (`/\d+/` vs `/\A\d+\z/`) allow injection of trailing characters.
- **Engine mounting**: mounted engines (RailsAdmin, Sidekiq::Web) may not inherit the host app's auth middleware.

## Bypass Techniques

- Content-type switching: `application/json` vs `application/xml` vs `multipart/form-data` — different parameter parsing and CSRF handling
- HTTP method override: `_method` parameter or `X-HTTP-Method-Override` header (Rails respects both by default)
- Parameter wrapping: Rails auto-wraps JSON body into `params[:controller_name]` — test fields at both nesting levels
- Format suffix: `/users/1.json` vs `/users/1.xml` vs `/users/1` — different response paths, potentially different auth
- Versioned API: `/api/v1/` vs `/api/v2/` with weaker auth on older version

## Testing Methodology

1. **Fingerprint** — Identify Rails via `_rails_session` cookie, `X-Runtime` header, error page format, route listing
2. **Route enumeration** — Discover all routes via development mode pages, client-side JS, or path fuzzing
3. **Mass assignment** — Test every create/update endpoint with unexpected fields (`role`, `is_admin`, `balance`, `verified`)
4. **SQLi audit** — Inject in all parameters reaching `where`, `order`, `pluck`, `find_by_sql` with string interpolation
5. **Auth matrix** — Test each route across unauthenticated, user, and admin with method override (`_method`)
6. **Session analysis** — Attempt to forge or decode `_rails_session` if `secret_key_base` is leaked
7. **Deserialization** — Fingerprint Rails version and serializer; test for Marshal-based session exploitation if key is available
8. **Template injection** — Test `render inline:` and `render file:` paths with user input

## Validation Requirements

- Mass assignment: field injection changing role/privilege on create or update (show before/after state)
- SQLi: error-based, blind, or data extraction via ActiveRecord string interpolation
- Deserialization RCE: code execution via Marshal payload in forged session (requires leaked `secret_key_base`)
- Template injection: ERB evaluation (`<%= 7*7 %>` → `49`) or file disclosure via `render file:`
- CSRF bypass: state-changing action executed cross-origin without valid authenticity token
- Auth bypass: side-by-side requests showing unauthorized access with method override or route manipulation
- Command injection: OS command output via Ruby shell execution methods
