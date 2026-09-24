---
name: auth0
description: Auth0 tenant security testing covering misconfigured rules/actions, scope escalation, MFA bypass, and cross-application token confusion
---

# Auth0

Auth0 misconfigurations enable account takeover, cross-tenant data access, and privilege escalation through Rules/Actions, loose application settings, weak API authorization, and token acceptance bugs in consuming applications. Test both the Auth0 tenant configuration and how downstream APIs validate Auth0-issued tokens.

## Attack Surface

**Auth0 Components**
- Applications: SPA, Regular Web, Native, Machine-to-Machine (M2M)
- APIs (Resource Servers): identifiers, scopes, RBAC, permissions
- Connections: database, social, enterprise (SAML/OIDC)
- Rules (legacy) and Actions (post-login, pre-user-registration, credentials exchange)
- Organizations (multi-tenant B2B), roles, permissions
- Universal Login, custom domains, custom database scripts

**Token Types**
- ID Token (OIDC), Access Token (JWT or opaque), Refresh Token
- Management API tokens, client credentials tokens (M2M)
- PAR, PKCE flows for public clients

**Management**
- Auth0 Management API (`/api/v2/`)
- Tenant settings, attack protection, MFA policies, anomaly detection
- Logs streaming, hooks, custom prompts

## Reconnaissance

**Tenant Discovery**
```
# From app config, JS bundles, mobile apps
domain: tenant.us.auth0.com / tenant.eu.auth0.com / login.customdomain.com
client_id, audience, scope values in authorize URLs
```

**OIDC Discovery**
```
GET https://TENANT.auth0.com/.well-known/openid-configuration
GET https://TENANT.auth0.com/.well-known/jwks.json
```

**Authenticated Userinfo** (requires bearer access token — unauthenticated requests return 401)
```
GET https://TENANT.auth0.com/userinfo
Authorization: Bearer <access_token>
```

**Application Fingerprint**
- Login redirect to `https://TENANT.auth0.com/authorize?client_id=...`
- `auth0-js`, `@auth0/auth0-spa-js`, `auth0-react` in frontend bundles
- API `audience` parameter in token requests

**Management API Exposure**
- Leaked M2M credentials with `read:users`, `update:users`, `create:users` scopes
- Management API called from browser (CORS misconfiguration)

## Key Vulnerabilities

### Application Configuration

**Callback URL / Origin Misconfigurations**
- Wildcard or overly broad Allowed Callback URLs: `https://app.com/*`, `http://localhost:*`
- Allowed Logout URLs, Web Origins, CORS origins too permissive
- Native app custom scheme hijacking (`com.app://callback`)

Auth0 matches `redirect_uri` against the Allowed Callback URLs list; the
practical bypasses:
- **`*` wildcard scope** — `https://app.com/*` matches any path on the origin,
  so any **open redirect on `app.com`** turns into code interception:
  `redirect_uri=https://app.com/out?url=https://attacker.tld/`. This is the
  most common real chain; load `open_redirect` for the redirector and the
  per-language `redirect_uri`-matching parser differentials.
- **`http://localhost:*`** left in a production app → an attacker who can make
  the victim's browser reach a localhost listener (or a dev proxy) captures the
  code; also useful when combined with DNS rebinding.
- **Trailing-segment / encoding tricks** against the exact match: test
  `https://app.com/callback/..%2f..%2f`, added path/query/fragment, and case,
  comparing what Auth0 accepts to where the code actually lands.
- **`post_logout_redirect_uri`** (Allowed Logout URLs) is validated
  separately and usually more loosely — test it for the same open-redirect
  chain to bounce a logged-out victim to a phishing origin on a trusted URL.

**Token Settings**
- ID Token used as API access token (audience/scope confusion)
- Refresh token rotation disabled; overly long TTL
- Signing algorithm downgrade if RS256 not enforced downstream

### API Authorization (Resource Server)

**Missing Scope/RBAC Enforcement**
- API accepts any valid access token without required `scope` or `permissions` claim
- RBAC enabled in Auth0 but API doesn't call `/userinfo` or validate `permissions` array
- Wrong `audience` accepted — token for App A works on App B's API

**Test:**
```
# Token for audience A used against API B
Authorization: Bearer <token_with_audience_A>
```

### Rules and Actions Abuse

**Post-Login Rule/Action Injection**
- Rules that add claims based on unvalidated user metadata:
  ```javascript
  user.app_metadata.role = 'admin'  // if user can set app_metadata via signup/API
  ```
- `context.authorization` manipulation in Actions
- Secrets in Rule code exposed to tenant admins or via Management API leak

**Signup / Registration Actions**
- `pre-user-registration` not blocking disposable emails or role self-assignment
- Social connection account linking without verified email → account takeover

**Actions runtime internals.** Actions are sandboxed Node functions triggered
per flow (`post-login`, `pre-user-registration`, `credentials-exchange`,
`post-change-password`, `send-phone-message`). The security-relevant APIs and
their failure modes:
- **`api.access.deny(reason)`** is the *only* thing stopping a login in a
  post-login Action. If the deny is inside a conditional that attacker input
  can falsify (a claim, an `event.request` field, a metadata value the user
  can set), the gate is bypassable. Trace every path that reaches or skips the
  `deny`, and test whether a second login, a different connection, or a
  different application skips the Action entirely.
- **Custom claims** — `api.idToken.setCustomClaim(name, value)` /
  `api.accessToken.setCustomClaim(...)`. If the value derives from
  `event.user.app_metadata`/`user_metadata` that a user can influence (signup
  payload, a self-service profile update, a writable Management API scope), the
  attacker sets their own roles/permissions claim. Namespaced claims
  (`https://app/roles`) are trusted by downstream APIs — this is the core
  privilege-escalation path.
- **`event.secrets`** — Action secrets (API keys, signing secrets, webhook
  URLs) are readable by anyone who can view/edit the Action (tenant admins,
  and anyone with `read:actions` on the Management API). A leaked Management
  token with `read:actions` dumps every Action's source *and* its secrets.
- **`api.redirect.sendUserTo(url, ...)`** (redirect Actions) — if `url` is
  built from `event.request.query`/user input, it is an open redirect *inside
  the auth flow* (and, server-side, an SSRF surface if the continue-token is
  fetched). Validate the redirect target; test the resume (`/continue`) step.
- **`credentials-exchange`** (M2M) Actions can add scopes to client-credentials
  tokens; a flaw here grants an M2M app more than its authorized scopes.

### Organizations (B2B Multi-Tenancy)

- Missing `org_id` validation in API — user from Org A accesses Org B data
- Invitation flows accepting attacker email domains
- Organization membership not re-checked after role change

### MFA Bypass

- MFA not enforced on Management API or high-risk applications
- Remember-browser cookie bypasses step-up for sensitive actions
- MFA challenge only on Universal Login but API accepts password-grant tokens without MFA
- Recovery codes/brute-force on enrollment endpoints

### Account Takeover Vectors

- Password reset link not invalidated after use; predictable reset tokens
- Email verification not required before sensitive actions
- Change password without re-auth or MFA
- Linking attacker's social IdP to victim account (same email, unverified)

**Account-linking takeover PoC.** Auth0 does not auto-link identities by
default, but apps commonly implement "link by email" in a post-login Action or
trust `email` without checking `email_verified`. Two exploit paths:
- **Unverified-email auto-link** — register with a social/enterprise IdP (or a
  DB connection) using the *victim's email* but an IdP that returns
  `email_verified: false` (or one the attacker controls). If the app's linking
  logic keys on `email` alone, the attacker's identity is merged into the
  victim's account → full takeover. Confirm the connection's `email_verified`
  value in the resulting profile and prove login as the victim.
- **Management-API forced link** — with a leaked `update:users` Management
  token, `POST /api/v2/users/{victim_id}/identities` with an attacker-owned
  `provider`/`user_id` (see Management API) links your credential onto the
  victim, then authenticate through that provider.
Validate by logging into the victim account via the attacker-controlled
identity and reading victim-only data; screenshot the merged `identities`
array as evidence.

### Management API

- M2M app with excessive scopes: `delete:users`, `update:users_app_metadata`
- Management API token in frontend JavaScript or mobile app
- Rate limiting absent on `/api/v2/users` enumeration

**Leaked M2M credentials → tenant-wide takeover.** A client_id/client_secret
for an M2M app authorized against the *Auth0 Management API* audience is
game over. Mint a token and drive `/api/v2/`:
```bash
# 1) exchange leaked M2M creds for a Management API token
TOKEN=$(curl -s https://TENANT.auth0.com/oauth/token -H 'Content-Type: application/json' -d '{
  "client_id":"<leaked>","client_secret":"<leaked>",
  "audience":"https://TENANT.auth0.com/api/v2/","grant_type":"client_credentials"}' | jq -r .access_token)
# 2) enumerate/read users (with read:users)
curl -s "https://TENANT.auth0.com/api/v2/users?per_page=100" -H "authorization: Bearer $TOKEN"
```
High-impact writes, by scope:
- `update:users` / `update:users_app_metadata` → `PATCH /api/v2/users/{id}`
  setting `app_metadata.roles` (or the RBAC role via
  `POST /api/v2/users/{id}/roles`) → privilege escalation of any user.
- **`update:users` + account linking → ATO.** Link an identity *you* control
  onto a victim's user object; you then authenticate as them:
  ```bash
  curl -s -X POST "https://TENANT.auth0.com/api/v2/users/<VICTIM_ID>/identities" \
    -H "authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"provider":"<your-conn>","user_id":"<ATTACKER_SUB>"}'
  ```
- `create:users` → seed an admin user in the tenant's DB connection.
- `read:client_keys`/`read:actions` → dump client secrets and Action secrets
  (see `event.secrets`).
Enumerate the token's real scopes first (decode the JWT `scope` claim); report
the exact scope that enabled each action.

### Custom Database Scripts

- Custom login script with SQL injection in username lookup
- `get_user` script returning excessive profile fields
- Scripts with hardcoded credentials or weak hashing

Custom DB connections run tenant-authored Node scripts (`login`, `get_user`,
`create`, `verify`, `change_password`, `delete`) against a real backend. The
`login` and `get_user` scripts take the attacker-supplied email/username and
frequently concatenate it into SQL — injectable from the login form / token
endpoint, pre-authentication:
```javascript
// vulnerable login script (concatenated query)
function login(email, password, callback) {
  const q = "SELECT id, password FROM users WHERE email = '" + email + "'";
  connection.query(q, function (err, rows) { /* ... */ });
}
```
- Inject via the `username`/`email` field: `' OR '1'='1' -- ` to return the
  first user, or `' UNION SELECT 1,'<bcrypt-of-known-pw>' -- ` to control the
  compared hash → authenticate as anyone. Blind boolean/time-based works the
  same as any SQLi (load `sql_injection`).
- `get_user` (used by password-reset/enumeration flows) injects the same way
  and runs even when the account doesn't exist — a pre-auth SQLi oracle.
- The script's DB credentials live in the script or connection config; a
  successful injection or a `read:connections` Management token exposes them.

## Advanced Techniques

**Cross-Application Token Confusion**
- Same `client_secret` reused across environments (dev/prod)
- Multiple APIs sharing signing keys without `aud` validation

**Resource Owner Password Grant (if enabled)**
- Legacy grant enabled — direct username/password to token endpoint, bypassing Universal Login MFA
- ROPC posts credentials straight to `/oauth/token`, skipping the interactive
  Universal Login where MFA, bot detection, and Actions-based step-up normally
  live — so it is both an **MFA-bypass** and a **credential brute-force**
  surface:
  ```bash
  curl -s https://TENANT.auth0.com/oauth/token -H 'Content-Type: application/json' -d '{
    "grant_type":"password","username":"victim@corp.com","password":"<guess>",
    "client_id":"<public_client_id>","audience":"<api>","scope":"openid","realm":"<db-connection>"}'
  ```
  (`grant_type=http://auth0.com/oauth/grant-type/password-realm` when the
  connection realm is required.) Requires the grant enabled on the app and a
  tenant **Default Directory** set. Check whether MFA policies actually apply
  to this path — many tenants enforce MFA only in Universal Login. Attempt
  detection is weaker here; pair with `weak_password_detection` for spray
  cadence and lockout behavior.

**Impersonation / Delegation**
- `act_as` or delegation features misconfigured (legacy features in older tenants)

## Testing Methodology

1. **Extract tenant config** — Domain, client_id, audience, scopes from app
2. **Callback/origin matrix** — Fuzz Allowed Callback URLs and Web Origins
3. **Token validation** — Swap audiences, strip scopes, expired tokens, wrong signing keys
4. **Org boundary** — Two org users accessing each other's org-scoped resources
5. **MFA policy** — Sensitive actions without step-up; API paths bypassing MFA
6. **Management API** — Hunt for leaked M2M creds; test scope boundaries
7. **Rules/Actions** — Trace claim injection from `user_metadata` / `app_metadata`

## Validation

1. Demonstrate account takeover or cross-org access with token/callback/metadata abuse
2. Show API accepting token without required scope/permission/audience
3. MFA bypass PoC on protected application flow
4. Document Auth0 setting (Rule, Application config, API RBAC) root cause
5. Provide authorize → callback → API request chain with evidence

## False Positives

- Callback URL validation rejects all fuzz attempts consistently
- API validates `aud`, `iss`, `scope`/`permissions` on every request
- MFA enforced via Auth0 Action on every login for sensitive apps
- `app_metadata` writable only by admin via Management API, not user signup
- Organizations feature correctly binds `org_id` in token and API enforces it

## Impact

- Full account takeover across Auth0-connected applications
- Cross-tenant data breach in B2B org deployments
- Privilege escalation via metadata/claim injection in Rules
- Mass user enumeration/modification via Management API abuse

## Pro Tips

1. Always capture full authorize URL — `audience` and `scope` reveal API targets
2. Decode access token JWT — check `permissions`, `scope`, `org_id`, `https://.../roles` claims
3. Test dev/stage tenants separately — often weaker callback rules
4. Pair with `oauth` and `authentication_jwt` skills for flow/token layer testing
5. Management API M2M creds in CI logs are high-value — search GitHub, buckets, artifacts

## Summary

Auth0 security spans tenant configuration (callbacks, MFA, Rules) and downstream API token validation (`aud`, `scope`, `permissions`, `org_id`). A perfectly configured Universal Login fails if the API accepts tokens without enforcing Auth0's authorization model.
