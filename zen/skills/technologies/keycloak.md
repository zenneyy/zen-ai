---
name: keycloak
description: Keycloak security testing covering realm/client misconfiguration, admin REST API exposure, redirect_uri bypass CVE classes, SAML/OIDC implementation flaws, offline-token abuse, and default-credential risk on self-hosted deployments
---

# Keycloak

Keycloak is a self-hosted identity provider — the attack surface includes both the identity-platform configuration (realms, clients, flows) and the deployment itself (admin API exposure, default credentials, container security). This skill owns Keycloak-specific surfaces: the admin REST API, realm/client misconfiguration, Keycloak CVE classes, and self-hosted deployment risks. It references `auth0` for shared identity-platform concepts (OIDC/OAuth flow mechanics, token validation, callback URL patterns) and `protocols/oauth` for protocol-level fundamentals — those are not re-implemented here.

## Attack Surface

**Identity Configuration**
- Realms: master (admin), tenant realms; realm settings (login, tokens, keys, sessions)
- Clients: confidential (server), public (SPA/mobile), bearer-only; flows, redirect URIs, scopes
- Users: federation (LDAP/Kerberos/AD), identity brokering (social/SAML/OIDC IdPs)
- Roles: realm roles, client roles, composite roles, service account roles
- Authentication flows: browser, direct grant, registration, reset credentials, first broker login

**Admin Interface**
- Admin REST API: `/admin/realms/{realm}/*` — full CRUD on users, clients, roles, flows
- Admin Console: `/admin/master/console/` (SPA)
- Default credentials: `admin:admin` on first startup (prompted to change, but change can be skipped)
- `admin-cli` client: public client pre-configured for ROPC (no client_secret required)

**Protocol Endpoints**
- OIDC: `/realms/{realm}/protocol/openid-connect/*` (auth, token, userinfo, certs, logout)
- SAML: `/realms/{realm}/protocol/saml`, `/realms/{realm}/protocol/saml/descriptor`
- Account console: `/realms/{realm}/account/` (self-service profile, sessions, credentials)
- Well-known: `/realms/{realm}/.well-known/openid-configuration`

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# OIDC discovery — reveals all endpoints, supported grant types, and signing algorithms
curl -s https://<target>/realms/<realm>/.well-known/openid-configuration | jq .

# Realm detection — common realm names
for realm in master main app sso auth default; do
  curl -so /dev/null -w "%{http_code} $realm\n" https://<target>/realms/$realm/
done

# Version disclosure — the OIDC discovery or login page often contains version info
# Cookie names: KEYCLOAK_IDENTITY, KEYCLOAK_SESSION, KC_RESTART, AUTH_SESSION_ID

# Admin console reachability
curl -sI https://<target>/admin/master/console/
```

Measured on Keycloak 26.0 (`start-dev`): OIDC discovery returns full configuration unauthenticated, including all grant types (`password`, `authorization_code`, `implicit`, `client_credentials`), all endpoints, and signing key metadata. The admin console path returns the SPA shell (HTTP 200) but requires authentication to operate.

**Deployment signals**
- Default port `:8080` (HTTP) / `:8443` (HTTPS); reverse-proxied on `:443`
- `/auth/` prefix on older Keycloak versions (pre-17); absent on Quarkus-based (17+)
- `X-Powered-By`, `Server` headers if not stripped

## Key Vulnerabilities

### Realm and Client Misconfiguration

**Public clients with overly broad flows**
- Public client (no client_secret) with `Direct Access Grants Enabled` (ROPC) — any user's credentials can be exchanged for tokens directly, bypassing the interactive login flow and any browser-based MFA. The built-in `admin-cli` client is public with ROPC enabled by default. Measured: password spray against `admin-cli` with default Keycloak produces tokens without any lockout (brute force protection is off by default).
- `Implicit Flow Enabled` on a confidential client — tokens in URL fragments.
- `Standard Flow` with wildcard redirect URIs (`*`, `http://localhost:*`) — the same class as auth0 callback-URL misconfig, but owned by `auth0`; here, confirm the Keycloak-specific redirect_uri validation (see CVE section below).

**Service account over-scoping**
- Confidential client with `Service Accounts Enabled` and realm-management roles (manage-users, manage-clients, manage-realm) — an M2M token grants full admin control. Equivalent to auth0's leaked M2M credentials; the platform-specific residual is that Keycloak service accounts are per-client, and scope is assigned via role mappings in the admin console.

**Token settings**
- Realm-level token lifespans: access token TTL too long (default 5 minutes, often extended to hours); refresh token TTL and idle timeout; offline token lifespan (default infinite).
- `Audience` not validated downstream — a token issued for Client A accepted by Client B's API.

### Admin REST API Exposure

The admin API (`/admin/realms/{realm}/*`) provides full CRUD over users, clients, roles, flows, and federation. It is the single highest-value endpoint on a Keycloak deployment.

- **Default credentials:** `admin:admin` on first startup. The prompted password change can be skipped in `start-dev` mode and some container orchestrations. Measured: default creds via ROPC on `admin-cli` return a valid admin token, then `GET /admin/realms/master/users` returns the full user list including `bruteForceProtected: false`.
- **CVE-2024-3656** (CVSS 8.1) — low-privilege users could access certain admin endpoints (user/group management) that should have been restricted to realm admins. Affected Keycloak before the fix; check version.
- **Admin API from the internet:** the admin API shares the same port/host as user-facing authentication in default deployments. Network-level restriction (reverse proxy ACL, Keycloak's `--hostname-admin` option) is the mitigation; test from the assessment vantage point.

### Redirect URI Validation Bypass (CVE Classes)

Keycloak has carried multiple redirect_uri validation bypasses — this is a recurring CVE class:

- **CVE-2024-1132** (CVSS 8.1) — path traversal in redirect_uri validation; bypass URL validation via encoded traversal sequences to redirect tokens to an attacker-controlled path.
- **CVE-2023-6291** (CVSS 7.1) — bypass of allowed-host redirect_uri validation enabling access token theft via open redirect.
- **CVE-2024-2419** (CVSS 7.1) — parsing flaw in redirect_uri comparison; variant of 6291.
- **CVE-2024-8883** (CVSS 6.1) — loopback redirect bypass; `localhost`/`127.0.0.1` in Valid Redirect URIs allows redirect to an arbitrary port/path.

The pattern: Keycloak's redirect_uri matching has repeatedly failed on encoding normalization, path traversal, and loopback edge cases. On every engagement, test the registered redirect URIs with traversal (`../`, `%2e%2e/`), fragment injection, query-string appending, and loopback substitution — even on patched versions, new variants in this class continue to appear.

### SAML and OIDC Implementation Flaws

- **CVE-2022-4361** (CVSS 10.0) — XSS in SAML and OIDC providers via attacker-set `AssertionConsumerServiceURL` or `redirect_uri` values that inject script into error pages. Critical; check version.
- **CVE-2023-0264** (CVSS 5.0) — incorrect OIDC authentication of requests using replay information; authentication confusion under specific conditions.
- Identity brokering: when Keycloak brokers login to an external IdP, the `First Broker Login` flow's account-linking step may link an attacker-controlled external identity to a victim's Keycloak account if email verification is not enforced. The same account-linking takeover class as in `auth0` (pointer — see auth0's account-linking section); the Keycloak-specific expression is in the `First Broker Login` flow configuration.

### Custom Authentication Flow Abuse

Keycloak's authentication flows are composable: browser flow, direct grant flow, registration, reset credentials, first broker login, and custom flows built from authenticator SPI providers. Security implications:

- **Authenticator ordering bypass:** flows evaluate authenticators sequentially or as alternatives. A flow with `Username Password Form` as REQUIRED and `OTP Form` as ALTERNATIVE allows login without OTP — the "alternative" designation means it is offered but not enforced when another authenticator in the same execution group succeeds.
- **Custom authenticator scripts:** Keycloak supports JavaScript authenticator scripts (deprecated in newer versions but still present on older deployments). A script authenticator with access to the session can be misconfigured to always return SUCCESS, bypass conditions, or leak session data.
- **Registration flow abuse:** the registration flow controls self-registration; if enabled without CAPTCHA or email verification, an attacker can create arbitrary accounts in the realm — including accounts with the same email as existing users if `Duplicate Emails` is allowed.
- **Reset credentials flow:** if the flow does not enforce the `Choose User` → `Send Reset Email` → `Update Password` sequence correctly (e.g., a custom flow skips email verification), an attacker can reset any user's password by supplying only their username.

**Enumeration via flows:** the login, registration, and password-reset flows reveal user existence by default — different error messages or response times for valid vs invalid usernames. Keycloak's `Login with Email` setting, when disabled, exposes username enumeration on the login form.

### Token Exchange and Impersonation

Keycloak supports token exchange (RFC 8693) — exchanging one token type for another. Security implications:

- **Internal-to-internal exchange:** a service with a valid access token exchanges it for a token impersonating a different user (`requested_subject` parameter). If the exchanging client's permissions allow impersonation, this is a legitimate feature; if the permissions are over-scoped, it is privilege escalation.
- **External-to-internal exchange:** exchanging a token from an external IdP for a Keycloak token. If the external IdP is attacker-controlled (identity brokering misconfiguration), the attacker mints arbitrary Keycloak tokens.
- Token exchange is disabled by default but frequently enabled for microservice architectures — check `Token Exchange` permission on the `token-exchange` scope in the client's service account roles.

**User federation LDAP injection:** when Keycloak federates against an LDAP/AD backend, user lookup queries are constructed from user input. If Keycloak's LDAP query escaping has gaps (version-dependent), login and search fields may be injectable — yielding LDAP injection pre-authentication. Test with standard LDAP injection payloads (`*`, `)(uid=*`, `\00`) against the login form.

### Offline Token and Session Abuse

- Offline tokens (`offline_access` scope) have infinite lifespan by default; a stolen offline token persists through password changes and session revocation unless explicitly revoked per-token.
- **CVE-2023-6563** (CVSS 7.7) — DoS via offline tokens; realms with >500k offline tokens cause unconstrained memory consumption.
- Session fixation: Keycloak rotates session IDs on login, but verify that the rotation actually fires on all flows (SAML, brokered, direct grant).

## Testing Methodology

1. **Fingerprint** version from OIDC discovery or login page; map to applicable CVEs.
2. **Default credentials** — try `admin:admin` via ROPC on `admin-cli` against the master realm.
3. **Admin API reachability** — confirm whether `/admin/realms/` is accessible from the assessment vantage point (internet vs internal).
4. **Realm enumeration** — probe common realm names (`master`, `main`, `app`, `sso`, `default`, company name); each discovered realm has its own client, user, and flow configuration to assess.
5. **Client inventory** — enumerate clients (if admin access obtained); identify public clients with ROPC/implicit, overly broad redirect URIs, and over-scoped service accounts.
6. **Authentication flow review** — inspect each flow's authenticator execution list; confirm MFA authenticators are REQUIRED not ALTERNATIVE; check registration and reset-credentials flows for missing verification steps.
7. **Redirect URI bypass** — test registered redirect URIs with traversal, fragment, query, and loopback variants against the target version's validation.
8. **Brute force** — confirm `bruteForceProtected` status on the realm; if disabled, demonstrate credential spray via ROPC on `admin-cli`.
9. **Token validation downstream** — test audience, issuer, and scope enforcement on APIs consuming Keycloak tokens.

## Validation

1. Show the Keycloak version and the CVE it maps to, with the primary advisory URL.
2. Default credentials: show the admin token obtained via ROPC and the admin API response (user list or realm config).
3. Redirect URI bypass: show the crafted redirect_uri and the token/code delivered to the attacker-controlled endpoint.
4. Service account over-scope: show the client's service account roles and the admin API action it can perform.
5. Brute force: show the brute-force-protection setting (`bruteForceProtected: false`) and a series of failed logins without lockout.
6. Authentication flow bypass: show the flow configuration with MFA as ALTERNATIVE and a login completing without the second factor.
7. Self-registration abuse: show an account created via the registration flow without email verification or CAPTCHA.

## False Positives

- `admin-cli` with ROPC enabled is **default and expected** — the finding is when default admin credentials work or when brute-force protection is off and the endpoint is internet-reachable, not the client configuration alone.
- OIDC discovery is **public by specification** — its exposure is expected; the finding is what the discovery reveals about enabled grant types and endpoints.
- Redirect URI validation passing all tests on a patched version — not a finding; report the version and patch status.
- Admin console reachable but authentication enforced — down-rate if the admin API is not accessible without valid credentials (still report internet exposure of the admin path).
- `start-dev` mode in a development/staging environment — confirm production vs non-production before reporting default-credential findings at high severity.
- Self-registration enabled intentionally (some applications require public sign-up) — the finding is missing CAPTCHA or email verification on the registration flow, not registration being enabled.
- Username enumeration on realms configured for internal-only use — down-rate when the realm is not internet-facing.

## Impact

- Full tenant takeover via admin API access (default credentials or CVE-2024-3656) — create/modify/delete users, clients, and roles.
- Account takeover via redirect_uri bypass — steal authorization codes or tokens.
- Credential spray at scale via public ROPC client with no brute-force protection.
- Persistent access via stolen offline tokens surviving password changes.
- XSS (CVE-2022-4361) in the identity provider context — session theft affecting all relying-party applications.
- Arbitrary account creation via unprotected registration flow — attacker provisions accounts in the realm without authorization.
- MFA bypass via authentication flow misconfiguration (ALTERNATIVE vs REQUIRED) — second factor skipped entirely.
- User impersonation via token exchange with over-scoped service account permissions.
- LDAP credential exposure when Keycloak federates against an LDAP backend and the attacker controls the Keycloak host.

## Pro Tips

1. Always try `admin:admin` on `admin-cli` via ROPC first — it's the fastest path to full admin control and it works more often than expected on internet-facing deployments.
2. `bruteForceProtected: false` is the default — check realm settings before assuming lockout exists.
3. The redirect_uri bypass CVE class recurs; test even on patched versions with novel encoding combinations.
4. Offline tokens are the persistence primitive — if you obtain one, it survives password resets and session revocation.
5. Review authentication flow execution lists — the ALTERNATIVE vs REQUIRED distinction on MFA authenticators is the single most common Keycloak MFA bypass.
6. Pair with `auth0` for shared identity concepts, `protocols/oauth` for OIDC fundamentals, `ssrf` if Keycloak's identity brokering fetches attacker-controlled URLs, and `authentication_jwt` for downstream token validation.

## Summary

Keycloak's attack surface combines identity-platform misconfiguration (public ROPC clients, over-scoped service accounts, wildcard redirect URIs, authentication flow misordering) with self-hosted deployment risks (default credentials, internet-exposed admin API, brute-force protection off by default). The redirect_uri validation bypass is a recurring CVE class — test encoding variants even on patched versions.

The admin REST API is the single highest-value target — default credentials via ROPC on `admin-cli` is the first test. Token exchange and offline tokens are persistence primitives that survive credential rotation.
