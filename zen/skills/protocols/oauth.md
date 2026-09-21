---
name: oauth
description: OAuth 2.0/2.1 and OIDC flow security testing covering redirect manipulation, token leakage, PKCE bypass, DPoP sender-constrained tokens, PAR/RAR, request_uri/JWKS/DCR SSRF, response_mode form_post XSS, and client misconfiguration
---

# OAuth 2.0 / OIDC

OAuth and OIDC failures often enable account takeover, token theft, and cross-client token confusion. Treat every redirect, client identifier, and token exchange as an authorization boundary — not a convenience layer.

## Attack Surface

**Flows**
- Authorization code (with/without PKCE)
- Implicit (legacy), hybrid, device authorization, client credentials
- Refresh token rotation, token introspection, revocation

**Endpoints**
- `/authorize`, `/token`, `/userinfo`, `/introspect`, `/revoke`, `/logout`
- `/.well-known/openid-configuration`, `/jwks.json`
- Dynamic client registration (if enabled)

**Token Types**
- Authorization codes, access tokens, refresh tokens, ID tokens
- Opaque vs JWT formats; reference tokens vs self-contained JWTs

**Client Types**
- Public clients (SPAs, mobile) vs confidential (server-side)
- Multiple redirect URIs, wildcard/pattern matching, custom URI schemes

## Reconnaissance

**Discovery**
```
GET /.well-known/openid-configuration
GET /oauth2/.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
```

Extract: `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, supported `response_types`, `code_challenge_methods_supported`, `grant_types_supported`.

**Client Enumeration**
- Inspect JS bundles, mobile APK/IPA configs, GitHub repos for `client_id`, redirect URIs, scopes
- Check error messages for client validation hints ("invalid redirect_uri", "unregistered client")

## Key Vulnerabilities

### Redirect URI Manipulation

**Open Redirect Chains**
- Register or guess permissive redirect patterns: `https://app.com/callback`, path-prefix only, subdomain wildcards
- Test: append paths, fragments, query injection, `@` tricks, encoded slashes, backslash variants

```
https://app.com/callback.evil.com
https://app.com/callback%2f..%2f@evil.com
https://app.com/callback?next=https://evil.com
com.app://callback  (mobile custom scheme)
```

**Redirect URI Validation Bypasses**
- Trailing slash, case, port, scheme downgrade (`http` vs `https`)
- Path normalization differentials between IdP validator and consuming app
- `redirect_uri` parameter pollution (first vs last wins)
- Wildcard subdomain acceptance: `*.app.com` → register `attacker.app.com` or find dangling subdomain

The core `redirect_uri` bug is a **parser differential**: the IdP validates one
representation (its registration-match logic) while the browser navigates to
another. The highest-yield payloads against exact/prefix matchers are the
backslash-before-userinfo (`https://good.app\@evil.tld`), the single-slash
scheme (`https:/evil.tld`), and encoded-slash forms — which the IdP's validator
and the browser resolve differently. Load `open_redirect` for the **empirically
measured per-language URL-parser table** (which forms resolve to which host on
Python/PHP/Node/Go/Java); apply it to both the IdP's validator *and* the
client's callback handler, since they often use different parsers. The
OAuth-specific chain is: pass the IdP's exact match, then land the `code` on an
open redirect hosted on the registered origin (below / see `open_redirect`).

### Authorization Code Issues

**Code Leakage**
- Codes in URL fragments, Referer headers, browser history, server logs, analytics
- Code replay before expiry; missing one-time-use enforcement
- Code sent to wrong redirect_uri if binding is weak

**Code Injection / Mix-Up**
- Attacker initiates flow, victim completes login, code delivered to attacker's redirect
- Mix-up attack: swap `client_id` between authorize and token steps
- Missing `redirect_uri` binding at token endpoint

### State and Nonce

- Missing, predictable, or reusable `state` → CSRF on OAuth login (session fixation, account linking)
- Missing `nonce` in OIDC → ID token injection/replay
- `state` not bound to client session or PKCE verifier

### PKCE Bypass

- `code_challenge_method` downgrade: accept `plain` instead of `S256`
- Missing PKCE requirement on public clients
- `code_verifier` not validated or compared case-insensitively with weak matching
- Authorization code issued without challenge, token endpoint accepts any verifier

### Client Authentication

**Public Client Abuse**
- Token endpoint accepts requests without `client_secret` for confidential clients
- `client_id` only authentication on token/introspection endpoints
- Dynamic registration with attacker-controlled redirect URIs

**Secret Leakage**
- Hardcoded secrets in mobile apps, SPAs, or public repos
- `client_secret` accepted in query string or logged in access logs

### Scope and Token Issues

- Scope escalation: request `admin`/`offline_access`/`openid profile email` beyond app need; server grants all requested scopes
- Refresh token not rotated or reuse not detected → persistent access
- Access token accepted across services (missing audience/resource binding)
- Token introspection returns `active:true` without proper auth on introspection endpoint

### OpenID Connect Specific

- ID token accepted as access token at resource servers (token confusion)
- `acr`, `amr`, `auth_time` not validated for step-up requirements
- Userinfo endpoint returns PII without matching access token scope
- `sub` collision across issuers if `iss` not validated

## Advanced Techniques

**Referer Leakage**
- Embed authorized redirect as subresource on attacker page; harvest `code` from Referer if policy allows

**Device Flow Abuse**
- Poll `device_code` endpoint with guessed codes; slow rate limits only
- User approves attacker-initiated device login

**Account Linking**
- OAuth login links attacker's IdP identity to victim's local account without re-auth
- Email collision: same email from different IdP providers

### Modern OAuth (2.1 / DPoP / PAR / RAR)

- **OAuth 2.1** (`draft-ietf-oauth-v2-1`) folds in the security BCP: PKCE
  mandatory for *all* clients, implicit and ROPC grants removed, **exact**
  redirect-URI string matching, refresh-token rotation or sender-constraining
  for public clients. Test whether an AS claiming 2.1 actually enforces these —
  one that still issues via implicit, accepts `code_challenge_method=plain`, or
  does prefix redirect matching is the finding.
- **DPoP — sender-constrained tokens (RFC 9449).** The client proves possession
  of a key on every call via a `DPoP` header carrying a proof JWT; the access
  token binds to the key thumbprint in `cnf.jkt`. Proof structure (built here):
  ```
  header: {"typ":"dpop+jwt","alg":"ES256","jwk":{...public key...}}
  claims: {"htm":"POST","htu":"https://as/token","iat":...,"jti":...,
           "ath":"<base64url(sha256(access_token))>"}   # ath only when calling an RS
  ```
  Attacks: (1) RS doesn't verify the `htu`/`htm`/`ath` binding → a *stolen*
  access token replays without the key; (2) no `jti`/`iat` replay-window check →
  proof replay; (3) `DPoP-Nonce` not enforced. If DPoP is absent, access tokens
  are plain **bearer** and replay from anywhere — the common case.
- **PAR (RFC 9126)** — the client POSTs the auth request to `/par` and gets a
  one-time `request_uri`; the front channel then carries only `client_id` +
  `request_uri`, so front-channel tampering is closed. Test `request_uri` reuse
  (must be one-time), and whether the AS still honors front-channel parameter
  overrides sent *alongside* a PAR `request_uri`.
- **RAR (RFC 9396)** — `authorization_details` (a JSON array) replaces coarse
  scopes. Test crafted `authorization_details` `type`/fields the AS grants
  without validating, and scope-vs-`authorization_details` confusion at the RS.

### SSRF Surfaces (request_uri / JWKS / DCR)

The AS/RS dereferences several client-supplied URLs — each is an SSRF (and
sometimes a key-injection) surface:
- **`request_uri` (RFC 9101 JAR)** — the AS fetches the request object from the
  supplied URL → SSRF to internal/metadata; also test a `request_uri` that
  302-redirects internally.
- **`jwks_uri`** — the AS/RS fetches verification keys from this URL. If a client
  can set it (via DCR or config) to an attacker origin, it's SSRF *and* token
  forgery (the fetched key verifies attacker-signed tokens — cross-ref the `jku`
  attack in `authentication_jwt`).
- **Dynamic Client Registration (RFC 7591)** — `jwks_uri`, `logo_uri`,
  `sector_identifier_uri`, and `request_uris` are all URLs the AS may fetch or
  render. `sector_identifier_uri` is fetched at registration; `logo_uri` may be
  rendered (stored XSS/SSRF). Register a client with these pointing at
  `169.254.169.254`/internal hosts. Load `ssrf` for the fetch-side bypasses.

### response_mode=form_post XSS

`response_mode=form_post` makes the AS return an **auto-submitting HTML form**
carrying the `code`/`id_token` in hidden inputs. If the AS reflects request
parameters (`state`, `redirect_uri`, error text) into that HTML **unescaped**,
you get XSS on the *AS origin* — which can read the code/token off the same
page and defeat the redirect. Inject into `state`/`redirect_uri` and inspect the
form_post response body for unescaped reflection. (`response_mode=query` leaks
the code via Referer/logs; `fragment` via JS — test which mode the flow allows.)

## Testing Methodology

1. **Map flows** — Identify all grant types, clients, and redirect URIs in use
2. **Redirect matrix** — For each client, fuzz redirect_uri validation with encoding and parser tricks
3. **CSRF** — Initiate OAuth without `state`; swap sessions mid-flow
4. **PKCE** — Replay codes with wrong/missing verifier; downgrade challenge method
5. **Token exchange** — Swap codes/tokens between clients; test cross-audience acceptance
6. **Mobile/deep links** — Custom schemes, intent filters, universal links hijacking

## Validation

1. Demonstrate stolen authorization code or token via redirect manipulation or Referer leak
2. Show account takeover or access to victim resources with attacker's OAuth session
3. Prove CSRF: victim completes login into attacker's linked session without consent UI bypass where applicable
4. Document exact validation gap (redirect binding, PKCE, state, audience)
5. Provide full authorize → callback → token request chain with before/after evidence

## False Positives

- Redirect URI rejected consistently across all bypass attempts
- Public client correctly requires PKCE S256 with strict verifier validation
- `state`/`nonce` enforced and bound; CSRF test fails as expected
- Token audience/issuer correctly validated at resource server
- Custom scheme redirects require app ownership proof (verified Android/iOS app links)

## Impact

- Full account takeover via stolen authorization codes or tokens
- Persistent access through refresh token theft
- Cross-tenant or cross-client data access via token confusion
- PII exposure from userinfo or ID token claim leakage

## Pro Tips

1. Always capture the full redirect chain including intermediate 302 locations
2. Compare authorize-step and token-step parameter binding (`redirect_uri`, `client_id`, PKCE)
3. Test both web and mobile clients — validation rules often differ
4. Check logout/revocation — tokens may remain valid after "logout"
5. Chain with open redirect or XSS on the legitimate redirect_uri to exfiltrate codes

## Tooling

The sandbox ships **jwt_tool** (already cloned at `/home/pentester/tools/jwt_tool`) plus `curl` — enough for the token side of OAuth/OIDC.

- **jwt_tool** (ticarpi) — inspect and tamper ID tokens / JWT access tokens: `alg:none`, `HS256`/`RS256` key confusion, `kid` injection, claim editing (`sub`, `aud`, `iss`, `exp`):
  ```
  python3 /home/pentester/tools/jwt_tool/jwt_tool.py <ID_TOKEN>                    # decode/inspect
  python3 /home/pentester/tools/jwt_tool/jwt_tool.py <ID_TOKEN> -X a               # alg:none
  python3 /home/pentester/tools/jwt_tool/jwt_tool.py <ID_TOKEN> -X k -pk pub.pem   # RS256->HS256 confusion
  ```
- **curl** — drive the authorize → callback → token chain by hand so you control every parameter (`redirect_uri`, `client_id`, `state`, PKCE `code_challenge`/`code_verifier`) and can test the binding/downgrade cases above.

Humans often use Burp's **EsPReSSO** (RUB-NDS) SSO extension for flow visualization; it is GUI-only, so prefer manual `curl` + `jwt_tool` in-sandbox.

## Summary

OAuth security hinges on strict redirect URI binding, unguessable state/nonce, PKCE for public clients, and consistent token audience validation. Any gap in the authorize-to-token chain is a potential account takeover.
