---
name: application-enumeration-auth-multiservice-deep
description: Advanced authenticated surface, multi-tenant and multi-service architecture enumeration, and AI/ML endpoint discovery. Loaded automatically by deep scan mode as a companion to application_enumeration.md. Covers OAuth 2.0/2.1/OIDC flow variant enumeration, SAML entity discovery, WebAuthn credential enumeration, magic-link and passwordless flows, session mechanics, multi-tenant surface diffing, docker-compose/kubernetes/helm/service-mesh parsing depth, and 2024-2026 AI/ML endpoint patterns (LLM APIs, vector DBs, RAG source enumeration, agent-adjacent endpoints).
sibling: application_enumeration
load_when: scan_mode == "deep"
---

# Application Enumeration — Auth, Multi-Service & AI/ML (Deep)

This is the deep sibling to `application_enumeration` for three surfaces the base file only names in passing: the **authenticated** surface (OAuth/OIDC/SAML/WebAuthn/passwordless/session mechanics), the **multi-service architecture** behind a single origin (parsed from compose/k8s/helm/mesh source), and the **AI/ML** endpoints (LLM APIs, vector DBs, RAG sources, agent/tool/MCP surfaces) that 2024-2026 apps expose.

It loads only in deep scan mode. Its companion `application_enumeration_api_deep` owns the *server-side API protocols* (REST/GraphQL/gRPC/WebSocket/WebRTC) and `application_enumeration_client_deep` owns the *client-side runtime* (workers, WASM, module federation, source maps) — this file does not re-enumerate those; it enumerates the identity layer that gates them, the service topology that hosts them, and the model-serving endpoints that back them. Auth *exploitation* lives in the vuln skills (`oauth`, `authentication_jwt`, `csrf`, `open_redirect`, `idor`, `race_conditions`); AI *exploitation* lives in `llm_applications` / `llm_prompt_injection`. This file stops at enumeration and points there.

The method: query every identity discovery document first (it hands you the whole feature set for free), diff the authenticated surface across roles and tenants, parse infrastructure source for the internal service graph, then enumerate the model-serving layer. Endpoint patterns and specs verified 2026-09-13; where a spec or product moved recently (OAuth 2.1 draft, MCP Streamable HTTP, ChromaDB/Milvus API versions, OpenAI Responses API), the current form is given. Never replay, exfiltrate, or use a discovered live credential, token, or assertion — record its presence, location, and scope only.

## OAuth 2.0/2.1 and OIDC Depth

OAuth/OIDC discovery documents publish the entire authorization-server feature set — grants, scopes, endpoints, key material. Query them first; everything else in this section refines what they reveal.

### Discovery endpoint enumeration

**Pattern**: `/.well-known/openid-configuration` (OIDC Discovery) and `/.well-known/oauth-authorization-server` (RFC 8414) at the issuer root, and sometimes per-tenant (`/<tenant>/.well-known/openid-configuration`).

```bash
for b in "" "/oauth2" "/auth/realms/<realm>" "/<tenant>"; do
  curl -s "https://<target>$b/.well-known/openid-configuration" | jq '{issuer,authorization_endpoint,token_endpoint,jwks_uri,userinfo_endpoint,registration_endpoint,introspection_endpoint,revocation_endpoint,pushed_authorization_request_endpoint,grant_types_supported,scopes_supported,response_types_supported,response_modes_supported,code_challenge_methods_supported}' 2>/dev/null; done
```

**Gotcha**: the discovery doc is the authoritative feature map — it names every endpoint (introspection/revocation/PAR/registration) and lists supported grants, scopes, response types, and PKCE methods; a feature listed here that the app never uses in the browser is exactly the "forgotten" surface to probe.

### Grant type enumeration

`grant_types_supported` lists what the server accepts. Each grant is a distinct surface: Authorization Code (+PKCE), Client Credentials (machine-to-machine), Device Authorization Grant (RFC 8628, `urn:ietf:params:oauth:grant-type:device_code`), Resource Owner Password Credentials (ROPC, deprecated), Implicit (deprecated), Token Exchange (RFC 8693), refresh_token.

```bash
curl -s https://<target>/.well-known/openid-configuration | jq '.grant_types_supported, .device_authorization_endpoint'
```

**Gotcha**: ROPC (`password`) and Implicit (`token`) are deprecated but frequently still enabled for legacy clients — ROPC turns the token endpoint into a credential-testing oracle (route to `weak_password_detection`), and the Device grant's user-code flow is often under-rate-limited; each enabled legacy grant is a finding on its own.

### Scope enumeration via error messages

Some IdPs echo the set of valid/available scopes in an error when an invalid scope is requested, or grant a superset silently.

```bash
curl -s "https://<target>/oauth2/authorize?client_id=<id>&response_type=code&scope=__invalid__&redirect_uri=<uri>" -i | grep -iE 'scope|error_description'
```

**Gotcha**: an `invalid_scope` error that lists valid scopes leaks the full privilege vocabulary (e.g. `admin:read`, `billing:write`); also test requesting broad scopes (`openid profile email offline_access <admin-ish>`) — a server that issues a token for an over-broad scope without consent is an over-privilege finding.

### Client enumeration

Public clients (SPAs, mobile) ship their `client_id` in the JS bundle (see `application_enumeration_client_deep`); confidential clients need a secret. Invalid vs valid `client_id` often produce different errors.

```bash
grep -rhoE "client_id['\"]?\s*[:=]\s*['\"][A-Za-z0-9._-]{8,}" bundles/ | sort -u
for c in <id1> <id2> __bogus__; do
  echo "$c $(curl -s -o /dev/null -w '%{http_code}' "https://<target>/oauth2/authorize?client_id=$c&response_type=code&redirect_uri=https://x")"; done
```

**Gotcha**: a differential response (unknown-client error vs redirect-uri-mismatch error) confirms a valid `client_id` — enumerate clients this way, then test each client's redirect-URI and grant configuration independently; different clients often have wildly different (and weaker) settings.

### Redirect URI enumeration

Redirect-URI validation is the classic OAuth weak point. Test the registered value against relaxed variants.

```bash
# probe validation strictness (record which are accepted, do not follow to a real attacker host)
for u in "https://app.tld/cb" "https://app.tld/cb/../x" "https://app.tld.evil.tld/cb" "https://app.tld@evil.tld" "https://app.tld:8443/cb" "https://app.tld/cb#@evil.tld" "https://sub.app.tld/cb"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://<target>/oauth2/authorize?client_id=<id>&response_type=code&redirect_uri=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$u")"); echo "$code  $u"; done
```

**Gotcha**: prefix/suffix matching, path-traversal, userinfo `@`, port, and subdomain-wildcard weaknesses all turn into token theft — load `open_redirect` for the chained exploitation; OAuth 2.1 mandates *exact* redirect-URI matching, so any accepted variant means the server is not on 2.1 semantics.

### Authorization response mode enumeration

`response_modes_supported` lists how the response is delivered: `query`, `fragment`, `form_post`, and `jwt` (JARM — JWT Secured Authorization Response Mode).

```bash
curl -s https://<target>/.well-known/openid-configuration | jq '.response_modes_supported, .authorization_response_iss_parameter_supported'
```

**Gotcha**: `fragment`/`query` delivery puts the code/token where browser history and Referer can leak it; JARM (`response_mode=jwt`) signs the whole response — its absence where sensitive flows exist is a hardening gap, and forcing `response_mode=query` on a flow designed for `form_post` sometimes bypasses response-integrity checks.

### Response type enumeration

`response_types_supported` distinguishes pure OAuth code flow from OIDC hybrid flows: `code`, `token` (implicit), `id_token`, `code id_token`, `code token`, `code id_token token`.

```bash
curl -s https://<target>/.well-known/openid-configuration | jq '.response_types_supported'
```

**Gotcha**: any `token`-bearing response type is an implicit/hybrid flow that returns an access token straight to the front channel (browser) — a deprecated, leak-prone path; a server offering `code token` or `id_token token` exposes the hybrid-flow attack surface (id_token/access_token substitution, nonce handling).

### JWKS URI analysis

`jwks_uri` serves the public signing keys used to verify issued JWTs.

```bash
curl -s "$(curl -s https://<target>/.well-known/openid-configuration | jq -r .jwks_uri)" | jq '.keys[] | {kid,kty,alg,use,n_len:(.n|length)}'
```

**Gotcha**: the JWKS lets you *verify* tokens offline and feeds `authentication_jwt` (algorithm-confusion, `kid` injection); multiple `kid`s hint at rotation cadence, and an RSA key with a short modulus or an `alg` set including `none`/`HS*` alongside `RS*` is a direct algorithm-confusion lead.

### Token endpoint variants

The `token_endpoint` serves multiple grant exchanges: `authorization_code`, `refresh_token`, `client_credentials`, and device-code polling. Each takes different parameters and often enforces auth differently.

```bash
curl -s -X POST https://<target>/oauth2/token -d 'grant_type=client_credentials&client_id=<id>&client_secret=<secret>&scope=<s>' | jq '{error,error_description,scope,token_type}'
```

**Gotcha**: a `client_credentials` grant that succeeds with a bundle-leaked "public" client secret, or issues a token with more scope than requested, is a privilege finding; the same endpoint's `refresh_token` path is where rotation (or its absence) is testable.

### Introspection endpoint

RFC 7662 `introspection_endpoint` returns metadata about a token (active, scope, sub, exp, client_id).

```bash
curl -s -X POST "$(curl -s https://<target>/.well-known/oauth-authorization-server | jq -r .introspection_endpoint)" \
  -d "token=<token>" -u '<client_id>:<client_secret>' | jq .
```

**Gotcha**: introspection is supposed to require client authentication — an endpoint that introspects any token with weak/absent client auth is a token-metadata oracle (confirm a stolen token's validity, scope, and owner); record whether it authenticates the caller.

### Revocation endpoint

RFC 7009 `revocation_endpoint` revokes tokens.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$(curl -s https://<target>/.well-known/oauth-authorization-server | jq -r .revocation_endpoint)" -d "token=<token>"
```

**Gotcha**: a revocation endpoint that accepts a token without validating the requesting client can let one client revoke another client's tokens — a denial-of-service against sessions; note whether client authentication is enforced.

### UserInfo endpoint

OIDC `userinfo_endpoint` returns claims for the bearer token.

```bash
curl -s "$(curl -s https://<target>/.well-known/openid-configuration | jq -r .userinfo_endpoint)" -H "Authorization: Bearer <token>" | jq .
```

**Gotcha**: the claims returned here (email, groups, roles, `hd`, custom org claims) map the identity model and often reveal more than the ID token; test whether it accepts tokens issued for other clients/audiences (audience confusion) and whether claims can be over-fetched.

### Dynamic Client Registration (RFC 7591)

`registration_endpoint` lets clients self-register; some deployments allow it anonymously.

```bash
curl -s -X POST "$(curl -s https://<target>/.well-known/openid-configuration | jq -r .registration_endpoint)" \
  -H 'Content-Type: application/json' -d '{"redirect_uris":["https://x/cb"],"client_name":"recon"}' | jq '{client_id,registration_access_token,error}'
```

**Gotcha**: anonymous DCR is a significant finding — you can register a client with attacker-controlled `redirect_uris`, `token_endpoint_auth_method: none`, and requested scopes, turning the IdP into an authorization primitive you control; record if it succeeds without a bearer/software statement.

### Rich Authorization Requests (RAR, RFC 9396)

`authorization_details_types_supported` indicates RAR: fine-grained authorization via an `authorization_details` JSON parameter instead of coarse scopes.

```bash
curl -s https://<target>/.well-known/openid-configuration | jq '.authorization_details_types_supported'
```

**Gotcha**: RAR carries structured, per-transaction authorization (e.g. `{"type":"payment","amount":...}`) — a rich, under-validated input surface; enumerate the supported `type`s and test whether the values (amounts, account ids, actions) are validated server-side or trusted from the request.

### Pushed Authorization Requests (PAR, RFC 9126)

`pushed_authorization_request_endpoint` (often `/oauth2/par`) accepts the authorization request out-of-band and returns a `request_uri`.

```bash
curl -s -X POST "$(curl -s https://<target>/.well-known/openid-configuration | jq -r .pushed_authorization_request_endpoint)" \
  -u '<client_id>:<secret>' -d 'response_type=code&scope=openid&redirect_uri=<uri>' | jq .
```

**Gotcha**: PAR is a hardening feature (parameters can't be tampered in the browser), but the PAR endpoint itself is a new authenticated surface — test its client auth and whether `require_pushed_authorization_requests` is enforced (if PAR is optional, the classic front-channel tampering surface still exists in parallel).

### OAuth 2.1 differences

OAuth 2.1 (`draft-ietf-oauth-v2-1`, an IETF draft treated as the current best-practice profile, not yet an RFC) consolidates 2.0 + security BCP: PKCE mandatory for *all* clients, Implicit and ROPC grants removed, exact redirect-URI matching, refresh tokens must be sender-constrained or one-time rotating, and bearer tokens forbidden in query strings.

**Gotcha**: use 2.1 as a compliance yardstick — if the server accepts an authorization request without PKCE, offers Implicit/ROPC, does relaxed redirect matching, or issues non-rotating bearer refresh tokens, it is running pre-2.1 semantics and each of those is a concrete finding; MCP's auth spec (below) builds on OAuth 2.1, so AI backends increasingly expose these endpoints too.

## SAML Depth

SAML metadata is self-describing XML that publishes entity IDs, consumer/logout URLs, certificates, and NameID formats — the SAML equivalent of an OIDC discovery doc.

### SAML metadata endpoint discovery

**Pattern**: `/saml/metadata`, `/api/saml/metadata`, `/auth/saml/metadata`, `/sso/saml/metadata`, `/simplesaml/module.php/saml/sp/metadata.php` (SimpleSAMLphp), `/adfs/ls/` and `/FederationMetadata/2007-06/FederationMetadata.xml` (ADFS), `/realms/<realm>/protocol/saml/descriptor` (Keycloak).

```bash
for p in /saml/metadata /api/saml/metadata /auth/saml/metadata /sso/saml/metadata /simplesaml/module.php/saml/sp/metadata.php /FederationMetadata/2007-06/FederationMetadata.xml; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
```

**Gotcha**: SP metadata is usually public by design and hands you the entity ID, ACS/SLO URLs, signing/encryption certs, and required NameID formats in one document — pull it before probing anything else in this section.

### Entity ID enumeration

The metadata's `entityID` identifies the SP (and, in IdP metadata, the IdP); one org frequently has many SP entities (one per integrated app).

```bash
curl -s https://<target>/saml/metadata | xmllint --xpath '//*[local-name()="EntityDescriptor"]/@entityID' - 2>/dev/null
```

**Gotcha**: multiple `entityID`s reveal multiple SAML integrations behind the same org — each is a separate trust relationship with its own ACS and its own (possibly weaker) assertion validation; enumerate them all as distinct targets.

### AssertionConsumerService (ACS) URL enumeration

The `AssertionConsumerService` URLs are the SP endpoints that receive and process SAML assertions.

```bash
curl -s https://<target>/saml/metadata | xmllint --xpath '//*[local-name()="AssertionConsumerService"]/@Location' - 2>/dev/null
```

**Gotcha**: the ACS is where assertion-parsing (and its bugs — signature-wrapping, XXE, comment truncation) live; multiple ACS bindings (HTTP-POST vs HTTP-Artifact) may be validated by different code paths — record each Location and Binding.

### SingleLogoutService (SLO) enumeration

`SingleLogoutService` URLs handle logout, often with less scrutiny than login.

```bash
curl -s https://<target>/saml/metadata | xmllint --xpath '//*[local-name()="SingleLogoutService"]/@Location' - 2>/dev/null
```

**Gotcha**: SLO endpoints frequently accept LogoutRequest/LogoutResponse with weaker signature validation than the ACS — a common spot for signature-bypass and session-fixation issues; enumerate and test SLO separately from login.

### NameID format enumeration

`NameIDFormat` entries declare accepted subject identifier formats: `emailAddress`, `persistent`, `transient`, `unspecified`, `X509SubjectName`.

```bash
curl -s https://<target>/saml/metadata | xmllint --xpath '//*[local-name()="NameIDFormat"]/text()' - 2>/dev/null
```

**Gotcha**: different NameID formats are often normalized by different code — `unspecified` in particular is a loosely-validated free-form identifier; a format mismatch between what the SP requests and accepts can enable account-linking confusion (route findings to `idor`/account-takeover analysis).

### SP-initiated vs IdP-initiated flows

SP-initiated flows require a signed `AuthnRequest`; IdP-initiated flows accept an *unsolicited* assertion at the ACS with no prior request.

```bash
# does the ACS accept an unsolicited POST (IdP-initiated)? (structure only — no forged assertion)
curl -s -o /dev/null -w '%{http_code}\n' -X POST "<ACS-URL>" -d 'SAMLResponse=<b64>&RelayState=/'
```

**Gotcha**: IdP-initiated SSO is inherently more dangerous — the SP consumes an assertion it never requested, so there is no `InResponseTo`/request binding to validate against, widening replay and injection surface; note whether IdP-initiated is enabled and whether `RelayState` is used as an open redirect.

### Attribute mapping enumeration

SAML `Attribute`/`AttributeStatement` values are mapped to application roles and identity.

```bash
curl -s https://<target>/saml/metadata | xmllint --xpath '//*[local-name()="RequestedAttribute"]/@Name' - 2>/dev/null
```

**Gotcha**: the requested attributes name exactly which claims the SP trusts for authorization (`role`, `groups`, `memberOf`, `isAdmin`) — the targets for assertion-manipulation/privilege escalation once a signing weakness exists; record the attribute names as the role model.

### Signed vs unsigned assertions

Metadata `WantAssertionsSigned` / `AuthnRequestsSigned` flags declare the SP's signature expectations.

```bash
curl -s https://<target>/saml/metadata | xmllint --xpath '//*[local-name()="SPSSODescriptor"]/@*[local-name()="WantAssertionsSigned" or local-name()="AuthnRequestsSigned"]' - 2>/dev/null
```

**Gotcha**: `WantAssertionsSigned="false"`, or signing the Response but not the Assertion (or vice-versa), is the precondition for XML Signature Wrapping and assertion injection — the single highest-impact SAML class; record the exact signing posture (this file enumerates it; exploitation is a downstream hunter).

### SAML metadata refresh mechanism

Some SPs periodically re-fetch IdP metadata (certs, endpoints) from a configured URL.

**Gotcha**: if the SP auto-refreshes IdP metadata from a URL that is attacker-influenceable (HTTP, a takeable host, an SSRF-reachable internal URL), poisoning that metadata swaps the trusted signing cert and compromises the whole trust — a high-impact, easily-forgotten surface; note any metadata URL the SP trusts and whether it is fetched over a weak channel.

### SAML analysis tooling

**Tools**: `SAML-tracer` (browser extension — capture and decode the live AuthnRequest/Response), `xmlsec1` (verify signatures), `xmllint` (XPath extraction above), SAMLtest.id (a reference IdP/SP for validation), Burp's SAML Raider extension (decode/edit/re-sign assertions during authorized testing).

**Gotcha**: decode every live SAML message with SAML-tracer first — the base64 `SAMLResponse` shows the actual attributes, conditions (`NotBefore`/`NotOnOrAfter`, `AudienceRestriction`), and signature scope, which is ground truth the metadata only hints at.

## WebAuthn and Passwordless

Passwordless surfaces (WebAuthn/passkeys, magic links, OTP) are often bolted on with less hardening than the password flow they replace. Enumerate the ceremony endpoints and their options.

### WebAuthn registration endpoint

**Pattern**: `/webauthn/register`, `/api/webauthn/registration/options`, `/auth/passkey/begin`, `/attestation/options` (FIDO conformance naming). Returns `PublicKeyCredentialCreationOptions`.

```bash
curl -s -X POST https://<target>/api/webauthn/registration/options -H 'Content-Type: application/json' -d '{"username":"<u>"}' \
  | jq '{rp,user,challenge:(.challenge|length),pubKeyCredParams,authenticatorSelection,attestation,excludeCredentials:(.excludeCredentials|length)}'
```

**Gotcha**: the creation options leak the RP ID, the user handle mapping, the accepted algorithms (`pubKeyCredParams`), and the attestation/UV policy — and `excludeCredentials` lists the user's *already-registered* credential IDs, i.e. a per-account credential enumeration if the endpoint answers for arbitrary usernames pre-auth.

### WebAuthn authentication endpoint

**Pattern**: `/webauthn/authenticate`, `/api/webauthn/authentication/options`, `/assertion/options`. Returns `PublicKeyCredentialRequestOptions`.

```bash
curl -s -X POST https://<target>/api/webauthn/authentication/options -H 'Content-Type: application/json' -d '{"username":"<u>"}' \
  | jq '{challenge:(.challenge|length),rpId,userVerification,allowCredentials}'
```

**Gotcha**: if `allowCredentials` is populated per-username, submitting valid vs invalid usernames is a user-enumeration oracle; an empty `allowCredentials` (discoverable-credential/usernameless flow) is a different, resident-key surface (below).

### WebAuthn credential enumeration

Account-settings endpoints list a user's registered authenticators (`/api/webauthn/credentials`, `/account/security/keys`).

```bash
curl -s https://<target>/api/webauthn/credentials -H "Authorization: Bearer <token>" | jq '.[]? | {id,type,name,createdAt,transports}'
```

**Gotcha**: a credentials list reachable with a weak/other-user token is an IDOR (route to `idor`); the `transports` and names (`YubiKey 5`, `iPhone`) fingerprint the user's devices, and credential IDs feed the `excludeCredentials`/`allowCredentials` enumeration above.

### Attestation format enumeration

The `attestation` option and returned statement `fmt` can be: `packed`, `tpm`, `android-key`, `android-safetynet` (deprecated), `fido-u2f`, `apple`, `none`.

**Gotcha**: `attestation: "none"` (or accepting a `none` statement when a specific format is expected) means the RP does not verify authenticator provenance — a spoofed/software authenticator is accepted; conversely, if the RP requires attestation and validates the cert chain, note that as stronger posture. Record the requested policy and whether the server validates the returned `fmt`.

### User verification requirements

`userVerification`: `required` | `preferred` | `discouraged` controls whether a PIN/biometric is checked.

**Gotcha**: `userVerification: "discouraged"` (or `preferred` treated as optional) permits *silent* authentication — mere possession of the authenticator, no user gesture — which weakens the second factor to a first; check the requested UV level and, at assertion verification, whether the server actually enforces the `UV` flag it asked for.

### Resident key (discoverable credential) support

`authenticatorSelection.residentKey`: `required`/`preferred`/`discouraged` and `requireResidentKey` indicate usernameless/discoverable credentials.

**Gotcha**: discoverable-credential flows accept an assertion with no username supplied (the credential carries the user handle) — a distinct code path where the server must map the returned `userHandle` to an account; test for user-handle confusion/IDOR in that mapping.

### Passkey conditional UI

Conditional mediation (`navigator.credentials.get({mediation:"conditional"})`) integrates passkeys into the browser autofill; look for it in the bundle and for a pre-fetched authentication challenge on page load.

```bash
grep -rhoE "mediation:\s*['\"]conditional['\"]|isConditionalMediationAvailable|autocomplete=['\"][^'\"]*webauthn" bundles/ *.html 2>/dev/null | sort -u
```

**Gotcha**: conditional UI issues an authentication challenge before the user acts — a challenge fetched on page load for any visitor can be a pre-auth enumeration/timing surface; note whether the challenge endpoint distinguishes existing from non-existing accounts.

### Magic link endpoint enumeration

**Pattern**: `/auth/magic-link`, `/auth/passwordless/email`, `/auth/otp/email`, `/login/link`. A token is emailed; validity depends on entropy, expiry, and single-use enforcement.

```bash
curl -s -X POST https://<target>/auth/magic-link -H 'Content-Type: application/json' -d '{"email":"<e>"}' -i | grep -iE 'http_code|token|expires|rate|retry-after'
```

**Gotcha**: magic-link security rests entirely on token unpredictability, short expiry, single use, and binding to the requesting browser — enumerate the endpoint and, where a test account exists, inspect the emitted token for length/structure (sequential/timestamp-derived = predictable) and whether it is consumed on first use; also whether the link's `redirect`/`next` parameter is an open redirect.

### SMS OTP endpoints

**Pattern**: `/auth/otp/sms`, `/verify/sms`, `/auth/phone/send`, `/auth/phone/verify`.

```bash
curl -s -X POST https://<target>/auth/otp/sms -d 'phone=<n>' -i | grep -iE 'http_code|retry-after|x-ratelimit|attempts'
```

**Gotcha**: SMS OTP is the most-abused passwordless surface — check code entropy (4-digit = 10k space, brute-forceable without lockout), send-side rate limiting (SMS-pumping/toll fraud), and verify-side attempt limits; a missing verify-side lockout on a short code is account takeover (route to `weak_password_detection`/`business_logic`).

### Email OTP endpoints

**Pattern**: `/verify/email-otp`, `/auth/otp/email/verify`, `/confirm-code`.

```bash
curl -s -X POST https://<target>/verify/email-otp -d 'email=<e>&code=000000' -i | grep -iE 'http_code|attempts|retry-after'
```

**Gotcha**: same analysis as SMS — short numeric codes plus weak verify-side rate limiting are brute-forceable; also test whether a code issued for one email verifies against another (code-reuse/confusion) and whether requesting a new code invalidates the old one.

## Session and Token Management

Once authenticated, the session mechanics — cookie names, attributes, storage, anti-CSRF — fingerprint the stack and define the post-auth attack surface.

### Session cookie enumeration

Cookie names fingerprint the framework: `sessionid` (Django), `PHPSESSID` (PHP), `JSESSIONID` (Java/servlet), `connect.sid` (Express `express-session` default), `AUTH_SESSION_ID`/`KEYCLOAK_IDENTITY`/`KEYCLOAK_SESSION`/`KC_RESTART` (Keycloak), `_<app>_session` (Rails), `laravel_session` (Laravel), `ASP.NET_SessionId`/`.AspNetCore.Session` (ASP.NET), `next-auth.session-token` / `__Secure-next-auth.session-token` (NextAuth/Auth.js).

```bash
curl -s -i https://<target>/ | grep -i '^set-cookie:' | sed 's/set-cookie://I'
```

**Gotcha**: the cookie name tells you the framework, which tells you the default session semantics and known CVE classes to check (`insecure_deserialization` for signed-but-not-encrypted Rails/Express/Flask cookies, etc.); a decodable/​unsigned session cookie is a direct finding.

### Cookie attributes

Each Set-Cookie's attributes carry security posture: `SameSite=Lax|Strict|None`, `Secure`, `HttpOnly`, `Path`, `Domain`, `Priority`, `Partitioned` (CHIPS, 2024).

```bash
curl -s -i https://<target>/ | grep -i '^set-cookie:' | grep -ioE 'samesite=[a-z]+|secure|httponly|domain=[^;]+|partitioned'
```

**Gotcha**: `SameSite=None` without a strong CSRF defense widens CSRF (load `csrf`); a session cookie missing `HttpOnly` is stealable via XSS; a broad `Domain=.tld` shares the cookie across every subdomain (one XSS anywhere = session theft everywhere); `Partitioned`/CHIPS changes cross-site cookie behavior and is worth noting for embedded/third-party contexts.

### Token storage location

Tokens live in cookies, `localStorage`, `sessionStorage`, IndexedDB, or memory-only; the choice sets the XSS blast radius.

```bash
grep -rhoE "(localStorage|sessionStorage)\.(setItem|getItem)\(['\"][^'\"]*(token|jwt|auth|session)[^'\"]*|__auth|access_token" bundles/ | sort -u
```

**Gotcha**: a JWT/refresh token in `localStorage` is readable by any XSS and never expires with the tab — a far worse XSS outcome than an `HttpOnly` cookie; cross-reference `application_enumeration_client_deep` (storage enumeration) and record where the access/refresh tokens actually live.

### CSRF token discovery

Anti-CSRF tokens ride headers (`X-CSRF-Token`, `X-XSRF-TOKEN`, `X-Requested-With`) or cookies (`XSRF-TOKEN`, `csrftoken`, `_csrf`).

```bash
curl -s -i https://<target>/ | grep -iE 'set-cookie:.*(xsrf|csrf)'
grep -rhoE "X-(CSRF|XSRF)-Token|xsrfHeaderName|withCredentials" bundles/ | sort -u
```

**Gotcha**: a `XSRF-TOKEN` cookie read by JS into an `X-XSRF-TOKEN` header is the double-submit pattern (Angular/Axios default) — bypassable if any subdomain XSS can set the cookie, or if the server accepts the request without the header for some methods; load `csrf` for exploitation. State-changing endpoints with *no* CSRF token and `SameSite=None`/`Lax`-exempt methods are the priority.

### Refresh token rotation patterns

Observe whether a refresh issues a new refresh token (rotation) and whether the old one is invalidated, and whether expiry is sliding or absolute.

```bash
curl -s -X POST https://<target>/oauth2/token -d 'grant_type=refresh_token&refresh_token=<rt>&client_id=<id>' | jq '{new_refresh:(.refresh_token!=null),expires_in}'
```

**Gotcha**: non-rotating bearer refresh tokens (the old one keeps working after a refresh) mean a stolen refresh token is a durable foothold; OAuth 2.1 requires rotation or sender-constraining — test by refreshing twice with the same original token and seeing if it still works (a reuse that succeeds is the finding; a reuse that revokes the whole chain is correct behavior).

### Token binding and sender-constraining

Signals of bound tokens: `Sec-Token-Binding` header (Token Binding, RFC 8471 — rare), mTLS-bound tokens (RFC 8705, `cnf.x5t#S256` claim), and DPoP (below).

**Gotcha**: sender-constrained tokens can't be replayed off the original client — their *presence* signals a sophisticated auth stack (and reduces the value of a stolen token); their *absence* on high-value APIs means a leaked bearer token is fully replayable. Record which, if any, binding is in use.

### DPoP (RFC 9449)

DPoP proves possession of a key per request via a `DPoP` header (a signed JWT) and a `DPoP-bound` access token (`token_type: DPoP`, `cnf.jkt` claim).

```bash
curl -s https://<target>/.well-known/openid-configuration | jq '.dpop_signing_alg_values_supported'
grep -rhoE "DPoP|dpop_jkt|createDPoPProof" bundles/ | sort -u
```

**Gotcha**: DPoP support (advertised in discovery or seen as a `DPoP` request header) means access tokens are key-bound — replay of a captured token fails without the private key; note it and hand JWT/DPoP proof analysis to `authentication_jwt`.

## Multi-Tenant Enumeration

Multi-tenant apps serve many customers from one codebase; the tenant boundary is the primary authorization surface, and it is enumerable from where the tenant identifier lives.

### Tenant identifier in URL

**Pattern**: `<tenant>.app.com` (subdomain), `app.com/tenant/<id>`, `app.com/t/<name>`, `app.com/org/<slug>`, or a `?tenant=` query.

```bash
grep -rhoE "https?://[a-z0-9-]+\.app\.tld|/(tenant|t|org|workspace|account)s?/[a-zA-Z0-9_-]+" bundles/ | sort -u
```

**Gotcha**: the tenant locator tells you how the app scopes data — a tenant in the *path or query* (vs a validated subdomain) is trivially swappable; enumerate valid tenant slugs (from bundles, CT logs via `asset_discovery_historical_deep`, or an `/org/<slug>` existence oracle) as the cross-tenant test seed.

### Tenant identifier in JWT claims

**Pattern**: `tenant_id`, `org_id`, `workspace_id`, `account_id`, `tid` (Microsoft Entra), `hd` (Google Workspace hosted domain), custom `https://<app>/org` namespaced claims.

```bash
# decode the JWT payload (no verification) and look for tenant claims
cut -d. -f2 <<<"<jwt>" | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{tenant_id,org_id,workspace_id,account_id,tid,hd,sub,roles,groups}'
```

**Gotcha**: if the tenant is carried *only* in a JWT claim and the server trusts it without re-checking the token's binding to that tenant, changing tenants becomes a token-crafting problem the moment any signing weakness exists; record every tenant/org claim as the authorization key to attack.

### Cross-tenant enumeration by request manipulation

Vary the tenant identifier across its three possible locations — URL, JWT claim, and header (`X-Tenant-Id`, `X-Org-Id`) — independently, and diff responses.

```bash
for t in <own-tenant> <other-tenant>; do
  echo "== $t =="; curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://<target>/api/resource" -H "Authorization: Bearer <own-token>" -H "X-Tenant-Id: $t"; done
```

**Gotcha**: the highest-value test is *disagreement* between locations — a token for tenant A with `X-Tenant-Id: B` (or URL `/t/B`) that returns B's data means the authorization trusts the header/URL over the token; a `200` with another tenant's data is a cross-tenant IDOR (route to `idor`), a `403` is correct isolation. Record the differential.

### Tenant metadata discovery

Tenant/workspace config endpoints (`/api/tenant/config`, `/api/workspace/<id>/settings`, `/api/org/<slug>`) expose per-tenant configuration.

```bash
for p in /api/tenant/config "/api/workspace/<id>/settings" "/api/org/<slug>" /api/account/current; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p -H 'Authorization: Bearer <token>')"; done
```

**Gotcha**: tenant config often leaks SSO settings, allowed domains, feature entitlements, admin emails, and IdP metadata URLs — a rich pre-attack map; test whether a tenant's config is readable by a user from another tenant (metadata-level cross-tenant leak even when data rows are isolated).

### Row-level security boundaries

Many apps enforce isolation at the data row (Postgres RLS, tenant-scoped queries) but leak at the aggregate/metadata layer.

```bash
# same query across tenants — do counts/aggregates leak beyond the row filter?
curl -s "https://<target>/api/search?q=*" -H "Authorization: Bearer <token>" | jq '{total,count:(.results|length)}'
```

**Gotcha**: RLS commonly filters returned rows but not `COUNT(*)`, autocomplete, "recently viewed", global search, or error messages ("record belongs to another org") — probe aggregates, typeahead, and cross-tenant object IDs for metadata leakage even when direct reads are blocked.

### Custom branding as tenant fingerprint

Per-tenant logos, colors, subdomains, and email domains identify tenants and confirm valid slugs.

```bash
curl -s "https://<tenant>.app.tld/api/branding" | jq '{name,logo,primaryColor,domains}' 2>/dev/null
```

**Gotcha**: a branding/theme endpoint that answers for arbitrary tenant slugs is a tenant-existence and tenant-inventory oracle (which customers exist) — useful for the cross-tenant seed list and, on its own, a customer-disclosure issue for a private platform.

### Tenant-specific feature flags

Feature flags are frequently scoped per tenant (see `application_enumeration_client_deep` for flag-provider detection); the same app exposes different routes per tenant.

**Gotcha**: a feature/route enabled for tenant A but not B (beta admin tools, data-export, API access) may still be *reachable* for B if the gate is client-side only — enumerate flags per tenant and test whether a flag-gated endpoint enforces the entitlement server-side; forcing a paid/beta feature is a `business_logic` finding.

### Tenant admin surface

Per-tenant admin routes (`/admin`, `/admin/tenant/<id>`, `/<tenant>/admin`, `/api/admin/*`) and cross-tenant "super admin" consoles.

```bash
for p in /admin "/admin/tenant/<id>" /api/admin/users /superadmin /internal/admin; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p -H 'Authorization: Bearer <token>')"; done
```

**Gotcha**: cross-tenant/super-admin surfaces are often "protected" only by IP allow-listing or a hidden route (security by obscurity) — test them from a normal tenant session and via `broken_function_level_authorization`; a tenant-admin endpoint that accepts another tenant's `<id>` is critical cross-tenant escalation.

### Impersonation and delegation features

Legitimate "act as" features: `/api/impersonate`, `/api/act-as`, `/admin/users/<id>/login-as`, `X-Impersonate-User` headers, OAuth Token Exchange (RFC 8693) `act`/`may_act` claims.

```bash
grep -rhoE "impersonat|act-as|act_as|login-as|X-Impersonate|switch_user|may_act" bundles/ | sort -u
```

**Gotcha**: impersonation endpoints are designed to cross the user boundary — the whole finding is whether the *caller* is authorized to impersonate the *target*; test impersonating across roles and across tenants, and check whether the resulting session is distinguishable from a real one (audit-log/attribution gaps compound the impact).

### Multi-region tenancy

The same app deployed per region (`us.app.tld`, `eu.app.tld`, `app.tld/eu`) can differ in features, patch level, and data.

```bash
for r in us eu ap; do echo "== $r =="; curl -s -o /dev/null -w '%{http_code}\n' "https://$r.app.tld/api/version"; done
```

**Gotcha**: regional deployments drift — one region may run an older build (unpatched CVE), expose a different feature set, or enforce isolation differently; enumerate each region as a separate target and diff versions (build fingerprints per `application_enumeration_client_deep`).

## Multi-Service Architecture — Source Parsing Depth

When source is available, infrastructure-as-code files describe the *entire* internal service graph — services the external surface never exposes. Parse them exhaustively; each internal service is a first-class, chain-relevant target.

### Docker Compose parsing beyond services

Beyond `services:`, the `networks:`, `secrets:`, `configs:`, `volumes:`, `depends_on:`, and `healthcheck:` sections carry topology and secrets.

```bash
yq '.services | to_entries[] | {svc:.key, image:.value.image, ports:.value.ports, env:(.value.environment|keys?), depends:.value.depends_on, health:.value.healthcheck.test}' docker-compose.yml
yq '.networks, .secrets, .configs, .volumes' docker-compose.yml
```

**Gotcha**: `secrets:`/`configs:` reveal how credentials are injected (file paths, external secret names to chase), `networks:` reveals segmentation (which services can talk to which), `depends_on:` reveals startup order (a timing surface for `race_conditions`), and `healthcheck:` frequently hardcodes an internal health/debug endpoint URL — catalog every internal service and its ports.

### Docker Compose override files

`docker-compose.override.yml` (auto-merged), `docker-compose.dev.yml`, `docker-compose.prod.yml`, `docker-compose.ci.yml`.

```bash
ls -1 docker-compose*.y*ml compose*.y*ml 2>/dev/null
yq '.services | to_entries[] | {svc:.key, ports:.value.ports, env:(.value.environment|keys?)}' docker-compose.override.yml 2>/dev/null
```

**Gotcha**: override files are where dev-only exposure lives — a `override`/`dev` file that publishes a debugger port (`9229`, `5005`), a database port, or sets `DEBUG=true`/`NODE_ENV=development` tells you what the team considers non-prod (and what might accidentally ship); diff override vs base for exposed ports and relaxed config.

### Docker Compose profiles

`profiles: [debug, tools, admin]` gate services so they only start under a named profile.

```bash
yq '.services | to_entries[] | select(.value.profiles) | {svc:.key, profiles:.value.profiles, image:.value.image}' docker-compose.yml
```

**Gotcha**: profile-gated services (debug consoles, admin UIs, seed/migration tools, mailhog/adminer) are the interesting ones precisely because they are meant to be optional — enumerate them and check whether any is reachable in the running deployment (a `tools`/`debug` profile left enabled in staging/prod is a direct finding).

### Kubernetes manifests — deployment analysis

`Deployment`/`StatefulSet`/`DaemonSet` specs carry images, commands, env, volume mounts, and security context.

```bash
yq eval-all '. | select(.kind=="Deployment" or .kind=="StatefulSet") | {name:.metadata.name, images:[.spec.template.spec.containers[].image], env:[.spec.template.spec.containers[].env[]?.name], caps:.spec.template.spec.containers[].securityContext, hostNet:.spec.template.spec.hostNetwork}' kubernetes/**/*.yaml
```

**Gotcha**: image tags pin exact versions (map to CVEs), `env`/`envFrom` names the config and secret refs, and a permissive `securityContext` (`privileged:true`, `runAsUser:0`, added capabilities, `hostNetwork/hostPID`) is a container-escape/privilege lead worth flagging even at the recon stage.

### Kubernetes manifests — service analysis

`Service` types define reachability: `ClusterIP` (internal-only), `NodePort`, `LoadBalancer` (external), `ExternalName` (CNAME to an external host).

```bash
yq eval-all '. | select(.kind=="Service") | {name:.metadata.name, type:.spec.type, ports:[.spec.ports[].port], selector:.spec.selector, externalName:.spec.externalName}' kubernetes/**/*.yaml
```

**Gotcha**: every `ClusterIP` service is an internal-only target you reach only via SSRF or a pivot (catalog them as chain destinations, per the deep-mode mandate); an `ExternalName` service points at an external dependency (its host is an SSRF/takeover lead), and a `LoadBalancer`/`NodePort` that shouldn't be public is a direct exposure.

### Kubernetes ingress analysis

`Ingress`/`HTTPRoute` (Gateway API) resources map external hostnames/paths to services; `IngressClass` and controller annotations name the enforcement layer.

```bash
yq eval-all '. | select(.kind=="Ingress" or .kind=="HTTPRoute") | {name:.metadata.name, class:(.spec.ingressClassName // .metadata.annotations["kubernetes.io/ingress.class"]), rules:.spec.rules, annotations:(.metadata.annotations|keys)}' kubernetes/**/*.yaml
```

**Gotcha**: ingress rules are the authoritative external route→service map (including hosts/paths not linked from the app); controller-specific annotations (`nginx.ingress.kubernetes.io/*`, `alb.ingress.*`) reveal rewrites, auth-snippets, and WAF config to account for — an `auth-url`/`auth-snippet` annotation names an external auth check you may be able to bypass by hitting the service directly.

### Kubernetes NetworkPolicy analysis

`NetworkPolicy` (and `CiliumNetworkPolicy`) declares intended pod-to-pod segmentation.

```bash
yq eval-all '. | select(.kind=="NetworkPolicy") | {name:.metadata.name, podSelector:.spec.podSelector, ingress:.spec.ingress, egress:.spec.egress}' kubernetes/**/*.yaml
grep -rL 'kind: NetworkPolicy' kubernetes/ >/dev/null 2>&1 && echo "note: check whether ANY NetworkPolicy exists"
```

**Gotcha**: the *absence* of NetworkPolicies is itself a finding — a cluster with none has flat pod networking, so any single-pod foothold reaches every service (maximal lateral movement); where they exist, egress rules reveal which external hosts pods may call (SSRF allow-list intel).

### Kubernetes RBAC analysis

`Role`/`ClusterRole` + `RoleBinding`/`ClusterRoleBinding` + `ServiceAccount` define in-cluster permissions.

```bash
yq eval-all '. | select(.kind=="ClusterRole" or .kind=="Role") | {name:.metadata.name, rules:.spec.rules // .rules}' kubernetes/**/*.yaml
yq eval-all '. | select(.kind=="ClusterRoleBinding" or .kind=="RoleBinding") | {name:.metadata.name, roleRef:.roleRef.name, subjects:[.subjects[].name]}' kubernetes/**/*.yaml
```

**Gotcha**: a ServiceAccount bound to a Role with `["*"]` verbs on `secrets`, or any `create`/`escalate`/`bind`/`impersonate` verb, is a privilege-escalation primitive from any pod running as that SA — a critical post-foothold chain target; note which SA each workload uses and whether `automountServiceAccountToken` is left on.

### Helm chart analysis

`values.yaml` + environment overlays (`values-prod.yaml`, `values-staging.yaml`) hold the real config; `templates/` renders the manifests.

```bash
helm template . -f values.yaml 2>/dev/null | yq eval-all '. | select(.kind=="Service" or .kind=="Ingress") | {kind,name:.metadata.name}'
yq '.image, .env, .ingress, .secrets, .externalServices, .database' values.yaml 2>/dev/null
```

**Gotcha**: render the chart (`helm template`) to see the *actual* manifests rather than guessing from templates; per-environment values files leak environment-specific hostnames, credentials refs, and toggles (a `values-staging.yaml` with `debug: true` or a hardcoded default password is a common find).

### Helm chart dependencies

`Chart.yaml` `dependencies:` (and `charts/`) pull in sub-charts — databases, caches, queues, and their default credentials.

```bash
yq '.dependencies[] | {name,version,repository,condition}' Chart.yaml 2>/dev/null
```

**Gotcha**: bundled dependency sub-charts (Bitnami postgres/redis/kafka/mongodb) ship with well-known default credentials and service names — if a dependency's `auth.enabled:false` or a default password is left in values, the backing datastore is directly attackable once you reach the cluster network; enumerate the data-tier from the dependency list.

### Kustomize overlays

`kustomization.yaml` + `overlays/<env>/kustomization.yaml` apply environment patches.

```bash
find . -name kustomization.yaml | sort
kubectl kustomize overlays/prod 2>/dev/null | yq eval-all '. | select(.kind=="Service" or .kind=="Ingress" or .kind=="Deployment") | {kind,name:.metadata.name}'
```

**Gotcha**: the overlay `patches`/`patchesStrategicMerge` show exactly what differs per environment (replica counts, images, injected env, exposed ports) — build (`kubectl kustomize`) each overlay to get the true per-env surface, and diff prod vs non-prod for accidental exposure.

### ArgoCD, Flux, and ApplicationSets

GitOps controllers: ArgoCD `Application`/`ApplicationSet` (generator-based), Flux `Kustomization`/`HelmRelease`.

```bash
yq eval-all '. | select(.kind=="Application" or .kind=="ApplicationSet") | {name:.metadata.name, repoURL:.spec.source.repoURL, path:.spec.source.path, dest:.spec.destination}' **/*.yaml 2>/dev/null
```

**Gotcha**: `Application`/`ApplicationSet` specs point at the source git repos and target namespaces/clusters — a map of every deployed app and where its manifests live (chase the `repoURL` for more source, per `asset_discovery_historical_deep`); a generator (`list`/`cluster`/`git`) reveals the full fleet of environments/tenants the platform deploys.

### Service mesh and serverless IaC

Mesh: Istio `VirtualService`/`DestinationRule`/`AuthorizationPolicy`, Linkerd `ServiceProfile`, Cilium `CiliumNetworkPolicy`. Serverless/IaC: `serverless.yml`, AWS SAM `template.yaml`, Terraform `*.tf`, Pulumi.

```bash
yq eval-all '. | select(.kind=="VirtualService" or .kind=="AuthorizationPolicy") | {kind,name:.metadata.name, hosts:.spec.hosts, rules:(.spec.http // .spec.rules)}' **/*.yaml 2>/dev/null
yq '.functions | to_entries[] | {fn:.key, handler:.value.handler, events:.value.events, url:.value.url}' serverless.yml 2>/dev/null
grep -rhoE 'aws_lambda_function|aws_api_gateway|aws_iam_policy|resource "aws_[a-z_]+"' *.tf 2>/dev/null | sort -u
```

**Gotcha**: mesh `AuthorizationPolicy`/`VirtualService` encode the intended service-to-service authz and routing (a mesh that allows-all or routes by an untrusted header is a lead); `serverless.yml`/SAM `template.yaml` enumerate every function, its trigger (HTTP/S3/SQS/cron), its `url` (Lambda Function URL — a public entry point), and its IAM policy (an over-broad function role is a privilege chain). Cross to `cloud/aws`/`gcp`/`azure` for the cloud-side follow-up.

## AI/ML Endpoint Discovery

2024-2026 apps expose model-serving, retrieval, and agent endpoints that traditional recon ignores. Enumerate them as first-class API surface; hand exploitation (prompt injection, RAG poisoning, tool abuse) to `llm_applications`/`llm_prompt_injection`.

### LLM API endpoint patterns

**Pattern**: OpenAI-compatible `/v1/chat/completions` and the newer stateful `/v1/responses` (OpenAI, March 2025) dominate, even when a non-OpenAI model backs them; also `/api/chat`, `/api/completions`, `/api/generate` (Ollama/text-gen), `/api/agent`, `/api/copilot`, `/api/ask`.

```bash
for p in /v1/chat/completions /v1/responses /api/chat /api/completions /api/generate /api/ask; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' -X POST https://<target>$p -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"ping"}],"model":"x","stream":false}')"; done
```

**Gotcha**: an OpenAI-compatible shape (`messages`/`model`/`stream`) is the near-universal tell even for self-hosted models — a `400` complaining about `model` confirms the endpoint; note whether it requires an API key or is reachable with the app's session (an unauthenticated or session-only LLM endpoint is a cost-abuse and prompt-injection surface). The legacy OpenAI Assistants API is being retired (Aug 2026) in favor of `/v1/responses`.

### Streaming response endpoints

LLM chat endpoints stream via `text/event-stream` (SSE) or `application/x-ndjson`.

```bash
curl -s -N -X POST https://<target>/api/chat -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"hi"}],"stream":true}' -i | grep -iE '^content-type:|^data:' | head
```

**Gotcha**: streaming endpoints often bypass response-size/WAF inspection that buffers full bodies, and the SSE frame format (`data:` chunks, `[DONE]` sentinel) confirms an LLM backend; a streaming endpoint frequently leaks partial system-prompt or tool-call frames worth capturing (analysis → `llm_prompt_injection`).

### Embedding endpoints

**Pattern**: `/v1/embeddings`, `/api/embed`, `/embeddings` — vectorize text, used by RAG ingestion and search.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<target>/v1/embeddings -H 'Content-Type: application/json' -d '{"input":"test","model":"x"}'
```

**Gotcha**: embedding endpoints are often less-hardened and less-rate-limited than chat (treated as "internal plumbing") — a reachable embeddings endpoint is a cost-abuse vector and, combined with the vector DB below, part of the RAG pipeline to map; note the model name it accepts.

### Vector database endpoints

**Pattern** (verified 2026-09): Pinecone data plane `<index>-<hash>.svc.<region-id>.pinecone.io` (host comes from describe-index, control plane at `api.pinecone.io`); Weaviate `/v1/objects`, `/v1/schema`, `/v1/graphql`; Qdrant `/collections`, `/collections/<name>`, `/collections/<name>/points/search`; ChromaDB `/api/v2/collections` (v1 removed); Milvus `/v2/vectordb/collections/list`, `/v2/vectordb/entities/search` (port 19530).

```bash
for p in /v1/schema /v1/objects /collections /api/v2/collections /v2/vectordb/collections/list; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
grep -rhoE "\.svc\.[a-z0-9-]+\.pinecone\.io|/v1/(objects|graphql)|/collections/[a-z0-9_-]+/points|/api/v2/collections|/v2/vectordb/" bundles/ | sort -u
```

**Gotcha**: an exposed vector DB is the newest high-value surface — Weaviate `/v1/schema` and Qdrant `/collections` enumerate the collections and their vector config without auth on many self-hosted deployments, and the stored vectors/metadata frequently *are* the RAG source documents (embedded customer data). Record collection names and whether reads/writes require auth; a writable collection is a RAG-poisoning primitive (route to `llm_applications`). Never dump the actual stored data — confirm access and scope only.

### RAG source enumeration

RAG systems retrieve from a document/knowledge store: `/api/knowledge`, `/api/documents`, `/api/kb`, `/api/sources`, `/api/collections`, `/api/files`, `/api/ingest`.

```bash
for p in /api/knowledge /api/documents /api/kb /api/sources /api/files /api/ingest; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p -H 'Authorization: Bearer <token>')"; done
```

**Gotcha**: a RAG source/document catalog endpoint that lists titles, IDs, or ingest sources leaks the knowledge base's contents and origin (internal wikis, S3 buckets, Confluence spaces to chase); an open `/api/ingest`/upload is a RAG-poisoning entry point (inject content the model will later retrieve and treat as trusted). Enumerate the catalog; leave exploitation to the LLM skills.

### Agent orchestration endpoints

**Pattern**: LangGraph Platform (renamed "LangSmith Deployment", 2025) exposes RESTful `/assistants`, `/threads`, `/threads/<id>/runs`, `/runs`, plus state/store endpoints; LangServe exposes `/invoke`, `/batch`, `/stream`, `/stream_log`, `/playground/`, `/input_schema`, `/config_schema` per mounted chain; CrewAI/AutoGen/custom stacks use illustrative shapes like `/api/agents/<name>/run`, `/api/tasks/execute`, `/api/crew/kickoff`.

```bash
for p in /assistants /threads /runs /invoke /stream /batch /playground/ /docs /openapi.json; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
curl -s https://<target>/openapi.json | jq '.paths | keys[]' 2>/dev/null | grep -iE 'assistant|thread|run|invoke|agent|tool'
```

**Gotcha**: LangServe mounts a `/playground/` and an OpenAPI schema per chain — a reachable playground is an interactive prompt-injection surface, and the schema enumerates every chain's input shape; LangGraph's `/threads`/`/runs` are stateful and often IDOR-prone (another user's thread by ID). Confirm the framework from `/openapi.json` and treat each run endpoint as an authorization test.

### Tool and function-calling endpoints

LLM tool-use exposes callable tools: `/api/tools`, `/api/functions`, `/api/tools/list`, or a function-calling schema embedded in the chat request/OpenAPI.

```bash
curl -s https://<target>/api/tools -H 'Authorization: Bearer <token>' | jq '.[]? | {name,description,parameters:(.parameters.properties|keys?)}' 2>/dev/null
grep -rhoE '"(name|function)":\s*"[a-z_]+".*"parameters"|tool_choice|function_call' bundles/ | sort -u
```

**Gotcha**: the tool catalog is the model's *action surface* — tools named `execute_sql`, `send_email`, `fetch_url`, `read_file`, `run_code` are exactly what prompt injection aims to trigger; enumerate the tool list and each tool's parameters (this is the target map for `llm_prompt_injection`), and note any tool that reaches internal systems or the filesystem.

### MCP (Model Context Protocol) endpoints

**Pattern** (verified): MCP servers speak JSON-RPC 2.0 over the **Streamable HTTP** transport at a single endpoint (commonly `/mcp`); `tools/list`, `resources/list`, `prompts/list` are JSON-RPC **method names** POSTed to that endpoint, not REST paths. A session is opened with an `initialize` call and carried in the `Mcp-Session-Id` header. (The older 2024 transport used HTTP+SSE with a `/sse` stream plus a POST message endpoint; now superseded.)

```bash
# initialize, then list tools — JSON-RPC to the single /mcp endpoint
curl -s -X POST https://<target>/mcp -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"recon","version":"0"}}}' -i | grep -i 'mcp-session-id'
curl -s -X POST https://<target>/mcp -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'Mcp-Session-Id: <id>' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | jq '.result.tools[]? | {name,description}'
```

**Gotcha**: an MCP server exposes its whole capability set (`tools/list`/`resources/list`/`prompts/list`) — a full inventory of what the AI application can *do* and *read*; a reachable MCP endpoint that lists high-impact tools (filesystem, DB, HTTP fetch) is a major finding, and MCP auth is defined on OAuth 2.1 (the OAuth section above applies). Enumerate capabilities; never invoke a state-changing tool.

### Prompt library and template endpoints

**Pattern**: `/api/prompts`, `/api/templates`, `/api/system-prompts`, prompt files in the bundle (`.prompt`, `prompts/*.txt`).

```bash
curl -s https://<target>/api/prompts -H 'Authorization: Bearer <token>' | jq '.[]? | {id,name,text:(.template//.content|.[0:80])}' 2>/dev/null
grep -rhoE "system['\"]?\s*:\s*['\"`][^'\"\`]{40,}|You are (a|an|the) [A-Za-z]" bundles/ | sort -u | head
```

**Gotcha**: exposed prompts (especially the *system* prompt) reveal the model's guardrails, persona, and tool-use instructions — the blueprint for crafting injections and jailbreaks; a system prompt visible in the bundle or via an API is both an information-disclosure finding and the key input for `llm_prompt_injection`.

### Fine-tuning and training endpoints

**Pattern**: `/api/fine-tune`, `/v1/fine_tuning/jobs`, `/api/training-jobs`, `/api/datasets`.

```bash
for p in /v1/fine_tuning/jobs /api/fine-tune /api/training-jobs /api/datasets; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p -H 'Authorization: Bearer <token>')"; done
```

**Gotcha**: fine-tuning/dataset endpoints reference training data (often customer or proprietary data) and are compute-expensive — a reachable one is both a data-exposure and a cost-abuse surface; a dataset listing can leak the names/sources of training corpora.

### Model registry endpoints

**Pattern**: MLflow (`/api/2.0/mlflow/registered-models/list`, `/ajax-api/2.0/...`, tracking UI at `/`), Weights & Biases (`api.wandb.ai`, self-hosted `/graphql`), SageMaker Model Registry, BentoML/`/yatai`, KServe `/v1/models/<name>` and `/v2/models`.

```bash
for p in /api/2.0/mlflow/registered-models/list /v2/models /v1/models "/v1/models/<name>"; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<target>$p)"; done
```

**Gotcha**: an exposed MLflow/KServe/registry endpoint enumerates model names, versions, and artifact URIs (S3/GCS paths to chase), and self-hosted MLflow has a history of unauthenticated access and LFI/SSRF classes — treat a reachable tracking/registry UI as both an inventory leak and a direct target (route CVEs via version fingerprint).

### Inference endpoint providers

**Pattern**: hosted-inference providers referenced from the bundle or backend — Replicate (`api.replicate.com/v1/predictions`), Together AI (`api.together.xyz/v1/...`), Fireworks (`api.fireworks.ai/inference/v1`), Groq (`api.groq.com/openai/v1`), Anyscale, Lepton, Hugging Face Inference Endpoints (`<id>.<region>.<vendor>.endpoints.huggingface.cloud`, see `asset_discovery_cloud_deep`).

```bash
grep -rhoE "api\.(replicate\.com|together\.xyz|fireworks\.ai|groq\.com)|endpoints\.huggingface\.cloud|inference" bundles/ | sort -u
```

**Gotcha**: provider references in the client reveal the model backend and, too often, a leaked provider API key in the bundle (a cost-abuse and data-egress credential — record location/scope, never use it); Groq/Together/Fireworks all speak the OpenAI-compatible shape, so a proxied endpoint on the target's own origin still tests like `/v1/chat/completions`.

## Advanced Detection Techniques for Auth Surface

When endpoints don't volunteer information, behavioral differentials do. Use these across the auth surface enumerated above.

### Timing attacks on auth endpoints

Response-time differences leak whether a username exists or a code path ran (bcrypt on a real user vs early-return on an unknown one).

```bash
for u in real@x.tld nobody@x.tld; do
  echo "$u"; for i in 1 2 3; do curl -s -o /dev/null -w '%{time_total}\n' -X POST https://<target>/login -d "email=$u&password=x"; done; done
```

**Gotcha**: a consistent timing gap between valid and invalid usernames (the valid one runs the password hash, the invalid one returns early) is a username-enumeration oracle even when the response body/status is identical; average several samples to beat jitter.

### Enumeration via response differentials

Signup, login, and password-reset frequently distinguish existing from non-existing accounts in status, body, redirect, or headers.

```bash
for ep in "/signup" "/auth/forgot-password"; do for e in real@x.tld nobody@x.tld; do
  echo "$ep $e -> $(curl -s -o /dev/null -w '%{http_code} %{size_download}' -X POST https://<target>$ep -d "email=$e")"; done; done
```

**Gotcha**: "email already registered" on signup, or "if an account exists we sent a link" that *differs* in size/timing between real and fake, is account enumeration; also test the reset flow's response for valid vs invalid emails — a differential there feeds targeted attacks.

### Race conditions in auth flows

Auth state transitions are concurrency-sensitive: concurrent signup with the same email, concurrent coupon/credit redemption, concurrent password-reset consumption, parallel MFA attempts.

```bash
# fire N concurrent identical requests (single-packet-style) and diff outcomes
seq 20 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<target>/auth/redeem -H 'Authorization: Bearer <token>' -d 'code=ONCE' | sort | uniq -c
```

**Gotcha**: TOCTOU in auth — two "verify email" or "redeem once" requests both succeeding, or concurrent signups both creating the same account — is a real class here; load `race_conditions` for the single-packet/last-byte-sync technique. Enumerate which state transitions are "once only" as the candidate list.

### State parameter analysis in OAuth

The `state` parameter must be unguessable and validated on return (CSRF defense for the redirect).

```bash
# capture several authorization requests and inspect the state values
for i in 1 2 3; do curl -s -i "https://<target>/oauth2/authorize?client_id=<id>&response_type=code&redirect_uri=<uri>&scope=openid" | grep -ioE 'state=[^&" ]+'; done
```

**Gotcha**: a missing, static, empty, or predictable `state` (or one the callback doesn't actually validate) is OAuth login-CSRF / authorization-code-injection — test by completing a flow with a tampered/omitted `state` and seeing if the callback accepts it; pair with the redirect-URI findings above.

### Nonce reuse in OIDC

The OIDC `nonce` binds an ID token to a session and must be single-use.

```bash
grep -rhoE "nonce" bundles/ | sort -u   # confirm the client sends a nonce at all
```

**Gotcha**: if the client omits the `nonce`, or the server accepts an ID token whose `nonce` was already used (replay) or doesn't match the request, ID-token replay/injection is possible — enumerate whether a nonce is sent and, with a test account, whether reusing an old ID token across sessions is accepted (hand token-crafting to `authentication_jwt`).

## Tooling and Command Reference

- **OAuth/OIDC**: `curl`+`jq` against the discovery docs (above); a well-known/OIDC scanner; `oauth2c` (interactive OAuth client for exercising grants); Burp/Caido for flow capture and `state`/redirect tampering.
- **SAML**: `SAML-tracer` (browser extension, decode live messages), `xmlsec1` (signature verification), `xmllint` (metadata XPath), Burp `SAML Raider` (decode/edit/re-sign during authorized tests), SAMLtest.id (reference IdP/SP).
- **WebAuthn/passwordless**: browser DevTools WebAuthn virtual authenticator tab, `webauthn.io` (reference RP for comparison), FIDO conformance option-shape naming.
- **JWT**: `jwt_tool` (algorithm/kid/claim attacks), `jwt.io`/`hashcat` (offline), `jwt-cracker` for weak HMAC secrets. Load `authentication_jwt`.
- **Multi-service source**: `yq` (YAML query, examples above), `kubectl kustomize`/`helm template` (render manifests), `kubeaudit`/`kube-score`/`checkov`/`kics` (IaC misconfig scan), `trivy config` (compose/k8s/terraform).
- **AI/ML**: `promptfoo` (prompt eval/regression), `garak` (LLM vulnerability scanner), Microsoft `PyRIT` (adversarial testing), the vendor SDKs (openai/langchain) for exercising discovered endpoints. Load `llm_applications`/`llm_prompt_injection`.

Install any tool not present at runtime. Never replay a discovered token/assertion/credential or invoke a state-changing AI tool — record presence, location, and scope only.

## What Deep Auth + Multi-Service + AI/ML Recon Completeness Looks Like

This surface is done only when:

- The OAuth/OIDC discovery document is queried and its grants, scopes, endpoints, response types, and PKCE/PAR/RAR/DCR support recorded
- SAML metadata is discovered (if applicable) with entity IDs, ACS/SLO URLs, NameID formats, and signing posture extracted
- WebAuthn/passwordless ceremony endpoints are identified with attestation/UV/resident-key policy and OTP/magic-link mechanics analyzed
- Session cookies, attributes, token storage, and CSRF/refresh/DPoP mechanics are catalogued
- Multi-tenant boundaries are enumerated (identifier location, cross-location differential, metadata/RLS leakage, admin/impersonation surface, regions)
- Docker Compose / Kubernetes / Helm / Kustomize / GitOps / service-mesh / serverless source is parsed and every internal service catalogued as a chain candidate
- AI/ML endpoints are enumerated (LLM chat/responses, embeddings, vector DBs, RAG sources, agent/tool/MCP surfaces, model registry, inference providers)
- Vector DB collections and tool/MCP capability catalogs are recorded (access + scope, never data dumps)

Only then scope hunters to the specific classes: OAuth authorization/redirect/state confusion (`oauth`, `open_redirect`), SAML signature-wrapping/XXE, JWT/DPoP manipulation (`authentication_jwt`), CSRF (`csrf`), cross-tenant IDOR and function-level authz (`idor`, `broken_function_level_authorization`), auth race conditions (`race_conditions`), internal-service pivots (SSRF chains), and AI prompt injection / RAG poisoning / tool abuse (`llm_applications`, `llm_prompt_injection`).

## Pro Tips

1. Query the OAuth/OIDC discovery document first — it hands you every endpoint, grant, and scope the server supports, including features (ROPC, Implicit, anonymous DCR, PAR) the team may have forgotten they enabled.
2. SAML metadata refresh mechanisms are forgotten attack surface — if the SP re-fetches IdP metadata from an attacker-influenceable URL, poisoning it swaps the trusted signing cert and breaks the whole trust.
3. Passwordless flows (magic links, SMS/email OTP, WebAuthn) frequently lack the rate-limiting and lockout hardening of the password flow they replaced — check code entropy and verify-side attempt limits first.
4. Multi-tenant apps commonly enforce isolation at the data row but leak at the metadata/aggregate layer — probe counts, typeahead, global search, and tenant-config endpoints, not just direct object reads.
5. The single highest-value cross-tenant test is *disagreement* between the tenant identifier's locations — a token for tenant A with a header/URL naming tenant B that returns B's data means authz trusts the wrong source.
6. Docker Compose override/profile files reveal what the team considers dev-only (debug ports, adminer, seed tools) — exactly the surface that ships to staging/prod by accident.
7. The absence of Kubernetes NetworkPolicies is itself a finding — flat pod networking means one foothold reaches every internal service; and a ServiceAccount with `secrets`/`*` verbs is a post-foothold escalation primitive.
8. AI/ML endpoints are almost always OpenAI-compatible (`messages`/`model`/`stream`) even when a different model backs them — a `400` about `model` confirms the endpoint; check whether it needs a key or rides the app session.
9. Vector databases and MCP servers are the newest RAG/agent attack surface — Weaviate `/v1/schema`, Qdrant `/collections`, and MCP `tools/list` enumerate the retrieval corpus and the agent's action set without touching the model; a writable collection or a filesystem/HTTP tool is a major finding.

## Summary

This deep sibling to `application_enumeration` maps the identity, topology, and AI layers: OAuth 2.0/2.1 + OIDC (discovery, grants, redirect/response modes, JWKS, introspection/revocation/userinfo/DCR/RAR/PAR), SAML (metadata, entities, ACS/SLO, NameID, signing posture, metadata-refresh trust), WebAuthn/passwordless (ceremony options, attestation/UV/resident keys, magic-link/OTP mechanics), session/token mechanics (cookies, storage, CSRF, refresh rotation, DPoP), multi-tenant boundaries (identifier location, differential testing, metadata/RLS leakage, admin/impersonation, regions), multi-service source parsing (compose/k8s/helm/kustomize/GitOps/mesh/serverless → internal service graph), and AI/ML endpoints (LLM chat/responses, embeddings, vector DBs, RAG sources, agent/tool/MCP surfaces, model registries, inference providers). It loads only in deep mode. Completeness means the discovery docs are queried, the service graph is parsed, and the model-serving layer is enumerated before auth/tenant/AI hunters are scoped. Companion deep siblings `application_enumeration_api_deep` (server-side API protocols) and `application_enumeration_client_deep` (client-side runtime) cover the adjacent surface. With this file, the base + three-deep-sibling pattern is complete for `application_enumeration`, mirroring `asset_discovery`.
