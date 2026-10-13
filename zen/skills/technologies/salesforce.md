---
name: salesforce
description: Salesforce security testing covering SOQL injection, Apex class/trigger abuse, guest-user and Experience Cloud over-exposure, FLS/CRUD/sharing-rule bypass, and misconfigured custom objects
---

# Salesforce

Salesforce is a multi-tenant SaaS platform where the attack surface is authorization boundaries and data-access controls, not infrastructure exploitation — the provider manages compute and storage. This skill owns SOQL injection (the Salesforce-specific expression of the injection class documented in `sql_injection`), Apex code abuse, guest-user and Experience Cloud/Community data exposure, and FLS/CRUD/sharing-rule bypass. It does not duplicate general OAuth/OIDC mechanics (see `authentication_jwt`), secret-in-code patterns (see `information_disclosure`), or identity-provider configuration (see `auth0`/`okta` for SSO surfaces that front Salesforce). Salesforce does not assign CVEs for platform-side fixes; vulnerability classes here are behavior-fingerprinted from researcher disclosures and vendor documentation.

## Attack Surface

**Authentication & identity**
- Username/password, SSO (SAML/OAuth), MFA (Salesforce Authenticator, TOTP, U2F)
- Connected Apps (OAuth client credentials, JWT bearer, refresh tokens)
- Session settings: timeout, IP restrictions, login IP ranges, trusted IP ranges

**Authorization model**
- Profiles, Permission Sets, Permission Set Groups
- Object-level: CRUD per profile/permission set
- Field-level: FLS (Field-Level Security) per profile/permission set
- Record-level: OWD (Organization-Wide Defaults), role hierarchy, sharing rules, manual shares, Apex managed sharing
- Guest User Profile: dedicated low-privilege profile for unauthenticated Experience Cloud access

**API & data endpoints**
- REST API: `/services/data/vXX.0/` — SOQL via `/query`, sObject CRUD via `/sobjects/`
- SOAP API: `login.salesforce.com/services/Soap/u/XX.0`
- Aura/Lightning: `/aura` endpoint — controller actions, including custom Apex
- Bulk API, Streaming API, Metadata API, Tooling API
- Experience Cloud (Communities): `/s/` paths, guest-accessible Aura controllers

**Data movement**
- Reports, dashboards, list views (respect FLS/CRUD at render time — but custom Apex may bypass)
- Data Loader, Dataflow, external objects (Salesforce Connect)
- Outbound messages, platform events, Change Data Capture

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# Domain patterns
# Production: <org>.my.salesforce.com
# Experience Cloud / Communities: <org>.my.site.com, <custom>.force.com, <org>.my.salesforce-sites.com
# Sandbox: <org>--<sandbox>.sandbox.my.salesforce.com

# SOAP API endpoint — confirms Salesforce, leaks API version
curl -s https://<target>/services/Soap/u/62.0 | head -20

# Aura endpoint probe (guest context)
curl -s 'https://<target>/s/sfsites/aura' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'message={}&aura.context={}'

# Lightning/Visualforce page source — look for:
# - "auraConfig", "auraContext" in page source → Lightning
# - <apex: tags → Visualforce
# - /services/data/ references → REST API version
# - SalesforceEndpointFQDN, organizationId in page metadata
```

**Detection signals for `register_detected_stack`:**
- Domains matching `*.force.com`, `*.my.salesforce.com`, `*.my.site.com`, `*.my.salesforce-sites.com`
- Response headers: `Salesforce` in `Server`, `BrowserId` cookie
- `/services/data/` path returning API version listing
- Visualforce `<apex:` tag prefix or Lightning `auraConfig` in page source
- `/aura` or `/s/sfsites/aura` endpoints responding with Aura framework errors

## Key Vulnerabilities

### SOQL Injection

SOQL (Salesforce Object Query Language) injection occurs when Apex code inserts user-controlled input into dynamic SOQL or SOSL queries without bind variables. The injection class is the same as SQL injection (see `sql_injection` for the reasoning framework); the platform-specific expression differs because SOQL has no `UNION`, no multi-statement, no DDL/DML — it is read-only. Exploitation yields unauthorized record access, not database-level RCE.

**Exploitation pattern:**
- Custom Apex controllers exposed via Aura (`@AuraEnabled` methods) or Visualforce accept user input and construct SOQL dynamically.
- Inject into `WHERE` clauses: `' OR Name != '` to widen the result set; `' AND <field> LIKE 'A%` for blind extraction.
- SOQL `LIKE` operator and `WHERE` clause manipulation are the primary injection vectors — `ORDER BY`, `LIMIT`, and subquery injection are secondary.
- Guest-accessible Aura controllers are the highest-risk surface: SOQL injection reachable without authentication, in the guest user's object/field access context.

**Blind SOQL injection via Aura:** the CsvDataImportResourceFamilyController class (a default Salesforce controller) was reported to accept unsanitized input in SOQL queries, enabling blind extraction of user records and document metadata from guest context. Salesforce patched this without a CVE or public advisory (disclosed by Tobia Righi, patched mid-2025, per researcher disclosure).

**Mitigation check:** Salesforce's recommended fix is bind variables (`[SELECT Id FROM Account WHERE Name = :userInput]`). Dynamic SOQL with `String.escapeSingleQuotes()` is a partial mitigation — it prevents quote-based injection but not injection into unquoted numeric or boolean fields.

### Guest-User and Experience Cloud Over-Exposure

The recurring Salesforce misconfiguration class: Experience Cloud (formerly Community) sites expose internal records to unauthenticated guest users through misconfigured object permissions, sharing rules, or Aura controllers.

**The exposure pattern:**
- Guest User Profile granted CRUD access to sensitive objects (Contact, Account, Case, custom objects containing PII).
- Organization-Wide Default (OWD) set to "Public Read" or "Public Read/Write" on objects that should be private — guest users inherit this access.
- Custom Aura controllers with `@AuraEnabled` methods that query records without enforcing `WITH SECURITY_ENFORCED` or manual FLS checks — the controller runs in system context, bypassing the guest profile's FLS/CRUD restrictions.
- Unauthenticated access to the Aura endpoint (`/s/sfsites/aura`) allows calling exposed controller methods directly, returning record data the guest profile's object permissions technically allow but the UI was not designed to surface.

AppOmni documented widespread exposure across government and enterprise Experience Cloud sites (2023 disclosure), finding sensitive records accessible via the unauthenticated Aura endpoint. This is a misconfiguration pattern, not a platform vulnerability — the underlying access-control model works as designed, but the default permissiveness of the Guest User Profile and the system-context execution of Apex combine to create the exposure.

### FLS/CRUD and Sharing-Rule Bypass

Apex code runs in system context by default — it ignores the running user's FLS, CRUD, and sharing rules unless the developer explicitly enforces them. This is by design (Salesforce documentation: "Apex generally runs in system context"), but it means every custom Apex controller, trigger, and batch job is a potential authorization bypass.

**Bypass patterns:**
- `@AuraEnabled` method returns fields the user's profile cannot see — FLS not checked.
- SOQL query in Apex without `WITH SECURITY_ENFORCED` or `Security.stripInaccessible()` — returns records/fields regardless of FLS/CRUD.
- `without sharing` keyword on an Apex class — sharing rules (record-level access) not enforced; all records visible.
- Triggers that modify records across sharing boundaries in `after insert`/`after update` context.
- API access (REST/SOAP) respects FLS/CRUD at the API layer, but Apex called from connected apps via the API runs in system context.

### Misconfigured Custom Objects and Metadata

- Custom objects with OWD "Public Read/Write" storing sensitive data (PII, financial records, credentials).
- Custom fields on standard objects (e.g., a `SSN__c` field on Contact) without FLS restrictions.
- Validation rules bypassed in bulk API context (Bulk API can skip some validation rules depending on configuration).
- Metadata API access with overly broad Connected App permissions — allows reading field definitions, page layouts, and Apex source code.

## Testing Methodology

1. **Fingerprint** the Salesforce instance type (production, sandbox, Experience Cloud) from domain patterns and page source.
2. **Guest-user access audit** — probe the Aura endpoint (`/s/sfsites/aura`) from an unauthenticated context; enumerate accessible controller methods and the objects/fields they return.
3. **SOQL injection** — test all user-controlled inputs reaching `@AuraEnabled` methods for dynamic SOQL construction; use blind SOQL techniques (boolean-based `WHERE` clause manipulation) where direct output is not reflected.
4. **FLS/CRUD enforcement** — with authenticated access, compare API-level field visibility (REST API `describe`) against Apex controller output; fields returned by Apex but blocked by FLS at the API layer indicate system-context bypass.
5. **Sharing-rule enforcement** — test record visibility: query records via REST API (respects sharing) vs via an Apex controller (may use `without sharing`); compare result sets.
6. **OWD and sharing configuration** — review Organization-Wide Defaults for sensitive objects; confirm private objects are not accessible from the guest profile.
7. **Connected App audit** — enumerate OAuth scopes, refresh-token lifetimes, and IP restrictions on Connected Apps with API access.

## Validation

1. Show the unauthenticated Aura endpoint response with record data that should not be guest-accessible — include the object name, field names, and record count.
2. SOQL injection: show the injected input, the modified SOQL query (inferred from response behavior), and the data extracted.
3. FLS bypass: show the field returned by the Apex controller alongside the FLS setting blocking that field at the profile/API level.
4. Sharing bypass: show records returned by `without sharing` Apex that are not visible via REST API under the same user.
5. OWD exposure: show the OWD setting ("Public Read") on a sensitive object and the guest-user query returning records.

## False Positives

- Guest-accessible Aura controllers returning **only public-facing data** (product catalog, FAQ) — this is intended functionality; the finding is when PII, internal cases, or credentials are exposed.
- FLS "bypass" where the user's profile actually grants field access — verify the FLS setting before claiming bypass; Apex system-context is a bypass only when FLS would otherwise restrict the field.
- `without sharing` on a class that only processes the current user's own records — the sharing bypass is only a finding when it exposes other users' records.
- Connected App with `api` scope on an internal-only integration — the finding is when the token can be obtained by external parties, not the scope itself.
- Sandbox environments with relaxed security settings — confirm production vs sandbox before reporting guest-exposure findings at production severity.

## Impact

- Mass PII exposure via unauthenticated Experience Cloud access — government and enterprise instances documented by AppOmni.
- Record-level data theft via SOQL injection from guest context — blind extraction of user, contact, and document data.
- Authorization bypass via system-context Apex — users accessing records and fields their profile is designed to restrict.
- Credential and secret exposure when custom objects store API keys, tokens, or passwords without FLS restrictions.

## Pro Tips

1. The Aura endpoint (`/s/sfsites/aura`) is the highest-value unauthenticated surface — probe it before authenticated testing.
2. `WITH SECURITY_ENFORCED` in SOQL is the developer's opt-in to FLS/CRUD enforcement — its absence in custom Apex is the most common bypass pattern.
3. `String.escapeSingleQuotes()` does not prevent SOQL injection in all cases — test numeric and boolean field injection separately.
4. Salesforce does not assign CVEs — platform-side patches are silent; track researcher disclosures (AppOmni, Varonis) for new exposure classes.
5. Pair with `sql_injection` for injection reasoning, `authentication_jwt` for OAuth/SSO token validation on Connected Apps, and `information_disclosure` for secrets in custom fields or metadata.

## Summary

Salesforce compromise follows the access-control-bypass path: SOQL injection in custom Apex, guest-user over-exposure on Experience Cloud sites, and FLS/CRUD/sharing-rule bypass from system-context Apex execution. The platform's multi-tenant model means there is no infrastructure to exploit — findings center on what the authorization boundaries permit, whether by misconfiguration or by Apex code running in system context without enforcing the security model. The unauthenticated Aura endpoint on Experience Cloud sites is the single highest-risk surface.
