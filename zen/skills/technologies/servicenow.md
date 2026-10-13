---
name: servicenow
description: ServiceNow security testing covering ACL misconfiguration and record exposure, the Simple List widget data-leak class, GlideExpression input-validation RCE (CVE-2024-5217/CVE-2024-4879), script injection via server-side Glide, and over-permissioned role abuse
---

# ServiceNow

ServiceNow is a cloud-hosted platform (Now Platform) where the attack surface is access-control configuration and server-side scripting, not infrastructure exploitation — ServiceNow manages the instance infrastructure. This skill owns ACL misconfiguration and record exposure (including the Simple List widget data-leak class), GlideExpression input-validation RCE CVE classes, server-side Glide script injection, and role/permission abuse. It does not duplicate general injection reasoning (see `sql_injection` for the class), identity-provider configuration (see `auth0`/`okta` for SSO surfaces), or API-level authorization flaws (see `idor`/`broken_function_level_authorization` for generic authz).

## Attack Surface

**Authentication & identity**
- Local accounts (username/password), SSO (SAML/OAuth/OIDC), MFA (multifactor via policy)
- Integration users and service accounts (mid-server, REST/SOAP integrations)
- Session management: glide session cookies, CSRF tokens

**Access control**
- ACLs (Access Control Lists): table-level, field-level, record-level conditions
- Roles: `admin`, `itil`, `snc_internal`, custom roles; role inheritance via `contains` relationships
- ACL evaluation order: table → table.field → table.field.operation; first matching ACL wins
- Guest/public access: ACLs without role or condition fields default to allowing all access (the root cause of the 2023 exposure class)

**Endpoints**
- Instance: `<instance>.service-now.com`
- REST API: `/api/now/table/<table>`, `/api/now/v2/`, custom scripted REST APIs
- Service Portal: `/sp`, widget endpoints, `/api/now/sp/`
- CMDB, ITSM, SecOps, HR modules — each with table-specific ACL configurations
- Admin UI: `nav_to.do`, form views, lists, reports

**Server-side scripting**
- Business Rules (before/after insert/update/delete/query)
- Script Includes (server-side JavaScript libraries)
- UI Pages, UI Macros, Processors (server-side HTML/JS)
- Scheduled Jobs, Flow Designer, IntegrationHub
- Glide API: `GlideRecord`, `GlideSystem`, `GlideExpression` — server-side JavaScript executing in the Now Platform context

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# Instance probe — confirms ServiceNow
curl -sI https://<instance>.service-now.com/
# Look for: "ServiceNow" in page title, Set-Cookie with glide_* prefixes

# Login page
curl -s https://<instance>.service-now.com/login.do | grep -i "servicenow\|instance_name"

# Service Portal (if enabled)
curl -s https://<instance>.service-now.com/sp

# REST API probe (unauthenticated — expect 401)
curl -sI https://<instance>.service-now.com/api/now/table/sys_user
# 401 = instance exists, auth required; connection refused = not reachable

# Version disclosure — stats.do or xmlstats.do (often ACL-protected but worth probing)
curl -s https://<instance>.service-now.com/stats.do
```

**Detection signals for `register_detected_stack`:**
- Domain matching `*.service-now.com`
- `glide_user_route`, `glide_session_store`, `JSESSIONID` cookies
- `/api/now/` REST API path prefix
- `/nav_to.do`, `/sp`, `/login.do` endpoint patterns
- `X-Is-Logged-In`, `X-Transaction-ID` response headers
- Page source containing `ServiceNow`, `snc-`, or `angular.module('sn.')` references

## Key Vulnerabilities

### ACL Misconfiguration and Record Exposure

The recurring ServiceNow data-exposure class: ACLs created without a `Role` field or a `Condition` script default to allowing access to all users, including unauthenticated guest users via the Service Portal.

**The Simple List widget exposure (2023 disclosure):** Aaron Costello (AppOmni) documented that the Simple List widget in Service Portal, when backed by tables with permissive ACLs, serves record data to unauthenticated visitors. The root cause is the ACL evaluation model — an ACL with no role and no condition matches all users. Tables commonly exposed: `sys_user` (employee directory with email, phone, manager), `kb_knowledge` (internal knowledge base articles), `sc_cat_item` (service catalog items with internal pricing/procedures), `incident`/`change_request` (IT tickets with sensitive details). ServiceNow patched by defaulting blank ACLs to require authentication, but existing instances with pre-patch ACLs remain exposed until manually remediated.

**CVE-2022-43684** (CVSS 9.9 per ServiceNow, 6.5 per NVD) — ACL bypass in Reporting functionality allowing authenticated users to access records from tables missing authorization controls. Affected Quebec through Tokyo releases.

**CVE-2025-3648** (CVSSv4 8.2) — unauthenticated and authenticated users can use range query requests to infer data from tables with certain ACL configurations. Disclosed by Varonis ("Count(er) Strike"), patched September 2024, CVE published July 2025. The fix added "Deny Unless" ACLs and restricted query-type ACLs for enumeration queries.

### Input-Validation RCE (GlideExpression Class)

Two critical input-validation flaws in the Now Platform enabling unauthenticated remote code execution:

**CVE-2024-5217** (CVSS 9.8) — incomplete input validation in GlideExpression scripts allows unauthenticated RCE over the network. Affects Washington DC, Vancouver, and earlier releases. CISA KEV (added July 2024, remediation deadline August 19, 2024). Public exploit code available (Exploit-DB #52410).

**CVE-2024-4879** (CVSS 9.8) — separate input-validation flaw enabling unauthenticated RCE. Affects Vancouver and Washington DC releases. Also in CISA KEV. Both CVEs have distinct root causes — patching one does not address the other.

**Exploitation context:** these are template-injection / expression-evaluation flaws where user input reaches server-side Glide expression evaluation without adequate filtering. The CWE assignments (CWE-697, CWE-184, CWE-1287) reflect incomplete-disallow-list validation. A version check against the fixed build numbers is the first gate.

### Server-Side Script Injection

ServiceNow's scripting layer (Business Rules, Script Includes, UI Pages, Processors) executes server-side JavaScript via the Glide API. Injection surfaces:

- **Scripted REST APIs** accepting user input and evaluating it in GlideRecord queries or GlideEvaluator expressions without sanitization — equivalent to server-side code injection.
- **Business Rules** with `current.getValue()` or `gs.getParameter()` passed into `GlideRecord.addEncodedQuery()` without validation — the encoded-query syntax supports complex expressions that can be manipulated to widen or redirect queries.
- **UI Pages / Processors** with inline `<g:evaluate>` blocks processing user-supplied parameters — direct server-side JavaScript execution.
- **Client-callable Script Includes** (`client_callable: true`) that accept and process user input without validation — reachable from the client side via GlideAjax, expanding the attack surface to any authenticated user.

### Over-Permissioned Roles and Elevation

- `admin` role grants unrestricted access to all tables, scripts, and system configuration — a compromised admin account is full instance takeover.
- `snc_internal` role (ServiceNow-internal) grants access to internal system functions; if assigned to customer-created accounts, it bypasses intended access restrictions.
- Role inheritance chains: a custom role that `contains` `admin` or `security_admin` inherits their full permissions — review the `sys_user_has_role` and `sys_group_has_role` tables.
- Impersonation: users with `impersonator` role can impersonate any user, including admins — this is a legitimate feature but a high-value target.
- Elevated roles (`security_admin`, `personalize_dictionary`, `catalog_admin`) modify ACLs, dictionary entries, and catalog configurations — each is an escalation path.

## Testing Methodology

1. **Fingerprint** the instance and identify the release family (Washington DC, Vancouver, Utah, etc.) from login page, headers, or API responses.
2. **Version-match** against CVE-2024-5217 and CVE-2024-4879 affected ranges — an unpatched instance is a critical finding.
3. **Unauthenticated Service Portal audit** — probe `/sp` and widget endpoints for data returned without authentication; test the Simple List widget and any custom widgets.
4. **ACL review** — with authenticated access, enumerate ACLs on sensitive tables (`sys_user`, `incident`, `kb_knowledge`, `cmdb_ci`); identify ACLs with no role and no condition.
5. **Script injection** — test Scripted REST APIs, client-callable Script Includes, and any endpoint accepting query parameters for GlideRecord injection or expression evaluation.
6. **Role audit** — enumerate users with `admin`, `security_admin`, `impersonator`, and custom elevated roles; check for service accounts with admin privileges.
7. **Integration credentials** — review mid-server configurations and REST/SOAP integration users for over-scoped access and stored credentials.

## Validation

1. Show the ServiceNow release version and the CVE it maps to, with the ServiceNow KB article URL.
2. Unauthenticated data exposure: show the widget endpoint response with record data (table name, fields, record count) from guest context.
3. ACL bypass: show the ACL configuration (no role, no condition) and the table data accessible through it.
4. RCE (CVE-2024-5217/4879): show the version in the affected range; exploitation demonstration per engagement rules.
5. Script injection: show the injected input and the server-side response confirming code execution or data exfiltration.
6. Over-permissioned role: show the role assignment and the administrative action it permits beyond the user's business function.

## False Positives

- Service Portal returning **public-facing catalog items** or knowledge articles intentionally published for external users — confirm the data is sensitive before reporting.
- ACL with no role but a restrictive `Condition` script — the condition may enforce access control even without a role requirement; evaluate the condition logic.
- `admin` role on a dedicated ServiceNow administrator account — the finding is when non-admin users have admin, or when admin accounts lack MFA, not the existence of admin accounts.
- `stats.do` / `xmlstats.do` accessible but returning no sensitive data — information-disclosure severity depends on what is exposed.
- Development/sub-production instances with relaxed ACLs — confirm instance type before reporting at production severity.
- Client-callable Script Includes that validate and sanitize input correctly — the finding is the injection, not the `client_callable` flag alone.

## Impact

- Unauthenticated data exposure via permissive ACLs — employee PII, IT tickets, internal knowledge base content, CMDB data.
- Unauthenticated remote code execution via GlideExpression input-validation flaws — full instance compromise.
- Privilege escalation via over-permissioned roles or impersonation — access to all data and configuration.
- Lateral movement to integrated systems via stored integration credentials and mid-server access.

## Pro Tips

1. The Simple List widget on Service Portal is the fastest unauthenticated data-exposure check — probe it before authenticated testing.
2. CVE-2024-5217 and CVE-2024-4879 have public exploits — version-match first; an unpatched internet-facing instance is critical.
3. `addEncodedQuery()` in Business Rules and Script Includes is the injection surface for GlideRecord query manipulation — test any user-reachable code path that feeds into it.
4. Check `sys_user_has_role` for any non-admin user holding `admin`, `security_admin`, or `impersonator` — these are the escalation primitives.
5. Pair with `idor`/`broken_function_level_authorization` for API-level authz testing, `authentication_jwt` for SSO token validation, and `information_disclosure` for credential exposure in integration configurations.

## Summary

ServiceNow's attack surface combines access-control misconfiguration (permissive ACLs defaulting to allow-all, the Simple List widget exposure class) with server-side code execution (GlideExpression input-validation RCE, script injection via Business Rules and Scripted REST APIs). The 2024 RCE CVEs (5217/4879) are critical — version-check first. The recurring data-exposure pattern stems from ACLs without role or condition fields defaulting to public access; test Service Portal unauthenticated before authenticated work.
