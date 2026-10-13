---
name: okta
description: Okta tenant security testing covering cross-tenant federation abuse, SWA credential exposure, SSWS API token over-permissioning, support-system breach (HAR file) incident classes, and sign-on policy bypass
---

# Okta

Okta is a managed identity platform — the attack surface is tenant configuration, federation trust, API token scoping, and the operational patterns (HAR file handling, helpdesk social engineering) that have driven real-world compromises. This skill owns Okta-specific surfaces: the org model, org2org federation, SWA apps, SSWS API tokens, Okta Workflows, and the incident classes unique to Okta's architecture. It references `auth0` for shared identity-platform concepts (OIDC/OAuth flow mechanics, callback URL patterns, token confusion) and `authentication_jwt` for JWT validation fundamentals — those are not re-implemented here. The Okta Classic app-sign-on-policy bypass is documented in `weak_password_detection` (novel_deep); this skill provides the broader Okta context it operates within.

## Attack Surface

**Tenant Model**
- Okta org: `<tenant>.okta.com` (production), `<tenant>.oktapreview.com` (sandbox)
- Custom domains: `sso.company.com` → Okta org
- Universal Directory: users, groups, profile attributes
- Application assignments: OIDC, SAML, SWA, API, bookmark

**Authentication and Policy**
- Global Session Policy → application sign-on policies (layered)
- MFA: Okta Verify (push, TOTP, FastPass/FIDO2), SMS, email, third-party
- Authenticator enrollment policies, factor sequencing
- Device trust / Okta FastPass (device-bound keys)

**Admin and API**
- Admin Console: super admin, org admin, app admin, helpdesk admin, read-only admin
- API tokens: `SSWS` prefix, created by admins, inherits creator's full permissions
- OAuth 2.0 tokens: scoped to declared grants (recommended replacement for SSWS)
- Okta Workflows: low-code automation with connectors to external services

**Federation**
- Inbound federation: external IdP → Okta org (SAML/OIDC)
- Org2Org federation: Okta org → Okta org (hub-and-spoke)
- Identity brokering: Okta as SP to upstream IdPs

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# Okta login page — confirms tenant
curl -sI https://<tenant>.okta.com/
# Look for: okta-signin-widget, X-Okta-Request-Id, okta-* headers

# OIDC discovery
curl -s https://<tenant>.okta.com/.well-known/openid-configuration | jq .
# Custom authorization servers
curl -s https://<tenant>.okta.com/oauth2/<auth-server-id>/.well-known/openid-configuration | jq .

# Widget fingerprinting in custom login pages
grep -r 'okta-signin-widget\|OktaSignIn\|okta-auth-js\|@okta/' <source>
# okta-auth-js versions in JS bundles may reveal outdated SDKs
```

**Tenant classification**
- `*.okta.com` → production; `*.oktapreview.com` → sandbox; `*.trexcloud.com` → FedRAMP
- Custom domain (e.g., `sso.company.com`) CNAME to `<tenant>.customdomains.okta.com`
- Multiple Okta orgs per company (dev/staging/prod) — credential reuse across orgs is common

**SWA app discovery**
- SWA (Secure Web Authentication) apps appear in the user's Okta dashboard alongside SAML/OIDC apps
- Okta stores the user's credentials for SWA apps and auto-fills them via the browser plugin or the Okta dashboard — the credentials are retrievable by the app admin

## Key Vulnerabilities

### Cross-Tenant Impersonation via Federation

The highest-impact Okta-specific attack class. Demonstrated in the 2023 campaigns against multiple organizations:

- Attacker compromises a super admin account (typically via social-engineered helpdesk MFA reset or credential stuffing against admin accounts without phishing-resistant MFA).
- Attacker configures a new inbound identity provider (IdP) in the victim's Okta org, pointing to an attacker-controlled IdP.
- Attacker authenticates through the attacker-controlled IdP, and Okta maps the resulting assertion to a legitimate user in the victim's directory.
- Result: attacker impersonates any user in the victim org, including users with downstream access to SAML/OIDC relying parties.

**Preconditions:** super admin access (or org admin with IdP management permissions). Org2Org federation and inbound SAML/OIDC federation are the mechanisms. The mitigation is phishing-resistant MFA on all admin accounts + monitoring for IdP creation events in the system log.

**Detection signal:** Okta system log event `system.idp.lifecycle.create` or `system.idp.lifecycle.activate` from an unexpected admin.

### SWA App Credential Exposure

SWA apps store user credentials in Okta and replay them into the target application's login form. The security implications:

- An app admin (not super admin — the lower-privileged `app admin` role) can configure a malicious SWA app definition that captures the user's Okta master password during the auto-fill process, with no user interaction beyond clicking the app in their dashboard.
- In hub-and-spoke Org2Org federation, a spoke org's app admin can craft a malicious SWA app that captures credentials from federated users originating in the hub org.
- SWA credentials are visible to Okta support in certain support scenarios — a lateral channel for credential exposure.

**Precondition:** app admin role assignment. The finding is the role assignment itself on a user who should not have it, combined with the SWA app attack path.

### SSWS API Token Over-Permissioning

Okta SSWS API tokens (`SSWS <token>`) are the legacy API authentication method:

- **Full permission inheritance:** the token inherits the creating admin's full permissions — always super admin level for tokens created by super admins. There is no scope restriction mechanism for SSWS tokens.
- **No expiration with use:** tokens expire after 30 days of inactivity but reset the timer on every use — a regularly-used SSWS token lives indefinitely.
- **No IP restriction by default:** tokens are usable from any IP unless an admin explicitly configures a network zone restriction.
- **Stored in integrations:** SSWS tokens embedded in SIEM connectors, SCIM provisioning, CI/CD scripts, and third-party tools are high-value targets in code/config leaks.

```
# Leaked SSWS token usage
curl -s -H "Authorization: SSWS <token>" https://<tenant>.okta.com/api/v1/users?limit=200
# Super admin token: full user/group/app/policy/IdP CRUD
```

Okta now recommends OAuth 2.0 tokens with declared scopes for API access. The finding is active SSWS tokens with no IP restriction and no rotation policy.

### Support System and HAR File Incident Class

The 2023 Okta support system breach established a replicable incident class:

- Okta support requests sometimes require customers to upload HTTP Archive (HAR) files for debugging. HAR files contain full HTTP request/response data including session cookies and bearer tokens.
- An attacker with access to the support system (or to the HAR files in transit/storage) extracts session tokens and replays them against the customer's Okta org.
- The 2023 incident affected 134 customers; attackers hijacked 5 active sessions (BeyondTrust, Cloudflare, 1Password were notified). Entry vector: a compromised service account whose credentials were saved to a personal Google profile.

**Defensive surface for pentesters:** verify that the organization's HAR file handling process sanitizes session tokens before upload, and that Okta support interactions are monitored for token exfiltration. This is an operational/process finding, not a technical vulnerability — but it chains to full tenant compromise.

### Sign-On Policy Bypass

Okta's layered policy model (Global Session Policy → app sign-on policies) has carried bypass classes:

- **Classic app-sign-on-policy bypass (2024):** between 2024-07-17 and 2024-10-04, Okta Classic evaluated user-agent to determine device type; a Python/uncommon UA was classified as "unknown," causing per-app policies (MFA, network zones, device-type restrictions) to be skipped for valid-credential-holding attackers. No CVE issued; documented in `weak_password_detection` (novel_deep). Patched 2024-10-04.
- **Policy ordering:** sign-on policies evaluate in order; a broadly-permissive "catch-all" policy positioned above a restrictive one negates the restriction. Misconfigured policy ordering is a common finding.
- **Factor downgrade:** if the policy allows multiple MFA factors, an attacker who can bypass one (e.g., SMS via SIM swap) authenticates through the weaker factor even when a stronger factor (FIDO2) is available.

### Okta Workflows and Event Hooks

**Okta Workflows** is a low-code automation platform with connectors to external services (Slack, Jira, AWS, custom HTTP). Security implications:

- A workflow configured with an HTTP connector that fetches a URL derived from user attributes or event data is an SSRF surface — the request originates from Okta's infrastructure. Route to `ssrf` for the methodology.
- Workflow connector credentials (API keys, OAuth tokens for external services) are stored in the workflow and accessible to workflow editors.
- A compromised admin account can create or modify workflows to exfiltrate data (user attributes, group memberships, authentication events) to attacker-controlled endpoints.

**Event hooks** send Okta system log events to external URLs via HTTP POST. An attacker with admin access can add a hook pointing to an attacker endpoint, receiving real-time authentication events (including session tokens in some event types). **Inline hooks** insert synchronous callouts into authentication flows — an attacker-controlled inline hook can modify token claims, deny/allow authentication, or inject data into the flow.

### Okta Verify Client Attack Surface

- **CVE-2024-9191** (CVSS 7.1) — Okta Verify for Windows: passwords used for Desktop MFA passwordless logins were retrievable from a compromised device.
- **CVE-2024-10327** (CVSS 8.1) — Okta Verify for iOS: push notification authentication bypass via iOS ContextExtension.
- **FastPass device-trust bypass:** FastPass binds authentication to device keys; test whether the device-trust attestation can be bypassed on jailbroken/rooted devices or by extracting the device-bound key.

## Testing Methodology

1. **Tenant fingerprint** — confirm org type (production/preview/FedRAMP), custom domain, and Okta SDK versions in client bundles.
2. **Admin access inventory** — identify admin roles and their holders; check for super admin accounts without phishing-resistant MFA.
3. **API token audit** — enumerate active SSWS tokens (requires admin access); check for IP restriction, rotation policy, and whether OAuth 2.0 migration is complete.
4. **Federation review** — list configured IdPs; verify each is expected and authorized; check for inbound federation from untrusted sources.
5. **SWA app review** — identify SWA apps; verify app admin assignments; test for credential-capture attack path.
6. **Policy review** — examine Global Session Policy and per-app sign-on policies for ordering, factor requirements, and network zone coverage.
7. **System log monitoring** — verify that IdP lifecycle events, admin actions, and policy changes generate alerts.

## Validation

1. Cross-tenant impersonation: show the attacker-controlled IdP configuration in the victim org and a successful authentication as a target user (in a controlled/authorized test).
2. SSWS token exposure: show the token, its permission scope (full super admin), and a demonstration of API access (user list, group modification).
3. SWA credential capture: show the malicious SWA app definition and the credential retrieval.
4. Policy bypass: show the policy configuration, the bypass path (UA manipulation, factor downgrade, policy ordering), and the resulting authentication without the intended control.

## False Positives

- OIDC discovery and login page publicly accessible — this is expected for any IdP; the finding is what the discovery reveals, not its reachability.
- Multiple Okta orgs (dev/staging/prod) — confirm the target org is production before reporting admin-access or policy findings at high severity.
- SSWS tokens with IP restrictions and short rotation policies — down-rate vs unrestricted tokens.
- SWA apps for legitimate use cases (legacy apps without SAML/OIDC support) — the finding is the app admin role assignment and the credential-capture path, not SWA use per se.
- Okta Verify CVEs on devices not in scope — CVE-2024-9191 and CVE-2024-10327 require device-level access; scope the finding to the client environment.
- HAR file incident class without evidence of current HAR file handling — report as a process recommendation, not a confirmed vulnerability.

## Impact

- Full tenant takeover via cross-tenant federation impersonation — attacker authenticates as any user to all relying-party applications.
- Mass credential theft via malicious SWA app configuration — affects all users assigned to the app.
- Persistent API access via leaked SSWS tokens with no expiration and no IP restriction.
- MFA bypass via sign-on policy misconfiguration or factor downgrade.
- Downstream compromise of all SAML/OIDC relying parties through a compromised Okta org.

## Pro Tips

1. The cross-tenant federation attack is Okta's highest-impact class — always check for inbound IdP configurations and admin account MFA posture.
2. SSWS tokens inherit the creator's full permissions and cannot be scoped down — their presence in third-party integrations is the most common Okta API credential leak vector.
3. SWA apps are an underrated attack path — app admin (a delegated, lower-privilege role) is sufficient to capture credentials.
4. Okta system log is the primary detection surface — verify that `system.idp.lifecycle.create`, `user.session.start` from unexpected locations, and admin impersonation events trigger alerts.
5. Pair with `auth0` for shared identity concepts, `weak_password_detection` for the Classic sign-on policy bypass and credential spray methodology, and `authentication_jwt` for downstream token validation on relying parties.

## Summary

Okta's attack surface centers on tenant configuration and trust model abuse — cross-tenant federation impersonation, SWA credential exposure, SSWS token over-permissioning, and sign-on policy bypass — rather than on platform-level CVEs. The highest-impact path is super admin compromise (via helpdesk social engineering or credential stuffing without phishing-resistant MFA) followed by attacker-controlled IdP injection, granting impersonation of any user to all relying parties. SSWS API tokens and SWA apps are persistent, under-monitored exposure channels.
