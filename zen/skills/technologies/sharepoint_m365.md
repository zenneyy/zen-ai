---
name: sharepoint_m365
description: SharePoint and Microsoft 365 security testing covering the SharePoint deserialization RCE lineage (ToolShell CVE-2025-53770 class), Graph API over-scoped permissions, Entra ID app-registration and consent abuse, and OneDrive/Teams/SharePoint data exposure
---

# SharePoint & Microsoft 365

SharePoint Server and the Microsoft 365 cloud suite (SharePoint Online, OneDrive, Teams, Entra ID) present two distinct attack surfaces: on-premises SharePoint Server carries a recurring deserialization RCE lineage where the attack primitive is unauthenticated code execution, while the M365 cloud suite's surface is identity and authorization — app-registration consent abuse, Graph API over-scoped permissions, and data-exposure misconfigurations. This skill owns these SharePoint/M365-specific surfaces. It references `insecure_deserialization` for the ViewState/MachineKey exploitation mechanics (which that skill documents as the canonical .NET deserialization chain — this skill owns the SharePoint-specific delivery primitive, not the deserialization technique itself), `active_directory` for on-premises AD domain infrastructure, and `auth0`/`okta` for generic identity-provider patterns. Entra ID (formerly Azure AD) is the M365-specific identity plane — this skill owns its app-registration and consent surfaces, not the general OAuth protocol (see `authentication_jwt`).

## Attack Surface

**SharePoint Server (on-premises)**
- Web application: IIS hosting SharePoint sites; `_layouts/`, `_vti_bin/`, `/_api/` endpoint prefixes
- Authentication: Windows auth (NTLM/Kerberos), claims-based (SAML/ADFS), forms-based
- ViewState: ASP.NET `__VIEWSTATE` serialization on legacy pages — protected by MachineKey (ValidationKey + DecryptionKey in `web.config`)
- Content databases: SQL Server backend; site collections, lists, document libraries
- Central Administration: management console (separate IIS site, often on a non-standard port)

**SharePoint Online (M365)**
- Tenant: `<tenant>.sharepoint.com`, personal OneDrive: `<tenant>-my.sharepoint.com`
- SharePoint REST API: `/_api/`, Microsoft Graph API: `graph.microsoft.com`
- Sharing: external sharing settings (organization-level, site-level, file-level), anonymous links
- Search: cross-site search indexes content the searching user's permissions can reach

**Entra ID (Azure AD)**
- App registrations: OAuth client_id/client_secret, redirect URIs, API permissions (delegated/application)
- Admin consent: tenant-wide consent grants allow apps to access all users' data
- Service principals: the runtime identity of an app registration; carries the granted permissions
- Conditional Access: MFA enforcement, device compliance, location-based policies

**Teams / OneDrive**
- Teams: channels, chats, files (backed by SharePoint document libraries), tabs, connectors, bots
- OneDrive for Business: user-level file storage (`/personal/` paths on `<tenant>-my.sharepoint.com`)
- Graph API scopes: `Files.Read.All`, `Mail.Read`, `Chat.Read.All`, `User.Read.All` — each a data-access primitive

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# SharePoint Server — on-premises
curl -sI https://<target>/_layouts/viewlsts.aspx
# Look for: X-SharePointHealthScore, MicrosoftSharePointTeamServices, SPRequestGuid headers

# Version disclosure
curl -sI https://<target>/_vti_pvt/service.cnf
# Response: vti_extenderversion:<version> — maps to SharePoint build number

# SharePoint Online — tenant existence
curl -sI https://<tenant>.sharepoint.com/
# 200/302 = tenant exists; 404 = not a valid tenant

# Entra ID / Azure AD — tenant discovery
curl -s https://login.microsoftonline.com/<tenant>/.well-known/openid-configuration | jq .
# Returns tenant_id, authorization/token endpoints, issuer

# Entra ID tenant existence (getuserrealm)
curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1'
# NameSpaceType: Managed (cloud-only) or Federated (ADFS/hybrid)
```

**Detection signals for `register_detected_stack`:**
- `*.sharepoint.com` domain (Online) or `X-SharePointHealthScore` / `MicrosoftSharePointTeamServices` headers (on-prem)
- `_layouts/`, `_vti_bin/`, `/_api/` URL path prefixes
- `login.microsoftonline.com` in authentication redirects (Entra ID)
- `SPRequestGuid`, `X-MS-InvokeApp` response headers
- SharePoint build version in `_vti_pvt/service.cnf` or `MicrosoftSharePointTeamServices` header

## Key Vulnerabilities

### SharePoint Server Deserialization RCE Lineage

SharePoint Server has carried a recurring deserialization RCE class across multiple release cycles. The structural root cause is the ASP.NET ViewState serialization surface on SharePoint's IIS-hosted pages — legacy endpoints accept serialized objects that, when the MachineKey is known or authentication is bypassed, yield remote code execution. The deserialization technique (ViewState forging, `ysoserial.net` gadget chains, `ObjectStateFormatter`) is documented in `insecure_deserialization` — this section owns the SharePoint-specific delivery primitives and CVE classes.

**ToolShell — CVE-2025-53770 + CVE-2025-53771 (July 2025)**
The most severe entry in the lineage. Two chained vulnerabilities enabling unauthenticated RCE:
- **CVE-2025-53770** (CVSS 9.8) — deserialization of untrusted data (CWE-502) in the legacy `ToolPane.aspx` endpoint. Unauthenticated code execution over the network.
- **CVE-2025-53771** (CVSS 6.5) — authentication bypass (CWE-287) via forged `Referer` header, allowing access to the `spinstall0.aspx` web shell, which dumps the MachineKey (ValidationKey and DecryptionKey) from `web.config`.
- **Chain:** authentication bypass (53771) → MachineKey extraction → ViewState forging with attacker payload → deserialization RCE (53770). The MachineKey dump is the pivot — without it, the deserialization endpoint's MAC validation blocks forged payloads. With the key, the attacker crafts a signed ViewState blob using `ysoserial.net` (see `insecure_deserialization`).
- **Post-exploitation persistence:** the MachineKey does not rotate on patch — an attacker who exfiltrated the key before patching retains RCE capability until the organization rotates the machine keys in `web.config` across all SharePoint servers. This mirrors the "patch is not remediation" pattern from `edge_vpn_appliances`.
- Affects SharePoint Server 2016, 2019, and Subscription Edition (on-premises only; SharePoint Online is not affected). Weaponized within days by Storm-2603 (Microsoft tracking). Patches: KB5002768, KB5002754, KB5002745.

**Prior lineage entries (all NVD-verified):**
- **CVE-2024-38094** (CVSS 7.2) — deserialization RCE requiring Site Owner rights (CWE-502). CISA KEV (October 2024); observed chained with CVE-2024-38023 (privilege escalation) for domain compromise in ransomware campaigns.
- **CVE-2023-29357** (CVSS 9.8) — privilege escalation enabling unauthenticated access. CISA KEV (January 2024). Chained with deserialization endpoints for full RCE.
- **CVE-2019-0604** (CVSS 9.8) — RCE via failure to validate application-package source markup (CWE-20). One of the earliest high-profile SharePoint RCE CVEs; affected SharePoint 2010 through 2019.

The pattern: SharePoint Server's serialization-heavy architecture produces new deserialization RCE variants across release cycles. On every on-premises SharePoint engagement, version-match against all known CVEs in this lineage, not just the latest.

### Graph API Over-Scoped Permissions

Microsoft Graph API (`graph.microsoft.com`) is the unified API for M365 data — mail, files, calendar, Teams, directory. Application permissions (vs. delegated) are the high-risk class: they grant access to all users' data without per-user consent.

**Over-scoped application permissions:**
- `Mail.ReadWrite` (application) → read/send email as any user in the tenant.
- `Files.ReadWrite.All` (application) → read/write all OneDrive and SharePoint files.
- `User.ReadWrite.All` (application) → modify all user profiles, including passwords.
- `Directory.ReadWrite.All` (application) → full directory CRUD including group membership and role assignments.

**Credential exposure:** the app registration's `client_secret` or certificate is the credential. Secrets in source code, CI/CD, or developer machines grant the application's full permission set without user authentication. Pair with `information_disclosure` for secret-scanning and `cryptographic_failures` for certificate-handling weaknesses.

### Entra ID App-Registration and Consent Abuse

**Illicit consent grant attack:** an attacker registers a malicious OAuth application and tricks a user (or admin) into granting it permissions. With admin consent, the application accesses all users' data tenant-wide.

**Misconfigured app registrations:**
- Overly broad redirect URIs (wildcards, `http://localhost`) — enable authorization-code interception.
- Multi-tenant apps (`signInAudience: AzureADMultipleOrgs`) with sensitive permissions — any tenant user can consent, and the app operates across tenants.
- No credential expiry — app secrets without expiration dates; long-lived credentials are persistence primitives.
- Reply URLs accepting `http://` (non-HTTPS) — token interception via MitM.

**CVE-2025-55241** (CVSS 10.0 per Microsoft, 9.8 per NVD) — Entra ID elevation-of-privilege vulnerability where the legacy Azure AD Graph API failed to validate the tenant source of authentication tokens, enabling cross-tenant access bypassing MFA and Conditional Access. Fixed July 2025; Azure AD Graph API retired August 2025.

### OneDrive / Teams / SharePoint Data Exposure

**Sharing misconfigurations:**
- Organization-level external sharing set to "Anyone" — anonymous links to files and folders accessible without authentication.
- Site-level sharing overriding organization defaults — a single site with "Anyone" sharing exposes its document library.
- "Anyone" links with no expiration — persistent unauthenticated access.
- Teams channels with guest access — external users added to Teams can access the backing SharePoint document library.

**Search-based data discovery:** SharePoint search indexes content across site collections. A user with access to one site can discover and potentially access content from other sites if search permissions are misconfigured (the search result respects ACLs, but metadata — titles, snippets — may leak sensitive information).

**OneDrive sync client exposure:** the sync client mirrors SharePoint/OneDrive files to local devices. Compromised endpoints with synced libraries expose the file data without requiring cloud authentication.

## Testing Methodology

1. **Fingerprint** on-premises SharePoint version from `_vti_pvt/service.cnf` or `MicrosoftSharePointTeamServices` header; for SharePoint Online, identify the tenant.
2. **Version-match** on-premises against the deserialization RCE lineage (CVE-2025-53770, CVE-2024-38094, CVE-2023-29357, CVE-2019-0604).
3. **MachineKey exposure check** — on-premises: test for `web.config` disclosure paths (`information_disclosure`); verify ToolShell indicators (spinstall0.aspx presence, w3wp.exe child processes).
4. **Entra ID app audit** — enumerate app registrations, permissions (application vs delegated), consent grants, credential expiry, and redirect URIs via Graph API or Azure portal.
5. **Graph API scope review** — list application permissions granted; identify over-scoped applications with `Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`.
6. **Sharing configuration audit** — review organization-level and site-level external sharing settings; enumerate anonymous links.
7. **Teams guest access** — enumerate Teams with external members; verify what data guests can access.

## Validation

1. On-premises RCE: show the SharePoint build number in the affected CVE range, the advisory URL, and (per engagement rules) the exploitation chain.
2. MachineKey exposure: show the `web.config` disclosure path or ToolShell indicator and the resulting key material.
3. Over-scoped Graph permissions: show the app registration, its application permissions, and a Graph API call demonstrating data access beyond the app's business function.
4. Consent abuse: show the consent grant and the data the consented app can access.
5. Sharing exposure: show the "Anyone" link configuration and the unauthenticated file access it permits.

## False Positives

- SharePoint Online — not affected by on-premises deserialization CVEs; do not report ToolShell or ViewState findings against SharePoint Online.
- App registration with application permissions but no exposed secret — the finding is the credential exposure, not the permission grant alone (though over-scoped permissions are a configuration finding regardless).
- "Anyone" sharing links that are configured with short expiry and limited scope (view-only, single file) — down-rate vs. no-expiry links to entire document libraries.
- Entra ID multi-tenant app configured intentionally for cross-tenant SaaS integration — the finding is the permission scope and credential hygiene, not multi-tenancy itself.
- SharePoint build in the fixed version range for all applicable CVEs — not exploitable; still report internet exposure of the management interface.
- Teams guest access limited to a single channel with non-sensitive content — down-rate when the guest's access scope is appropriate to their role.

## Impact

- Unauthenticated RCE on SharePoint Server via the deserialization lineage — OS-level code execution on the IIS host, typically a domain-joined server.
- Full tenant data access via over-scoped Graph API application permissions — email, files, directory, Teams chats for every user.
- Cross-tenant access via Entra ID token-validation bypass (CVE-2025-55241) — bypassing MFA and Conditional Access.
- Persistent access via exfiltrated MachineKey (on-prem) or long-lived app secrets (M365) — survives patching without credential rotation.
- Data exposure via anonymous sharing links — unauthenticated access to internal documents, presentations, spreadsheets.

## Pro Tips

1. `_vti_pvt/service.cnf` is the fastest on-prem version fingerprint — the build number maps directly to KB and CVE applicability.
2. ToolShell's MachineKey persistence means patching is not remediation — always verify key rotation post-patch; `insecure_deserialization` documents the ViewState forging technique.
3. Application permissions (vs. delegated) in Graph API are the high-risk class — they bypass per-user consent and operate tenant-wide.
4. `login.microsoftonline.com/getuserrealm.srf` reveals whether a domain is Managed (cloud-only) or Federated (ADFS) — this determines the authentication attack surface.
5. Pair with `insecure_deserialization` for ViewState/MachineKey exploitation mechanics, `active_directory` for domain-pivot post-SharePoint RCE, `auth0`/`okta` for federated identity patterns, and `information_disclosure` for secret and config-file exposure.

## Summary

SharePoint and M365's attack surface splits between on-premises deserialization RCE (a recurring lineage from CVE-2019-0604 through ToolShell CVE-2025-53770 — version-match first, then check MachineKey exposure and post-patch persistence) and cloud identity/authorization abuse (Graph API over-scoped permissions, Entra ID app-registration consent attacks, sharing misconfigurations). On-prem: the deserialization lineage is the highest-priority surface. Cloud: over-scoped application permissions and illicit consent grants are the primary escalation paths.
