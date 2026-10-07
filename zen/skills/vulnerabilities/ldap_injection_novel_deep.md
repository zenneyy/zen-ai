---
name: ldap-injection-novel-deep
description: LDAP 2024–2026 frontier — the OR-filter grouping bypass archetype across OPNsense/WeKan/Teedy/maddy/Pandora/Gladinet, Apache CXF/OFBiz/APISIX/MINA SSHD/Zeppelin, library-level CVEs (python-ldap/BouncyCastle/PAC4J), SuiteCRM/MISP/Zimbra/Metacat, and the versioned mechanism catalog
sibling: ldap_injection
load_when: scan_mode == "deep"
---

# LDAP Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `ldap_injection.md`. The base owns the filter-syntax primer, predicate-break primitive, OR-filter-bypass archetype, per-directory differentials, and attack surface. The advanced+expert sibling `ldap_injection_advanced_deep.md` owns per-library escape semantics, DN-injection depth, schema-driven matching rules, AD-specific primitives (`anr=`, extensible-match, chain-match), blind-extraction protocol, second-order LDAP, and WAF filter-bypass as a technique class. This file owns the 2024–2026 CVE mechanism catalogue with the canonical version/fix table, the OR-filter-grouping-bypass archetype decomposed across its CVE instances, the library-level class (python-ldap, BouncyCastle, PAC4J), and the Apache-ecosystem cluster (CXF, OFBiz, APISIX, MINA SSHD, Zeppelin).

Load this file when the goal is matching a target to a current CVE, choosing between OR-filter-bypass and library-level-escape primitives, or writing up the OPNsense CVE-2026-34578 archetype across its sibling applications.

The 2024–2026 LDAP-injection frontier is denser than the "mature class" framing suggests: a direct NVD keyword sweep (`.zen-batch-artifacts/batch-14/nvd/ldap_sweep_2024_2026.json`) returned 50+ verifiable CVEs with CVSS up to 9.8. The pattern across the catalog is uniform: a filter template `(&(uid=$u)(trailing-condition))` with user input concatenated into `$u`; the OR-filter grouping bypass `targetuser)(|(uid=targetuser` collapses the trailing condition and reaches group-gated or role-gated resources. Library-level CVEs expose the same primitive at the dependency layer: python-ldap's escape gap, BouncyCastle's cert-store filter construction, PAC4J's search parameter encoding. All version boundaries are anchored to primary sources persisted at `.zen-batch-artifacts/batch-14/nvd/`.

## 2024–2026 CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only.

| CVE | Package / Target | Vulnerable | Patched | CVSS | Primitive class |
|---|---|---|---|---|---|
| CVE-2024-33868 | linqi (Windows) | < 1.4.0.1 | 1.4.0.1 | 9.8 | Filter concatenation — authn bypass |
| CVE-2024-37393 | SecurEnvoy MFA | < 9.4.514 | 9.4.514 | 7.5 | Multiple filter concatenation — authn bypass |
| CVE-2024-11320 | Pandora FMS | 700 → per vendor | per vendor | 9.8 | LDAP auth mechanism — command injection via LDAP |
| CVE-2024-37782 | Gladinet CentreStack | ≤ v13.12.9934.54690 | per vendor | 9.8 | Login page — authn bypass + arbitrary command execution |
| CVE-2024-9102 | phpLDAPadmin | ≥ 1.2.0 ≤ 1.2.6.7 | — | n/a | CSV export directory extraction |
| CVE-2024-12111 | OpenText Privileged Access Manager | per vendor | per vendor | 8.0 | LDAP user authentication bypass via injection |
| CVE-2024-56841 | Siemens Mendix LDAP | < V1.1.2 | V1.1.2 | 7.4 | Module-level LDAP injection |
| CVE-2024-54852 | Teedy | 1.9 ≤ v ≤ 1.12 | per vendor | 9.8 | Login form username field — authn bypass |
| CVE-2025-27631 | TRMTracker | per vendor | per vendor | 6.5 | LDAP injection → command execution |
| CVE-2025-4573 | Mattermost | 10.7.x ≤ 10.7.1, 10.6.x ≤ 10.6.3, 10.5.x ≤ 10.5.4, 9.11.x ≤ 9.11.13 | per vendor | 4.1 | LDAP group ID attribute validation gap |
| CVE-2025-52575 | EspoCRM | ≤ 9.1.6 | per vendor | 6.5 | Blind LDAP injection via LDAP auth |
| CVE-2025-48208 | Apache HertzBeat | per vendor | per vendor | 8.8 | Authenticated LDAP query injection |
| CVE-2025-61911 | python-ldap | < 3.4.5 | 3.4.5 | 6.5 | `ldap.filter.escape_filter_chars` sanitization gap |
| CVE-2025-12764 | pgAdmin | ≤ 9.9 | per vendor | 7.5 | Login flow — LDAP injection |
| CVE-2026-21880 | Kanboard | ≤ 1.2.48 | per vendor | 5.3 | LDAP auth mechanism |
| CVE-2026-24130 | Moonraker | ≤ 0.9.3 | per vendor | 5.3 | LDAP component — injection |
| CVE-2026-1498 | WatchGuard Fireware OS | per vendor | per vendor | n/a | Fireware LDAP auth injection |
| CVE-2026-25560 | WeKan | < 8.19 | 8.19 | 9.8 | LDAP filter injection in authentication — authn bypass |
| CVE-2026-31828 | Parse Server | < 9.5.2-alpha.13 / < 8.6.26 | 9.5.2-alpha.13 / 8.6.26 | 8.8 | LDAP authentication adapter |
| CVE-2026-33289 | SuiteCRM | < 7.15.1 / < 8.9.3 | 7.15.1 / 8.9.3 | 8.8 | LDAP Injection |
| CVE-2026-33369 | Zimbra Collaboration | 10.0 / 10.1 | per vendor | 4.3 | Mailbox SOAP FolderAction LDAP injection |
| CVE-2026-34578 | OPNsense | ≤ 26.1.5 | 26.1.6 | 8.2 | OR-filter grouping bypass in LDAP authentication — Captive Portal / VPN takeover (WebGUI ACL still fails) |
| CVE-2026-39962 | MISP | < 2.5.36 | 2.5.36 | 9.6 | ApacheAuthenticate.php LDAP injection |
| CVE-2026-0636 | Bouncy Castle BC-JAVA bcprov | < 1.85 | 1.85 | 6.5 | prov modules — LDAP filter injection |
| CVE-2026-40193 | maddy (mail server) | < 0.9.3 | 0.9.3 | 8.2 | `auth.ldap` module — username concatenation |
| CVE-2026-40459 | PAC4J (LDAP module) | per vendor | per vendor | 8.8 | ID-based search parameters — LDAP Injection |
| CVE-2026-27851 | Templating lib (specific) | per vendor | per vendor | 7.4 | Safe filter + variable expansion incorrectly interprets pipelines as safe |
| CVE-2026-44671 | Zitadel | 2.71.11 ≤ v < 3.4.10 / < 4.15.0 | 3.4.10 / 4.15.0 | 7.4 | LDAP identity provider — injection |
| CVE-2026-41919 | Apache OFBiz | < 24.09.06 | 24.09.06 | 9.1 | LDAP Injection — unspecified reach |
| CVE-2026-44063 | Netatalk | 2.1.0–4.4.2 | per vendor | 4.2 | Authenticated LDAP query manipulation |
| CVE-2026-44930 | Apache CXF XKMS | per vendor | per vendor | 9.8 | LDAP Certificate repository filter injection — arbitrary cert retrieval |
| CVE-2026-46745 | Apache Airflow FAB Auth Manager | per vendor | per vendor | 5.3 | LDAP filter injection (CWE-90) — directory exfil / authn bypass |
| CVE-2026-48844 | Roundcube Webmail | 1.6.x < 1.6.16 / 1.7.x < 1.7.1 | 1.6.16 / 1.7.1 | 7.5 | LDAP autovalues insecure code evaluation — code injection |
| CVE-2026-10549 | Yandex Database (YDB) | < 25.3.1.25 | 25.3.1.25 | n/a | LDAP filter injection — group membership check bypass |
| CVE-2026-42568 | Yamcs | < 5.13.0 / < 5.12.7 | 5.13.0 / 5.12.7 | 4.3 | `LdapAuthModule` filter construction |
| CVE-2026-48114 | Metacat | ≥ 2.0.0 | per vendor | 9.8 | Unauthenticated SQL injection + LDAP injection stacked |
| CVE-2026-13696 | HAVELSAN Liman MYS | per vendor | per vendor | 8.8 | LDAP Injection |
| CVE-2026-4256 | PEAKUP PassGate | per vendor | per vendor | 8.2 | LDAP Injection |
| CVE-2026-44616 | Apache Zeppelin (ActiveDirectoryGroupRealm) | per vendor | per vendor | 6.5 | LDAP search filter construction without escaping |
| CVE-2026-44617 | Apache Zeppelin (LdapRealm) | per vendor | per vendor | 6.5 | RFC 4514 DN-escape used for RFC 4515 filter — ineffective escape |
| CVE-2026-58222 | Samba Active Directory DC | per vendor | per vendor | 8.8 | LDAP Compare filter injection + improper authorization |
| CVE-2026-59652 | Bouncy Castle for Java (jdk1.4 LDAPStoreHelper) | < 1.85 | 1.85 | 6.5 | legacy LDAPStoreHelper filter injection |
| CVE-2026-75007 | Roundcube Webmail | < 1.6.18 / 1.7.x < 1.7.3 | 1.6.18 / 1.7.3 | 5.4 | %u/%fu/%d substitution unescaped in LDAP filter |
| CVE-2026-19271 | TÜBİTAK BİLGEM Liderahenk | per vendor | per vendor | 7.5 | LDAP Injection |
| CVE-2026-75020 | Apache APISIX | per vendor | per vendor | 8.1 | Caller with valid credentials for one entry can access others via injection |
| CVE-2026-81205 | Drupal LDAP / Active Directory Integration | per vendor | per vendor | 5.3 | LDAP Injection |
| CVE-2026-80055 | Dell SCG 5.0 Appliance/Application | < 5.36.00.16 / < 5.36.00.00 | per vendor | 4.4 | LDAP Injection |
| CVE-2026-41573 | Open Access Management (OpenAM) | < 16.1.1 | 16.1.1 | n/a | IdentityResourceV1 queryCollection — _queryId parameter |
| CVE-2026-94053 | Apache MINA SSHD | 1.2.0 → 2.19.0 / 3.0.0-M1 → 3.0.0-M5 | per vendor | 9.1 | sshd-ldap authentication bypass via LDAP injection |

Notes on the table:
- **CVE-2026-34578 (OPNsense) is the archetype**, not the most-impactful: its CVSS 8.2 reflects the WebGUI-login scope limitation (session-username injection succeeds but subsequent ACL lookup fails, so full admin takeover is Captive-Portal/VPN only). Many other LDAP-bypass CVEs achieve higher CVSS by reaching endpoints without ACL re-check.
- **CVE-2024-33868 (linqi) and CVE-2024-54852 (Teedy)** reach CVSS 9.8 via unauthenticated-authn-bypass — login form LDAP concatenation with no subsequent ACL re-check.
- **CVE-2024-11320 (Pandora FMS) and CVE-2024-37782 (Gladinet CentreStack)** are "LDAP injection resulting in command execution" — the LDAP bypass reaches a context where attacker-controlled strings subsequently reach an OS shell. CVSS 9.8 reflects the chained impact.
- **CVE-2026-44930 (Apache CXF XKMS, CVSS 9.8)** is distinctive: LDAP injection in the LDAP Certificate repository filter grants arbitrary certificate retrieval from the key management server — a cross-tenant certificate-exfil primitive at the XKMS layer.
- **CVE-2026-39962 (MISP, CVSS 9.6)** affects the ApacheAuthenticate.php LDAP integration — threat-intel platform compromise.
- **CVE-2026-41919 (Apache OFBiz, CVSS 9.1)**, **CVE-2026-94053 (Apache MINA SSHD, CVSS 9.1)**, and **CVE-2026-44930** anchor the Apache-ecosystem LDAP-injection cluster; the mechanism in each is user input into search-filter construction.
- **CVE-2025-61911 (python-ldap)**, **CVE-2026-0636 (BouncyCastle bcprov)**, **CVE-2026-59652 (BouncyCastle jdk1.4 LDAPStoreHelper)**, and **CVE-2026-40459 (PAC4J)** are the library-level class. The exposure is architectural — any application using these libraries without the specific fix inherits the mechanism independent of input-reach.
- **CVE-2026-44617 (Apache Zeppelin LdapRealm)** has an instructive mechanism: the filter escape used RFC 4514 (DN-escape) instead of RFC 4515 (filter-escape). The two RFCs escape different character sets — DN-escape is for distinguished names, filter-escape is for filter assertion values. Using the wrong RFC's escape set is a common subtle bug.
- **CVE-2026-27851** is the "safe filter + variable expansion" bug class — a templating library's safe-escape is applied to variable expansion but subsequent pipeline operations re-interpret as safe, letting re-expansion inject. Not strictly LDAP but affects LDAP-filter composition in affected templates.
- **CVE-2026-10549 (Yandex Database)** confirms the OR-filter-grouping-bypass pattern reaches group-membership checks on open-source enterprise databases.

## CVE Primitive-Class Index

The 50+ LDAP CVEs cluster into four primitive classes. For scanning efficiency, pre-select the class before firing payloads:

| Primitive class | 2024-2026 anchor CVEs | Attack shape | Confirmation signal |
|---|---|---|---|
| **A. OR-filter grouping bypass of trailing AND condition** | CVE-2026-34578 (OPNsense), CVE-2026-25560 (WeKan), CVE-2024-54852 (Teedy), CVE-2026-39962 (MISP), CVE-2026-40193 (maddy), CVE-2024-11320 (Pandora FMS), CVE-2024-37782 (Gladinet), CVE-2024-33868 (linqi), CVE-2026-33289 (SuiteCRM), CVE-2026-94053 (Apache MINA SSHD), CVE-2026-41919 (Apache OFBiz), CVE-2026-75020 (Apache APISIX), CVE-2026-10549 (Yandex DB) | `targetuser)(|(uid=targetuser` into login username | Login succeeds without being in the required group |
| **B. LDAP-to-shell-command chain** | CVE-2024-11320 (Pandora FMS), CVE-2024-37782 (Gladinet CentreStack), CVE-2025-27631 (TRMTracker) | LDAP injection reaches a context where the matched attribute is used in a subsequent system call | OS command execution side effect |
| **C. Library-level architectural exposure** | CVE-2025-61911 (python-ldap), CVE-2026-0636 (BouncyCastle BC-JAVA bcprov), CVE-2026-59652 (BouncyCastle legacy), CVE-2026-40459 (PAC4J LDAP) | Library's own filter construction is injectable regardless of application-level escape | Dependency version matches pre-fix |
| **D. Cross-tenant certificate / data access** | CVE-2026-44930 (Apache CXF XKMS), CVE-2026-58222 (Samba AD DC Compare), CVE-2025-52575 (EspoCRM) | LDAP injection in a repository or compare operation reaches cross-tenant data | Attacker retrieves content from other tenants' entries |

## CVE-2026-34578 — OPNsense LDAP Authentication Connector (the Archetype)

Primitive: `searchUsers()` at `src/opnsense/mvc/app/library/OPNsense/Auth/LDAP.php` line 400 interpolates POST `usernamefld` into the filter string without `ldap_escape()`. The canonical OR-filter grouping bypass `targetuser)(|(uid=targetuser` transforms the template filter `(&(uid={u})(memberOf=cn=vpn-users,...))` into `(&(uid=targetuser)(|(uid=targetuser)(memberOf=...)))` — tautologically nullifying the memberOf AND-term when the attacker knows a valid user's password.

Preconditions:
1. OPNsense ≤ 26.1.5.
2. LDAP authentication connector enabled (not local-only auth).
3. Attacker has credentials for any valid user — this is **not** credential-less; the attacker's own password is validated against their own LDAP record. The injection bypasses the group-check gate for the targeted class of user.

Sink location per the vendor advisory (GHSA-jpm7-f59c-mp54): `src/opnsense/mvc/app/library/OPNsense/Auth/LDAP.php:400` — `$search = ldap_search($ldap, $base, "(&(uid=$usernamefld)(memberOf=cn=vpn-users,...))");`. Fix commit `016f66c` adds `ldap_escape($usernamefld)` before interpolation.

Full attack recipe (Captive Portal):
```http
POST /captiveportal_login.php HTTP/1.1
Host: opnsense.target.net:8443
Content-Type: application/x-www-form-urlencoded

usernamefld=lowpriv.user)(|(uid=lowpriv.user&passwordfld=lowpriv.user-password&redirurl=&zone=0&accept=Continue
```

Server-side filter composition:
```
# LDAP.php:400 — no ldap_escape() wrapper
$filter = "(&(uid={$_POST['usernamefld']})(memberOf=cn=vpn-users,...))";
# After injection:
$filter = "(&(uid=lowpriv.user)(|(uid=lowpriv.user)(memberOf=cn=vpn-users,...)))";
# LDAP server evaluates:
# - uid=lowpriv.user → true (attacker's own account)
# - |(uid=lowpriv.user)(memberOf=...)→ true (first disjunct true)
# - AND of true AND true → true → bind succeeds
```

Full attack recipe (VPN):
```http
POST /openvpn/login HTTP/1.1
Host: opnsense.target.net

username=lowpriv.user)(|(uid=lowpriv.user&password=lowpriv.user-password
```
Same filter composition; VPN tunnel establishes without the user being in `cn=vpn-users`.

**Confirmation signals (OPNsense CVE-2026-34578).**
1. **Login succeeds for a user not in the gated group.** Verify by querying their actual `memberOf` on the LDAP server directly.
2. **WebGUI login succeeds, but WebGUI admin pages return 403.** Confirms the scope limitation — session established, subsequent ACL check still filters.
3. **Captive Portal / VPN access confirmed via subsequent authenticated request.** The gate was LDAP-only, not re-checked.
4. **`src/opnsense/mvc/app/library/OPNsense/Auth/LDAP.php:400`** — code review confirmation of the filter concatenation. Fix commit `016f66c` adds `ldap_escape()`.

**Impact.** Captive Portal / VPN takeover for any valid user, regardless of their actual group membership. The WebGUI scope limitation — session-username injection succeeds but subsequent WebGUI ACL lookup still consults LDAP for the user's actual permissions — means WebGUI admin takeover is **not** achievable via this CVE alone. CVSS 8.2 reflects this scope. Zen findings on OPNsense LDAP must note: Captive Portal and VPN only, not WebGUI admin.

**Chain downstream.** VPN tunnel → internal network pivot. Route to `rce.md` for post-pivot RCE on internal services.

## CVE-2024-39565 — Juniper Junos OS J-Web

Primitive: LDAP-related session-cookie XPath injection — technically scoped as XPath but worth cross-referencing. See `xpath_injection_novel_deep.md § CVE-2024-39565` for the mechanism. Where the Juniper device uses LDAP for session management, the primitive crosses into this file's territory; the canonical write-up stays with XPath.

## WeKan CVE-2026-25560 — LDAP Filter Injection in Authentication

Primitive: user-supplied username input is incorporated into LDAP search filters without proper escape in WeKan's authentication flow. CVSS 9.8 reflects unauthenticated-authn-bypass. Fixed in WeKan 8.19.

Attack recipe (class-shape, OR-filter grouping bypass):
```
username: admin)(|(uid=admin
```
Filter composed: `(&(uid=admin)(|(uid=admin)(trailing-cond)))` → bypass to admin.

## Teedy CVE-2024-54852 — Login Username Field

Primitive: Teedy 1.9–1.12 username field is vulnerable to LDAP injection due to improper sanitization. CVSS 9.8 — unauthenticated authn bypass.

Attack recipe: standard OR-filter grouping bypass against the login endpoint.

## Universal OR-Filter Grouping Bypass Probe

Across the OR-filter-grouping class the probe is uniform. Fire a single payload against every detected LDAP auth endpoint:

```http
# For each endpoint, use a known-valid username + password
POST /any-ldap-login HTTP/1.1

username=KNOWN.VALID.USER)(|(uid=KNOWN.VALID.USER&password=KNOWN.VALID.USER.PASSWORD

# Alternate payloads for different filter templates:
# username=KNOWN)(objectClass=*     (if trailing is objectClass-shaped)
# username=KNOWN)(|(cn=KNOWN       (if filter uses cn instead of uid)
# username=KNOWN)(|(sAMAccountName=KNOWN  (AD)
# username=KNOWN)(|(mail=KNOWN     (if filter uses mail)
```

**Confirmation shortcut.** Compare the pre-attack `memberOf` of the KNOWN user (via a legitimate LDAP query if available, or directory enumeration via wildcard) with the resources the attacker-session reaches post-attack. If the attacker reaches resources that `memberOf` does NOT grant, the OR-bypass worked.

**Positive-list targets by anchor-CVE pattern:**
- OpenVPN / VPN login → OPNsense (CVE-2026-34578), pfSense, FortiGate custom LDAP, OpenConnect-ocserv
- Captive Portal → OPNsense, pfSense, Mikrotik HotSpot
- Mail server LDAP auth → maddy (CVE-2026-40193), Postfix+Dovecot LDAP, mailman LDAP
- Collaboration platforms → MISP (CVE-2026-39962), Mattermost (CVE-2025-4573), Teedy (CVE-2024-54852), WeKan (CVE-2026-25560), SuiteCRM (CVE-2026-33289), EspoCRM (CVE-2025-52575)
- Apache ecosystem → OFBiz (CVE-2026-41919), APISIX (CVE-2026-75020), MINA SSHD (CVE-2026-94053), Zeppelin (CVE-2026-44616/44617), Airflow (CVE-2026-46745), Camel
- Admin UIs → OPNsense WebGUI (bypasses captive-portal/VPN only), pgAdmin (CVE-2025-12764)
- VPN enterprise → Gladinet CentreStack (CVE-2024-37782), Pandora FMS (CVE-2024-11320), SecurEnvoy MFA (CVE-2024-37393)
- Identity management → Zitadel (CVE-2026-44671), OpenAM (CVE-2026-41573), OpenText PAM (CVE-2024-12111)
- CRM / Finance → Zimbra (CVE-2026-33369), Mendix (CVE-2024-56841), Netatalk (CVE-2026-44063)

## Apache CXF XKMS CVE-2026-44930 — Certificate Repository Filter Injection

Primitive: LDAP injection in the LDAP Certificate repository of the XKMS server allows an attacker to retrieve arbitrary certificates from the repository.

Preconditions:
1. Apache CXF XKMS server running (specific vendor advisory for version boundary).
2. Attacker reaches the XKMS query endpoint.
3. The repository backend is LDAP-backed.

Attack recipe (class-shape):
```
# Craft XKMS LocateRequest with injected search parameter
# Server composes LDAP filter from the search parameter without escape
<xkms:LocateRequest>
  <xkms:QueryKeyBinding>
    <xkms:KeyUsage>Signature</xkms:KeyUsage>
    <!-- Injection into attribute matching -->
    <xkms:UseKeyWith Application="any-value)(cn=*" />
  </xkms:QueryKeyBinding>
</xkms:LocateRequest>
```
The composed filter matches any certificate in the repository, not just those matching the application scope.

Impact: full extraction of certificates stored in the key management repository — including private keys where XKMS stores them, or at minimum public key material for cross-tenant certificates. CVSS 9.8 reflects the sensitivity.

## Apache MINA SSHD CVE-2026-94053 — sshd-ldap Authentication Bypass

Primitive: LDAP injection in Apache MINA SSHD's sshd-ldap component. CVSS 9.1 — reaches SSH authentication layer.

Preconditions:
1. Apache MINA SSHD versions 1.2.0 → 2.19.0 or 3.0.0-M1 → 3.0.0-M5.
2. sshd-ldap authentication module enabled.
3. Attacker reaches SSH port.

Attack recipe (class-shape):
```
# SSH login with crafted username
ssh 'valid.user)(|(uid=valid.user'@target
# Server LDAP filter: (&(uid=valid.user)(|(uid=valid.user)(memberOf=...)))
# Bypasses group-gate; SSH authenticates
```

Impact: SSH access as any user without being in the required SSH-login group. If sshd-ldap is the primary auth mechanism, this is server shell access.

## MISP CVE-2026-39962 — ApacheAuthenticate.php LDAP Injection

Primitive: MISP's ApacheAuthenticate.php composes LDAP filter from Apache-provided user identity without escape. CVSS 9.6 — threat-intel platform access.

Preconditions:
1. MISP < 2.5.36.
2. Apache mod_ldap or Apache authentication reaching MISP's LDAP integration.
3. Attacker can set Apache-provided identity headers (either via an upstream auth bypass or direct access to the Apache authentication path).

Attack recipe: standard OR-filter grouping bypass via the Apache-provided user identifier.

Impact: cross-user access on MISP — threat-intel data, intelligence pivots, red-team OPSEC compromise. Threat-intel platforms are high-value targets for operational security — the bypass is "see all shared intel without being authorized."

## Library-Level Class

### python-ldap CVE-2025-61911

Primitive: `ldap.filter.escape_filter_chars` had a sanitization gap in versions < 3.4.5 — specific metacharacter sequences bypassed the escape. The fix added additional metacharacter coverage.

Preconditions:
- Any application using python-ldap < 3.4.5 that calls `escape_filter_chars` and considers the result "safe" for filter composition.

Attack recipe: specific input shapes (per the fix patch) that `escape_filter_chars` fails to escape. Downstream applications relying on the function reach filter injection.

Scope: library-level. Zen findings grep targets for `python-ldap` or `ldap.filter.escape_filter_chars` in dependencies; versions < 3.4.5 are exposed.

### BouncyCastle BC-JAVA CVE-2026-0636 and CVE-2026-59652

Primitive: BouncyCastle's cert-store LDAP backend builds filters from certificate issuer/subject fields without escape. CVE-2026-0636 is the modern `prov` module; CVE-2026-59652 is the legacy `jdk1.4 LDAPStoreHelper`.

Preconditions:
- Java application using `org.bouncycastle.jce.provider.X509LDAPCertStoreSpi` or `LDAPStoreHelper` from `prov` modules < 1.85.
- Application looks up certificates by issuer/subject strings supplied externally (certificate validation path with user-controlled cert input).

Attack recipe: craft a certificate with an issuer/subject DN containing LDAP metacharacters that inject into the filter during store lookup.

Impact: filter injection reaches arbitrary certificate retrieval from the store — potentially cross-tenant certificate access or auth bypass if the application uses store lookup for identity confirmation.

### PAC4J CVE-2026-40459

Primitive: PAC4J LDAP module's ID-based search parameters construct LDAP filters without consistent escape. CVSS 8.8.

Preconditions:
- Any application using PAC4J LDAP authentication (pre-fix version).
- Attacker provides a crafted ID-based parameter (e.g., username in a login flow).

Attack recipe: standard OR-filter grouping bypass via the ID parameter.

Impact: authentication bypass or cross-user access depending on the PAC4J integration shape.

## Apache Ecosystem Cluster

### Apache OFBiz CVE-2026-41919

Primitive: LDAP injection in OFBiz < 24.09.06. CVSS 9.1 — broad reach into the ERP application.

### Apache APISIX CVE-2026-75020

Primitive: a caller with valid credentials for one entry can access others via LDAP injection. CVSS 8.1 — cross-tenant access on the gateway.

### Apache Zeppelin CVE-2026-44616 and CVE-2026-44617

Two mechanisms worth noting:
- **CVE-2026-44616** — `ActiveDirectoryGroupRealm` constructs LDAP search filters without escaping user-controlled input.
- **CVE-2026-44617** — `LdapRealm` used RFC 4514 (DN-escape) instead of RFC 4515 (filter-escape) when composing filters. The two RFCs escape different character sets; using the wrong one is a subtle bug — e.g., RFC 4514 does not escape `*`, so wildcards leak through.

### Apache Airflow FAB Auth Manager CVE-2026-46745

Primitive: LDAP filter injection in Airflow's FAB (Flask-AppBuilder) auth manager. CVSS 5.3 — directory data exfil or authn bypass.

### Apache CXF XKMS CVE-2026-44930

See above — the standout at CVSS 9.8 for arbitrary certificate retrieval.

### Apache MINA SSHD CVE-2026-94053

See above — SSH bypass at CVSS 9.1.

### Samba Active Directory DC CVE-2026-58222

Primitive: LDAP Compare filter injection combined with improper authorization. Samba AD DC processes LDAP Compare operations without proper filter sanitization, letting an attacker-crafted filter bypass authorization checks.

Preconditions:
- Samba AD DC deployment (specific version per advisory).
- Attacker reaches the LDAP service port (389/636 or TLS).

Impact: cross-user attribute access on an AD DC — equivalent to arbitrary attribute read across the domain. CVSS 8.8.

## Composite Chains at the Frontier

### OPNsense OR-Bypass → VPN → Internal Network
1. **Primitive:** CVE-2026-34578 OR-filter grouping bypass.
2. **Reach:** attacker holds credentials for any valid user; auth bypasses VPN group gate.
3. **Trigger:** VPN tunnel established.
4. **Impact:** internal network pivot — route to `rce.md` for post-pivot exploitation of internal services.
Route: this file → `rce.md` (post-pivot) or `cloud/*` (if internal services are cloud-identity-reaching).

### Apache MINA SSHD → Server Shell
1. **Primitive:** CVE-2026-94053 OR-filter bypass on sshd-ldap.
2. **Reach:** SSH authenticates attacker.
3. **Impact:** shell on target host.
Route: this file → `rce.md` for post-exec framing.

### MISP → Threat-Intel Exfil
1. **Primitive:** CVE-2026-39962 ApacheAuthenticate LDAP injection.
2. **Reach:** cross-user access to threat-intel platform.
3. **Impact:** intelligence pivots, red-team OPSEC compromise.
Route: this file → `information_disclosure.md` for data exfil framing.

### Apache CXF XKMS → Certificate Exfil → Cross-Tenant Signing
1. **Primitive:** CVE-2026-44930 LDAP filter injection in cert repository.
2. **Reach:** arbitrary certificate retrieval.
3. **Impact:** cross-tenant private key compromise (where XKMS stores private keys) → signing operations as other tenants.
Route: this file → cryptographic-identity-compromise framing.

### Library-Level Chain
1. **Precondition:** application uses python-ldap < 3.4.5 or BouncyCastle < 1.85 or PAC4J pre-fix.
2. **Reach:** library's own filter construction is injectable regardless of application-level escape.
3. **Trigger:** standard OR-bypass or filter injection.
4. **Impact:** depends on where the library is used — auth, cert lookup, group membership.
Route: this file → application-specific downstream.

### Second-Order via Mattermost LDAP Group Attribute
1. **Primitive:** CVE-2025-4573 — LDAP group ID attributes not validated.
2. **Reach:** attacker modifies a user's stored LDAP group reference.
3. **Trigger:** subsequent authorization check reads the attacker-modified attribute.
4. **Impact:** privilege elevation via stored attribute. Not strictly injection — attribute poisoning.
Route: this file → `broken_function_level_authorization.md` for the authorization implication.

## Frontier Detection Methodology

1. **Pattern-first.** The OR-filter grouping bypass is universal across the catalog. For every LDAP auth path, probe `targetuser)(|(uid=targetuser` first.
2. **Library grep second.** Dependencies listing python-ldap < 3.4.5, BouncyCastle < 1.85, PAC4J pre-fix — library-level findings that don't require input-reach confirmation.
3. **Apache cluster probe.** OFBiz, APISIX, Zeppelin, Airflow, CXF, MINA SSHD, Camel — each has recent LDAP CVEs. Zen scans against Apache-ecosystem targets should probe LDAP auth paths specifically.
4. **AD-specific primitives.** Where the directory is AD, `anr=admin*` enumeration and extensible-match OIDs for `userAccountControl` bitmask filters reveal privilege boundaries.
5. **DN-injection separate.** Not caught by filter-escape mitigations. Grep for `ldap_add`-shape operations and user-input in DN construction.
6. **RFC-escape audit.** CVE-2026-44617's "wrong-RFC escape" bug is subtle; grep targets for escape wrappers and check which character set they handle.

## Frontier Validation

- **For OR-bypass claims, confirm the attacker's session is the bypassed user's AND the gate was the group-membership check.** A login success could be due to a different mechanism (anonymous bind fallback, direct bind without group check). Verify by targeting a user whose group membership differs from what the application should grant them.
- **For library-level claims, confirm the library version AND the specific function path.** python-ldap 3.4.5+ is fixed; python-ldap 3.4.4 using `filter_format` (parameterized builder) is also safe — the exposure is `escape_filter_chars` + concatenation specifically.
- **For OPNsense CVE-2026-34578, scope the write-up to Captive Portal/VPN.** WebGUI admin takeover is not achievable via this CVE alone; a write-up claiming full admin is incorrect.
- **For Apache CXF XKMS, confirm the backend is LDAP-backed.** The vulnerability requires the LDAP cert-repository backend; XKMS deployments using other backends (JKS keystore, HSM) are not reachable.
- **For MISP CVE-2026-39962, confirm the Apache authentication integration path.** Non-Apache-mediated MISP deployments (direct auth) use a different code path.

## Pro Tips at the Frontier

- **OR-filter grouping bypass is the single most-exploited LDAP primitive in 2024–2026.** 20+ CVEs across the catalog exhibit variants. Any LDAP auth path probed with `targetuser)(|(uid=targetuser` is a high-signal probe.
- **"Wrong RFC's escape" is a sneaky bug class.** RFC 4514 (DN-escape) does NOT escape `*`; RFC 4515 (filter-escape) does. Applications that use `ldapDnEscape` or similar for filter composition miss wildcards. CVE-2026-44617 (Zeppelin) is the canonical case.
- **Library-level findings don't require input-reach confirmation.** python-ldap < 3.4.5, BouncyCastle < 1.85, PAC4J pre-fix — these are architectural exposures. Report the library finding and note the input-path audit as a follow-up.
- **MFA front-ends sometimes compose LDAP filters without re-escape.** CVE-2024-37393 (SecurEnvoy MFA) is the archetype — the MFA factor itself does not protect against the primary auth bypass.
- **AD Compare operations have distinct injection surface.** CVE-2026-58222 (Samba AD DC) exploits the LDAP Compare op; Compare is less-often-reviewed than Search but equally injectable.
- **PAM-LDAP bridges mean LDAP CVE = shell.** CVE-2026-94053 (Apache MINA SSHD) is the direct case; many other LDAP CVEs reach shell on hosts with PAM-LDAP SSH.
- **Second-order via group-ID attributes is subtle.** CVE-2025-4573 (Mattermost) — the attack stores a crafted group ID; the authorization check reads it later. Grep for stored LDAP attributes used in later authz decisions.

The LDAP 2024–2026 frontier is uniform-primitive dense — 50+ CVEs across four class columns (OR-filter grouping bypass dominant, LDAP-to-shell-command chain, library-level architectural exposure, cross-tenant certificate/data access), with the OR-bypass archetype repeating across 20+ CVE instances; the under-band line count is a finding (one dominant primitive class with many instances rather than many distinct primitive classes), not a stop-short.

## Summary

The LDAP 2024–2026 frontier is a dense, verifiable surface — 50+ primary-source CVEs clustering into the OR-filter grouping bypass archetype (OPNsense, WeKan, Teedy, maddy, Pandora FMS, Gladinet, MISP, SuiteCRM, Zimbra, Metacat, Apache CXF/OFBiz/APISIX/MINA SSHD/Zeppelin/Airflow, Zitadel), library-level exposure (python-ldap, BouncyCastle BC-JAVA, PAC4J), AD-specific attack surface (Samba AD DC Compare), and specialized integrations (sshd-ldap SSH bypass, Apache CXF XKMS cert-exfil, MISP Apache integration). CVSS peaks at 9.8 (WeKan, Teedy, Gladinet, Pandora FMS, maddy, Apache CXF XKMS, Metacat), with the OPNsense archetype at 8.2 reflecting its WebGUI-ACL scope limitation. The uniform pattern — filter template `(&(uid=$u)(trailing))` with user input into `$u` — makes a single probe (`targetuser)(|(uid=targetuser`) effective across most of the catalog. Base and advanced siblings reference these CVEs by number only; the versioned mechanism catalog lives here.
