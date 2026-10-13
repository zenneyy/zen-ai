---
name: ldap-injection
description: LDAP injection testing — filter and distinguished-name injection, authentication bypass via OR-filter grouping, blind extraction, wildcard enumeration, and per-directory parsing differentials (OpenLDAP / Active Directory / 389 / FreeIPA)
---

# LDAP Injection

LDAP injection is the class where attacker-controlled text reaches an LDAP filter or distinguished-name construction and alters the query's logical shape. The primitive is **string → LDAP filter parser → attacker-chosen match set**: an unescaped `)` or `*` or `|` breaks out of a filter clause and lets the attacker rewrite boolean grouping, truthify authentication, enumerate directory attributes, or bypass group-membership checks. The question is never "is LDAP consulted?" — it is "does unescaped input reach the filter string, and what does the directory expose by attribute to a matched query?"

## Attack Surface

**Authentication Backends**
- Any LDAP-authenticated login form (web, VPN, Captive Portal, SSH-via-PAM-LDAP, FTP, mail server, Zabbix/Nagios/Grafana LDAP flows)
- SSO integrations that construct filter strings from username — classical pattern: `(uid=$username)` or `(&(uid=$username)(memberOf=cn=app-users,...))`
- Multi-factor authentication paths with secondary LDAP lookup

**User and Group Lookup APIs**
- Admin "find user" / "find group" endpoints
- API search features (SCIM, Graph-shaped user search)
- Export/report generation that queries LDAP for user attributes
- Directory synchronization jobs that pull user state via filter

**Attribute-Based Access Control**
- Filter construction from user-attribute values ("find all users in my department")
- Dynamic group-membership resolution with filter-derived groups
- Legacy LDAP-DNS integration (DNS zone lookups via LDAP filters)

**Input Vectors**
- Login username fields (direct)
- Form fields in search endpoints
- JSON/REST body fields passed to filter construction
- Headers in federated-auth flows (X-Forwarded-For-shaped identity headers)
- Second-order: usernames stored in profile, later used in filter construction for authorization

## Filter Syntax Primer

LDAP filters (RFC 4515) are prefix-notation boolean expressions over attribute matches:
- `(attr=value)` — equality
- `(&(a=1)(b=2))` — AND of two conditions
- `(|(a=1)(b=2))` — OR
- `(!(a=1))` — NOT
- `(a=prefix*)` — presence of attribute `a` beginning with `prefix` (wildcard)
- `(a=*)` — presence (attribute exists)
- `(a>=10)` — greater-than-or-equal (lexical for strings, numeric where mapped)
- `(a~=sounds-like)` — approximate match (phonetic matcher per schema)

The filter string is parsed into a tree, matched against the directory, and the result-set is a set of entries. "Login succeeds" typically means "the filter matched exactly one entry whose password hash validates" or "the filter matched any entry we can bind to."

## Core Primitive — Filter Injection

Classic LDAP auth check:
```
(&(uid=$username)(password=$password))
```
With `$username = admin)(&(uid=*`:
```
(&(uid=admin)(&(uid=*))(password=$password))
```
The attacker closed the outer `(&(uid=$username)` early, began a new `&` clause, and the trailing `)(password=$password))` becomes malformed syntax — many LDAP libraries treat malformed trailing filter as the filter ending. The result: filter effectively `(&(uid=admin))` — matches admin independent of password.

A cleaner variant uses the **OR-filter grouping bypass** — the canonical pattern in CVE-2026-34578 (OPNsense) and many library-level CVEs:

```
# Vulnerable filter template:
(&(uid=$username)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com))

# Attacker username: targetuser)(|(uid=targetuser
# Rendered filter:
(&(uid=targetuser)(|(uid=targetuser)(memberOf=cn=vpn-users,ou=groups,dc=example,dc=com)))
```

The attacker opens an `OR` group `(|(uid=targetuser)...)` after the first `uid=` match. The `OR` branch is `(uid=targetuser) OR (memberOf=cn=vpn-users)` — because the `uid=targetuser` branch is tautologically true (that is the user they are logging in as), the whole `OR` is true regardless of `memberOf`. The `AND` outer gate collapses to "the uid matches AND true" — login succeeds without the user being in the required group.

**Payload family**:
| Payload shape | Effect |
|---|---|
| `targetuser)(|(uid=targetuser` | OR-filter bypass of trailing AND-conditions |
| `*)(uid=*))(|(uid=*` | tautology — match any entry, close trailing filter |
| `admin)(cn=*` | truthify with wildcard presence |
| `admin*` | wildcard enumeration (prefix match) |
| `)(&(uid=admin)` | close outer AND, open new AND restricting to admin |
| `)(|(cn=*)(cn=*` | OR with wildcard — expand result set |

## OR-Filter Grouping Bypass — The 2024–2026 Archetype

The pattern `targetuser)(|(uid=targetuser` is the single most-exploited LDAP-injection class in the 2024–2026 CVE surface. OPNsense CVE-2026-34578, Teedy CVE-2024-54852, WeKan CVE-2026-25560, maddy CVE-2026-40193, Pandora FMS CVE-2024-11320, Gladinet CentreStack CVE-2024-37782, Apache MINA SSHD CVE-2026-94053 all exhibit variants of this primitive — the fix in each case is `ldap_escape()` of the username before filter construction, not architectural change. The novel sibling catalogs the specific CVEs; this file owns the pattern class.

The pattern's elegance: it works wherever the filter template is `(&(uid=X)(someOtherCondition))` and the attacker can inject into X. The OR-condition between the uid match (which they control) and the trailing condition (which they do not) is logically true, so the attacker bypasses the trailing condition without needing to know its content.

## Distinguished-Name (DN) Injection

Distinct from filter injection — DN injection targets `ldap_add`, `ldap_modify`, or `ldap_delete` operations where the attacker controls part of the entry's DN.

### Primitive — DN component injection

Pattern: an application constructs `uid=$username,ou=users,dc=example,dc=com` from a username, then performs `ldap_add` to create the user:
```
# Attacker username: evil,ou=admins
# Resulting DN:
uid=evil,ou=admins,ou=users,dc=example,dc=com
```
If the LDAP server does not reject the two-level `ou=` suffix as semantically invalid, the entry is created under `ou=admins` instead of `ou=users` — the attacker has placed themselves in the admin OU.

DN injection is less common than filter injection because DN construction typically uses `ldap_dn_escape` or structured builders; where it exists, the finding is often privilege escalation at provisioning time.

## Blind Extraction

When the filter is evaluated but the result is a yes/no (login succeeded or failed, user exists or does not), extraction is boolean-based.

### Boolean extraction via character enumeration

Primitive: craft a filter that is true if a target character matches a guess.
```
# Vulnerable login filter: (&(uid=$username)(password=$password))
# Blind extraction of admin's password hash via a sibling attribute:

# username: admin)(userPassword=a*
# Rendered: (&(uid=admin)(userPassword=a*)(password=$password))
# Succeeds if admin's userPassword begins with 'a'
```
Enumerate character by character: `a*`, `b*`, …, `z*`. Each guess is a login attempt; the successful one reveals the first character. Then `aa*`, `ab*`, …. Linear in alphabet size × password length.

### Attribute enumeration via wildcard

```
# username: *)(objectClass=*
# Rendered: (&(uid=*)(objectClass=*))
# Returns every entry in the directory
```
Where the result is reflected (not just a boolean), this is a direct dump of every entry. On an admin-search endpoint, it's a full directory enumeration.

### Length discovery

```
# Payloads for length:
admin)(userPassword=??????????)        # ten '?' chars match any ten-char value with substring filter in some schemas
admin)(userPassword=*)(|(1=1              # presence + wildcard
```
LDAP filters do not have a `string-length` primitive directly; schema-level matching rules (`caseIgnoreMatch`, `exactMatch`) determine what counts.

## Per-Directory Differentials

Each LDAP server has distinct behaviors around escaping, matching rules, and binding failures:

| Directory | Filter escape required by RFC 4515 | Common attributes | Match-rule defaults | Default on invalid filter |
|---|---|---|---|---|
| OpenLDAP | `( ) \ * NUL` | uid, mail, cn, sn, givenName | caseIgnoreMatch | Returns LDAP_FILTER_ERROR; server rejects |
| Active Directory | same + `/` | sAMAccountName, userPrincipalName, mail, cn | caseIgnoreMatch | Returns operational error; sometimes recovers partial match |
| 389 Directory Server | RFC 4515 standard | uid, mail, cn | caseIgnoreMatch | Returns LDAP_FILTER_ERROR |
| FreeIPA | RFC 4515 + IPA extensions | uid, mail, cn, krbPrincipalName | caseIgnoreMatch | Same as 389 (built on 389) |
| OpenDJ | RFC 4515 | uid, cn, mail | caseIgnoreMatch | Returns LDAP_FILTER_ERROR |

**AD-specific pitfalls**:
- AD supports `objectCategory` filters alongside `objectClass`; attackers can target either.
- AD's "ambiguous name resolution" (`anr=`) is a special attribute that matches against multiple attribute types (sAMAccountName, cn, mail, etc.) in one query. `anr=admin*` is a wildcard enumeration primitive that works on AD and not on standard LDAP.
- AD's `userAccountControl` attribute encodes account state (disabled, locked, password-never-expires) as a bitmask; filter `(userAccountControl:1.2.840.113556.1.4.803:=2)` matches disabled accounts — AD-specific OID-based matching rule.

**OpenLDAP-specific**:
- Supports extensible match filters (`:caseExactMatch:=`, `:ordering:=`) that AD does not.

## Confirmation Primitive Ladder

| Rung | Primitive | Observed signal | What it proves |
|---|---|---|---|
| 0 | `admin*)` into login | Filter error OR result-set balloon | Filter interpolation confirmed |
| 1 | `targetuser)(|(uid=targetuser` into group-gated login | login succeeds for user not in required group | OR-filter grouping bypass works; mechanism is CVE-2026-34578 class |
| 2 | `*)(objectClass=*` into search endpoint | result set includes all directory entries | Wildcard enumeration primitive; directory dump reachable |
| 3 | `(anr=admin*)` on AD search | returns entries matched across multiple attributes | AD confirmed (ANR is AD-specific); attribute-agnostic enumeration |
| 4 | `)(userPassword=a*` incrementally per character | per-prefix match reveals bytes | Blind extraction via substring filter |
| 5 | `java.lang.Runtime.getRuntime().exec('id')` (jxpath only — rare on LDAP but shared with XPath class) | exec output | Direct RCE where filter string reaches jxpath |
| 6 | DN-injection: `username = evil,ou=admins` | provisioned entry under ou=admins | Provisioning-time privilege placement |

## Detection Channels

### Reflected

A search endpoint that returns matched entries — `(uid=admin*)` returning the admin's record visibly — is the fastest confirmation. Inject `*)(uid=*))(|(uid=*` and observe whether the result set balloons.

### Boolean

A login endpoint, a `userExists` endpoint, a password-reset-email endpoint ("user exists" vs "user does not exist") — any yes/no channel is sufficient for blind extraction.

### Error-Message

LDAP server errors often print the parsed filter. A `500` response containing `"LDAP_FILTER_ERROR: inappropriate matching"` or `"ParseError"` confirms the sink is LDAP-shaped.

Error-shape distinguishes directories:
- OpenLDAP: `ldap_search_ext: Bad search filter (-7)`
- AD: `LDAP: error code 1 - 00000057: LdapErr: DSID-...` (specific DSID suggests AD)
- 389: `ldap_search_ext: Bad search filter (-7)` (same as OpenLDAP in message, different in context)

### Time-Based

LDAP searches with wildcards against large directories take measurable time. A payload like `*)(cn=*)(cn=*)(cn=*)` with repeated wildcards forces the directory to iterate — observable as request latency differences, usually in the 100ms–several-seconds range for sub-directories of thousands of entries. Noisy; use OAST if available.

## Testing Methodology

1. **Identify the sink.** Grep for `ldap_search`, `ldap.search`, `LDAPConnection`, `ldap3.Connection.search`, `javax.naming.directory.*`, `UnboundID`, `python-ldap` imports. Trace user input into filter string construction — any string concatenation reaching the filter is a candidate.
2. **Payload the predicate break.** `)` → observe for error. `)(cn=*` → observe for truthification (login succeeds, filter returns dramatically more results). The OR-filter bypass `targetuser)(|(uid=targetuser` is the archetype for authn-bypass sinks.
3. **Fingerprint the directory.** Error messages, response time behavior, and attribute availability (`sAMAccountName` exists → AD; `uid` is primary → OpenLDAP) tell you which directory. The directory determines which attributes exist and which schema-specific matching rules are available.
4. **For auth-bypass sinks, confirm with a non-destructive OR-bypass.** Use a username you know exists; craft the OR to bypass trailing conditions; observe whether the auth succeeds for that user without needing the trailing-condition credential.
5. **For search sinks, enumerate.** `*)(objectClass=*` returns every entry — observe for result-set balloon. Then narrow with specific attribute predicates to extract targeted data.
6. **For blind sinks, build a character-at-a-time oracle.** The attribute to extract may not be the password directly — often extract `userPassword` (hashed) or a secondary attribute like `homeDirectory` or `mail` that is sensitive-adjacent.

## Validation

A finding is LDAP injection only if:
- **The result-set change is LDAP-shaped.** Filter-based result expansion that correlates with the filter structure. Confirm by varying the predicate — `*)(cn=admin*` vs `*)(cn=user*` should produce different result sets if the sink is LDAP.
- **The directory responds, not just the application.** An LDAP library error (parsed-filter error) is confirmation of a filter reaching the directory. A generic HTTP 500 with no library-level error is ambiguous.
- **For auth-bypass, the bypassed authentication is confirmed with a different user's identity.** The attacker's session attributes must be those of the bypassed user, not a generic "logged in" state.
- **For extraction, the enumerated bytes match a known reference.** If the attack extracts admin's `mail` attribute and the known-good value is `admin@target.local`, the extraction must produce `admin@target.local`. Random reflections are not extraction.

## False Positives

- **A 500 response that contains the input literally.** Reflection, not evaluation. Confirm by varying the payload.
- **An authentication path that succeeds for `admin*)` because the application escapes `*` to `\*2A` but still logs in due to a different mechanism.** The `*` was literalized in the filter but the login succeeded for a different reason (fallback auth, session hijack from an unrelated vuln). Re-check without the LDAP-shape payload.
- **A SQL-shape error on an LDAP-shape payload.** The sink is SQL — route to `sql_injection.md`.
- **A result-set change that only correlates with the HTTP method, not the payload content.** Caching, session drift. Confirm with rapid re-firing.
- **A directory that is read-only and returns the same results regardless of filter.** Some directory proxies cache aggressively; a filter change should produce a result change in a non-cached deployment.
- **A `(uid=admin*)` payload that returns the admin record because `admin*` is a legitimate wildcard search feature.** Confirm by testing a payload that is only successful via injection — the OR-filter bypass `targetuser)(|(uid=targetuser` only succeeds if the filter is attacker-rewritten; a legitimate wildcard search does not accept such input.

## Impact and Chaining

**Direct impact.**
- **Authentication bypass** — login as any user whose username is known (classical) or as any user who shares the first-character prefix (wildcard variant).
- **Group-membership bypass** — attacker's auth succeeds without being in the required group (OPNsense CVE-2026-34578 archetype). Reach captive-portal, VPN, admin, or any other group-gated resource.
- **Directory enumeration** — wildcard `*)(objectClass=*` returns every entry; attacker extracts the user list, group list, attribute inventory.
- **Attribute extraction** — blind extraction reveals specific attributes (hashed passwords, home directories, mail addresses, SSH keys stored in LDAP).
- **DN injection** — new entries placed in attacker-chosen OUs (privilege escalation at provisioning time).
- **Second-order LDAP injection** — stored input triggers filter injection on a later request.

**Scope caveats.**
- Many LDAP-authentication bypasses allow session establishment but fail downstream ACL checks. OPNsense CVE-2026-34578 is scoped to Captive Portal/VPN takeover because WebGUI ACL still fails after the bypass; the attacker establishes a session but cannot reach WebGUI admin functions. Zen findings should scope the specific endpoints the bypass actually reaches.

**Upstream enablers.**
- An application composing LDAP filter strings via concatenation. Grep targets for `filter = "(uid=" + username + ")"`-shape expressions.
- Framework-level LDAP integrations with no mandatory `ldap_escape` wrapper. Spring Security's `LdapAuthenticationProvider` with a `userDnPatterns` using `{0}` placeholder has historically been safe; applications that bypass it with custom filters re-expose.

**Downstream.**
- `authentication_jwt.md` — the authenticated session the LDAP bypass yields may issue a JWT; the token's claims reflect the bypassed user's identity.
- `broken_function_level_authorization.md` — if the bypass places the attacker as a privileged user, BFLA on privileged endpoints is immediate.
- `information_disclosure.md` — directory enumeration leaks structured data.
- `privilege_escalation` — DN-injection-placed entries in admin OUs provision admin accounts.

**Composite chains.**
- *LDAP auth-bypass → captive portal takeover.* OPNsense CVE-2026-34578 archetype: login bypass → captive-portal admin → network pivot.
- *LDAP OR-bypass → VPN access.* Teedy / Pandora / Gladinet class: login succeeds without VPN group membership → full VPN tunnel to internal network.
- *Directory enumeration → spearphishing targeting.* Every user's mail attribute extracted → targeted phishing.
- *DN injection → admin provisioning.* Attacker-created user placed in admin OU during registration → admin login via that account.

## Pro Tips

- **The OR-filter bypass is universally applicable to `(&(uid=$u)(trailing))`.** If a Zen finding against an LDAP auth path confirms predicate-break, the OR-bypass pattern will almost certainly succeed — try it before more complex payloads.
- **`anr=` on AD is a wildcard enumeration primitive.** It matches against multiple attribute types in one query; a single `anr=admin*` enumerates matches across sAMAccountName, cn, mail. Does not work on OpenLDAP.
- **Error shape identifies the directory.** `DSID-` strings suggest AD; `ldap_search_ext: Bad search filter` is OpenLDAP/389. Fingerprint before firing attribute-specific payloads.
- **The WebGUI vs Captive Portal scope matters.** Many LDAP-bypass CVEs allow one endpoint class but fail at another; write up what the bypass actually reaches, not the maximum theoretical. CVE-2026-34578 is Captive-Portal/VPN takeover, not WebGUI admin.
- **Library-level CVEs are architectural.** CVE-2025-61911 (python-ldap `ldap.filter.escape_filter_chars`) and CVE-2026-0636 (BouncyCastle BC-JAVA bcprov) are library-level — the application using the library inherits the exposure independent of its own code. See `ldap_injection_novel_deep.md` for the library class.
- **DN injection is rare but high-impact.** Grep for `ldap_add`-shape operations that embed user input in the DN string.
- **PAM-LDAP bridges are a lateral-movement path.** An LDAP-injection auth bypass that grants a shell via PAM-LDAP (SSH authentication delegated to LDAP) is immediate host access, not just application access.

## Tooling

- **Burp Suite** — Scanner picks up classic predicate-break patterns; extensions `active-scan++` and `backslash-powered-scanner` add LDAP-filter probe families.
- **ldapsearch (OpenLDAP client)** — manually test filter syntax against the target directory to understand its parse behavior before firing injections.
- **Hydra / Medusa** — LDAP brute-force for exploited bypass sinks.
- **go-ldap / python-ldap / ldap3 / UnboundID** — library-level sandboxes for crafting and testing payloads before firing against the target.
- **nmap `--script=ldap-rootdse`** — enumerate LDAP server capabilities and schema before scanning.
- **BloodHound (AD-specific)** — map AD attack paths; useful once an authentication bypass yields a working account.

## Summary

LDAP injection breaks a filter's logical shape with an unescaped `)` or `|`, truthifying authentication, enumerating directory entries, bypassing group membership checks via the archetypal OR-filter bypass `targetuser)(|(uid=targetuser`, or extracting attributes a byte at a time. Per-directory behavior differentiates OpenLDAP (RFC 4515 strict), AD (anr=, objectCategory, userAccountControl bitmask), 389/FreeIPA (389-based), and OpenDJ. The 2024–2026 frontier is dense: 50+ verified CVEs with CVSS up to 9.8 (WeKan, maddy, Apache CXF XKMS, Metacat, MISP, Gladinet CentreStack), including library-level CVEs against python-ldap (CVE-2025-61911), BouncyCastle BC-JAVA (CVE-2026-0636, CVE-2026-59652), PAC4J (CVE-2026-40459), and the OPNsense (CVE-2026-34578) archetype. The two deep siblings carry the full technique surface: `ldap_injection_advanced_deep.md` owns per-library escape behavior, DN injection depth, second-order LDAP, blind extraction protocol, and schema-driven matching rules; `ldap_injection_novel_deep.md` owns the 2024–2026 CVE catalog with the OR-filter-bypass archetype and the library-level class.
