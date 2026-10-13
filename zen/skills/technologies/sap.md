---
name: sap
description: SAP security testing covering ICMAD-class HTTP request smuggling (CVE-2022-22536), RECON authentication bypass (CVE-2020-6287), RFC gateway abuse, default credentials (SAP*/DDIC), SAP Router and message-server exposure, and transaction-code privilege escalation
---

# SAP

SAP systems expose a layered attack surface spanning web-facing components (ICM, NetWeaver AS Java/ABAP), internal RPC protocols (RFC, message server), and application-level authorization (transactions, roles, authorization objects). This skill owns the SAP-specific surfaces: ICMAD-class HTTP request smuggling, RECON-class authentication bypass, RFC gateway abuse, default credentials, SAP Router/message-server exposure, and transaction-code escalation. It does not duplicate generic web-application injection reasoning (see `sql_injection` for the class, which applies to SAP's SQL-backed queries), deserialization chains (see `insecure_deserialization`), or identity-provider SSO surfaces (see `auth0`/`okta`). SAP does not publicly disclose most vulnerabilities outside SAP Security Notes — CVE classes here are verified against NVD; SAP Note numbers are cited where applicable.

## Attack Surface

**Web-facing components**
- SAP Internet Communication Manager (ICM): HTTP/HTTPS reverse proxy and request handler; shared by NetWeaver AS ABAP, AS Java, Web Dispatcher, and Content Server
- SAP Web Dispatcher: dedicated reverse-proxy/load-balancer component (uses ICM internally)
- NetWeaver AS Java: J2EE stack — web admin consoles, LM Configuration Wizard, UME (User Management Engine)
- NetWeaver AS ABAP: BSP (Business Server Pages), ICF (Internet Communication Framework) services under `/sap/bc/`

**Internal protocols**
- RFC (Remote Function Call): `sapgw<NN>` on port `33<NN>` — the primary ABAP-to-ABAP and external integration protocol
- SAP Message Server: ports `36<NN>` (HTTP), `39<NN>` (internal) — coordinates application-server instances in a cluster; registration port accepts new AS registrations
- SAP Router: port `3299` — network-level proxy for RFC and other SAP protocols; often exposed to the internet as the entry point to internal SAP landscapes
- SAP GUI: ports `32<NN>` (diag protocol) — the fat-client interface to ABAP transactions

**Authorization model**
- Users: `SAP*` (superuser), `DDIC` (data dictionary), `EARLYWATCH` (monitoring), `TMSADM` (transport management), plus functional/technical users
- Roles: single roles, composite roles, derived roles; mapped to authorization objects
- Authorization objects: fine-grained checks (e.g., `S_TCODE` for transaction access, `S_RFC` for RFC function modules, `S_DEVELOP` for ABAP development)
- Transaction codes (T-codes): the primary UI entrypoints; each T-code maps to a program/screen and checks `S_TCODE` + additional authorization objects

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# ICM/Web Dispatcher — HTTP headers reveal SAP
curl -sI https://<target>/sap/bc/
# Look for: SAP-ABAP, SAP-SYSTEM, sap-* cookies, disp+work version in headers

# NetWeaver AS Java — admin console
curl -sI https://<target>/nwa
# /startPage, /webdynpro/welcome, /irj/portal — each confirms Java stack

# SAP GUI / diag protocol — port 32<NN>
nmap -Pn -p 3200-3299 --script banner <target>

# RFC gateway — port 33<NN>
nmap -Pn -p 3300-3399 <target>

# SAP Message Server — HTTP info port 81<NN> or 36<NN>
curl -s http://<target>:8100/msgserver/text/logon

# SAP Router — port 3299
nmap -Pn -p 3299 <target>

# Version disclosure — error pages, login screens, /sap/public/info
curl -s https://<target>/sap/public/info | grep -i "kernel\|version\|release"
```

**Detection signals for `register_detected_stack`:**
- `/sap/bc/` URL path prefix (ICF services on ABAP stack)
- `SAP-ABAP`, `SAP-SYSTEM`, `sap-usercontext` in response headers or cookies
- Ports `32NN`/`33NN`/`36NN`/`39NN`/`3299` open (diag, RFC, message server, SAP Router)
- `/nwa`, `/irj/portal`, `/webdynpro/` paths (Java stack)
- Login page containing "SAP NetWeaver", "SAP Fiori", "SAP Business Client"

## Key Vulnerabilities

### ICMAD — HTTP Request Smuggling (CVE-2022-22536 Class)

Three related vulnerabilities in SAP's Internet Communication Manager, collectively ICMAD (ICM Advanced Desync):

**CVE-2022-22536** (CVSS 10.0) — HTTP request smuggling via memory-pipe desynchronization in ICM. An unauthenticated attacker prepends arbitrary data to a victim's request when a proxy sits between the client and ICM — enabling session hijacking, cache poisoning, and credential theft. Affects SAP NetWeaver (ABAP and Java), ABAP Platform, SAP Content Server 7.53, and SAP Web Dispatcher. CISA KEV (added August 2022). A single HTTP request is sufficient when a proxy with default configuration fronts the ICM.

**CVE-2022-22532** (CVSS 9.8) — improper shared-memory buffer handling in ICM on NetWeaver AS Java. An unauthenticated attacker sends a crafted request that triggers payload execution, enabling victim impersonation or session theft. Exploitable without a proxy (unlike CVE-2022-22536). Affects KERNEL 7.22–7.53.

**CVE-2022-22533** (CVSS 7.5) — memory corruption in ICM. The least severe of the three; causes denial of service or information disclosure.

**Assessment implication:** version-check the ICM/kernel against the affected ranges first. An SAP system with an internet-exposed ICM (Web Dispatcher, AS Java portal, Fiori launchpad) in the affected version range is a critical finding even without exploitation.

### RECON — Missing Authentication (CVE-2020-6287)

**CVE-2020-6287** (CVSS 10.0) — SAP NetWeaver AS Java's LM Configuration Wizard does not enforce authentication. An unauthenticated attacker with HTTP access to the Java stack creates an administrative user account, achieving full system compromise. Affects AS Java versions 7.30–7.50. CISA KEV. The vulnerability is in the `/CTCWebService/CTCWebServiceBean` endpoint — probe its reachability as a first check.

### Default Credentials

SAP systems create standard accounts during installation with well-known default passwords. Default-credential exposure is a perennial finding:

- **SAP*** — the superuser; default password `06071992` (historical) or `PASS` (depending on release). The profile parameter `login/no_automatic_user_sapstar` controls whether `SAP*` is recreated on deletion; when set to `0` (default on older systems), deleting `SAP*` re-creates it with the default password on next login attempt.
- **DDIC** — data dictionary user with `SAP_ALL` authorization; default password `19920706`.
- **EARLYWATCH** — monitoring user; default password `SUPPORT`.
- **TMSADM** — transport management; default password `PASSWORD` or `$1Pawd2&`.

Test via SAP GUI (transaction `SE38` → `RSUSR003` lists users with default passwords) or RFC:
```
# RFC login with default credentials (requires network access to port 33<NN>)
# Tools: pysap, SAP RFC SDK, or rfcexe
```

### RFC Gateway Abuse

The RFC gateway (`sapgw<NN>`, port `33<NN>`) mediates all RFC communication. Security depends on gateway ACL configuration (`gw/acl_mode`, `gw/reg_info`, `gw/sec_info`):

- **Unprotected gateway:** default configuration on older systems allows any host to register external server programs and execute RFC function modules — including `RFC_SYSTEM_INFO` (system metadata), `RFC_READ_TABLE` (arbitrary table read), `BAPI_USER_GET_DETAIL` (user details), and `RFC_ABAP_INSTALL_AND_RUN` (arbitrary ABAP execution).
- **reginfo/secinfo bypass:** the ACL files (`reginfo`, `secinfo`) control external program registration and RFC function-module access. Misconfigured entries (wildcards, commented-out deny rules) weaken the boundary.
- **RFC destination abuse:** with low-privilege SAP access, enumerate RFC destinations (transaction `SM59`) — stored credentials for remote systems are retrievable by users with `S_RFC` authorization.

### SAP Router and Message-Server Exposure

**SAP Router** (port 3299) is a network proxy intended to restrict access to internal SAP systems. When internet-exposed:
- Route-string brute-forcing (`/H/<internal_host>/S/<port>`) probes internal network topology and pivots to otherwise unreachable SAP systems.
- Information disclosure: SAP Router's info request reveals internal hostnames, instance numbers, and SIDs.

**SAP Message Server** registration port (port `39NN`): accepts application-server registrations for the SAP cluster. An attacker with network access to this port can register a rogue application server, intercepting client connections and credentials. The profile parameter `rdisp/msserv_internal` should designate a separate internal-only port; when unset, the registration port is the same as the client-facing HTTP port.

### Transaction-Code Privilege Escalation

SAP authorization checks are granular but complex — escalation paths arise from misassigned authorization objects:
- `S_TCODE` granting access to sensitive T-codes (`SE16` — table browser with direct database read, `SE38`/`SA38` — ABAP program execution, `SM49`/`SM69` — OS command execution, `STMS` — transport management).
- `S_DEVELOP` with object type `DEBUG` — ABAP debugger allows modifying variable values at runtime, bypassing authorization checks in running programs.
- `S_RFC` with wildcard function-group access — allows calling any RFC function module including `RFC_ABAP_INSTALL_AND_RUN`.
- Authorization-object value ranges with wildcards (`*` in `ACTVT` field) granting all activities (read/write/delete/execute) on sensitive objects.

## Testing Methodology

1. **Fingerprint** the SAP stack (ABAP, Java, or dual-stack), kernel version, and exposed components from HTTP headers, login pages, and port scans.
2. **Version-match** against ICMAD (CVE-2022-22536/22532) and RECON (CVE-2020-6287) affected ranges — these are critical unauthenticated findings.
3. **Default credentials** — test `SAP*`, `DDIC`, `EARLYWATCH`, `TMSADM` via SAP GUI or RFC.
4. **RFC gateway** — test reachability of port `33NN`; attempt `RFC_SYSTEM_INFO` to confirm access; enumerate function modules.
5. **SAP Router** — test port 3299; attempt route-string enumeration; retrieve info request.
6. **Message server** — test registration-port access; verify `rdisp/msserv_internal` configuration.
7. **Transaction-code audit** — with authenticated access, review role assignments for sensitive T-codes (`SE16`, `SM49`, `SE38`, `STMS`) and authorization objects with wildcard values.

## Validation

1. Show the kernel/component version and the CVE it maps to, with the SAP Security Note number and NVD URL.
2. Default credentials: show the successful login (SAP GUI screenshot or RFC response) with the default account and the authorization profile it carries.
3. RFC gateway: show the `RFC_SYSTEM_INFO` response confirming unauthenticated RFC access and the system metadata disclosed.
4. ICMAD: show the version in the affected range; demonstrate the request-smuggling preconditions (proxy configuration, ICM version).
5. Transaction escalation: show the role assignment, the sensitive T-code access, and the data or action it permits beyond the user's business function.

## False Positives

- SAP Router exposed but with a restrictive route-permission table — test actual route-string traversal before claiming internal pivot capability.
- Default accounts exist but passwords have been changed — the finding is the default password, not the account's existence (though `SAP*` with `login/no_automatic_user_sapstar=0` is a separate finding).
- RFC gateway reachable but ACL enforced — test with `RFC_SYSTEM_INFO`; a connection-refused or access-denied response means the ACL is working.
- ICMAD-affected version but no proxy in the path — CVE-2022-22536 requires a proxy; CVE-2022-22532 does not. Scope each independently.
- Java stack present but LM Configuration Wizard endpoint not reachable — RECON requires HTTP access to `/CTCWebService/CTCWebServiceBean`; if the endpoint is blocked, the vulnerability is not exploitable from the assessment vantage point.

## Impact

- Full system compromise via RECON (CVE-2020-6287) — unauthenticated administrative user creation on NetWeaver AS Java.
- Session hijacking and credential theft via ICMAD request smuggling — affects all users transiting the ICM.
- Arbitrary ABAP execution via RFC gateway abuse (`RFC_ABAP_INSTALL_AND_RUN`) — OS-level command execution on the SAP application server.
- Credential harvesting from default accounts and stored RFC-destination passwords.
- Internal network pivot via SAP Router route-string traversal.
- Business-process manipulation via transaction-code privilege escalation — financial postings, material movements, user administration.

## Pro Tips

1. `RFC_SYSTEM_INFO` is the fastest RFC-gateway test — if it responds, the gateway is unprotected and every RFC function module is reachable.
2. `SAP*` with `login/no_automatic_user_sapstar=0` is a backdoor by design — deleting the account re-creates it with the default password.
3. `SE16` (table browser) with `S_TABU_DIS` authorization is effectively a database shell — test for it on every authenticated engagement.
4. SAP kernel versions are the version-match target for ICMAD — they span multiple product lines (NetWeaver, Web Dispatcher, Content Server).
5. Pair with `rce` for post-exploitation from RFC/OS-command paths, `information_disclosure` for credential exposure in RFC destinations, and `active_directory` where the SAP system authenticates against AD/LDAP.

## Summary

SAP's attack surface spans web-facing HTTP request smuggling (ICMAD class), authentication-bypass endpoints (RECON), internal RPC protocols (RFC gateway), and application-level authorization (transactions, roles, default credentials). The ICMAD and RECON CVE classes are unauthenticated and critical — version-match first. Default credentials (`SAP*`, `DDIC`) and unprotected RFC gateways are perennial findings on internal engagements. SAP Router and message-server exposure extends the attack surface to network-level pivot.
