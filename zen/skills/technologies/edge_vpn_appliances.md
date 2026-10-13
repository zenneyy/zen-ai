---
name: edge_vpn_appliances
description: Edge/VPN appliance security testing covering Citrix NetScaler, Fortinet FortiOS, Ivanti Connect Secure, and Palo Alto GlobalProtect — pre-auth exploitation classes, session-token disclosure, post-patch persistence, and management-interface fingerprinting
---

# Edge/VPN Appliances

Edge appliances — SSL-VPN concentrators, ADCs, and remote-access gateways — are the dominant initial-access class in 2024–2026 campaigns. They sit at the network perimeter with internet-exposed management interfaces, run proprietary firmware that patches slowly, and grant authenticated-session or OS-level access upon compromise. This skill covers attack-surface methodology for Citrix NetScaler ADC/Gateway, Fortinet FortiOS (FortiGate), Ivanti Connect Secure (formerly Pulse Secure), and Palo Alto GlobalProtect. It does not duplicate `active_directory` domain-pivot techniques or generic `authentication_jwt` session-handling — those are referenced at chaining boundaries.

## Attack Surface

**Citrix NetScaler ADC / Gateway**
- Management: NSIP (`:443`/`:80`), SNIP for backend health
- Gateway vServer: SSL-VPN portal, ICA proxy, EPA scan
- AAA: LDAP/RADIUS/SAML/certificate binds
- Session: NSC_AAAC/NSC_TMAS/NSC_TMAA cookies, DTLS sessions

**Fortinet FortiOS (FortiGate)**
- Management: `:443` HTTPS admin UI, `:22` SSH, `:8443` (alternate HTTPS)
- SSL-VPN: `/remote/login` portal, FortiClient SSLVPN tunnel
- Web filtering/proxy, FortiGuard connectivity, HA sync
- Session: SVPNCOOKIE, FortiToken MFA integration

**Ivanti Connect Secure / Policy Secure**
- Management: admin interface (`:443`), separate management port configurations
- User portal: `/dana-na/auth/url_default/welcome.cgi`, Pulse Launcher
- SAML: SAML authentication component (separate from core auth)
- Session: DSID/DSSignInURL cookies, DSLastAccess

**Palo Alto GlobalProtect**
- Management: `/php/login.php` (PAN-OS admin), Panorama (`:443`)
- Portal/Gateway: `/global-protect/login.esp`, `/ssl-vpn/hipreport.esp`
- GlobalProtect agent: HIP check, pre-logon tunnel
- Session: PHPSESSID, custom auth cookies

## Reconnaissance

Fingerprinting the vendor and firmware version is the first gate — it determines which vulnerability classes apply and whether the instance is in a patched or unpatched range. All probes below are unauthenticated.

**Citrix NetScaler**
```
# Login page reveals product
curl -sk https://<target>/vpn/index.html
# Look for: "Citrix Gateway", "NetScaler AAA", "StoreFront"
# Version inference from static assets or error pages
curl -sk https://<target>/vpn/js/ctxs.*.js   # bundled JS versioning
```

**Fortinet FortiGate**
```
# SSL-VPN portal endpoint (primary signal)
curl -sk https://<target>/remote/login?lang=en
# Static-file SHA-256 fingerprinting maps to firmware builds
curl -sk https://<target>/remote/fgt_lang.js | sha256sum
curl -sk https://<target>/lang/x-sjis.json | sha256sum
# ETag header version disclosure (CVE-2024-23662)
# Unauthenticated request; ETag encodes build info on FortiOS 7.4.0–7.4.1, 7.2.0–7.2.5, all 7.0.x and 6.4.x
curl -skI https://<target>/remote/login | grep -i etag
```

**Ivanti Connect Secure**
```
# Welcome page (classic Pulse Secure)
curl -sk https://<target>/dana-na/auth/url_default/welcome.cgi
# Shodan favicon hash for Connect Secure: -1439222863
# Version often in page source or X-UA-Compatible header
curl -skI https://<target>/ | grep -i "x-frame\|server\|x-content"
```

**Palo Alto GlobalProtect**
```
# PAN-OS management login
curl -sk https://<target>/php/login.php
# GlobalProtect portal
curl -sk https://<target>/global-protect/login.esp
# Version in the login page title/meta or /api/?type=version (if accessible)
```

**Cross-vendor signals**
- CISA BOD 23-02 scopes VPN concentrators, firewalls, load balancers, and proxies — management interfaces on these device classes must not be internet-exposed. An internet-reachable management interface is itself a compliance finding.
- Shodan/Censys/BinaryEdge queries for each product return exposure counts; correlate with target IP ranges.

## Key Vulnerability Classes

### Citrix NetScaler — Session-Token Disclosure

**CVE-2023-4966 (CitrixBleed)** — information disclosure vulnerability (CVSS 9.4) in NetScaler ADC and Gateway that leaks session tokens from device memory via unauthenticated requests. Affected versions: 14.1 before 14.1-8.50, 13.1 before 13.1-49.15, 13.0 before 13.0-92.19, 12.1-FIPS/NDcPP before 12.1-55.300. Mandiant confirmed zero-day exploitation from late August 2023, before the October 10 Citrix bulletin. Ransomware affiliates actively distributed exploit scripts.

**The critical remediation property:** hijacked sessions persist even after the patch is applied because pre-patch stolen session tokens remain valid. Patching stops new token leakage but does not invalidate existing sessions — credential rotation and session termination are required post-patch.

**Preconditions:** appliance configured as Gateway (VPN virtual server, ICA proxy, CVPN, RDP proxy) or AAA vServer. Appliances not configured as a Gateway or AAA vServer are not affected. Firmware in the affected version range.

**Post-exploitation chain:** stolen session token → authenticated session bypassing MFA → VDI/Citrix desktop access → internal network pivot. Observed post-exploitation includes remote PowerShell, `whoami`/`net user`/`WMIC` reconnaissance, and deployment of internal scanning tools onto VDI hosts. Route session-handling to `authentication_jwt`; route internal pivot to `active_directory` where the target network is domain-joined.

### Fortinet FortiOS — Pre-Auth Exploitation and Post-Patch Persistence

Three distinct CVE classes affect the FortiOS SSL-VPN and management interfaces:

- **CVE-2022-42475** — heap-based buffer overflow in the SSL-VPN component, enabling pre-auth RCE. Fixed in 7.2.3, 7.0.9, 6.4.11, 6.2.12.
- **CVE-2023-27997** — heap buffer overflow in SSL-VPN pre-authentication, independently from 42475. Fixed in 7.4.0, 7.2.5, 7.0.12, 6.4.13, 6.2.15.
- **CVE-2024-21762** — out-of-bounds write (CWE-787) in FortiOS and FortiProxy allowing RCE via crafted requests. Fixed in 7.4.3, 7.2.7, 7.0.14, 6.4.15, 6.2.16.

Each CVE has a distinct root cause; patching one does not address the others. Not all require SSL-VPN to be enabled — scope each CVE's preconditions independently against the target's configuration.

**Post-patch persistence via filesystem symlink:** threat actors create a symbolic link in the SSL-VPN language-file folder that connects the user-accessible filesystem to the root filesystem. This symlink survives normal firmware updates because it resides in user-writable storage outside the patch scope. Remediation requires upgrading to builds that actively remove the symlink (7.6.2, 7.4.7, 7.2.11, 7.0.17, 6.4.16) plus configuration review and credential rotation. The Canadian Centre for Cyber Security (AL25-005, April 2025), CISA, and Fortinet PSIRT all confirmed thousands of compromised devices retaining persistence after patching.

**Detection signal for prior compromise:** the symlink's existence is the indicator. On a compromised appliance, the attacker maintains read access to the entire filesystem including configuration files and credentials, even on a "patched" device. An appliance in a nominally patched version range with the symlink present is actively compromised.

Route pre-auth RCE to `rce`; route credential theft from filesystem access to `cryptographic_failures`; route LDAP credential exposure (FortiGate sends LDAP passwords in cleartext via simple bind, observable by an attacker controlling the appliance) to `information_disclosure`.

### Ivanti Connect Secure — Pre-Auth RCE Chains

Multiple independent pre-auth vulnerability classes disclosed within weeks:

**CVE-2023-46805 + CVE-2024-21887 chain** — authentication bypass via path traversal (CVSS 8.2) chained with authenticated admin command injection (CVSS 9.1) to achieve unauthenticated RCE on Connect Secure and Policy Secure versions 9.x and 22.x. Rapid7 independently reproduced the chain and published a Metasploit module. CISA added both to KEV on January 10, 2024. Post-exploitation: webshell deployment, credential harvesting, lateral movement into the internal network.

**CVE-2024-21893** — SSRF in the SAML authentication component, providing a separate pre-auth path independent of the 46805+21887 chain. Confirmed exploited by January 31, 2024. Route to `ssrf` for the SSRF methodology; the platform-specific residual is that this SSRF reaches the appliance's internal services, not a web application backend.

**CVE-2025-0282** — stack-based buffer overflow (CVSS 9.0) enabling unauthenticated RCE on Connect Secure, Policy Secure, and ZTA Gateways. CISA identified the RESURGE malware variant (MAR-25993211.R1.V1.CLEAR) that undermined earlier prescribed mitigations, prompting revised guidance in April 2025. Route to `rce`.

**Cross-CVE pattern:** Ivanti's internal and external Integrity Checker Tool (ICT) has been demonstrated to miss compromise in multiple campaigns (CISA joint advisory AA24-060B). Do not treat a clean ICT result as proof of non-compromise on an appliance that was ever in a vulnerable version range.

**Preconditions gate for each chain:** version range + network reachability to the affected endpoint (SAML for 21893, the web interface for 46805+21887 and 0282). A patched appliance or one not exposing the affected component is not vulnerable to that specific chain.

### Palo Alto GlobalProtect

GlobalProtect and PAN-OS management interfaces have carried pre-auth RCE and authentication bypass CVEs, but the research for this skill did not surface a verified CVE class cluster at the same depth as the three vendors above. Cross-reference PAN-OS advisories at security.paloaltonetworks.com and verify any candidate CVE against NVD before asserting it. The detection methodology (management-interface fingerprinting, portal endpoint probing) applies; load vendor-specific advisories at assessment time.

## Post-Exploitation Patterns

A cross-vendor pattern defines this device class: **patching alone is insufficient remediation.** CitrixBleed sessions persist after patch; FortiOS symlinks survive firmware updates; Ivanti mitigations were undermined by RESURGE. For any appliance that was ever in a vulnerable version range, assume compromise until forensic investigation disproves it — patched + credential-rotated + session-terminated is the minimum remediation bar.

**Downstream capabilities from appliance compromise:**
- **Authenticated VPN session** → internal network access bypassing perimeter controls → route to target-specific skills (`active_directory`, `ssrf` against internal services)
- **Credential harvesting** from device configuration (LDAP bind passwords, RADIUS shared secrets, SAML signing keys) → route to `cryptographic_failures` and `authentication_jwt`
- **Persistence mechanisms** (symlinks, webshells, scheduled tasks in appliance OS) → route to `rce` for the OS-level foothold
- **Lateral movement** via stolen VPN user credentials or session tokens replayed against other internal services

## Testing Methodology

1. **Fingerprint** vendor and firmware version from unauthenticated management-interface probes (Reconnaissance section).
2. **Version-match** against the CVE version ranges above — an appliance in an affected range on an exposed interface is a confirmed finding even without exploitation.
3. **Post-patch persistence check** — for FortiOS, verify symlink absence; for Citrix, verify session invalidation was performed post-patch; for Ivanti, verify ICT results are current and that RESURGE indicators are absent.
4. **Credential exposure** — test for default credentials on management interfaces; check for LDAP/RADIUS credential leakage from config access.
5. **Management-interface exposure** — an internet-reachable management interface on any of these platforms is a standalone finding per CISA BOD 23-02.
6. **Chain assessment** — if an exploitable version is confirmed, articulate the downstream capability (VPN session → internal access → specific target).

## Validation

1. Show the exact firmware version (from fingerprinting) and the CVE version range it falls within — with the primary-source advisory URL.
2. For post-patch persistence, demonstrate the persistence indicator (symlink presence, active stolen session, RESURGE IOC) on the target.
3. For management-interface exposure, confirm the interface is reachable from the internet (not an internal-only management network behind ACLs).
4. Provide the full chain: exposed interface → version-confirmed vulnerability → downstream capability gained.

## False Positives

- Appliance firmware is in the **fixed version range** for all applicable CVEs — not exploitable (still report management-interface internet exposure as a separate finding per BOD 23-02).
- Management interface reachable only from a dedicated management VLAN/subnet behind ACLs — verify from the actual assessment vantage point, not from internal scans.
- FortiOS appliance with SSL-VPN disabled — reduces the attack surface for SSL-VPN-specific CVEs (42475, 27997) but does not eliminate exposure to management-interface CVEs (21762 affects FortiOS broadly, not only SSL-VPN).
- Citrix appliance not configured as Gateway or AAA vServer — not affected by CitrixBleed.
- ICT "clean" result on Ivanti — insufficient to rule out compromise (AA24-060B); do not use as sole negative evidence.
- Version fingerprint from a reverse proxy or CDN that fronts the appliance — confirm the fingerprint maps to the appliance, not the proxy.

## Impact

- Pre-authentication remote code execution on the network perimeter — immediate OS-level access to the appliance.
- Authenticated VPN session hijacking bypassing MFA — full internal network access under a legitimate user identity.
- Credential harvesting (LDAP, RADIUS, SAML keys) from device configuration — lateral movement into identity infrastructure.
- Post-patch persistence enabling long-term access even after the organization applies vendor patches.
- VulnCheck 2026 data: 42.5% of exploited edge device vulnerabilities in 2025 targeted end-of-life hardware; only 23.7% of exploited edge device CVEs appeared in CISA KEV.

## Pro Tips

1. Fingerprint before anything else — the version determines the entire attack tree; a patched appliance with an exposed management interface is still a BOD 23-02 finding.
2. The patch-is-not-enough pattern is universal across these vendors — always check for post-patch persistence indicators, not just the firmware version.
3. FortiOS ETag fingerprinting (CVE-2024-23662) is the most reliable version-disclosure probe; the static-file SHA-256 method requires a hash-to-version lookup table.
4. Ivanti ICT misses compromise — treat it as one signal among many, never definitive.
5. For Citrix, session invalidation post-patch is separate from applying the patch — confirm the organization performed both.
6. Pair with `nmap` for port/service discovery, `active_directory` for domain-pivot post-compromise, and `authentication_jwt` for session-token analysis.

## Summary

Edge/VPN appliances are perimeter targets where a single pre-auth vulnerability grants VPN session hijacking, OS-level RCE, or credential harvesting from device configuration — and where patching alone does not remediate prior compromise. Fingerprint the vendor and version, match against known CVE classes (CitrixBleed, FortiOS pre-auth chain, Ivanti pre-auth RCE chains), check for post-patch persistence, and articulate the downstream capability each exploitation path grants into the internal network.
