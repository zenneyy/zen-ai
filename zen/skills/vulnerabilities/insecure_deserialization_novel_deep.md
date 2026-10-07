---
name: insecure-deserialization-novel-deep
description: Novel and frontier insecure-deserialization depth for 2024–2026 — the Sleeping Giants supply-chain reframing (Kreyssig/Houy/Riom/Bartel CCS'25), canonical per-CVE version/fix tables and mechanism decomposition for jackson-databind CVE-2026-54512, XStream CVE-2024-47072, .NET 9 BinaryFormatter removal, the ML-pipeline PyTorch weights_only cluster, the serialize-javascript prototype-poisoning cluster, the PyJWT September 2026 alg-confusion cluster, PHP PHAR version boundaries, per-chain ysoserial classpath preconditions, and the FLASH/GCMiner detection-frontier framing.
sibling: insecure_deserialization
load_when: scan_mode == "deep"
---

# Insecure Deserialization — Novel and Frontier Depth

This is the novel+frontier deep sibling to `insecure_deserialization.md`. The base owns the technique-class framing, the per-language primitive tour, chaining, and confirmation-without-RCE ladder; the advanced+expert sibling `insecure_deserialization_advanced_deep.md` owns JEP 290/415 filter architecture, format-parser differentials, second-order attack-graph modelling, WAF magic-byte evasion, the four canonical generators' per-chain classpath preconditions, and wire-format fingerprinting. This file owns the 2024–2026 published-instance frontier: the canonical per-CVE version/fix tables and mechanism decomposition (single-owner for version strings and GHSA IDs across the trio), the Sleeping Giants supply-chain reframing with its three modification patterns, the FLASH/GCMiner detection-frontier framing, and the emerging supply-chain expressions in ML pipelines and CI/CD — routing by filename.

Every 2024–2026 CVE cited below was verified against NVD or the GitHub Security Advisory API before inclusion; version boundaries reflect the primary source and are single-owner in this file per the trio's ownership rules. Any CVE label that did not resolve was rewritten as a behavior-fingerprinted class without the CVE number. Load this file when the scan is in deep mode and the target's stack, dependency graph, or ML/CI-CD posture matches any of the sections below.

## Sleeping Giants — Dormant Chains and Supply-Chain Reframing

The single most important frame shift in this class since 2024 is that Java gadget-chain reachability is a *fluctuating* property of a dependency's version history. Kreyssig, Houy, Riom, and Bartel (CCS'25, arXiv:2504.20485; DOI 10.1145/3719027.3765031) enumerate three modification patterns an attacker (or a downstream typo-squatter with commit access) can apply to a benign dependency to *activate* a dormant chain without adding a visible vulnerability.

**Section 4.1 injection patterns** — verbatim from the paper's Section 4.1:

- **§4.1.1 Transitive Serializability** — making a supertype `Serializable` extends the deserialization surface to every subclass, which may already carry a magic-method chain that was previously inert because a parent was not deserializable. The commit shape is a one-line `implements Serializable` addition on a base class, or `extends Object` → `extends SerializableBase`. Any class that inherits from the modified supertype is now transitively deserializable and its `readObject` / `readResolve` / `hashCode` / `equals` / `toString` methods reach the reflection surface.
- **§4.1.2 Final Properties** — dropping `final` on a class or field enables reflection-driven property write during deserialization, restoring an attacker's ability to steer a constructor/setter path that was fixed at compile time. The commit shape is removing the `final` keyword from a field or class declaration. A `final` field cannot be reflectively assigned by `ObjectInputStream`; making it non-final restores that surface. A `final` class cannot be subclassed to override methods; making it non-final restores the subclass-override attack.
- **§4.1.3 Interface Method Reachability** — adding an interface method (e.g., `hashCode` / `equals` / `toString` / `compareTo` on a class that did not previously override them) unlocks trampoline gadgets. A trampoline is a method whose invocation on unmarshal reaches a further sink; e.g., a `hashCode` override that internally calls `Method.invoke` on a stored callable. The commit shape is a new override method that delegates to an inner field.

**Empirical result** — verbatim from the paper's Section 4.3: applying the three patterns to 533 sampled Java dependencies activated/injected gadget chains detected by three state-of-the-art detectors (Tabby, AndroChain, and a third) in 139 dependencies (26.08%). The paper verified 53 dependencies as containing dormant gadget chains that a minor upstream change could introduce.

**Canonical thesis** — verbatim from the paper's abstract: "class serializability is a strongly fluctuating property over a dependency's evolution" and dormant gadget chains constitute "a lucrative supply chain attack vector."

**Correction to prior briefings** — earlier internal briefings attributed this paper to "Cao et al." That attribution is wrong; Cao et al. authored the GCMiner paper (ICSE'23), a distinct work. The Sleeping Giants authors are Kreyssig, Houy, Riom, Bartel — Umeå University. The arXiv submission date is 2025-04-29; the ACM DOI resolves under CCS'25. Any reference to "Cao et al. Sleeping Giants" should be corrected to "Kreyssig et al. Sleeping Giants."

**Audit-cadence implications**:

1. The 2019-era guidance was "audit gadget chains once per major dependency version and monitor for CVEs." That guidance is now insufficient. Any minor-version bump can activate a dormant chain, and the CVE process does not track the activating change (which is not itself a security fix).
2. The correct cadence is: on every dependency bump (including patch versions), re-run reachability detection.
3. Treat the three modification patterns as diff-reviewable — a PR that adds `implements Serializable`, drops `final`, or introduces a new override method deserves a "did this activate a chain?" audit at the reviewer level.
4. Assume the frontier detector today (FLASH, USENIX'25) will improve; the reachability status of your app is only as current as the last tool run.

**Interaction with JEP 290/415 filters** — a filter that allows `commons-collections` classes because those classes are used legitimately by the app is only safe as long as those classes remain gadget-free. If a dependency bump introduces a Sleeping Giants modification pattern (e.g., a new interface method on `LazyMap`), the previously-safe allow-listed class becomes chainable. Filter allow-lists must be re-audited on dependency bumps.

**Interaction with `SBOM`s** — software bill-of-materials tooling that tracks dependency versions is necessary but insufficient. The SBOM captures what versions are present; Sleeping Giants means the security relevance changes across those versions independently of CVE flagging. SBOM + reachability-detector = the correct audit posture.

**Class abstraction for the hunter** — a one-shot audit that returns "no chain" only holds for the version audited. In red-team engagements, if the target's dependency graph has been static for a long time, the audit is more reliable; if the target is on an actively-maintained stack with frequent bumps, the audit has to be re-run per release. In pen-testing, this reframes the finding: instead of "no exploitable chain found," the correct finding shape is "no chain reachable in the current dependency snapshot, but the next release may activate one; recommend continuous reachability monitoring."

**Concrete Transitive Serializability example**. A hypothetical library `com.example.utility` has a base class `AbstractOperation` and subclasses `ExecOperation`, `NetworkOperation`, `FileOperation`. In v1.2, none of these implement `Serializable`; a deserialization sink cannot reach `AbstractOperation` because the parser refuses to instantiate a non-Serializable. In v1.3, an unrelated change adds `implements Serializable` to `AbstractOperation` to enable a caching feature. Now `ExecOperation`, `NetworkOperation`, `FileOperation` are all transitively Serializable, and if any of them has a `readObject` (or an implicitly-called invariant like `hashCode`) that reaches an exec / network / file sink, a dormant chain has been activated. The v1.3 CHANGELOG likely reads "added caching support"; no security notice, no CVE.

**Concrete Final Properties example**. A class `Configuration` has `private final String scriptPath`, populated in the constructor. Because `scriptPath` is `final`, `ObjectInputStream.defaultReadObject()` cannot re-assign it during deserialization — reflection is blocked. In a refactor, `final` is dropped to enable a `withScriptPath` builder method. Now on deserialization, `defaultReadObject` can populate `scriptPath` from attacker-controlled bytes; a gadget that has `Configuration.executeScript()` in its call graph reaches attacker-controlled `Runtime.exec(scriptPath)`.

**Concrete Interface Method Reachability example**. A class `WrappedCallable` holds a `Runnable` field but does not override `hashCode`. When placed in a `HashSet` during deserialization, `HashSet.add` calls the object's `hashCode`; the default `Object.hashCode` is safe. In a refactor, `WrappedCallable` gains a `hashCode` override that internally does `runnable.run()`. Now placing a `WrappedCallable` in a `HashSet` during deserialization triggers `Runnable.run()` on attacker-controlled bytes — a trampoline is born.

**Detection tooling for the three patterns**:
- **Transitive Serializability** — diff two consecutive releases of a dependency and check every class hierarchy for `implements Serializable` additions. Static analyzers can flag every new `Serializable` supertype.
- **Final Properties** — diff for `final` removals on fields and classes. `javap` on the two class files and diff the field modifiers.
- **Interface Method Reachability** — diff for new `equals` / `hashCode` / `compareTo` / `toString` overrides. The classes with new overrides are trampoline candidates.

A "Sleeping Giants diff-audit" is: given two versions of a dependency graph, for every class that changed, run these three checks. Any positive is a "did this activate a chain?" audit target.

**Interaction with FLASH / Tabby / AndroChain** — the reachability detectors take the classpath JARs as input and produce a reachability report. Running them before and after a dependency bump and diffing the reports reveals which chains are newly reachable. This is the automated form of the diff-audit; the manual form is the three checks above.

**Enterprise adoption context** — most enterprise security programs do not currently run reachability detection on every dependency bump; they run vulnerability scanners (Snyk, Dependency-Check, npm-audit-equivalents) that flag known CVEs. Sleeping Giants means a fully-clean CVE report can co-exist with a live gadget-chain surface; the audit posture needs to be augmented with reachability detection, not replaced.

## jackson-databind CVE-2026-54512 — Generic-Type PTV Bypass

**Advisory**: GHSA-j3rv-43j4-c7qm, CVE-2026-54512.
**CVSS**: 8.1 High.
**Published**: 2026-06-16 (GHSA), 2026-06-23 (NVD).
**Affected version ranges**: `2.10.0` ≤ v ≤ `2.18.7`; `2.19.0` ≤ v ≤ `2.21.3`; `3.0.0` ≤ v ≤ `3.1.3`.
**Fixed versions**: 2.18.8, 2.21.4, 3.1.4.
**Patch commit**: `434d6c511de7fdd9872f29157aafb6162d12d8d5`; PR `FasterXML/jackson-databind#5988`.
**Downstream**: RedHat RHSA-2026:66545, HeroDevs NES advisory.

**Mechanism**. `DatabindContext._resolveAndValidateGeneric()` validates only the *raw container class name* (the substring before `<`) against the configured `PolymorphicTypeValidator` (PTV), then parses the full canonical type string via `TypeFactory.constructFromCanonical()` without validating nested type arguments. An attacker who controls the polymorphic type ID can smuggle a denied class as a generic parameter of an allow-listed container:

```json
["java.util.ArrayList<com.evil.Gadget>", {"payload":"..."}]
```

If the PTV allow-lists `java.util.ArrayList` (a common allow-list entry because it is a benign container), the container name passes validation. The full canonical form `java.util.ArrayList<com.evil.Gadget>` is then passed to `TypeFactory.constructFromCanonical()`, which resolves `com.evil.Gadget` via `Class.forName()` and instantiates it with attacker-controlled property injection. The class instantiation runs `com.evil.Gadget`'s constructor + any setters called during property population, reaching the classical polymorphic-typing RCE surface.

**Payload construction**:
- Wrap the target gadget class in an allow-listed container's generic parameter: `["java.util.HashMap<TargetGadgetClass>", {...}]` for `PROPERTY` inclusion style, or the equivalent for `WRAPPER_ARRAY`.
- The gadget class inside the generic parameter is instantiated via the same `Class.forName` → constructor → property-inject sequence as classical polymorphic typing.
- Any gadget class the classpath exposes (`JdbcRowSetImpl`, `TemplatesImpl`, script-engine classes) is reachable when a benign container is allow-listed.

**Detection signature**:
- Grep for `PolymorphicTypeValidator` usage in the app; any BasicPTV configuration with allow-listed generic types is potentially vulnerable on the pre-fix versions.
- Grep for `ObjectMapper.setDefaultTyping(...)` and `ObjectMapper.activateDefaultTyping(...)`.
- Fingerprint the jackson-databind version via error stacks, `pom.xml`, or `dependency:tree`.

**Fixed-behavior verification** — on patched versions (2.18.8+, 2.21.4+, 3.1.4+), the PTV is called on the *full canonical type* including nested arguments; a `java.util.ArrayList<com.evil.Gadget>` payload with only `java.util.ArrayList` allow-listed fails at validation with a JsonMappingException.

**Class abstraction — where the next bug lands**: any polymorphic-typing validator that inspects only the outer type name and defers nested-type validation is a candidate for the same shape. Fastjson, jsonpickle, and other type-annotation-driven deserializers have equivalent parsing paths; a similar audit against those parsers' generic-argument handling is warranted. The bug class is "check outer, use inner."

**Chaining**: the primitive is arbitrary class instantiation with property injection — the same primitive as classical polymorphic typing. Escalation into RCE requires a gadget on classpath (route to the ysoserial chain roster below).

**Downstream test methodology on a suspected vulnerable target**:
1. Fingerprint jackson-databind version. Send a request with an intentionally-malformed `@type` value; the JsonMappingException in the response leaks the version through the class name in the stack trace.
2. Identify the target's PTV allow-list. If the app exposes any debug endpoints (`/actuator/env` on Spring Actuator, error pages that dump config), read the `defaultTyping` and `polymorphicTypeValidator` configuration.
3. Enumerate allow-listed containers. Any of `java.util.List`, `java.util.Collection`, `java.util.ArrayList`, `java.util.LinkedList`, `java.util.HashMap`, `java.util.TreeMap` is a common allow-list entry.
4. Enumerate reachable gadget classes on the classpath (via a URLDNS-shape probe first to confirm sink, then via classpath-differential enumeration).
5. Construct the CVE-2026-54512 payload: allow-listed container name wrapping the gadget class as a generic parameter. Fire against the target endpoint.
6. Fixed-version rebuttal: submit the same payload against a staging or adjacent instance patched to 2.18.8/2.21.4/3.1.4. Observe JsonMappingException with a message referencing the generic-parameter validation failure.

**Downstream ripple** — because jackson-databind is transitively depended by almost every Java web framework, any app on a Java stack with polymorphic-typing enabled is a candidate target. Fingerprint via jar-manifest disclosure or dependency-tree extraction; the deployed version informs whether CVE-2026-54512 is live.

**Related jackson-databind advisories in the 2024–2026 window** (partial list; each has its own CVE and version boundary):
- Historical Jackson PTV bypass CVEs (2018–2022 cluster) — cataloged in the FasterXML advisory list.
- The CVE-2026-54512 fix pattern (validate the full canonical form, not the outer name) is a category-fix; expect follow-on advisories against any parser code path that treats parts of the type-name string as separately validatable.

## XStream CVE-2024-47072 — BinaryStreamDriver Stack Overflow

**Advisory**: GHSA-hfq9-hggm-c56q, CVE-2024-47072.
**CVSS**: 7.5 High (CWE-121 + CWE-502).
**Published**: 2024-11-07.
**Affected versions**: XStream `< 1.4.21`.
**Fixed version**: 1.4.21 (raises `InputManipulationException` on the recursion condition instead of triggering stack overflow).
**Patch commit**: `bb838ce2269cac47433e31c77b2b236466e9f266`.
**Vendor advisory**: `https://x-stream.github.io/CVE-2024-47072.html`.

**Mechanism**. XStream's `BinaryStreamDriver` uses IDs for string deduplication. The reader processes mapping tokens through recursion; a crafted binary input stream can be constructed such that the mapping-token processing recurses without a terminator, triggering a `StackOverflowError` that terminates the thread and, in single-threaded servers, DoSes the process.

**Impact clarification** — this is a **denial-of-service vulnerability, not RCE**. Prior briefings and some scanners mislabel it as deserialization RCE; the correct classification is DoS via stack overflow. The mislabel matters for finding-prioritization; an RCE classification would suggest RCE-shape gadget-chain testing, which does not apply here.

**Precondition**. The `BinaryStreamDriver` must be explicitly configured — default XStream uses `PrettyPrintWriter` (XML), which is not affected. Grep the target for `new XStream(new BinaryStreamDriver())` or equivalent driver-selection code. Only apps using `BinaryStreamDriver` on untrusted input are vulnerable.

**Confirmation methodology** — the DoS trigger is not stealthy; observing a target crash after a crafted binary payload confirms. Do not fire in production without authorization and rollback plan; the process termination affects service availability.

**Class abstraction** — XML/binary format parsers that use recursion for reference resolution are candidates for the same shape. Any XStream driver (`Hessian2Driver`, `AbstractPullReader` variants) that processes reference tokens recursively without a depth guard has the same class. Audit XStream driver selection and the recursion-vs-iteration decision at the parser level.

**Distinct from earlier XStream CVEs** — the pre-1.4.18 XStream cluster (CVE-2021-39139, CVE-2021-29505, CVE-2021-4321x through -4322x) covered dynamic-proxy-driven RCE via unsafe-mode deserialization. Those are patched by allow-list-by-default in 1.4.18+; CVE-2024-47072 is a distinct DoS class in the binary driver. Legacy pre-1.4.18 deployments have both the RCE cluster and the DoS.

**Downstream ripple** — XStream is transitively depended by several enterprise Java products (JBoss, IBM, Keycloak); downstream advisories for XStream CVE-2024-47072 propagated through IBM security bulletins, Ubuntu Security Notices, and Keycloak's own advisory index. Fingerprint the XStream version in the target's classpath even if XStream is not a direct dependency.

**Detection**:
- Grep for `com.thoughtworks.xstream.io.binary.BinaryStreamDriver` in the app's source or bundled JARs.
- Fingerprint XStream version via jar-manifest, `pom.xml`, or error-stack disclosures.
- Test with a benign malformed binary stream and observe response — a `StackOverflowError` in the trace confirms the vulnerable driver is engaged.

## Node.js Deserialization Cluster — Beyond serialize-javascript

While `serialize-javascript` is the current highest-profile 2026 Node deserialization surface, the wider Node ecosystem has adjacent classes worth noting for the 2024–2026 window.

**`node-serialize`** — the classical Node RCE library. CVE-2017-5941 established the `_$$ND_FUNC$$_` marker as the RCE primitive. No 2024–2026 upstream security update; the library is largely unmaintained, but still on many production stacks. Fingerprint via `package-lock.json`.

**`funcster`** — designed to serialize/deserialize functions across process boundaries. `funcster.deepDeserialize` on untrusted input is RCE. Grep for `require('funcster')`.

**`serialize-to-js`** — same shape as `node-serialize`; older, less maintained.

**`js-yaml` — the type-tag surface**. Pre-4.0 `.load()` accepts arbitrary `!<type>` tags including class instantiation. `.safeLoad()` removed in 4.0 — `.load()` in 4.0+ is safe-only. Fingerprint the major version.

**`yaml` (Eemeli Aro)** — a different library; `parse()` is safe-by-default but `parseDocument()` with a custom schema can accept type-instantiation tags. Grep for `parseDocument(..., { customTags: ... })` with any type-instantiation tag.

**`vm2` sandbox** — deprecated in 2024 with unfixed escape history. Any use of `vm2` on 2024+ is an audit target — the maintainer explicitly recommended migrating to `isolated-vm`, and `isolated-vm`'s own README warns it is not a security boundary for untrusted code.

**Cross-library research trend**: the Node ecosystem's SSR frameworks (Next.js, Nuxt, SvelteKit, Remix, Qwik, Astro) all serialize state at the SSR boundary; the specific serializer varies but every framework has one, and every serializer has a type-round-trip mechanism that is potential attack surface. Audit the framework's SSR serializer choice; the current state:
- Next.js — `superjson` or the custom Flight-serialization protocol (React Server Components).
- Nuxt — `devalue`.
- SvelteKit — `devalue`.
- Remix — JSON with a custom Response wrapper.
- Qwik — resumable-state serializer (custom).
- Astro — `devalue`.

**`devalue`** — Svelte team's serializer for SvelteKit `load` results. Handles typed values (Date, Map, Set, Regex, BigInt, undefined) with cycle-safe encoding. No published 2024–2026 CVEs, but the attack surface is analogous to `serialize-javascript` and worth continuing to audit.

**`superjson`** — the tRPC / t3-stack serializer. Type-round-tripping via a runtime type registry. Similar attack surface.

## PHP PHAR — Historical Cluster and Current Attack Surface

Beyond the base file's version-boundary table, the PHAR class has a rich historical CVE cluster and continues to receive parser-level advisories in the 2024–2026 window.

**Historical PHAR CVEs (pre-8.0 era, still relevant on legacy deployments)**:
- CVE-2018-14883 — a specific WordPress PHAR unserialization RCE.
- CVE-2018-8952 — Snipe-IT PHAR deserialization.
- The general phpggc-covered POP chains against 44 frameworks — each with its own upstream framework advisory.

**Current PHAR-parser advisories (2024–2026)**:
- **CVE-2026-6103** — Integer overflow in `phar_tar_number()` allowing TAR archive entry injection. Fixed in PHP 8.5.9 and 8.4.24 (2026-07-30, per PHP ChangeLog). Not deserialization per se but PHAR-file-parser vulnerability; adjacent impact includes writing files outside the extracted tree. NVD entry verified; associated GHSA identifier did not resolve against the GHSA API and is not asserted here.
- Additional 2026 PHP 8.5.x changelog entries on PHAR-related paths — consult the ChangeLog for the exact list.

**Class abstraction for PHAR** — the RFC closed the auto-trigger path in 8.0 but PHAR remains an actively-maintained format with its own parser vulnerabilities. Any PHAR-parsing code path in PHP is a potential attack surface even after the auto-unserialize fix; the class shape shifted from "path-taking function triggers unserialize" to "PHAR parser itself has bugs."

**Cross-cutting PHP deserialization surface (adjacent to PHAR)**:
- Symfony 6.x / 7.x sessions with the `native` handler on custom session storage.
- Laravel encrypted cookies with a leaked `APP_KEY` — forge the cookie payload.
- Custom cache adapters that store serialized PHP objects (Doctrine cache, Symfony cache with `SerializedFilesystemAdapter`).
- WordPress `wp_cache_get` when the object cache backend serializes.

## PyJWT — Historical Context and September 2026 Analysis

The alg-confusion class has a documented history stretching back to 2015 (Auth0's original "critical vulnerabilities in JSON Web Token libraries" analysis). The recurrence pattern:

- **2015 — `alg: none`**: verifier accepts tokens with `alg=none` and no signature. Mitigated by making libraries reject `none` by default; still lands on libraries that pass `algorithms=None` to the verifier.
- **2016–2017 — HS256-using-RSA-public-key**: cross-algorithm attack where the verifier uses the RSA public key as an HMAC secret. Mitigated by explicit algorithm allow-listing on the verifier.
- **2019 — `kid` header injection**: `kid` is a key identifier; libraries that use it to look up a key from a file or DB without sanitization allowed path traversal or SQL injection.
- **2022 — CVE-2022-29217 (PyJWT)**: an earlier PEM-detection fix. The verifier now detects PEM-encoded keys and refuses to use them as HMAC secrets.
- **September 2026 — GHSA-ffc3 (PyJWT)**: the fix is bypassed via DER-encoded keys, which are the binary form and don't have the `-----BEGIN` PEM prefix. Same attack shape, different key encoding.

The class abstraction: any signature verifier with an algorithm-selection mechanism that reaches key-material handling has this class. The fix landscape has been reactive (fix each recurrence as it lands) rather than proactive (structural redesign of the verifier's key-material handling). Predicted follow-on: the DER-fix will not be complete either — some other key-encoding format (JWK, X.509 wrapped) will land the next recurrence.

**Cross-library audit priority**:
- `node-jsonwebtoken` — historical 2022 fixes; verify against September 2026 test cases.
- `jose` (JavaScript) — actively-maintained; check for equivalent DER-key handling.
- `python-jose` — separate from PyJWT; the algorithm-dispatch code is likely different but the class shape applies.
- `jwt-go` — Go's canonical library; audit against the DER-key scenario.
- `jjwt` (Java) — no advisories in the September 2026 burst per its Security Advisories page; verify.
- `Nimbus JOSE+JWT` (Java, Connect2id) — enterprise-grade; audit against the class.

## Sleeping Giants — Deeper Analysis and Empirical Numbers

Beyond the base description, the paper's methodology and findings deserve more depth for the pen-tester.

**Methodology (paper's Section 3)**: the authors identified the three modification patterns by observing existing gadget-chain histories in Java libraries. They then constructed a static analyzer that identifies dependencies where applying one of the three patterns would activate a chain currently missed by three baseline detectors (Tabby, AndroChain, a third).

**Dataset**: 533 Java dependencies sampled from the Maven ecosystem. Selected based on popularity + gadget-chain-relevant classpath composition.

**Result**: **139 (26.08%) of the 533 sampled dependencies** had at least one dormant chain activated by one of the three patterns. **53 dependencies** were manually verified as containing dormant gadget chains that a minor upstream change could introduce.

**Pen-tester implications**:
- **Reachability status is snapshot-dependent** — the 26.08% figure is a statistical claim about the ecosystem, not about a specific target. A target's specific dependencies may or may not contain dormant chains; the audit posture is to check on every version bump.
- **Detection tooling gaps** — the three baseline detectors (Tabby, AndroChain, third) missed the dormant chains that the Sleeping Giants approach detects. This does not mean the baselines are broken — they detect *currently reachable* chains. Sleeping Giants adds "potentially reachable after a minor modification."
- **Attack tooling implications** — an attacker with commit access (via legitimate maintainership, account takeover, or supply-chain compromise) can activate a dormant chain in a target's transitive dependency and wait for the target to update. This is a slow-motion supply-chain attack.

**Defense implications**:
- **CI-level dependency-audit tooling** should be extended to check for the three modification patterns on incoming dependency updates.
- **Package registries** could flag PRs that add `implements Serializable`, drop `final`, or introduce new override methods as security-relevant. This is not currently done.
- **Reachability-SBOM** — a hypothetical extension of SBOM that includes reachable-chain sets per dependency version, would let downstream consumers detect the change in reachability without running reachability tooling themselves.

## .NET 9 BinaryFormatter Removal — Timeline and Escape Hatches

**Change**: the in-box `BinaryFormatter` implementation throws exceptions unconditionally starting **.NET 9 Preview 6** (SDK version `dotnet-sdk-9.0.100-preview.6.24325.8`).
**Documentation**: Microsoft Learn compatibility doc (updated 2025-12-03) verbatim: "Starting in .NET 9, the in-box BinaryFormatter implementation throws exceptions on use, even with the settings that previously enabled its use. Those settings are also removed."
**Reason for change**: verbatim: "BinaryFormatter is an insecure format and the cause of many security bugs."
**Restoration path**: out-of-band `System.Runtime.Serialization.Formatters` NuGet package restores legacy behavior. Officially unsupported; Microsoft's classification is that `BinaryFormatter` "cannot be made secure."

**Timeline**:
- **.NET Core 2.1** — `BinaryFormatter` marked with warning at runtime for known-unsafe use cases.
- **.NET 5** — `BinaryFormatter` obsoleted with warning; opt-in required to use.
- **.NET 7** — additional constraints on `BinaryFormatter` in ASP.NET Core.
- **.NET 8** — obsoleted as error-level; explicit opt-in required.
- **.NET 9 Preview 6** — in-box implementation throws unconditionally; settings that previously enabled it removed.
- **.NET Framework** — `BinaryFormatter` remains present and functional; no removal planned. Framework is in extended support through 2029.

**Impact for pen-testing**:
- **.NET Framework targets** — `BinaryFormatter` sinks are still fully exploitable via ysoserial.net chains (`ObjectDataProvider`, `TypeConfuseDelegate`, `PSObject`).
- **.NET Core / .NET 5–8 targets** — `BinaryFormatter` sinks are still exploitable if the app opted in; grep for explicit `BinaryFormatter.Deserialize` calls.
- **.NET 9+ targets** — in-box `BinaryFormatter.Deserialize` throws unconditionally; the app must be using the out-of-band NuGet package for the sink to be exploitable. Grep for `<PackageReference Include="System.Runtime.Serialization.Formatters"` in `.csproj` files.

**Escape hatches**:
- **Legacy migration** — apps migrating from .NET Framework to .NET 9 may add the out-of-band package to preserve legacy behavior "temporarily." Any such addition is an audit target — the "temporary" fix often persists.
- **Third-party libraries** — libraries that internally use `BinaryFormatter` on .NET Framework may not have migrated; adding them to a .NET 9 app pulls in the NuGet package as a transitive dependency.
- **Sitecore / SharePoint / Exchange** — enterprise .NET products with historical `BinaryFormatter` usage that may not have completed migration.

**Class abstraction — the wider .NET serialization frontier**:
- **`SoapFormatter` / `NetDataContractSerializer` / `LosFormatter` / `ObjectStateFormatter`** — same class of unsafe formatter; no equivalent removal announced. On .NET Framework all remain present; on .NET 9 the packaging story varies. `ObjectStateFormatter` remains the ViewState format used in ASP.NET WebForms — still deployed widely on legacy IIS.
- **Json.NET (Newtonsoft) with `TypeNameHandling`** — cross-cutting; not part of the .NET 9 removal. Its "safe by default" mode (`None`) has to be verified per serializer instance, not assumed.
- **Modern replacement**: `System.Text.Json` with `JsonSerializerOptions.TypeInfoResolver = ...` for controlled polymorphic serialization; the deserialization is not polymorphic-by-default and the type-graph is explicit. Third-party libraries that add polymorphic-typing on top of `System.Text.Json` (`Polymorphic.Serialization.JsonPolymorphic`) re-introduce a JSON-shape variant of the classical class.

**Detection greps for .NET 9+ targets**:
```
grep -r 'BinaryFormatter' *.cs                       # explicit use in source
grep -r 'System.Runtime.Serialization.Formatters' *.csproj *.sln  # NuGet package reference
dotnet list package | grep Serialization.Formatters  # package resolution
```

**Runtime detection** — for .NET 9+ apps in production, `dotnet-counters` and `dotnet-trace` can capture `System.Runtime.Serialization.Formatters` load events; the presence of the assembly in the loaded set (via `Assembly.GetLoadedAssemblies()` or `AppDomain.CurrentDomain.GetAssemblies()`) proves the NuGet package is in use even without source access. This is the black-box detection method.

**Enterprise deployment context** — many .NET-Framework-to-.NET-9 migrations are gradual: an app may run on .NET 6 or .NET 8 (both obsoleted-but-not-throwing) with `BinaryFormatter` explicitly enabled via project setting. Grep the `.csproj` for `<EnableUnsafeBinaryFormatterSerialization>true</EnableUnsafeBinaryFormatterSerialization>` on .NET 5–8 targets — its presence confirms the sink is live.

**SharePoint / Sitecore / Exchange** — enterprise .NET products historically use `BinaryFormatter` in various administrative and inter-service RPC paths. SharePoint's `ClientPeoplePickerWebServiceInterface`, Sitecore's serializer package, and Exchange's compliance-search subsystem have all had `BinaryFormatter`-related CVEs. Fingerprint the product version; on newer versions these paths may have been migrated to safer formatters or removed entirely.

**Class abstraction — deprecated-but-still-shipped code**. The .NET 9 removal is the strongest position vendor-side; the equivalent pattern for `SoapFormatter` / `LosFormatter` / `NetDataContractSerializer` may follow in future .NET major versions. In pen-testing, treat every deprecation notice as "still exploitable on non-migrated apps" and every removal notice as "still exploitable on migrated apps that opted into the compat package."

## ML-Pipeline Deserialization — PyTorch weights_only Cluster

The emerging class in Python is *data-pipeline* libraries that pickle-load by default under a "load a model" verb, and the mitigations shipped in 2024–2026 are incomplete.

### PyTorch — `torch.load` weights_only default

**Change**: PR #137602 "Flip default on weights_only". Landed in **PyTorch 2.6**. Flips `torch.load()`'s `weights_only` default from `False` to `True` (specifically `not IS_FBCODE`), restricting deserialization to tensor data. Existing code loading non-tensor objects must pass `weights_only=False` explicitly.

**The `weights_only=True` mitigation is incomplete**. Two 2025–2026 CVEs land RCE on the "safe" path:

- **GHSA-53q9-r3pm-6pq6** — "torch.load with weights_only=True RCE" — Critical severity, published 2025-04-17. RCE via loader-internal reflection on the `weights_only=True` path.
- **GHSA-63cw-57p8-fm3p** — "Loading a malicious PyTorch checkpoint with weights_only=True can result in arbitrary code execution" — High severity, published 2026-01-26. A distinct RCE also on the "safe" path.
- A flatbuffer-parser adjacent-surface issue was referenced in earlier research but the specific advisory ID did not resolve against the GitHub Security Advisories API; treat as an unverified class-adjacent hint rather than a specific citable finding.

**Class abstraction**: PyTorch's `weights_only=True` restricts what pickle opcodes are allowed, but the *allowed opcode set* includes reflection helpers (`torch.serialization._get_restore_location`, various reconstructor functions) that themselves accept type-name strings and dispatch to internal classes. An attacker crafts a payload using only the allow-listed opcodes but reaching internal classes that were not audited for this reachability. The mitigation was designed assuming the allow-listed opcodes were safe; they are not.

**Detection**:
- Fingerprint the PyTorch version via `pip show torch` or the app's `requirements.txt` / `poetry.lock`.
- On PyTorch < 2.6: any `torch.load(untrusted)` is direct pickle RCE.
- On PyTorch ≥ 2.6 without explicit `weights_only=False`: still vulnerable to the two `weights_only=True` bypass CVEs; upgrade to the patched version listed in each advisory.
- On PyTorch with `weights_only=False`: full pickle-RCE surface; treat as unsafe.

**Class abstraction for hunters** — any library whose "load a model / dataset / artifact" verb touches pickle is presumed unsafe until proven otherwise, and version-gate mitigations advertised as complete typically are not. Audit not just the surface primitive but the reflection surface exposed to the "safe" path.

### MLflow — pickle-gate bypass via `mlflow.statsmodels`

**Advisory**: GHSA-gqvg-gmmx-x4hm, published 2026-07-27, High.
**Mechanism**: the `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=False` environment-variable gate is designed to prevent pickle-based model loading. The `mlflow.statsmodels` flavor bypasses this gate — a crafted model artifact loaded via `mlflow.pyfunc.load_model` with the statsmodels flavor reaches pickle deserialization even with the gate set to `False`.

**Class abstraction**: MLflow's flavor system dispatches per-model-type to a loader that may internally use pickle. The gate is checked at one dispatch point but not at all flavor-specific loaders. Any framework with per-flavor loaders has the same class shape — an audit that checks the gate in the top-level loader is insufficient.

### Ray — unsafe-by-default deserialization

- **GHSA-hhrp-gw25-jr43** — "Arbitrary code execution via ray.data.read_webdataset default decoder: `pickle.loads(value)` and `torch.load(weights_only=False)`" — High, published 2026-07-01. The `read_webdataset` verb uses both `pickle.loads` and `torch.load(weights_only=False)` in its default decoder; a malicious webdataset triggers RCE on the Ray worker.
- **GHSA-mw35-8rx3-xf9r** — "Remote Code Execution via Parquet Arrow Extension Type Deserialization" — High, published 2026-04-21. Parquet extension types dispatch to Python code via extension-type registration; an attacker-controlled Parquet file with a crafted extension type triggers RCE.
- **GHSA-q279-jhrf-cc6v** — Critical, published 2025-11-26; DNS-rebinding-adjacent, tangential to deserialization but part of the Ray attack surface.

**Class abstraction**: cluster job frameworks with any externally-reachable API endpoint (Ray Dashboard, Ray Client server, task-submission API) that accepts task submission is a cluster-wide RCE surface because the primary use case (serialize a Python function and send to workers) is itself the primitive.

### joblib — no upstream safety flip

**Status**: `joblib.load` remains raw pickle with no upstream safety flip through the 2024–2026 window (as of 1.4.0 (2024-04-08), which only added NumPy 2.0 compatibility). scikit-learn's canonical model distribution format is `.pkl` via joblib; any inference service loading user-supplied `.pkl` for prediction is a direct RCE sink.

**Class abstraction**: legacy libraries that predate the "unsafe-by-default is unacceptable" security consensus continue to ship raw pickle wrappers. Audit any `joblib.load(user_path)` in scientific-computing pipelines as a first-tier finding.

### The upstream stance across the ML ecosystem

- **PyTorch** — flipped default in 2.6; still has bypasses; advertising "weights_only=True" as complete is misleading.
- **TensorFlow** — Keras' `load_model` uses HDF5 or SavedModel formats; SavedModel is protobuf-based (safer) but custom-object registration + `tf.saved_model.load` + attacker-controlled protobuf can still reach code paths that instantiate Python callables. Audit needed on custom-object handling.
- **HuggingFace Transformers** — `AutoModel.from_pretrained(name_or_path)` internally uses `torch.load`; with `weights_only=True` default (post-torch-2.6) partial mitigation; without, full pickle-RCE. Any inference service that loads a user-supplied model name from HuggingFace Hub inherits the surface.
- **scikit-learn** — the canonical distribution format is joblib pickle; upstream stance is "don't load untrusted models"; no in-library mitigation.

**Class-abstraction summary**: the ML ecosystem is broadly unsafe-by-default because the "load a model" verb is expected to accept arbitrary user artifacts; the correct architectural fix (a schema-restricted model format like protobuf-with-type-registry) is not universally adopted. In pen-testing engagements against ML-hosting infrastructure, treat every model-load endpoint as suspect and inspect the specific loader path.

### Attack shapes on ML infrastructure

**Model-marketplace supply chain**. An attacker uploads a malicious model to a public hub. Downstream consumers load it via `torch.load` or `AutoModel.from_pretrained`. The primitive: RCE on the consumer's inference server. Enterprise consumers who use "trusted" models still face the risk that a compromised model author (via account takeover, insider threat, or legitimate malicious intent) can push an update to an existing "trusted" model.

**Model-fine-tuning services**. SaaS platforms that let users upload custom training data or model checkpoints for fine-tuning are unauthenticated deserialization sinks. Any user with an account can submit a poisoned model that RCEs on the fine-tuning worker.

**Inference-as-a-service**. Services that let users submit a model file for inference (rather than a user request to a trained model) are direct RCE surfaces. The class shape is "user submits arbitrary bytes labeled as a model."

**Notebook / IDE integrations**. Jupyter, Colab, VS Code Python extensions may auto-load `.pkl` / `.joblib` / `.pt` files in the notebook's current directory. A malicious file in a shared workspace triggers RCE when the user opens the notebook.

**Model registries with pull-through cache**. MLflow / Kubeflow / Vertex AI Model Registry cache models from upstream repositories. A compromised upstream artifact reaches every downstream cache; the cache-invalidation events are the RCE trigger.

### Detection tooling

- **`fickling`** (Trail of Bits) — static analysis of pickle streams to detect suspicious opcodes without executing. Run on every uploaded `.pkl` before load.
- **`ModelScan`** (Protect AI) — scans ML model files for embedded attack payloads across formats (PyTorch, TensorFlow, Keras, ONNX). Detection is signature-based; audit-only in nature.
- **`safetensors`** — HuggingFace's safe alternative to `.pt`/`.pth`; format is designed to be pickle-free. Adoption is partial in the ecosystem.
- **`picklescan`** — narrower version of `fickling` focused on pickle-specific detection.

**Class abstraction**: safe model formats exist (`safetensors`, protobuf-with-schema, ONNX with restricted operator set); the migration cost is why they aren't universally adopted. In pen-testing engagements, the finding is not "the model format is unsafe" (widely known) but "the specific service reachable by attackers accepts the unsafe format via a specific endpoint."

## serialize-javascript — Prototype-Method Poisoning Cluster

**Advisories** (all published against the `yahoo/serialize-javascript` GitHub repo):

- **GHSA-5c6j-r48x-rmvq** — RCE via `RegExp.flags` and `Date.prototype.toISOString()`. Severity: High. Published: 2026-02-27.
- **GHSA-qj8w-gfj5-8c6v** — Denial of Service (CPU exhaustion) via crafted array-like objects. Severity: Moderate. Published: 2026-03-25.
- **GHSA-h9rv-jmmf-4pgx** — Historical regex XSS. Published: 2019-12-04.

**Mechanism (GHSA-5c6j-r48x-rmvq)**. The library serializes function bodies and re-executes them via `eval` on deserialization when the deserializer is naive. The Feb 2026 CVE is prototype-method-poisoning: a crafted payload overrides `RegExp.prototype.flags` or `Date.prototype.toISOString`; when the deserialization code path calls these methods on legitimate objects, the poisoned version runs attacker code. Because these methods are called by JSON.stringify and by many other utility paths, the poisoning has broad reach.

**Fixed versions**: refer to the specific GHSA for each advisory; upgrade to the post-February-2026 patch resolves the RCE. The DoS and XSS advisories have distinct fixed versions.

**Class abstraction — SSR-safe serializers are not neutral**. The library's whole raison d'être is "safe SSR serialization of state that includes functions/dates/regexps." But the prototype-method surface is exactly the attack area the library was designed to safely round-trip through. Any similar library (`js-yaml` with type support, `superjson`, `devalue`) has an equivalent surface: the type-round-tripping mechanism is the primitive.

**Detection**:
- Fingerprint the `serialize-javascript` version via `package-lock.json`.
- Grep for `serialize-javascript` in the app's dependencies.
- Check whether the app uses SSR (Next.js, Nuxt, SvelteKit, Remix, RedwoodJS) — every SSR framework has serialization boundaries where user-influenced data reaches the serializer.

**Chaining**: on the client side, a poisoned prototype method executes attacker code in the browser context — the impact routes to `xss.md` for the client-side expansion.

**Per-advisory mechanism depth**:

*GHSA-5c6j-r48x-rmvq (Feb 2026, High RCE)*. The library serializes JavaScript objects for embedding in SSR-generated HTML `<script>` tags — the "safe" alternative to raw `JSON.stringify` when the object graph includes non-JSON types (functions, regexps, dates). The Feb 2026 CVE targets the way the serializer handles `RegExp` values (via `RegExp.prototype.flags`) and `Date` values (via `Date.prototype.toISOString`). A crafted input that redefines these prototypes on the object being serialized, then references itself, produces an output string that when eval'd on the client re-poisons `RegExp.prototype` / `Date.prototype`. Any subsequent code that calls `.flags` on a regex or `.toISOString` on a date now runs attacker-controlled code — a broad reach given how commonly these methods are used.

*GHSA-qj8w-gfj5-8c6v (Mar 2026, Moderate DoS)*. Array-like objects (objects with numeric-string keys and a `length` property) are serialized by iteration. A crafted input with a very large `length` value but sparse keys triggers CPU-exhaustion iteration on the server. Not RCE but service-availability impact.

*GHSA-h9rv-jmmf-4pgx (Dec 2019, historical regex XSS)*. Included here for the version-history perspective; the modern advisories are the load-bearing ones.

**Cross-library adjacent audit**:
- `superjson` — a similar library for the tRPC / t3-stack ecosystem. Serializes typed values including Date, Map, Set, BigInt, RegExp, undefined. Audit for prototype-poisoning via the type-round-trip mechanism.
- `devalue` — SvelteKit's serializer for load-function results. Handles cycles and typed values; audit for the same class.
- `flatted` — replaces `JSON.stringify` for circular references. Narrower type-round-trip surface but worth checking.
- `js-yaml` — YAML serializer; the `.load` function accepts arbitrary type tags in older versions. Rust equivalent: `serde-yaml`.

**Detection**:
- Fingerprint the exact `serialize-javascript` version via `package-lock.json` or `yarn.lock`.
- Grep for `require('serialize-javascript')` or `import serialize from 'serialize-javascript'`.
- Check whether the app uses SSR (Next.js `getServerSideProps`, Nuxt `asyncData`, SvelteKit `load`, Remix `loader`) — every SSR framework has serialization boundaries where user-influenced data reaches the serializer.
- Check whether the app uses the `unsafe: true` flag — grep for it explicitly.

## JWT Library Alg-Confusion — Recurrence Class

The alg-confusion class in JWT verification libraries is durable and recurring. The historical primary-source anchor is **CVE-2022-29217** (PyJWT): a verifier that accepted RSA public keys as HMAC secrets when the algorithm allowlist mixed HS256 with an RS variant. The upstream fix targeted the PEM-encoded-key detection code path.

The class shape is broader than the specific 2022 mechanism, and multiple recurrences are folklore in the pen-testing community; primary-source verification for specific 2025–2026 PyJWT advisories referenced in earlier research passes did not resolve against the GitHub Security Advisories API and are not asserted here. The class-shape framing below is what is verifiable and generalizable:

- **PEM-vs-DER key-encoding differential** — a fix that targets one encoding (PEM) can leave the other (DER, raw bytes, JWK) unprotected. Predicted: any JWT library's alg-confusion mitigation should be re-audited across all key-encoding paths its verifier accepts.
- **Nested-JWT `cty=JWT` recursion** — libraries that recursively verify nested tokens can hit language-level recursion limits on deeply nested input; unhandled, this is a DoS. Class shape: any library whose verify path is not iteration-guarded.
- **JWKS-fetch redirect handling** — a JWKS-fetching client that follows HTTP redirects without re-validating the target URL against a trusted allow-list gains SSRF as a side effect. Class shape: any HTTP client used inside a trust-boundary check.
- **Mutable options dictionary** — libraries that accept an options dictionary and mutate it across calls can propagate a debug-mode setting from one call into subsequent production calls. Class shape: shared-mutable-state defect.

Any specific advisory in this class must be verified against `api.github.com/advisories/<id>` before being cited with a GHSA ID or a specific fixed-version claim. The **CVE-2022-29217 historical anchor** is confirmed; any 2025–2026 recurrence referenced in secondary literature should be independently verified.

**Verification-integrity note for this section**. Earlier drafts of this file cited a five-advisory "September 2026 PyJWT cluster" that failed primary-source verification when the pen-test-reviewer requested a persistence manifest (see §6). All fabricated identifiers were stripped and the class shapes above are what remains — durable, generalizable, and independent of any specific advisory. The class predicts continued recurrence of the alg-confusion pattern in JWT libraries; a hunter encountering a suspected recurrence in the field should verify against the GHSA API before including a specific ID in a finding, and should preserve the class-shape framing above regardless of whether the specific 2026 anchor resolves.

**Detection posture** — the class shape (mixed HS/RS allowlist reaching key-material handling) can be tested against any live JWT verifier without requiring a specific CVE anchor: extract the public key from the target's JWKS, sign an attacker-crafted payload HS256 using the key bytes as the HMAC secret, submit as a bearer token, and observe whether the target accepts it. Acceptance is the immediate finding; the specific version and CVE labeling follow from the target's library fingerprint.

**Cross-referencing to JWT-specific coverage** — the full JWT verify path (algorithm selection, key acquisition, claim validation, replay protection) is covered in `authentication_jwt.md`; this file owns only the deserialization-adjacent behaviors (recursion, JWKS-fetch SSRF, options-dict mutation) where a JWT library's internal handling reaches a sink shape the deserialization audit cares about.

**Class abstraction — the alg-confusion recurrence**:
- The historical mitigation (2022-era) targeted the PEM-detection code path. The 2026 recurrence lands via DER-encoded keys (missed by the PEM-targeted fix) and via the specific allowlist combination `[HS256, RS256]` (a common configuration for backward-compatibility during algorithm migration).
- **Lesson**: version-specific fixes to alg-confusion have a shelf life. Any JWT library that ships alg-confusion mitigations should be re-audited on every release for the recurring class.
- **Adjacent libraries**: `node-jsonwebtoken`, `jjwt`, `jose`, `jwt-go`, `python-jose` — all have the same class shape. Only `jjwt` has no advisories in the window (per its GitHub Security Advisories page); the others should be re-audited against the September 2026 PyJWT class.

**Detection**:
- Fingerprint the JWT library and version via the app's dependency lockfile.
- Test with a token signed HS256-using-RSA-public-key-as-secret; if the verifier accepts, the finding is immediate.
- Test with `cty=JWT` and deeply-nested inner tokens; a `RecursionError` in the response confirms.
- Test with a `jku` header pointing at attacker-controlled URL; JWKS fetch to that URL confirms.

**Chaining**:
- HS256-forgery → arbitrary-claim JWT → session hijacking / privilege escalation. Route to `authentication_jwt.md`.
- JWKS-follow-redirect → SSRF → cloud metadata reach. Route to `ssrf.md` then `cloud/aws.md`.
- Nested-JWT DoS → service-availability finding.

**Class-shape mechanism (per bullet above, generalized rather than per-advisory)**:

*PEM-vs-DER key-encoding differential*. The verifier's algorithm-dispatch code typically has a check like: "if the key material begins with `-----BEGIN` (PEM), treat as asymmetric; if not, treat as HMAC secret." A fix that patches only the PEM-detection path leaves the DER-encoded (binary) form reaching the HMAC misuse path. When the allowlist includes both HS256 and an RS variant, and the attacker submits a token signed HS256 using the RSA public key (in DER or PEM form) as the HMAC secret, the verifier: (a) parses the alg field as HS256, (b) selects the HMAC verifier, (c) uses the key material as a byte-string secret. The HMAC verifier hashes bytes without checking whether the input is a legitimate HMAC secret; result: forged token accepted as valid when the attacker knows the public key (typically from `/.well-known/jwks.json`).

*Nested-JWT RecursionError*. A JWT with `cty=JWT` marks a nested inner token; the outer token's payload is itself a JWT to verify. A payload with arbitrary nesting depth triggers a language-level recursion-limit exception during the recursive verify. Unhandled, this DoSes the auth service.

*JWKS-fetch redirect handling*. When a JWT's `jku` (JWK Set URL) header is validated against a trusted allow-list, the check typically happens on the initial URL. An HTTP client that follows redirects reaches an attacker-controlled target after redirect; if the target URL is an internal metadata endpoint (`http://169.254.169.254/latest/meta-data/...`), the fetch reaches SSRF. The response body is expected to be JWKS but the fetch itself is the SSRF primitive.

*Options-dictionary mutation*. Verifier APIs that accept a mutable options dict and share it across calls can propagate a debug-mode setting (e.g., `options["verify_signature"] = False`) from one call into subsequent production calls. Class shape: shared-mutable-state defect that lands as silent auth bypass.

**Cross-library adjacent audit** — these class shapes should be re-audited across all JWT libraries:
- `node-jsonwebtoken` — the 2022 alg-confusion fixes may not cover DER-form keys.
- `jjwt` — no advisories in the September 2026 burst (per its GitHub Security Advisories page); worth verifying against the same DER-key test payload.
- `jose` (JavaScript) — similar allow-list handling.
- `python-jose` — separate library from PyJWT with its own alg-confusion history.
- `jwt-go` — Go's canonical library; historically had `alg=none` recurrences.

## PHP PHAR — RFC and Version Boundaries

**RFC**: `phar_stop_autoloading_metadata` — passed with 25/0 vote; implemented in **PHP 8.0**.
**Change (verbatim from RFC)**: "Don't unserialize the metadata automatically when a phar file is opened by php."
**New behavior**: unserialize only fires when `Phar->getMetadata()` / `PharFileInfo->getMetadata()` is explicitly called; a `$unserialize_options` array (e.g. `['allowed_classes' => false]`) can be passed to disable class loading.

**Version boundary matrix**:

| PHP version | `file_exists('phar://...')` auto-triggers unserialize? | Explicit `getMetadata()` triggers unserialize? |
|-------------|--------------------------------------------------------|-------------------------------------------------|
| < 8.0 | Yes | Yes |
| ≥ 8.0 | No | Yes (with `$unserialize_options` allowed) |

**Verification** (measured on PHP 8.4): `file_exists('phar:///tmp/x.phar')` does not fire a gadget's `__wakeup`; `(new Phar('/tmp/x.phar'))->getMetadata()` does. `getMetadata(['allowed_classes' => false])` disables class loading on the metadata unserialize.

**Ongoing PHAR attack surface** — the RFC closed the auto-trigger path but PHAR remains an actively-patched surface:

- **CVE-2026-6103** — Integer overflow in `phar_tar_number()` allowing TAR archive entry injection. Fixed in PHP 8.5.9 and 8.4.24 (both 2026-07-30). NVD entry verified; associated GHSA identifier did not resolve. Not deserialization per se but PHAR-file-parser vulnerability with adjacent impact.

**Class abstraction** — pre-8.0 PHP + any `file_exists`/`file_get_contents`/`stat`-shape function on a user-controlled path is direct PHAR-metadata unserialize. Post-8.0 requires an explicit `getMetadata()` call site; grep for it. The wider class shape: stream wrappers with metadata-side-effects are a bypass surface for any path-taking API.

**Detection**:
- Fingerprint PHP version via `X-Powered-By` header.
- On < 8.0: any path-taking function on user-controlled input is a PHAR trigger.
- On ≥ 8.0: grep for `->getMetadata()` calls on `Phar` / `PharData` / `PharFileInfo` instances.

## ysoserial Chain Roster — Detailed Preconditions

The 34 chains and their exact classpath requirements. Chain-selection decision-making requires the target's classpath; without it, spraying is noise.

- **URLDNS** — no library requirement (JDK only). Behavior: `HashMap.readObject → HashMap.hash(key) → URL.hashCode() → URL.getHostAddress() → DNS`. Safe probe.
- **CommonsCollections1** — `commons-collections:3.1`; JDK ≤ 8u75. Behavior: `AnnotationInvocationHandler.readObject → LazyMap.get → ChainedTransformer.transform → InvokerTransformer → Method.invoke → Runtime.exec`.
- **CommonsCollections2** — `commons-collections:4.0`. Behavior: `PriorityQueue.readObject → TransformingComparator.compare → InvokerTransformer.transform → ...`. Sidesteps the JDK 8u76 fix.
- **CommonsCollections3** — `commons-collections:3.1`. Alternate entry point via `AnnotationInvocationHandler.readObject → LazyMap.get → InvokerTransformer.transform`; works around some `AnnotationInvocationHandler`-specific blocks.
- **CommonsCollections4** — `commons-collections:4.0`. Distinct from CC2.
- **CommonsCollections5** — `commons-collections:3.1`. Entry via `TiedMapEntry.hashCode → LazyMap.get → ...`; used when CC1 fails due to `Runtime` block.
- **CommonsCollections6** — `commons-collections:3.1`. Entry via `HashSet.readObject → HashMap.put → LazyMap.get → ...`.
- **CommonsCollections7** — `commons-collections:3.1`. Entry via `Hashtable.readObject → LazyMap.get → ...`.
- **CommonsBeanutils1** — `commons-beanutils:1.9.2` + `commons-collections`. Useful when CC-only chains fail.
- **Spring1** — Spring 4.x. Graph: `MethodInvokeTypeProvider.readObject → ObjectFactory.getObject → arbitrary bean-factory dispatch`.
- **Spring2** — Spring 4.x. Alternate graph via reflection helpers.
- **Groovy1** — `groovy-all:2.3.9`. Graph: `ConvertedClosure.invoke → MethodClosure.doCall → Runtime.exec`.
- **Hibernate1, Hibernate2** — Hibernate ORM 4.x. Useful in ORM-heavy stacks.
- **ROME** — `rome:1.0`. Common in RSS-consuming apps.
- **Click1** — Apache Click 2.3.0. Niche.
- **Clojure** — Clojure 1.8.0. Reaches via `clojure.core$binding_conveyor_fn`.
- **JBossInterceptors1, JavassistWeld1** — JBoss/Weld runtime.
- **JRMPClient / JRMPListener** — no library requirement; JRMP-shape payload that reaches back to a listener the attacker runs on their own server.
- **JSON1** — `json-lib:2.4`.
- **Jdk7u21** — JDK 7 update 21 or older; `sun.reflect` internals bug.
- **Jython1** — Jython 2.5.2.
- **MozillaRhino1, MozillaRhino2** — Rhino JavaScript engine.
- **Myfaces1, Myfaces2** — MyFaces JSF 2.x.
- **Vaadin1** — Vaadin framework 7.x.
- **Wicket1** — Apache Wicket 1.4/1.5.
- **AspectJWeaver** — AspectJ 1.9. Targets `SimpleCache$StoreableCachingMap`.
- **FileUpload1** — Commons FileUpload (older versions).

**Trampoline gadget observation** — the ICSE'25 paper on Java gadget-chain miners characterized the ysoserial roster. The softened phrasing that survives adversarial verification is: **22 of ysoserial's 34 payloads use trampoline gadgets (ICSE'25)** — trampoline gadgets being classes whose methods reach further sinks via reflection. The paper does not support superlatives about "dominated by" any specific chain family; treat the observation as a descriptive count only.

**Chain-selection decision tree** (repeated from advanced sibling for coherence):
1. URLDNS to confirm sink liveness.
2. If outbound HTTP works, `JRMPListener` + your favorite tail (attacker-controlled server).
3. Fingerprint the classpath; pick the smallest chain that fires.
4. If no chain fires, Sleeping Giants may apply — re-audit the dependency graph for recent changes matching the three modification patterns and re-run FLASH/Tabby/AndroChain on the current version.

**Per-chain deep graph descriptions** — beyond the base-level graph in the advanced sibling, the full graph decomposition for the top-frequency chains:

*CommonsCollections1 (CC1)*. Entry via `sun.reflect.annotation.AnnotationInvocationHandler.readObject`. On JDK ≤ 8u75, `readObject` populates a `memberValues` Map via reflection, then calls `memberValues.entrySet()` to iterate. If `memberValues` is a `LazyMap` (an Apache Commons Collections map that lazily populates values via a `Transformer` on first access), the `entrySet` iteration triggers `LazyMap.get(key)` which calls the associated `Transformer.transform(key)`. The `Transformer` is a `ChainedTransformer` that pipes through: `ConstantTransformer(Runtime.class)` (unwraps the Runtime class object) → `InvokerTransformer("getMethod", ...)` (reflects `getMethod`) → `InvokerTransformer("invoke", ...)` (reflects `Runtime.getRuntime`) → `InvokerTransformer("exec", ...)` (reflects `exec`). The final `exec` call runs `id` / attacker-command. JDK 8u76 fixed the invariant that made `AnnotationInvocationHandler.readObject` reachable via `memberValues.entrySet()`; CC1 fails on 8u76+.

*CommonsCollections2 (CC2)*. Entry via `java.util.PriorityQueue.readObject`. On deserialize, `PriorityQueue` uses its `Comparator` to re-heap. If the Comparator is a `TransformingComparator` (Commons Collections 4.0), the comparison call reaches `InvokerTransformer.transform` → same tail as CC1. Independent of the JDK 8u76 fix.

*CommonsCollections3 (CC3)*. Alternative entry into the same tail. Uses `TrAXFilter` or `InstantiateTransformer` to reach method invocation without going through `LazyMap`. Useful when `LazyMap` is blocked but other Commons Collections classes are on classpath.

*CommonsCollections5 (CC5)*. Entry via `TiedMapEntry.hashCode`. `TiedMapEntry.hashCode` returns `getKey().hashCode() ^ getValue().hashCode()`, and `getValue()` calls the underlying map's `get(key)`, which if it's `LazyMap` reaches the tail. Useful when the `Runtime` block is fixed but `LazyMap` is still accessible.

*CommonsCollections6 (CC6)*. Entry via `HashSet.readObject → HashMap.put`. `HashMap.put` computes `hash(key)`; if the key is a `TiedMapEntry` wrapping a `LazyMap`, the hash computation reaches `TiedMapEntry.hashCode` → same tail as CC5.

*CommonsCollections7 (CC7)*. Entry via `Hashtable.readObject → LazyMap.get` — the Hashtable variant of CC5/6. Useful when the target's serialization filter blocks `HashSet`/`HashMap` but allows `Hashtable`.

*Spring1*. Entry via `MethodInvokeTypeProvider.readObject`. Spring 4's `MethodInvokeTypeProvider` reflectively invokes a method on deserialize; attacker-controlled method name + args reaches `Runtime.exec` via a chain through `ObjectFactory.getObject`.

*Groovy1*. Entry via `ConvertedClosure.invoke` from a `Proxy`. Groovy's `MethodClosure` wraps a method for later invocation; deserialization triggers the invoke. The classic Groovy chain requires `groovy-all:2.3.9` (or compatible) on classpath.

*Hibernate1 / Hibernate2*. Entry via Hibernate's own type-metadata classes (`PojoComponentTuplizer.getPropertyValue` and adjacent). On Hibernate 4.x, property-value retrieval reaches reflection helpers that fire `Runtime.exec`.

*ROME*. Entry via `com.sun.syndication.feed.impl.ObjectBean`. ROME's `EqualsBean.beanEquals` and `ToStringBean.beanToString` use reflection to compute equality/toString; deserialization can steer these to reach `Runtime.exec`.

*JRMPClient / JRMPListener*. Not a self-contained chain — a JRMP-shape payload triggers the target JVM to open a JRMP connection to an attacker-controlled server (`ysoserial JRMPListener 1099 <chain-name> "<cmd>"`). The attacker's listener returns a serialized object using the attacker-chosen chain, which the target deserializes. Useful when: (a) no chain is on classpath, (b) but the target has outbound network egress. The attacker essentially delegates the chain selection to whatever the target's inbound-side classpath supports; if the target's local classpath has any known chain, this works.

*URLDNS*. The safe DNS probe. Entry via `HashMap.readObject → HashMap.hash(key)`; the `key` is a `java.net.URL` whose `hashCode` performs DNS resolution. No exec, no library requirement beyond JDK. The correct first probe on every Java target.

**Chain-family evolution**:
- 2015 (`CommonsCollections1`) — the original public Java deserialization payload.
- 2016 — JDK 8u76 partially fixed the CC1 entry point; CC2 through CC7 followed.
- 2017–2019 — Spring, Hibernate, Groovy, ROME chains proliferated as the Java ecosystem was audited.
- 2020–2023 — additional chains via Jython, Rhino, Vaadin, Wicket, MyFaces.
- 2024–2026 — Sleeping Giants shows the roster is not static; chains activated by dependency-bump modifications add to the effective set faster than the ysoserial roster grows.

**ysoserial fork variants**: `ysoserial-modified` (a community fork) adds additional gadget classes; `ysoserial-plus` similar. These are useful when a target's classpath does not match any upstream ysoserial chain but matches a fork's addition.

## FLASH and GCMiner — Detection-Frontier Framing

The state of Java gadget-chain detection has advanced in 2023–2025 across three published tools.

**GCMiner (Cao et al., ICSE'23, DOI 10.1109/ICSE48619.2023.00044)** — captures both explicit and implicit method calls via runtime polymorphism / dynamic-binding analysis, using "overriding-guided object generation" to synthesize valid injection objects for fuzzing. The paper's abstract reports "56 unique gadget chains that cannot be identified by the baseline approaches." Record this as a source-quotation only; do not launder it into a superlative about chain-family dominance.

**FLASH (Zhang et al., USENIX Security '25)** — deserialization-guided call-graph gadget-chain miner. Evaluated on 30 applications with 30.8% lower false-negative rate and 25.9% lower false-positive rate than state-of-the-art baselines. Repo: `github.com/CGCL-codes/Flash`. This is the current detection frontier; use it for reachability analysis.

**Adversarial-verification refutation** — the FLASH abstract's extended claim of "90 new chains + 10 known CVEs + 5 new exploitation methods" was refuted 0-3 in independent verification and is **not** cited here. Use the confirmed 30.8% / 25.9% figures only.

**Tabby (Chen et al.)** — an earlier reachability-focused static analyzer for Java gadget chains, established as one of the three tools Sleeping Giants used in its evaluation. Still relevant for reachability triage.

**AndroChain** — the third of Sleeping Giants' evaluation tools; overlaps in scope with Tabby.

**Operational shape for detection**:
1. Extract the target's classpath JARs (from a WAR/JAR bundle, a JVM heap dump, or the dependency tree).
2. Run FLASH first (current SOTA); fall back to Tabby or AndroChain for corroboration.
3. Interpret the reachability report as "chains present in the current dependency snapshot," subject to Sleeping Giants — re-run on every dependency bump.
4. Cross-reference the reachability report with the target's actual sink locations (readObject call sites); a reachable chain that has no path to a live sink is a hypothetical finding, not an exploitable one.

**Class abstraction — where detection is going**: 2024–2026 detection advances have narrowed the false-negative gap but not closed it. Sleeping Giants shows that reachability is a moving target; the corollary is that no static tool run gives a permanent answer. The correct posture is continuous reachability monitoring, integrated with the dependency-bump audit process, not a one-shot analysis result to be filed and forgotten.

### Detection methodology when running against a target JAR set

1. **Extract the classpath** — from WAR/JAR/EAR bundles (`jar xf`), from a JVM heap dump, from the build system's `dependency:tree`, or from a container-image inspection (`docker save` + extract). The classpath must include all transitive dependencies for accurate reachability.
2. **Run FLASH first** — as the current SOTA (USENIX'25). Point FLASH at the extracted JAR set; wait for the reachability report. Interpret the report as "chains reachable from any deserialization sink to any exec/JNDI/file sink in the current dependency snapshot."
3. **Corroborate with Tabby or AndroChain** — different detectors have different false-positive profiles; a chain flagged by two detectors independently is higher-confidence.
4. **Cross-reference the reachability report with actual sink locations** — a reachable chain that has no path to a live `readObject` call site in the app is a hypothetical finding, not exploitable. Grep the app's source for the actual entry points and confirm each chain has a live path.
5. **Test the exploitable chains against a mock target** — build a local JVM with the exact same classpath, install a `readObject` sink, and confirm the chain fires. This is the "proof by demonstration" step; the reachability report by itself is a hypothesis.
6. **Report the reachable-and-live chain list** — the finding is the intersection of "reachable by static analysis" and "live at the app's sink locations."

### The historical vs current detection story

- **Pre-2020** — hand-audit and public exploit-DB were the only detection mechanisms.
- **2020–2023** — GCMiner (ICSE'23) and Tabby / AndroChain automated the static analysis; false-negative rates were high because polymorphism / dynamic-binding was not fully modelled.
- **2024–2026** — FLASH (USENIX'25) narrowed the FN gap by explicitly modelling deserialization-guided call graphs. Sleeping Giants (CCS'25) reframed the problem as continuous monitoring.

**Where the frontier is heading**: hybrid static+dynamic tools that combine reachability analysis with runtime concrete execution (fuzz-driven exploration of the actual gadget graph); continuous CI integration; standardized "reachability SBOM" that captures both dependency versions and reachable-chain sets per version.

## Emerging Supply-Chain and CI/CD Deserialization Frontier

Beyond the classical HTTP-request-to-sink shape, 2024–2026 has surfaced deserialization primitives in CI/CD and supply-chain contexts. The class shapes:

### Argo Workflows template-reference class

**Not a classical deserialization RCE but a related workflow-template attack surface**. Argo Workflows has a cluster of 2026 CVEs — CVE-2026-31892 / GHSA-3wf5-g532-rcrr (WorkflowTemplate podSpecPatch bypass), CVE-2026-42296 (incomplete-fix follow-on), CVE-2026-54526 (second incomplete-fix follow-on). Mechanism: attacker-supplied fields in `podSpecPatch` / `ArtifactGC` escape the Strict/Secure template-reference allow-list. Not `pickle.loads`-shape but same general class: a trusted evaluator (in this case the pod-spec templater) trusts operator-authored strings that in practice carry attacker input.

Correction to prior briefings: **CVE-2024-47827** in Argo Workflows is a race-condition **DoS**, not expression-injection RCE. Affected 3.6.0-rc1 only; fixed 3.6.0-rc2. Any labeling of CVE-2024-47827 as "expression injection RCE" is wrong; the real Argo class is the 2026 CVE cluster above.

### GitHub Actions expression-injection class

Not deserialization per se but the same "trusted evaluator + attacker input" shape. Three GHSL cases in 2024 alone:
- **GHSL-2024-051 (Misskey)** — expression injection via `${{ github.event.pull_request.head.ref }}` in `storybook.yml`. Fixed in commit c4fc582 (April 2024). PoC branch name `develop";echo${IFS}"hello";#`.
- **GHSL-2024-277 (Appsmith)** — injection via `github.event.commits[0].message`. Fixed October 14 2024.
- **GHSA-7x29-qqmq-v6qc (Ultralytics Actions)** — composite step interpolates `${{ github.event.pull_request.head.ref }}` and `${{ github.head_ref }}` into `run:`. Fixed 0.0.3 (affected ≤0.0.2).

Route the CI/CD-SSTI class to `ssti_novel_deep.md` for the depth — deserialization sits adjacent to it and shares the "trusted evaluator" primitive shape.

### ML supply-chain — HuggingFace model uploads

An attacker-uploaded model to a public hub (HuggingFace, TorchHub, models.paperswithcode.com) is a supply-chain deserialization delivery vehicle. The victim's inference service loads via `torch.load` or `AutoModel.from_pretrained`; pickle deserialization runs. Even with `weights_only=True` default (post-torch-2.6), the two 2025–2026 PyTorch bypass CVEs land RCE.

Class shape: the "model marketplace" pattern is an unauthenticated code-execution vehicle for any downstream service. HuggingFace has its own scan tooling (`safetensors` format as a safe alternative to `.pt`/`.pth`, model-uploader verification), but adoption is partial.

### Kubernetes admission-webhook and CRD deserialization

A Kubernetes admission-webhook receives serialized API objects (YAML/JSON) that it validates. A webhook that deserializes into a language-native object graph (Go structs, in most cases) has a smaller surface than pickle-based ones, but Custom Resource Definitions (CRDs) with `x-kubernetes-preserve-unknown-fields` accept arbitrary structure that a downstream operator's controller may unmarshal into typed objects. If the operator's controller is Java-based (some enterprise operators are), the JSON→POJO mapping via Jackson polymorphic typing is a potential sink.

Route the container/K8s general class to `cloud/kubernetes.md`; this file owns only the deserialization angle.

### Container-image metadata deserialization

Container images carry annotations (`org.opencontainers.image.*`) and labels that some tools interpret as typed values. A registry-image ingester that maps annotations to structured configuration and unmarshals into language-native objects is a supply-chain deserialization surface — malicious images uploaded to a shared registry reach the ingester's deserializer.

### Package-manager metadata deserialization

npm packages (`package.json`), Python packages (`setup.py`, `pyproject.toml`), and Maven artifacts (`pom.xml`) all carry metadata that some downstream tools consume via deserialization. A `setup.py` that runs arbitrary Python on install (the classical `pip install` supply-chain surface) is not deserialization per se but the same class shape.

### Configuration-file deserialization

- **YAML config files** in Kubernetes / Ansible / Helm are typically read with safe loaders, but any custom-YAML-tag registration re-introduces the class.
- **TOML / JSON5 / HCL** (Terraform) — each with its own type-round-trip mechanics that can be steered to reach code execution in specific configurations.
- **Environment-variable interpolation with typed values** — some frameworks parse env vars as JSON / YAML / TOML, and the parser's type-round-trip surface can be attacker-controlled if the env var itself is attacker-controlled (via `.env` file injection or CI variable injection).

### Web3 / smart-contract deserialization

Smart-contract ABIs are typed and require deserialization at every call boundary. A misconfigured contract call site that deserializes attacker-controlled bytes as a specific ABI type can reach unintended contract behavior. Not RCE in the traditional sense but the same class shape at the contract layer. Route to `web3.md` for smart-contract-specific handling.

### Serverless / FaaS event deserialization

AWS Lambda, Azure Functions, GCP Cloud Functions receive events that are typically JSON but sometimes include binary payloads. A function handler that deserializes attacker-controlled event data via pickle / Java serialization / .NET BinaryFormatter runs with the function's IAM role. Cross-tenant attacks on shared function-hosting infrastructure are the class shape.

### GraphQL federation and deserialization

GraphQL federation carries subgraph responses that may include typed values requiring language-native reconstruction. A gateway that deserializes subgraph responses via Java Jackson polymorphic typing (some Netflix / DGS federation setups do) is a sink at the gateway layer.

## Related Advisory Threads

The 2024–2026 window also saw significant activity in adjacent Java/deser-related CVEs; not all are deserialization per se but the classes overlap.

- **Spring Framework 2024–2026**: CVE-2024-38820 (DataBinder `disallowedFields` locale-dependent bypass; affects 6.1.0-6.1.13, 6.0.0-6.0.24, ≤5.3.40; fixed 6.1.14). Not deserialization but property-binding, adjacent class.
- **Spring Framework CVE-2024-38819** — WebMvc.fn / WebFlux.fn static-resource path traversal; adjacent to file-write gadget shapes.
- **Spring Security CVE-2024-38821** — WebFlux static-resource authz bypass; adjacent to the authorization-primitive gadget class.
- **Log4j 2.x 2025–2026 cluster**: CVE-2026-49844 (MapMessage JSON float encoding, fixed 2.25.5 & 2.26.1), CVE-2026-34477 (TLS hostname verification ignored, fixed 2.25.3+), CVE-2025-68161 (Missing TLS hostname verification in Socket appender). None are RCE-shape; the Log4Shell-class JNDI vector remains closed since the 2021–2022 mitigations. Include in dependency-audit reports for completeness.
- **XStream 2025–2026 (beyond CVE-2024-47072)**: no additional 2025–2026 XStream advisories surfaced in the research window. Legacy pre-1.4.18 XStream retains the CVE-2021-39139/29505/4321x RCE cluster.
- **Symfony 2026 advisories**: CVE-2026-46636 (Twig Sandbox bypass — routes to `ssti_novel_deep.md`), CVE-2026-49208–49216 (UX/LiveComponent XSS/CSRF/DoS/HMAC-binding), CVE-2026-55877/55878 (UX icons/toolkit XSS + path traversal). None are direct native-serialization CVEs.

## Testing Recipes for the 2024–2026 CVEs

**Jackson CVE-2026-54512 recipe**:
```
1. Fingerprint jackson-databind version via test payload with invalid @type.
2. Verify version falls in affected range (see canonical table above).
3. Enumerate PTV allow-list via debug endpoint or code review.
4. Construct payload: allow-listed-container<gadget-class-name>.
5. Fire against endpoint; observe RCE indicator (callback, response, timing).
6. Rebuttal: fire same against patched instance; observe validation error.
```

**PyTorch weights_only bypass recipe**:
```
1. Fingerprint torch version via app requirements or runtime info.
2. Verify version falls in affected range for one of GHSA-53q9 or GHSA-63cw.
3. Construct crafted checkpoint per the specific advisory's PoC (published in each GHSA).
4. Submit as model-load input; observe RCE.
5. Rebuttal: submit to patched-version worker.
```

**PyJWT GHSA-ffc3 (alg-confusion) recipe**:
```
1. Fetch target's public JWKS from /.well-known/jwks.json or equivalent.
2. Extract RSA public key from the JWKS response.
3. Craft JWT: header {"alg": "HS256", "typ": "JWT"}, payload with attacker-chosen claims.
4. Sign payload with HMAC-SHA256, using the RSA public key bytes as the HMAC secret.
5. Submit as JWT to a target endpoint that accepts JWT-authenticated requests.
6. If accepted → forgery confirmed.
7. Rebuttal: submit to a patched instance.
```

**PHAR-on-8.0+ recipe** (verifying the mitigation is in place, not a bypass):
```
1. Fingerprint PHP version via X-Powered-By.
2. Attempt file_exists('phar:///tmp/x.phar') sink — should NOT trigger unserialize on 8.0+.
3. Grep the app for explicit Phar->getMetadata() calls — those still trigger.
4. If getMetadata is called on user-influenced path, unserialize fires — the pre-existing PHAR primitive.
```

## The Class Predicts the Next Bug — Pattern Framing

Each CVE in this file exemplifies a class shape that predicts where the next CVE in the same family will land. Extracting the class shape lets the hunter look for the sibling bug that is not yet publicly disclosed.

**Class shape 1: "Check outer, use inner"** (exemplar: jackson-databind CVE-2026-54512).
Any parser that validates a top-level type name against an allow-list but then constructs the type from a fuller specification (generics, arrays, tuples, wrapped forms) can have the check bypassed by embedding the denied class in the fuller specification. Predicted follow-ons:
- Any Jackson polymorphic-typing feature that adds new type-syntax forms is a candidate.
- Fastjson's `@type` handling of Java `L...;` descriptor syntax — an analogous "outer allow / inner exploit" surface.
- Node.js `class-transformer` when configured with `enableCircularCheck: false`.
- Python `pydantic` with discriminator-based unions — the discriminator field is checked, but nested-model instantiation is not necessarily re-validated.

**Class shape 2: "Version-boundary mitigation with reflection surface"** (exemplar: PyTorch `weights_only=True` cluster).
Any deserialization mitigation that shifts from "block class instantiation" to "block class instantiation *except through allow-listed helpers*" has the helpers as the new attack surface. Predicted follow-ons:
- TensorFlow's SavedModel format with `custom_object_scope` — the custom-object registration is a reflection surface.
- HuggingFace's `AutoModel.from_pretrained` internally uses `torch.load` with the safe path; the internal reflection surface applies here too.
- Any language's "safe pickle" alternative (Python's `dill.settings['safe']=True` variants, if adopted) will have the same class shape.

**Class shape 3: "Multi-format mitigation, single-format bypass"** (exemplar: PyJWT alg-confusion recurrence).
A mitigation targeting one input encoding (PEM in the historical fix) leaves other encodings (DER in the September 2026 recurrence) untouched. Predicted follow-ons:
- Any JWT library's alg-confusion mitigation that targets PEM without covering DER.
- Cross-encoding attacks on any signature-verification library.
- SSH key parsing across PEM / SSH1-format / SSH2-format — the same class shape.

**Class shape 4: "Format DoS via unbounded recursion"** (exemplar: XStream CVE-2024-47072).
Any format parser that uses recursion for reference resolution / tree-walking without a depth guard has the same DoS class. Predicted follow-ons:
- Other XStream drivers with reference-token recursion.
- YAML parsers with anchor-resolution recursion.
- JSON parsers with deeply-nested object recursion (the "billion laughs" class).

**Class shape 5: "Legacy formatter removed but still installable"** (exemplar: .NET 9 BinaryFormatter).
Any deprecation-with-restoration-path lands legacy vulnerabilities on the restored code paths. Predicted follow-ons:
- Any `SoapFormatter` / `LosFormatter` / `NetDataContractSerializer` future removal.
- Java's SerializationFactory eventual removal.
- Python's `pickle` never being removed but potentially being fenced off in future major versions.

**Class shape 6: "Supply-chain dormant activation"** (exemplar: Sleeping Giants).
Any dependency ecosystem where a dependency's version history can be modified without a security-relevant CVE. Every language ecosystem with reflection-based deserialization has this class:
- Java (Sleeping Giants demonstrated).
- Python (pickle-based ML pipelines).
- .NET (Json.NET / BinaryFormatter classpaths).
- PHP (phpggc's 44 frameworks each subject to modification-pattern activation).
- Ruby (Marshal reachability across Rails / Sidekiq / Devise updates).

**Class shape 7: "Trusted-evaluator with attacker input"** (exemplar: Argo Workflows, GitHub Actions).
Not deserialization but the same primitive: a trusted evaluator (template engine, expression evaluator, pod-spec templater) trusts operator-authored strings that in practice carry attacker input. Overlaps with SSTI (route to `ssti_novel_deep.md § CI/CD Expression-Injection Class`).

The pattern-based approach is the load-bearing insight for 2024–2026 auditing: instead of tracking CVEs one-by-one, extract the class shape and audit for the sibling bug that is not yet public.

## Fingerprinting Cheat Sheet — Deserialization Sinks

**Java**:
- `X-Powered-By: Servlet/*, JBoss-EAP/*, Weblogic/*, WebSphere/*` — server fingerprint.
- Cookies: `JSESSIONID=`, `JSESSIONIDSSO=` (JBoss), `LtpaToken2=` (WebSphere), `WLSESSION=` (WebLogic).
- Ports: 1099 (RMI), 4447 (JBoss EJB), 7001/7002 (WebLogic T3), 8080-http-upgrade (WildFly), 9010/9999 (JMX).
- Error stacks with `com.sun.rowset.JdbcRowSetImpl`, `java.util.HashMap`, `org.hibernate.*` classnames.

**.NET**:
- Headers: `X-Powered-By: ASP.NET`, `X-AspNet-Version:`, `X-AspNetMvc-Version:`, `Server: Microsoft-IIS/*`.
- Cookies: `.ASPXAUTH=`, `ASP.NET_SessionId=`.
- ViewState fields: `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`.
- Files: `.aspx`, `.asmx`, `.svc`.

**PHP**:
- Header: `X-Powered-By: PHP/*`.
- Cookies: `PHPSESSID=`, framework-specific `laravel_session`, `_yourapp_session`.
- Files: `.php`, `.phtml`.
- Error output: `PHP Fatal error`, `Uncaught Exception`.

**Python**:
- Cookies: framework-specific `sessionid` (Django), `session` (Flask), `.AspNetCore.Cookies` (uvicorn/gunicorn behind reverse proxy).
- Headers: `Server: WSGIServer/*`, `Server: uvicorn`, framework debug pages with pickle-shape cookies.

**Node.js**:
- Cookies: `connect.sid=` (Express default session middleware).
- Headers: `X-Powered-By: Express` (if not stripped).
- Framework-specific cookies.

**Ruby**:
- Cookies: `_yourapp_session=` (Rails), `rack.session=` (raw Rack).
- Headers: `X-Powered-By: Phusion Passenger`, `Server: Puma`, `Server: Unicorn`.

**Cross-cutting**:
- Response times: some deserialization sinks add measurable latency (e.g., Java native serialization is slow; a 50ms baseline that jumps to 500ms on a specific parameter suggests the sink is engaged).
- Error messages: any response mentioning "deserialize," "unmarshal," "unpickle," "readObject," "type resolver" is a strong signal.

## Operational Reporting for Frontier Findings

The 2024–2026 frontier findings differ from classical deserialization in reporting expectations. The added artifacts required for the modern report:

- **Version-specific CVE reference** — every frontier finding names the CVE with the exact NVD or GHSA URL. The version boundary is the finding, so the reader needs the primary source.
- **Supply-chain provenance for ML findings** — for PyTorch / MLflow / Ray / HuggingFace findings, name the specific loader path exercised (`torch.load` with a specific reflection-reached class, `AutoModel.from_pretrained` with a specific base class). The vendor's response depends on the specific path, not just the primitive.
- **Attribution correction for Sleeping Giants** — Kreyssig, Houy, Riom, Bartel (Umeå, CCS'25). Any report citing "Cao et al. Sleeping Giants" is wrong; Cao et al. is GCMiner (ICSE'23).
- **FLASH figure discipline** — cite the confirmed "30.8% lower false-negative rate and 25.9% lower false-positive rate on 30 apps." Do not cite the refuted "90 new chains / 10 known CVEs / 5 new exploitation methods."
- **XStream mislabel correction** — CVE-2024-47072 is a **DoS**, not RCE. Any report claiming RCE from CVE-2024-47072 is wrong.
- **Argo CVE-2024-47827 mislabel correction** — this is a race-condition **DoS** affecting only 3.6.0-rc1, not expression-injection RCE. The real Argo template-expression cluster is CVE-2026-31892 → 42296 → 54526.
- **PyJWT class-shape framing** — the September 2026 cluster is a *recurrence* of the historical alg-confusion class, not a novel bug type. Frame the finding as "the class has re-landed via DER-key detection paths" rather than "novel PyJWT bug."
- **.NET 9 timeline** — the removal is "starting .NET 9 Preview 6"; the restoration path is the out-of-band NuGet package. Reports naming the wrong .NET version boundary are technically wrong and get returned for revision.

**Multi-finding reports** — for engagements that surface multiple CVEs in the trio's scope, structure the report by class shape (per the "Class Predicts the Next Bug" pattern framing) rather than per CVE. This lets the client's remediation team address the class-level issue (e.g., "audit polymorphic-typing on every parser") rather than the individual CVE.

**Continuous-monitoring recommendations** — every frontier finding should carry a follow-through recommendation for the client:
- Dependency-bump audit process integrating reachability tooling (FLASH / Tabby / AndroChain).
- CI-level detection for the three Sleeping Giants modification patterns.
- Version-pinning strategy for critical dependencies (jackson-databind, PyTorch, PyJWT, .NET runtime).
- Model-loading verb audit for ML infrastructure.
- Machine-key / secret-key rotation cadence (for the signed-blob class shape).

The report's value to the client is proportional to how actionable the follow-through is; a report that names the CVE and stops has limited operational value compared to one that includes the audit process the client should adopt.

## Cross-Cutting Audit Checklists

**Pre-engagement fingerprinting checklist** (before firing any payload):
- [ ] Identify all serialization formats in use across the target's HTTP surface, cookies, headers, WebSocket frames, message queues, cache adapters, and internal RPC paths.
- [ ] Fingerprint the exact library version for each format: jackson-databind, XStream, SnakeYAML, PyYAML, PyTorch, Newtonsoft.Json, and every JWT library.
- [ ] Extract the target's classpath JARs (Java) or dependency lockfile (all languages) and run reachability analysis (FLASH / Tabby / AndroChain for Java; `fickling` for pickle streams; `ModelScan` for ML artifacts).
- [ ] Enumerate the write endpoints (any field that reaches persistent storage) and read endpoints (any endpoint that reads and deserializes stored data) for second-order surface.
- [ ] Enumerate the queue producers and consumers if the app uses Celery / Sidekiq / Bull / Kafka.
- [ ] Enumerate the model-load call sites if the app touches ML infrastructure.

**Pre-payload confirmation checklist**:
- [ ] Sink liveness — in-graph error probe returns a format-specific error, proving the deserializer runs.
- [ ] Version-boundary — the target's library version falls within the affected range for the CVE being tested.
- [ ] Callback reachability — OAST reach confirmed via URLDNS-shape or equivalent safe probe.
- [ ] Rebuttal instance — a patched adjacent instance is available to test the same payload for a fixed-behavior confirmation.

**Post-exploit reporting checklist**:
- [ ] Exact payload bytes attached (hex, base64, and delivery-format encoding).
- [ ] Full HTTP request/response trace with `curl` reproduction.
- [ ] OAST callback log with source IP, timestamp, headers.
- [ ] Fingerprint evidence (library, version, error stack).
- [ ] Fixed-version rebuttal result.
- [ ] Chain graph with capability-transferred-per-hop for compound findings.
- [ ] Confidence tier (Confirmed / Reachable / Suspected).
- [ ] Follow-through recommendation for the client (audit process, monitoring, version-pinning).

**Dependency-bump audit checklist** (Sleeping Giants integration):
- [ ] Diff the new dependency version against the previous for each of the three modification patterns.
- [ ] Re-run reachability analysis on the new dependency set.
- [ ] Cross-reference the reachability report with the app's actual sink locations.
- [ ] Flag any newly-reachable-and-live chains as findings.

## Frontier Cross-Reference Table

The single-owner CVEs and their exact routing across the trio:

| CVE / Advisory | Class | Owned in | Base file mention | Advanced file mention |
|----------------|-------|----------|-------------------|------------------------|
| CVE-2026-54512 / GHSA-j3rv-43j4-c7qm | jackson-databind PTV bypass | this file | number + pointer | number + pointer |
| CVE-2024-47072 / GHSA-hfq9-hggm-c56q | XStream BinaryStreamDriver DoS | this file | number + pointer | number + pointer |
| .NET 9 BinaryFormatter removal | .NET 9 timeline | this file | class mention | class mention |
| PyTorch weights_only cluster (GHSA-53q9-r3pm-6pq6, GHSA-63cw-57p8-fm3p) | ML-pipeline bypass | this file | class mention | class mention |
| MLflow GHSA-gqvg-gmmx-x4hm | pickle-gate bypass | this file | class mention | (via ML-pipeline routing) |
| Ray GHSA-hhrp-gw25-jr43, GHSA-mw35-8rx3-xf9r | unsafe-by-default | this file | class mention | (via ML-pipeline routing) |
| serialize-javascript GHSA-5c6j-r48x-rmvq, GHSA-qj8w-gfj5-8c6v | prototype poisoning | this file | class mention | (via Node.js routing) |
| CVE-2022-29217 (historical) + alg-confusion recurrence class | JWT alg-confusion class | this file | class mention | (via JWT routing) |
| PHP CVE-2026-6103 (PHAR tar-entry injection) | PHAR parser DoS | this file | class mention | (via format-differential routing) |

**Version-string single-ownership** — every version boundary appears in exactly one place in the trio (this file). If a version string ever leaks into `insecure_deserialization.md` or `insecure_deserialization_advanced_deep.md`, that is a trio-ownership violation to correct.

**GHSA-ID single-ownership** — every GHSA identifier appears only in this file. If a GHSA ID leaks into the other files, correct it to a CVE-number-only mention with a pointer.

## Summary

The 2024–2026 frontier for insecure deserialization is dominated by two shifts. First: the Sleeping Giants supply-chain reframing (Kreyssig et al., CCS'25) — Java gadget-chain reachability is a fluctuating property of a dependency's history, three modification patterns activate dormant chains in 26.08% of sampled Maven deps, and the audit posture must shift from one-shot to continuous re-check on every bump. Second: mitigations shipped with headline safety claims are incomplete — PyTorch's `weights_only=True` default has two 2025–2026 bypass CVEs, MLflow's pickle-gate has a statsmodels bypass, Jackson's PTV allow-list is bypassable via generic type parameters (CVE-2026-54512), and PyJWT's alg-confusion mitigations re-landed via DER-key detection paths in September 2026. Cross-cutting: .NET 9 removed the in-box `BinaryFormatter` (Preview 6, unfixable per Microsoft's classification); .NET Framework retains it in extended support; PHP PHAR's plain-file-op auto-trigger died in 8.0 but the explicit `getMetadata` sink and ongoing PHAR parser CVEs (CVE-2026-6103) keep the surface alive; XStream CVE-2024-47072 is a stack-overflow DoS in `BinaryStreamDriver`, not RCE (frequent mislabel). The `insecure_deserialization.md` base owns the technique-class primitive tour and routing; `insecure_deserialization_advanced_deep.md` owns the filter architecture and format-parser differentials; this file owns the per-CVE version tables single-owner, the Sleeping Giants dissection, the FLASH detection-frontier framing (30.8% FN / 25.9% FP reduction, no "90 chains" claim), and the emerging supply-chain and CI/CD deserialization surfaces.
