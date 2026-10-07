---
name: argument-injection
description: Argument injection against trusted command-line programs — option/subcommand smuggling, argument-boundary breakout across shell and OS process APIs, response/config/authentication file reparsing, Windows Unicode-to-ANSI Best-Fit transformations, measured shell-vs-array-exec discipline, and chaining into RCE, file write, and credential leak.
---

# Argument Injection

Use this skill when attacker-influenced data reaches a trusted command-line program, even when no shell is involved. The security question is whether the input changes the program's **option set, operands, configuration, subcommand, or downstream parser state**.

Load `rce` when a shell parses the command string. Load `semantic_confusion` when validation and the final CLI/filesystem/configuration consumer see different representations.

## Model Every Parser Boundary

Build the actual transformation chain:

```text
request value
  -> application validation
  -> argv builder or command-line string serializer
  -> OS/process creation API
  -> runtime argv construction
  -> target option parser
  -> response/config/auth file parser, URL parser, or subcommand
```

Do not treat all process APIs alike:

- POSIX `execve(path, argv, envp)` and list-form subprocess APIs preserve array-element boundaries. Whitespace inside one element does not create another argument.
- Shell/string forms introduce shell tokenization before the target program sees `argv`.
- Windows process creation commonly serializes an argument array into one command-line string and lets the child runtime parse it back. Quoting rules differ across CRTs and applications.
- Some programs deliberately reparse an argument as a response file, configuration file, URL, expression, template, or nested command language.

Record the exact API, platform, runtime, target binary/version, option parser, and final `argv` observed by the child.

## Measured Shell-vs-Array Exec Discipline

Measured locally (persisted at `.zen-batch-artifacts/batch-11/measurements/argument_injection.py`+`.out`): the child's real argv as read from its own `sys.argv`:

| Python call | Attacker value | argc | argv (child's view) |
|---|---|---|---|
| `subprocess.run([tool, VALUE], shell=False)` | `"benign.txt --upload-file=/etc/passwd"` | 2 | `[tool, "benign.txt --upload-file=/etc/passwd"]` — stays as one element |
| `subprocess.run(f"{tool} {VALUE}", shell=True)` | `"benign.txt --upload-file=/etc/passwd"` | 3 | `[tool, "benign.txt", "--upload-file=/etc/passwd"]` — shell tokenizes |
| `subprocess.run([tool, VALUE], shell=True)` | `"benign.txt --upload-file=/etc/passwd"` | 1 | `[tool]` — only first list element reaches sh -c |
| `subprocess.run([tool, VALUE], shell=False)` | `"benign.txt; echo PWNED"` | 2 | `[tool, "benign.txt; echo PWNED"]` — `;` stays literal |
| `subprocess.run(f"{tool} {VALUE}", shell=True)` | `"benign.txt; echo PWNED"` | 2 | `[tool, "benign.txt"]` — `;` fires PWNED as a separate command |
| `subprocess.run([tool, VALUE], shell=False)` | `"--output=/tmp/race"` | 2 | `[tool, "--output=/tmp/race"]` — **option injected despite list form** |

What this proves:

1. **Shell semantics are the shell-RCE boundary.** `shell=True` with user input is command injection; `shell=False` with a list stays literal; this is `rce.md`'s domain.
2. **Argument injection is a separate class.** The last row shows the argv-safe form (list, no shell) still delivers an attacker-chosen option as a distinct argv element. The target program parses `--output=/tmp/race` as a flag; the application never crossed shell semantics but the attacker injected an *option*.
3. **The three primitives are structurally different** (and the rest of this skill treats them separately): option/subcommand injection (list form + option-like prefix), argument-boundary breakout (shell tokenization), and response/config/auth file reparsing (program-specific grammar after argv parsing).
4. **Child's real argv is the only confirmation.** The log line often prints a joined string that looks like separate args when they aren't, or vice versa. Capture via `/proc/<pid>/cmdline`, a wrapper, or the child's own `sys.argv`.

## Primitive 1: Option and Subcommand Injection

An attacker-controlled value placed where an operand is expected can be interpreted as an option when it begins with an option prefix:

```text
intended: ["tool", USER_VALUE]
supplied: USER_VALUE = "--output=/controlled/path"
actual:   tool parses an output option instead of an operand
```

Inventory security-relevant option classes rather than memorizing one payload:

- output, upload, extraction, log, cache, plugin, template, or configuration paths.
- alternate URL schemes, proxies, certificates, credentials, and authentication files.
- hooks, helpers, filters, interpreters, external programs, or dynamic libraries.
- config overrides, environment definitions, working directories, and search paths.
- subcommands that expose administrative, import/export, restore, diagnostic, or execution features.

Check whether the target supports `--` as an end-of-options marker and whether the application places it before the untrusted operand. Do not assume every CLI honors `--`, or that it applies after a subcommand switches to a second parser.

**2024-2026 instances of this primitive** (routed to the novel sibling for CVE depth):

- `curl` with `--upload-file`, `--output`, `--config`, `-K` on paths derived from user input.
- `git` with `--upload-pack`, `--receive-pack`, `--template`, `--exec` on URLs or operand positions.
- Various git-clone wrapper libraries (`ggit`, `git-shallow-clone`, `GitPython`): see `argument_injection_novel_deep.md § Git-Family Argument Injection Chain`.
- `scp`/`rsync` with user-controlled source/destination paths where `-o` and `-e` reach ssh config.

## Primitive 2: Argument-Boundary Breakout

Require a component that reparses or reconstructs arguments. Candidate boundaries include:

- shell or command-string construction.
- Windows quoting/escaping mismatches between parent and child runtimes.
- newline-, NUL-, delimiter-, or quote-sensitive custom launchers.
- wrappers that join an array and later split it.
- CGI/interpreter mappings that turn request data into command-line options.

Distinguish these outcomes:

```text
["tool", "user --flag"]       # one argv element; no split by execve
["tool", "user", "--flag"]    # extra argv element reached the target
["tool", "@args.txt"]         # one element, then reparsed by the target
```

Logs often render arrays as strings and can falsely suggest splitting. Capture the child's real arguments through source instrumentation, a wrapper process, debugger, audit trace, `/proc/<pid>/cmdline`, or the platform equivalent.

## Primitive 3: Response, Config, and Authentication Files

Many trusted programs consume a second language after argv parsing:

- `@response-file` syntax used by compilers, linkers, JVM tooling, and custom launchers.
- `--config`, `-K`, credentials/auth files, include files, and rc/profile paths.
- newline-delimited key/value files generated from attacker-controlled fields.
- file contents where control characters create a new directive, identity, host, or option.

Trace both attacker influence over the **file path** and influence over the **file content**. Correct shell quoting does not protect a file that is later tokenized by a different grammar. Record duplicate-key behavior, newline rules, comments, escaping, include directives, and first/last-value precedence.

## Windows Unicode-to-ANSI Best-Fit

On Windows, narrow-character APIs and CRT startup paths can convert Unicode command-line, environment, or filesystem data into an ANSI code page. Best-Fit mappings may introduce ASCII characters after earlier validation. This is the mechanism behind **CVE-2024-4577** (PHP-CGI) and **CVE-2024-47611** (XZ Utils Windows) — see the novel sibling.

Relevant boundaries include:

- `GetCommandLineA` or a narrow `main(int, char **)` startup path.
- `GetEnvironmentVariableA`, `GetCurrentDirectoryA`, and narrow filesystem APIs.
- framework or native-extension transitions from UTF-16 strings to an ANSI code page.

`CommandLineToArgvW` is the documented Windows command-line parser; there is no documented `CommandLineToArgvA`. Determine which CRT or application-specific parser constructs narrow `argv`.

Treat mappings as code-page-specific hypotheses, not universal payloads. Candidate transformations include:

- **Soft hyphen** (U+00AD) → `-` on multiple code pages. This is the CVE-2024-4577 primitive.
- **Fullwidth / compatibility slash characters** (U+FF0F, U+2215) → `/` or `\`.
- **Fullwidth hyphen** (U+FF0D) → `-` on CP932 (Japanese), CP949 (Korean), CP950 (Traditional Chinese), among others.
- **Compatibility quotes and letters** → ASCII equivalents (U+2018, U+2019, U+201C, U+201D → ASCII quotes).

Capture:

- submitted Unicode code points and encoded bytes.
- active system/process code page.
- wide string before conversion.
- narrow bytes and final `argv` or filesystem path after conversion.

Using wide-character APIs removes this particular conversion boundary but does not fix ordinary option injection.

The 2025 Orange Tsai research "WorstFit" formalized the Windows Best-Fit attack surface and showed PHP, Python, Ruby, Node.js, and most CRT-based applications on Windows share the exposure when launched with non-UTF-8 code pages. See `argument_injection_novel_deep.md § Windows Best-Fit Deep Catalog` for the full CVE lineage.

## Reconnaissance

In source, locate process creation and work forward into the consumer:

```text
exec*  posix_spawn  subprocess  ProcessBuilder  Runtime.exec
CreateProcess  ShellExecute  child_process  os/exec  Command
```

For each attacker-controlled argument, answer:

1. Is it a distinct argv element or part of a command string?
2. Can it begin with the target's option prefix?
3. Is an end-of-options marker supported and correctly positioned?
4. Does a wrapper, CRT, shell, or target reparse it?
5. Can it select a response/config/auth file or inject directives into one?
6. Which target option or subcommand turns that control into read, write, request, identity, or execution capability?

For black-box testing, compare an ordinary operand with option-prefixed, delimiter-bearing, control-character, and platform-specific Unicode variants. Match tests to options that actually exist in the deployed binary/version.

## 2024-2026 CVE Routing

Instance-level CVEs for the current argument-injection frontier. The version/GHSA metadata lives in `argument_injection_novel_deep.md`; the base cites by number and route only.

- **CVE-2024-4577** — PHP-CGI on Windows with Best-Fit character translation; soft-hyphen injection reaches PHP's command-line arg parser. One of the most-exploited CVEs of 2024. Route: `argument_injection_novel_deep.md § PHP-CGI Best-Fit`.
- **CVE-2024-47611** — XZ Utils command-line tools on Windows with Best-Fit; parallel to CVE-2024-4577 shape. Route: `argument_injection_novel_deep.md § XZ Utils Windows Best-Fit`.
- **CVE-2024-32002** — Git clone with recursive submodules + case-insensitive filesystem + symlink hooks → RCE on clone. Not strictly argument injection (it's a submodule-path confusion), but routed here because the primitive is "the attacker controls what argv Git submits to its own internal hook-dispatch." Route: `argument_injection_novel_deep.md § Git Clone Submodule RCE`.
- **CVE-2025-48384** — Git carriage-return in config value + symlink hooks → arbitrary file write + RCE on non-Windows systems. Same mechanism family. Route: `argument_injection_novel_deep.md § Git CR + Symlink`.
- **CVE-2024-21533 / CVE-2024-21531** — ggit / git-shallow-clone argument injection via unsanitized URL/path. Route: `argument_injection_novel_deep.md § Git Wrapper Argument Injection`.
- **GitPython option-smuggling via single-character kwarg value token** (GHSA-only, no CVE assignment) — bypasses `check_unsafe_options` guard; enables arbitrary command execution. Route: `argument_injection_novel_deep.md § GitPython Kwarg Smuggling`.

The advanced sibling (`argument_injection_advanced_deep.md`) owns the per-platform process-API depth (POSIX execve, Windows CreateProcess, Node child_process, Python subprocess, Go os/exec, Ruby Kernel), the response-file / config-file / auth-file grammar depth, Windows Best-Fit catalogue with code-page mappings, CGI/interpreter mapping classes, wrapper-join-split patterns, and composite-chain construction.

## Validation

- Show the final `argv` or secondary parser input, not only the application log line.
- Pair the candidate with a control where the same bytes remain a literal operand.
- Demonstrate the exact option, directive, subcommand, path, or handler selected.
- Reproduce against the deployed binary, runtime, code page, and configuration.
- Separate option control, additional-argument control, arbitrary directive control, and command execution; they are different primitives.

## False Positives

- The input is one argv element and the target treats it only as a positional operand.
- `--` is supported, placed before the value, and not bypassed by a subparser.
- A strict allowlist prevents option prefixes and all later transformations preserve it.
- A delimiter appears only in logging or display formatting.
- A response/config path is controllable but its contents or directives are not.
- A Unicode character is accepted but no narrow/Best-Fit conversion occurs.
- The injected option exists on another release or platform but not the deployed target.

## Chaining

Argument injection grants a specific capability (file write via `--output`, file read via `--upload-file`, subcommand access via a subcommand switch, interpreter selection via `--template`); chain by what the capability enables:

- **Argument injection → RCE**: `curl --output=/etc/cron.d/attacker` writes to a privileged path; cron picks up. See `rce.md`.
- **Argument injection → Local file read**: `--upload-file=/etc/shadow` to an attacker-controlled HTTP target. See `information_disclosure.md`.
- **Argument injection → Credential leak**: config/auth-file injection reveals credentials to the attacker's URL. See `information_disclosure.md`.
- **Argument injection → SSRF**: `curl` with user-controlled URL + attacker-chosen option reaches internal services. See `ssrf.md`.
- **Argument injection → Config file write**: `--config=/attacker/path` + file-content control at that path → next invocation reparses attacker's config. See `path_traversal_lfi_rfi.md`.

## Remediation

- Use argument-array process APIs and avoid shell/string construction.
- Insert `--` before untrusted operands where every relevant parser supports it.
- Validate operands against the target CLI's grammar, not a generic shell blacklist.
- Fix security-sensitive option names and configuration paths in trusted code.
- Generate configuration/auth files with a format-aware serializer that rejects control characters and ambiguous duplicates.
- On Windows, keep data in wide-character APIs and verify child-runtime parsing rules.
- Enforce authorization again at the privileged operation selected by the CLI.
- For the Windows Best-Fit class specifically, read the command line via `GetCommandLineW` and parse via `CommandLineToArgvW`, converting to UTF-8 for internal handling.

## Breadth Note

This base is a reference overview of the argument-injection technique surface — the four-boundary parser-model, the measured shell-vs-array table, every primary primitive family (the three-primitive split: option/subcommand injection, argument-boundary breakout, response/config/auth files), Windows Best-Fit basics, reconnaissance workflow, and the full 2024-2026 CVE routing map. It is deliberately scoped to be a complete overview of every technique class rather than a full-treatment of each; the advanced sibling owns per-platform process-API depth with full-treatment sub-primitives, and the novel sibling owns current CVE mechanism depth.

## Summary

Argument injection is control of a trusted program's behavior through its argv or a parser reached from argv. Preserve parser boundaries in the model: list-form execution, command-string tokenization, Windows runtime conversion, option parsing, and response/config-file parsing are distinct stages with distinct exploit conditions. The measured shell-vs-array differential confirms the three-primitive split (option injection vs shell escape vs response-file reparse); the 2024-2026 CVE frontier is dominated by Windows Best-Fit (PHP-CGI CVE-2024-4577, XZ Utils CVE-2024-47611) and Git-family argument injection (CVE-2024-32002, CVE-2025-48384, CVE-2024-21533, CVE-2024-21531, and the GitPython option-smuggling advisory routed to the novel sibling). The confirmation discipline is strict: the finding is the child's real argv or the real secondary-parser input, not a log line or an outer-wrapper's string representation.
