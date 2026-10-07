---
name: semgrep
description: Exact Semgrep CLI structure, metrics-off scanning, scoped ruleset selection, and automation-safe output patterns.
---

# Semgrep CLI Playbook

Official docs:
- https://semgrep.dev/docs/cli-reference
- https://semgrep.dev/docs/getting-started/cli
- https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-intro

Canonical syntax:
`semgrep scan [flags] [targets]`

High-signal flags:
- `-f, -c, --config <rule_or_ruleset>` ruleset, registry pack, local rule file, or directory (repeatable; stacks)
- `-e, --pattern <pattern>` inline code pattern (requires `-l/--lang`)
- `-l, --lang <lang>` language for inline pattern (e.g. `python`, `javascript`, `go`, `java`)
- `--replacement <val>` autofix expression for inline `-e` pattern matches
- `--metrics=off` disable telemetry and metrics reporting
- `--json` JSON output
- `--json-output <file|url>` write JSON copy to file or POST to URL
- `--sarif` SARIF output
- `--sarif-output <file|url>` write SARIF copy to file or POST to URL
- `--gitlab-sast` / `--gitlab-secrets` GitLab format output
- `--gitlab-sast-output <file|url>` / `--gitlab-secrets-output <file|url>` GitLab copies
- `--junit-xml` / `--junit-xml-output <file|url>` JUnit XML
- `--emacs` / `--vim` single-line editor-integration format
- `--emacs-output <file|url>` / `--vim-output <file|url>` editor-format copies
- `--text` / `--text-output <file|url>` plain text
- `-o, --output <file|url>` primary output destination (default stdout)
- `--severity <INFO|WARNING|ERROR>` filter by severity (repeatable)
- `--error` return non-zero exit (1) when findings exist
- `--strict` non-zero exit on WARN-level errors (strict CI gate)
- `-q, --quiet` suppress progress noise — only output findings
- `-v, --verbose` show rule/file details
- `--debug` all of `--verbose` plus internal debug info
- `-j, --jobs <n>` parallel workers (default ~85% of logical cores)
- `--timeout <seconds>` per-file per-rule timeout (default 5.0)
- `--timeout-threshold <int>` max rules timing out per file before file is skipped (default 3)
- `--max-memory <MiB>` system memory cap (0 = unlimited; CI Pro defaults to 90% container or 8 GiB)
- `--max-target-bytes <val>` max file size to scan (default 1000000 bytes; 0 = unlimited)
- `--exclude <pattern>` exclude path pattern (gitignore glob syntax; repeatable)
- `--include <pattern>` include path pattern (repeatable)
- `--exclude-rule <rule_id>` suppress specific rule (repeatable)
- `--exclude-binary-files` skip binary files (enabled by default; `--no-exclude-binary-files` to scan them)
- `--exclude-minified-files` skip minified files (<7% whitespace or >1000 bytes/line avg; off by default)
- `--baseline-commit <sha>` only report findings introduced after this commit (diff-aware)
- `--dataflow-traces` explain how non-local values reach findings in text/SARIF output
- `--matching-explanations` add per-rule-part match tracing in JSON output (rule dev / debug)
- `-a, --autofix` apply `fix` fields from rules (WARNING: data loss possible — use VCS)
- `--dryrun` preview autofix to console without writing (requires `--autofix`)
- `--pro` enable Pro engine (inter-file analysis + Pro languages)
- `--pro-intrafile` intra-file inter-procedural taint (implies `--pro-languages`)
- `--pro-languages` enable Pro languages (Apex, C#, Elixir)
- `--pro-path-sensitive` path sensitivity (implies `--pro-intrafile`)
- `--oss-only` force OSS engine only
- `--interfile-timeout <int>` max time for interfile analysis (default 0 = unlimited; CI default 3h)
- `--secrets` run Semgrep Secrets product (live validation; separate from `p/secrets` registry pack)
- `--historical-secrets` scan git history with Secrets rules
- `--no-secrets-validation` disable live secret validation
- `--secrets-timeout <int>` per-validation HTTP timeout (default 30s)
- `--allow-untrusted-validators` allow validators from non-semgrep.dev origins
- `--validate` validate rule YAML without scanning
- `--dump-ast` show AST of input file/expression (combine with `--json`)
- `--scan-unknown-extensions` bypass language detection for CLI-specified files
- `--no-git-ignore` scan gitignored and submodule files
- `--project-root <dir>` force project root (novcs mode; `.semgrepignore` anchor)
- `--optimizations <all|none>` toggle internal optimizer (default `all`)
- `--show-supported-languages` list languages and exit

Agent-safe baseline for automation:
`semgrep scan --config p/default --metrics=off --json --output semgrep.json --quiet --jobs 4 --timeout 20 /workspace`

Common patterns:
- Default security scan:
  `semgrep scan --config p/default --metrics=off --json --output semgrep.json --quiet /workspace`
- High-severity focused pass:
  `semgrep scan --config p/default --severity ERROR --metrics=off --json --output semgrep_high.json --quiet /workspace`
- OWASP-oriented scan:
  `semgrep scan --config p/owasp-top-ten --metrics=off --sarif --output semgrep.sarif --quiet /workspace`
- Language- or framework-specific rules:
  `semgrep scan --config p/python --config p/secrets --metrics=off --json --output semgrep_python.json --quiet /workspace`
- Scoped directory scan:
  `semgrep scan --config p/default --metrics=off --json --output semgrep_api.json --quiet /workspace/services/api`
- Pro engine check or run:
  `semgrep scan --config p/default --pro --metrics=off --json --output semgrep_pro.json --quiet /workspace`
- Inline pattern (quick ad-hoc grep):
  `semgrep scan -e 'eval($X)' -l python --metrics=off --json /workspace`
- Diff-aware CI scan (only new findings):
  `semgrep scan --config p/default --baseline-commit origin/main --metrics=off --json --error --quiet /workspace`
- Dual-output (JSON + SARIF simultaneously):
  `semgrep scan --config p/default --metrics=off --json-output semgrep.json --sarif-output semgrep.sarif --quiet /workspace`
- Secrets scan (git history):
  `semgrep scan --secrets --historical-secrets --metrics=off --json --output secrets.json --quiet /workspace`
- Validate custom rules before use:
  `semgrep scan --validate --config ./rules/ --metrics=off`

Critical correctness rules:
- Always include `--metrics=off`; Semgrep sends telemetry by default.
- Always provide an explicit `--config`; do not rely on vague or implied defaults.
- Prefer `--json --output <file>` or `--sarif --output <file>` for machine-readable downstream processing.
- Keep the target path explicit; use an absolute or clearly scoped workspace path instead of `.` when possible.
- If Pro availability matters, check it explicitly with a bounded command before assuming cross-file analysis exists.
- `--autofix` modifies files in place — always run under version control, preview with `--dryrun` first.
- `-e/--pattern` requires `-l/--lang`; without it, semgrep cannot parse the pattern.
- `--baseline-commit` requires a clean git working tree and the baseline SHA must exist in the local repo.

Exit codes:
- `0` — OK, no findings
- `1` — findings present (only when `--error` is set; otherwise 0 with findings)
- `2` — fatal error
- `3` — invalid target code
- `4` — invalid pattern
- `5` — unparseable YAML rule file
- `7` — missing configuration
- `8` — invalid language
- `13` — invalid API key

Usage rules:
- Start with `p/default` unless the task clearly calls for a narrower pack.
- Add focused packs such as `p/secrets`, `p/python`, or `p/javascript` only when they match the target stack.
- Use `--quiet` in automation to reduce noisy logs.
- Use `--jobs` and `--timeout` explicitly for reproducible runtime behavior.
- Do not use `-h`/`--help` for routine operation unless absolutely necessary.

Failure recovery:
- If scans are too slow, narrow the target path and reduce the active rulesets before changing engine settings.
- If scans time out, increase `--timeout` modestly or lower `--jobs`.
- If output is too broad, scope `--config`, add `--severity`, or exclude known irrelevant paths.
- If Pro mode fails, rerun with `--oss-only` or without `--pro` and note the loss of cross-file coverage.
- Pattern returns no matches: verify `-l` matches the target language; run `--dump-ast` on a sample file to inspect the tree; try `--scan-unknown-extensions` for files with non-standard extensions.
- Rule validation errors: run `--validate --config ./rules/` to see parse errors before scanning.

If uncertain, query web_search with:
`site:semgrep.dev semgrep <flag> cli`

---

## Custom Rule Authoring

Semgrep's power beyond the registry is custom YAML rules — pattern-match against AST structures across 30+ languages with the same rule syntax.

### Rule structure

```yaml
rules:
  - id: rule-unique-id
    message: What was found and why it matters
    severity: ERROR        # INFO | WARNING | ERROR
    languages: [python]    # list; multi-language rules repeat per lang
    pattern: dangerous_call($X)
```

Minimal: `id`, `message`, `severity`, `languages`, and one pattern operator.

### Pattern operators

Single-pattern matching:
- `pattern: <code>` — match code structurally; metavariables capture sub-nodes
- `pattern-regex: <regex>` — match code as a regex (when AST structure is insufficient)

Compound (under a `patterns:` list — implicit AND):
- `pattern: ...` + `pattern-not: ...` — match A but exclude B
- `pattern-inside: ...` — restrict matches to code nested inside this context
- `pattern-not-inside: ...` — exclude matches nested inside this context
- `pattern-either:` — OR across multiple patterns (list of pattern objects)

Nesting: `patterns` can nest `pattern-either`, `pattern-inside`, etc. to arbitrary depth. Evaluation is top-down; `pattern-inside` restricts the scope before `pattern` runs.

### Metavariables

- `$X` — captures a single AST node (expression, identifier, literal, type)
- `$...X` — spread/ellipsis capture (zero or more arguments, statements)
- `$_` — anonymous single capture (matches but does not bind a name)
- `...` — ellipsis (matches zero or more nodes without binding)

Metavariable constraints (under `patterns:`):
- `metavariable-pattern: {metavariable: $X, pattern: <sub-pattern>}` — restrict $X to nodes matching a sub-pattern
- `metavariable-regex: {metavariable: $X, regex: <regex>}` — restrict $X to nodes whose text matches regex
- `metavariable-comparison: {metavariable: $X, comparison: $X > 0}` — numeric/boolean comparison on $X
- `metavariable-analysis: {metavariable: $X, analyzer: <name>}` — built-in analysis (e.g. `entropy` for secrets)
- `focus-metavariable: $X` — narrow the reported finding location to $X's span (not the whole pattern match)

### Autofix in rules

```yaml
rules:
  - id: python-eval-user-input
    patterns:
      - pattern: eval($X)
      - pattern-not: eval("...")
    message: eval() with non-literal argument
    severity: ERROR
    languages: [python]
    fix: ast.literal_eval($X)
```

`fix` interpolates metavariables from the pattern. Apply with `semgrep --autofix`; preview with `--autofix --dryrun`.

### Rule metadata

```yaml
    metadata:
      cwe:
        - "CWE-94: Improper Control of Generation of Code"
      owasp:
        - A03:2021
      confidence: HIGH
      impact: HIGH
      references:
        - https://cwe.mitre.org/data/definitions/94.html
```

Metadata is informational — it populates SARIF `properties`, GitHub code scanning severity, and Semgrep App dashboards. It does not affect matching.

### Advanced pattern examples

**SSRF — outbound request with user-controlled URL:**
```yaml
rules:
  - id: ssrf-user-url
    patterns:
      - pattern-either:
          - pattern: requests.get($URL, ...)
          - pattern: requests.post($URL, ...)
          - pattern: urllib.request.urlopen($URL)
          - pattern: httpx.get($URL, ...)
      - pattern-not-inside: |
          if is_internal_url($URL):
              ...
      - metavariable-pattern:
          metavariable: $URL
          pattern-not: "..."
    message: HTTP request with non-literal URL — potential SSRF
    severity: ERROR
    languages: [python]
    metadata:
      cwe: ["CWE-918"]
      owasp: ["A10:2021"]
```

**Hardcoded credentials with entropy check:**
```yaml
rules:
  - id: hardcoded-secret
    pattern: $KEY = "..."
    metavariable-analysis:
      metavariable: $KEY
      analyzer: entropy
    metavariable-regex:
      metavariable: $KEY
      regex: (?i)(password|secret|token|api_key|apikey)
    message: Hardcoded credential with high entropy
    severity: ERROR
    languages: [python, javascript, go, java]
```

**Path traversal — user input in file operations:**
```yaml
rules:
  - id: path-traversal
    mode: taint
    pattern-sources:
      - pattern: flask.request.args.get($KEY)
      - pattern: flask.request.form[$KEY]
    pattern-sinks:
      - pattern: open($PATH, ...)
      - pattern: pathlib.Path($PATH)
      - pattern: os.path.join(..., $PATH, ...)
    pattern-sanitizers:
      - pattern: os.path.basename($X)
      - pattern: secure_filename($X)
    message: User-controlled path in file operation
    severity: ERROR
    languages: [python]
```

### Rule directory structure

```
rules/
├── python/
│   ├── injection.yml
│   ├── crypto.yml
│   └── auth.yml
├── javascript/
│   ├── xss.yml
│   └── prototype-pollution.yml
└── generic/
    └── secrets.yml
```

Pass `--config ./rules/` to load all. Use `--config ./rules/python/` to scope to a subdirectory. Rule `id` should be globally unique across all files.

---

## Taint Mode

Standard pattern rules find local code patterns. Taint mode (`mode: taint`) tracks data flow from sources through propagators to sinks, flagging when unsanitized tainted data reaches a dangerous function.

### Rule structure

```yaml
rules:
  - id: flask-sqli
    message: User input flows to SQL query without sanitization
    severity: ERROR
    languages: [python]
    mode: taint
    pattern-sources:
      - pattern: flask.request.$ATTR
      - pattern: flask.request.$METHOD(...)
    pattern-sinks:
      - pattern: cursor.execute($QUERY, ...)
      - pattern: db.engine.execute($QUERY)
    pattern-sanitizers:
      - pattern: sqlalchemy.text($X)
      - pattern: escape($X)
```

### Components

- `pattern-sources:` — where tainted data enters (user input, file reads, env vars, network)
- `pattern-sinks:` — where tainted data is dangerous (SQL exec, `eval`, `exec`, `system`, template render, response write)
- `pattern-sanitizers:` — transformations that neutralize taint (escaping, parameterization, validation)
- `pattern-propagators:` — functions that transfer taint from input to output (e.g. string concat wrappers, custom encoders)

Each component takes a list of pattern objects (same operators as standard rules).

### Propagators

```yaml
    pattern-propagators:
      - pattern: $TO = encode($FROM)
        from: $FROM
        to: $TO
```

`from`/`to` metavariables tell the engine which argument carries taint in and which carries it out.

### Dataflow traces

`--dataflow-traces` adds the taint path to text and SARIF output — each intermediate step from source to sink. Critical for triage: the trace shows whether the flow is real or crosses a sanitizer the rule missed.

```bash
semgrep scan --config ./rules/taint/ --dataflow-traces --metrics=off --sarif --output taint.sarif /workspace
```

### Source labels and multi-source tracking

Sources can be labeled to distinguish different taint origins:

```yaml
    pattern-sources:
      - pattern: flask.request.args.get(...)
        label: USERINPUT
      - pattern: os.environ.get(...)
        label: ENVVAR
    pattern-sinks:
      - pattern: subprocess.run($CMD, ...)
        requires: USERINPUT
```

`requires:` on a sink fires only when taint from the specified label reaches it. This prevents false positives from trusted sources (env vars) while catching untrusted ones (user input).

### Sanitizer specificity

Sanitizers should be as narrow as possible — a broad `pattern: escape($X)` sanitizer can suppress real findings. Prefer:

```yaml
    pattern-sanitizers:
      - pattern: bleach.clean($X)          # HTML sanitization
      - pattern: shlex.quote($X)           # shell argument escaping
      - pattern: int($X)                   # type coercion to safe type
      - pattern: re.match("^[a-z]+$", $X)  # allowlist validation
        by-side-effect: true               # sanitizes by confirming, not transforming
```

`by-side-effect: true` marks sanitizers that validate without transforming (e.g. regex checks, type guards) — the variable is still tainted in the data flow but the sanitizer's presence on the path clears the finding.

### OSS vs Pro taint

| Capability | OSS | Pro (`--pro`) | Pro intrafile (`--pro-intrafile`) | Pro path-sensitive (`--pro-path-sensitive`) |
|---|---|---|---|---|
| Intra-function taint | yes | yes | yes | yes |
| Inter-procedural (same file) | no | yes | yes | yes |
| Inter-file taint | no | yes | no | no |
| Path sensitivity | no | no | no | yes |

OSS taint is intra-function only — taint crossing a function boundary is invisible. `--pro-intrafile` adds inter-procedural within a file. `--pro` adds cross-file. `--pro-path-sensitive` adds branch-aware analysis (taint through an if-else that sanitizes one path).

### Taint debugging

When a taint rule returns no findings or too many:
1. Run `--dataflow-traces` to see the computed paths
2. Check if the source pattern matches: extract it to a standalone `pattern:` rule and verify matches
3. Check if a sanitizer is over-broad: temporarily remove sanitizers and re-run
4. Check if the sink pattern matches: same — extract and verify
5. Run with `--matching-explanations --json` for per-component match status

---

## Registry Packs and Rule Selection

### Core packs

| Pack | Scope |
|---|---|
| `p/default` | broad security + correctness, curated by Semgrep |
| `p/security-audit` | deeper security rules, higher noise |
| `p/owasp-top-ten` | OWASP Top 10 mapped rules |
| `p/secrets` | secret/credential detection (pattern-based; see also `--secrets` for live validation) |
| `p/python` / `p/javascript` / `p/go` / `p/java` / `p/ruby` / `p/typescript` | language-specific |
| `p/django` / `p/flask` / `p/react` / `p/nodejs` | framework-specific |
| `p/ci` | lightweight CI-optimized set |

### Stacking and combining

```bash
semgrep scan --config p/default --config p/secrets --config ./custom-rules/ \
  --metrics=off --json --output semgrep.json --quiet /workspace
```

Multiple `--config` flags stack — all rules from all sources run. Local rule directories are recursively scanned for `.yml`/`.yaml` files.

### Scoping

- `--exclude-rule <id>` suppresses a specific rule by its `id` (repeatable)
- `--severity ERROR` restricts output to ERROR-level findings only (repeatable per level)
- `--exclude <pattern>` / `--include <pattern>` scope by file path (gitignore glob syntax)
- Rule-level `paths:` in YAML scopes the rule to specific include/exclude patterns

### Validation

```bash
semgrep scan --validate --config ./rules/ --metrics=off
```

Checks YAML syntax, pattern parse, and rule schema without running a scan. Use before committing custom rules.

---

## Pro Engine Modes

The Pro engine (requires Semgrep login or license) adds inter-file analysis, inter-procedural taint, path sensitivity, and additional languages. OSS covers single-file, single-function analysis.

### Mode hierarchy

```
--oss-only   (force OSS)
  ↓
(default)    (OSS unless logged in with Pro toggle)
  ↓
--pro        (inter-file + Pro languages)
  ↓
--pro-intrafile  (inter-procedural taint within a file; implies --pro-languages)
  ↓
--pro-path-sensitive  (branch-aware; implies --pro-intrafile)
```

Each level implies the ones above it.

### Bounding Pro analysis

```bash
semgrep scan --config p/default --pro --interfile-timeout 600 --max-memory 4096 \
  --metrics=off --json --output semgrep_pro.json --quiet /workspace
```

- `--interfile-timeout <sec>` — cap interfile analysis time (default 0 = unlimited; CI default 3h)
- `--max-memory <MiB>` — memory cap; 0 = unlimited (CI Pro defaults to 90% container RAM or 8 GiB)
- `--timeout <sec>` — per-file per-rule cap (default 5s); still applies under Pro

If Pro fails or times out, fall back to `--oss-only` and note the coverage loss.

---

## Secrets Scanning

Two distinct secrets capabilities:

1. **`p/secrets` registry pack** — pattern-based detection (regex + entropy); no live validation; runs in OSS engine
2. **`--secrets` flag** — Semgrep Secrets product with live validation (HTTP calls to verify if detected secrets are active); requires Semgrep access

### Live validation

```bash
semgrep scan --secrets --metrics=off --json --output secrets.json --quiet /workspace
```

When a secret pattern matches, Semgrep makes an HTTP request to the service to test if the credential is valid. `--secrets-timeout <sec>` (default 30) bounds each validation request.

- `--no-secrets-validation` — disable live validation; pattern-match only
- `--allow-untrusted-validators` — permit validation rules from non-semgrep.dev sources (risk: the validation request exposes the secret to the validator endpoint)

### Historical secrets

```bash
semgrep scan --secrets --historical-secrets --metrics=off --json --output secrets_history.json --quiet /workspace
```

Scans git history for secrets that were committed and then removed. Finds credentials that are still valid despite being deleted from the current tree.

---

## Output Formats and CI Integration

Semgrep supports simultaneous multi-format output — each `--*-output <file>` flag writes a copy independently of the primary `--output`/stdout.

### Format matrix

| Flag | Description | Copy flag |
|---|---|---|
| `--json` | Semgrep JSON | `--json-output <file\|url>` |
| `--sarif` | SARIF 2.1.0 | `--sarif-output <file\|url>` |
| `--gitlab-sast` | GitLab SAST | `--gitlab-sast-output <file\|url>` |
| `--gitlab-secrets` | GitLab Secrets | `--gitlab-secrets-output <file\|url>` |
| `--junit-xml` | JUnit XML | `--junit-xml-output <file\|url>` |
| `--emacs` | Emacs single-line | `--emacs-output <file\|url>` |
| `--vim` | Vim single-line | `--vim-output <file\|url>` |
| `--text` | plain text (default) | `--text-output <file\|url>` |

The copy flags POST to a URL if the value starts with `http://` or `https://`; otherwise write to a local file.

### CI gating

```bash
semgrep scan --config p/default --error --strict \
  --baseline-commit "$MERGE_BASE" \
  --metrics=off --json-output semgrep.json --sarif-output semgrep.sarif \
  --quiet /workspace
```

- `--error` — exit 1 on any finding (CI break)
- `--strict` — exit non-zero on WARN-level errors (parse failures, rule load errors)
- `--baseline-commit <sha>` — diff-aware: only findings introduced after the baseline; requires clean git tree and local SHA

### SARIF for Zen integration

SARIF output feeds directly into Zen's report pipeline:
```bash
semgrep scan --config p/default --metrics=off --sarif --output findings.sarif --quiet /workspace
# findings.sarif → zen_runs/<run>/findings.sarif
```

---

## Autofix

### Rule-based autofix

Rules with a `fix:` field provide automated patches:

```yaml
rules:
  - id: insecure-random
    pattern: random.random()
    fix: secrets.SystemRandom().random()
    message: Use cryptographic random
    severity: WARNING
    languages: [python]
```

Apply:
```bash
semgrep scan --config ./rules/ --autofix --metrics=off --quiet /workspace
```

Preview without writing:
```bash
semgrep scan --config ./rules/ --autofix --dryrun --metrics=off /workspace
```

### Inline pattern autofix

```bash
semgrep scan -e 'random.random()' -l python --replacement 'secrets.SystemRandom().random()' \
  --autofix --dryrun --metrics=off /workspace
```

`--replacement` is the inline equivalent of `fix:` — metavariable interpolation works the same way.

### Fix safety

- `--autofix` writes files in place — run under version control, review diffs after
- `--dryrun` shows what would change without writing
- Multiple fixes to the same line may conflict — semgrep applies the first and skips overlapping fixes
- Autofix does not re-run the scan after patching; verify with a second scan

---

## Performance Tuning

### Parallelism

```bash
semgrep scan --config p/default --jobs 8 --metrics=off --quiet /workspace
```

`-j/--jobs` (default ~85% of logical cores). Over-subscribing threads to CPUs induces GC latency — semgrep recommends under-provisioning by 10–15% (e.g. 10–11 on a 12-core box).

### Timeouts

- `--timeout <sec>` (default 5.0) — per-file per-rule; a complex rule on a large file can hit this. Raise modestly rather than disabling (0 = unlimited).
- `--timeout-threshold <int>` (default 3) — after this many rules time out on a single file, the entire file is skipped. Catches pathological files rather than burning all rules' budgets.

### Memory and file-size bounds

- `--max-memory <MiB>` — hard memory cap; 0 = unlimited. CI Pro defaults to 90% container RAM.
- `--max-target-bytes <val>` (default 1000000 = ~1 MB) — files larger than this are silently skipped. Raise for codebases with large generated files; lower if you're only interested in hand-written source.

### Skip categories

- `--exclude-binary-files` (on by default) — skip files with binary magic bytes
- `--exclude-minified-files` (off by default) — skip files <7% whitespace or >1000 bytes/line avg
- `--optimizations all` (default) — internal optimizer; `none` for debugging only

---

## AST Debugging and Rule Development

### Inspect the AST

```bash
semgrep scan --dump-ast --json -l python -e 'eval($X)' --metrics=off
```

Prints the AST of the pattern or input file. Use to understand how semgrep parses code — alignment between your mental model and the actual tree is the #1 debugging step for pattern authoring.

### Match explanations

```bash
semgrep scan --config ./rules/ --matching-explanations --json --metrics=off /workspace
```

Adds per-rule-part matching trace to JSON output: which sub-pattern matched, which didn't, and where metavariables bound. Expensive — use for debugging specific rules, not production scans.

### Ad-hoc pattern testing

```bash
semgrep scan -e 'os.system($CMD)' -l python --metrics=off /workspace
```

Quick structural grep without writing a YAML rule. Stack with `--severity`, `--json`, `--output` as needed. Combine with `--replacement` + `--autofix --dryrun` for a preview of what a fix rule would do.

### Rule validation

```bash
semgrep scan --validate --config ./rules/ --metrics=off
```

Checks YAML schema, pattern parse (per-language), and `fix` template validity. Run before committing rules; exit code 5 = unparseable YAML.

---

## Inline Pattern Search

`-e/--pattern` turns semgrep into a structural grep — AST-aware code search from the command line without writing YAML.

```bash
# Find all subprocess.Popen calls with shell=True
semgrep scan -e 'subprocess.Popen($...ARGS, shell=True, $...MORE)' -l python \
  --metrics=off --json /workspace

# Find SQL string formatting (f-string)
semgrep scan -e 'cursor.execute(f"...", ...)' -l python --metrics=off /workspace

# Find React dangerouslySetInnerHTML
semgrep scan -e 'dangerouslySetInnerHTML={{__html: $X}}' -l javascript --metrics=off /workspace
```

Limitations:
- Single pattern only — no `pattern-not`, `pattern-inside`, or compound operators (use YAML rules for those)
- One language per `-l` — multi-language search requires multiple invocations
- `--scan-unknown-extensions` may be needed if target files use non-standard extensions

---

## Tool Chaining

### SARIF → Zen report pipeline

```bash
semgrep scan --config p/default --metrics=off --sarif --output findings.sarif --quiet /workspace
```

`findings.sarif` feeds directly into Zen's SARIF 2.1.0 intake.

### Baseline-commit in CI

```bash
MERGE_BASE=$(git merge-base HEAD origin/main)
semgrep scan --config p/default --baseline-commit "$MERGE_BASE" \
  --error --metrics=off --json --output semgrep_diff.json --quiet /workspace
```

Only findings introduced after the merge base — no noise from pre-existing issues.

### Semgrep + bandit

Complementary on Python codebases:
- Semgrep: cross-language rules, taint mode, registry breadth, autofix
- Bandit: Python-specific depth (B-code test catalogue mapped to Python vulnerability classes), simpler to configure for Python-only projects

Run both; deduplicate findings by file:line:

```bash
semgrep scan --config p/python --metrics=off --sarif --output semgrep.sarif --quiet /workspace
bandit -r -ll -ii -f json -o bandit.json --exit-zero -q /workspace
```

### Semgrep + ast-grep

Complementary:
- Semgrep: registry rules, taint mode, multi-language packs, SARIF ecosystem
- ast-grep: custom structural patterns with rewrite, tree-sitter-backed, zero network dependency

Use semgrep for broad security scans; use ast-grep for ad-hoc structural grep and codemod patterns that semgrep's `-e` can't express (e.g. node-kind matching, strictness levels).

---

## Environment Variables

- `SEMGREP_RULES` — equivalent to `--config`
- `SEMGREP_SEND_METRICS` — equivalent to `--metrics` (`auto`/`on`/`off`)
- `SEMGREP_BASELINE_COMMIT` — equivalent to `--baseline-commit`
- `SEMGREP_ENABLE_VERSION_CHECK` — equivalent to `--enable-version-check`
- `SEMGREP_FORCE_COLOR` — equivalent to `--force-color`

In automation, prefer explicit flags over environment variables for reproducibility.

---

Routed consumers:
- `coordination/source_aware_whitebox.md`, `custom/source_aware_sast.md` (whitebox pipelines)
- `tooling/bandit.md` (Python-specific complementary — semgrep for cross-language, bandit for Python depth)
- `tooling/ast-grep.md` (structural grep complementary — semgrep for registry rules, ast-grep for custom patterns)
- `vulnerabilities/sql_injection.md`, `vulnerabilities/rce.md`, `vulnerabilities/ssrf.md`, `vulnerabilities/insecure_deserialization.md`, `vulnerabilities/path_traversal_lfi_rfi.md` (taint rules map to these classes via registry packs)
- `vulnerabilities/information_disclosure.md` (secrets scanning: `--secrets`, `--historical-secrets`, `p/secrets`)
