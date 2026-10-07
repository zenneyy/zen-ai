---
name: ast-grep
description: ast-grep structural code search/rewrite — pattern syntax, scan vs. run, strictness levels, and raw tree-sitter query fallback.
---

# ast-grep CLI Playbook

Official docs:
- https://ast-grep.github.io/
- https://ast-grep.github.io/guide/pattern-syntax.html
- https://ast-grep.github.io/reference/cli.html
- https://github.com/ast-grep/ast-grep

Canonical syntax:
- One-shot pattern search/rewrite: `ast-grep run -p <pattern> -l <lang> [--rewrite <fix>] [paths]`
- Configured scan (YAML rules): `ast-grep scan [--rule <file>|--inline-rules <yaml>] [paths]`
- Shortcut binary: `sg` is a hardlinked alias of `ast-grep` (same flags).

High-signal `run` flags:
- `-p, --pattern <pattern>` AST pattern to match (metavariables: `$NAME`, `$$$BODY` for lists)
- `-l, --lang <lang>` language (e.g. `python`, `javascript`, `typescript`, `tsx`, `go`, `java`, `rust`, `bash`, `json`, `yaml`); required for `-p`
- `-k, --kind <kind>` match by AST node kind (ESQuery selector syntax)
- `--selector <kind>` extract a sub-syntax-node from the pattern as the actual matcher
- `--strictness <level>` match strictness: `cst` (exact including trivia), `smart` (default), `ast` (AST only), `relaxed` (AST except comments), `signature` (AST except comments, no text), `template` (text only)
- `-r, --rewrite <fix>` replace match with text (`$VAR` metavariable interpolation)
- `--debug-query <pattern|ast|cst|sexp>` print the parsed query for debugging
- `--globs <glob>` include/exclude by path pattern
- `--no-ignore <hidden|dot|exclude|global|parent|vcs>` ignore `.gitignore` / hidden-file rules
- `--follow` follow symlinks
- `--stdin` read source from stdin
- `-i, --interactive` start interactive edit session (confirm/tweak changes selectively)
- `-U, --update-all` apply all rewrites without confirmation
- `--files-with-matches` print only paths with at least one match
- `-j, --threads <num>` parallel threads (default 0 = auto heuristic)
- `--color <auto|always|ansi|never>` control output coloring
- `--inspect <nothing|summary|entity>` trace file/rule discovery and scanning (outputs to stderr)
- `--heading <auto|always|never>` group output by file (auto = heading for TTY, prefix for pipe)
- Output: `--json[=pretty|stream|compact]` structured output; `-A/-B/-C <n>` after/before/context lines

High-signal `scan` flags:
- `-r, --rule <file>` single YAML rule file
- `--inline-rules <yaml>` rule inline on the command line (separate multiple rules with `---`)
- `-c, --config <file>` project config (`sgconfig.yml`)
- `--filter <regex>` only run rules whose id matches the regex
- `--min-severity <level>` drop rules below this severity
- `--error[=<rule_id>...]` set specified rule(s) severity to error; bare `--error` sets all to error
- `--warning[=<rule_id>...]` set specified rule(s) severity to warning
- `--info[=<rule_id>...]` set severity to info
- `--hint[=<rule_id>...]` set severity to hint
- `--off[=<rule_id>...]` turn off specified rule(s); bare `--off` disables all
- `--max-results <num>` stop after N results (fail-fast on large codebases)
- `--format <github|sarif>` output format for CI/SARIF consumers
- `--report-style <rich|medium|short>` terminal format (default `rich`)
- `--include-metadata` include rule metadata in JSON output (requires `--json`)
- `-i, --interactive` / `-U, --update-all` / `--files-with-matches` / `--color` / `--inspect` / `--heading` — same behavior as `run`

Agent-safe baseline for automation:
`ast-grep scan --config sgconfig.yml --format sarif /workspace > ast-grep.sarif`
(or for ad-hoc search: `ast-grep run -p '<pattern>' -l python --json /workspace > ast-grep.jsonl`)

Common patterns:
- Find Python `eval(` calls:
  `ast-grep run -p 'eval($$$)' -l python src/`
- Find Flask routes with `debug=True`:
  `ast-grep run -p 'app.run($$$, debug=True, $$$)' -l python src/`
- Find JS `document.innerHTML =` sinks:
  `ast-grep run -p '$EL.innerHTML = $VAL' -l javascript src/`
- Rewrite `console.log(` to `logger.debug(` (dry-run, then `--update-all`):
  `ast-grep run -p 'console.log($$$ARGS)' -r 'logger.debug($$$ARGS)' -l javascript src/`
- JSON output for pipeline consumption:
  `ast-grep run -p 'eval($$$)' -l python --json src/ > evals.jsonl`
- Debug a stubborn pattern (print its AST):
  `ast-grep run -p 'eval($$$)' -l python --debug-query ast src/`
- Match by node kind only (any function call):
  `ast-grep run -k call_expression -l python src/`
- Project-scoped rules scan with SARIF for Code Scanning:
  `ast-grep scan --config sgconfig.yml --format sarif /workspace > ast-grep.sarif`
- Inline rule for one-off scan:
  `ast-grep scan --inline-rules 'id: no-eval
language: python
rule:
  pattern: eval($$$)
severity: error' /workspace`
- Fail-fast scan (stop after 10 results):
  `ast-grep scan --config sgconfig.yml --max-results 10 --json=compact /workspace`
- Override severity at CLI (promote a specific rule to error):
  `ast-grep scan --config sgconfig.yml --error=no-eval --format github /workspace`

Critical correctness rules:
- `-l <lang>` is required for `-p` — without it, ast-grep guesses from file extension and silently misses files when the pattern parses in a different language.
- Metavariable syntax: single-token `$NAME`, multi-token (statements, arguments) `$$$NAME`. Confusing them is the top-N cause of empty matches.
- `--strictness` matters: default `smart` matches `foo(a)` and `foo(a,)` identically. For exact-text matching (literals, comments, whitespace), use `cst` or `template`.
- `scan` uses project config (`sgconfig.yml`); `run` uses just the CLI flags. Mixing them (passing `-c sgconfig.yml` to `run`) partially works but surprises on severity filtering.
- `--rewrite` writes to stdout only by default; apply changes with `--update-all` (ast-grep prompts without it).
- `.gitignore` / hidden files are honored by default — pass `--no-ignore hidden` etc. when scanning dependencies or dotfiles.
- Patterns run through the embedded tree-sitter grammar for the chosen language; the sandbox also ships prebuilt grammars under `/home/pentester/.tree-sitter/parsers/` (java/javascript/typescript/tsx/python/go/bash/json/yaml). ast-grep uses its own grammar set — the tree-sitter parsers are for the raw `tree-sitter query` fallback below.
- Severity override flags (`--error`, `--warning`, etc.) use `=` syntax: `--error=rule-id`. Bare `--error` with no ID sets ALL rules to that level.

Usage rules:
- Prefer `scan` for repeatable project checks (version-controlled rules under `sgconfig.yml` + a `rules/` directory). Use `run` for ad-hoc greps.
- Keep JSON/SARIF outputs for downstream parsing; terminal `rich` is lossy.
- Use `--inspect summary` to debug why a scan matches fewer files than expected.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- Zero matches on a pattern you know should hit: run with `--debug-query ast` or `--debug-query cst` to see what ast-grep parsed; try `--strictness relaxed`; verify `-l` matches the file language.
- Rewrite does nothing: `--rewrite` prints the diff only; add `--update-all` to apply. Confirm with `--interactive` first if risky.
- "no files searched": `.gitignore` is excluding the paths; add `--no-ignore hidden,dot,vcs` as needed.
- Pattern doesn't parse: break it into a smaller fragment; use `--selector` to extract just the sub-node you care about.
- Scan finds nothing but run with the same pattern hits: `scan` filters by `--min-severity` and `--filter` — check those settings and the rule's `severity` field.

If uncertain, query web_search with:
`site:ast-grep.github.io ast-grep <flag>` or `site:github.com/ast-grep/ast-grep`

---

## Pattern Language

ast-grep's pattern language is the core differentiator: write the code shape you want to find, using metavariables as holes. The pattern is parsed by tree-sitter for the target language, so it must be syntactically valid in that language.

### Metavariable syntax

| Syntax | Captures | Example |
|---|---|---|
| `$NAME` | Exactly one named AST node | `eval($INPUT)` captures the single argument |
| `$$$NAME` | Zero or more nodes (variadic) | `foo($$$ARGS)` matches `foo()`, `foo(a)`, `foo(a, b, c)` |
| `$_` | Wildcard (one node, unnamed) | `$_.innerHTML = $VAL` matches any receiver |

**Critical:** lowercase `$name` is treated as **literal code**, not a metavariable capture. `eval($x)` matches only calls to `eval` with a literal identifier named `x`. Use uppercase: `eval($X)`.

Metavariables bind across a pattern — `$X == $X` matches self-equality checks where both operands are the same AST node.

### Strictness levels

`--strictness` controls how tightly the pattern matches the source. The six levels from tightest to loosest:

**`cst`** — exact, including trivia (whitespace, comments, trailing commas). Use for literal-text comparison where formatting matters:
```bash
ast-grep run -p 'foo(a, b,)' -l python --strictness cst src/
# Matches only `foo(a, b,)` with trailing comma — NOT `foo(a, b)`
```

**`smart`** (default) — matches all nodes except source-trivial nodes. Trailing commas, semicolons, and other language trivia are ignored:
```bash
ast-grep run -p 'foo(a, b)' -l python src/
# Matches both `foo(a, b)` and `foo(a, b,)`
```

**`ast`** — only named AST nodes. Ignores unnamed nodes (operators, punctuation, keywords used as syntax):
```bash
ast-grep run -p 'a + b' -l python --strictness ast src/
# Matches `a + b`, `a+b`, `a  +  b` — the `+` operator node kind matters, not its text
```

**`relaxed`** — AST nodes except comments. Matches the same as `ast` but also ignores comment nodes in the source:
```bash
ast-grep run -p 'foo($X)' -l python --strictness relaxed src/
# Matches `foo(x)` even if the source has `foo(/* important */ x)` in JS or `foo(x)  # comment` adjacent in Python
```

**`signature`** — AST nodes except comments, no text. Matches the structural shape only; string/identifier text is ignored:
```bash
ast-grep run -p 'foo($X)' -l python --strictness signature src/
# Matches `bar(y)` — same call structure, different identifiers
```

**`template`** — text only, node kinds ignored. Matches based on the text content of the pattern regardless of how tree-sitter parses it:
```bash
ast-grep run -p 'TODO' -l python --strictness template src/
# Matches any occurrence of the text "TODO" regardless of AST node type
```

Decision guide:
- Most searches: `smart` (default)
- Exact literal comparison: `cst` or `template`
- Structure-only (ignore formatting/trivia): `ast`
- API shape matching (function-call shape regardless of names): `signature`
- Ignoring comments in the way: `relaxed`

### Selector

`--selector <kind>` extracts a sub-node from the pattern to use as the actual matcher. The pattern provides context, but only the selected node kind is reported:

```bash
# Match function definitions that contain eval(), but report only the eval call
ast-grep run -p 'def $FN($$$): $$$BODY' --selector call_expression -l python src/
```

The selector is a tree-sitter node kind name — use `--debug-query ast` to discover the kind names for your target language.

### Kind matching

`-k, --kind <kind>` matches by AST node kind directly, without a code pattern. Supports ESQuery-style selector syntax:

```bash
# All function calls in Python
ast-grep run -k call -l python src/

# All string literals
ast-grep run -k string -l python src/
```

Combine with `--json` to extract all instances of a structural element for downstream analysis.

### Debug query

When a pattern doesn't match as expected, `--debug-query` shows how ast-grep parsed it:

```bash
# See the pattern's AST structure
ast-grep run -p 'eval($X)' -l python --debug-query ast

# See the full CST (including unnamed nodes)
ast-grep run -p 'eval($X)' -l python --debug-query cst

# S-expression format (tree-sitter native)
ast-grep run -p 'eval($X)' -l python --debug-query sexp
```

If the AST shows unexpected structure, the pattern likely doesn't parse as intended in the target language — simplify or split it.

---

## YAML Rule Authoring

YAML rules are the structured, repeatable form of ast-grep patterns. A rule file defines matching logic, severity, message, and optional autofix. Place rules in a `rules/` directory referenced by `sgconfig.yml`.

### Rule structure

```yaml
id: rule-id-kebab-case
language: python
severity: error        # error | warning | hint | info | off
message: Human-readable finding message — $VAR interpolation works here
note: Optional longer explanation or remediation guidance
url: https://link-to-reference
rule:
  # matching spec (see atomic/relational/composite below)
  pattern: dangerous_call($$$)
fix: safe_call($$$)    # optional autofix with metavariable interpolation
constraints:           # optional metavariable constraints
  VAR:
    regex: "^user_"
transform:             # optional metavariable transforms
  NEW_VAR:
    substring:
      source: $VAR
      startChar: 0
      endChar: 5
```

### Atomic rules

Atomic rules match a single condition:

**`pattern`** — the code shape to match (same syntax as `-p` on CLI):
```yaml
rule:
  pattern: eval($X)
```

**`kind`** — match by AST node kind:
```yaml
rule:
  kind: function_definition
```

**`regex`** — match by regex on the node's text:
```yaml
rule:
  regex: "password|secret|token"
```

**`nthChild`** — match the Nth child of a parent node:
```yaml
rule:
  nthChild:
    position: 0
    ofRule:
      kind: argument_list
```

### Relational rules

Relational rules filter by relationships between nodes:

**`inside`** — the match must be inside a node matching the sub-rule:
```yaml
rule:
  pattern: $X
  inside:
    kind: function_definition
    has:
      pattern: def admin_$FN($$$)
```

**`has`** — the match must contain a descendant matching the sub-rule:
```yaml
rule:
  kind: function_definition
  has:
    pattern: eval($$$)
```

**`follows`** / **`precedes`** — sibling ordering constraints:
```yaml
rule:
  pattern: return $X
  follows:
    pattern: $Y = user_input($$$)
```

**`matches`** — reference another rule by its `id` (rule composition):
```yaml
utils:
  is-user-input:
    pattern: request.$ATTR
rules:
  - id: eval-user-input
    rule:
      pattern: eval($X)
      constraints:
        X:
          matches: is-user-input
```

### Composite rules

Combine rules with logical operators:

**`all`** — all sub-rules must match (AND):
```yaml
rule:
  all:
    - pattern: $FUNC($$$ARGS)
    - kind: call
    - inside:
        kind: function_definition
```

**`any`** — at least one sub-rule must match (OR):
```yaml
rule:
  any:
    - pattern: eval($$$)
    - pattern: exec($$$)
    - pattern: compile($$$)
```

**`not`** — negate a rule:
```yaml
rule:
  pattern: yaml.load($$$ARGS)
  not:
    pattern: yaml.load($$$, Loader=SafeLoader)
```

### Constraints

Constrain metavariable values without changing the structural match:

**Regex constraint** — metavariable text must match a regex:
```yaml
rule:
  pattern: $FUNC($$$)
constraints:
  FUNC:
    regex: "^(eval|exec|compile|__import__)$"
```

**Pattern constraint** — metavariable must itself match a pattern:
```yaml
rule:
  pattern: cursor.execute($QUERY)
constraints:
  QUERY:
    not:
      regex: '^"[^"]*"$'   # reject string literals — catch only dynamic SQL
```

### Transform

Transform metavariable values before using them in `fix` or `message`:

```yaml
transform:
  UPPER_NAME:
    convert:
      source: $NAME
      toCase: upperCase
  SHORT:
    substring:
      source: $NAME
      startChar: 0
      endChar: 10
  CLEANED:
    replace:
      source: $NAME
      replace: "_"
      by: "-"
```

Available operations: `substring`, `replace`, `convert` (toCase: upperCase/lowerCase/camelCase/snakeCase/pascalCase/kebabCase), `rewrite`.

### Fix / autofix

The `fix` field defines the replacement text, with metavariable interpolation:

```yaml
id: yaml-safe-load
language: python
rule:
  pattern: yaml.load($DATA)
  not:
    pattern: yaml.load($DATA, Loader=$$$)
fix: yaml.safe_load($DATA)
severity: error
message: Use yaml.safe_load() instead of yaml.load() — arbitrary code execution risk
```

Apply fixes:
```bash
# Preview fixes (stdout only)
ast-grep scan --rule yaml-safe-load.yml /workspace

# Interactive confirmation
ast-grep scan --rule yaml-safe-load.yml -i /workspace

# Apply all without confirmation
ast-grep scan --rule yaml-safe-load.yml -U /workspace
```

---

## Security Pattern Catalogue

ast-grep patterns for common vulnerability classes. Each pattern is a ready-to-use `run` command or YAML rule fragment; the full vulnerability context lives in the routed consumer.

### Command injection sinks

```bash
# Python
ast-grep run -p 'os.system($CMD)' -l python src/
ast-grep run -p 'subprocess.Popen($$$, shell=True, $$$)' -l python src/
ast-grep run -p 'subprocess.call($$$, shell=True, $$$)' -l python src/
ast-grep run -p 'subprocess.run($$$, shell=True, $$$)' -l python src/

# JavaScript / Node
ast-grep run -p 'child_process.exec($CMD)' -l javascript src/
ast-grep run -p 'child_process.execSync($CMD)' -l javascript src/
```

Route: `vulnerabilities/rce.md`, `vulnerabilities/argument_injection.md`

### Code execution sinks

```bash
ast-grep run -p 'eval($$$)' -l python src/
ast-grep run -p 'exec($$$)' -l python src/
ast-grep run -p 'compile($$$)' -l python src/
ast-grep run -p '__import__($$$)' -l python src/

# JavaScript
ast-grep run -p 'eval($$$)' -l javascript src/
ast-grep run -p 'Function($$$)' -l javascript src/
ast-grep run -p 'new Function($$$)' -l javascript src/
```

Route: `vulnerabilities/rce.md`

### XSS sinks

```bash
ast-grep run -p '$EL.innerHTML = $VAL' -l javascript src/
ast-grep run -p '$EL.outerHTML = $VAL' -l javascript src/
ast-grep run -p 'document.write($$$)' -l javascript src/
ast-grep run -p 'document.writeln($$$)' -l javascript src/

# React
ast-grep run -p 'dangerouslySetInnerHTML={{__html: $VAL}}' -l tsx src/
```

Route: `vulnerabilities/browser_security.md`

### SQL injection sinks

```yaml
# YAML rule — catch f-string SQL
id: fstring-sql
language: python
rule:
  regex: 'f"(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)'
severity: error
message: f-string SQL construction — parameterize instead
```

```bash
# Direct pattern — cursor.execute with non-literal
ast-grep run -p 'cursor.execute($Q)' -l python src/
# Then manually inspect: is $Q a literal string or a variable/f-string?
```

Route: `vulnerabilities/sql_injection.md`

### Insecure deserialization

```bash
ast-grep run -p 'pickle.loads($$$)' -l python src/
ast-grep run -p 'pickle.load($$$)' -l python src/
ast-grep run -p 'marshal.loads($$$)' -l python src/
ast-grep run -p 'yaml.load($$$)' -l python src/
# Refine: exclude safe usage
ast-grep run -p 'yaml.load($DATA)' -l python src/
# Then filter with YAML rule using `not: pattern: yaml.load($$$, Loader=SafeLoader)`
```

Route: `vulnerabilities/insecure_deserialization.md`

### Weak cryptography

```bash
ast-grep run -p 'hashlib.md5($$$)' -l python src/
ast-grep run -p 'hashlib.sha1($$$)' -l python src/
ast-grep run -p 'DES.new($$$)' -l python src/
```

Route: `vulnerabilities/weak_password_detection.md`

### SSRF-susceptible patterns

```yaml
id: requests-variable-url
language: python
rule:
  pattern: requests.get($URL, $$$)
  not:
    constraints:
      URL:
        regex: '^"https?://'
severity: warning
message: Variable URL in requests.get — potential SSRF
```

Route: `vulnerabilities/ssrf.md`

### Jinja2 autoescape disabled

```bash
ast-grep run -p 'Environment($$$, autoescape=False, $$$)' -l python src/
ast-grep run -p 'Environment($$$)' -l python src/
# Second form catches when autoescape is not specified at all (defaults to False)
```

Route: `vulnerabilities/ssti.md`

---

## Project Configuration (`sgconfig.yml`)

`sgconfig.yml` in the project root tells `ast-grep scan` where to find rules and how to apply them:

```yaml
ruleDirs:
  - rules/security
  - rules/style
testConfigs:
  - testDir: rules/__tests__
languageGlobs:
  python:
    - "*.py"
    - "*.pyi"
  javascript:
    - "*.js"
    - "*.mjs"
    - "*.cjs"
```

### Rule directory layout

```
sgconfig.yml
rules/
  security/
    no-eval.yml
    no-pickle.yml
    sql-injection.yml
  style/
    no-console-log.yml
```

Each `.yml` file in `ruleDirs` is auto-discovered. Rules can also be grouped in a single file separated by `---`.

### Severity overrides at CLI

Override rule severities without editing YAML:
```bash
# Promote one rule to error for CI gating
ast-grep scan --config sgconfig.yml --error=no-eval --format github /workspace

# Disable a noisy rule for this run
ast-grep scan --config sgconfig.yml --off=no-console-log /workspace

# Set all rules to warning except one critical rule
ast-grep scan --config sgconfig.yml --warning --error=sql-injection /workspace
```

### Rule filtering

`--filter <regex>` runs only rules whose id matches:
```bash
# Run only security-prefixed rules
ast-grep scan --config sgconfig.yml --filter "^security-" /workspace

# Run only rules mentioning "sql"
ast-grep scan --config sgconfig.yml --filter "sql" --json=compact /workspace
```

---

## Rewrite and Autofix Workflow

### CLI rewrite (`run`)

```bash
# Preview: prints diff to stdout, does not modify files
ast-grep run -p 'console.log($$$ARGS)' -r 'logger.debug($$$ARGS)' -l javascript src/

# Interactive: confirm each match before applying
ast-grep run -p 'console.log($$$ARGS)' -r 'logger.debug($$$ARGS)' -l javascript -i src/

# Apply all: modifies files without confirmation
ast-grep run -p 'console.log($$$ARGS)' -r 'logger.debug($$$ARGS)' -l javascript -U src/
```

### YAML rule autofix (`scan`)

```bash
# Preview: prints findings with fix suggestions
ast-grep scan --rule yaml-safe-load.yml /workspace

# Interactive: confirm each fix
ast-grep scan --rule yaml-safe-load.yml -i /workspace

# Apply all
ast-grep scan --rule yaml-safe-load.yml -U /workspace
```

### Transform before fix

When the fix needs more than direct metavariable interpolation, use `transform`:

```yaml
id: rename-handler
language: python
rule:
  pattern: def handle_$NAME($$$PARAMS):
    $$$BODY
transform:
  UPPER:
    convert:
      source: $NAME
      toCase: upperCase
fix: |-
  def process_$NAME($$$PARAMS):
    logger.info("$UPPER")
    $$$BODY
severity: hint
message: Rename handler functions
```

### Security fix patterns

Autofix should be conservative for security rules — prefer a fix that breaks compilation over one that silently changes semantics:

```yaml
# Good: replace with safe equivalent
fix: yaml.safe_load($DATA)

# Good: comment out with explanation
fix: "# SECURITY: removed eval — use ast.literal_eval if needed"

# Bad: silently swallow the call
fix: "pass"
```

---

## Multi-Language Support

### Supported languages (sandbox 0.45.3)

Python, JavaScript, TypeScript, TSX, Go, Java, Rust, C, C++, C#, Swift, Kotlin, Ruby, Lua, Dart, Bash, JSON, YAML, HTML, CSS, and additional languages via tree-sitter grammars.

`-l <lang>` is required for `run -p`. For `scan`, the language is inferred from file extensions and can be overridden via `languageGlobs` in `sgconfig.yml`.

### File discovery

By default, ast-grep respects `.gitignore`, `.ignore`, and hidden file rules. Override with:
```bash
# Scan hidden files
ast-grep run -p '$PATTERN' -l python --no-ignore hidden src/

# Scan everything (no ignore rules at all)
ast-grep run -p '$PATTERN' -l python --no-ignore hidden --no-ignore dot --no-ignore vcs src/

# Include/exclude by glob
ast-grep run -p '$PATTERN' -l python --globs '*.py' --globs '!*_test.py' src/
```

### Cross-language scanning

YAML rules specify language per-rule, so a single `sgconfig.yml` can contain rules for Python, JavaScript, Go, and more — `ast-grep scan` applies each rule only to matching files:

```yaml
# rules/no-eval-python.yml
id: no-eval-py
language: python
rule:
  pattern: eval($$$)
severity: error
message: eval() in Python

---

# rules/no-eval-js.yml
id: no-eval-js
language: javascript
rule:
  pattern: eval($$$)
severity: error
message: eval() in JavaScript
```

---

## Output Formats and CI Integration

### JSON output

```bash
# Pretty-printed (human-readable)
ast-grep run -p 'eval($$$)' -l python --json src/

# Streaming (one JSON object per line — JSONL)
ast-grep run -p 'eval($$$)' -l python --json=stream src/

# Compact (single-line array)
ast-grep scan --config sgconfig.yml --json=compact /workspace > findings.json
```

JSON output includes: file path, match range (start/end line/column), matched text, metavariable bindings, rule id (for `scan`), and message.

### SARIF output

```bash
ast-grep scan --config sgconfig.yml --format sarif /workspace > ast-grep.sarif
```

SARIF 2.1.0 for GitHub Code Scanning, Azure DevOps, and other SARIF consumers. Each rule becomes a SARIF `reportingDescriptor`; each finding a `result`.

### GitHub Actions format

```bash
ast-grep scan --config sgconfig.yml --format github /workspace
```

Outputs `::error file=...,line=...,col=...::message` annotations directly consumable by GitHub Actions.

### Metadata in output

```bash
# Include rule metadata (url, note, severity) in JSON
ast-grep scan --config sgconfig.yml --json --include-metadata /workspace
```

### Inspection / debugging

```bash
# Summary: how many files scanned/skipped
ast-grep scan --config sgconfig.yml --inspect summary /workspace

# Per-entity: which files and rules were scanned or skipped and why
ast-grep scan --config sgconfig.yml --inspect entity /workspace 2>inspect.log
```

Inspection output goes to stderr; it does not affect findings output.

---

## ast-grep vs. semgrep

| Dimension | ast-grep | semgrep |
|---|---|---|
| Pattern language | Code-shaped patterns parsed by tree-sitter | Code-shaped patterns parsed by semgrep's own parser |
| Taint analysis | No | Yes (Pro: interprocedural, cross-file) |
| Rule ecosystem | No registry; custom YAML rules only | Large public registry (`p/default`, `p/owasp-top-ten`, `p/secrets`, …) |
| Autofix / rewrite | Native (`--rewrite`, `fix:` in rules, transforms) | `-a/--autofix` with `fix:` in rules |
| Performance | Fast (tree-sitter, Rust) | Slower on large codebases (OCaml + Python) |
| Multi-language | Tree-sitter grammar coverage | Broader (40+ languages including Pro) |
| Output | JSON, SARIF, GitHub | JSON, SARIF, GitLab SAST, JUnit, Emacs, Vim |

Use both:
- **semgrep** for broad coverage via the registry and for taint/dataflow analysis
- **ast-grep** for custom structural patterns, fast rewrites, and when semgrep's rules don't cover a project-specific code shape

---

## Tool Chaining

- `ast-grep scan --format sarif` → Zen findings pipeline (`findings.sarif`)
- `ast-grep run --json=stream` → `jq` filter → feed file/line to nuclei/httpx for live endpoint validation
- ast-grep rewrite (`-U`) → semgrep validate → confirm the fix doesn't introduce new patterns that trigger other rules
- ast-grep + bandit: ast-grep for custom Python structural patterns bandit's B-code catalogue doesn't cover; bandit for its 70+ built-in Python security tests
- ast-grep + trivy: ast-grep finds code-level patterns, trivy finds dependency/config issues — complementary, non-overlapping

---

## Raw `tree-sitter query` fallback

The sandbox also ships the `tree-sitter` CLI (0.27.0) with prebuilt grammars for the common languages. Reach for it only when ast-grep's pattern syntax can't express the query — most structural searches should live in ast-grep.

- `tree-sitter query <query_file> <source...>` runs a tree-sitter S-expression query across source files
- `--scope <lang>` select the language by its tree-sitter scope rather than file extension
- `--captures` order results by capture rather than match
- `--byte-range <start:end>` / `--row-range <start:end>` restrict query to a range
- `--config-path <file>` custom tree-sitter config (default `~/.config/tree-sitter/config.json`, already seeded in the sandbox to find the prebuilt grammars)

Minimal query example (Python, find all `eval` calls):
```
; eval.scm
(call
  function: (identifier) @fn
  (#eq? @fn "eval")) @call
```
`tree-sitter query eval.scm --scope source.python src/`

---

Routed consumers:
- `coordination/source_aware_whitebox.md`, `custom/source_aware_sast.md` (whitebox pipelines)
- `tooling/semgrep.md` (semgrep is the broader-rule SAST; ast-grep is the structural grep + light rewriter)
- `tooling/bandit.md` (Python-specific sibling; use bandit for ruleset coverage, ast-grep for custom patterns)
- `vulnerabilities/rce.md`, `vulnerabilities/argument_injection.md` (command injection / code execution sinks)
- `vulnerabilities/sql_injection.md` (SQL injection sink patterns)
- `vulnerabilities/insecure_deserialization.md` (pickle/marshal/yaml.load patterns)
- `vulnerabilities/browser_security.md` (XSS sink patterns)
- `vulnerabilities/ssrf.md` (variable-URL request patterns)
- `vulnerabilities/ssti.md` (Jinja2 autoescape patterns)
