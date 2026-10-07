---
name: gitleaks
description: Gitleaks git/filesystem secret scanning syntax, scope flags, and pipeline-ready output patterns.
---

# gitleaks CLI Playbook

Official docs:
- https://github.com/gitleaks/gitleaks
- https://github.com/gitleaks/gitleaks/wiki

Canonical syntax:
`gitleaks <command> [flags]` where `<command>` is one of `git | dir | stdin`

High-signal flags:
- `git <path>` scan a git repo's commit history (local path; `--log-opts` to narrow the commit range)
- `dir <path>` scan a directory tree without git history
- `stdin` scan content piped on stdin (CI / inline checks)
- `-c, --config <file>` custom rules TOML (precedence: `-c`, `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`, `<path>/.gitleaks.toml`, built-in default)
- `-f, --report-format <json|csv|junit|sarif|template>` structured output format
- `-r, --report-path <file>` report file (`-` for stdout)
- `--report-template <file>` template for `--report-format template`
- `-b, --baseline-path <file>` baseline findings to ignore (prior accepted leaks)
- `--enable-rule <ids>` only enable specific rule IDs
- `-i, --gitleaks-ignore-path <path>` custom `.gitleaksignore` file/directory
- `--ignore-gitleaks-allow` ignore `gitleaks:allow` inline comments
- `--max-target-megabytes <n>` skip files larger than N MiB
- `--max-archive-depth <n>` recurse into archives up to N (0 disables)
- `--max-decode-depth <n>` recursive decoding depth for base64/hex/etc. (default 5)
- `--redact [=N]` redact matches in logs/output; optional percentage (`--redact=20` leaves first 20% visible; default `--redact` = 100% redacted)
- `--exit-code <n>` exit code when findings exist (default 1)
- `--log-level <trace|debug|info|warn|error|fatal>` log verbosity
- `--no-banner` suppress banner (recommended in automation)
- `--no-color` disable ANSI color
- `-v, --verbose` show every finding on stdout
- `--timeout <sec>` global timeout in seconds (0 disables)
- `--platform <github|gitlab>` generate clickable source links in reports (git subcommand only)
- `--pre-commit` scan using `git diff` — what is about to be committed (git subcommand only)
- `--staged` scan staged commits — good for pre-commit hooks (git subcommand only)
- `--follow-symlinks` follow symlinks during directory scan (dir subcommand only)
- `--diagnostics <modes>` enable profiling: `http` serves pprof; or comma-separated `cpu,mem,trace` for CPU profile, memory profile, execution tracing
- `--diagnostics-dir <dir>` directory for diagnostics output files (defaults to cwd; non-http modes only)

Agent-safe baseline for automation:
`gitleaks git --report-format sarif --report-path gitleaks.sarif --redact --no-banner --exit-code 0 --max-target-megabytes 10 /workspace`
(`--exit-code 0` keeps the scan from failing CI on findings so downstream parsing runs; swap to `1` for gating pipelines.)

Common patterns:
- Scan the whole git history of a local repo:
  `gitleaks git --report-format json --report-path gitleaks.json --redact /workspace`
- Scan only a commit range (release delta, PR scope):
  `gitleaks git --log-opts "main..HEAD" --report-format json --report-path gitleaks.json /workspace`
- Scan a working tree without git (release artifact, clone-less target):
  `gitleaks dir --report-format json --report-path gitleaks.json --redact /workspace`
- One-shot stdin check (CI step on diff):
  `git diff HEAD~1 HEAD | gitleaks stdin --report-format json --report-path - --no-banner`
- SARIF for Code Scanning / IDE integration:
  `gitleaks git --report-format sarif --report-path gitleaks.sarif /workspace`
- Baseline-aware re-scan (ignore previously accepted findings):
  `gitleaks git --baseline-path gitleaks_baseline.json --report-format json --report-path gitleaks.json /workspace`
- Narrow to one rule (e.g. AWS keys only):
  `gitleaks git --enable-rule aws-access-token --report-format json --report-path gitleaks.json /workspace`
- Scan archives (nested zips/tars):
  `gitleaks dir --max-archive-depth 3 --report-format json --report-path gitleaks.json /workspace`
- Pre-commit scan (staged changes only):
  `gitleaks git --staged --report-format json --report-path - --no-banner --exit-code 1 /workspace`
- Platform-aware scan with clickable GitHub links:
  `gitleaks git --platform github --report-format json --report-path gitleaks.json /workspace`
- Follow symlinks in directory scan:
  `gitleaks dir --follow-symlinks --report-format json --report-path gitleaks.json /workspace`

Critical correctness rules:
- `git` vs `dir`: `git` reads commit blobs (catches rotated secrets still in history), `dir` reads the working tree (catches current leaks + untracked files). Run both when both matter.
- `--redact` is on-by-default visibility control for secrets in logs/reports; drop it only when the consumer must see the raw match (and ensure the output file is handled accordingly).
- `--exit-code` defaults to 1 on findings — in agent automation set it to 0 so downstream parsing still runs; in pipelines leave it to gate.
- `--log-opts` passes through to `git log` — scope ranges with it rather than mutating the working tree.
- `--max-target-megabytes 0` means "no limit" and will try to scan multi-GB binaries; set an explicit cap in automation.
- Rules under `--enable-rule` are matched by rule ID — use the default config as the source of truth (`gitleaks git --no-banner --report-format json --report-path - --log-opts "HEAD~1..HEAD" ...` to discover IDs).
- `--baseline-path` requires a prior JSON report; it does not auto-generate.

Usage rules:
- Prefer SARIF for IDE/GitHub consumers, JSON for downstream Python/jq parsing.
- Pin `--max-target-megabytes` (10-50 is reasonable) in automation to keep runtime bounded.
- Keep `--no-banner` on for pipeline-friendly stdout.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- No findings on a repo you expect leaks in: verify you're on `git`, not `dir`; verify the config hasn't been overridden by a project-level `.gitleaks.toml`; run with `--log-level debug`.
- Huge runtimes: add `--max-target-megabytes 10 --max-archive-depth 0` and narrow `--log-opts`.
- Noisy false positives: emit a baseline (`--report-path baseline.json`), curate it, re-run with `--baseline-path baseline.json`.
- SARIF rejected by consumer: validate with `jq .` first; some older consumers reject gitleaks' SARIF schema version.

---

## Custom TOML Rule Authoring

Gitleaks rules live in a TOML config file. The precedence chain: `--config/-c` → `GITLEAKS_CONFIG` env → `GITLEAKS_CONFIG_TOML` env (inline content) → `<scan_path>/.gitleaks.toml` → built-in defaults.

### Rule Structure

```toml
# .gitleaks.toml
title = "custom gitleaks config"

[[rules]]
id = "custom-api-key"
description = "Custom API key pattern"
regex = '''(?i)x-api-key[\s:="']+([a-zA-Z0-9]{32,64})'''
secretGroup = 1
entropy = 3.5
tags = ["api-key", "custom"]
keywords = ["x-api-key"]

[rules.allowlist]
description = "ignore test fixtures"
paths = ['''test/.*''', '''fixtures/.*''']
regexes = ['''EXAMPLE_KEY''', '''test-key-\d+''']
regexTarget = "match"
stopwords = ["example", "placeholder", "dummy"]
```

### Field Reference

- `id` — unique rule identifier; used by `--enable-rule` and in reports
- `description` — human-readable label for findings
- `regex` — Go `regexp` pattern; use raw strings (`'''...'''`) to avoid TOML escaping issues
- `secretGroup` — capture group index from `regex` to report as the secret (default 0 = full match; set to 1+ when the regex includes a prefix/label pattern)
- `entropy` — minimum Shannon entropy for the `secretGroup` match; filters low-entropy false positives without tightening the regex
- `keywords` — case-insensitive pre-filter; gitleaks only applies the regex to lines/chunks containing at least one keyword. Massive speedup on large repos — always set when the pattern has a predictable prefix
- `tags` — freeform labels for grouping/filtering in downstream consumers
- `path` — regex to restrict which file paths this rule applies to (matches against the full relative path)

### Allowlists

Allowlists suppress matches at three levels:

```toml
# Rule-level allowlist (inside [[rules]])
[rules.allowlist]
description = "known false positives for this rule"
paths = ['''vendor/.*''', '''go\.sum''']
regexes = ['''REDACTED''', '''0{32}''']
regexTarget = "match"        # "match" (default) or "line"
stopwords = ["example", "test", "dummy"]
commits = ["abc1234"]        # specific commit SHAs to ignore

# Global allowlist (top level, applies to ALL rules)
[allowlist]
description = "global suppressions"
paths = ['''\.git/.*''', '''node_modules/.*''']
regexes = ['''(?i)example''']
```

- `regexTarget = "match"` — test the allowlist regex against the matched secret only
- `regexTarget = "line"` — test against the entire line containing the match
- `stopwords` — if the secret contains any stopword (case-insensitive), the finding is suppressed
- `commits` — suppress findings from specific commit SHAs

### Extending vs Overriding Defaults

By default, `-c custom.toml` **replaces** the entire built-in ruleset. To extend:

```toml
# extend.toml — add rules on top of defaults
[extend]
useDefault = true

[[rules]]
id = "internal-token"
description = "Internal service token"
regex = '''int_tok_[a-zA-Z0-9]{40}'''
keywords = ["int_tok_"]
```

`useDefault = true` loads all built-in rules first, then appends your custom rules. Override a built-in rule by using the same `id` — yours wins.

### Entropy-Only Rules

Catch high-entropy strings in specific contexts without a fixed regex:

```toml
[[rules]]
id = "high-entropy-env"
description = "High-entropy value in .env file"
regex = '''(?i)(password|secret|token|key)\s*=\s*(.+)'''
secretGroup = 2
entropy = 4.0
path = '''\.env.*'''
keywords = ["password", "secret", "token", "key"]
```

Entropy thresholds: 3.0–3.5 catches most base64/hex strings; 4.0+ is very selective. Below 3.0 produces excessive noise on natural language.

### Regex Best Practices

- Anchor patterns to a context prefix (`(?i)api[_-]?key[\s:="']+`) rather than matching bare hex/base64 strings — the keyword pre-filter handles the performance, the regex handles the precision
- Use `secretGroup` to isolate the secret from its label; this is what `--redact` masks
- Avoid `.+` greediness across lines; gitleaks processes chunks, not single lines, so greedy patterns can span boundaries
- Test patterns with `--log-level trace` on a known-positive repo before deploying to CI

---

## Baseline Workflow

Baselines separate known/accepted findings from new ones. The workflow:

### Initial Baseline Creation

```bash
gitleaks git --report-format json --report-path baseline.json --no-banner /workspace
```

Review `baseline.json` — each entry has `RuleID`, `Match`, `File`, `StartLine`, `Commit`. Remove entries that represent real, un-rotated secrets (those need remediation, not suppression).

### Baseline-Aware Re-scan

```bash
gitleaks git --baseline-path baseline.json \
  --report-format json --report-path new_findings.json \
  --no-banner --exit-code 1 /workspace
```

Only findings **not** in `baseline.json` appear in `new_findings.json`. Matching is by `RuleID` + `Match` + `Commit` + `File` + `StartLine`.

### PR-Scoped CI Pattern

```bash
# Only scan commits in this PR
gitleaks git --log-opts "origin/main..HEAD" \
  --baseline-path baseline.json \
  --report-format sarif --report-path gitleaks.sarif \
  --no-banner --exit-code 1 /workspace
```

This gates on **new secrets in this PR only** — existing secrets in the baseline don't fail the build. Merge `new_findings.json` into `baseline.json` after review.

### Baseline Maintenance

- Check `baseline.json` into the repo (it contains match metadata, not the secrets themselves, when `--redact` was used on the original scan)
- Periodically audit the baseline: run with `--ignore-gitleaks-allow` to bypass inline suppressions and see the full picture
- After secret rotation, remove the rotated entry from the baseline and re-scan to confirm it's gone

---

## Decode Depth Mechanics

`--max-decode-depth <n>` (default 5) controls recursive decoding of encoded content. Gitleaks applies a chain of decoders (base64, hex, URL encoding, UTF-16) to each chunk, feeding each decoder's output back through the chain up to the configured depth.

Depth 1 = single pass: catches `base64(secret)`.
Depth 2+ = chained: catches `base64(hex(secret))`, `url(base64(secret))`, etc.

When to adjust:
- **Raise** (7–10): obfuscated configuration files, packed artifacts, intentionally layered encoding
- **Lower** (1–2): performance-critical scans on large repos where deep decoding adds minutes; known-plaintext targets
- **Default (5)**: catches the vast majority of real-world encoding layers without excessive runtime

```bash
# Deep decode for obfuscated configs
gitleaks dir --max-decode-depth 10 --report-format json --report-path gitleaks.json /workspace

# Shallow decode for speed
gitleaks git --max-decode-depth 1 --report-format json --report-path gitleaks.json /workspace
```

---

## Archive Scanning

`--max-archive-depth <n>` (default 0 = disabled) enables recursive scanning into compressed archives (zip, tar, tar.gz, tar.bz2).

- Depth 1: scans files inside top-level archives
- Depth 2+: scans archives inside archives (e.g. a zip containing a tar.gz)
- Depth 0: no archive traversal (default)

```bash
# Scan up to 3 levels of nested archives
gitleaks dir --max-archive-depth 3 --max-target-megabytes 50 \
  --report-format json --report-path gitleaks.json /workspace
```

Always pair with `--max-target-megabytes` when scanning archives — a zip bomb or large binary archive without a size cap will exhaust memory. Depth 2–3 is sufficient for most real-world packaging (e.g. wheel inside tar.gz, jar inside zip).

Archive scanning applies to `dir` mode primarily. In `git` mode, gitleaks processes commit blobs directly — if an archive was committed to git, it's scanned as a blob, not extracted. Use `dir` mode for archive-aware scanning of release artifacts.

---

## Pre-commit and Staged Integration

### `--pre-commit` Flag

`gitleaks git --pre-commit` scans the **current git diff** — the changes about to be committed. It runs `git diff` internally and checks only the diff output, not the full history or working tree.

```bash
gitleaks git --pre-commit --report-format json --report-path - --no-banner --exit-code 1 .
```

### `--staged` Flag

`gitleaks git --staged` scans **staged changes** (what `git diff --cached` shows). This is the correct mode for a git pre-commit hook — it matches exactly what the commit will contain.

```bash
gitleaks git --staged --report-format json --report-path - --no-banner --exit-code 1 .
```

### Git Hook Wiring

```bash
#!/bin/sh
# .git/hooks/pre-commit
gitleaks git --staged --no-banner --exit-code 1 .
```

Or via the `pre-commit` framework (`.pre-commit-config.yaml`):

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
```

### `--pre-commit` vs `--staged`

Both scan uncommitted changes, but:
- `--staged` sees only `git add`'d content — exactly what the commit will contain
- `--pre-commit` runs `git diff` which sees unstaged modifications too

For pre-commit hooks, `--staged` is correct. `--pre-commit` is useful for ad-hoc "what am I about to leak?" checks before staging.

---

## Platform-Aware Reporting

`--platform <github|gitlab>` (git subcommand only) generates clickable source links in the report. Each finding includes a URL pointing to the exact file and line on the platform.

```bash
# GitHub-linked report
gitleaks git --platform github --report-format json --report-path gitleaks.json /workspace

# GitLab-linked report
gitleaks git --platform gitlab --report-format json --report-path gitleaks.json /workspace
```

The links are constructed from the remote URL and commit SHA. Use this for team-facing reports where reviewers need one-click access to the finding location. Omit for machine-parsed reports where the link adds noise.

Platform links appear in JSON and SARIF output. They do not affect CSV or text formats.

---

## Report Template Authoring

`--report-template <file>` with `--report-format template` renders findings through a Go `text/template`. The template receives a slice of finding structs.

```go
{{/* findings.tmpl — one-line-per-finding for Slack/chat */}}
{{- range . -}}
🔑 {{ .RuleID }}: {{ .Description }}
   File: {{ .File }}:{{ .StartLine }}
   Commit: {{ .Commit | printf "%.8s" }}
   Author: {{ .Author }}
{{ end -}}
```

```bash
gitleaks git --report-format template --report-template findings.tmpl \
  --report-path gitleaks_summary.txt --no-banner /workspace
```

### Available Template Fields

Each finding exposes:
- `.RuleID` — rule identifier
- `.Description` — rule description
- `.Match` — the matched secret (redacted if `--redact` is on)
- `.Secret` — alias for `.Match`
- `.File` — relative file path
- `.StartLine` / `.EndLine` — line range
- `.StartColumn` / `.EndColumn` — column range
- `.Commit` — commit SHA
- `.Author` — commit author
- `.Email` — commit author email
- `.Date` — commit date
- `.Message` — commit message (first line)
- `.Tags` — rule tags (string slice)
- `.Entropy` — Shannon entropy of the match
- `.Fingerprint` — unique finding identifier

Use templates for:
- Custom Slack/Teams notifications
- Internal ticketing system integrations
- Compliance-specific report formats
- Aggregated summaries (use `{{- len . -}}` for finding count)

---

## High-Signal Built-in Rules

Gitleaks ships ~150 built-in rules. The highest-signal ones for pentest/security workflows:

### Cloud Provider Credentials

| Rule ID | What It Catches |
|---------|----------------|
| `aws-access-token` | AWS access key IDs (`AKIA...`) |
| `aws-secret-access-key` | AWS secret keys |
| `gcp-api-key` | Google Cloud API keys |
| `gcp-service-account` | GCP service account JSON key files |
| `azure-storage-key` | Azure storage account keys |

### Platform Tokens

| Rule ID | What It Catches |
|---------|----------------|
| `github-pat` | GitHub personal access tokens (`ghp_...`) |
| `github-fine-grained-pat` | GitHub fine-grained PATs (`github_pat_...`) |
| `github-oauth` | GitHub OAuth tokens |
| `github-app-token` | GitHub App installation tokens (`ghs_...`) |
| `gitlab-pat` | GitLab personal access tokens (`glpat-...`) |
| `gitlab-pipeline-trigger-token` | GitLab CI trigger tokens |

### Communication / SaaS

| Rule ID | What It Catches |
|---------|----------------|
| `slack-bot-token` | Slack bot tokens (`xoxb-...`) |
| `slack-user-token` | Slack user tokens (`xoxp-...`) |
| `slack-webhook-url` | Slack incoming webhook URLs |
| `sendgrid-api-token` | SendGrid API keys (`SG.`) |
| `twilio-api-key` | Twilio API keys |
| `stripe-access-token` | Stripe live/test secret keys (`sk_live_`, `sk_test_`) |

### Cryptographic Material

| Rule ID | What It Catches |
|---------|----------------|
| `private-key` | RSA/EC/DSA/OpenSSH private keys (`-----BEGIN ... PRIVATE KEY-----`) |
| `jwt` | JSON Web Tokens (`eyJ...`) |

### Database / Infrastructure

| Rule ID | What It Catches |
|---------|----------------|
| `generic-api-key` | High-entropy strings near key/token/secret keywords |
| `password-in-url` | Credentials embedded in URLs (`://user:pass@host`) |

### Focused Scans

Run only the rules you care about:

```bash
# AWS credentials only
gitleaks git --enable-rule aws-access-token --enable-rule aws-secret-access-key \
  --report-format json --report-path aws.json /workspace

# All GitHub token types
gitleaks git --enable-rule github-pat --enable-rule github-fine-grained-pat \
  --enable-rule github-oauth --enable-rule github-app-token \
  --report-format json --report-path github_tokens.json /workspace

# Private keys and JWTs
gitleaks git --enable-rule private-key --enable-rule jwt \
  --report-format json --report-path crypto.json /workspace
```

`--enable-rule` is repeatable. When set, **only** the named rules run — all others are disabled. To run everything except a few, use a custom config with an allowlist instead.

---

## CI Integration Patterns

### GitHub Actions

```yaml
# .github/workflows/gitleaks.yml
name: gitleaks
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The official action handles SARIF upload to GitHub Code Scanning automatically. For custom control:

```yaml
      - name: gitleaks scan
        run: |
          gitleaks git --log-opts "origin/main..HEAD" \
            --baseline-path .gitleaks-baseline.json \
            --report-format sarif --report-path gitleaks.sarif \
            --no-banner --exit-code 1 .
      - name: upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
gitleaks:
  stage: test
  image: zricethezav/gitleaks:latest
  script:
    - gitleaks git --log-opts "origin/main..HEAD"
        --report-format json --report-path gitleaks.json
        --no-banner --exit-code 1 .
  artifacts:
    paths:
      - gitleaks.json
    when: always
  allow_failure: false
```

### Exit Code Strategy

| Pipeline Intent | `--exit-code` | Effect |
|----------------|---------------|--------|
| Gate: block merge on secrets | `1` (default) | Non-zero fails the step |
| Report: scan and proceed | `0` | Always pass; findings in the report |
| Custom: integrate with other tooling | `<N>` | Your automation branches on the code |

### SARIF Upload to GitHub Code Scanning

```bash
gitleaks git --report-format sarif --report-path gitleaks.sarif --no-banner --exit-code 0 /workspace
# Upload via gh CLI
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -f "commit_sha=$(git rev-parse HEAD)" \
  -f "ref=refs/heads/$(git branch --show-current)" \
  -F "sarif=@gitleaks.sarif"
```

---

## Redaction Controls

`--redact` masks matched secrets in verbose output and reports. In 8.30.x, it accepts an optional percentage:

```bash
# Full redaction (default) — secret replaced entirely
gitleaks git --redact --report-format json --report-path gitleaks.json /workspace

# Partial redaction — show first 20% of the match
gitleaks git --redact=20 --report-format json --report-path gitleaks.json /workspace

# No redaction — raw secrets in output (handle with care)
gitleaks git --report-format json --report-path gitleaks.json /workspace
```

Partial redaction (`--redact=20`) is useful when reviewers need to identify which specific key variant was leaked without exposing the full secret. The percentage is applied to the `secretGroup` match — the labeled portion of the finding, not the full regex match.

Reports written to files (JSON, SARIF, JUnit, CSV) inherit the redaction level. Redact before sharing reports externally.

---

## Diagnostics and Profiling

`--diagnostics` enables runtime profiling for debugging slow scans:

```bash
# HTTP pprof server (access at http://localhost:6060/debug/pprof/)
gitleaks git --diagnostics http /workspace

# File-based diagnostics
gitleaks git --diagnostics cpu,mem --diagnostics-dir /tmp/gitleaks-diag /workspace
```

Modes:
- `http` — starts a `net/http/pprof` server; connect with `go tool pprof`
- `cpu` — writes CPU profile to `--diagnostics-dir`
- `mem` — writes memory profile
- `trace` — writes execution trace (view with `go tool trace`)

Use diagnostics when:
- A scan takes unexpectedly long (profile reveals which rule/file dominates)
- Memory usage spikes (memory profile shows allocation hotspots)
- Comparing scan performance across config changes

---

## gitleaks vs trufflehog

Both are secret scanners. Choose by capability need:

| Dimension | gitleaks | trufflehog |
|-----------|----------|------------|
| **Primary strength** | Fast git-native scanning with custom TOML rules | Live credential verification against provider APIs |
| **Git history** | Native (`git` subcommand, `--log-opts`) | Native (`git` subcommand, `--since-commit`, `--branch`) |
| **Non-git sources** | `dir`, `stdin` | `filesystem`, `stdin`, plus GitHub org, GitLab, S3, GCS, Docker image, Postman, Jenkins, HuggingFace, Elasticsearch, syslog, CircleCI, TravisCI |
| **Verification** | None (match-only) | Live API verification: tells you if the secret still works |
| **Custom rules** | TOML with regex, entropy, keywords, allowlists | YAML config with custom verifier endpoints |
| **Report formats** | JSON, CSV, JUnit, SARIF, Go templates | JSONL on stdout |
| **Pre-commit** | `--staged`, `--pre-commit` flags | Not native (wrap in a hook manually) |
| **Archive scanning** | `--max-archive-depth` | `--archive-max-depth`, `--archive-max-size`, `--archive-timeout` |
| **Exit code on findings** | `1` (default), configurable | `183` with `--fail` |

### Complementary Pairing Strategy

Run gitleaks as the bulk sweep (fast, customizable, CI-native), then trufflehog as the verification pass (which of those secrets are still live?):

```bash
# Step 1: bulk sweep with gitleaks
gitleaks git --report-format json --report-path gitleaks.json --no-banner --exit-code 0 /workspace

# Step 2: verify the critical findings with trufflehog
trufflehog filesystem --results verified --json --no-update /workspace > trufflehog_verified.jsonl

# Step 3: merge — gitleaks findings enriched with trufflehog verification status
# gitleaks gives breadth (custom rules, all git history); trufflehog gives depth (is it live?)
```

Reach for trufflehog first when:
- The task requires verified-live credentials (not just pattern matches)
- The target is a non-git source (S3 bucket, Docker image, GitHub org API)
- You need the `analyze` subcommand to enumerate a token's permissions

Reach for gitleaks first when:
- You need custom TOML rules for internal token formats
- The pipeline requires SARIF output for GitHub Code Scanning
- Pre-commit hook integration is needed (`--staged`)
- Speed matters on large repos with narrow commit ranges (`--log-opts`)

---

## Tool Chaining

- **trufflehog** (`tooling/trufflehog.md`): verification-first sibling — gitleaks finds secrets, trufflehog confirms which are still live. Run both for coverage + confidence.
- **trivy** (`tooling/trivy.md`): `trivy fs --scanners secret` overlaps for repo-less trees but has narrower rules. Gitleaks is the primary secret scanner; trivy's secret scanner is a bonus on top of its SCA/misconfig strengths.
- **bandit** (`tooling/bandit.md`): bandit's B105–B107 catch hardcoded credentials in Python source code; gitleaks catches secrets in git history and broader file types. Complementary, non-overlapping.
- **semgrep** (`tooling/semgrep.md`): semgrep's `--secrets` mode overlaps for code-level secret detection; gitleaks covers git history and non-code files that semgrep skips.

Pipeline:
```bash
gitleaks git --report-format sarif --report-path gitleaks.sarif --no-banner --exit-code 0 /workspace
trufflehog filesystem --results verified --json --no-update /workspace > trufflehog_verified.jsonl
# Cross-reference: gitleaks SARIF for breadth, trufflehog JSONL for verified-only
```

If uncertain, query web_search with:
`site:github.com/gitleaks/gitleaks gitleaks <flag>`

Routed consumers:
- `vulnerabilities/information_disclosure.md` (committed-secret class)
- `coordination/source_aware_whitebox.md`, `custom/source_aware_sast.md` (whitebox pipelines)
- `tooling/trufflehog.md` (verification-first sibling — same workflow, trufflehog adds live-verified credentials)
- `tooling/trivy.md` (`trivy fs --scanners secret` overlaps for repo-less trees but has narrower rules)
- `tooling/bandit.md` (B105–B107 hardcoded credentials in Python — complementary)
- `tooling/semgrep.md` (`--secrets` mode overlaps for code-level detection)
