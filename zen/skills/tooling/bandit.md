---
name: bandit
description: Bandit Python security linter — test ID selection, severity/confidence filtering, baseline mode, and JSON/HTML/SARIF output patterns.
---

# bandit CLI Playbook

Official docs:
- https://bandit.readthedocs.io/
- https://bandit.readthedocs.io/en/latest/plugins/
- https://github.com/PyCQA/bandit

Canonical syntax:
`bandit [options] <targets...>`

High-signal flags:
- `-r, --recursive` recurse into directories (required for folder targets)
- `-a, --aggregate <file|vuln>` aggregate output by vulnerability (default) or by filename
- `-c, --configfile <file>` select plugins / override defaults
- `-p, --profile <name>` named profile from config
- `-t, --tests <ids>` run only these test IDs (comma-separated; e.g. `B301,B307,B602`)
- `-s, --skip <ids>` skip these test IDs
- `-l` / `-ll` / `-lll` severity floor (LOW / MEDIUM / HIGH); or `--severity-level <all|low|medium|high>`
- `-i` / `-ii` / `-iii` confidence floor; or `--confidence-level <all|low|medium|high>`
- `-f, --format <csv|custom|html|json|screen|txt|xml|yaml>` output format
- `--msg-template <template>` custom text format (only with `--format custom`; vars: `{abspath}`, `{relpath}`, `{line}`, `{col}`, `{test_id}`, `{severity}`, `{msg}`, `{confidence}`, `{range}`)
- `-o, --output <file>` write report to file
- `-b, --baseline <file>` baseline JSON report (suppress findings already present)
- `-x, --exclude <paths>` exclude paths (glob; adds to default `.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg`)
- `--ini <path>` path to a `.bandit` INI file that supplies default command-line arguments
- `--ignore-nosec` do not skip lines marked `# nosec`
- `--exit-zero` always exit 0 even with findings
- `-n, --number <n>` context lines around each finding
- `-q, --quiet, --silent` only show output on error
- `-v, --verbose` include excluded/included file list in output
- `-d, --debug` debug mode

Agent-safe baseline for automation:
`bandit -r -ll -ii -f json -o bandit.json --exit-zero -q /workspace`
(recursive, medium-severity/confidence floor, JSON output, exit-zero so downstream parsing runs.)

Common patterns:
- Baseline recursive scan:
  `bandit -r /workspace`
- High-signal recursive scan (med+ severity, med+ confidence) with JSON:
  `bandit -r -ll -ii -f json -o bandit.json --exit-zero -q /workspace`
- SARIF-equivalent XML for CI (bandit has no SARIF; XML is the closest machine-readable option — convert downstream if SARIF is required):
  `bandit -r -ll -ii -f xml -o bandit.xml --exit-zero -q /workspace`
- Narrow to specific test IDs (e.g. injection + crypto):
  `bandit -r -t B301,B303,B304,B305,B307,B601,B602,B605,B608 -f json -o bandit_focus.json --exit-zero -q /workspace`
- Skip noisy tests (`B101 assert_used` is common noise in test suites):
  `bandit -r -s B101,B110,B112 -f json -o bandit.json --exit-zero -q /workspace`
- Baseline-aware re-scan (ignore previously accepted findings):
  `bandit -r -b bandit_baseline.json -f json -o bandit.json --exit-zero -q /workspace`
- Scan a single file:
  `bandit -ll -ii -f json -o bandit.json path/to/file.py`
- Honor `# nosec` suppressions (default) vs. ignore them:
  `bandit -r --ignore-nosec -ll -ii -f json -o bandit_strict.json --exit-zero -q /workspace`
- Custom format for terminal review:
  `bandit -r -ll -ii -f custom --msg-template '{relpath}:{line}:{test_id} [{severity}/{confidence}] {msg}' /workspace`
- Use `.bandit` INI file for default arguments:
  `bandit --ini .bandit -r /workspace`

Critical correctness rules:
- `-r` is **required** for directory targets — without it, bandit treats the argument as a single file and silently matches nothing.
- Severity (`-l/-ll/-lll`) and confidence (`-i/-ii/-iii`) stack independently; a `MEDIUM`-severity, `HIGH`-confidence finding passes `-ll -ii` but not `-lll -iii`.
- Default behavior respects `# nosec` comments — audit-strict runs should pass `--ignore-nosec` so suppressions can't hide live issues.
- Default-excluded paths (`.git`, `.tox`, `__pycache__`, …) are additive; `-x` **adds** to them, not replace. Pass `-c` with an override to change the base.
- `--exit-zero` is critical in automation: without it, bandit exits non-zero when findings exist and shell pipelines may error before parsing the report.
- Test IDs are stable (`B101` to `B704`); the plugin list is printed on every run (and in the help). Use `-t`/`-s` for scoped runs.
- `-f json` is the structured consumer; `-f xml` is the closest to SARIF (convert via `sarif-multitool` or similar); `-f screen` is pretty-print only.

Usage rules:
- Pair with `tooling/semgrep.md` on Python-heavy codebases — semgrep has broader rules, bandit has deeper Python-specific coverage.
- Keep `-ll -ii` as the automation floor; `-l -i` floods on test suites and large projects.
- Store a baseline JSON in-repo and re-scan with `-b`; it keeps regressions visible without churn.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- Zero findings on code you expect issues in: verify `-r` is passed, check the path isn't in the default excludes (`__pycache__`, `.tox`, …), lower severity/confidence floor, run without `--ignore-nosec` to see if suppressions are the cause.
- Huge findings count: tighten with `-ll -ii`, skip noisy IDs (`-s B101,B404`), scope to the module under test.
- JSON output empty but screen output shows findings: verify `-o <file>` was supplied; without `-o`, JSON goes to stdout.
- "No such file or directory": bandit does not glob; pass directory + `-r`, or expand globs in the shell.

If uncertain, query web_search with:
`site:bandit.readthedocs.io bandit <flag>` or `site:github.com/PyCQA/bandit`

---

## B-Code Test Catalogue

Bandit 1.9.4 ships 73 test plugins (B101–B704). The catalogue below groups them by the vulnerability class they detect, with the corresponding `vulnerabilities/*.md` skill route. Use `-t <ids>` for focused scans against a specific class, `-s <ids>` to suppress noise from classes outside scope.

### Code Execution / RCE → `vulnerabilities/rce.md`

Direct code execution sinks and process-spawning patterns:

| ID | Name | What it catches |
|----|------|-----------------|
| B102 | `exec_used` | `exec()` calls — arbitrary code execution |
| B307 | `eval` | `eval()` calls — expression evaluation from untrusted input |
| B601 | `paramiko_calls` | Paramiko `exec_command`/`invoke_shell` — remote command execution |
| B602 | `subprocess_popen_with_shell_equals_true` | `subprocess.Popen(..., shell=True)` — shell injection via string interpolation |
| B603 | `subprocess_without_shell_equals_true` | `subprocess.Popen` without `shell=True` — still risky if args come from user input |
| B604 | `any_other_function_with_shell_equals_true` | Non-subprocess functions called with `shell=True` |
| B605 | `start_process_with_a_shell` | `os.system()`, `os.popen()` — shell command execution |
| B606 | `start_process_with_no_shell` | `os.execl()`, `os.spawnl()` — direct process execution |
| B607 | `start_process_with_partial_path` | Subprocess with partial path (e.g. `Popen("ls")` instead of `/usr/bin/ls`) — PATH hijack risk |
| B609 | `linux_commands_wildcard_injection` | Wildcards in subprocess args (e.g. `tar cf * ...`) — argument injection via crafted filenames |

Focused scan: `bandit -r -t B102,B307,B601,B602,B603,B604,B605,B606,B607,B609 -f json -o bandit_rce.json --exit-zero -q /workspace`

The high-signal subset for live injection risk: **B602, B605, B307, B102** (shell=True, os.system, eval, exec). B603/B606/B607 are lower-confidence — the risk depends on whether input reaches the arguments.

Triage B602 (the most common RCE finding):
1. Trace the first argument to `Popen(cmd, shell=True)` — if `cmd` is a constant string, suppress with `# nosec B602`.
2. If `cmd` is built from user input (request params, file contents, env vars), it's a confirmed shell injection.
3. If `cmd` comes from config or internal state, assess whether an attacker can control that state.
4. The fix is always the same: switch to `shell=False` with a list of arguments: `Popen(["ls", "-la", path], shell=False)`.

### SQL Injection → `vulnerabilities/sql_injection.md`

| ID | Name | What it catches |
|----|------|-----------------|
| B608 | `hardcoded_sql_expressions` | String concatenation or f-string in SQL queries (`"SELECT * FROM " + table`) |
| B610 | `django_extra_used` | Django QuerySet `.extra()` with raw SQL fragments |
| B611 | `django_rawsql_used` | Django `RawSQL()` expressions |

B608 is the workhorse — it catches the classic concatenation pattern. False positives are common on string constants that contain SQL keywords but aren't queries; triage by checking whether user input reaches the concatenation.

Triage B608:
1. Check whether the concatenated value comes from user input (request params, form data, headers).
2. If the query uses an ORM's parameterized interface (`cursor.execute("SELECT ... WHERE id = %s", (user_id,))`), it's safe — B608 doesn't fire on parameterized queries.
3. If the finding is Django `.extra()` (B610) or `RawSQL()` (B611), the same input-tracing applies — but these are higher signal because raw SQL in Django usually means the ORM was deliberately bypassed.

### Insecure Deserialization → `vulnerabilities/insecure_deserialization.md`

| ID | Name | What it catches |
|----|------|-----------------|
| B301 | `pickle` | `pickle.loads()`, `pickle.load()`, `cPickle` equivalents — arbitrary code execution on untrusted data |
| B302 | `marshal` | `marshal.loads()` — Python-internal serialization, not safe for untrusted data |
| B403 | `import_pickle` | `import pickle` / `import cPickle` — informational; flags the import so you audit usage |
| B506 | `yaml_load` | `yaml.load()` without `Loader=SafeLoader` — YAML deserialization can execute arbitrary Python |
| B614 | `pytorch_load` | `torch.load()` — uses pickle internally; arbitrary code execution on untrusted model files |
| B615 | `huggingface_unsafe_download` | HuggingFace `from_pretrained()` with unsafe download — model file may contain arbitrary code |

B301 and B506 are the high-value findings. B614/B615 are ML-specific — increasingly relevant as model files become attack vectors.

Triage B301 (pickle):
1. If `pickle.load()`/`pickle.loads()` receives data from a network request, file upload, or external source: confirmed deserialization RCE.
2. If it reads from a trusted internal file (model cache, precomputed data): lower risk, but note that the trust boundary includes anyone who can write to that file.
3. The fix: use `json`, `msgpack`, or protocol buffers for data interchange. For ML models, use `safetensors` or `torch.load(..., weights_only=True)`.

Triage B506 (yaml.load):
1. `yaml.load(data)` without a Loader argument defaults to `FullLoader` in modern PyYAML, which is safer than the old default but still allows some object construction.
2. Always use `yaml.safe_load(data)` or `yaml.load(data, Loader=yaml.SafeLoader)`.
3. If the YAML input is from an untrusted source and uses `yaml.FullLoader` or `yaml.UnsafeLoader`: confirmed deserialization.

### XXE / XML Parsing → `vulnerabilities/xxe.md`

Insecure XML parsers that allow external entity resolution:

| ID | Name | What it catches |
|----|------|-----------------|
| B313 | `xml_bad_cElementTree` | `xml.etree.cElementTree` — vulnerable to XXE |
| B314 | `xml_bad_ElementTree` | `xml.etree.ElementTree` — vulnerable to XXE |
| B315 | `xml_bad_expatreader` | `xml.sax.expatreader` — vulnerable to XXE |
| B316 | `xml_bad_expatbuilder` | `xml.dom.expatbuilder` — vulnerable to XXE |
| B317 | `xml_bad_sax` | `xml.sax` — vulnerable to XXE |
| B318 | `xml_bad_minidom` | `xml.dom.minidom` — vulnerable to XXE |
| B319 | `xml_bad_pulldom` | `xml.dom.pulldom` — vulnerable to XXE |
| B405 | `import_xml_etree` | Import of `xml.etree` (informational) |
| B406 | `import_xml_sax` | Import of `xml.sax` (informational) |
| B407 | `import_xml_expat` | Import of `xml.parsers.expat` (informational) |
| B408 | `import_xml_minidom` | Import of `xml.dom.minidom` (informational) |
| B409 | `import_xml_pulldom` | Import of `xml.dom.pulldom` (informational) |
| B411 | `import_xmlrpclib` | Import of `xmlrpc` — also a deserialization risk |

The B313–B319 tests flag actual parser usage; B405–B411 flag imports (lower signal). When B313–B319 fire, check whether the code disables external entity resolution — if not, it's exploitable.

Focused scan: `bandit -r -t B313,B314,B315,B316,B317,B318,B319 -f json -o bandit_xxe.json --exit-zero -q /workspace`

Triage B313–B319:
1. Check whether the XML parser processes external input (uploaded XML, API payloads, SOAP).
2. If external entities are disabled (e.g. `parser.setFeature(handler.feature_external_ges, False)`), the parser is safe — suppress.
3. If external entities are not explicitly disabled: confirmed XXE risk. The fix: use `defusedxml` instead of the stdlib XML modules, or explicitly disable entity resolution.
4. The import-level tests (B405–B411) are informational — they fire on the import, not on usage. Use them to locate code that needs manual audit for entity resolution settings.

### Cryptographic Weakness → crypto / `vulnerabilities/weak_password_detection.md`

| ID | Name | What it catches |
|----|------|-----------------|
| B303 | `md5` | MD5 usage (broken for collision resistance) |
| B304 | `ciphers` | Insecure ciphers: DES, Blowfish, ARC4, IDEA |
| B305 | `cipher_modes` | Insecure cipher modes: ECB (no diffusion) |
| B324 | `hashlib_insecure_functions` | `hashlib.md5()`, `hashlib.sha1()` — weak hash functions |
| B505 | `weak_cryptographic_key` | RSA/DSA/EC key sizes below recommended minimums |

B303/B324 overlap on MD5 — B324 is the more general hashlib check. B505 catches key-generation calls with small bit sizes (e.g. `RSA.generate(1024)`).

### Hardcoded Credentials → `vulnerabilities/information_disclosure.md`

| ID | Name | What it catches |
|----|------|-----------------|
| B105 | `hardcoded_password_string` | `password = "..."` — password as a string literal |
| B106 | `hardcoded_password_funcarg` | `connect(password="secret")` — password as a function argument |
| B107 | `hardcoded_password_default` | `def login(password="default")` — password as a default parameter |

These tests look for variables/arguments named `password`, `passwd`, `secret`, `token`, etc. with string-literal values. High false-positive rate on test fixtures and configuration defaults — triage by checking whether the literal reaches a production code path.

### Network and TLS → transport security

| ID | Name | What it catches |
|----|------|-----------------|
| B104 | `hardcoded_bind_all_interfaces` | Binding to `0.0.0.0` — exposes service on all interfaces |
| B310 | `urllib_urlopen` | `urllib.urlopen()` — SSRF risk if URL comes from user input |
| B321 | `ftplib` | FTP usage — unencrypted protocol |
| B323 | `unverified_context` | `ssl._create_unverified_context()` — disables certificate validation |
| B401 | `import_telnetlib` | Import of `telnetlib` — unencrypted protocol |
| B402 | `import_ftplib` | Import of `ftplib` — unencrypted protocol |
| B412 | `import_httpoxy` | Import of `CGIHandler`/`BaseHTTPRequestHandler` — httpoxy vulnerability |
| B501 | `request_with_no_cert_validation` | `requests.get(..., verify=False)` — disables TLS certificate validation |
| B502 | `ssl_with_bad_version` | Explicit use of SSLv2/SSLv3/TLSv1/TLSv1.1 |
| B503 | `ssl_with_bad_defaults` | `ssl.wrap_socket()` without explicit protocol — may default to insecure version |
| B504 | `ssl_with_no_version` | `ssl.SSLContext()` without protocol version — defaults may be insecure |
| B507 | `ssh_no_host_key_verification` | Paramiko `set_missing_host_key_policy(AutoAddPolicy)` — accepts any host key |
| B508 | `snmp_insecure_version` | SNMPv1/v2c — community-string auth, no encryption |
| B509 | `snmp_weak_cryptography` | SNMPv3 with weak crypto — DES or MD5 |

B501 and B323 are the most common TLS findings. B502–B504 catch explicit or implicit use of deprecated protocol versions.

### Template Injection / XSS → `vulnerabilities/ssti.md`, `vulnerabilities/browser_security.md`

| ID | Name | What it catches |
|----|------|-----------------|
| B308 | `mark_safe` | Generic `mark_safe()` usage — bypasses output encoding |
| B701 | `jinja2_autoescape_false` | `jinja2.Environment(autoescape=False)` — disables XSS protection |
| B702 | `use_of_mako_templates` | Mako templates — no auto-escaping by default |
| B703 | `django_mark_safe` | Django `mark_safe()` — marks string as safe HTML (bypasses escaping) |
| B704 | `markupsafe_markup_xss` | `markupsafe.Markup()` with user input — XSS via explicit unsafe markup |

B701 is the high-signal Jinja2 finding. B703/B704/B308 fire when code explicitly marks output as safe — audit whether the marked content can contain user-controlled input.

Triage B701:
1. Check whether the Jinja2 environment renders user-controlled content. `autoescape=False` on admin-only templates with no user data is lower risk.
2. If the template renders any user input (names, comments, form fields): confirmed stored/reflected XSS.
3. Fix: `jinja2.Environment(autoescape=True)` or `jinja2.Environment(autoescape=select_autoescape())`.

Triage B703/B704:
1. Trace the argument to `mark_safe()` / `Markup()` — if it contains user input without prior sanitization: confirmed XSS.
2. If the argument is a static HTML string or server-generated markup with no user data: suppress.
3. Common pattern: `mark_safe(f"<a href='{url}'>{name}</a>")` — both `url` and `name` are injection points.

### General Security Hygiene

| ID | Name | What it catches | Signal level |
|----|------|-----------------|--------------|
| B101 | `assert_used` | `assert` statements — stripped in optimized bytecode (`python -O`) | Low; noisy in test suites — skip with `-s B101` |
| B103 | `set_bad_file_permissions` | `os.chmod()` with overly permissive modes (e.g. `0o777`) | Medium |
| B108 | `hardcoded_tmp_directory` | Hardcoded `/tmp`, `/var/tmp` paths — race conditions, symlink attacks | Medium |
| B110 | `try_except_pass` | `except: pass` — silently swallows all exceptions including security errors | Low; common noise |
| B112 | `try_except_continue` | `except: continue` — same swallowing pattern in loops | Low |
| B113 | `request_without_timeout` | `requests.get()` without `timeout=` — can hang indefinitely | Medium |
| B201 | `flask_debug_true` | `app.run(debug=True)` — exposes Werkzeug debugger (RCE if reachable) | High |
| B202 | `tarfile_unsafe_members` | `tarfile.extractall()` without member filtering — path traversal via `../../` entries | High |
| B306 | `mktemp_q` | `tempfile.mktemp()` — race condition between name generation and file creation | Medium |
| B311 | `random` | `random.random()` etc. for security purposes — use `secrets` module instead | Medium |
| B312 | `telnetlib` | Direct `telnetlib` usage — unencrypted remote access | Low |
| B404 | `import_subprocess` | `import subprocess` — informational; the import itself isn't dangerous | Low; skip in automation |
| B413 | `import_pycrypto` | `import Crypto` (PyCrypto) — deprecated, use `cryptography` or `pycryptodome` | Medium |
| B415 | `import_pyghmi` | `import pyghmi` — IPMI library, may expose BMC interfaces | Low |
| B612 | `logging_config_insecure_listen` | `logging.config.listen()` — opens a socket that accepts arbitrary logging config | High |
| B613 | `trojansource` | Unicode bidi override characters — trojan source attack | High |

Common noise filter for automation: `-s B101,B110,B112,B404` removes the four lowest-signal tests without suppressing real findings.

---

## Scan Methodology

### Full audit pass

```bash
# 1. Full scan with no suppressions — capture everything
bandit -r --ignore-nosec -l -i -f json -o bandit_full.json --exit-zero -q /workspace

# 2. Count and summarize by class
jq '[.results[].test_id] | group_by(.) | map({id: .[0], count: length}) | sort_by(-.count)' bandit_full.json

# 3. Focus on high-signal classes
bandit -r --ignore-nosec -t B301,B307,B506,B602,B605,B608,B701 -lll -iii -f json -o bandit_critical.json --exit-zero -q /workspace

# 4. Triage critical findings manually (trace input to sink)
jq '.results[] | "\(.filename):\(.line_number) \(.test_id) \(.issue_text)"' bandit_critical.json
```

### Differential scan (PR-scoped)

```bash
# Scan only changed Python files
git diff --name-only --diff-filter=ACMR HEAD~1 -- '*.py' | xargs bandit -ll -ii -f json -o bandit_diff.json --exit-zero -q
```

### Class-specific deep dive

Run bandit for one vulnerability class, then hand off to the corresponding vulnerability skill for exploitation methodology:

| Vulnerability class | Bandit flags | Then route to |
|---------------------|-------------|---------------|
| RCE | `-t B102,B307,B602,B605` | `vulnerabilities/rce.md` |
| SQLi | `-t B608,B610,B611` | `vulnerabilities/sql_injection.md` |
| Deserialization | `-t B301,B302,B506,B614` | `vulnerabilities/insecure_deserialization.md` |
| XXE | `-t B313,B314,B315,B316,B317,B318,B319` | `vulnerabilities/xxe.md` |
| SSTI / XSS | `-t B701,B702,B703,B704,B308` | `vulnerabilities/ssti.md` |
| Secrets | `-t B105,B106,B107` | `vulnerabilities/information_disclosure.md` |

---

## Configuration and Profiles

### YAML config file (`-c, --configfile`)

```yaml
# .bandit.yaml
tests: [B602, B608, B301, B506, B701]
skips: [B101, B110, B404]
exclude_dirs:
  - tests/
  - venv/
  - .tox/
```

Pass with `-c .bandit.yaml`. The config selects which tests run and overrides default exclusion paths. Per-plugin settings can tune thresholds (e.g. custom paths for B108 `hardcoded_tmp_directory`).

### INI file (`--ini`)

```ini
# .bandit
[bandit]
targets = /workspace
recursive = true
tests = B602,B608,B301,B506
severity = medium
confidence = medium
format = json
output = bandit.json
exit_zero = true
```

Pass with `--ini .bandit`. Supplies default CLI arguments — useful for standardizing team-wide scan parameters. CLI flags override INI values.

### Profiles (`-p, --profile`)

Named profiles in the YAML config group test selections:

```yaml
profiles:
  injection:
    include: [B102, B307, B602, B605, B608]
  crypto:
    include: [B303, B304, B305, B324, B505]
```

`bandit -r -p injection /workspace` runs only the injection-class tests.

---

## Baseline Workflow

The baseline mechanism suppresses known findings so only regressions surface:

```bash
# 1. Generate initial baseline
bandit -r -f json -o bandit_baseline.json --exit-zero -q /workspace

# 2. Review and accept baseline findings (manual triage)

# 3. Re-scan against baseline — only new findings appear
bandit -r -b bandit_baseline.json -f json -o bandit.json --exit-zero -q /workspace
```

- `-b` accepts only JSON-formatted baselines — other formats are rejected.
- The baseline comparison is by file path + line number + test ID. Refactored code may re-surface previously baselined findings if line numbers shift.
- Version-control the baseline JSON alongside the codebase. Re-generate after major refactors.
- CI pattern: fail the gate only when `bandit.json` contains findings not in the baseline.

Baseline generation for a new project:
```bash
# Run with --ignore-nosec to capture everything in the baseline
bandit -r --ignore-nosec -f json -o bandit_baseline.json --exit-zero -q /workspace
# Count baseline findings
jq '.results | length' bandit_baseline.json
# Triage: review each finding, file or suppress the real ones, then commit the baseline
```

Baseline-gated CI check:
```bash
bandit -r -b bandit_baseline.json -ll -ii -f json -o bandit_new.json --exit-zero -q /workspace
NEW_COUNT=$(jq '.results | length' bandit_new.json)
if [ "$NEW_COUNT" -gt 0 ]; then
  echo "FAIL: $NEW_COUNT new bandit findings since baseline"
  jq '.results[] | "\(.filename):\(.line_number) \(.test_id) [\(.issue_severity)] \(.issue_text)"' bandit_new.json
  exit 1
fi
```

---

## Severity and Confidence Tuning

Severity and confidence are **independent axes**. A finding must meet both thresholds to be reported:

| Flags | Severity floor | Confidence floor | Use case |
|-------|---------------|-----------------|----------|
| (none) | LOW | LOW | Audit everything — noisy but complete |
| `-ll -ii` | MEDIUM | MEDIUM | Automation floor — balanced signal |
| `-lll -iii` | HIGH | HIGH | Critical-only — few findings, high precision |
| `-l -iii` | LOW | HIGH | Low-severity but high-confidence — unusual combo |
| `--ignore-nosec -l -i` | LOW | LOW | Strict audit — no suppressions, everything visible |

Common automation floor: `-ll -ii`. For security audit work where completeness matters: `--ignore-nosec -l -i` with post-scan triage.

---

## Output Formats and Parsing

| Format | Flag | Machine-readable | Notes |
|--------|------|-------------------|-------|
| JSON | `-f json` | Yes | Primary structured output; required for `-b` baseline |
| XML | `-f xml` | Yes | Closest to SARIF — convert via `sarif-multitool convert --tool bandit` |
| CSV | `-f csv` | Yes | Spreadsheet-friendly |
| YAML | `-f yaml` | Yes | Alternative structured format |
| HTML | `-f html` | No | Shareable report |
| Screen | `-f screen` | No | Default terminal pretty-print |
| Text | `-f txt` | No | Plain text |
| Custom | `-f custom` | Depends | Requires `--msg-template`; Python `str.format()` syntax |

JSON output structure (per finding):
```json
{
  "test_id": "B602",
  "test_name": "subprocess_popen_with_shell_equals_true",
  "filename": "app/utils.py",
  "line_number": 42,
  "line_range": [42, 43],
  "col_offset": 4,
  "end_col_offset": 55,
  "issue_severity": "HIGH",
  "issue_confidence": "HIGH",
  "issue_text": "subprocess call with shell=True identified",
  "code": "    subprocess.Popen(cmd, shell=True)\n"
}
```

Parse with jq:
```bash
# High-severity findings only
jq '.results[] | select(.issue_severity == "HIGH")' bandit.json

# Count by test ID
jq '[.results[].test_id] | group_by(.) | map({id: .[0], count: length})' bandit.json

# Extract for SARIF conversion
jq '.results[] | {file: .filename, line: .line_number, id: .test_id, severity: .issue_severity, msg: .issue_text}' bandit.json
```

---

## `# nosec` Suppressions

Lines with `# nosec` are skipped by default:
```python
password = "dev-only"  # nosec B105 — test fixture, not production
subprocess.call(cmd, shell=True)  # nosec B602 — input is validated above
```

- `# nosec` without test IDs suppresses all tests on that line.
- `# nosec B602,B605` suppresses only the named tests — prefer this over blanket `# nosec`.
- `--ignore-nosec` overrides all suppressions — use for audit runs.

Audit pattern:
1. Run with `--ignore-nosec -l -i` to see all findings including suppressed ones.
2. For each `# nosec`, verify the justification still holds.
3. Flag `# nosec` without a test ID or comment — these are suppression debt.

---

## CI Integration

### GitHub Actions

```yaml
- name: Bandit security scan
  run: |
    bandit -r -b bandit_baseline.json -ll -ii -f json -o bandit.json --exit-zero -q src/
    NEW=$(python3 -c "import json; print(len(json.load(open('bandit.json'))['results']))")
    if [ "$NEW" -gt 0 ]; then
      bandit -r -b bandit_baseline.json -ll -ii -f screen src/
      exit 1
    fi
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/PyCQA/bandit
  rev: '1.9.4'
  hooks:
    - id: bandit
      args: ['-ll', '-ii', '--exit-zero', '-q']
```

### Exit codes

Bandit's exit codes without `--exit-zero`:
- `0` — no findings at or above the severity/confidence threshold
- `1` — findings present
- `2` — error during execution

With `--exit-zero`: always exits `0` regardless of findings — parse the JSON report for pass/fail.

### Combining with semgrep in CI

Run both tools and merge findings for a unified view:
```bash
bandit -r -ll -ii -f json -o bandit.json --exit-zero -q /workspace
semgrep scan --config p/python --metrics=off --json --output semgrep.json --quiet /workspace
# Both produce structured JSON; merge or report independently
# bandit covers Python-specific tests (B-codes); semgrep covers cross-language rules + taint analysis
```

---

## Tool Chaining

- **semgrep** (`tooling/semgrep.md`): complementary — semgrep has broader cross-language rules and taint tracking; bandit has deeper Python-specific coverage and the B-code catalogue. Run both on Python codebases.
- **ast-grep** (`tooling/ast-grep.md`): custom structural patterns when bandit's built-in rules don't match the pattern you need. Write a one-off `ast-grep run -p '<pattern>' -l python` for patterns outside the B-code catalogue.
- **gitleaks/trufflehog** (`tooling/gitleaks.md`, `tooling/trufflehog.md`): bandit's B105–B107 catch hardcoded credentials in code; gitleaks/trufflehog catch secrets in git history and broader file types.
- **trivy** (`tooling/trivy.md`): bandit catches code-level issues; trivy catches dependency vulnerabilities, misconfigs, and license issues.
- **nuclei** (`tooling/nuclei.md`): bandit finding → nuclei template to validate the issue is exploitable in a running instance.

Pipeline:
```bash
bandit -r -ll -ii -f json -o bandit.json --exit-zero -q /workspace
semgrep scan --config p/python --metrics=off --json --output semgrep_python.json --quiet /workspace
# Merge findings by file/line for deduplication
```

Routed consumers:
- `coordination/source_aware_whitebox.md`, `custom/source_aware_sast.md` (whitebox pipelines)
- `vulnerabilities/sql_injection.md` (`B608`), `vulnerabilities/rce.md` (`B602-B606`, `B307`), `vulnerabilities/insecure_deserialization.md` (`B301`, `B403`, `B506`), `vulnerabilities/xxe.md` (`B313-B320`, `B405-B411`), `vulnerabilities/weak_password_detection.md` (`B303-B305`, `B324`, `B505`) — bandit test IDs map directly to these vuln classes
- `vulnerabilities/ssti.md` (`B701`, `B702`), `vulnerabilities/browser_security.md` (`B703`, `B704`, `B308`) — template/XSS findings
- `vulnerabilities/information_disclosure.md` (`B105-B107`) — hardcoded credentials
- `tooling/semgrep.md` (complementary — semgrep for cross-language rules, bandit for Python depth)
- `tooling/ast-grep.md` (custom structural patterns for Python when bandit's built-in rules don't match)
