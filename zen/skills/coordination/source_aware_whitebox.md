---
name: source-aware-whitebox
description: Coordination playbook for source-aware white-box testing with static triage and dynamic validation
---

# Source-Aware White-Box Coordination

Use this coordination playbook when repository source code is available.

## Objective

Increase white-box coverage by combining source-aware triage with dynamic validation. Source-aware tooling is expected by default when source is available.

## Recommended Workflow

1. Build a quick source map before deep exploitation, including at least one AST-structural pass (`sg` or `tree-sitter`) scoped to relevant paths.
   - For `sg` baseline, derive `sg-targets.txt` from `semgrep.json` scope first (`paths.scanned`, fallback to unique `results[].path`) and run `xargs ... sg run` on that list.
   - Only fall back to path heuristics when semgrep scope is unavailable.
2. Run first-pass static triage to rank high-risk paths.
3. Use triage outputs to prioritize dynamic PoC validation.
4. Keep findings evidence-driven: no report without validation.

## Source-Aware Triage Stack

- `semgrep`: fast security-first triage and custom pattern scans
- `ast-grep` (`sg`): structural pattern hunting and targeted repo mapping
- `tree-sitter`: syntax-aware parsing support for symbol and route extraction
- `gitleaks` + `trufflehog`: complementary secret detection (working tree and history coverage)
- `trivy fs`: dependency, misconfiguration, license, and secret checks

Coverage target per repository:
- one `semgrep` pass
- one AST structural pass (`sg` and/or `tree-sitter`)
- one secrets pass (`gitleaks` and/or `trufflehog`)
- one `trivy fs` pass

## Agent Delegation Guidance

- Keep child agents specialized by vulnerability/component as usual.
- For source-heavy subtasks, prefer creating child agents with `source_aware_sast` skill.
- Use source findings to shape payloads and endpoint selection for dynamic testing.

## Routing Triage Hits to Specialists

A triage hit routes to the specialist skill that owns its exploitation.
Spawn (or become) an agent loaded with that skill; the routing signal is the
sink or pattern, not the language.

| Triage signal (sink / pattern) | Route to |
| --- | --- |
| Raw SQL string-building, ORM `.raw()`/`.extra()`, query concatenation | `sql_injection` |
| Mongo `$where` / operator injection, JSON query bodies | `nosql_injection` |
| `exec`/`spawn`/`system`/`subprocess`/backticks/`Runtime.exec` | `rce` (+ `argument_injection` for argv arrays) |
| `pickle`/`yaml.load`/`ObjectInputStream`/`unserialize`/`Marshal.load` | `insecure_deserialization` |
| Template render of user input (Jinja, Freemarker, Handlebars, ERB) | `ssti` |
| Path join + open/read/write on user input, `../` handling | `path_traversal_lfi_rfi` |
| Server-side fetch of a user-controlled URL, webhook/callback client | `ssrf` |
| XML parse / `DocumentBuilder` / `etree` / entity resolution | `xxe` |
| Redirect or `Location` set from user input | `open_redirect` |
| JWT decode/verify, session/token issuance, auth-state transition | `authentication_jwt` |
| Request body bound onto a model/struct, `Object.assign`, `**kwargs` | `mass_assignment` |
| Object fetched by id with no ownership/tenant check | `idor`, `broken_function_level_authorization` |
| HTML/DOM sink, `innerHTML`/`dangerouslySetInnerHTML`, unescaped render | `xss` |
| Response header set from user input | `header_injection` |
| Recursive merge, `__proto__`/`constructor.prototype` write | `prototype_pollution` |
| File upload handler, content-type/extension gate | `insecure_file_uploads` |
| Dependency manifest/lockfile with known-vuln versions | `dependency_cve_scanning` |

For *which instances to enumerate* once routed — every codec, every call
site, every duplicated copy across packages — the enumeration discipline is
`source_aware_discovery`, not here.

## Triage-to-Dynamic Handoff

Static triage produces hypotheses; the decision is *when* to spend a dynamic
agent confirming one. Hand a static finding to a dynamic-validation agent
when all of these hold:

- The trace is complete: attacker-controlled input reaches a dangerous sink
  by a reachable path, with the broken or missing control named.
- There is a running instance to hit. If the target is source-only with no
  deployable instance, dynamic validation is unavailable — keep it static
  and report at reduced confidence (the bar is in `counterevidence`).
- The entrypoint is reachable from an attacker position you can occupy: an
  exposed route, a queue you can post to, a file you can upload.

Hand off the trace, not the hunch. Give the dynamic agent the entrypoint,
the exact input that should trigger the sink, the observable that proves it
fired (a response value, an out-of-band callback, a state change), and the
benign case that should *not* fire. A dynamic agent handed only "SQLi
somewhere in the orders API" re-does the triage you already did.

Do not spend a dynamic agent when there is no running instance, when the
sink is inert in context, or when the finding has no attacker-reachable
path. A recorded proof gap is a legitimate outcome; a dynamic agent burned
on an unreachable path is waste.

## Validation Guardrails

- Static findings are hypotheses until validated.
- Dynamic exploitation evidence is still required before vulnerability reporting.
- Keep scanner output concise, deduplicated, and mapped to concrete code locations.
