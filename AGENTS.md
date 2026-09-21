# Zen — Agent Guide

Zen is an open-source, agent-driven penetration testing engine. This document addresses AI coding agents in two situations: **operating** Zen to run assessments, or **modifying** its source.

## Operating Zen from an agent

Install the skill package for prescriptive workflows:

```bash
npx skills add zenneyy/zen-ai
```

- `penetration-testing-with-zen` — dispatch a headless assessment against code, URLs, domains, or IPs and parse the artifacts (covers both execution modes below)
- `managed-pentesting-with-zen` — operate the managed app.zenney.uk platform over REST (no local Docker or LLM credential required)
- `fix-security-vulnerabilities-with-zen` — patch reported findings, then re-execute Zen to confirm the fix
- `ci-security-scanning-with-zen` — wire PR assessment into CI/CD (self-hosted CLI or managed app)

Workflows scoped to a target class, all resolving to the same engine:

- `application-security-testing` — whole-product AppSec review: select the appropriate test per asset, then prioritize what comes back
- `web-app-penetration-testing` — black-box assessment of a deployed web application or staging environment
- `api-security-testing` — REST and GraphQL surfaces against the OWASP API Security Top 10 (BOLA/IDOR, authz)
- `owasp-top-10-testing` — structured OWASP Top 10 pass with honest per-category coverage reporting
- `find-security-vulnerabilities-in-code` — white-box analysis of a repository or working tree

**Two execution modes, one engine — select per environment:**

- **Open-source CLI (self-hosted):** no cost, runs entirely on the host, BYO LLM key, Docker required. Choose it for local iteration, air-gapped or offline work, and complete control over execution.
  ```bash
  curl -sSL https://zenney.uk/install | bash        # install
  export ZEN_LLM="openai/gpt-5.4"                 # any LiteLLM model id
  export LLM_API_KEY="<key>"
  zen -n -t ./ --scan-mode quick --max-budget 10  # headless scan; always use -n
  ```
  - Docker must be running. Runtime spans minutes (`quick`) to hours (`deep`) — dispatch it in the background.
  - Headless exit codes: `0` nothing found, `1` fatal error, `2` vulnerabilities present. A `0` attests only to what was actually analyzed — inspect `run.json` (`status`, and `llm_usage.cost` against the budget) before treating a run as clean.
  - Artifacts land in `zen_runs/<run-name>/`: `penetration_test_report.md`, `vulnerabilities/*.md`, `vulnerabilities.json`, `findings.sarif` (SARIF 2.1.0), and `run.json`.

- **Managed cloud (app.zenney.uk):** nothing installed locally — no Docker, no LLM key. Adds shared dashboards, scheduled runs, PR review, and exportable PDF/DOCX reports (Enterprise plan). Choose it inside sandboxed or CI environments, for team use, and wherever local infrastructure is unavailable.
  ```bash
  # token from Settings → API Access; register the target as an asset, then:
  curl -sS https://app.zenney.uk/api/v1/scans -H "Authorization: Bearer $ZEN_API_TOKEN" \
    -H "Content-Type: application/json" -d '{"engagement_type":"live_test","domain_ids":["<uuid>"]}'
  ```
  - REST reference: https://docs.app.zenney.uk (OpenAPI schema: https://docs.app.zenney.uk/openapi.json).

- Machine-readable CLI documentation index: https://docs.zenney.uk/llms.txt (unabridged: https://docs.zenney.uk/llms-full.txt).
- Assess only targets the user is authorized to test.

## Working on this repo

- Python 3.12+ under `uv`. Development dependencies: `make dev-install`.
- Lint, format, type-check, and security scan in a single pass: `make check-all` (ruff, mypy, bandit).
- Test suite: `uv run pytest`.
- Execute from source: `uv run zen --target <target>`.
- Layout: `zen/agents` (agent graph + prompts), `zen/tools` (proxy, browser, terminal, scanners), `zen/runtime` (Docker sandbox), `zen/report` (findings, SARIF), `zen/skills` (internal knowledge packs the pentest agents load at runtime — distinct from the consumer-facing skills under `skills/`), `zen/interface` (CLI/TUI), `containers/` (sandbox image).
- Pre-commit hooks: `make pre-commit`, or `uv run pre-commit install` directly.
