<p align="center">
  <a href="https://zenney.uk/">
    <pre>
███████╗███████╗███╗   ██╗ 
╚══███╔╝██╔════╝████╗  ██║
  ███╔╝ █████╗  ██╔██╗ ██║
 ███╔╝  ██╔══╝  ██║╚██╗██║
███████╗███████╗██║ ╚████║
╚══════╝╚══════╝╚═╝  ╚═══╝    
    </pre>
  </a>
</p>

<div align="center">

# Zen

### Open-source offensive security agents. Autonomous pentesting that discovers, exploits, and remediates vulnerabilities in running code.

<br/>

<a href="https://docs.zenney.uk"><img src="https://img.shields.io/badge/Docs-docs.zenney.uk-02A3CF?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://zenney.uk"><img src="https://img.shields.io/badge/Website-zenney.uk-f0f0f0?style=for-the-badge&logoColor=000000" alt="Website"></a>
<a href="https://discord.gg/v5dPr4wcTz"><img src="https://img.shields.io/badge/Discord-Join-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>

<a href="https://deepwiki.com/zenneyy/zen-ai"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
<a href="https://github.com/zenneyy/zen-ai"><img src="https://img.shields.io/github/stars/zenneyy/zen-ai?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="License"></a>
<a href="https://pypi.org/project/zen-agent/"><img src="https://img.shields.io/pypi/v/zen-agent?style=flat-square" alt="PyPI Version"></a>

<a href="https://x.com/zen_ai"><img src="https://img.shields.io/badge/X-Follow-000000?style=flat-square&logo=x&logoColor=white" alt="Follow on X"></a>

</div>


> [!TIP]
> Zen executes natively inside GitHub Actions and other CI/CD systems. Assess every pull request and stop exploitable code at the merge boundary rather than in production - [Get started with no setup required](https://app.zenney.uk).

---


## What is Zen

Zen dispatches a fleet of autonomous agents that execute your application, observe its runtime behavior, and confirm each defect by exploiting it. Nothing is reported until it has been reproduced, so the output is a set of demonstrated attacks rather than a queue of suspicions. It targets engineering organizations that need security validation at a cadence manual assessment cannot sustain, and at a precision static analysis does not reach.

**Core capabilities:**

- **Complete offensive tooling** — reconnaissance, exploitation, and verification in one runtime, with nothing to assemble
- **Multi-agent execution** — specialized agents partition the target and scale horizontally across it
- **Proof-carrying findings** — every report ships with a proof-of-concept that executes against the live target
- **Terminal-native workflow** — output written for the engineer who has to land the fix, remediation context included
- **Automated remediation and reporting** — generated patches, plus assessment documents formatted for audit


<br>

## Where it fits

- **Application Security Testing** — locate exploitable defects across an application and confirm each one is reachable
- **Rapid Penetration Testing** — compress a full engagement, compliance documentation included, from weeks into hours
- **Bug Bounty Automation** — automate the reconnaissance and exploitation loop, then submit against generated proof-of-concepts
- **CI/CD Integration** — enforce a security gate in the pipeline so exploitable code never reaches production

## 🚀 Get started

**Requirements:**
- A running Docker daemon
- One of:
  - **Claude Code** installed and signed in, with the Zen bridge running — no API key required
  - A **DeepSeek API key**

See [supported providers](https://docs.zenney.uk/llm-providers/overview) for the full list.

### Install and run an assessment

```bash
# Install Zen
curl -sSL https://zenney.uk/install | bash

# Option A — Claude via the bridge
npm install -g @anthropic-ai/claude-code
claude                      # sign in once, then exit
python -m zen.bridge        # starts the bridge; connects the session automatically

export ZEN_LLM="claude/claude-opus-4-8"

# Option B — DeepSeek API key
export ZEN_LLM="deepseek/deepseek-v4-pro"
export DEEPSEEK_API_KEY="your-deepseek-api-key"

# Run your first security assessment
zen --target ./app-directory
```

> [!NOTE]
> The sandbox image (`ghcr.io/zenneyy/zen-sandbox:1.2.0`) is pulled on first execution. Run artifacts are written to `zen_runs/<run-name>`.

---

## ☁️ Managed platform

**[app.zenney.uk](https://app.zenney.uk)** hosts the same engine as a managed service. Register an account, attach your repositories and domains, and assessments dispatch without any local infrastructure.

- **Validated findings with PoCs** — a reproducible exploit and its reproduction sequence accompany every reported vulnerability
- **One-click autofix** — model-generated security patches delivered as reviewable pull requests
- **Continuous pentesting** — assessment on a persistent schedule, tracking your deployment velocity
- **DevSecOps integrations** — GitHub, GitLab, Bitbucket, Slack, Jira, Linear, and CI/CD pipelines
- **Continuous learning** — prior findings inform subsequent runs; the system adapts to your codebase and suppresses recurring false positives

[**Run your first assessment →**](https://app.zenney.uk)

---

## ✨ Architecture

### Agent tooling

Every agent operates the same instrumentation a professional penetration tester would reach for:

- **HTTP Interception Proxy** — Caido, integrated for complete request and response manipulation and analysis
- **Browser Exploitation** — an instrumented browser covering XSS, CSRF, clickjacking, and authentication bypass flows
- **Shell & Command Execution** — an interactive terminal for exploit development and post-exploitation activity
- **Custom Exploit Runtime** — a Python sandbox in which proof-of-concept code is authored and verified
- **Reconnaissance & OSINT** — automated attack surface mapping, subdomain enumeration, and service fingerprinting
- **Static & Dynamic Code Analysis** — SAST and DAST in combination, so both the code and its running form are covered
- **Vulnerability Knowledge Base** — findings held in structured form, with CVSS scoring and OWASP classification

### Vulnerability coverage

Detection, validation, and exploitation span the OWASP Top 10 and extend well past it:

- **Broken Access Control** — IDOR, horizontal and vertical privilege escalation, authorization bypass
- **Injection Attacks** — SQL and NoSQL injection, OS command injection, SSTI
- **Server-Side Vulnerabilities** — SSRF, remote code execution, insecure deserialization, XXE
- **Client-Side Attacks** — stored, reflected, and DOM-based XSS, prototype pollution, CSRF
- **Business Logic Flaws** — workflow bypass, payment manipulation, race conditions
- **Authentication & Session** — credential stuffing vectors, session fixation, JWT attacks
- **Infrastructure & Cloud** — misconfiguration, unintentionally exposed services, cloud security weaknesses
- **API Security** — broken authentication, mass assignment, rate limit bypass

### Agent graph (distributed execution)

Coordination between agents is what makes that breadth tractable:

- **Distributed Pentesting** — reconnaissance, exploitation, and post-exploitation each assigned to a specialist agent
- **Scalable Security Testing** — targets assessed concurrently, so coverage does not trade against wall-clock time
- **Dynamic Coordination** — agents propagate discoveries between themselves and chain vulnerabilities the way a red team does

---

## 🖥️ Local result viewer

Artifacts are written to disk as the assessment proceeds. A single command renders them in a local dashboard:

```bash
# Open the most recent run
zen view

# ...or open a specific run by name
zen view my-run-name

# Expose the viewer on all IPv4 interfaces at a fixed port
zen view --host 0.0.0.0 --port 8080 --no-open
```

`zen view` binds a lightweight server to `127.0.0.1` on an ephemeral port and opens a private, token-scoped URL in your browser. Nothing transits the network: the dashboard reads run files directly from the filesystem, with no account provisioning and no upload step. The interface is compiled into the distribution, so there is no additional dependency and no JavaScript build to run.

To reach the viewer from another host, pass `--host 0.0.0.0` and substitute a resolvable hostname or address for the `0.0.0.0` in the emitted URL. Handle that URL as a credential: its token authorizes access to the selected run's scan data, history, and steering interface, so restrict distribution and firewall the port accordingly. Requests that carry no token-derived session are refused.

### Viewer surfaces

- **Overview**: current run state, the configured target, and a severity distribution across findings so far.
- **Vulnerabilities**: each validated finding with severity, supporting detail, and a reproduction sequence.
- **Agent graph**: a live topology of the agent fleet, showing the task assigned to each node.
- **Steering**: inject instructions into an in-flight assessment and redirect the agents without restarting.
- **History**: every prior run recorded on this host, addressable directly.
- **Reports**: compile a distributable report and dispatch it by email.

---

## Usage patterns

### Common invocations

```bash
# Scan a local codebase
zen --target ./app-directory

# Security review of a GitHub repository
zen --target https://github.com/org/repo

# Black-box web application assessment
zen --target https://your-app.com
```

### Assessment from an API specification (OpenAPI / Swagger / Postman)

Supply a contract and Zen exercises every endpoint the specification
declares, instead of inferring the surface by crawling. Pair the
specification with the live base URL so requests are routed correctly:

```bash
# OpenAPI / Swagger file (.json / .yaml)
zen --target ./openapi.yaml --target https://api.your-app.com

# Postman collection export
zen --target ./collection.postman_collection.json --target https://api.your-app.com

# Postman collection pulled live by id (no manual export)
export POSTMAN_API_KEY="PMAK-..."
zen --target postman://<collection-uuid>

# ...with a Postman environment to resolve {{baseUrl}} / token variables
zen --target "postman://<collection-uuid>?env=<environment-uuid>"
```


### Advanced invocations

```bash
# Grey-box authenticated testing
zen --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
zen -t https://github.com/org/app -t https://your-app.com

# Targets from a file, one target per non-empty, non-comment line
zen --target-list ./targets.txt

# White-box source-aware scan (local repository)
zen --target ./app-directory --scan-mode standard

# Focused testing with custom instructions
zen --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"

# Provide detailed instructions through file (e.g., rules of engagement, scope, exclusions)
zen --target api.your-app.com --instruction-file ./instruction.md

# Force PR diff-scope against a specific base branch
zen -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main
```

### Headless execution

`-n/--non-interactive` disables the terminal UI, which is the correct mode for servers and scheduled jobs. Findings stream to stdout as they are validated, the final report follows, and the process terminates with a non-zero status when anything was found.

```bash
zen -n --target https://your-app.com
```

### GitHub Actions integration

A minimal workflow is sufficient to assess every pull request:

```yaml
name: zen-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Zen
        run: curl -sSL https://zenney.uk/install | bash

      - name: Run Zen
        env:
          ZEN_LLM: ${{ secrets.ZEN_LLM }}
          DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}

        run: zen -n -t ./ --scan-mode quick
```

> [!TIP]
> During pull request runs, Zen restricts quick reviews to the changed file set automatically.
> Where the diff scope cannot be resolved, confirm the checkout retrieved full history
> (`fetch-depth: 0`), or supply `--diff-base` explicitly.
>
> CI runners cannot complete an interactive Claude Code sign-in, so use the DeepSeek API key path
> for pipeline runs.

### Environment configuration

```bash
# Model selection — pick one
export ZEN_LLM="claude/claude-opus-4-8"      # Claude, via the bridge
export ZEN_LLM="claude/claude-opus-4-6"      # Prior Claude generation, same path
export ZEN_LLM="deepseek/deepseek-v4-pro"    # DeepSeek V4 Pro, API key required
export ZEN_LLM="deepseek/deepseek-v4-flash"  # DeepSeek V4 Flash, API key required

# API keys — only required for DeepSeek
export DEEPSEEK_API_KEY="your-deepseek-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"      # if using a local model (Ollama, LMStudio)
export PERPLEXITY_API_KEY="your-api-key"     # for search capabilities
export ZEN_REASONING_EFFORT="high"           # thinking effort (default: high, quick scan: medium)
```

> [!NOTE]
> Configuration is persisted to `~/.zen/cli-config.json` on write, so these values survive between runs. Claude credentials are not written there — the bridge reads them from the Claude Code session at runtime.

#### Sign in with a ChatGPT subscription

Instead of a metered API key, you can run Zen on your ChatGPT Plus/Pro subscription:

```bash
zen auth login chatgpt             # sign in with your ChatGPT account
export ZEN_LLM="chatgpt/gpt-5.4"   # chatgpt/<model> runs on the subscription
zen auth status                    # show the active sign-in, or logout to forget it
```
#### Claude via the bridge

Zen has no Claude login of its own. Install Claude Code, sign in there once, then start the bridge — it picks up that session automatically and serves it to Zen for the duration of the run.

```bash
# One-time setup
npm install -g @anthropic-ai/claude-code
claude                      # sign in on first run, then exit

# Start the bridge (leave it running)
python -m zen.bridge

# In another shell
export ZEN_LLM="claude/claude-opus-4-8"
zen --target ./app-directory
```

The bridge is a long-running local process: start it before a scan and leave it up. No API key is stored, and no credentials are copied into Zen's own configuration. If the Claude Code session expires, run `claude` again to sign back in — the bridge reconnects without a restart.

Use the DeepSeek API key path instead if you need a metered, non-subscription setup, if you plan to run at concurrency that exceeds subscription rate limits, or if you are running in CI where an interactive sign-in is not possible.

#### MCP server integration

Zen can attach to Model Context Protocol (MCP) servers and expose their tools to the agents during a run. Declare them in `~/.zen/mcp-servers.json` as a JSON array. Each entry is either a `stdio` server that Zen launches as a local subprocess, or a remote `http` endpoint:

```json
[
  {
    "name": "local_fs",
    "transport": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
  },
  {
    "name": "github",
    "transport": "http",
    "url": "https://api.githubcopilot.com/mcp/",
    "auth": { "kind": "bearer", "token": "your-token" },
    "allowed_tools": ["list_issues"]
  }
]
```

Tool identifiers are namespaced under the server's `name` — `local_fs_read_file`, for example. Omitting `allowed_tools` exposes the server's full tool set; supplying a list constrains the agents to those entries. The file itself is optional, and a server that fails to connect is skipped without aborting the run. Set `ZEN_MCP_CONFIG` to load the declaration from another path.

**Recommended model configurations:**

- [Anthropic Claude Opus 4.8](https://claude.com/platform/api) — `claude/claude-opus-4-8` (via the bridge, no API key)
- [Anthropic Claude Opus 4.6](https://claude.com/platform/api) — `claude/claude-opus-4-6` (via the bridge, prior generation)
- [DeepSeek V4 Pro](https://platform.deepseek.com/) — `deepseek/deepseek-v4-pro` (API key)
- [DeepSeek V4 Flash](https://platform.deepseek.com/) — `deepseek/deepseek-v4-flash` (API key, faster and cheaper tier)

Locally hosted models are supported through the `LLM_API_BASE` override; the [LLM Providers documentation](https://docs.zenney.uk/llm-providers/overview) enumerates every configuration option.

## Enterprise

The same engine under organizational controls: [enterprise-grade](https://zenney.uk/demo) SSO via SAML or OIDC, custom penetration testing reports mapped to SOC 2, ISO 27001, and PCI DSS, dedicated support under SLA, flexible deployment topologies including VPC and self-hosted, BYOK model access, and agents tuned against your environment. [Learn more](https://zenney.uk/demo).

## Reference documentation

The complete reference lives at **[docs.zenney.uk](https://docs.zenney.uk)**, covering usage, CI/CD integration, skills, and advanced configuration.

## Development and contributions

Code, documentation, and new skills are all in scope. Start from the [Contributing Guide](https://docs.zenney.uk/contributing), or go directly to a [pull request](https://github.com/zenneyy/zen-ai/pulls)/[issue](https://github.com/zenneyy/zen-ai/issues).

## Community

Questions, defect reports, and design discussion happen on **[Discord](https://discord.gg/v5dPr4wcTz)**.

## Support

If Zen earns a place in your toolchain, a ⭐ on GitHub helps others find it.

## License and attribution

Zen is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text and [`NOTICE`](NOTICE) for attribution.

Zen is a derivative work of [Strix](https://github.com/usestrix/strix), Copyright 2025 OmniSecure Inc., licensed under Apache-2.0. Files throughout this distribution have been modified from the original Strix sources. Our thanks to the Strix team for the foundation this builds on.

## Upstream projects

Zen and Strix both build on [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright), and [Bubble Tea](https://github.com/charmbracelet/bubbletea). Our thanks to the teams maintaining them.


> [!WARNING]
> **Authorized use only.** Zen executes live attacks against whatever target it is given. Run it exclusively against systems you own or hold **explicit, written permission** to assess, and remain within the agreed scope. Unauthorized testing carries criminal liability in most jurisdictions.
>
> Obtaining that authorization and complying with applicable law is the operator's responsibility. Zen is distributed "as is", without warranty, and its authors accept no liability for misuse.
>
> **Model behavior.** Autonomous agents backed by large language models can misinterpret scope, execute unexpected actions, and produce false-positive findings. Review every reported vulnerability before treating it as actionable, and confine test runs to isolated environments where any collateral impact stays contained.

</div>
